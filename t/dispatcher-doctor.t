#!/usr/bin/perl
# t/dispatcher-doctor.t
#
# T-055: 'ctrl-exec-dispatcher doctor'. Each check against a throwaway
# dispatcher config (temp CA, certificates, registry, hook, socket; the old and
# new config directories through Exec::DispatcherConfig's seams): what it
# reports, at which severity, with which fix; a clean dispatcher reports
# nothing; --fix restores the API socket's mode and group (and a second --fix
# changes nothing); the CLI's exit status and --json; unprivileged, what it
# cannot read is a note.

use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/../lib", "$Bin/lib";
use File::Temp qw(tempdir);
use File::Path qw(make_path);
use IO::Socket::UNIX;
use JSON qw(decode_json encode_json);

plan skip_all => 'openssl not available' unless system('openssl version >/dev/null 2>&1') == 0;

use Exec::Doctor             qw();
use Exec::Doctor::Dispatcher qw();
use Exec::DispatcherConfig   qw();
use Exec::Log                qw();
require AgentRig;

{
    no warnings 'redefine';
    *Exec::Log::log_action = sub { 1 };
}

sub slurp { open my $fh, '<', $_[0] or die "$_[0]: $!"; local $/; scalar <$fh> }
sub spew  { open my $fh, '>', $_[0] or die "$_[0]: $!"; print $fh $_[1]; close $fh }
sub sh    { system(@_) == 0 or die "failed: @_\n" }

# A dispatcher: <root>/etc/ctrl-exec-dispatcher with a CA, a dispatcher
# certificate valid for $o{days} (400), ctrl-exec.conf ($o{conf} appended), and
# a registry. The config directories point into <root>. The certificate carries
# key identifiers, as Exec::CA issues it from 0.14 (on OpenSSL 1.1 too); with
# aki => 0 it has none, as a 1.1 host issued it before 0.14 (AgentRig::key_id_ext).
sub dispatcher {
    my (%o) = @_;
    my $r = tempdir(CLEANUP => 1);
    my $d = "$r/etc/ctrl-exec-dispatcher";
    make_path($d, "$r/agents");
    sh("openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout $d/ca.key"
     . " -out $d/ca.crt -subj /CN=ca -days 3650 2>/dev/null");
    sh("openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout $d/dispatcher.key"
     . " -out $d/d.csr -subj /CN=d 2>/dev/null");
    spew("$d/d.ext", "basicConstraints=CA:FALSE\n" . AgentRig::key_id_ext($o{aki} // 1));
    sh("openssl x509 -req -in $d/d.csr -CA $d/ca.crt -CAkey $d/ca.key -set_serial 7 -extfile $d/d.ext"
     . " -out $d/dispatcher.crt -days " . ($o{days} // 400) . " 2>/dev/null");
    spew("$d/ctrl-exec.conf", "cert = $d/dispatcher.crt\nkey = $d/dispatcher.key\nca = $d/ca.crt\n"
       . "registry_dir = $r/agents\n" . ($o{conf} // ''));
    return { root => $r, dir => $d, conf => "$d/ctrl-exec.conf" };
}

sub checks {
    my ($x, %o) = @_;
    local $Exec::DispatcherConfig::CONF_DIR   = "$x->{root}/etc/ctrl-exec-dispatcher";
    local $Exec::DispatcherConfig::LEGACY_DIR = "$x->{root}/etc/ctrl-exec";
    local $Exec::Doctor::Dispatcher::DPKG_INFO = "$x->{root}/dpkg-info";
    return Exec::Doctor::Dispatcher::checks(%o);
}

sub by_check { my ($f, $c) = @_; return grep { $_->{check} eq $c } @$f }
sub ids { return [ map { $_->{check} } @{ $_[0] } ] }

sub agent_record {
    my ($x, $name, $expiry, %extra) = @_;
    spew("$x->{root}/agents/$name.json", encode_json({ hostname => $name, ip => '192.0.2.1',
        paired => '2026-01-01T00:00:00Z', expiry => $expiry, reqid => 'r', %extra }));
}

sub expiry_in_days {
    my ($days) = @_;
    my @t = gmtime(time + $days * 86400);
    my @mon = qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec);
    return sprintf '%s %2d %02d:%02d:%02d %d GMT', $mon[$t[4]], $t[3], @t[2,1,0], $t[5] + 1900;
}

subtest 'a clean dispatcher: nothing to report' => sub {
    my $x = dispatcher();
    agent_record($x, 'agent-01', expiry_in_days(200));
    my $f = checks($x);
    is_deeply ids($f), [], 'no findings' or diag explain $f;
    is Exec::Doctor::exit_status($f), 0, 'exit 0';
};

subtest 'the config directory (T-047/T-065)' => sub {
    my $x = dispatcher();
    my ($old, $new) = ("$x->{root}/etc/ctrl-exec", $x->{dir});

    # Old real, new real: refused by ced and the API; doctor reports it.
    make_path($old);
    spew("$old/ctrl-exec.conf", "cert = x\n");
    spew("$old/ca.key", "K\n");
    my $f = checks($x);
    is_deeply ids($f), ['config-dir'], 'refused: one finding, nothing else checked without --config';
    is $f->[0]{severity}, 'problem', 'a problem';
    like $f->[0]{what}, qr/refuse to start \(exit 78\).* Both hold a CA/, 'says what and why';
    like $f->[0]{fix}, qr/merge it into \Q$new\E, then: sudo rm -r \Q$old\E/, 'fix: merge, remove';
    $f = checks($x, config => $x->{conf});
    is $f->[0]{check}, 'config-dir', 'with --config: reported ...';
    is scalar @$f, 1, '... and the named config checked (clean)';

    # Old real, new absent: in place, a note; the installers move it.
    my $y = dispatcher();
    rename $y->{dir}, "$y->{root}/etc/ctrl-exec" or die;
    my $conf = "$y->{root}/etc/ctrl-exec/ctrl-exec.conf";
    spew($conf, slurp($conf) =~ s{/etc/ctrl-exec-dispatcher/}{/etc/ctrl-exec/}gr);
    $f = checks($y);
    my ($n) = by_check($f, 'config-dir-in-place');
    ok $n, 'in place: reported';
    is $n->{severity}, 'note', 'a note: it works';
    like $n->{what}, qr/still at \S+\/etc\/ctrl-exec and is used there; it works as it is/, 'says it works';
    like $n->{fix}, qr/^sudo \.\/install\.sh --dispatcher .*leaves a symlink/, 'tarball: re-run install.sh';
    is scalar @$f, 1, 'and the config there is checked (clean)' or diag explain $f;
    spew("$y->{root}/dpkg-info", '');
    ($n) = by_check(checks($y), 'config-dir-in-place');
    like $n->{fix}, qr/^sudo dpkg-reconfigure ctrl-exec-dispatcher/, 'packages: dpkg-reconfigure';
    make_path("$y->{root}/etc/ctrl-exec-dispatcher.seeded");
    ($n) = by_check(checks($y), 'config-dir-in-place');
    like $n->{fix}, qr/^sudo rm -r \S+\.seeded, then: sudo dpkg-reconfigure/, 'a leftover .seeded is named first';

    {
        no warnings 'redefine';
        local $Exec::DispatcherConfig::IS_MOUNT = sub { 1 };
        ($n) = by_check(checks($y), 'config-dir-in-place');
        like $n->{what}, qr/is a mount at/, 'a mount: says so';
        like $n->{fix}, qr/^mount the volume at \S+\/etc\/ctrl-exec-dispatcher instead/, 'fix: remount';
    }
};

subtest 'ctrl-exec.conf, fresh install, CA and certificate' => sub {
    my $x = dispatcher();
    spew($x->{conf}, "cert = /x\n");
    my $f = checks($x);
    is_deeply ids($f), ['config'], 'unloadable: a finding';
    is $f->[0]{severity}, 'problem', 'a problem';

    $x = dispatcher();
    unlink "$x->{dir}/ca.crt", "$x->{dir}/dispatcher.crt";
    $f = checks($x);
    is_deeply ids($f), ['not-set-up'], 'no CA, no certificate, no agent: a fresh install';
    is $f->[0]{severity}, 'note', 'a note';
    like $f->[0]{fix}, qr/setup-ca, then: sudo ctrl-exec-dispatcher setup-ctrl-exec/, 'fix: set up';

    agent_record($x, 'agent-01', expiry_in_days(200));
    $f = checks($x);
    is_deeply [ sort @{ ids($f) } ], [qw(ca-cert dispatcher-cert)], 'with an agent registered: two problems';
    like((by_check($f, 'ca-cert'))[0]{fix}, qr/restore it from a backup/, 'the CA: restore it');

    $x = dispatcher(days => 10);
    ($f) = by_check(checks($x), 'dispatcher-cert-expiry');
    ok $f && $f->{severity} eq 'problem', 'certificate expiring in 10 days: a problem';
    is $f->{fix}, 'sudo ctrl-exec-dispatcher rotate-cert', 'fix: rotate';

    $x = dispatcher(days => 10, conf => "cert_renewal_days = 5\n");
    ok !by_check(checks($x), 'dispatcher-cert-expiry'), 'not yet due with cert_renewal_days = 5';

    # T-068: a certificate issued before 0.14 on an OpenSSL 1.1 host.
    $x = dispatcher(aki => 0);
    agent_record($x, 'agent-01', expiry_in_days(200));
    $f = checks($x);
    is_deeply ids($f), ['dispatcher-cert-no-aki'], 'a certificate without an AKI: one finding';
    is $f->[0]{severity}, 'note', 'a note: it works with every agent but one case';
    like $f->[0]{what}, qr/\Qpredates 0.14: it has no Authority Key Identifier, so an agent that\E
                          \Q also trusts another CA with the same name\E/x, 'says why it matters';
    like $f->[0]{fix}, qr/\Asudo ctrl-exec-dispatcher rotate-cert\b/, 'fix: rotate';
    is Exec::Doctor::exit_status($f), 0, 'exit 0';
};

subtest 'the auth hook' => sub {
    my $x = dispatcher();
    my $hook = "$x->{dir}/auth-hook";
    spew($x->{conf}, slurp($x->{conf}) . "auth_hook = $hook\n");

    my ($f) = by_check(checks($x), 'auth-hook-missing');
    ok $f && $f->{severity} eq 'problem', 'a missing hook: a problem';

    spew($hook, "#!/bin/sh\nexit 0\n");
    ($f) = by_check(checks($x), 'auth-hook-not-executable');
    ok $f, 'not executable: reported';
    is $f->{fix}, "sudo chmod 755 $hook", 'fix: chmod';

    chmod 0755, $hook;
    ($f) = by_check(checks($x), 'auth-hook-allow-all');
    ok $f && $f->{severity} eq 'problem', 'exit 0 only: allow-all, a problem';
    like $f->{fix}, qr/sudoedit \S+auth-hook; or comment out auth_hook/, 'fix: real rules, or no hook';

    spew($hook, slurp("$Bin/../etc/auth-hook.example"));
    ok by_check(checks($x), 'auth-hook-allow-all'), 'the shipped example is allow-all';

    spew($hook, "#!/bin/sh\n[ \"\$ENVEXEC_TOKEN\" = secret ] || exit 1\nexit 0\n");
    is_deeply ids(checks($x)), [], 'a hook with a rule: nothing to say';

    ok Exec::Doctor::Dispatcher::hook_allows_all("#!/bin/bash\n# x\n\n  exit 0 ;\n"), 'exit 0 with spacing';
    ok Exec::Doctor::Dispatcher::hook_allows_all("#!/bin/sh\ntrue\n"), 'true';
    ok !Exec::Doctor::Dispatcher::hook_allows_all("#!/bin/sh\nexit 1\n"), 'exit 1 is not';
};

subtest 'the API listener and socket; --fix restores mode and group, once' => sub {
    my $x = dispatcher(conf => "api_port = off\n");
    my ($f) = by_check(checks($x), 'api-config');
    ok $f && $f->{severity} eq 'problem', 'no listener: ctrl-exec-api refuses to start, a problem';
    like $f->{what}, qr/no API listener configured/, 'with the API\'s own reason';

    my $sock = "$x->{dir}/api.sock";
    my $gid  = (split ' ', $))[0];
    spew($x->{conf}, slurp($x->{conf}) . "api_socket = $sock\napi_socket_group = $gid\n");
    ($f) = by_check(checks($x), 'api-socket-absent');
    ok $f && $f->{severity} eq 'note', 'no socket: a note (the API is not running)';

    my $srv = IO::Socket::UNIX->new(Local => $sock, Listen => 1) or die "socket: $!";
    chmod 0666, $sock;
    my $all = checks($x);
    ($f) = by_check($all, 'api-socket-mode');
    ok $f && $f->{severity} eq 'problem', 'mode 0666: a problem';
    like $f->{what}, qr/mode 0666: every local user can call the API/, 'says why';
    ok $f->{autofix}, 'automatic with --fix';
    Exec::Doctor::apply_fixes($all);
    ok $f->{fixed}, 'fixed';
    is((stat $sock)[2] & 07777, 0660, 'the socket is 0660 again');
    my $again = checks($x);
    is_deeply ids($again), [], 'nothing left';
    Exec::Doctor::apply_fixes($again);
    is((stat $sock)[2] & 07777, 0660, 'a second --fix changes nothing');

    my ($other) = grep { $_ != $gid } split ' ', $);
    SKIP: {
        skip 'this user is in one group only', 3 unless defined $other;
        chown -1, $other, $sock or skip "chgrp: $!", 3;
        $all = checks($x);
        ($f) = by_check($all, 'api-socket-group');
        ok $f && $f->{severity} eq 'problem', 'another group: a problem';
        Exec::Doctor::apply_fixes($all);
        is((stat $sock)[5], $gid, '--fix gives it api_socket_group again');
        is_deeply ids(checks($x)), [], 'nothing left';
    }
    close $srv;
};

subtest 'the registry: agents another dispatcher\'s CA issued, expired agents' => sub {
    my $x = dispatcher();
    my $fpr = 'ab' x 32;
    agent_record($x, 'pinned-soon', expiry_in_days(10), agent_ca_fpr => $fpr, agent_ca => 'PEM');
    agent_record($x, 'pinned-later', expiry_in_days(200), agent_ca_fpr => $fpr, agent_ca => 'PEM');
    agent_record($x, 'own-expired', expiry_in_days(-3));
    agent_record($x, 'own-soon', expiry_in_days(10));
    my $f = checks($x);
    is_deeply [ sort @{ ids($f) } ], [qw(agent-cert-expired agent-cert-pinned-expiry)],
        'the pinned agent expiring soon and the expired one; the others are fine (this dispatcher renews its own)';
    my ($p) = by_check($f, 'agent-cert-pinned-expiry');
    is $p->{severity}, 'problem', 'pinned within 30 days: a problem';
    like $p->{what}, qr/Agent 'pinned-soon' keeps a certificate issued by another dispatcher's CA \(SHA256:\Q$fpr\E\)/,
        'names the agent and the CA';
    like $p->{fix}, qr/maintain there.*--rekey/, 'fix: renew there, or re-key here';
    like((by_check($f, 'agent-cert-expired'))[0]{what}, qr/'own-expired'/, 'the expired one named');
};

sub ced {
    my ($x, @args) = @_;
    my @cmd = ($^X, "-I$Bin/../lib", "-I$Bin/lib", '-MNoSyslog', "$Bin/../bin/ctrl-exec-dispatcher",
               '--config', $x->{conf}, @args);
    open my $p, '-|', "@cmd 2>/dev/null" or die "run: $!";
    local $/;
    my $out = <$p> // '';
    close $p;
    return ($out, $? >> 8);
}

subtest 'CLI' => sub {
    my $x = dispatcher();
    my ($out, $rc) = ced($x, 'doctor');
    is $rc, 0, 'clean: exit 0' or diag $out;
    is $out, "ctrl-exec-dispatcher doctor: no problems.\n", 'one line';

    spew($x->{conf}, slurp($x->{conf}) . "auth_hook = $x->{dir}/none\n");
    ($out, $rc) = ced($x, 'doctor');
    is $rc, 1, 'a problem: exit 1';
    like $out, qr/^PROBLEM  auth_hook names .* Fix: /m, 'one line with its fix';
    ($out, $rc) = ced($x, 'doctor', '--json');
    is decode_json($out)->{findings}[0]{check}, 'auth-hook-missing', '--json: stdout is the JSON';
    ($out, $rc) = ced($x, 'doctor', 'extra');
    is $rc, 2, 'usage: exit 2';
};

SKIP: {
    skip 'root reads every file', 1 unless $>;
    subtest 'unprivileged: what it cannot read is a note' => sub {
        my $x = dispatcher();
        chmod 0, $x->{conf};
        my $f = checks($x);
        is_deeply ids($f), ['access'], 'one note';
        like $f->[0]{what}, qr/Could not read \S+ctrl-exec\.conf \(permission denied\)/, 'says what';
        is Exec::Doctor::exit_status($f), 0, 'exit 0';
        chmod 0600, $x->{conf};
    };
}

done_testing;
