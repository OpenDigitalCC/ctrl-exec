#!/usr/bin/perl
# t/exec-privilege-root.t  (TC-001)
#
# Behaviour test for the executor's PRIVILEGE-APPLICATION path - the cap
# bounding-set drop, run_as setgid/setuid, capability set, ambient raise and
# no_new_privileges in apply_profile(). These steps only run as root with
# CAP_SYS_ADMIN, so the normal offline suite (which runs the binary in
# allow_unpriv/non-root mode) never exercises them: a regression in the privilege
# drop would hand an action MORE privilege than the front-end authorised and no
# offline test would fail. Run this as root to actually verify the drop:
#
#     sudo prove -Ilib t/exec-privilege-root.t
#     (or: sudo bash tmp/run-exec-privilege-check.sh  -> captures to a file)
#
# It compiles the executor, runs a probe script under a profile, and asserts the
# probe really ran as the configured uid/gid holding EXACTLY the declared caps.

use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use FindBin    qw($Bin);
use lib "$Bin/../lib";
use POSIX qw();

use Exec::Agent::ExecClient qw();

plan skip_all => 'must run as root (the executor privilege-drop path)' unless $> == 0;

my $cc = `command -v gcc 2>/dev/null`; chomp $cc;
plan skip_all => 'gcc not available' unless $cc && -x $cc;

my @nobody = getpwnam('nobody');
plan skip_all => 'no "nobody" user to drop to' unless @nobody;
my ($nobody_uid, $nobody_gid) = @nobody[2, 3];

# CAP_NET_BIND_SERVICE is capability number 10 -> bit 10 -> 0x400. The executor
# drops the bounding set to exactly the declared caps and raises them ambient so
# they survive the setuid, so every cap mask we read back must be exactly this.
my $CAP_NBS_HEX = '0000000000000400';
my $CAP_NONE    = '0000000000000000';

# A tempdir nobody can traverse+exec under (default tempdir mode is 0700).
my $TMP = tempdir(DIR => '/var/tmp', CLEANUP => 1);
chmod 0755, $TMP;
my $BIN = "$TMP/ctrl-exec-exec";
system($cc, '-O2', '-o', $BIN, "$Bin/../src/ctrl-exec-exec.c", '-lcap') == 0
    or plan skip_all => 'could not compile the executor';

# Probe: report the identity and capability state the action actually runs with.
my $probe = "$TMP/probe.sh";
open my $p, '>', $probe or die $!;
print $p <<'SH';
#!/bin/sh
echo "UID=$(id -u)"
echo "GID=$(id -g)"
grep -E '^(CapEff|CapPrm|CapBnd|CapAmb|NoNewPrivs):' /proc/self/status \
    | sed 's/:[[:space:]]*/=/'
SH
close $p;
chmod 0755, $probe;

# Helper: write a config with one profile and serve it, run the probe, return
# the parsed key=value output (or undef if the run produced nothing).
sub run_under_profile {
    my (%opt) = @_;
    my $prof_body = $opt{profile_body};
    my $label     = $opt{label};

    my $agent_conf = "$TMP/agent.$label.conf";
    open my $a, '>', $agent_conf or die $!;
    print $a "port = 7443\ncert = /x\nkey = /y\nca = /z\nscript_dirs = $TMP\n"
           . "[profile $label]\n$prof_body";
    close $a;

    my $scripts_conf = "$TMP/scripts.$label.conf";
    open my $s, '>', $scripts_conf or die $!;
    print $s "probe = $probe profile=$label\n";
    close $s;

    my $sock = "$TMP/exec.$label.sock";
    my $pid  = fork();
    die "fork: $!" unless defined $pid;
    if ($pid == 0) {
        # Silence the executor's own stderr so a deliberate config rejection does
        # not clutter the TAP stream.
        open STDERR, '>', "$TMP/serve.$label.err";
        exec($BIN, 'serve', $sock, $agent_conf, $scripts_conf, 'root')
            or POSIX::_exit(127);
    }

    my $ready = 0;
    for (1 .. 100) { if (-S $sock) { $ready = 1; last } select undef, undef, undef, 0.05 }
    unless ($ready) {
        # Serve never came up - e.g. the config was rejected. Fail-closed.
        kill 'TERM', $pid; waitpid $pid, 0;
        return { _no_serve => 1 };
    }

    my $r = Exec::Agent::ExecClient::run(
        socket => $sock, reqid => "p-$label", script => 'probe', args => []);
    kill 'TERM', $pid; waitpid $pid, 0;

    my %kv;
    for my $line (split /\n/, ($r->{stdout} // '')) {
        $kv{$1} = $2 if $line =~ /^(\w+)=(.+)$/;
    }
    return \%kv;
}

subtest 'run_as + caps: action runs as the configured user with exactly the declared caps' => sub {
    my $kv = run_under_profile(
        label        => 'dropped',
        profile_body => "run_as = nobody\ncaps = CAP_NET_BIND_SERVICE\n",
    );
    ok !$kv->{_no_serve}, 'executor served the profile' or return;

    is $kv->{UID}, $nobody_uid, "action runs as nobody uid ($nobody_uid)";
    is $kv->{GID}, $nobody_gid, "action runs as nobody gid ($nobody_gid)";
    is $kv->{CapBnd}, $CAP_NBS_HEX, 'bounding set dropped to exactly CAP_NET_BIND_SERVICE';
    is $kv->{CapEff}, $CAP_NBS_HEX, 'effective set is exactly the declared cap';
    is $kv->{CapPrm}, $CAP_NBS_HEX, 'permitted set is exactly the declared cap';
    is $kv->{CapAmb}, $CAP_NBS_HEX, 'ambient set raised so the cap survives setuid';
    is $kv->{NoNewPrivs}, '1', 'no_new_privileges is set';
};

subtest 'default-shaped profile: unprivileged user, no capabilities at all' => sub {
    my $kv = run_under_profile(
        label        => 'plain',
        profile_body => "run_as = nobody\n",
    );
    ok !$kv->{_no_serve}, 'executor served the profile' or return;

    is $kv->{UID}, $nobody_uid, 'action runs as nobody';
    is $kv->{CapBnd}, $CAP_NONE, 'bounding set is empty';
    is $kv->{CapEff}, $CAP_NONE, 'effective set is empty';
    is $kv->{CapAmb}, $CAP_NONE, 'ambient set is empty';
    is $kv->{NoNewPrivs}, '1', 'no_new_privileges is set';
};

subtest 'out-of-range numeric run_as is refused, never truncated to root' => sub {
    # 4294967296 = 2^32: truncates to uid 0 (root) under a 32-bit uid_t. The
    # executor must reject it (at config load or apply), not run the action as
    # root. Either the serve refuses to start, or the action never runs as uid 0.
    my $kv = run_under_profile(
        label        => 'oob',
        profile_body => "run_as = 4294967296\n",
    );
    if ($kv->{_no_serve}) {
        pass 'executor refused to serve a profile with an out-of-range run_as (fail-closed)';
        return;
    }
    isnt $kv->{UID}, '0',
        'out-of-range run_as did NOT silently truncate to root (uid 0)';
};

subtest 'unannotated script with no [profile default] is refused, never run as root' => sub {
    # The no-built-in-default guarantee: a script with no profile= resolves to
    # the name 'default'; with no [profile default] defined it must be refused,
    # NOT run under an implicit root context.
    my $agent_conf = "$TMP/agent.nodef.conf";
    open my $a, '>', $agent_conf or die $!;
    print $a "port = 7443\ncert = /x\nkey = /y\nca = /z\nscript_dirs = $TMP\n";  # no [profile default]
    close $a;
    my $scripts_conf = "$TMP/scripts.nodef.conf";
    open my $s, '>', $scripts_conf or die $!;
    print $s "probe = $probe\n";   # no profile= -> resolves to 'default'
    close $s;

    my $sock = "$TMP/exec.nodef.sock";
    my $pid  = fork();
    die "fork: $!" unless defined $pid;
    if ($pid == 0) {
        open STDERR, '>', "$TMP/serve.nodef.err";
        exec($BIN, 'serve', $sock, $agent_conf, $scripts_conf, 'root') or POSIX::_exit(127);
    }
    my $ready = 0;
    for (1 .. 100) { if (-S $sock) { $ready = 1; last } select undef, undef, undef, 0.05 }
    my $r = $ready
        ? Exec::Agent::ExecClient::run(socket => $sock, reqid => 'nodef', script => 'probe', args => [])
        : undef;
    kill 'TERM', $pid; waitpid $pid, 0;

    my $out = ($r && defined $r->{stdout}) ? $r->{stdout} : '';
    my $err = $r ? (($r->{stderr} // '') . ($r->{error} // '')) : '';
    unlike $out, qr/UID=/, 'the unannotated script did not run (no implicit profile)';
    unlike $out, qr/UID=0/, 'and most importantly did NOT run as root';
    like $err, qr/undefined profile/, 'executor reports the undefined profile';
};

done_testing;
