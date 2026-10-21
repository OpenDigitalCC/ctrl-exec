#!/usr/bin/perl
# t/agent-script-ownership.t  (T-045, T-054)
#
# The front end applies the script ownership rule (script and every directory
# on its path owned by root, not group- or other-writable, script a regular
# file) at allowlist load.
#
# With script_ownership = strict (T-045) a breaking entry is skipped with the
# reason, which a run reports as "script not permitted: <reason>" and
# self-check lists - and the rule is applied again before each run, so a script
# that changed after load is refused and, without an executor, never run.
#
# With script_ownership = warn (T-054, the default) the entry stays allowlisted
# and runs; the reason is logged once per allowlist load and shown by
# self-check next to the script, and never appears in a run's output.
#
# Unprivileged: the test user cannot create root-owned files, so the rule's test
# seam trusts the test user like root (@TRUSTED_OWNERS) and leaves the
# tempdir's ancestors (/tmp, world-writable) unchecked ($TRUSTED_TOP). Setting
# @TRUSTED_OWNERS back to (0) shows the "owned by uid N, not root" reason. The
# root-owned cases end to end, through the executor, are in
# t/exec-ownership-root.t; parity with the executor is t/exec-ownership-parity.t.
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use FindBin    qw($Bin);
use lib "$Bin/../lib";
use IO::Socket::UNIX qw();
use JSON::PP qw(decode_json);

use Exec::Agent::Config qw();
use Exec::Agent::Server qw();
use Exec::Log           qw();

Exec::Log::init('test');
my @LOG;
{
    no warnings 'redefine';
    *Exec::Log::log_action = sub { push @LOG, [ $_[0], { %{ $_[1] } } ] };
}

umask 022;
my $dir = tempdir(CLEANUP => 1);
@Exec::Agent::Config::TRUSTED_OWNERS = (0, $>);
$Exec::Agent::Config::TRUSTED_TOP    = $dir;

sub write_file { my ($p, $c) = @_; open my $fh, '>', $p or die "$p: $!"; print $fh $c; close $fh }

my $marker = "$dir/ran";
mkdir "$dir/s"  or die;
mkdir "$dir/ww" or die; chmod 01777, "$dir/ww";
for my $f ("$dir/s/ok.sh", "$dir/s/gw.sh", "$dir/s/late.sh", "$dir/ww/x.sh") {
    write_file($f, "#!/bin/sh\necho ran >> '$marker'\nexit 0\n");
    chmod 0755, $f;
}
chmod 0775, "$dir/s/gw.sh";
symlink "$dir/ww/x.sh", "$dir/s/link.sh";

my $allow = "$dir/scripts.conf";
write_file($allow, join '', map { "$_\n" }
    "ok    = $dir/s/ok.sh",
    "gw    = $dir/s/gw.sh",
    "ww    = $dir/ww/x.sh",
    "link  = $dir/s/link.sh",
    "late  = $dir/s/late.sh",
    "ghost = $dir/s/not-installed.sh",
);

my ($allowlist, $skipped);
{
    local $SIG{__WARN__} = sub {};
    ($allowlist, $skipped) = Exec::Agent::Config::load_allowlist_full(
        $allow, ["$dir/s", "$dir/ww"], 'strict');
}

subtest 'strict load: entries that break the rule are skipped with the reason' => sub {
    ok exists $allowlist->{ok},   'a correctly owned script is kept';
    ok exists $allowlist->{late}, 'so is one that passes at load';
    is $skipped->{gw},   "'$dir/s/gw.sh' is group-writable",  'group-writable script';
    is $skipped->{ww},   "'$dir/ww' is world-writable",       'script under a world-writable directory';
    is $skipped->{link}, "'$dir/ww' is world-writable",       'a link is followed and its target checked';
    ok exists $allowlist->{ghost},
        'a script not installed yet gives no verdict at load (the run fails, or the executor decides)';
};

subtest 'load: a script owned by another user' => sub {
    plan skip_all => 'running as root: the test files are root-owned' if $> == 0;
    local @Exec::Agent::Config::TRUSTED_OWNERS = (0);
    local $SIG{__WARN__} = sub {};
    my (undef, $sk) = Exec::Agent::Config::load_allowlist_full($allow, ["$dir/s", "$dir/ww"], 'strict');
    is $sk->{ok}, "'$dir' is owned by uid $>, not root",
        'the first directory not owned by root is named';
};

# Drive a run request through the real handler (direct mode: no executor).
sub run_reply {
    my ($name, $config, $al, $sk) = @_;
    $config //= { script_ownership => 'strict' };
    my $body = '{"script":"' . $name . '","args":[]}';
    my ($client, $server) = IO::Socket::UNIX->socketpair(
        IO::Socket::AF_UNIX(), IO::Socket::SOCK_STREAM(), 0) or die "socketpair: $!";
    print $client "POST /run HTTP/1.0\r\nContent-Length: " . length($body) . "\r\n\r\n$body";
    $client->shutdown(1);
    Exec::Agent::Server::handle_connection(
        $server, '10.0.0.5', $al // $allowlist, $config, {},
        { deadbeef => 'disp-1' }, 'deadbeef', {}, '9.9.9', $sk // $skipped,
    );
    $server->close;
    local $/;
    my $resp = <$client> // '';
    $client->close;
    $resp =~ s/\A.*?\r\n\r\n//s;
    return decode_json($resp);
}

subtest 'run: a skipped script says why and does not run' => sub {
    unlink $marker;
    my $r = run_reply('gw');
    is $r->{exit}, -1, 'exit -1';
    is $r->{error}, "script not permitted: '$dir/s/gw.sh' is group-writable", 'reason';
    ok !-e $marker, 'the script did not run';
};

subtest 'run: a correctly owned script runs' => sub {
    unlink $marker;
    my $r = run_reply('ok');
    is $r->{exit}, 0, 'exit 0';
    ok -e $marker, 'the script ran';
};

subtest 'run: a script that changed after load is refused at run time' => sub {
    unlink $marker;
    chmod 0777, "$dir/s/late.sh";
    my $r = run_reply('late');
    chmod 0755, "$dir/s/late.sh";
    is $r->{exit}, -1, 'exit -1';
    is $r->{error}, "script not permitted: '$dir/s/late.sh' is world-writable", 'reason';
    ok !-e $marker, 'the script did not run';

    # and a directory on its path made writable after load
    chmod 0775, "$dir/s";
    $r = run_reply('late');
    chmod 0755, "$dir/s";
    is $r->{error}, "script not permitted: '$dir/s' is group-writable", 'directory reason';
    ok !-e $marker, 'the script did not run';
};

# self-check through the real modulino, with the same seam as above.
sub self_check {
    my ($mode_line) = @_;
    my $conf = "$dir/agent.conf";
    write_file($conf, "port = 7443\ncert = /c.crt\nkey = /c.key\nca = /ca.crt\n"
                    . "script_dirs = $dir/s:$dir/ww\n${mode_line}[profile default]\n");
    my $agent = "$Bin/../bin/ctrl-exec-agent";
    my $seam = '@Exec::Agent::Config::TRUSTED_OWNERS = (0, $>);'
             . '$Exec::Agent::Config::TRUSTED_TOP = shift;'
             . 'my $a = shift; do $a or die $@ || $!; main()';
    my $cmd = join ' ', map { "'$_'" } $^X, "-I$Bin/../lib", '-MExec::Agent::Config',
                                        '-e', $seam, $dir, $agent, '--config', $conf,
                                        '--allowlist', $allow, 'self-check';
    return scalar `$cmd 2>/dev/null`;
}

subtest 'strict self-check lists the skipped entries with their reasons' => sub {
    my $out = self_check("script_ownership = strict\n");
    like $out, qr{Script ownership: strict}, 'the mode is shown';
    like $out, qr{Script 'gw': SKIPPED - '\Q$dir\E/s/gw\.sh' is group-writable}, 'group-writable listed';
    like $out, qr{Script 'ww': SKIPPED - '\Q$dir\E/ww' is world-writable},       'world-writable dir listed';
    unlike $out, qr{Script 'ok': SKIPPED}, 'a correctly owned script is not listed as skipped';
};

# ---- script_ownership = warn (T-054, the default) ----------------------------

my ($wal, $wsk, @wwarn);
{
    local $SIG{__WARN__} = sub { push @wwarn, $_[0] };
    ($wal, $wsk) = Exec::Agent::Config::load_allowlist_full($allow, ["$dir/s", "$dir/ww"]);
}

subtest 'warn load (the default): breaking entries stay allowlisted, with the reason' => sub {
    is_deeply [ sort keys %$wsk ], [], 'nothing is skipped';
    ok exists $wal->{$_}, "'$_' is allowlisted" for qw(ok gw ww link late ghost);
    is $wal->{gw}{ownership_warning},   "'$dir/s/gw.sh' is group-writable", 'gw carries the reason';
    is $wal->{ww}{ownership_warning},   "'$dir/ww' is world-writable",      'ww carries the reason';
    is $wal->{link}{ownership_warning}, "'$dir/ww' is world-writable",      'link carries the reason';
    ok !exists $wal->{ok}{ownership_warning}, 'a correctly owned script carries none';
    ok( (grep { /'gw' - '\Q$dir\E\/s\/gw\.sh' is group-writable; running anyway \(script_ownership = warn\)/ } @wwarn),
        'the load warning says it runs anyway' );

    local $SIG{__WARN__} = sub {};
    my (undef, $sk2) = Exec::Agent::Config::load_allowlist_full($allow, ["$dir/s", "$dir/ww"], 'warn');
    is_deeply $sk2, {}, "explicit 'warn' is the same";
};

subtest 'warn: the reason is logged once per load as a WARNING' => sub {
    @LOG = ();
    Exec::Agent::Config::log_ownership_warnings($wal);
    my @own = grep { $_->[1]{ACTION} eq 'script-ownership' } @LOG;
    is_deeply [ map { $_->[1]{SCRIPT} } @own ], [qw(gw link ww)], 'one line per breaking script';
    is $own[0][0], 'WARNING', 'at WARNING';
    is $own[0][1]{REASON}, "'$dir/s/gw.sh' is group-writable", 'with the reason';
};

subtest 'warn: a breaking script runs; the warning is not in its output nor logged per run' => sub {
    @LOG = ();
    for my $name (qw(gw ww link)) {
        unlink $marker;
        my $r = run_reply($name, {}, $wal, $wsk);
        is $r->{exit}, 0, "'$name' exit 0" or diag explain $r;
        ok -e $marker, "'$name' ran";
        unlike( ($r->{stdout} // '') . ($r->{stderr} // '') . ($r->{error} // ''),
                qr/writable|script_ownership|warning/i, "'$name': no warning in the run's output");
    }
    ok !(grep { $_->[1]{ACTION} eq 'script-ownership' } @LOG), 'no ownership line logged per run';

    # A script that breaks the rule only after load runs too (no run-time re-check).
    unlink $marker;
    chmod 0777, "$dir/s/late.sh";
    my $r = run_reply('late', { script_ownership => 'warn' }, $wal, $wsk);
    chmod 0755, "$dir/s/late.sh";
    is $r->{exit}, 0, 'a script made world-writable after load runs';
    ok -e $marker, 'it ran';
};

subtest 'warn self-check shows the warning next to the script' => sub {
    for my $mode_line ('', "script_ownership = warn\n") {
        my $out = self_check($mode_line);
        like $out, qr{Script ownership: warn}, 'the mode is shown';
        like $out, qr{Script 'gw': \Q$dir\E/s/gw\.sh  \(profile: default\) \[ok\] \[warning: '\Q$dir\E/s/gw\.sh' is group-writable\]},
            'gw is listed with its warning';
        like $out, qr{Script 'ww': \S+ .*\[warning: '\Q$dir\E/ww' is world-writable\]}, 'ww is listed with its warning';
        like $out, qr{Script 'ok': \S+  \(profile: default\) \[ok\]\n}, 'ok has no warning';
        unlike $out, qr{SKIPPED}, 'nothing is skipped';
    }
};

subtest 'a bad script_ownership value is a config error' => sub {
    my $conf = "$dir/bad.conf";
    write_file($conf, "port = 7443\ncert = /c\nkey = /k\nca = /a\nscript_ownership = off\n");
    my $c = eval { Exec::Agent::Config::load_config($conf) };
    like $@, qr{Invalid script_ownership 'off' in '\Q$conf\E' \(expected warn or strict\)}, 'refused with the value';
    write_file($conf, "port = 7443\ncert = /c\nkey = /k\nca = /a\n");
    is Exec::Agent::Config::load_config($conf)->{script_ownership}, 'warn', 'absent is warn';
};

done_testing;
