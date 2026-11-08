#!/usr/bin/perl
# t/agent-script-path.t  (T-074)
#
# script_path in agent.conf at the agent (direct runs, no executor): the
# syntax rule, the default when unset, the fallback and warning when invalid
# (the agent still starts), the PATH a direct run and an async run get, that
# a reload follows a change, and that nothing from the request or the
# agent's own environment reaches PATH. The executor side is
# t/exec-script-path.t; the two parsers are compared in t/exec-conformance.t.

use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use FindBin    qw($Bin);
use lib "$Bin/../lib";
use IO::Socket::UNIX qw();
use JSON::PP ();

use Exec::Agent::Config      qw();
use Exec::Agent::Runner      qw();
use Exec::Agent::AsyncRunner qw();
use Exec::Agent::Server      qw();
use Exec::Log                qw();

my @logs;
{
    no warnings 'redefine';
    *Exec::Log::log_action = sub { push @logs, { level => $_[0], %{ $_[1] } } };
}

my $DEFAULT = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin';
my $NIXOS   = '/run/wrappers/bin:/run/current-system/sw/bin';

my $dir = tempdir(CLEANUP => 1);
umask 022;
@Exec::Agent::Config::TRUSTED_OWNERS = (0, $>);
$Exec::Agent::Config::TRUSTED_TOP    = $dir;
sub write_file { my ($p, $c) = @_; open my $fh, '>', $p or die "$p: $!"; print $fh $c; close $fh }
sub slurp { open my $fh, '<', $_[0] or return ''; local $/; scalar <$fh> }

my $REQUIRED = "port = 7443\ncert = /x\nkey = /y\nca = /z\n";
sub conf {
    my ($extra) = @_;
    my $p = "$dir/agent.conf";
    write_file($p, $REQUIRED . $extra);
    @logs = ();
    return Exec::Agent::Config::load_config($p);
}

# --- the rule -----------------------------------------------------------------

is Exec::Agent::Config::DEFAULT_SCRIPT_PATH(), $DEFAULT, 'the default is the fixed PATH of 0.14.0';

my @valid = ('/usr/bin', $NIXOS, "$NIXOS:/usr/bin:/bin", '/', '/opt/a-b/c_d/e.f/g+h',
             '/usr//bin', '/opt/..x/.y', '/' . ('a' x 4089));
for my $v (@valid) {
    is scalar(Exec::Agent::Config::script_path_problem($v)), undef,
        'valid: ' . (length $v > 60 ? substr($v, 0, 20) . '... (' . length($v) . ' bytes)' : $v);
}
my @invalid = (
    ['',                  'entry 1 is empty'],
    [':',                 'entry 1 is empty'],
    [':/usr/bin',         'entry 1 is empty'],
    ['/usr/bin:',         'entry 2 is empty'],
    ['/usr/bin::/bin',    'entry 2 is empty'],
    ['bin',               'entry 1 is not an absolute path'],
    ['/usr/bin:.',        'entry 2 is not an absolute path'],
    ['/usr/bin:~/bin',    'entry 2 has a character outside A-Z a-z 0-9 / . _ + -'],
    ['/opt/./bin',        'entry 1 has a . or .. component'],
    ['/opt/bin/..',       'entry 1 has a . or .. component'],
    ['/usr/my bin',       'entry 1 has a character outside A-Z a-z 0-9 / . _ + -'],
    ["/usr/bin\t",        'entry 1 has a character outside A-Z a-z 0-9 / . _ + -'],
    ['/opt/$HOME/bin',    'entry 1 has a character outside A-Z a-z 0-9 / . _ + -'],
    ["/srv/caf\xc3\xa9",  'entry 1 has a character outside A-Z a-z 0-9 / . _ + -'],
    ['/' . ('a' x 4090),  'longer than 4090 bytes'],
);
for my $c (@invalid) {
    my ($v, $why) = @$c;
    (my $show = $v) =~ s/[^\x21-\x7e]/?/g;
    $show = substr($show, 0, 20) . '...' if length $show > 60;
    is scalar(Exec::Agent::Config::script_path_problem($v)), $why, "invalid: '$show' - $why";
}
is Exec::Agent::Config::SCRIPT_PATH_MAX(), 4090,
    'the bound: "PATH=" + value + NUL fill the executor\'s 4096-byte (VALLEN) buffer';

# --- load_config ----------------------------------------------------------------

subtest 'load: unset is the default, set is used, invalid falls back with a warning' => sub {
    my $c = conf('');
    is Exec::Agent::Config::script_path($c), $DEFAULT, 'unset: the default';
    is scalar(grep { ($_->{ACTION} // '') eq 'config-warn' } @logs), 0, 'unset: no warning';

    $c = conf("script_path = $NIXOS\n");
    is Exec::Agent::Config::script_path($c), $NIXOS, 'set: the value';
    is scalar(grep { ($_->{ACTION} // '') eq 'config-warn' } @logs), 0, 'valid: no warning';

    $c = conf("script_path =   $NIXOS:/usr/bin   \n");
    is Exec::Agent::Config::script_path($c), "$NIXOS:/usr/bin", 'padded: trimmed like any value';

    $c = conf("script_path = /usr/bin\nscript_path = /bin\n");
    is Exec::Agent::Config::script_path($c), '/bin', 'the last value wins';

    $c = conf("[tags]\nscript_path = /evil\n");
    is Exec::Agent::Config::script_path($c), $DEFAULT, 'in [tags] it is a tag, not the setting';

    $c = conf("script_path = usr/bin:/bin\n");
    ok $c, 'invalid: the config still loads (report, do not break)';
    is Exec::Agent::Config::script_path($c), $DEFAULT, 'invalid: the default';
    my @w = grep { ($_->{ACTION} // '') eq 'config-warn' } @logs;
    is scalar @w, 1, 'invalid: one warning';
    is $w[0]{level}, 'WARNING', 'at WARNING';
    is $w[0]{KEY}, 'script_path', 'names the key';
    is $w[0]{MSG}, 'invalid script_path (entry 1 is not an absolute path) - using the default PATH',
        'says why and what is used';
};

subtest 'reload: script_path follows a change of agent.conf' => sub {
    my $p = "$dir/agent.conf";
    my $old = conf('');
    write_file("$dir/empty.conf", '');
    write_file($p, $REQUIRED . "script_path = $NIXOS\n");
    my $plan = Exec::Agent::Config::reload_plan($p, "$dir/empty.conf", $old, {}, {});
    is Exec::Agent::Config::script_path($plan->{config}), $NIXOS, 'the reloaded config has the new PATH';
    is_deeply $plan->{notes}, [], 'no restart needed';
};

# --- direct runs --------------------------------------------------------------------

mkdir "$dir/s" or die;
my $probe = "$dir/s/probe.sh";
write_file($probe, "#!/bin/sh\nprintf 'PATH=[%s]\\n' \"\$PATH\"\n");
chmod 0755, $probe;
sub path_in { my ($out) = @_; my ($p) = ($out // '') =~ /^PATH=\[(.*)\]$/m; return $p }

# The agent's own environment, polluted: it must not reach the script.
local $ENV{PATH} = "/evil/inherited:$ENV{PATH}";

subtest 'run_script: default, or the PATH it is given' => sub {
    my $r = Exec::Agent::Runner::run_script($probe, []);
    is path_in($r->{stdout}), $DEFAULT, 'no PATH given: the default, not the agent\'s own';
    $r = Exec::Agent::Runner::run_script($probe, [], undef, undef, undef, $NIXOS);
    is path_in($r->{stdout}), $NIXOS, 'PATH given: that one';
};

write_file("$dir/scripts.conf", "probe = $probe\nfields = $probe input=fields\n");
my ($allowlist, $skipped);
{
    local $SIG{__WARN__} = sub {};
    ($allowlist, $skipped) = Exec::Agent::Config::load_allowlist_full("$dir/scripts.conf", ["$dir/s"]);
}
mkdir "$dir/tmp" or die;
mkdir "$dir/runs" or die;

my $JSON = JSON::PP->new->canonical;
sub post {
    my ($payload, %cfg) = @_;
    my $body = $JSON->encode($payload);
    my ($client, $server) = IO::Socket::UNIX->socketpair(
        IO::Socket::AF_UNIX(), IO::Socket::SOCK_STREAM(), 0) or die "socketpair: $!";
    print $client "POST /run HTTP/1.0\r\nContent-Length: " . length($body) . "\r\n\r\n$body";
    $client->shutdown(1);
    Exec::Agent::Server::handle_connection(
        $server, '10.0.0.5', $allowlist,
        { script_dirs => ["$dir/s"], input_dir => "$dir/tmp", runs_dir => "$dir/runs", %cfg },
        {}, { deadbeef => 'disp-1' }, 'deadbeef', {}, '9.9.9', $skipped,
    );
    $server->close;
    local $/;
    my $resp = <$client> // '';
    $client->close;
    $resp =~ s/\A.*?\r\n\r\n//s;
    return JSON::PP::decode_json($resp);
}

subtest 'a direct run through the server: the configured PATH; nothing from the request' => sub {
    my $c = conf("script_path = $NIXOS:/usr/bin:/bin\n");
    my $r = post({ script => 'probe', args => [], reqid => 'r1' }, %$c);
    is $r->{exit}, 0, 'ran' or diag explain $r;
    is path_in($r->{stdout}), "$NIXOS:/usr/bin:/bin", 'the configured PATH';

    $r = post({ script => 'probe', args => ['PATH=/evil/arg'], reqid => 'r2', PATH => '/evil/field',
                env => { PATH => '/evil/env' }, username => 'PATH=/evil/user' }, %$c);
    is path_in($r->{stdout}), "$NIXOS:/usr/bin:/bin", 'args and request fields leave PATH alone';

    $r = post({ script => 'fields', args => [], reqid => 'r3', input => { PATH => '/evil/input' } }, %$c);
    is path_in($r->{stdout}), "$NIXOS:/usr/bin:/bin", 'an input field named PATH leaves PATH alone'
        or diag explain $r;

    my $d = conf('');
    $r = post({ script => 'probe', args => [], reqid => 'r4' }, %$d);
    is path_in($r->{stdout}), $DEFAULT, 'unset: the default';

    my $bad = conf("script_path = /usr/bin::/bin\n");
    $r = post({ script => 'probe', args => [], reqid => 'r5' }, %$bad);
    is path_in($r->{stdout}), $DEFAULT, 'invalid: the default';
};

# Poll the result store until the run is done.
sub wait_done {
    my ($reqid) = @_;
    for (1 .. 250) {
        my $r = Exec::Agent::AsyncRunner::result($reqid, "$dir/runs", 'disp-1');
        return $r if $r && ($r->{status} // '') eq 'done';
        select undef, undef, undef, 0.02;
    }
    return Exec::Agent::AsyncRunner::result($reqid, "$dir/runs", 'disp-1');
}

subtest 'an async run: the configured PATH' => sub {
    my $c = conf("script_path = /opt/tools/bin:/usr/bin:/bin\n");
    my $r = post({ script => 'probe', args => ['PATH=/evil'], reqid => 'a1', async => JSON::PP::true },
                 %$c, async_runs_dir => "$dir/runs");
    my $rec = wait_done('a1');
    is $rec->{status}, 'done', 'the async run finished' or diag explain [$r, $rec];
    is path_in($rec->{stdout}), '/opt/tools/bin:/usr/bin:/bin', 'the configured PATH';

    my $sub = Exec::Agent::AsyncRunner::submit(reqid => 'a2', script => 'probe2', script_path => $probe,
                                               runs_dir => "$dir/runs", owner => 'disp-1');
    $rec = wait_done('a2');
    is path_in($rec->{stdout}), $DEFAULT, 'submit without a path: the default';
};

# self-check through the real modulino: the PATH in force, and why.
sub self_check {
    my ($extra) = @_;
    my $conf = "$dir/sc-agent.conf";
    write_file($conf, $REQUIRED . $extra . "[profile default]\n");
    my $agent = "$Bin/../bin/ctrl-exec-agent";
    my $seam = '@Exec::Agent::Config::TRUSTED_OWNERS = (0, $>);'
             . '$Exec::Agent::Config::TRUSTED_TOP = shift;'
             . 'my $a = shift; do $a or die $@ || $!; main()';
    my $cmd = join ' ', map { "'$_'" } $^X, "-I$Bin/../lib", '-MExec::Agent::Config',
                                        '-e', $seam, $dir, $agent, '--config', $conf,
                                        '--allowlist', "$dir/scripts.conf", 'self-check';
    return scalar `$cmd 2>/dev/null`;
}

subtest 'self-check shows the PATH scripts get' => sub {
    like self_check(''), qr{^  Script PATH: \Q$DEFAULT\E \(the default; script_path unset\)$}m, 'unset';
    like self_check("script_path = $NIXOS\n"), qr{^  Script PATH: \Q$NIXOS\E \(script_path\)$}m, 'set';
    like self_check("script_path = $NIXOS:\n"),
        qr{^  Script PATH: \Q$DEFAULT\E \(the default; script_path is INVALID - entry 3 is empty\)$}m,
        'invalid: the default, and why';
};

done_testing;
