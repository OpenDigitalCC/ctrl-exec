#!/usr/bin/perl
# t/dispatcher-api-socket.t  (T-080)
#
# A user who cannot read dispatcher.key (the key stays 0600 by design, T-076)
# runs `ced run` and `ced ping` through the API's unix socket when api_socket is
# set: same output and exit codes as the direct path, a hook denial is the CLI's
# denial, and ced itself calls neither the hook nor the run lock on that route
# (the API does). Without a usable socket the T-076 message gains one line.
#
# A real Exec::API server listens on a socket in a temp directory with a real
# fixture hook; only the dispatch to agents, the registry, the lock and the run
# store are stubbed in the server process. ced is a subprocess whose key is
# chmod 000; config directories are the fixture's (DispatcherRoot). Skipped as
# root, which reads every file.

use strict;
use warnings;
use feature qw(signatures);
no warnings qw(experimental::signatures);
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/../lib", "$Bin/lib";
use File::Temp qw(tempdir);
use File::Path qw(make_path);
use JSON qw(decode_json encode_json);
use ChildGuard qw(guarded_fork);

plan skip_all => 'root reads every file' unless $>;

use Exec::API qw();
use Exec::Engine qw();
use Exec::Lock qw();
use Exec::Log qw();
use Exec::Registry qw();
use Exec::RunStore qw();

sub spew { open my $fh, '>', $_[0] or die "$_[0]: $!"; print $fh $_[1]; close $fh }
sub slurp { open my $fh, '<', $_[0] or return ''; local $/; scalar <$fh> }

# Socket paths are limited to ~107 bytes: keep the directory short.
my $r = tempdir('cexXXXX', TMPDIR => 1, CLEANUP => 1);
my $d = "$r/etc/ctrl-exec-dispatcher";
make_path($d, "$r/agents");
spew("$d/$_", "x\n") for qw(ca.crt dispatcher.crt);
spew("$d/dispatcher.key", "x\n");
chmod 0, "$d/dispatcher.key";
my $sock = "$r/api.sock";

# The API's hook: this uid may run backup/health/fail/locked on agent-01 and
# ping it, and nothing else. It records what it saw of username and token.
my $uid = $>;
spew("$r/hook.sh", <<"SH");
#!/bin/sh
echo "\$ENVEXEC_ACTION \$ENVEXEC_USERNAME \$ENVEXEC_TOKEN" >> "$r/hook.seen"
[ "\$ENVEXEC_PEER_UID" = "$uid" ] || exit 3
case "\$ENVEXEC_ACTION" in
  api) exit 0 ;;
  ping) case "\$ENVEXEC_HOSTS" in agent-01|nope) exit 0 ;; esac; exit 3 ;;
  run)
    [ "\$ENVEXEC_HOSTS" = "agent-01" ] || exit 3
    case "\$ENVEXEC_SCRIPT" in backup|health|fail|locked) exit 0 ;; esac
    exit 3 ;;
esac
exit 1
SH
chmod 0755, "$r/hook.sh";

# ced's own hook: if ced ever calls it, it leaves a marker.
spew("$r/cli-hook.sh", "#!/bin/sh\ntouch $r/cli-hook.called\nexit 0\n");
chmod 0755, "$r/cli-hook.sh";

my $pid = guarded_fork() // die "fork: $!";
if ($pid == 0) {
    open STDOUT, '>', '/dev/null';
    {
        no warnings 'redefine';
        *Exec::Log::log_action = sub { 1 };
        *Exec::RunStore::record_sync = sub { 1 };
        *Exec::Lock::check_available = sub (%o) {
            return $o{script} eq 'locked'
                ? { ok => 0, conflicts => ['agent-01:locked'] } : { ok => 1 };
        };
        *Exec::Registry::resolve_dispatch = sub ($h) {
            my @u = grep { $_ ne 'agent-01' } @$h;
            return @u ? { ok => 0, unknown => \@u } : { ok => 1, hosts => $h };
        };
        *Exec::Registry::did_you_mean = sub { '' };
        *Exec::Engine::dispatch_all = sub (%o) {
            if ($o{input}) {    # T-086: what reached dispatch
                open my $fh, '>', "$r/dispatch.input" or die; print $fh encode_json($o{input}); close $fh;
            }
            my $fail = $o{script} eq 'fail';
            return [ { host => 'agent-01', exit => ($fail ? 3 : 0), rtt => '12ms', reqid => 'abc123',
                       stdout => ($fail ? '' : "hello\n"), stderr => ($fail ? "boom\n" : '') } ];
        };
        *Exec::Engine::ping_all = sub (%o) {
            return [ { host => 'agent-01', status => 'ok', rtt => '3ms',
                       expiry => 'Jan 15 12:00:00 2030 GMT', version => '0.14.2' } ];
        };
    }
    Exec::API::run(config => {
        api_socket => $sock, api_port => 'off', auth_hook => "$r/hook.sh",
    });
    exit 0;
}
for (1 .. 100) { last if -S $sock; select undef, undef, undef, 0.1 }
plan skip_all => 'fixture API did not start' unless -S $sock;

sub conf {
    my (%o) = @_;
    my $sock_line = exists $o{socket} ? ($o{socket} ? "api_socket = $o{socket}\n" : '') : "api_socket = $sock\n";
    spew("$d/ctrl-exec.conf", "cert = $d/dispatcher.crt\nkey = $d/dispatcher.key\nca = $d/ca.crt\n"
       . "registry_dir = $r/agents\nauth_hook = $r/cli-hook.sh\n$sock_line");
    return "$d/ctrl-exec.conf";
}

# ced as a subprocess: (stdout, stderr, exit).
sub ced {
    my (@args) = @_;
    local $ENV{CE_TEST_DISPATCHER_ROOT} = $r;
    local $ENV{USER} = 'tester';
    local $ENV{ENVEXEC_TOKEN};
    my @cmd = ($^X, "-I$Bin/../lib", "-I$Bin/lib", '-MNoSyslog', '-MDispatcherRoot',
               "$Bin/../bin/ctrl-exec-dispatcher", '--config', "$d/ctrl-exec.conf", @args);
    open my $p, '-|', "@cmd 2>$r/stderr" or die "run: $!";
    local $/; my $out = <$p> // ''; close $p;
    return ($out, slurp("$r/stderr"), $? >> 8);
}

conf();

subtest 'run: output and exit equal the direct path' => sub {
    unlink "$r/cli-hook.called", "$r/hook.seen";
    my ($out, $err, $rc) = ced('run', 'agent-01', 'backup', '--', 'full');
    is $out, "==> agent-01  [OK  exit:0  12ms  req:abc123]\nhello\n", 'the direct path\'s text';
    is $err, '', 'nothing on stderr';
    is $rc, 0, 'exit 0';
    ok !-e "$r/cli-hook.called", 'ced did not call its own hook (the API does)';
    like slurp("$r/hook.seen"), qr/^run tester $/m, 'the API\'s hook saw the run with $USER as username';
};

subtest 'run: --input-file and --input-json reach dispatch through the API' => sub {
    unlink "$r/dispatch.input", "$r/hook.seen";
    spew("$r/doc", "line1\nSOCKET-SECRET-ced86\n");
    my ($out, $err, $rc) = ced('run', 'agent-01', 'backup', '--input-file', "$r/doc", '--input-field', 'key');
    is $rc, 0, 'exit 0' or diag $err;
    is_deeply decode_json(slurp("$r/dispatch.input")), { key => "line1\nSOCKET-SECRET-ced86\n" }, 'the file, as the named field';
    unlike slurp("$r/hook.seen"), qr/SOCKET-SECRET/, 'the API\'s hook never saw the value';
    unlink "$r/dispatch.input";
    spew("$r/f.json", encode_json({ a => 'x', b => 'y' }));
    ($out, $err, $rc) = ced('run', 'agent-01', 'backup', '--input-json', "$r/f.json");
    is_deeply decode_json(slurp("$r/dispatch.input")), { a => 'x', b => 'y' }, 'fields JSON';
    unlink "$r/dispatch.input";
    ($out, $err, $rc) = ced('run', 'agent-01', 'backup', '--input-json', "$r/f.json", '--input-file', "$r/doc");
    isnt $rc, 0, 'both refused';
    ok !-e "$r/dispatch.input", 'nothing dispatched';
};

subtest 'run --json' => sub {
    my ($out, $err, $rc) = ced('--json', 'run', 'agent-01', 'backup');
    my $j = eval { decode_json($out) };
    is_deeply [ sort keys %$j ], [qw(ok results)], 'ok + results, as the direct path' or diag $out;
    is $j->{ok}, 1, 'ok';
    is $j->{results}[0]{stdout}, "hello\n", 'the agent result';
    is $rc, 0, 'exit 0';
};

subtest 'run: a failing script' => sub {
    my ($out, $err, $rc) = ced('run', 'agent-01', 'fail');
    is $out, "==> agent-01  [FAIL  exit:3  12ms  req:abc123]\n    STDERR: boom\n\n", 'the direct path\'s text';
    is $rc, 1, 'exit 1';
};

subtest 'run: username and token reach the API\'s hook' => sub {
    unlink "$r/hook.seen";
    my ($out, $err, $rc) = ced('--username', 'bob', '--token', 'tok-1', 'run', 'agent-01', 'health');
    is $rc, 0, 'exit 0';
    like slurp("$r/hook.seen"), qr/^run bob tok-1$/m, 'run: --username and --token';
    my $ping = ced('--username', 'bob', '--token', 'tok-2', 'ping', 'agent-01');
    like slurp("$r/hook.seen"), qr/^ping bob tok-2$/m, 'ping: the same';
    unlink "$r/hook.seen";
    local $ENV{ENVEXEC_TOKEN} = 'from-env';
    open my $p, '-|', "ENVEXEC_TOKEN=from-env CE_TEST_DISPATCHER_ROOT=$r USER=carol $^X -I$Bin/../lib -I$Bin/lib"
        . " -MNoSyslog -MDispatcherRoot $Bin/../bin/ctrl-exec-dispatcher --config $d/ctrl-exec.conf"
        . " run agent-01 health" or die;
    my @ignore = <$p>; close $p;
    like slurp("$r/hook.seen"), qr/^run carol from-env$/m, '$USER and ENVEXEC_TOKEN when no flags';
};

subtest 'ping: output equals the direct path' => sub {
    my ($out, $err, $rc) = ced('ping', 'agent-01');
    is $out, sprintf("%-30s  %-8s  %-8s  %-28s  %s\n%s\n%-30s  %-8s  %-8s  %-28s  %s\n",
        'HOST', 'STATUS', 'RTT', 'CERT EXPIRY', 'VERSION', '-' x 85,
        'agent-01', 'ok', '3ms', 'Jan 15 12:00:00 2030 GMT', '0.14.2'), 'the table';
    is $rc, 0, 'exit 0';
    ok !-e "$r/cli-hook.called", 'ced did not call its own hook';
    my ($jout) = ced('--json', 'ping', 'agent-01');
    my $j = decode_json($jout);
    is_deeply [ sort keys %$j ], [qw(ok results)], '--json: ok + results';
    is $j->{results}[0]{rtt}, '3ms', 'the result';
};

subtest 'hook denial: the CLI\'s denial and exit code' => sub {
    my ($out, $err, $rc) = ced('run', 'agent-01', 'wipe');
    is $out, '', 'nothing on stdout';
    is $err, "Denied: insufficient privilege\n", 'the CLI\'s text, the hook\'s reason';
    is $rc, 1, 'exit 1';
    ($out, $err, $rc) = ced('--json', 'run', 'agent-01', 'wipe');
    is_deeply decode_json($out), { ok => 0, error => 'insufficient privilege', code => 3 }, '--json: the CLI\'s body';
    is $rc, 1, 'exit 1';
    ($out, $err, $rc) = ced('ping', 'agent-02');
    like $err, qr/^Denied: insufficient privilege$/, 'ping denied the same way';
    is $rc, 1, 'exit 1';
    ok !-e "$r/cli-hook.called", 'ced\'s own hook was never called';
};

subtest 'lock conflict and unknown agent' => sub {
    my ($out, $err, $rc) = ced('run', 'agent-01', 'locked');
    is $err, "Locked: already running: agent-01:locked\n", 'the CLI\'s lock text';
    is $rc, 1, 'exit 1';
    ($out, $err, $rc) = ced('ping', 'nope');
    like $err, qr/^Error: unknown agent: nope/, 'unknown agent, as the direct path says it'
        or diag $err;
    isnt $rc, 0, 'non-zero exit';
};

subtest '--async and --port are refused, not dropped' => sub {
    for my $f (qw(async port)) {
        my @a = $f eq 'async' ? ('--async') : ('--port', '7443');
        my ($out, $err, $rc) = ced(@a, 'run', 'agent-01', 'backup');
        is $rc, 1, "--$f: exit 1";
        like $err, qr/--$f is not available through the API socket.*sudo/s, "--$f: says why and what to do";
        is $out, '', "--$f: nothing run";
    }
};

subtest 'no api_socket: the T-076 message, with the socket line' => sub {
    conf(socket => '');
    for my $cmd (['ping', 'agent-01'], ['run', 'agent-01', 'backup']) {
        my ($out, $err, $rc) = ced(@$cmd);
        is $rc, 1, "$cmd->[0]: exit 1";
        like $err, qr/cannot read \Q$d\E\/dispatcher.key as/, "$cmd->[0]: the T-076 message";
        like $err, qr/sudo.*API/s, "$cmd->[0]: sudo or the API";
        like $err, qr/ask for the API socket \(api_socket\) to be enabled/, "$cmd->[0]: the socket line";
    }
    conf();
};

subtest 'api_socket set but unreachable: the message says why' => sub {
    conf(socket => "$r/missing.sock");
    my ($out, $err, $rc) = ced('ping', 'agent-01');
    is $rc, 1, 'exit 1';
    like $err, qr/cannot read \Q$d\E\/dispatcher.key as/, 'the T-076 message';
    like $err, qr/api_socket = \Q$r\E\/missing.sock\), but .*does not exist/, 'names the socket and why';

    # A stale socket file: exists, is a socket, nobody listening.
    my $stale = "$r/stale.sock";
    require IO::Socket::UNIX;
    { my $s = IO::Socket::UNIX->new(Local => $stale, Listen => 1) or die; }
    conf(socket => $stale);
    ($out, $err, $rc) = ced('run', 'agent-01', 'backup');
    is $rc, 1, 'stale socket: exit 1';
    like $err, qr/cannot read .*dispatcher.key as/, 'stale socket: the T-076 message';
    like $err, qr/but cannot connect to \Q$stale\E/, 'stale socket: says it did not answer';
    conf();
};

subtest 'Exec::APIClient::unusable_reason' => sub {
    require Exec::APIClient;
    is Exec::APIClient::unusable_reason($sock), undef, 'a socket this user may write';
    like Exec::APIClient::unusable_reason("$r/nope"), qr/does not exist/, 'missing';
    like Exec::APIClient::unusable_reason("$r/hook.sh"), qr/is not a socket/, 'a file';
    like Exec::APIClient::unusable_reason('relative'), qr/absolute/, 'relative';
};

kill 'TERM', $pid;
done_testing;
