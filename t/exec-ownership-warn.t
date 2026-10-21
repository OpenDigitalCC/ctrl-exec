#!/usr/bin/perl
# t/exec-ownership-warn.t  (T-054)
#
# script_ownership in agent.conf decides what the executor does with a script
# that breaks the ownership rule (T-045): 'warn' (the default) runs it, 'strict'
# refuses it (exit 126, "executor: script not permitted: <reason>").
#
# In warn mode the executor writes nothing about the rule into the run: in the
# forked child fd 2 is already the action's stderr pipe, so a warning there
# would reach the caller as the script's own stderr. The run's stdout and stderr
# must be exactly the script's. The front end logs the reason once per
# allowlist load instead (t/agent-script-ownership.t).
#
# Unprivileged test build (-DCE_TEST_SEAM, CTRL_EXEC_EXEC_ALLOW_UNPRIV): the
# test user is trusted like root and the tempdir's ancestors are not checked,
# so a group-writable script directory is the only thing breaking the rule.
# Driven both directly (ExecClient) and through the agent front end
# (handle_connection with executor_socket), as t/exec-stdio-closed.t does.
# The root cases are in t/exec-ownership-root.t. CE_EXECUTOR_SRC=<file> builds
# another executor source instead (to show the executor before T-054).
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use FindBin    qw($Bin);
use lib "$Bin/../lib", "$Bin/lib";
use ChildGuard ();
use IO::Socket::UNIX qw();
use JSON::PP ();
use POSIX qw();

use Exec::Agent::Config     qw();
use Exec::Agent::ExecClient qw();
use Exec::Agent::Server     qw();
use Exec::Log               qw();

my $cc = `command -v gcc 2>/dev/null`; chomp $cc;
plan skip_all => 'gcc not available' unless $cc && -x $cc;

{
    no warnings 'redefine';
    *Exec::Log::log_action = sub { };
}
my $JSON = JSON::PP->new->canonical;

umask 022;
my $dir = ChildGuard::dir(tempdir(CLEANUP => 1));
chmod 0755, $dir;
my $SRC = $ENV{CE_EXECUTOR_SRC} // "$Bin/../src/ctrl-exec-executor.c";
my $BIN = "$dir/ctrl-exec-executor";
system($cc, '-O2', '-DCE_TEST_SEAM', '-o', $BIN, $SRC, '-lcap') == 0
    or plan skip_all => "could not compile $SRC";
@Exec::Agent::Config::TRUSTED_OWNERS = (0, $>);
$Exec::Agent::Config::TRUSTED_TOP    = $dir;

sub write_file { my ($p, $c, $m) = @_; open my $fh, '>', $p or die "$p: $!"; print $fh $c; close $fh; chmod $m, $p if $m }

# The script directory is group-writable (as /srv/scripts 2775 root:dev).
my $S = "$dir/s";
mkdir $S or die;
chmod 0775, $S;
write_file("$S/hello.sh", "#!/bin/sh\necho \"out:\$0\"\necho err-line >&2\nexit 3\n", 0755);
my $scripts_conf = "$dir/scripts.conf";
write_file($scripts_conf, "hello = $S/hello.sh\n");
my $REASON = "'$S' is group-writable";

# Start an executor on agent.conf with the given script_ownership line; returns
# ($pid, $sock, $errfile).
sub start_executor {
    my ($tag, $line) = @_;
    my $conf = "$dir/agent-$tag.conf";
    write_file($conf, "port = 7443\ncert = /x\nkey = /y\nca = /z\nscript_dirs = $S\n"
                    . $line . "[profile default]\n");
    my $sock = "$dir/exec-$tag.sock";
    my $err  = "$dir/exec-$tag.err";
    unlink $sock;
    my $pid = ChildGuard::guarded_fork() // die "fork: $!";
    if (!$pid) {
        $ENV{CTRL_EXEC_EXEC_ALLOW_UNPRIV} = 1;
        $ENV{CE_TEST_TRUSTED_UID} = $>;
        $ENV{CE_TEST_TRUSTED_TOP} = $dir;
        open STDERR, '>', $err or POSIX::_exit(126);
        exec($BIN, 'serve', $sock, $conf, $scripts_conf, scalar getpwuid($>)) or POSIX::_exit(127);
    }
    for (1 .. 100) { last if -S $sock; select undef, undef, undef, 0.05 }
    return ($pid, $sock, $err, $conf);
}
sub stop { my ($pid) = @_; kill 'TERM', $pid; waitpid $pid, 0 }
sub slurp { my ($p) = @_; open my $f, '<', $p or return ''; local $/; my $s = <$f>; $s // '' }

# A run through the agent front end with the executor.
sub front_end_run {
    my ($sock, $config_path) = @_;
    my $config = Exec::Agent::Config::load_config($config_path);
    $config->{executor_socket} = $sock;
    my ($al, $sk);
    { local $SIG{__WARN__} = sub {};
      ($al, $sk) = Exec::Agent::Config::load_allowlist_full(
          $scripts_conf, $config->{script_dirs}, $config->{script_ownership}); }
    my $body = $JSON->encode({ script => 'hello', args => [], reqid => 'w-1',
                               username => 'u', token => 't' });
    my ($client, $server) = IO::Socket::UNIX->socketpair(
        IO::Socket::AF_UNIX(), IO::Socket::SOCK_STREAM(), 0) or die "socketpair: $!";
    print $client "POST /run HTTP/1.0\r\nContent-Length: " . length($body) . "\r\n\r\n$body";
    $client->shutdown(1);
    Exec::Agent::Server::handle_connection(
        $server, '10.0.0.5', $al, $config, {}, { deadbeef => 'disp-1' }, 'deadbeef',
        {}, '9.9.9', $sk,
    );
    $server->close;
    my $resp = do { local $/; <$client> // '' };
    $client->close;
    $resp =~ s/\A.*?\r\n\r\n//s;
    return eval { JSON::PP::decode_json($resp) } // { raw => $resp };
}

for my $case (['default (no setting)', 'dflt', ''], ['explicit warn', 'warn', "script_ownership = warn\n"]) {
    my ($label, $tag, $line) = @$case;
    subtest "warn mode, $label: the script runs and its output is its own" => sub {
        my ($pid, $sock, $err, $conf) = start_executor($tag, $line);
        ok -S $sock, 'executor serving' or return stop($pid);

        my $r = Exec::Agent::ExecClient::run(socket => $sock, reqid => 'w-0', script => 'hello', args => []);
        is $r->{exit},   3,                    'direct: the action\'s exit status' or diag explain $r;
        is $r->{stdout}, "out:$S/hello.sh\n",  'direct: stdout is exactly the script\'s';
        is $r->{stderr}, "err-line\n",         'direct: stderr is exactly the script\'s (no warning)';

        my $f = front_end_run($sock, $conf);
        is $f->{exit},   3,                    'front end: exit status' or diag explain $f;
        is $f->{stdout}, "out:$S/hello.sh\n",  'front end: stdout';
        is $f->{stderr}, "err-line\n",         'front end: stderr carries no warning';

        stop($pid);
        unlike slurp($err), qr/writable|not permitted/, 'the executor did not log a per-run refusal';
    };
}

subtest 'strict mode: the executor refuses with the reason' => sub {
    my ($pid, $sock, $err, $conf) = start_executor('strict', "script_ownership = strict\n");
    ok -S $sock, 'executor serving' or return stop($pid);

    my $r = Exec::Agent::ExecClient::run(socket => $sock, reqid => 's-0', script => 'hello', args => []);
    is $r->{exit},   126, 'direct: exit 126' or diag explain $r;
    is $r->{stdout}, '',  'direct: no output';
    is $r->{stderr}, "executor: script not permitted: $REASON\n", 'direct: the reason';

    my $f = front_end_run($sock, $conf);
    is $f->{exit},  -1, 'front end: refused before the executor';
    is $f->{error}, "script not permitted: $REASON", 'front end: the same reason';
    stop($pid);
};

subtest 'a bad script_ownership value is a config error in the executor' => sub {
    my $conf = "$dir/agent-bad.conf";
    write_file($conf, "port = 7443\ncert = /x\nkey = /y\nca = /z\nscript_ownership = maybe\n[profile default]\n");
    my $out = `\Q$BIN\E resolve \Q$conf\E \Q$scripts_conf\E hello 2>&1`;
    is $? >> 8, 2, 'resolve: config error (exit 2)';
    like $out, qr{Invalid script_ownership 'maybe' in '\Q$conf\E' \(expected warn or strict\)},
        'the same message as the front end';
    local $ENV{CTRL_EXEC_EXEC_ALLOW_UNPRIV} = 1;
    # timeout: an executor that accepted the value would serve forever.
    my $serve = `timeout 5 \Q$BIN\E serve \Q$dir/bad.sock\E \Q$conf\E \Q$scripts_conf\E \Q${\ scalar getpwuid($>)}\E 2>&1`;
    isnt $? >> 8, 0, 'serve: refuses to start';
    like $serve, qr{Invalid script_ownership 'maybe'}, 'serve: says why';
};

done_testing;
