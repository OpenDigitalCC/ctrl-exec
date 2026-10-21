#!/usr/bin/perl
# t/exec-stdio-closed.t  (T-051 follow-up)
#
# Started with stdin, stdout and stderr closed, the executor fills them with
# /dev/null before it opens anything, so its listening socket, connections and
# pipes never take fd 0-2 (where its error messages, or the action's stdio
# wiring, would land on them). A run through it still returns the action's
# real stdout, stderr and exit status.
#
# Unprivileged test build (CTRL_EXEC_EXEC_ALLOW_UNPRIV), driven through the
# agent front end as t/exec-fd.t does. CE_EXECUTOR_SRC=<file> builds another
# executor source instead (to show the executor before the guard).

use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use FindBin    qw($Bin);
use lib "$Bin/../lib";
use IO::Socket::UNIX qw();
use JSON::PP ();
use POSIX qw();

use Exec::Agent::Config qw();
use Exec::Agent::Server qw();
use Exec::Log           qw();

my $cc = `command -v gcc 2>/dev/null`; chomp $cc;
plan skip_all => 'gcc not available' unless $cc && -x $cc;
plan skip_all => '/proc/self/fd not available' unless -d '/proc/self/fd';

{
    no warnings 'redefine';
    *Exec::Log::log_action = sub { };
}
my $JSON = JSON::PP->new->canonical;

umask 022;   # nothing group-writable: the executor refuses it (T-045)
my $dir = tempdir(CLEANUP => 1);
my $SRC = $ENV{CE_EXECUTOR_SRC} // "$Bin/../src/ctrl-exec-executor.c";
my $BIN = "$dir/ctrl-exec-executor";
system($cc, '-O2', '-DCE_TEST_SEAM', '-o', $BIN, $SRC, '-lcap') == 0
    or plan skip_all => "could not compile $SRC";
@Exec::Agent::Config::TRUSTED_OWNERS = (0, $>);
$Exec::Agent::Config::TRUSTED_TOP    = $dir;
mkdir "$dir/s" or die;
sub write_file { my ($p, $c, $m) = @_; open my $fh, '>', $p or die "$p: $!"; print $fh $c; close $fh; chmod $m, $p if $m }

write_file("$dir/s/echo.sh", <<'SH', 0755);
#!/bin/sh
read line
echo "out:$line"
echo "err:$line" >&2
exit 3
SH
my $agent_conf = "$dir/agent.conf";
write_file($agent_conf, "port = 7443\ncert = /x\nkey = /y\nca = /z\nscript_dirs = $dir/s\n[profile default]\n");
my $scripts_conf = "$dir/scripts.conf";
write_file($scripts_conf, "echo = $dir/s/echo.sh\n");
my ($allowlist, $skipped);
{
    local $SIG{__WARN__} = sub {};
    ($allowlist, $skipped) = Exec::Agent::Config::load_allowlist_full($scripts_conf, ["$dir/s"]);
}
is scalar(keys %$allowlist), 1, 'test script allowlisted' or diag explain $skipped;

my $sock = "$dir/exec.sock";
my $epid = fork // die "fork: $!";
if (!$epid) {
    $ENV{CTRL_EXEC_EXEC_ALLOW_UNPRIV} = 1;
    $ENV{CE_TEST_TRUSTED_UID} = $>;
    $ENV{CE_TEST_TRUSTED_TOP} = $dir;
    my @argv = ($BIN, 'serve', $sock, $agent_conf, $scripts_conf, scalar getpwuid($>));
    POSIX::close($_) for 0 .. 2;
    exec(@argv) or POSIX::_exit(127);
}
my $up = 0;
for (1 .. 100) { if (-S $sock) { $up = 1; last } select undef, undef, undef, 0.05 }
ok $up, 'executor started with fds 0-2 closed and created its socket'
    or do { kill 'TERM', $epid; waitpid $epid, 0; done_testing; exit };

for my $fd (0 .. 2) {
    is readlink("/proc/$epid/fd/$fd"), '/dev/null', "the executor's fd $fd is /dev/null";
}

my $body = $JSON->encode({ script => 'echo', args => [], reqid => 'stdio-1',
                           username => 'u', token => 't' });
my ($client, $server) = IO::Socket::UNIX->socketpair(
    IO::Socket::AF_UNIX(), IO::Socket::SOCK_STREAM(), 0) or die "socketpair: $!";
print $client "POST /run HTTP/1.0\r\nContent-Length: " . length($body) . "\r\n\r\n$body";
$client->shutdown(1);
Exec::Agent::Server::handle_connection(
    $server, '10.0.0.5', $allowlist,
    { script_dirs => ["$dir/s"], executor_socket => $sock },
    {}, { deadbeef => 'disp-1' }, 'deadbeef', {}, '9.9.9', $skipped,
);
$server->close;
my $resp = do { local $/; <$client> // '' };
$client->close;
$resp =~ s/\A.*?\r\n\r\n//s;
my $r = eval { JSON::PP::decode_json($resp) } // {};

is $r->{exit}, 3, 'the action\'s exit status comes back' or diag $resp;
like $r->{stdout} // '', qr/\Aout:/, 'and its stdout';
like $r->{stderr} // '', qr/\Aerr:/, 'and its stderr';

kill 'TERM', $epid; waitpid $epid, 0;
done_testing;
