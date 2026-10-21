#!/usr/bin/perl
# t/agent-output-utf8.t
#
# A script's stdout and stderr reach the caller as the same text whether the
# agent runs it directly or through the executor: valid UTF-8 is decoded once
# (an accented word arrives as that word, not as its bytes read as Latin-1),
# and bytes that are not valid UTF-8 become U+FFFD instead of a malformed
# string in the JSON reply.
#
# Unprivileged test build of the executor (CTRL_EXEC_EXEC_ALLOW_UNPRIV), driven
# through the agent front end as t/exec-stdio-closed.t does.

use strict;
use warnings;
use utf8;
use Test::More;
use File::Temp qw(tempdir);
use FindBin    qw($Bin);
use lib "$Bin/../lib", "$Bin/lib";
use ChildGuard ();
use IO::Socket::UNIX qw();
use JSON::PP ();
use POSIX qw();

use Exec::Agent::Config qw();
use Exec::Agent::Server qw();
use Exec::Log           qw();

my $cc = `command -v gcc 2>/dev/null`; chomp $cc;
plan skip_all => 'gcc not available' unless $cc && -x $cc;

{
    no warnings 'redefine';
    *Exec::Log::log_action = sub { };
}
my $JSON = JSON::PP->new->canonical;

umask 022;   # nothing group-writable: the executor refuses it (T-045)
my $dir = ChildGuard::dir(tempdir(CLEANUP => 1));
my $SRC = $ENV{CE_EXECUTOR_SRC} // "$Bin/../src/ctrl-exec-executor.c";
my $BIN = "$dir/ctrl-exec-executor";
system($cc, '-O2', '-DCE_TEST_SEAM', '-o', $BIN, $SRC, '-lcap') == 0
    or plan skip_all => "could not compile $SRC";
@Exec::Agent::Config::TRUSTED_OWNERS = (0, $>);
$Exec::Agent::Config::TRUSTED_TOP    = $dir;
mkdir "$dir/s" or die;
sub write_file { my ($p, $c, $m) = @_; open my $fh, '>:raw', $p or die "$p: $!"; print $fh $c; close $fh; chmod $m, $p if $m }

# The script writes raw bytes: "café ✓" in UTF-8 on stdout, and two bytes that
# are not UTF-8 (0xFF 0xFE) followed by " ok" on stderr.
write_file("$dir/s/text.sh", <<'SH', 0755);
#!/bin/sh
printf 'caf\303\251 \342\234\223\n'
printf '\377\376 ok\n' >&2
SH
my $agent_conf = "$dir/agent.conf";
write_file($agent_conf, "port = 7443\ncert = /x\nkey = /y\nca = /z\nscript_dirs = $dir/s\n[profile default]\n");
my $scripts_conf = "$dir/scripts.conf";
write_file($scripts_conf, "text = $dir/s/text.sh\n");
my ($allowlist, $skipped);
{
    local $SIG{__WARN__} = sub {};
    ($allowlist, $skipped) = Exec::Agent::Config::load_allowlist_full($scripts_conf, ["$dir/s"]);
}
is scalar(keys %$allowlist), 1, 'test script allowlisted' or diag explain $skipped;

my $sock = "$dir/exec.sock";
my $epid = ChildGuard::guarded_fork() // die "fork: $!";
if (!$epid) {
    $ENV{CTRL_EXEC_EXEC_ALLOW_UNPRIV} = 1;
    $ENV{CE_TEST_TRUSTED_UID} = $>;
    $ENV{CE_TEST_TRUSTED_TOP} = $dir;
    exec($BIN, 'serve', $sock, $agent_conf, $scripts_conf, scalar getpwuid($>))
        or POSIX::_exit(127);
}
my $up = 0;
for (1 .. 100) { if (-S $sock) { $up = 1; last } select undef, undef, undef, 0.05 }
ok $up, 'executor created its socket'
    or do { kill 'TERM', $epid; waitpid $epid, 0; done_testing; exit };

sub run_text {
    my (%cfg) = @_;
    my $body = $JSON->encode({ script => 'text', args => [], reqid => 'utf8-1',
                               username => 'u', token => 't' });
    my ($client, $server) = IO::Socket::UNIX->socketpair(
        IO::Socket::AF_UNIX(), IO::Socket::SOCK_STREAM(), 0) or die "socketpair: $!";
    print $client "POST /run HTTP/1.0\r\nContent-Length: " . length($body) . "\r\n\r\n$body";
    $client->shutdown(1);
    Exec::Agent::Server::handle_connection(
        $server, '10.0.0.5', $allowlist, { script_dirs => ["$dir/s"], %cfg },
        {}, { deadbeef => 'disp-1' }, 'deadbeef', {}, '9.9.9', $skipped,
    );
    $server->close;
    my $resp = do { local $/; <$client> // '' };
    $client->close;
    $resp =~ s/\A.*?\r\n\r\n//s;
    return eval { JSON::PP::decode_json($resp) } // { raw => $resp };
}

for my $mode ('direct', 'executor') {
    subtest "$mode: output is decoded once, bad bytes become U+FFFD" => sub {
        my $r = run_text($mode eq 'executor' ? (executor_socket => $sock) : ());
        is $r->{exit}, 0, 'the script ran' or diag explain $r;
        is $r->{stdout}, "café ✓\n", 'valid UTF-8 arrives as the same text';
        is $r->{stderr}, "\x{FFFD}\x{FFFD} ok\n", 'invalid bytes arrive as U+FFFD';
    };
}

kill 'TERM', $epid; waitpid $epid, 0;
done_testing;
