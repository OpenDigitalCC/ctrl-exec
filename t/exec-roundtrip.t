#!/usr/bin/perl
# End-to-end round trip: Perl front-end client -> C executor over its unix
# socket -> profiled exec -> framed result back. Exercises the socket, the
# SO_PEERCRED check (same-uid passes), the request/response framing, stdin
# delivery, and stdout/stderr/exit capture - all for the unprivileged 'default'
# profile so it runs without root (CTRL_EXEC_EXEC_ALLOW_UNPRIV). The privileged
# ns/cap/setuid paths are exercised on a real host (see the on-host test plan).
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use FindBin    qw($Bin);
use lib "$Bin/../lib";
use POSIX      qw(:sys_wait_h);

use Exec::Agent::ExecClient qw();

my $cc = `command -v gcc 2>/dev/null`; chomp $cc;
plan skip_all => 'gcc not available' unless $cc && -x $cc;

my $TMP  = tempdir(CLEANUP => 1);
my $BIN  = "$TMP/ctrl-exec-exec";
system($cc, '-O2', '-o', $BIN, "$Bin/../src/ctrl-exec-exec.c", '-lcap') == 0
    or plan skip_all => 'could not compile src/ctrl-exec-exec.c';

# A script that proves stdin delivery, both streams, args, and exit code.
my $script = "$TMP/echo.sh";
open my $sf, '>', $script or die $!;
print $sf <<'SH';
#!/bin/sh
read line
echo "stdin=[$line] arg1=[$1]"
echo "to-stderr" >&2
exit 7
SH
close $sf;
chmod 0755, $script;

# A script that floods stdout with > MAX_OUTPUT (16 MiB) so the executor's
# output cap is exercised: it must truncate rather than buffer unboundedly.
my $bigscript = "$TMP/bigout.sh";
open my $bf, '>', $bigscript or die $!;
print $bf "#!/bin/sh\nhead -c 17000000 /dev/zero | tr '\\0' x\n";
close $bf;
chmod 0755, $bigscript;

# An explicit [profile default] with no run_as and no caps -> runs as the current
# user, no root needed (there is no built-in default; it must be defined). Empty
# body keeps it usable in the unprivileged allow_unpriv test path.
my $agent_conf = "$TMP/agent.conf";
open my $af, '>', $agent_conf or die $!;
print $af "port = 7443\ncert = /x\nkey = /y\nca = /z\nscript_dirs = $TMP\n"
        . "[profile default]\n";
close $af;

my $scripts_conf = "$TMP/scripts.conf";
open my $cf, '>', $scripts_conf or die $!;
print $cf "echo = $script\n";          # default profile
print $cf "bigout = $bigscript\n";
close $cf;

my $sock = "$TMP/exec.sock";
my $user = getpwuid($>);               # peer-user = us; PEERCRED uid will match

my $pid = fork();
die "fork: $!" unless defined $pid;
if ($pid == 0) {
    $ENV{CTRL_EXEC_EXEC_ALLOW_UNPRIV} = 1;          # test-only: skip root requirement
    exec($BIN, 'serve', $sock, $agent_conf, $scripts_conf, $user)
        or POSIX::_exit(127);
}

# Wait for the socket to appear (executor bound + listening).
my $ready = 0;
for (1 .. 100) { if (-S $sock) { $ready = 1; last } select undef, undef, undef, 0.05 }
ok $ready, 'executor created its socket' or do { kill 'TERM', $pid; done_testing; exit };

subtest 'permitted script: stdin, args, both streams, exit code round-trip' => sub {
    my $r = Exec::Agent::ExecClient::run(
        socket => $sock, reqid => 'r1', dispatcher_id => 'disp-1',
        script => 'echo', args => ['hello'], stdin => "world\n",
    );
    is $r->{exit}, 7, 'exit code propagated';
    like $r->{stdout}, qr/stdin=\[world\]/, 'stdin delivered to the script';
    like $r->{stdout}, qr/arg1=\[hello\]/,  'argument passed through';
    like $r->{stderr}, qr/to-stderr/,       'stderr captured separately';
};

subtest 'unknown script is refused by the executor (re-validation)' => sub {
    my $r = Exec::Agent::ExecClient::run(
        socket => $sock, script => 'nope', args => [],
    );
    isnt $r->{exit}, 0, 'non-zero exit';
    like $r->{stderr}, qr/not permitted/, 'executor refuses a non-allowlisted script';
};

subtest 'transport error when the socket is gone' => sub {
    my $r = Exec::Agent::ExecClient::run(socket => "$TMP/nope.sock", script => 'echo');
    is $r->{exit}, -1, 'exit -1 on unreachable executor';
    like $r->{error}, qr/unreachable/, 'reports a transport error';
};

subtest 'oversized output is capped, not buffered unboundedly (PERF-004)' => sub {
    my $r = Exec::Agent::ExecClient::run(
        socket => $sock, reqid => 'big', script => 'bigout', args => [],
    );
    my $len = length($r->{stdout} // '');
    # 16 MiB cap + the short truncation marker; nowhere near the 17 MB produced.
    ok $len <= 16 * 1024 * 1024 + 64,
        "stdout capped at ~16 MiB (got $len bytes from a 17 MB flood)";
    like $r->{stdout}, qr/\[output truncated\]/, 'truncation marker appended';
};

subtest 'agent.conf is reloaded on mtime change (PERF-003)' => sub {
    # Rewrite agent.conf to REMOVE [profile default], bumping mtime so the serve
    # loop's stat-based reload picks it up. The next request for the unannotated
    # 'echo' script (-> profile 'default', now undefined) must be refused -
    # proving the cached config was reloaded, not stale. (Run last: it disables
    # the default profile the earlier subtests rely on.)
    open my $a, '>', $agent_conf or die $!;
    print $a "port = 7443\ncert = /x\nkey = /y\nca = /z\nscript_dirs = $TMP\n";  # no [profile default]
    close $a;
    utime time + 10, time + 10, $agent_conf;     # force a distinct mtime

    my $r = Exec::Agent::ExecClient::run(
        socket => $sock, reqid => 'reload', script => 'echo', args => ['x'], stdin => "y\n");
    like $r->{stderr}, qr/undefined profile/,
        'removing [profile default] takes effect on the next request';
};

kill 'TERM', $pid;
waitpid $pid, 0;
done_testing;
