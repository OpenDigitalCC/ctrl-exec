#!/usr/bin/perl
# T-036: the executor must feed the action's stdin while it drains the action's
# stdout and stderr, not before.
#
# The handler used to write the whole stdin payload with a blocking write and
# only then start reading the action's output. An action that writes more than
# a pipe buffer of output before it reads stdin (or never reads it at all)
# blocks on its own write while the handler blocks on the stdin write, and both
# hang until something kills them. Here the stdin payload (1 MiB) and the
# output (256 KiB on a stream) are both larger than a pipe buffer, so the old
# code hangs for certain. Each run is bounded by an alarm, so a regression fails
# rather than hanging the suite.
#
# Unprivileged 'default' profile (CTRL_EXEC_EXEC_ALLOW_UNPRIV), as in
# t/exec-sigpipe.t, so no root is needed.
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use FindBin    qw($Bin);
use lib "$Bin/../lib", "$Bin/lib";
use ChildGuard ();
use POSIX      qw();

use Exec::Agent::ExecClient qw();

my $cc = `command -v gcc 2>/dev/null`; chomp $cc;
plan skip_all => 'gcc not available' unless $cc && -x $cc;

my $TMP = ChildGuard::dir(tempdir(CLEANUP => 1));
umask 022;   # nothing group-writable: the executor refuses it (T-045)
my $BIN = "$TMP/ctrl-exec-executor";
system($cc, '-O2', '-DCE_TEST_SEAM', '-o', $BIN, "$Bin/../src/ctrl-exec-executor.c", '-lcap') == 0
    or plan skip_all => 'could not compile src/ctrl-exec-executor.c';

my $OUT = 256 * 1024;              # more output than a pipe buffer holds
my $IN  = 1024 * 1024;             # more stdin than a pipe buffer holds

sub script {
    my ($name, $body) = @_;
    my $f = "$TMP/$name.sh";
    open my $fh, '>', $f or die $!;
    print $fh "#!/bin/sh\n$body";
    close $fh;
    chmod 0755, $f;
    return $f;
}

# Writes $OUT bytes to stdout, then reads all of stdin and reports its size.
my $late = script('late', <<"SH");
head -c $OUT /dev/zero | tr '\\0' a
echo
n=\$(wc -c)
echo "stdin=\$((n))"
exit 3
SH

# Writes $OUT bytes to stdout and to stderr and never reads stdin.
my $never = script('never', <<"SH");
head -c $OUT /dev/zero | tr '\\0' b
head -c $OUT /dev/zero | tr '\\0' c >&2
exit 5
SH

my $agent_conf = "$TMP/agent.conf";
open my $af, '>', $agent_conf or die $!;
print $af "port = 7443\ncert = /x\nkey = /y\nca = /z\nscript_dirs = $TMP\n"
        . "[profile default]\n";
close $af;

my $scripts_conf = "$TMP/scripts.conf";
open my $cf, '>', $scripts_conf or die $!;
print $cf "late = $late\nnever = $never\n";
close $cf;

my $user = getpwuid($>);
my $sock = "$TMP/exec.sock";

# The executor runs in its own process group, so a hung handler and its action
# can be killed with it at the end.
my $pid = ChildGuard::guarded_fork();
die "fork: $!" unless defined $pid;
if ($pid == 0) {
    POSIX::setpgid(0, 0);
    $ENV{CTRL_EXEC_EXEC_ALLOW_UNPRIV} = 1;
    # Test build (CE_TEST_SEAM): trust the test user and $TMP's ancestors in the
    # script ownership rule (T-045), which otherwise wants a root-owned path.
    $ENV{CE_TEST_TRUSTED_UID} = $>;
    $ENV{CE_TEST_TRUSTED_TOP} = $TMP;
    exec($BIN, 'serve', $sock, $agent_conf, $scripts_conf, $user)
        or POSIX::_exit(127);
}
for (1 .. 100) { last if -S $sock; select undef, undef, undef, 0.05 }
ok -S $sock, 'executor created its socket'
    or do { kill 'KILL', -$pid; waitpid $pid, 0; done_testing; exit };

# One run, bounded by an alarm; returns the result or { timeout => 1 }.
sub bounded_run {
    my (%o) = @_;
    my $r = eval {
        local $SIG{ALRM} = sub { die "timeout\n" };
        alarm 10;
        my $res = Exec::Agent::ExecClient::run(socket => $sock, args => [], %o);
        alarm 0;
        $res;
    };
    alarm 0;
    return $r // { timeout => 1, error => $@ };
}

my $big = 'x' x $IN;

subtest 'action writes a pipe buffer of output before reading stdin' => sub {
    my $r = bounded_run(reqid => 'late', script => 'late', stdin => $big);
    ok !$r->{timeout}, 'run completed (no stdin/stdout deadlock)' or return;
    is $r->{exit}, 3, 'exit code is the action\'s';
    my ($body) = ($r->{stdout} // '') =~ /^(a*)\n/;
    is length($body // ''), $OUT, 'all of the output delivered';
    like $r->{stdout}, qr/^stdin=$IN$/m, 'the action read the whole stdin payload';
};

subtest 'action never reads stdin and fills stdout and stderr' => sub {
    my $r = bounded_run(reqid => 'never', script => 'never', stdin => $big);
    ok !$r->{timeout}, 'run completed (no stdin/stdout deadlock)' or return;
    is $r->{exit}, 5, 'exit code is the action\'s';
    is $r->{stdout}, 'b' x $OUT, 'all of stdout delivered';
    is $r->{stderr}, 'c' x $OUT, 'all of stderr delivered';
};

kill 'KILL', -$pid;
waitpid $pid, 0;
done_testing;
