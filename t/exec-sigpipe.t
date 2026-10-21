#!/usr/bin/perl
# T-034: an action that exits without reading its stdin must still get a framed
# response back, not "executor closed before responding".
#
# The executor's handler writes the request context to the action's stdin after
# fork. If the action has already exited (or closed stdin), that write hits a pipe
# with no reader. With SIGPIPE at its default disposition the handler was killed
# there, before writing any response. That raced the action's exit, so it showed
# as an intermittent exit -1 on a trivial script. Here the race is made certain:
# the stdin payload (1 MiB) is larger than a pipe buffer, so the write must block
# until the action exits and then fail.
#
# The executor is started with SIGPIPE at SIG_DFL (as OpenRC and a shell start
# it), which is the case that failed. A second instance is started with SIGPIPE
# ignored (as systemd starts it) to check that the action itself always starts
# with SIGPIPE at its default, not an inherited SIG_IGN.
#
# Unprivileged 'default' profile (CTRL_EXEC_EXEC_ALLOW_UNPRIV), as in
# t/exec-roundtrip.t, so no root is needed.
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
plan skip_all => '/proc/self/status not readable' unless -r '/proc/self/status';

my $TMP = ChildGuard::dir(tempdir(CLEANUP => 1));
umask 022;   # nothing group-writable: the executor refuses it (T-045)
my $BIN = "$TMP/ctrl-exec-executor";
system($cc, '-O2', '-DCE_TEST_SEAM', '-o', $BIN, "$Bin/../src/ctrl-exec-executor.c", '-lcap') == 0
    or plan skip_all => 'could not compile src/ctrl-exec-executor.c';

# Prints a line and exits 0 without reading stdin.
my $early = "$TMP/early.sh";
open my $ef, '>', $early or die $!;
print $ef "#!/bin/sh\necho early-exit-ok\nexit 0\n";
close $ef;
chmod 0755, $early;

# Reports whether SIGPIPE (signal 13, bit 12 of SigIgn) is ignored in the action
# (the shell's own status, read with builtins only: some awks ignore SIGPIPE
# themselves, so a child probe would mislead).
my $disp = "$TMP/sigpipe.sh";
open my $df, '>', $disp or die $!;
print $df <<'SH';
#!/bin/sh
mask=0
while read -r k v; do [ "$k" = "SigIgn:" ] && mask=$v; done < /proc/$$/status
if [ $(( 0x$mask & 0x1000 )) -ne 0 ]; then echo sigpipe=ignored; else echo sigpipe=default; fi
SH
close $df;
chmod 0755, $disp;

my $agent_conf = "$TMP/agent.conf";
open my $af, '>', $agent_conf or die $!;
print $af "port = 7443\ncert = /x\nkey = /y\nca = /z\nscript_dirs = $TMP\n"
        . "[profile default]\n";
close $af;

my $scripts_conf = "$TMP/scripts.conf";
open my $cf, '>', $scripts_conf or die $!;
print $cf "early = $early\nsigpipe = $disp\n";
close $cf;

my $user = getpwuid($>);

# Start an executor with the given SIGPIPE disposition; returns (pid, socket).
sub start_executor {
    my ($name, $sigpipe) = @_;
    my $sock = "$TMP/$name.sock";
    my $pid  = ChildGuard::guarded_fork();
    die "fork: $!" unless defined $pid;
    if ($pid == 0) {
        $SIG{PIPE} = $sigpipe;
        $ENV{CTRL_EXEC_EXEC_ALLOW_UNPRIV} = 1;
        # Test build (CE_TEST_SEAM): trust the test user and $TMP's ancestors in the
        # script ownership rule (T-045), which otherwise wants a root-owned path.
        $ENV{CE_TEST_TRUSTED_UID} = $>;
        $ENV{CE_TEST_TRUSTED_TOP} = $TMP;
        exec($BIN, 'serve', $sock, $agent_conf, $scripts_conf, $user)
            or POSIX::_exit(127);
    }
    for (1 .. 100) { last if -S $sock; select undef, undef, undef, 0.05 }
    return ($pid, $sock);
}

my ($pid_dfl, $sock_dfl) = start_executor('dfl', 'DEFAULT');
my ($pid_ign, $sock_ign) = start_executor('ign', 'IGNORE');
ok -S $sock_dfl && -S $sock_ign, 'both executors created their sockets'
    or do { kill 'TERM', $pid_dfl, $pid_ign; done_testing; exit };

my $big = 'x' x (1024 * 1024);     # larger than any pipe buffer

subtest 'action exits without reading stdin: response still delivered' => sub {
    for my $n (1 .. 3) {
        my $r = Exec::Agent::ExecClient::run(
            socket => $sock_dfl, reqid => "early-$n", script => 'early',
            args => [], stdin => $big,
        );
        is $r->{exit}, 0, "run $n: exit 0 (not -1)"
            or diag 'error: ' . ($r->{error} // '(none)');
        like $r->{stdout} // '', qr/early-exit-ok/, "run $n: stdout delivered";
    }
};

subtest 'action starts with SIGPIPE at its default disposition' => sub {
    for my $case ([ $sock_dfl, 'executor started with SIGPIPE default' ],
                  [ $sock_ign, 'executor started with SIGPIPE ignored' ]) {
        my $r = Exec::Agent::ExecClient::run(
            socket => $case->[0], reqid => 'disp', script => 'sigpipe',
            args => [], stdin => "{}\n",
        );
        is $r->{exit}, 0, "$case->[1]: exit 0";
        like $r->{stdout} // '', qr/sigpipe=default/, "$case->[1]: action has SIG_DFL";
    }
};

kill 'TERM', $pid_dfl, $pid_ign;
waitpid $pid_dfl, 0;
waitpid $pid_ign, 0;
done_testing;
