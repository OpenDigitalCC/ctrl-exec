#!/usr/bin/perl
# t/exec-ownership-root.t  (T-045)
#
# End to end through the root executor: a script is run only when it and every
# directory on its path are owned by root and writable by neither group nor
# other. Each refusal is exit 126 with "executor: script not permitted: <path>
# <rule>" and the script does not run. A '#!' bash script and a '#!' perl script
# still run, and see their own path as $0 (the executor execs by path, not by
# fd, so a script that finds its files from $0 keeps working).
#
# Swap after the check: a test build of the executor (-DCE_TEST_SEAM) pauses
# between the ownership check and the exec; the test then points the
# allowlisted symlink at another root-owned script. The executor must notice
# that the path no longer names the file it checked and run neither.
#
# Root only (skipped otherwise); run in the wedge rig (tools/wedge-rig), e.g.
#   docker exec ce-wedge-rig sh -c 'cd /opt/ctrl-exec && prove -Ilib t/exec-ownership-root.t'
# CE_EXECUTOR_SRC=<file> builds another executor source instead (to show the
# refusal cases fail on the executor before T-045).
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use FindBin    qw($Bin);
use lib "$Bin/../lib", "$Bin/lib";
use ChildGuard ();
use POSIX      qw(mkfifo);
use Fcntl      qw(O_WRONLY O_NONBLOCK);

use Exec::Agent::ExecClient qw();

plan skip_all => 'must run as root (the executor runs scripts as root)' unless $> == 0;
my $cc = `command -v gcc 2>/dev/null`; chomp $cc;
plan skip_all => 'gcc not available' unless $cc && -x $cc;

umask 022;
# /run is root-owned 0755 on a normal host and in the rig; /tmp and /var/tmp
# are world-writable, so a script under them is refused.
my $T = ChildGuard::dir(tempdir(DIR => '/run', CLEANUP => 1));
chmod 0755, $T;
my $SRC  = $ENV{CE_EXECUTOR_SRC} // "$Bin/../src/ctrl-exec-executor.c";
my $BIN  = "$T/executor";
my $SEAM = "$T/executor-seam";
system($cc, '-O2', '-o', $BIN, $SRC, '-lcap') == 0
    or plan skip_all => 'could not compile the executor';
system($cc, '-O2', '-DCE_TEST_SEAM', '-o', $SEAM, $SRC, '-lcap') == 0
    or plan skip_all => 'could not compile the executor (test build)';

my $nobody = getpwnam('nobody');
plan skip_all => 'no nobody user' unless defined $nobody && $nobody != 0;

my $S      = "$T/s";              # the script directory: root, 0755
my $marker = "$T/ran";            # every script appends its name here
mkdir $S or die;
sub script {
    my ($path, $mode, $body) = @_;
    open my $f, '>', $path or die "$path: $!";
    print $f $body;
    close $f;
    chmod $mode, $path;
}
sub sh { my ($name) = @_; "#!/bin/bash\necho \"\$0\"\necho $name >> '$marker'\nexit 0\n" }

script("$S/ok.sh",   0755, sh('ok'));
script("$S/gw.sh",   0775, sh('gw'));
script("$S/other.sh", 0755, sh('other'));  chown $nobody, 0, "$S/other.sh";
script("$S/ok.pl",   0755, "#!/usr/bin/perl\nprint \"\$0\\n\";\n"
                         . "open my \$m, '>>', '$marker' or die; print \$m \"pl\\n\";\nexit 0;\n");
mkdir "$T/ww";   chmod 01777, "$T/ww";  script("$T/ww/x.sh", 0755, sh('ww'));
mkdir "$T/odir"; chown $nobody, 0, "$T/odir"; script("$T/odir/x.sh", 0755, sh('odir'));
script("$S/good.sh", 0755, sh('good'));
script("$S/evil.sh", 0755, sh('evil'));
symlink "$S/good.sh", "$S/link.sh";

my $agent_conf = "$T/agent.conf";
script($agent_conf, 0644, "port = 7443\ncert = /x\nkey = /y\nca = /z\n"
                        . "[profile default]\nno_new_privileges = yes\n");
my $scripts_conf = "$T/scripts.conf";
script($scripts_conf, 0644, join '', map { "$_\n" }
    "ok    = $S/ok.sh",
    "pl    = $S/ok.pl",
    "gw    = $S/gw.sh",
    "other = $S/other.sh",
    "ww    = $T/ww/x.sh",
    "odir  = $T/odir/x.sh",
    "link  = $S/link.sh",
);

# Start an executor, run one script through it, stop it.
sub run_via {
    my ($bin, $name, %env) = @_;
    my $sock = "$T/exec.sock";
    unlink $sock;
    my $pid = ChildGuard::guarded_fork() // die "fork: $!";
    if ($pid == 0) {
        $ENV{$_} = $env{$_} for keys %env;
        open STDERR, '>>', "$T/serve.err";
        exec($bin, 'serve', $sock, $agent_conf, $scripts_conf, 'root') or POSIX::_exit(127);
    }
    my $ready = 0;
    for (1 .. 100) { if (-S $sock) { $ready = 1; last } select undef, undef, undef, 0.05 }
    my $r = $ready
        ? Exec::Agent::ExecClient::run(socket => $sock, reqid => "o-$name", script => $name, args => [])
        : { exit => -1, error => 'executor did not serve' };
    kill 'TERM', $pid; waitpid $pid, 0;
    return $r;
}
sub ran { open my $m, '<', $marker or return ''; local $/; my $s = <$m>; return $s }

subtest 'a correctly owned bash script runs, with its own path as $0' => sub {
    unlink $marker;
    my $r = run_via($BIN, 'ok');
    is $r->{exit}, 0, 'exit 0' or diag explain $r;
    is $r->{stdout}, "$S/ok.sh\n", '$0 is the script path';
    is ran(), "ok\n", 'it ran';
};

subtest 'a #! perl script runs, with its own path as $0' => sub {
    unlink $marker;
    my $r = run_via($BIN, 'pl');
    is $r->{exit}, 0, 'exit 0' or diag explain $r;
    is $r->{stdout}, "$S/ok.pl\n", '$0 is the script path';
    is ran(), "pl\n", 'it ran';
};

my %refused = (
    gw    => "'$S/gw.sh' is group-writable",
    other => "'$S/other.sh' is owned by uid $nobody, not root",
    ww    => "'$T/ww' is world-writable",
    odir  => "'$T/odir' is owned by uid $nobody, not root",
);
for my $name (sort keys %refused) {
    subtest "refused: $refused{$name}" => sub {
        unlink $marker;
        my $r = run_via($BIN, $name);
        is $r->{exit}, 126, 'exit 126';
        is $r->{stderr}, "executor: script not permitted: $refused{$name}\n", 'names the path and the rule';
        is ran(), '', 'the script did not run';
    };
}

subtest 'a symlink swapped after the check: neither file runs' => sub {
    unlink $marker;
    my $fifo = "$T/pause";
    mkfifo($fifo, 0600) or die "mkfifo: $!";
    # Helper: wait until the executor is paused at the fifo (after the check),
    # swap the link to evil.sh (also root-owned and allowed by the rule), then
    # let the executor go on.
    my $helper = fork() // die "fork: $!";
    if ($helper == 0) {
        my ($fh, $open);
        for (1 .. 200) {
            if (sysopen $fh, $fifo, O_WRONLY | O_NONBLOCK) { $open = 1; last }
            select undef, undef, undef, 0.05;
        }
        POSIX::_exit(3) unless $open;        # never paused
        symlink "$S/evil.sh", "$S/link.new" or POSIX::_exit(4);
        rename "$S/link.new", "$S/link.sh"  or POSIX::_exit(5);
        syswrite $fh, 'g';
        close $fh;
        POSIX::_exit(0);
    }
    my $r = run_via($SEAM, 'link', CE_TEST_PAUSE_FIFO => $fifo);
    waitpid $helper, 0;
    is $? >> 8, 0, 'the executor paused between the check and the exec, and the link was swapped';
    is $r->{exit}, 126, 'exit 126';
    is $r->{stderr}, "executor: script not permitted: '$S/link.sh' changed while it was being checked\n",
        'the change is named';
    is ran(), '', 'neither the checked script nor the swapped-in one ran';

    # Unswapped, the same link runs its target.
    unlink "$S/link.sh"; symlink "$S/good.sh", "$S/link.sh";
    unlink $marker;
    $r = run_via($BIN, 'link');
    is $r->{exit}, 0, 'a link in a root-owned directory to a root-owned script runs';
    is ran(), "good\n", 'its target ran';
};

done_testing;
