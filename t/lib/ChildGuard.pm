package ChildGuard;
# Helpers a test forks (an executor in serve mode, a listener, a stub server)
# must not outlive the test, however it ends. Three layers:
#
#   - END block: a test that finishes or dies stops every helper still running.
#   - TERM, INT and HUP handlers: a test killed by one of these (timeout(1),
#     Ctrl-C, a closed terminal) stops its helpers and removes its temporary
#     directories before it dies of the same signal.
#   - A watchdog process, in its own session, holding the read end of a pipe
#     from the test. When the test is gone for any reason - including SIGKILL,
#     or a SIGPIPE after prove itself was killed - the pipe reads EOF and the
#     watchdog stops the helpers and removes the directories registered with
#     dir(). It can also end a test that runs past a deadline().
#
# Each helper started with guarded_fork leads its own process group, so
# stopping it also stops what it started (an executor's actions, a listener's
# per-connection children). A helper is identified by its pid and its start
# time, so a pid reused after the helper exited is never signalled.
#
# The remaining exposure: SIGKILL of the watchdog itself together with the
# test (a kill of every process of the user, or of both pids) leaves helpers
# running, as before.

use strict;
use warnings;
use Exporter   qw(import);
use Fcntl      qw(F_GETFD F_SETFD FD_CLOEXEC);
use POSIX      qw(WNOHANG);
use Time::HiRes qw(sleep time);

our @EXPORT_OK = qw(guarded_fork);

my $OWNER = $$;
my %KIDS;          # pid => start time
my $WATCH;         # write end of the pipe to the watchdog

sub _start_time {
    my ($pid) = @_;
    open my $fh, '<', "/proc/$pid/stat" or return undef;
    my $s = <$fh> // return undef;
    $s =~ s/\A.*\)\s+//s;
    my @f = split ' ', $s;
    return $f[0] eq 'Z' ? undef : $f[19];    # field 22: start time in ticks
}

sub _live {
    # A child that exited but is not reaped yet shows as a zombie: reap it here
    # so it reads as gone.
    waitpid $_, WNOHANG for keys %KIDS;
    return grep { my $t = _start_time($_); defined $t && $t eq $KIDS{$_} } keys %KIDS;
}

# Stop every helper still alive: TERM to its group, then KILL after a grace.
sub _stop_all {
    my @live = _live();
    for my $sig (qw(TERM KILL)) {
        last unless @live;
        kill $sig, -$_, $_ for @live;
        my $until = time + 3;
        while (time < $until && (@live = _live())) { sleep 0.05 }
    }
    %KIDS = ();
}

# The watchdog: a fresh perl (exec, so it holds none of the test's sockets and
# runs none of its END blocks) in its own session, so signals sent to the
# test's process group do not reach it.
my $WATCHDOG = <<'PERL';
use strict; use warnings; use POSIX (); use File::Path qw(remove_tree);
use Time::HiRes qw(sleep time);
my ($fd, $test) = @ARGV;
# Its stderr is the test's, often a pipe to prove: if prove is gone, a
# report must not end the watchdog before it has done its work.
$SIG{PIPE} = 'IGNORE';
open my $in, '<&=', $fd or exit 1;
my (%kids, @dirs, $deadline, $buf);
sub st { open my $f, '<', "/proc/$_[0]/stat" or return undef; my $s = <$f> // return undef;
         $s =~ s/\A.*\)\s+//s; my @f = split ' ', $s; $f[0] eq 'Z' ? undef : $f[19] }
sub live { grep { my $t = st($_); defined $t && $t eq $kids{$_} } keys %kids }
my $killed = 0;
while (1) {
    my $wait = defined $deadline ? $deadline - time : undef;
    $wait = 0 if defined $wait && $wait < 0;
    my $rin = ''; vec($rin, $fd, 1) = 1;
    my $n = select(my $rout = $rin, undef, undef, $wait);
    if ($n == 0) {
        # Past the deadline: end the test; its signal handler stops its helpers.
        print STDERR "# ChildGuard: test $test still running at its deadline - sending TERM\n";
        kill 'TERM', $test;
        $deadline = time + 10;
        kill 'KILL', $test if $killed++;
        next;
    }
    next if $n < 0;
    my $got = sysread $in, my $chunk, 4096;
    last unless $got;    # EOF: the test is gone
    $buf .= $chunk;
    while ($buf =~ s/\A([^\n]*)\n//) {
        my $l = $1;
        if    ($l =~ /\AP (\d+) (\d+)\z/) { $kids{$1} = $2 }
        elsif ($l =~ /\AD (.+)\z/)        { push @dirs, $1 }
        elsif ($l =~ /\AT (\d+)\z/)       { $deadline = $1 }
    }
}
my @left = live();
my @live;
for my $sig (qw(TERM KILL)) {
    last unless @live = live();
    kill $sig, -$_, $_ for @live;
    my $until = time + 3;
    while (time < $until && (@live = live())) { sleep 0.05 }
}
remove_tree($_) for grep { -d } @dirs;
print STDERR "# ChildGuard: test $test ended with helper(s) running (@left) - stopped them\n" if @left;
POSIX::_exit(0);
PERL

sub _watch {
    return $WATCH if $WATCH || $$ != $OWNER;
    pipe my $r, my $w or return undef;
    # Forked twice, so the watchdog is no child of the test: a test (or the
    # code it drives) that reaps any child never meets it.
    my $pid = CORE::fork();
    return undef unless defined $pid;
    if ($pid == 0) {
        POSIX::setsid();
        POSIX::_exit(0) if CORE::fork();
        close $w;
        my $flags = fcntl $r, F_GETFD, 0;
        fcntl $r, F_SETFD, $flags & ~FD_CLOEXEC;
        open STDIN,  '<', '/dev/null';
        open STDOUT, '>', '/dev/null';
        no warnings q(exec);
        exec { $^X } $^X, '-e', $WATCHDOG, fileno($r), $OWNER;
        POSIX::_exit(127);
    }
    waitpid $pid, 0;
    close $r;
    $w->autoflush(1);
    $WATCH = $w;
    return $WATCH;
}

sub _tell {
    my ($line) = @_;
    my $w = _watch() or return;
    local $SIG{PIPE} = 'IGNORE';
    syswrite $w, "$line\n";
}

# Register a helper pid (parent side). Prefer guarded_fork, which does it.
sub track {
    my ($pid) = @_;
    return $pid unless $pid && $$ == $OWNER;
    POSIX::setpgid($pid, $pid);    # also done in the child; whichever runs first
    my $t = _start_time($pid) // return $pid;
    $KIDS{$pid} = $t;
    _tell("P $pid $t");
    return $pid;
}

# A directory the watchdog removes if the test dies without cleaning up.
sub dir {
    my ($path) = @_;
    _tell("D $path") if $$ == $OWNER;
    return $path;
}

# End the test (TERM) if it is still running $secs from now.
sub deadline {
    my ($secs) = @_;
    _tell('T ' . int(time + $secs)) if $$ == $OWNER;
}

# fork() for a long-lived helper. Returns as fork does. The child leads its
# own process group and has the default TERM, INT and HUP dispositions.
sub guarded_fork {
    _watch();
    my $pid = CORE::fork();
    return undef unless defined $pid;
    if ($pid == 0) {
        POSIX::setpgid(0, 0);
        $SIG{$_} = 'DEFAULT' for qw(TERM INT HUP);
        return 0;
    }
    return track($pid);
}

for my $sig (qw(TERM INT HUP)) {
    next if defined $SIG{$sig} && $SIG{$sig} ne '' && $SIG{$sig} ne 'DEFAULT';
    $SIG{$sig} = sub {
        if ($$ == $OWNER) {
            local $SIG{PIPE} = 'IGNORE';    # prove may be gone already
            _stop_all();
            File::Temp::cleanup() if defined &File::Temp::cleanup;
            print STDERR "# ChildGuard: caught SIG$sig - stopped helpers\n";
        }
        $SIG{$sig} = 'DEFAULT';
        kill $sig, $$;
    };
}

END {
    if ($$ == $OWNER && %KIDS) {
        local ($?, $!);
        _stop_all();
    }
}

1;
