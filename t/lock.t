#!/usr/bin/perl
use strict;
use warnings;
use Test::More tests => 35;
use File::Temp qw(tempdir);
use IPC::Open2  qw(open2);
use FindBin    qw($Bin);
use lib "$Bin/../lib";

# Suppress syslog noise during tests
open my $saved_stderr, '>&', \*STDERR;
open STDERR, '>', '/dev/null';

use Exec::Lock qw();

my $tmpdir  = tempdir(CLEANUP => 1);
my $dir     = "$tmpdir/locks";
my $holder  = "$Bin/lock-holder.pl";

# Helper: start the lock holder, wait for "locked" confirmation.
# Returns ($pid, $child_stdin, $child_stdout).
# Close $child_stdin to release the lock.
sub start_holder {
    my ($host, $script) = @_;
    my ($child_out, $child_in);
    my $pid = open2($child_out, $child_in, $^X, $holder, $dir, $host, $script)
        or BAIL_OUT("Cannot start lock holder: $!");
    my $msg = <$child_out>;
    chomp $msg;
    BAIL_OUT("Lock holder failed to acquire $host:$script") unless $msg eq 'locked';
    return ($pid, $child_in, $child_out);
}

sub stop_holder {
    my ($pid, $child_in, $child_out) = @_;
    close $child_in;
    close $child_out;
    waitpid $pid, 0;
}

# --- argument validation ---

{
    eval { Exec::Lock::check_available(script => 'x', lock_dir => $dir) };
    like $@, qr/hosts required/, 'check_available: dies without hosts';
}

{
    eval { Exec::Lock::check_available(hosts => ['h'], lock_dir => $dir) };
    like $@, qr/script required/, 'check_available: dies without script';
}

{
    eval { Exec::Lock::check_available(hosts => 'bad', script => 'x', lock_dir => $dir) };
    like $@, qr/hosts must be an arrayref/, 'check_available: dies if hosts not arrayref';
}

{
    eval { Exec::Lock::acquire(script => 'x', lock_dir => $dir) };
    like $@, qr/hosts required/, 'acquire: dies without hosts';
}

{
    eval { Exec::Lock::acquire(hosts => ['h'], lock_dir => $dir) };
    like $@, qr/script required/, 'acquire: dies without script';
}

{
    eval { Exec::Lock::release(hosts => [], script => 'x') };
    like $@, qr/handles required/, 'release: dies without handles';
}

# A new lock file is group-writable, so the root CLI and the unprivileged
# ctrl-exec API (both in the ctrl-exec group via the setgid dir) can each flock
# locks the other created.
{
    my $res  = Exec::Lock::acquire(hosts => ['gw'], script => 'gw', lock_dir => $dir);
    my $mode = (stat "$dir/gw--gw.lock")[2] & 07777;
    ok $mode & 0020, sprintf('a new lock file is group-writable (mode %04o)', $mode);
    Exec::Lock::release(handles => $res->{handles}) if $res->{ok};
}

# --- check_available: no conflict ---

{
    my $result = Exec::Lock::check_available(
        hosts    => ['host-a'],
        script   => 'backup',
        lock_dir => $dir,
    );
    ok $result->{ok}, 'check_available: no conflict on fresh lock dir';
}

{
    my $result = Exec::Lock::check_available(
        hosts    => ['host-a', 'host-b'],
        script   => 'backup',
        lock_dir => $dir,
    );
    ok $result->{ok}, 'check_available: no conflict for multiple hosts';
}

# --- acquire and release ---

{
    my $result = Exec::Lock::acquire(
        hosts    => ['host-a'],
        script   => 'backup',
        lock_dir => $dir,
    );
    ok $result->{ok},                    'acquire: succeeds on free lock';
    ok ref $result->{handles} eq 'ARRAY', 'acquire: returns handles arrayref';
    is scalar @{ $result->{handles} }, 1, 'acquire: one handle per host';

    Exec::Lock::release(
        handles => $result->{handles},
        hosts   => ['host-a'],
        script  => 'backup',
    );

    # After release, should be acquirable again
    my $result2 = Exec::Lock::acquire(
        hosts    => ['host-a'],
        script   => 'backup',
        lock_dir => $dir,
    );
    ok $result2->{ok}, 'acquire: succeeds again after release';
    Exec::Lock::release(
        handles => $result2->{handles},
        hosts   => ['host-a'],
        script  => 'backup',
    );
}

# --- lock files are opened with O_NOFOLLOW (T-024) ---
# A symlink planted at the lock path must be refused, not followed, and its
# target must not be created, truncated or chmod-ed.
{
    my $target = "$tmpdir/victim";
    open my $v, '>', $target or die $!;
    print $v "precious\n";
    close $v;
    chmod 0600, $target;
    symlink $target, "$dir/ln--ln.lock" or die "symlink: $!";

    eval { Exec::Lock::acquire(hosts => ['ln'], script => 'ln', lock_dir => $dir) };
    like $@, qr/symlink|Too many levels/i, 'acquire: a symlinked lock path is refused';
    eval { Exec::Lock::check_available(hosts => ['ln'], script => 'ln', lock_dir => $dir) };
    like $@, qr/symlink|Too many levels/i, 'check_available: a symlinked lock path is refused';

    is((stat $target)[2] & 07777, 0600, 'symlink target mode untouched');
    open my $r, '<', $target or die $!;
    is scalar(<$r>), "precious\n", 'symlink target content untouched';
    close $r;

    my $held = Exec::Lock::list_held(lock_dir => $dir);
    ok !(grep { $_->{host} eq 'ln' } @$held), 'list_held: skips the symlink';
    unlink "$dir/ln--ln.lock";
}

# --- lock files do not accumulate (T-024) ---
# Release never unlinks (unlinking a flock'd file lets a second process lock a
# fresh inode while the first still holds the old one), so repeated cycles on the
# same pair must reuse one file, and sweep_stale removes files nobody holds.
{
    my $count = sub { scalar(() = glob "$dir/*.lock") };
    my $r1 = Exec::Lock::acquire(hosts => ['cyc'], script => 'cyc', lock_dir => $dir);
    Exec::Lock::release(handles => $r1->{handles});
    my $after_one = $count->();
    for (1 .. 5) {
        my $r = Exec::Lock::acquire(hosts => ['cyc'], script => 'cyc', lock_dir => $dir);
        Exec::Lock::release(handles => $r->{handles});
    }
    is $count->(), $after_one, 'repeated lock/unlock does not grow the directory';

    # Many distinct pairs, each used once: files for pairs no longer in use are
    # swept, so the directory stays bounded instead of gaining one per pair.
    for my $n (1 .. 8) {
        my $r = Exec::Lock::acquire(hosts => ["churn$n"], script => 'churn', lock_dir => $dir);
        Exec::Lock::release(handles => $r->{handles});
    }
    cmp_ok $count->(), '<=', $after_one + 1,
        'distinct short-lived pairs do not accumulate lock files';

    # A held file must survive the sweep, an idle one must go.
    my $held = Exec::Lock::acquire(hosts => ['keep'], script => 'keep', lock_dir => $dir);
    Exec::Lock::check_available(hosts => ['idle'], script => 'idle', lock_dir => $dir);
    ok -e "$dir/idle--idle.lock", 'check_available leaves an idle lock file behind';
    my $removed = Exec::Lock::sweep_stale(lock_dir => $dir);
    is $removed, 1, 'sweep_stale: removes exactly the idle file';
    ok !-e "$dir/idle--idle.lock", 'sweep_stale: removes an unheld lock file';
    ok -e "$dir/keep--keep.lock", 'sweep_stale: keeps a held lock file';
    Exec::Lock::release(handles => $held->{handles});
}

# --- conflict detection ---
# Uses an exec'd subprocess (lock-holder.pl) to hold the lock. A forked
# child cannot be used because flock locks are per open-file-description -
# fork shares the parent's file table, so the parent sees the lock as
# already held by itself and check_available incorrectly reports no conflict.

{
    my ($pid, $child_in, $child_out) = start_holder('host-c', 'deploy');

    my $check = Exec::Lock::check_available(
        hosts    => ['host-c'],
        script   => 'deploy',
        lock_dir => $dir,
    );
    ok !$check->{ok},                           'check_available: detects held lock';
    is scalar @{ $check->{conflicts} }, 1,      'check_available: one conflict';
    is $check->{conflicts}[0], 'host-c:deploy', 'check_available: correct conflict pair';

    my $acq = Exec::Lock::acquire(
        hosts    => ['host-c'],
        script   => 'deploy',
        lock_dir => $dir,
    );
    ok !$acq->{ok},                           'acquire: fails on held lock';
    is $acq->{conflicts}[0], 'host-c:deploy', 'acquire: correct conflict pair';

    stop_holder($pid, $child_in, $child_out);

    my $after = Exec::Lock::check_available(
        hosts    => ['host-c'],
        script   => 'deploy',
        lock_dir => $dir,
    );
    ok $after->{ok}, 'check_available: free after lock released';
}

# --- multi-host partial conflict ---

{
    my ($pid, $child_in, $child_out) = start_holder('host-d', 'sync');

    my $check = Exec::Lock::check_available(
        hosts    => ['host-d', 'host-e'],
        script   => 'sync',
        lock_dir => $dir,
    );
    ok !$check->{ok},                         'multi-host: partial conflict detected';
    is scalar @{ $check->{conflicts} }, 1,    'multi-host: only one conflict reported';
    is $check->{conflicts}[0], 'host-d:sync', 'multi-host: correct conflicting pair';

    my $acq = Exec::Lock::acquire(
        hosts    => ['host-d', 'host-e'],
        script   => 'sync',
        lock_dir => $dir,
    );
    ok !$acq->{ok}, 'multi-host acquire: fails on partial conflict';

    stop_holder($pid, $child_in, $child_out);

    # host-e must be free - acquire rolled back on conflict
    my $e_check = Exec::Lock::check_available(
        hosts    => ['host-e'],
        script   => 'sync',
        lock_dir => $dir,
    );
    ok $e_check->{ok}, 'multi-host: rollback - host-e free after failed acquire';
}

# Restore stderr
open STDERR, '>&', $saved_stderr;

done_testing;
