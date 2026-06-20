#!/usr/bin/perl
use strict;
use warnings;
use Test::More tests => 24;
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
