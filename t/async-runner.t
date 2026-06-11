#!/usr/bin/perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use FindBin    qw($Bin);
use lib "$Bin/../lib";

use Exec::Agent::AsyncRunner qw();

# Suppress syslog output during tests.
{
    no warnings 'redefine';
    *Exec::Log::log_action = sub {};
}

# Poll the result store until $reqid reaches $want status, or timeout. Polling
# (not a fixed sleep) keeps the test deterministic regardless of scheduling.
sub wait_for_status {
    my ($reqid, $dir, $want, $timeout) = @_;
    $timeout //= 5;
    my $deadline = time + $timeout;
    while (time <= $deadline) {
        my $r = Exec::Agent::AsyncRunner::result($reqid, $dir);
        return $r if $r && ($r->{status} // '') eq $want;
        select undef, undef, undef, 0.02;
    }
    return Exec::Agent::AsyncRunner::result($reqid, $dir);
}

sub write_script {
    my ($path, $body) = @_;
    open my $fh, '>', $path or die "write $path: $!";
    print {$fh} $body;
    close $fh;
    chmod 0755, $path;
}

# --- a fast job completes detached: result captured in the store ---
{
    my $dir    = tempdir(CLEANUP => 1);
    my $script = "$dir/echo.sh";
    write_script($script, "#!/bin/sh\necho hello-async\nexit 7\n");
    my $reqid  = 'aabbccdd00110001';

    my $ok = Exec::Agent::AsyncRunner::submit(
        reqid       => $reqid,
        script      => 'echo',
        script_path => $script,
        args        => [],
        runs_dir    => $dir,
    );
    is $ok->{ok}, 1, 'submit returns ok=1 (job spawned)';

    my $rec = wait_for_status($reqid, $dir, 'done', 5);
    is   $rec->{status}, 'done',           'job reaches done';
    is   $rec->{exit},   7,                'script exit code captured';
    like $rec->{stdout}, qr/hello-async/,  'script stdout captured';
    is   $rec->{reqid},  $reqid,           'reqid recorded';
    ok   $rec->{started} && $rec->{finished}, 'started and finished timestamps present';
}

# --- the running state is visible while the script runs (submit is async) ---
{
    my $dir    = tempdir(CLEANUP => 1);
    my $script = "$dir/slow.sh";
    write_script($script, "#!/bin/sh\nsleep 1\necho slow-done\n");
    my $reqid  = 'aabbccdd00110002';

    Exec::Agent::AsyncRunner::submit(
        reqid => $reqid, script => 'slow', script_path => $script, runs_dir => $dir,
    );

    # submit recorded 'running' synchronously before detaching; the 1s sleep
    # guarantees the script has not finished by the time we read here.
    my $running = Exec::Agent::AsyncRunner::result($reqid, $dir);
    is $running->{status}, 'running', 'result is running while the detached script runs';

    my $done = wait_for_status($reqid, $dir, 'done', 5);
    is   $done->{status}, 'done',         'result becomes done after the script exits';
    like $done->{stdout}, qr/slow-done/,  'slow job stdout captured';
}

# --- agent-side concurrency: same script refused while one is detached ---
{
    my $dir    = tempdir(CLEANUP => 1);
    my $script = "$dir/conc.sh";
    write_script($script, "#!/bin/sh\nsleep 1\necho conc-done\n");

    my $first = Exec::Agent::AsyncRunner::submit(
        reqid => 'aabbccdd00220001', script => 'conc',
        script_path => $script, runs_dir => $dir,
    );
    is $first->{ok}, 1, 'first run of a script is accepted';

    # The first job is still sleeping, so a second run of the same script is
    # refused with reason 'busy' (no record written for the second reqid).
    my $second = Exec::Agent::AsyncRunner::submit(
        reqid => 'aabbccdd00220002', script => 'conc',
        script_path => $script, runs_dir => $dir,
    );
    is $second->{ok},     0,      'concurrent run of the same script refused';
    is $second->{reason}, 'busy', 'refusal reason is busy';
    is Exec::Agent::AsyncRunner::result('aabbccdd00220002', $dir), undef,
        'no record written for the refused run';

    # A different script is unaffected by the lock on 'conc'.
    my $other_script = "$dir/other.sh";
    write_script($other_script, "#!/bin/sh\necho other\n");
    my $other = Exec::Agent::AsyncRunner::submit(
        reqid => 'aabbccdd00220003', script => 'other',
        script_path => $other_script, runs_dir => $dir,
    );
    is $other->{ok}, 1, 'a different script runs concurrently';

    # Once the first job finishes the lock frees and the script can run again.
    # The lock releases as the detached job exits, just after it writes 'done';
    # poll so the test does not race that final microsecond.
    wait_for_status('aabbccdd00220001', $dir, 'done', 5);
    my $again;
    my $deadline = time + 5;
    while (time <= $deadline) {
        $again = Exec::Agent::AsyncRunner::submit(
            reqid => 'aabbccdd00220004', script => 'conc',
            script_path => $script, runs_dir => $dir,
        );
        last if $again->{ok};
        select undef, undef, undef, 0.02;
    }
    is $again->{ok}, 1, 'script can run again after the previous job completes';
    wait_for_status('aabbccdd00220004', $dir, 'done', 5);
}

# --- result() for unknown reqid, and purge_expired ---
{
    my $dir = tempdir(CLEANUP => 1);
    is Exec::Agent::AsyncRunner::result('deadbeef', $dir), undef,
        'unknown reqid returns undef';

    my $script = "$dir/q.sh";
    write_script($script, "#!/bin/sh\nexit 0\n");
    my $reqid = 'aabbccdd00110003';
    Exec::Agent::AsyncRunner::submit(reqid => $reqid, script_path => $script, runs_dir => $dir);
    wait_for_status($reqid, $dir, 'done', 5);

    is Exec::Agent::AsyncRunner::purge_expired($dir, 86400), 0,
        'fresh record not purged within ttl';
    ok -f "$dir/$reqid.json", 'record still present';

    # Backdate the record well beyond the ttl, then purge.
    my $old = time() - 100_000;
    utime $old, $old, "$dir/$reqid.json";
    is Exec::Agent::AsyncRunner::purge_expired($dir, 86400), 1, 'aged record purged';
    ok !-f "$dir/$reqid.json", 'record removed';
}

# --- submit argument validation ---
{
    eval { Exec::Agent::AsyncRunner::submit(script_path => '/x') };
    like $@, qr/reqid required/, 'submit requires reqid';

    eval { Exec::Agent::AsyncRunner::submit(reqid => 'aabb') };
    like $@, qr/script_path required/, 'submit requires script_path';

    eval { Exec::Agent::AsyncRunner::submit(reqid => '../evil', script_path => '/x') };
    like $@, qr/invalid reqid/, 'submit rejects a reqid with path characters';
}

done_testing;
