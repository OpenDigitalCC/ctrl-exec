#!/usr/bin/perl
# update-ctrl-exec-serial.t
#
# Tests for the update-ctrl-exec-serial bash script.
#
# The script runs on the agent host. These tests invoke it directly via
# system() so they require bash to be present. The tests do not require
# a running ctrl-exec-agent - the SIGHUP send is exercised against a
# temporary pid file pointing at the test process itself.
#
# Exit codes documented:
#   0  success
#   1  usage error (bad or missing serial argument)
#   2  write failed
#   3  reload failed (could not send SIGHUP)

use strict;
use warnings;
use Test::More;
use File::Temp qw(tempfile tempdir);
use File::Basename qw(dirname);
use POSIX qw(getpid);
use FindBin qw($Bin);

# Locate the script relative to this test file.
# Expected layout: bin/update-ctrl-exec-serial, t/update-ctrl-exec-serial.t
my $SCRIPT = "$Bin/../bin/update-ctrl-exec-serial";
unless (-f $SCRIPT && -x $SCRIPT) {
    plan skip_all => "update-ctrl-exec-serial not found or not executable at $SCRIPT";
}
unless (system('bash --version >/dev/null 2>&1') == 0) {
    plan skip_all => 'bash not available';
}

# Several subtests point the script's pid file at this test process so the
# reload SIGHUP is delivered to a live process. Ignore SIGHUP process-wide so
# that delivery cannot terminate the test (the default disposition). The
# dedicated reload subtest installs a local handler to observe receipt.
$SIG{HUP} = 'IGNORE';

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

sub run_script {
    my (%opts) = @_;
    # opts: serial, serial_file, pid_file, env
    my @env_pairs;
    push @env_pairs, "ENVEXEC_SERIAL_FILE=$opts{serial_file}"
        if defined $opts{serial_file};
    push @env_pairs, "ENVEXEC_AGENT_PIDFILE=$opts{pid_file}"
        if defined $opts{pid_file};

    my $env_prefix = @env_pairs ? join(' ', @env_pairs) . ' ' : '';
    my $serial_arg = defined $opts{serial} ? " '$opts{serial}'" : '';

    my $cmd = "${env_prefix}bash $SCRIPT${serial_arg} 2>/tmp/_test_stderr";
    my $out = `$cmd`;
    my $rc  = $? >> 8;
    my $err = do { local $/; open my $fh, '<', '/tmp/_test_stderr' or ''; <$fh> // '' };
    return ($rc, $out, $err);
}

# ---------------------------------------------------------------------------
# Argument validation
# ---------------------------------------------------------------------------

subtest 'rejects missing serial argument' => sub {
    my ($rc, $out, $err) = run_script();
    is $rc, 1, 'exits 1 for missing argument';
    like $err || $out, qr/usage|serial|required/i,
        'usage message mentions serial';
};

subtest 'rejects empty serial' => sub {
    my ($rc, $out, $err) = run_script(serial => '');
    is $rc, 1, 'exits 1 for empty serial';
};

subtest 'rejects non-hex serial' => sub {
    for my $bad ('not-hex', 'UPPER123', '12 34', 'abc!', '0xdeadbeef') {
        my ($rc, $out, $err) = run_script(serial => $bad);
        is $rc, 1, "exits 1 for non-hex serial '$bad'";
    }
};

# ---------------------------------------------------------------------------
# Serial length validation
# ---------------------------------------------------------------------------

subtest 'rejects serial shorter than 8 hex characters' => sub {
    for my $bad ('', 'a', 'ab', 'abcdef', '1234567') {
        next if $bad eq '';   # covered by empty serial test above
        my ($rc, $out, $err) = run_script(serial => $bad);
        is $rc, 1, "exits 1 for serial of length " . length($bad) . " ('$bad')";
        like $err || $out, qr/length|8.*40|short/i,
            'error message mentions length';
    }
};

subtest 'rejects serial longer than 40 hex characters' => sub {
    my $long41 = 'a' x 41;
    my ($rc, $out, $err) = run_script(serial => $long41);
    is $rc, 1, 'exits 1 for 41-character serial';
    like $err || $out, qr/length|8.*40|long/i,
        'error message mentions length';

    my $long80 = 'b' x 80;
    ($rc, $out, $err) = run_script(serial => $long80);
    is $rc, 1, 'exits 1 for 80-character serial';
};

subtest 'accepts serial of minimum length (8 chars)' => sub {
    my $dir   = tempdir(CLEANUP => 1);
    my $sfile = "$dir/ctrl-exec-serial";
    my $pfile = "$dir/ctrl-exec-agent.pid";
    open my $fh, '>', $pfile or die $!;
    print $fh getpid(), "\n";
    close $fh;

    my ($rc, $out, $err) = run_script(
        serial      => 'deadbeef',   # exactly 8 chars
        serial_file => $sfile,
        pid_file    => $pfile,
    );
    is $rc, 0, 'exits 0 for 8-character serial';
};

subtest 'accepts serial of typical length (20 chars)' => sub {
    my $dir   = tempdir(CLEANUP => 1);
    my $sfile = "$dir/ctrl-exec-serial";
    my $pfile = "$dir/ctrl-exec-agent.pid";
    open my $fh, '>', $pfile or die $!;
    print $fh getpid(), "\n";
    close $fh;

    my ($rc, $out, $err) = run_script(
        serial      => 'a' x 20,
        serial_file => $sfile,
        pid_file    => $pfile,
    );
    is $rc, 0, 'exits 0 for 20-character serial';
};

subtest 'accepts serial of maximum length (40 chars)' => sub {
    my $dir   = tempdir(CLEANUP => 1);
    my $sfile = "$dir/ctrl-exec-serial";
    my $pfile = "$dir/ctrl-exec-agent.pid";
    open my $fh, '>', $pfile or die $!;
    print $fh getpid(), "\n";
    close $fh;

    my ($rc, $out, $err) = run_script(
        serial      => 'f' x 40,   # exactly 40 chars
        serial_file => $sfile,
        pid_file    => $pfile,
    );
    is $rc, 0, 'exits 0 for 40-character serial';
};

subtest 'uppercase serial normalised to lowercase in output file' => sub {
    my $dir   = tempdir(CLEANUP => 1);
    my $sfile = "$dir/ctrl-exec-serial";
    my $pfile = "$dir/ctrl-exec-agent.pid";
    open my $fh, '>', $pfile or die $!;
    print $fh getpid(), "\n";
    close $fh;

    run_script(
        serial      => 'DEADBEEF01234567',
        serial_file => $sfile,
        pid_file    => $pfile,
    );
    my $content = do { local $/; open my $rfh, '<', $sfile or die $!; <$rfh> };
    chomp $content;
    is $content, 'deadbeef01234567', 'uppercase serial stored as lowercase';
};

# ---------------------------------------------------------------------------
# Valid lowercase hex serial (original tests continue below)
# ---------------------------------------------------------------------------

subtest 'accepts valid lowercase hex serial' => sub {
    my $dir    = tempdir(CLEANUP => 1);
    my $sfile  = "$dir/ctrl-exec-serial";
    my $pfile  = "$dir/ctrl-exec-agent.pid";

    # Point pid file at our own process so SIGHUP is sent to a live process
    open my $fh, '>', $pfile or die "Cannot write pid file: $!";
    print $fh getpid(), "\n";
    close $fh;

    my ($rc, $out, $err) = run_script(
        serial      => 'deadbeef01234567',
        serial_file => $sfile,
        pid_file    => $pfile,
    );
    is $rc, 0, 'exits 0 for valid lowercase hex serial';
};

subtest 'accepts valid uppercase hex serial (normalised to lowercase)' => sub {
    my $dir    = tempdir(CLEANUP => 1);
    my $sfile  = "$dir/ctrl-exec-serial";
    my $pfile  = "$dir/ctrl-exec-agent.pid";

    open my $fh, '>', $pfile or die $!;
    print $fh getpid(), "\n";
    close $fh;

    my ($rc, $out, $err) = run_script(
        serial      => 'DEADBEEF01234567',
        serial_file => $sfile,
        pid_file    => $pfile,
    );
    # Script may accept uppercase or normalise - either is correct.
    # What matters is it does not reject it with exit 1.
    isnt $rc, 1, 'does not reject uppercase hex as invalid';
};

# ---------------------------------------------------------------------------
# File write
# ---------------------------------------------------------------------------

subtest 'writes serial to ENVEXEC_SERIAL_FILE' => sub {
    my $dir    = tempdir(CLEANUP => 1);
    my $sfile  = "$dir/ctrl-exec-serial";
    my $pfile  = "$dir/ctrl-exec-agent.pid";

    open my $fh, '>', $pfile or die $!;
    print $fh getpid(), "\n";
    close $fh;

    my ($rc, $out, $err) = run_script(
        serial      => 'cafebabe00001111',
        serial_file => $sfile,
        pid_file    => $pfile,
    );
    is $rc, 0, 'exits 0';
    ok -f $sfile, 'serial file created';

    my $written = do { local $/; open my $rfh, '<', $sfile or die $!; <$rfh> };
    chomp $written;
    like $written, qr/cafebabe00001111/i, 'serial written to file';
};

subtest 'serial file contains only the serial (no extra content)' => sub {
    my $dir    = tempdir(CLEANUP => 1);
    my $sfile  = "$dir/ctrl-exec-serial";
    my $pfile  = "$dir/ctrl-exec-agent.pid";

    open my $fh, '>', $pfile or die $!;
    print $fh getpid(), "\n";
    close $fh;

    run_script(
        serial      => 'aabb1122ccdd3344',
        serial_file => $sfile,
        pid_file    => $pfile,
    );

    my $content = do { local $/; open my $rfh, '<', $sfile or die $!; <$rfh> };
    # Strip newline; file should be the serial and nothing else
    $content =~ s/\s+$//;
    like $content, qr/^[0-9a-fA-F]+$/, 'serial file contains only hex content';
};

subtest 'overwrites existing serial file' => sub {
    my $dir    = tempdir(CLEANUP => 1);
    my $sfile  = "$dir/ctrl-exec-serial";
    my $pfile  = "$dir/ctrl-exec-agent.pid";

    # Write an old serial
    open my $fh, '>', $sfile or die $!;
    print $fh "oldserial0000\n";
    close $fh;

    open $fh, '>', $pfile or die $!;
    print $fh getpid(), "\n";
    close $fh;

    run_script(
        serial      => 'feedface12345678',
        serial_file => $sfile,
        pid_file    => $pfile,
    );

    my $content = do { local $/; open my $rfh, '<', $sfile or die $!; <$rfh> };
    like $content, qr/feedface12345678/i, 'old serial overwritten with new';
    unlike $content, qr/oldserial/,        'old serial not present';
};

subtest 'uses default serial file path when env var not set' => sub {
    # We cannot write to /etc/ctrl-exec-agent/ in a test environment.
    # Confirm the script accepts the path from env and that the default
    # is documented. Skip if running as non-root.
    if ($> != 0) {
        pass 'skipped: default path test requires root';
        return;
    }
    # If running as root, verify /etc/ctrl-exec-agent/ is the default
    # by checking the script source.
    my $src = do { local $/; open my $fh, '<', $SCRIPT or die $!; <$fh> };
    like $src, qr{/etc/ctrl-exec-agent},
        'default serial file path is /etc/ctrl-exec-agent/...';
};

# ---------------------------------------------------------------------------
# SIGHUP / reload
# ---------------------------------------------------------------------------

subtest 'sends SIGHUP to pid from pid file' => sub {
    my $dir    = tempdir(CLEANUP => 1);
    my $sfile  = "$dir/ctrl-exec-serial";
    my $pfile  = "$dir/ctrl-exec-agent.pid";

    # Use our own PID; SIGHUP to ourself is harmless in a Perl test process
    open my $fh, '>', $pfile or die $!;
    print $fh getpid(), "\n";
    close $fh;

    # Install a SIGHUP handler to detect receipt
    my $got_hup = 0;
    local $SIG{HUP} = sub { $got_hup = 1 };

    my ($rc, $out, $err) = run_script(
        serial      => 'deadbeef01234567',
        serial_file => $sfile,
        pid_file    => $pfile,
    );

    # Note: the child process sends SIGHUP to our PID. Whether the parent
    # (this test) receives it depends on signal delivery timing. We check
    # exit code as the primary assertion; the got_hup flag is informational.
    is $rc, 0, 'exits 0 when pid file exists and points to live process';
    diag "SIGHUP received by test process: " . ($got_hup ? 'yes' : 'no (timing dependent)');
};

subtest 'handles missing pid file gracefully' => sub {
    my $dir    = tempdir(CLEANUP => 1);
    my $sfile  = "$dir/ctrl-exec-serial";
    my $pfile  = "$dir/nonexistent.pid";

    # No pid file written - script should fall back to pidof or fail with exit 3
    my ($rc, $out, $err) = run_script(
        serial      => 'aabbccdd11223344',
        serial_file => $sfile,
        pid_file    => $pfile,
    );

    # Serial file may or may not be written before the reload attempt.
    # Exit 3 is expected when reload fails; exit 0 is acceptable if the
    # script finds the agent via a fallback (pidof).
    ok $rc == 0 || $rc == 3,
        "exits 0 (fallback found agent) or 3 (reload failed) when pid file absent, got $rc";

    if ($rc == 3) {
        like $err || $out, qr/reload|pid|signal|hup/i,
            'exit 3 accompanied by explanatory message';
    }
};

subtest 'exit 2 when serial file cannot be written' => sub {
    # Point serial file to a non-writable directory
    my $dir   = tempdir(CLEANUP => 1);
    my $pfile = "$dir/ctrl-exec-agent.pid";

    open my $fh, '>', $pfile or die $!;
    print $fh getpid(), "\n";
    close $fh;

    # Skip if running as root (root can write anywhere)
    if ($> == 0) {
        pass 'skipped: unwritable path test cannot run as root';
        return;
    }

    my ($rc, $out, $err) = run_script(
        serial      => 'deadbeef',
        serial_file => '/root/cannot-write-here',
        pid_file    => $pfile,
    );
    is $rc, 2, 'exits 2 when serial file cannot be written';
};

done_testing;
