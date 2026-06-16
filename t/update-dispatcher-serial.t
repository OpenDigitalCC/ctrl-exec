#!/usr/bin/perl
# update-dispatcher-serial.t
#
# Tests for the update-ctrl-exec-serial bash script, which maintains the agent's
# trusted-dispatcher map during cert rotation (add-then-remove), without
# re-pairing. The script runs on the agent host; these tests invoke it directly
# via system() so they require bash. The reload SIGHUP is exercised against a
# temporary pid file pointing at the test process itself.
#
# Exit codes documented:
#   0  success
#   1  usage / validation error
#   2  write failed
#   3  reload failed

use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use POSIX qw(getpid);
use FindBin qw($Bin);

my $SCRIPT = "$Bin/../bin/update-ctrl-exec-serial";
unless (-f $SCRIPT && -x $SCRIPT) {
    plan skip_all => "update-ctrl-exec-serial not found or not executable at $SCRIPT";
}
unless (system('bash --version >/dev/null 2>&1') == 0) {
    plan skip_all => 'bash not available';
}

# Several subtests point the script's pid file at this test process so the
# reload SIGHUP is delivered to a live process; ignore it so delivery cannot
# terminate the test.
$SIG{HUP} = 'IGNORE';

my $ERRFILE = "/tmp/_upd_serial_stderr_$$";

# Run the script with the given args (arrayref) and env overrides.
sub run_script {
    my (%opts) = @_;
    my @env;
    push @env, "ENVEXEC_TRUSTED_FILE=$opts{trusted_file}" if defined $opts{trusted_file};
    push @env, "ENVEXEC_AGENT_PIDFILE=$opts{pid_file}"    if defined $opts{pid_file};
    my $env_prefix = @env ? join(' ', @env) . ' ' : '';
    my $args = join ' ', map { "'$_'" } @{ $opts{args} // [] };
    my $cmd  = "${env_prefix}bash $SCRIPT $args 2>$ERRFILE";
    my $out  = `$cmd`;
    my $rc   = $? >> 8;
    my $err  = do { local $/; open my $fh, '<', $ERRFILE or return ($rc, $out, ''); <$fh> // '' };
    return ($rc, $out, $err);
}

# Set up a temp map dir with a pid file pointing at this process.
sub fresh {
    my (%opts) = @_;
    my $dir = tempdir(CLEANUP => 1);
    my $map = "$dir/ctrl-exec-dispatchers";
    my $pid = "$dir/agent.pid";
    open my $fh, '>', $pid or die $!;
    print $fh getpid(), "\n";
    close $fh;
    if (defined $opts{seed}) {
        open my $mh, '>', $map or die $!;
        print $mh $opts{seed};
        close $mh;
    }
    return ($dir, $map, $pid);
}

sub slurp {
    my ($path) = @_;
    return '' unless -f $path;
    open my $fh, '<', $path or die $!;
    local $/;
    return scalar <$fh>;
}

# ---------------------------------------------------------------------------
# Usage / argument errors
# ---------------------------------------------------------------------------

subtest 'rejects missing arguments' => sub {
    my ($rc) = run_script(args => []);
    is $rc, 1, 'no args exits 1';

    ($rc) = run_script(args => ['deadbeef']);
    is $rc, 1, 'single bare arg exits 1';

    ($rc) = run_script(args => ['a', 'b', 'c']);
    is $rc, 1, 'three args exits 1';
};

# ---------------------------------------------------------------------------
# Serial validation (shared by add and remove)
# ---------------------------------------------------------------------------

subtest 'rejects malformed serials' => sub {
    for my $bad ('not-hex', 'UPPER12!', '12 34', '0xdeadbeef', 'abcdef', 'a' x 41) {
        my ($rc) = run_script(args => [$bad, 'automation']);
        is $rc, 1, "add rejects serial '$bad'";
    }
    my ($rc) = run_script(args => ['--remove', 'zzzz']);
    is $rc, 1, 'remove rejects a non-hex serial';
};

# ---------------------------------------------------------------------------
# Dispatcher-id validation (add only)
# ---------------------------------------------------------------------------

subtest 'rejects malformed dispatcher ids' => sub {
    for my $bad ('bad id', '.leading', '-leading', 'has/slash', 'a' x 65) {
        my ($rc) = run_script(args => ['deadbeef01', $bad]);
        is $rc, 1, "rejects id '$bad'";
    }
};

# ---------------------------------------------------------------------------
# Add
# ---------------------------------------------------------------------------

subtest 'add writes the entry and reloads' => sub {
    my ($dir, $map, $pid) = fresh();
    my ($rc, $out) = run_script(
        args => ['deadbeef01', 'automation'], trusted_file => $map, pid_file => $pid);
    is $rc, 0, 'exits 0';
    like slurp($map), qr/^deadbeef01 automation$/m, 'entry written to the map';
};

subtest 'add normalises an uppercase serial to lowercase' => sub {
    my ($dir, $map, $pid) = fresh();
    run_script(args => ['DEADBEEF01', 'automation'], trusted_file => $map, pid_file => $pid);
    like slurp($map), qr/^deadbeef01 automation$/m, 'serial stored lowercase';
    unlike slurp($map), qr/DEADBEEF01/, 'uppercase form not present';
};

subtest 'add preserves other dispatchers and comments' => sub {
    my ($dir, $map, $pid) = fresh(seed => "# a comment\nbbbb2222 human\n");
    run_script(args => ['deadbeef01', 'automation'], trusted_file => $map, pid_file => $pid);
    my $c = slurp($map);
    like $c, qr/^# a comment$/m,         'comment preserved';
    like $c, qr/^bbbb2222 human$/m,      'other dispatcher preserved';
    like $c, qr/^deadbeef01 automation$/m, 'new dispatcher added';
};

subtest 'add updates the identity for an existing serial (no duplicate)' => sub {
    my ($dir, $map, $pid) = fresh(seed => "deadbeef01 oldname\n");
    run_script(args => ['deadbeef01', 'newname'], trusted_file => $map, pid_file => $pid);
    my $c = slurp($map);
    like   $c, qr/^deadbeef01 newname$/m, 'identity updated';
    unlike $c, qr/oldname/,               'old identity gone';
    my @lines = grep { /deadbeef01/ } split /\n/, $c;
    is scalar @lines, 1, 'no duplicate serial line';
};

# ---------------------------------------------------------------------------
# Remove (the second half of add-then-remove rotation)
# ---------------------------------------------------------------------------

subtest 'remove deletes the entry and keeps the rest' => sub {
    my ($dir, $map, $pid) = fresh(seed => "bbbb2222 human\ndeadbeef01 automation\n");
    my ($rc) = run_script(args => ['--remove', 'deadbeef01'], trusted_file => $map, pid_file => $pid);
    is $rc, 0, 'exits 0';
    my $c = slurp($map);
    unlike $c, qr/deadbeef01/,       'target serial removed';
    like   $c, qr/^bbbb2222 human$/m, 'other dispatcher kept';
};

subtest 'remove of an absent serial is a no-op success' => sub {
    my ($dir, $map, $pid) = fresh(seed => "bbbb2222 human\n");
    my ($rc) = run_script(args => ['--remove', 'ffff9999'], trusted_file => $map, pid_file => $pid);
    is $rc, 0, 'exits 0 even when the serial is not present';
    like slurp($map), qr/^bbbb2222 human$/m, 'existing entry untouched';
};

# ---------------------------------------------------------------------------
# Write / reload failures
# ---------------------------------------------------------------------------

subtest 'exit 2 when the map directory does not exist' => sub {
    my ($dir, undef, $pid) = fresh();
    my ($rc) = run_script(
        args => ['deadbeef01', 'automation'],
        trusted_file => "$dir/nonexistent-subdir/ctrl-exec-dispatchers",
        pid_file => $pid);
    is $rc, 2, 'exits 2 when the target directory is missing';
};

subtest 'exit 3 when the agent process cannot be signalled' => sub {
    my ($dir, $map, undef) = fresh();
    my ($rc) = run_script(
        args => ['deadbeef01', 'automation'],
        trusted_file => $map,
        pid_file => "$dir/nonexistent.pid");
    # The map is written, but reload fails because no pid/pidof match.
    ok $rc == 0 || $rc == 3,
        "exits 0 (pidof fallback found agent) or 3 (reload failed), got $rc";
    like slurp($map), qr/^deadbeef01 automation$/m, 'map still updated before reload attempt';
};

subtest 'default map path is the agent state directory' => sub {
    my $src = slurp($SCRIPT);
    like $src, qr{/var/lib/ctrl-exec-agent/ctrl-exec-dispatchers},
        'default ENVEXEC_TRUSTED_FILE is in the agent state directory';
};

unlink $ERRFILE;
done_testing;
