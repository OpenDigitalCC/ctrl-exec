#!/usr/bin/perl
# t/dispatcher-conf-dir-migrate.t
#
# T-065: a dispatcher whose real config is still at the old /etc/ctrl-exec runs
# on it (in place) instead of refusing, and the installers (deb postinst,
# install.sh) move it to /etc/ctrl-exec-dispatcher. "Real" is ctrl-exec.conf
# plus the CA key (ca.key); the directory the image and packages seed holds no
# CA. Only that case changes: both directories with a CA, an old directory
# with no CA, and a symlink elsewhere are refused as before (T-047), and a
# fresh or already migrated host sees nothing new. A mount point (a container
# volume) is never moved. The directories are pointed at temp dirs through
# the package variables.

use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use FindBin    qw($Bin);
use lib "$Bin/../lib";

use Exec::DispatcherConfig qw();

sub fresh_root {
    my $root = tempdir(CLEANUP => 1);
    return ($root, "$root/ctrl-exec-dispatcher", "$root/ctrl-exec");
}

sub put {
    my ($path, $body) = @_;
    open my $fh, '>', $path or die "$path: $!";
    print $fh $body;
    close $fh;
}

sub slurp {
    my ($path) = @_;
    open my $fh, '<', $path or return;
    local $/;
    return scalar <$fh>;
}

# A real 0.12 config: ctrl-exec.conf naming files under the old directory, the CA.
sub real_config {
    my ($dir) = @_;
    mkdir $dir or die "$dir: $!";
    put("$dir/ctrl-exec.conf",
        "# operator's config\ncert = $dir/dispatcher.crt\nkey  = $dir/dispatcher.key\n"
      . "ca   = $dir/ca.crt\nauth_hook = $dir/auth-hook\napi_port = 7445\n");
    put("$dir/ca.key", "OLDCAKEY\n");
    put("$dir/ca.crt", "OLDCA\n");
    put("$dir/auth-hook", "#!/bin/sh\nexit 0\n");
}

# What the packages and the image seed: the example config and hook, no CA.
sub seeded_config {
    my ($dir) = @_;
    mkdir $dir or die "$dir: $!";
    put("$dir/ctrl-exec.conf", "# seeded example\n");
    put("$dir/auth-hook", "#!/bin/sh\nexit 0\n");
}

# Run $code with the dirs pointed at the temp tree; no mount points, unless
# the caller says the old directory is one.
sub with_dirs {
    my ($new, $old, $code, %o) = @_;
    local $Exec::DispatcherConfig::CONF_DIR   = $new;
    local $Exec::DispatcherConfig::LEGACY_DIR = $old;
    local $Exec::DispatcherConfig::IS_MOUNT   = sub { $o{mount} ? 1 : 0 };
    local $Exec::DispatcherConfig::RENAME     = $o{rename} if $o{rename};
    my @w;
    local $SIG{__WARN__} = sub { push @w, @_ };
    my $r = eval { $code->() };
    return ($r, $@, \@w);
}

sub state_of { my ($new, $old, %o) = @_;
    my ($s) = with_dirs($new, $old, sub { Exec::DispatcherConfig::conf_dir_state() }, %o);
    return $s;
}

sub migrate { my ($new, $old, %o) = @_;
    my ($r, $err) = with_dirs($new, $old, sub { Exec::DispatcherConfig::migrate_legacy_dir() }, %o);
    die $err if $err;
    return $r;
}

# --- old real, new absent ------------------------------------------------------
{
    my ($root, $new, $old) = fresh_root();
    real_config($old);
    my ($d, $err) = with_dirs($new, $old, sub { Exec::DispatcherConfig::conf_dir() });
    is $err, '', 'old real only: no refusal';
    is $d, $old, 'old real only: runs in place on the old directory';
    my $s = state_of($new, $old);
    is $s->{action}, 'in-place', 'old real only: state is in-place';
    my ($e) = with_dirs($new, $old, sub { Exec::DispatcherConfig::legacy_dir_error() });
    ok !defined $e, 'old real only: legacy_dir_error is undef';

    # The installer moves it.
    my $r = migrate($new, $old);
    is $r->{result}, 'migrated', 'old real only: installer migrates';
    ok -l $old, 'old path is now a symlink';
    is readlink($old), $new, 'pointing at the new directory';
    is slurp("$new/ca.key"), "OLDCAKEY\n", 'the CA key moved with it';
    my $conf = slurp("$new/ctrl-exec.conf");
    like $conf, qr{^cert = \Q$new\E/dispatcher\.crt$}m, 'cert path rewritten';
    like $conf, qr{^auth_hook = \Q$new\E/auth-hook$}m, 'auth_hook path rewritten';
    unlike $conf, qr{\Q$old\E/}, 'no old path left in ctrl-exec.conf';
    like $conf, qr{^api_port = 7445$}m, 'other lines untouched';
    like slurp("$new/ctrl-exec.conf.pre-0.13"), qr{\Q$old\E/dispatcher\.crt}, 'previous config kept';
    ($d, $err) = with_dirs($new, $old, sub { Exec::DispatcherConfig::conf_dir() });
    is $d, $new, 'after migration: the new directory';

    # A second run changes nothing.
    $r = migrate($new, $old);
    is $r->{result}, 'none', 'migration is idempotent';
}

# --- old real, new seeded --------------------------------------------------------
{
    my ($root, $new, $old) = fresh_root();
    real_config($old);
    seeded_config($new);
    my ($d, $err) = with_dirs($new, $old, sub { Exec::DispatcherConfig::conf_dir() });
    is $err, '', 'old real + new seeded: no refusal';
    is $d, $old, 'old real + new seeded: runs in place on the old directory (the real CA)';

    my $r = migrate($new, $old);
    is $r->{result}, 'migrated', 'old real + new seeded: installer migrates';
    is slurp("$new/ca.key"), "OLDCAKEY\n", 'the real config is at the new path';
    is readlink($old), $new, 'old path symlinked';
    is slurp("$new.seeded/ctrl-exec.conf"), "# seeded example\n", 'the seeded directory is kept aside, not deleted';
}

# --- both real: refuse, naming both, and the installer leaves both alone ------------
{
    my ($root, $new, $old) = fresh_root();
    real_config($old);
    real_config($new);
    my ($d, $err) = with_dirs($new, $old, sub { Exec::DispatcherConfig::conf_dir() });
    ok !defined $d, 'both with a CA: conf_dir does not return';
    like $err, qr/\Q$old\E/, 'both with a CA: names the old path';
    like $err, qr/\Q$new\E/, 'both with a CA: names the new path';
    like $err, qr/both/i, 'both with a CA: says both hold a CA';
    my $r = migrate($new, $old);
    is $r->{result}, 'refused', 'both with a CA: installer does not migrate';
    ok -d $old && !-l $old, 'both with a CA: old directory untouched';
    is slurp("$old/ca.key"), "OLDCAKEY\n", 'both with a CA: old CA untouched';
}

# --- old with no CA beside an existing new dir: ambiguous, refused (T-047) ------------
for my $kind (qw(seeded real)) {
    my ($root, $new, $old) = fresh_root();
    seeded_config($old);
    $kind eq 'real' ? real_config($new) : seeded_config($new);
    my ($d, $err) = with_dirs($new, $old, sub { Exec::DispatcherConfig::conf_dir() });
    ok !defined $d, "old dir with no CA, new $kind: refused";
    like $err, qr/\Q$old\E.*\Q$new\E/s, "old dir with no CA, new $kind: the T-047 message";
    is migrate($new, $old)->{result}, 'refused', "old dir with no CA, new $kind: installer does not move it";
    ok -d $old && !-l $old, "old dir with no CA, new $kind: untouched";
}

# --- old with ctrl-exec.conf but no ca.key, new absent: no ambiguity, so as before
# 0.13 it is moved by the installers and used in place at start (a CA kept
# elsewhere via ca =, or a dispatcher not yet initialised) -----------------------------
{
    my ($root, $new, $old) = fresh_root();
    mkdir $old or die;
    put("$old/ctrl-exec.conf", "cert = $old/dispatcher.crt\nca = /srv/ca/ca.crt\n");
    my ($d, $err) = with_dirs($new, $old, sub { Exec::DispatcherConfig::conf_dir() });
    is $err, '', 'old conf without CA, new absent: no refusal';
    is $d, $old, 'old conf without CA, new absent: runs in place';
    my $r = migrate($new, $old);
    is $r->{result}, 'migrated', 'old conf without CA, new absent: installer migrates';
    is readlink($old), $new, 'old conf without CA, new absent: symlink left';
    my $conf = slurp("$new/ctrl-exec.conf");
    like $conf, qr{^cert = \Q$new\E/dispatcher\.crt$}m, 'old conf without CA: path rewritten';
    like $conf, qr{^ca = /srv/ca/ca\.crt$}m, 'old conf without CA: CA kept elsewhere untouched';
}
{
    # An old directory with no ctrl-exec.conf at all is still not a config.
    my ($root, $new, $old) = fresh_root();
    mkdir $old or die;
    my ($d) = with_dirs($new, $old, sub { Exec::DispatcherConfig::conf_dir() });
    ok !defined $d, 'old dir with no ctrl-exec.conf, new absent: refused as before';
    is migrate($new, $old)->{result}, 'refused', 'old dir with no ctrl-exec.conf: installer does not move it';
}

# --- the migration symlink and a fresh host: no change at all ---------------------------
{
    my ($root, $new, $old) = fresh_root();
    real_config($new);
    symlink $new, $old or die;
    my ($d, $err, $w) = with_dirs($new, $old, sub { Exec::DispatcherConfig::conf_dir() });
    is $d, $new, 'symlink: new directory';
    is scalar(@$w), 0, 'symlink: no warning';
    is state_of($new, $old)->{action}, 'new', 'symlink: state is new';
    is migrate($new, $old)->{result}, 'none', 'symlink: installer does nothing';
}
{
    my ($root, $new, $old) = fresh_root();
    my ($d, $err, $w) = with_dirs($new, $old, sub { Exec::DispatcherConfig::conf_dir() });
    is $d, $new, 'fresh: new directory';
    is scalar(@$w), 0, 'fresh: no warning';
    is migrate($new, $old)->{result}, 'none', 'fresh: installer does nothing';
    ok !-e $new && !-e $old, 'fresh: nothing created';
}

# --- container: the old path is a mount point - run in place, never move ----------------
{
    my ($root, $new, $old) = fresh_root();
    real_config($old);
    seeded_config($new);
    my ($d, $err) = with_dirs($new, $old, sub { Exec::DispatcherConfig::conf_dir() }, mount => 1);
    is $d, $old, 'mount point: runs in place';
    my $s = state_of($new, $old, mount => 1);
    ok $s->{mount}, 'mount point: state says so (for the log and doctor)';
    my $r = migrate($new, $old, mount => 1);
    is $r->{result}, 'in-place', 'mount point: installer does not move it';
    ok -d $old && !-l $old, 'mount point: old directory untouched';
    like slurp("$old/ctrl-exec.conf"), qr{\Q$old\E/dispatcher\.crt}, 'mount point: config not rewritten';
    is slurp("$new/ctrl-exec.conf"), "# seeded example\n", 'mount point: seeded dir untouched';
}

# --- a failed move leaves everything as it was --------------------------------------
{
    my ($root, $new, $old) = fresh_root();
    real_config($old);
    seeded_config($new);
    my $n = 0;
    # The first rename (seeded dir aside) works, the second (old -> new) fails.
    my $rename = sub { return ++$n == 1 ? rename($_[0], $_[1]) : do { $! = 18; 0 } };
    my $r = migrate($new, $old, rename => $rename);
    is $r->{result}, 'in-place', 'failed move: reported, runs in place';
    ok -d $old && !-l $old, 'failed move: old directory intact';
    is slurp("$old/ca.key"), "OLDCAKEY\n", 'failed move: old CA intact';
    like slurp("$old/ctrl-exec.conf"), qr{\Q$old\E/dispatcher\.crt}, 'failed move: config not rewritten';
    is slurp("$new/ctrl-exec.conf"), "# seeded example\n", 'failed move: seeded dir put back';
    ok !-e "$new.seeded", 'failed move: no aside left behind';
    my ($d) = with_dirs($new, $old, sub { Exec::DispatcherConfig::conf_dir() });
    is $d, $old, 'failed move: conf_dir still runs in place';
}

# --- a process that cannot read the old directory gets the T-047 message ----------------
SKIP: {
    skip 'root reads any directory', 2 if $> == 0;
    my ($root, $new, $old) = fresh_root();
    real_config($old);
    chmod 0000, $old or die;
    my ($d, $err) = with_dirs($new, $old, sub { Exec::DispatcherConfig::conf_dir() });
    chmod 0755, $old;
    ok !defined $d, 'unreadable old dir: does not run';
    like $err, qr/refusing.*\Q$old\E/s, 'unreadable old dir: the T-047 message';
}

# --- the mount point check itself ------------------------------------------------------
ok Exec::DispatcherConfig::_is_mount_point('/proc'), '/proc is a mount point';
{
    my ($root) = fresh_root();
    mkdir "$root/d" or die;
    ok !Exec::DispatcherConfig::_is_mount_point("$root/d"), 'a plain directory is not';
}

# --- the binaries run in place: no exit 78, nothing on stderr about the directory --------
{
    my ($root, $new, $old) = fresh_root();
    real_config($old);
    seeded_config($new);
    my $out = qx{$^X -I$Bin/../lib -e '
        use Exec::DispatcherConfig;
        \$Exec::DispatcherConfig::CONF_DIR = q{$new};
        \$Exec::DispatcherConfig::LEGACY_DIR = q{$old};
        \$Exec::DispatcherConfig::IS_MOUNT = sub { 1 };
        print Exec::DispatcherConfig::startup_check(), "\\n";
    ' 2>&1};
    is $?, 0, 'startup_check: in place does not exit';
    like $out, qr/^\Q$old\E$/m, 'startup_check: returns the old directory';
    unlike $out, qr/refusing/, 'startup_check: no refusal text';
}

done_testing;
