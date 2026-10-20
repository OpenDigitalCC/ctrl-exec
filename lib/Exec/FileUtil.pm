package Exec::FileUtil;

# Shared file helpers. These were reimplemented (near-)identically in a dozen
# modules - _slurp in two flavours (croak vs return-undef) and an atomic
# temp-file+rename writer with per-module mode/owner quirks. Consolidated here so
# the atomic-write guarantee (no torn reads of registry/run/cert files) is in one
# place and cannot silently regress to a plain truncating write.

use strict;
use warnings;
use feature      qw(signatures);
no warnings      qw(experimental::signatures);
use Carp           qw(croak);
use File::Basename qw(dirname);
use File::Path     qw(make_path);
use File::Temp     qw(tempfile);
use Fcntl          qw(O_CREAT O_RDWR O_NOFOLLOW LOCK_EX LOCK_NB LOCK_UN);
use Exporter       qw(import);

our @EXPORT_OK = qw(slurp slurp_maybe write_atomic open_lock flock_path_nb sweep_lock_files);

# Read a whole file and return its contents. Croaks if it cannot be opened.
sub slurp ($path) {
    open my $fh, '<', $path or croak "Cannot read '$path': $!";
    local $/;
    return scalar <$fh>;
}

# Like slurp, but returns undef on failure instead of dying.
sub slurp_maybe ($path) {
    open my $fh, '<', $path or return undef;
    local $/;
    return scalar <$fh>;
}

# Atomically write $content to $path via a temp file in the same directory plus
# rename, so a concurrent reader never observes a partial write. Options:
#   mode     => octal perms for the final file (default 0644)
#   make_dir => create the parent dir if missing (default 1); when 0, croak if
#               the parent does not already exist
# Croaks on failure (after cleaning up the temp file).
sub write_atomic ($path, $content, %opts) {
    my $mode = defined $opts{mode} ? $opts{mode} : 0644;
    my $dir  = dirname($path);

    if ($opts{make_dir} // 1) {
        make_path($dir) unless -d $dir;
    }
    else {
        croak "Directory '$dir' does not exist" unless -d $dir;
    }

    my ($tmp_fh, $tmp_path) = tempfile(DIR => $dir, UNLINK => 0);
    print $tmp_fh $content;
    close $tmp_fh;
    chmod $mode, $tmp_path;

    rename $tmp_path, $path
        or do { unlink $tmp_path; croak "Cannot write '$path': $!" };
    return 1;
}

# --- lock files ---------------------------------------------------------------
#
# Lock files live in directories that more than one account can write (the
# setgid ctrl-exec lock dir), so a planted symlink at a lock path must be refused,
# never followed: every lock open uses O_NOFOLLOW (fails with ELOOP) and a lock
# file is only ever created, never truncated.

# Open (creating if need be) a lock file for flock-ing. Returns the filehandle,
# or undef with $! set (ELOOP when $path is a symlink). A freshly created file is
# made group-writable: the root CLI and the unprivileged API server must each be
# able to flock a lock the other created. Only the creator can chmod, and it is
# harmless if the file already existed.
sub open_lock ($path) {
    my $existed = -e $path;
    sysopen(my $fh, $path, O_CREAT | O_RDWR | O_NOFOLLOW, 0660) or return undef;
    chmod 0660, $path unless $existed;
    return $fh;
}

# True if $fh is still the file at $path (it has not been swept away or replaced).
sub _same_file ($fh, $path) {
    my @a = stat $fh   or return 0;
    my @b = lstat $path or return 0;
    return $a[0] == $b[0] && $a[1] == $b[1];
}

# Try, without blocking, to take an exclusive flock on the lock file at $path.
# Returns ($fh, 1) when taken, ($fh, 0) when another process holds it, and
# (undef) when the file cannot be opened ($! set). Stale lock files are removed
# by sweep_lock_files, so after a successful flock the path is re-checked: if the
# file was unlinked between our open and our flock we hold a dead inode and must
# retry on the fresh one, or two processes could each "hold" the same lock.
sub flock_path_nb ($path) {
    for (1 .. 5) {
        my $fh = open_lock($path) or return undef;
        my $got = flock($fh, LOCK_EX | LOCK_NB) ? 1 : 0;
        return ($fh, $got) if _same_file($fh, $path) || ($got == 0 && -e $path);
        close $fh;   # swept under us - retry on the current file
    }
    $! = 0;
    return undef;
}

# Remove lock files in $dir whose name matches $re and which nobody holds. Safe
# against concurrent lockers: a file is unlinked only while we hold its flock,
# and flock_path_nb re-checks the path after locking. Symlinks and non-regular
# files are left alone. Returns the number removed.
sub sweep_lock_files ($dir, $re) {
    opendir my $dh, $dir or return 0;
    my @names = grep { $_ =~ $re } readdir $dh;
    closedir $dh;
    my $removed = 0;
    for my $n (@names) {
        my $path = "$dir/$n";
        next if -l $path || !-f _;
        sysopen(my $fh, $path, O_RDWR | O_NOFOLLOW) or next;
        if (flock($fh, LOCK_EX | LOCK_NB)) {
            $removed++ if _same_file($fh, $path) && unlink $path;
            flock $fh, LOCK_UN;
        }
        close $fh;
    }
    return $removed;
}

1;
