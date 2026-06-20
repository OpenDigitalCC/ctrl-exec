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
use Exporter       qw(import);

our @EXPORT_OK = qw(slurp slurp_maybe write_atomic);

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

1;
