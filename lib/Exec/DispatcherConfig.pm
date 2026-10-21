package Exec::DispatcherConfig;

# The dispatcher's flat INI config loader (key = value, '#' comments), shared by
# ctrl-exec-dispatcher and ctrl-exec-api, which carried byte-identical copies.
# Requires cert/key/ca. The agent's richer sectioned config (profiles, tags) is a
# deliberately separate parser - Exec::Agent::Config.

use strict;
use warnings;
use feature      qw(signatures);
no warnings      qw(experimental::signatures);
use Exporter qw(import);
use Cwd      qw(abs_path);

our @EXPORT_OK = qw(load_config conf_dir conf_path legacy_dir_error);

# The dispatcher's config directory (ctrl-exec.conf, the CA, the dispatcher
# cert/key, auth-hook). It was /etc/ctrl-exec before 0.13; the installers move an
# existing one and leave a symlink at the old name for one release. A real
# directory still at the old name is refused (T-047), never used and never
# ignored: falling back to it, or quietly preferring the new directory, let a
# host run on the wrong config (an allow-all hook, or a second CA beside the
# real one). The two package variables are the seam the tests use.
our $CONF_DIR   = '/etc/ctrl-exec-dispatcher';
our $LEGACY_DIR = '/etc/ctrl-exec';

# The refusal message when the old path exists and is not the migration symlink
# to the new directory, else undef. The binaries call this first so the refusal
# is logged and exits 78 (EX_CONFIG) before any mode runs.
sub legacy_dir_error () {
    return unless -e $LEGACY_DIR || -l $LEGACY_DIR;
    my $new = abs_path($CONF_DIR);
    my $old = -l $LEGACY_DIR ? abs_path($LEGACY_DIR) : undef;
    return if defined $old && defined $new && $old eq $new;
    return "ctrl-exec: refusing to start: the old config directory $LEGACY_DIR "
         . "exists and is not a symlink to $CONF_DIR.\n"
         . "The dispatcher's config now lives in $CONF_DIR, and running on "
         . "either directory while the other exists could use the wrong "
         . "configuration or create a second CA.\n"
         . "To migrate: stop ctrl-exec-api, move the directory "
         . "(mv $LEGACY_DIR $CONF_DIR; if $CONF_DIR already exists, merge "
         . "what you need into it and remove $LEGACY_DIR), then change the "
         . "paths inside $CONF_DIR/ctrl-exec.conf (cert, key, ca, auth_hook, "
         . "...) from $LEGACY_DIR/ to $CONF_DIR/.\n"
         . "In a container: mount the volume at $CONF_DIR instead of "
         . "$LEGACY_DIR, edit those paths on the volume, and recreate the "
         . "container.\n";
}

# The directory to use. Dies with legacy_dir_error() when the old path blocks
# it; otherwise the new directory, whether or not it exists yet (a fresh
# install creates it).
sub conf_dir () {
    my $err = legacy_dir_error();
    die $err if defined $err;
    return $CONF_DIR;
}

# Default location of ctrl-exec.conf under the directory conf_dir() picked.
sub conf_path () {
    return conf_dir() . '/ctrl-exec.conf';
}

sub load_config ($path) {
    open my $fh, '<', $path
        or die "Cannot open config '$path': $!\n";
    my %config;
    while (my $line = <$fh>) {
        chomp $line;
        next if $line =~ /^\s*[#\s]/;
        $config{$1} = $2 if $line =~ /^\s*(\w+)\s*=\s*(.+?)\s*$/;
    }
    close $fh;
    for my $k (qw(cert key ca)) {
        die "Missing '$k' in $path\n" unless $config{$k};
    }
    return \%config;
}

1;
