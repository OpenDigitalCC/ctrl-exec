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

our @EXPORT_OK = qw(load_config conf_dir conf_path);

# The dispatcher's config directory (ctrl-exec.conf, the CA, the dispatcher
# cert/key, auth-hook). It was /etc/ctrl-exec before 0.13; the installers move an
# existing one and leave a symlink at the old name for one release. A host that
# still has only the old directory (half-migrated, or the migration not run yet)
# keeps working: conf_dir() falls back to it, with a warning. The two package
# variables are the seam the tests use.
our $CONF_DIR   = '/etc/ctrl-exec-dispatcher';
our $LEGACY_DIR = '/etc/ctrl-exec';
our $WARNED     = 0;

# The directory to use: the new one if it exists (it wins when both do), else
# the old one with a one-time warning, else the new one (a fresh install).
sub conf_dir () {
    return $CONF_DIR if -d $CONF_DIR;
    if (-d $LEGACY_DIR) {
        warn "ctrl-exec: using the legacy config directory $LEGACY_DIR - "
           . "move it to $CONF_DIR (install.sh and the packages do this on upgrade)\n"
            unless $WARNED++;
        return $LEGACY_DIR;
    }
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
