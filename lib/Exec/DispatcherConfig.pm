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

our @EXPORT_OK = qw(load_config);

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
