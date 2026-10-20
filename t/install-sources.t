#!/usr/bin/perl
# t/install-sources.t
#
# Every file install.sh copies from the source tree must exist in it. A rename
# that misses install.sh otherwise breaks an install with no test failing (the
# 0.13 dispatcher-config rename pointed install.sh at a non-existent
# etc/ctrl-exec-dispatcher.conf.example).

use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);

my $root = "$Bin/..";
open my $fh, '<', "$root/install.sh" or die "install.sh: $!";
my $text = do { local $/; <$fh> };
close $fh;

# Literal "$SOURCE_DIR/<path>" references; skip ones built from variables.
my %paths;
while ($text =~ m{\$SOURCE_DIR/([A-Za-z0-9_./-]+)}g) {
    my $p = $1;
    $p =~ s{/+$}{};
    $paths{$p} = 1;
}

ok scalar(keys %paths) > 5, 'found the source paths install.sh copies';
ok -e "$root/$_", "install.sh source exists: $_" for sort keys %paths;

done_testing;
