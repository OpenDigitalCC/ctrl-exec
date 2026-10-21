#!/usr/bin/perl
# t/perlcritic.t
#
# Run Perl::Critic over lib/ and bin/ with the repository's .perlcriticrc, so a
# new `return undef` (or anything else the agreed policy set catches) fails the
# suite. Skips when Perl::Critic is not installed; it is a development check,
# not a runtime dependency.

use strict;
use warnings;
use Test::More;
use File::Find qw(find);
use FindBin    qw($Bin);

eval { require Perl::Critic; 1 }
    or plan skip_all => 'Perl::Critic not installed';

my $root    = "$Bin/..";
my $profile = "$root/.perlcriticrc";
ok -f $profile, '.perlcriticrc present';

my $critic = Perl::Critic->new(-profile => $profile);

my @files;
find({ no_chdir => 1, wanted => sub { push @files, $_ if /\.pm\z/ } }, "$root/lib");
push @files, grep { -f } glob "$root/bin/*";

for my $file (sort @files) {
    (my $shown = $file) =~ s{\A\Q$root\E/}{};
    my @v = $critic->critique($file);
    is scalar @v, 0, "perlcritic: $shown"
        or diag join '', map { "$_" } @v;
}

done_testing;
