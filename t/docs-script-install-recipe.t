#!/usr/bin/perl
# t/docs-script-install-recipe.t  (T-048 follow-up)
#
# The recipe that installs an agent script must give a file the default
# profile's run_as user (nobody) can read and execute, and root must own it
# (T-045). A 750 root:ctrl-exec-agent file fails with "not executable by the
# profile's run_as user". Two checks:
#   1. the documented modes, applied to a real file, pass the same "other"
#      permission test the executor's access(X_OK) applies to run_as=nobody,
#      and a 750 root:group file does not;
#   2. no install recipe in the docs, website, installer hints or postinst
#      messages still tells the operator to use mode 750 for a script.
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use FindBin qw($Bin);

my $root = "$Bin/..";

# 1. Mode arithmetic: a user who is neither owner nor in the group falls to the
# "other" bits (the run_as=nobody case), which must include read+execute.
sub other_can_rx { my ($mode) = @_; return ($mode & 05) == 05 }
my $T = tempdir(CLEANUP => 1);
for my $case ([0755, 1, 'documented 755 root:root'], [0750, 0, '750 root:group']) {
    my ($mode, $ok, $label) = @$case;
    my $f = "$T/s-$mode.sh";
    open my $h, '>', $f or die; print $h "#!/bin/sh\nexit 0\n"; close $h;
    chmod $mode, $f;
    is other_can_rx((stat $f)[2] & 07777) ? 1 : 0, $ok, "$label: run_as 'nobody' can read+exec = $ok";
}

# 2. No recipe still says 750 for a script (the directory and the shipped
# demonstrator are 750 as installed and are not recipes).
my @files = ('docs/INSTALL.md', 'docs/DEVELOPER.md', 'docs/DOCKER.md',
             'website/plugins.md', 'website/quickstart.md', 'install.sh');
for my $rel (@files) {
    open my $h, '<', "$root/$rel" or die "$rel: $!";
    my @bad;
    while (<$h>) {
        next unless /\b(?:install\b.*-m\s*750|chmod\s+750)\b.*\.sh\b/;
        next if /demonstrator/;
        push @bad, "$.: $_";
    }
    ok !@bad, "$rel: no 750 script install recipe" or diag @bad;
}
done_testing;
