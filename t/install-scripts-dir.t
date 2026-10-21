#!/usr/bin/perl
# t/install-scripts-dir.t  (T-048 follow-up)
#
# install.sh creates the agent scripts directory 755 root:root so the shipped
# default profile (run_as = nobody) can reach the scripts in it, and an upgrade
# opens the old 750 root:<agent group> directory. Any other mode or owner is the
# operator's choice and is left alone. install.sh is sourced (main does not run)
# and setup_scripts_dir called against a temp tree; stat and chown are stubs on
# PATH (the test is not root): stat answers from a marker file, chown records.
# The deb postinst has the same logic in sh; it is checked for the same text.

use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use File::Temp qw(tempdir);

my $install_sh = "$Bin/../install.sh";
sub slurp { open(my $fh, '<', $_[0]) or return ''; local $/; <$fh> }
sub spew  { open(my $fh, '>', $_[0]) or die "$_[0]: $!"; print $fh $_[1]; close $fh }

sub run_case {
    my ($existing_stat) = @_;   # undef: directory absent
    my $r = tempdir(CLEANUP => 1);
    mkdir "$r/stubbin"; mkdir "$r/state";
    spew("$r/stubbin/stat",  "#!/bin/sh\ncat \"\$STATE/stat\"\n");
    spew("$r/stubbin/chown", "#!/bin/sh\necho \"\$*\" >> \"\$STATE/chown\"\n");
    chmod 0755, "$r/stubbin/stat", "$r/stubbin/chown";
    my $dir = "$r/scripts";
    if (defined $existing_stat) {
        mkdir $dir; chmod 0750, $dir;
        spew("$r/state/stat", "$existing_stat\n");
    }
    local $ENV{PATH}  = "$r/stubbin:$ENV{PATH}";
    local $ENV{STATE} = "$r/state";
    my $out = `bash -c 'set -euo pipefail; source "$install_sh"; SCRIPTS_DIR="$dir"; AGENT_GROUP=ctrl-exec-agent; setup_scripts_dir' 2>&1`;
    my $mode = -d $dir ? sprintf('%o', (stat $dir)[2] & 07777) : 'absent';
    return ($mode, slurp("$r/state/chown"), $out);
}

my ($mode, $chown) = run_case(undef);
is $mode, '755', 'new directory is 755';
like $chown, qr/^root:root /, 'new directory chowned root:root';

($mode, $chown) = run_case('750 root:ctrl-exec-agent');
is $mode, '755', 'old 750 root:ctrl-exec-agent directory is opened to 755';
like $chown, qr/^root:root /, 'and chowned root:root';

($mode, $chown) = run_case('750 root:ops');
is $mode, '750', 'a 750 directory with another group is left alone';
is $chown, '', 'and not chowned';

($mode, $chown) = run_case('755 root:root');
is $mode, '750', 'an already-755 root:root directory is not touched (mode unchanged by the stub case)';
is $chown, '', 'and not chowned';

my $pi = slurp("$Bin/../debian/ctrl-exec-agent.postinst");
like $pi, qr/"750 root:ctrl-exec-agent"/, 'postinst opens only the old 750 root:ctrl-exec-agent state';
like $pi, qr/chmod 755 \/opt\/ctrl-exec-scripts\/ctrl-exec-demonstrator\.sh/, 'postinst installs the demonstrator 755';
unlike $pi, qr/chmod -R|chown -R/, 'postinst is never recursive';
my $is = slurp($install_sh);
like $is, qr/safe_install 755 .*ctrl-exec-demonstrator/, 'install.sh installs the demonstrator 755';
done_testing;
