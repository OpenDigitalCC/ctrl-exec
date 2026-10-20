#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use File::Temp qw(tempdir);

# install.sh's install_completion() and the debian packaging both ship every
# file in etc/bash-completion/, with ced and cea as links to their commands.

my $root = "$Bin/..";
my @files = map { s{.*/}{}r } glob("$root/etc/bash-completion/*");
is_deeply([ sort @files ], [qw(ctrl-exec-agent ctrl-exec-api ctrl-exec-dispatcher)],
    'one completion file per command');

# install.sh, lazily loaded directory: files plus ced/cea links.
my $dst = tempdir(CLEANUP => 1);
my $script = <<"END";
set -euo pipefail
source "$root/install.sh"
SOURCE_DIR="$root"
COMPLETION_DIR="$dst/completions"
mkdir -p "\$COMPLETION_DIR"
install_completion ctrl-exec-agent cea
install_completion ctrl-exec-dispatcher ced
install_completion ctrl-exec-api
END
is(system('bash', '-c', $script . ' >/dev/null'), 0, 'install_completion runs');
ok(-f "$dst/completions/$_", "$_ installed") for @files;
is(readlink("$dst/completions/ced"), 'ctrl-exec-dispatcher', 'ced links to the dispatcher file');
is(readlink("$dst/completions/cea"), 'ctrl-exec-agent', 'cea links to the agent file');

# Old-style directory: files only (the complete line covers the short names).
my $dst2 = tempdir(CLEANUP => 1);
$script =~ s{COMPLETION_DIR="[^"]*"}{COMPLETION_DIR="$dst2/bash_completion.d"};
$script =~ s{completions"\n}{bash_completion.d"\n};
is(system('bash', '-c', $script . ' >/dev/null'), 0, 'install into bash_completion.d');
ok(-f "$dst2/bash_completion.d/ctrl-exec-agent", 'file installed');
ok(!-e "$dst2/bash_completion.d/cea", 'no short-name link there');

# No completion directory: skipped without error.
is(system('bash', '-c', qq{source "$root/install.sh"; SOURCE_DIR="$root"; COMPLETION_DIR=""; install_completion ctrl-exec-agent cea}), 0,
    'no completion directory: no error');

# Debian packaging.
open my $fh, '<', "$root/debian/rules" or die; my $rules = do { local $/; <$fh> }; close $fh;
my %pkg;
for my $p (qw(agent dispatcher)) {
    for my $k (qw(install links)) {
        open my $f, '<', "$root/debian/ctrl-exec-$p.$k" or die; $pkg{"$p.$k"} = do { local $/; <$f> }; close $f;
    }
}
like($rules, qr{for c in ctrl-exec-agent ctrl-exec-dispatcher ctrl-exec-api;.*etc/bash-completion/\$\$c}s,
    'debian/rules stages all three files');
my $cd = 'usr/share/bash-completion/completions';
like($pkg{'agent.install'},      qr{^\Q$cd\E/ctrl-exec-agent$}m, 'agent deb ships its completion');
like($pkg{'dispatcher.install'}, qr{^\Q$cd\E/ctrl-exec-dispatcher$}m, 'dispatcher deb ships its completion');
like($pkg{'dispatcher.install'}, qr{^\Q$cd\E/ctrl-exec-api$}m, 'dispatcher deb ships the api completion');
like($pkg{'agent.links'},      qr{^\Q$cd\E/ctrl-exec-agent \Q$cd\E/cea$}m, 'cea link in the agent deb');
like($pkg{'dispatcher.links'}, qr{^\Q$cd\E/ctrl-exec-dispatcher \Q$cd\E/ced$}m, 'ced link in the dispatcher deb');

done_testing;
