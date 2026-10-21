#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);

# bash completion for ctrl-exec-agent / cea (etc/bash-completion/): the file is
# sourced in a bash subprocess with COMP_WORDS and COMP_CWORD set.

my $comp = "$Bin/../etc/bash-completion/ctrl-exec-agent";
my $bin  = "$Bin/../bin/ctrl-exec-agent";
ok(-f $comp, 'completion file present');

sub complete {
    my @w = @_;
    my $arr = join ' ', map { "'$_'" } @w;
    my $out = `bash -c "source '$comp'; COMP_WORDS=($arr); COMP_CWORD=$#w; _ctrl_exec_agent; printf '%s\\n' \\"\\\${COMPREPLY[@]}\\"" 2>&1`;
    return [ sort grep { length } split /\n/, $out ];
}

my @modes = qw(serve request-pairing pairing-status self-check self-ping
    promote-cert cert-staged paired remove-dispatcher list-dispatchers doctor);

is_deeply(complete('cea', ''), [ sort @modes ], 'first word: all modes');
is_deeply(complete('cea', 'self'), [qw(self-check self-ping)], 'mode prefix');
is_deeply(complete('cea', 'rem'), ['remove-dispatcher'], 'remove-dispatcher completes');
is_deeply(complete('cea', 'pa'), [qw(paired pairing-status)], 'prefix with two matches');
is_deeply(complete('cea', '--config', '/x', 'ser'), ['serve'], 'option value is not the mode');
is_deeply(complete('cea', 'serve', ''), [], 'no further words after the mode');

is_deeply(complete('cea', 'request-pairing', '--d'), [qw(--dispatcher --dispatcher-fingerprint)],
    'request-pairing --dispatcher');
is_deeply(complete('cea', 'request-pairing', '--dispatcher-f'), ['--dispatcher-fingerprint'],
    'request-pairing --dispatcher-fingerprint');
is_deeply(complete('cea', 'request-pairing', '--dispatcher', 'h', '--ba'), ['--background'],
    'request-pairing --background');
is_deeply(complete('cea', 'request-pairing', '--lookup-by', ''), [qw(hostname ip)], '--lookup-by values');
is_deeply(complete('cea', '--'),
    [qw(--allowlist --background --brief --config --dispatcher --dispatcher-fingerprint --fix
        --json --lookup-by --pidfile --port --rekey --timeout --version)],
    'all options');
is_deeply(complete('cea', 'serve', '--al'), ['--allowlist'], 'serve --allowlist');
is_deeply(complete('cea', 'do'), ['doctor'], 'doctor completes');
is_deeply(complete('cea', 'doctor', '--f'), ['--fix'], 'doctor --fix');

my $alias = `bash -c "source '$comp'; complete -p cea ctrl-exec-agent" 2>&1`;
like($alias, qr/-F _ctrl_exec_agent cea/, 'cea registered');
like($alias, qr/-F _ctrl_exec_agent ctrl-exec-agent/, 'ctrl-exec-agent registered');

# Drift: every mode and option in the bin is in the completion.
open my $bfh, '<', $bin or die "$bin: $!"; my $src = do { local $/; <$bfh> }; close $bfh;
my ($table) = $src =~ /my %dispatch = \((.*?)\n    \);/s;
my @bin_modes = $table =~ /^\s*'?([\w-]+)'?\s*=>/mg;
cmp_ok(scalar @bin_modes, '>=', 8, 'parsed the dispatch table');
my $all = join ' ', @{ complete('cea', '') };
for my $m (@bin_modes) {
    like($all, qr/(?:^| )\Q$m\E(?: |$)/, "mode '$m' is completed");
}
my ($go) = $src =~ /GetOptions\((.*?)\n    \)/s;
my @bin_opts = $go =~ /'([\w-]+)[=!]?[si]?'\s*=>/g;
cmp_ok(scalar @bin_opts, '>=', 7, 'parsed the option table');
my $opts = join ' ', @{ complete('cea', '--') };
for my $o (@bin_opts) {
    like($opts, qr/(?:^| )--\Q$o\E(?: |$)/, "option --$o is completed");
}

done_testing;
