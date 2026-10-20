#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use File::Temp qw(tempdir);

# bash completion for ctrl-exec-api (etc/bash-completion/ctrl-exec-api).

my $comp = "$Bin/../etc/bash-completion/ctrl-exec-api";
my $bin  = "$Bin/../bin/ctrl-exec-api";
ok(-f $comp, 'completion file present');

my $tmp = tempdir(CLEANUP => 1);
open my $fh, '>', "$tmp/ctrl-exec.conf" or die; close $fh;

sub complete {
    my @w = @_;
    my $arr = join ' ', map { "'$_'" } @w;
    my $out = `bash -c "source '$comp'; COMP_WORDS=($arr); COMP_CWORD=$#w; _ctrl_exec_api; printf '%s\\n' \\"\\\${COMPREPLY[@]}\\"" 2>&1`;
    return [ sort grep { length } split /\n/, $out ];
}

is_deeply(complete('ctrl-exec-api', '--'), ['--config'], 'options');
is_deeply(complete('ctrl-exec-api', ''), [], 'no modes');
is_deeply(complete('ctrl-exec-api', '--config', "$tmp/ctrl"), ["$tmp/ctrl-exec.conf"],
    '--config completes a file');

# Drift: every option in the bin is in the completion.
open my $bfh, '<', $bin or die "$bin: $!"; my $src = do { local $/; <$bfh> }; close $bfh;
my ($go) = $src =~ /GetOptions\((.*?)\)\s*\n?\s*or die/s;
my @bin_opts = $go =~ /'([\w-]+)[=!]?[si]?'\s*=>/g;
cmp_ok(scalar @bin_opts, '>=', 1, 'parsed the option table');
my $opts = join ' ', @{ complete('ctrl-exec-api', '--') };
for my $o (@bin_opts) {
    like($opts, qr/(?:^| )--\Q$o\E(?: |$)/, "option --$o is completed");
}

done_testing;
