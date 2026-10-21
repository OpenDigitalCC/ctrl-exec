#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use File::Temp qw(tempdir);

# bash completion for ctrl-exec-dispatcher / ced (etc/bash-completion/).
# The completion file is sourced in a bash subprocess with COMP_WORDS and
# COMP_CWORD set, and the resulting COMPREPLY is asserted.

my $comp = "$Bin/../etc/bash-completion/ctrl-exec-dispatcher";
my $bin  = "$Bin/../bin/ctrl-exec-dispatcher";
ok(-f $comp, 'completion file present');

my $tmp = tempdir(CLEANUP => 1);
mkdir "$tmp/agents";
for my $h (qw(alpha beta.example)) {
    open my $fh, '>', "$tmp/agents/$h.json" or die; print $fh "{}"; close $fh;
}
open my $sc, '>', "$tmp/scripts.conf" or die;
print $sc "# comment\nbackup-db = /opt/x/backup.sh\ndeploy = /opt/x/d.sh profile=p\n";
close $sc;

# Candidates for the words (last word is the one being completed).
sub complete {
    my (%a) = @_;
    my @w = @{ $a{words} };
    my $fn = $a{fn} // '_ctrl_exec_dispatcher';
    my $arr = join ' ', map { "'$_'" } @w;
    my $reg = $a{registry} // "$tmp/agents";
    my $out = `env CTRL_EXEC_COMPLETION_REGISTRY_DIR='$reg' CTRL_EXEC_COMPLETION_ALLOWLIST='$tmp/scripts.conf' bash -c "source '$comp'; COMP_WORDS=($arr); COMP_CWORD=$#w; $fn; printf '%s\\n' \\"\\\${COMPREPLY[@]}\\"" 2>&1`;
    return [ sort grep { length } split /\n/, $out ];
}

my @modes = qw(run status wait ping pairing-mode list-requests approve deny ca-fingerprint
    setup-ca setup-ctrl-exec list-agents edit-agent list-locks rotate-cert
    serial-status unpair maintain doctor);

is_deeply(complete(words => ['ced', '']), [ sort @modes ], 'first word: all modes');
is_deeply(complete(words => ['ced', 'se']), [qw(serial-status setup-ca setup-ctrl-exec)], 'mode prefix');
is_deeply(complete(words => ['ced', 'pa']), ['pairing-mode'], 'single prefix match');
is_deeply(complete(words => ['ced', '--json', 'li']), [qw(list-agents list-locks list-requests)],
    'mode after a global option');
is_deeply(complete(words => ['ced', '--config', '/nonexistent/x', 'pi']), ['ping'],
    'option value is not taken as the mode');

# Options.
is_deeply(complete(words => ['ced', 'approve', '--']),
    [qw(--agent-port --config --ip --json --lookup-by --port --token --username --version)],
    'approve options');
is_deeply(complete(words => ['ced', 'edit-agent', 'alpha', '--r']), ['--rename'], 'edit-agent --rename');
is_deeply(complete(words => ['ced', 'run', '--as']), ['--async'], 'run --async');
is_deeply(complete(words => ['ced', 'list-agents', '--ta']), ['--tags'], 'list-agents --tags');
is_deeply(complete(words => ['ced', 'doctor', '--f']), ['--fix'], 'doctor --fix');
is_deeply(complete(words => ['ced', 'doctor', '--b']), ['--brief'], 'doctor --brief');
is_deeply(complete(words => ['ced', 'wait', 'r1', '--ti']), ['--timeout'], 'wait --timeout');
is_deeply(complete(words => ['ced', 'approve', 'r1', '--lookup-by', '']), [qw(hostname ip)],
    '--lookup-by values');
is_deeply(complete(words => ['ced', 'approve', 'r1', '--lookup-by', 'i']), ['ip'], '--lookup-by prefix');
is_deeply(complete(words => ['ced', 'pairing-mode', '']), [qw(start stop)], 'pairing-mode actions');
is_deeply(complete(words => ['ced', 'pairing-mode', 'start', '']), [], 'nothing after the action');

# Hosts and scripts.
is_deeply(complete(words => ['ced', 'ping', '']), [qw(alpha beta.example)], 'ping: hosts');
is_deeply(complete(words => ['ced', 'ping', 'b']), ['beta.example'], 'ping: host prefix');
is_deeply(complete(words => ['ced', 'unpair', 'a']), ['alpha'], 'unpair: host');
is_deeply(complete(words => ['ced', 'edit-agent', '']), [qw(alpha beta.example)], 'edit-agent: host');
is_deeply(complete(words => ['ced', 'run', '']),
    [qw(alpha backup-db beta.example deploy)], 'run: hosts and scripts');
is_deeply(complete(words => ['ced', 'run', 'alpha', 'b']), [qw(backup-db beta.example)],
    'run: second host or script');
is_deeply(complete(words => ['ced', 'run', 'alpha', 'deploy', '']), [],
    'run: nothing after the script');
is_deeply(complete(words => ['ced', 'run', 'alpha', 'deploy', '--', '']), [],
    'run: nothing after --');
is_deeply(complete(words => ['ced', 'ping', ''], registry => "$tmp/none"), [],
    'unreadable or absent registry: no candidates, no error');

# Short-name alias.
my $alias = `bash -c "source '$comp'; complete -p ced ctrl-exec-dispatcher" 2>&1`;
like($alias, qr/-F _ctrl_exec_dispatcher ced/, 'ced registered');
like($alias, qr/-F _ctrl_exec_dispatcher ctrl-exec-dispatcher/, 'ctrl-exec-dispatcher registered');

# Drift: every mode and option in the bin is in the completion.
open my $bfh, '<', $bin or die "$bin: $!";
my $src = do { local $/; <$bfh> };
close $bfh;
my ($table) = $src =~ /my %dispatch = \((.*?)\n    \);/s;
my @bin_modes = $table =~ /^\s*'?([\w-]+)'?\s*=>/mg;
cmp_ok(scalar @bin_modes, '>=', 15, 'parsed the dispatch table');
my $all = join ' ', @{ complete(words => ['ced', '']) };
for my $m (@bin_modes) {
    like($all, qr/(?:^| )\Q$m\E(?: |$)/, "mode '$m' is completed");
}
my ($go) = $src =~ /GetOptions\((.*?)\n    \)/s;
my @bin_opts = $go =~ /'([\w-]+)[=!]?[si]?'\s*=>/g;
cmp_ok(scalar @bin_opts, '>=', 10, 'parsed the option table');
open my $cfh, '<', $comp or die; my $csrc = do { local $/; <$cfh> }; close $cfh;
for my $o (@bin_opts) {
    like($csrc, qr/--\Q$o\E\b/, "option --$o is completed");
}

done_testing;
