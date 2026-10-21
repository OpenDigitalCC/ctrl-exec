#!/usr/bin/perl
# config-error-exit.t
#
# A configuration error must NOT make the agent die with a generic exception and
# let systemd respawn it forever (the "restart counter is at 134" symptom that
# buries the real error). serve must print a clear configuration error naming the
# file, and exit EX_CONFIG (78) - which the unit lists in
# RestartPreventExitStatus, so systemd reports one failure instead of a loop.

use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);

my $bin = 'bin/ctrl-exec-agent';
plan skip_all => "$bin not found" unless -e $bin;

my $dir = tempdir(CLEANUP => 1);

# A base agent.conf with valid syntax; cert/key/ca need not exist - config
# loading/validation runs before the not-paired (cert-present) check.
my $base = "port = 7443\ncert = /tmp/x\nkey = /tmp/x\nca = /tmp/x\n";

sub run_serve {
    my ($agent_conf, $scripts_conf) = @_;
    my $ac = "$dir/agent.conf";
    my $sc = "$dir/scripts.conf";
    open my $f, '>', $ac or die $!; print $f $agent_conf; close $f;
    open my $g, '>', $sc or die $!; print $g $scripts_conf; close $g;
    my $out = `$^X -Ilib $bin serve --config $ac --allowlist $sc 2>&1`;
    return ($? >> 8, $out);
}

subtest 'invalid capability -> exit 78 with a clear message, not a loop' => sub {
    my ($code, $out) = run_serve(
        $base . "[profile p]\ncaps = CAP_CHOWN  # inline note\n",
        "s = /srv/x.sh profile=p\n");
    is $code, 78, 'exits EX_CONFIG (78), so systemd does not respawn-loop';
    like $out, qr/configuration error/i, 'frames it as a configuration error';
    like $out, qr/invalid capability/,   'names the specific problem';
    like $out, qr/\Q$dir\E/,             'names the offending config file';
};

# T-059: an undefined profile skips only that script; it is not a
# configuration error (serve then stops only because the rig is not paired).
subtest 'undefined profile -> that script is skipped, not a configuration error' => sub {
    my ($code, $out) = run_serve($base, "s = /srv/x.sh profile=ghost\n");
    unlike $out, qr/configuration error/i, 'not a configuration error';
    like $out, qr/skipping 's' - profile 'ghost' is not defined in agent\.conf/,
        'the entry is skipped with the reason';
    like $out, qr/not been paired/, 'start-up goes on to the next check';
};

done_testing;
