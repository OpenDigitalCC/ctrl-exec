#!/usr/bin/perl
# t/doctor-install-hooks.t
#
# T-055: after an upgrade the deb postinst of each package and install.sh run
# doctor and print what it finds: report only (--brief, never --fix), and its
# exit status, or its failing to run at all, never fails the install. Not on a
# first install. The postinst block is cut out and run with a stand-in doctor
# on PATH; install.sh is sourced (main does not run) and run_doctor called
# with a stand-in under BIN_DIR, as t/install-version.t does; then once with
# the real ctrl-exec-agent doctor, which finds a problem (exit 1).

use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use File::Temp qw(tempdir);

sub slurp { open my $fh, '<', $_[0] or die "$_[0]: $!"; local $/; scalar <$fh> }
sub spew  { open my $fh, '>', $_[0] or die "$_[0]: $!"; print $fh $_[1]; close $fh }

# A stand-in doctor: prints its arguments, then exits $rc.
sub fake_bin {
    my ($dir, $prog, $rc) = @_;
    spew("$dir/$prog", "#!/bin/sh\necho \"$prog \$*\"\nexit $rc\n");
    chmod 0755, "$dir/$prog";
}

for my $pkg (qw(agent dispatcher)) {
    my $prog = "ctrl-exec-$pkg";
    my $text = slurp("$Bin/../debian/$prog.postinst");
    my ($block) = $text =~ /(case "\$1" in\n    configure\)\n        if \[ -n "\$2" \]; then\n            \Q$prog\E doctor[^\n]*\n.*?\nesac\n)/s;
    ok $block, "$pkg postinst: has the doctor block" or next;
    like $block, qr/\Q$prog\E doctor --brief \|\| true/, "$pkg postinst: --brief, and || true";
    unlike $block, qr/--fix/, "$pkg postinst: never --fix";
    like $text, qr/\Q$block\E\nexit 0\n\z/, "$pkg postinst: the block runs last, after the restarts";

    for my $rc (0, 1, 2, 127) {
        my $d = tempdir(CLEANUP => 1);
        fake_bin($d, $prog, $rc);
        spew("$d/block.sh", "set -e\n$block\necho END\n");
        my $out = `PATH=$d:/usr/bin:/bin sh $d/block.sh configure 0.13.2 2>&1`;
        is $? >> 8, 0, "$pkg postinst: doctor exit $rc does not fail the configure";
        like $out, qr/^\Q$prog\E doctor --brief\nEND\n\z/, "$pkg postinst: doctor ran, its output printed";
    }
    {
        my $d = tempdir(CLEANUP => 1);
        spew("$d/block.sh", "set -e\n$block\necho END\n");
        my $out = `PATH=$d:/usr/bin:/bin sh $d/block.sh configure 0.13.2 2>&1`;
        is $? >> 8, 0, "$pkg postinst: doctor missing altogether does not fail the configure";
        like $out, qr/END\n\z/, "$pkg postinst: and the script goes on";

        fake_bin($d, $prog, 0);
        $out = `PATH=$d:/usr/bin:/bin sh $d/block.sh configure 2>&1`;
        is $out, "END\n", "$pkg postinst: a first install (no previous version) does not run doctor";
    }
}

# install.sh
my $install_sh = "$Bin/../install.sh";
my $src = slurp($install_sh);
like $src, qr/run_doctor\(\) \{.*?"\$BIN_DIR\/\$prog" doctor --brief \|\| true\n\}/s,
    'install.sh: run_doctor runs doctor --brief, || true';
unlike(($src =~ /(run_doctor\(\) \{.*?\n\})/s)[0], qr/--fix/, 'install.sh: never --fix');
like $src, qr/if \[\[ -f "\$AGENT_CONF_DIR\/agent\.conf" \]\]; then\n\s+upgrade=true\n\s+fi\n\s+install_agent\n\s+if \[\[ "\$upgrade" == true \]\]; then\n\s+run_doctor ctrl-exec-agent/,
    'install.sh: the agent role runs it after an upgrade only';
like $src, qr/upgrade=true\n\s+fi\n\s+install_ctrl_exec_dispatcher\n\s+if \[\[ "\$upgrade" == true \]\]; then\n\s+run_doctor ctrl-exec-dispatcher/,
    'install.sh: the dispatcher role too';

sub run_doctor_sh {
    my ($bin_dir, $prog) = @_;
    my $out = `bash -c 'set -euo pipefail; source "$install_sh"; BIN_DIR="$bin_dir"; run_doctor $prog; echo END' 2>&1`;
    return ($? >> 8, $out);
}

for my $rc (0, 1, 2) {
    my $d = tempdir(CLEANUP => 1);
    fake_bin($d, 'ctrl-exec-agent', $rc);
    my ($status, $out) = run_doctor_sh($d, 'ctrl-exec-agent');
    is $status, 0, "install.sh: doctor exit $rc does not fail the install";
    like $out, qr/ctrl-exec-agent doctor --brief\nEND\n\z/, 'install.sh: doctor ran, output printed';
}

# The real doctor, finding a problem (an agent.conf that does not parse): the
# hook prints its report and still succeeds.
{
    my $d = tempdir(CLEANUP => 1);
    spew("$d/agent.conf", "port = x\n");
    spew("$d/ctrl-exec-agent", "#!/bin/sh\nexec $^X -I$Bin/../lib -I$Bin/lib -MNoSyslog $Bin/../bin/ctrl-exec-agent"
       . " --config $d/agent.conf --allowlist $d/scripts.conf \"\$@\"\n");
    chmod 0755, "$d/ctrl-exec-agent";
    my ($status, $out) = run_doctor_sh($d, 'ctrl-exec-agent');
    is $status, 0, 'install.sh: the real doctor finding a problem does not fail the install';
    like $out, qr/^PROBLEM  agent\.conf cannot be loaded/m, 'and its finding is printed';
    like $out, qr/^ctrl-exec-agent doctor: 1 problem\.\nEND\n\z/m, 'with the summary line';
}

done_testing;
