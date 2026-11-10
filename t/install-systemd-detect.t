#!/usr/bin/perl
# t/install-systemd-detect.t
#
# T-087 (R-032): install.sh decides "systemd" by a RUNNING systemd (the
# /run/systemd/system directory, sd_booted's test), not by the systemctl
# binary. A container with supervisord as PID 1 that carries systemctl must
# take the "no supported init system" warning path: no systemctl call, exit 0.
# install.sh is sourced; SYSTEMD_RUN_DIR points at a temp dir; systemctl is a
# stub that records its calls. Nothing touches the host.
use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use File::Temp qw(tempdir);
use File::Path qw(make_path);

my $install_sh = "$Bin/../install.sh";
sub slurp { open(my $fh, '<', $_[0]) or return ''; local $/; <$fh> }
sub spew  { open(my $fh, '>', $_[0]) or die "$_[0]: $!"; print $fh $_[1]; close $fh }

sub host {
    my $r = tempdir(CLEANUP => 1);
    make_path("$r/pathbin", "$r/systemd", "$r/bin", "$r/sbin");
    for my $t (qw(bash sh sed grep cat mkdir chmod chown dirname basename tr head
                  id rm cp mv ln install env echo printf readlink)) {
        for my $d (qw(/usr/bin /bin)) {
            if (-x "$d/$t") { symlink "$d/$t", "$r/pathbin/$t"; last }
        }
    }
    spew("$r/pathbin/systemctl", "#!/bin/sh\necho \"systemctl \$*\" >> \"$r/calls\"\n");
    chmod 0755, "$r/pathbin/systemctl";
    return $r;
}

# Run detect_init then install_service_unit under set -e; $run_dir is the
# value of SYSTEMD_RUN_DIR.
sub run {
    my ($r, $run_dir) = @_;
    my $script = <<"END";
set -euo pipefail
source "$install_sh"
SYSTEMD_RUN_DIR="$run_dir"
SYSTEMD_DIR="$r/systemd"
BIN_DIR="$r/bin"
SBIN_DIR="$r/sbin"
SOURCE_DIR="$Bin/.."
detect_init
install_service_unit ctrl-exec-api.service
echo "HAS_SYSTEMD=\$HAS_SYSTEMD"
END
    local $ENV{PATH} = "$r/pathbin";
    my $out = `$r/pathbin/bash -c '$script' 2>&1`;
    return ($? >> 8, $out);
}

# --- systemctl present, systemd not running -> warning, exit 0, no calls ---
{
    my $r = host();
    my ($rc, $out) = run($r, "$r/no-such-run-dir");
    is $rc, 0, 'no running systemd: exit 0';
    like $out, qr/No supported init system/, 'no running systemd: the warning is given';
    like $out, qr/HAS_SYSTEMD=false/, 'no running systemd: HAS_SYSTEMD false';
    is slurp("$r/calls"), '', 'no running systemd: systemctl never called';
    ok !-e "$r/systemd/ctrl-exec-api.service", 'no running systemd: no unit installed';
}

# --- systemd running -> unchanged: unit installed, daemon-reload ---
{
    my $r = host();
    make_path("$r/run-systemd");
    my ($rc, $out) = run($r, "$r/run-systemd");
    is $rc, 0, 'running systemd: exit 0';
    unlike $out, qr/No supported init system/, 'running systemd: no warning';
    like $out, qr/HAS_SYSTEMD=true/, 'running systemd: HAS_SYSTEMD true';
    is slurp("$r/calls"), "systemctl daemon-reload\n", 'running systemd: daemon-reload called';
    ok -f "$r/systemd/ctrl-exec-api.service", 'running systemd: unit installed';
}

done_testing;
