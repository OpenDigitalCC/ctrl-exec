#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use File::Temp qw(tempdir);
use File::Basename qw(basename);

# The systemd units exist once, as templates in etc/systemd/ with @BINDIR@ /
# @SBINDIR@ placeholders (T-014). install.sh renders them with /usr/local, the
# Debian build (debian/rules) with /usr. This test renders the canonical set for
# both targets through the same helper both use, and checks: nothing unresolved,
# the expected ExecStart paths, install.sh's own install path, debian/rules'
# unit map covers every template, and the units parse (systemd-analyze verify
# when available - needs no root).

my $root = "$Bin/..";
my $dir  = "$root/etc/systemd";
my $render = "$dir/render-unit";

my @units = map { basename($_) } glob("$dir/ctrl-exec-*.service $dir/ctrl-exec-*.timer");
is(scalar(@units), 7, 'seven canonical units in etc/systemd/') or diag("@units");

# Stale copies must not come back next to the canonical set.
my @stale = (glob("$root/etc/*.service"), glob("$root/etc/*.timer"),
             glob("$root/debian/*.service"), glob("$root/debian/*.timer"));
# debian/*.service are build products (git-ignored); only flag tracked ones.
my @tracked = grep { my $f = $_; system("git -C '$root' ls-files --error-unmatch '$f' >/dev/null 2>&1") == 0 } @stale;
is_deeply(\@tracked, [], 'no tracked unit copies outside etc/systemd/');

sub slurp { open(my $fh, '<', $_[0]) or die "$_[0]: $!"; local $/; <$fh> }

sub render {
    my ($bin, $sbin, $unit, $out) = @_;
    return system('sh', $render, $bin, $sbin, "$dir/$unit", $out);
}

my %targets = (
    install => ['/usr/local/bin', '/usr/local/sbin'],
    debian  => ['/usr/bin',       '/usr/sbin'],
);
my %expect = (
    'ctrl-exec-agent.service'       => ['ExecStartPre=+%B/ctrl-exec-agent promote-cert',
                                        'ExecStart=%B/ctrl-exec-agent serve'],
    'ctrl-exec-api.service'         => ['ExecStart=%B/ctrl-exec-api'],
    'ctrl-exec-maintenance.service' => ['ExecStart=%B/ctrl-exec-dispatcher maintain'],
    'ctrl-exec-exec.service'        => ['ExecStart=%S/ctrl-exec-exec serve '],
);

for my $t (sort keys %targets) {
    my ($bin, $sbin) = @{ $targets{$t} };
    my $out = tempdir(CLEANUP => 1);
    for my $u (@units) {
        is(render($bin, $sbin, $u, "$out/$u"), 0, "$t: render $u");
        my $txt = slurp("$out/$u");
        unlike($txt, qr/\@(?:BINDIR|SBINDIR)\@/, "$t: $u has no placeholder left");
        unlike($txt, qr/yourorg/, "$t: $u has no placeholder URL");
        if ($t eq 'debian') {
            unlike($txt, qr{/usr/local}, "debian: $u has no /usr/local path");
        }
        for my $line (@{ $expect{$u} || [] }) {
            (my $l = $line) =~ s/%B/$bin/g;
            $l =~ s/%S/$sbin/g;
            like($txt, qr/^\Q$l\E/m, "$t: $u has '$l'");
        }
    }
}

# install.sh installs through the same renderer into SYSTEMD_DIR.
{
    my $sd = tempdir(CLEANUP => 1);
    my $cmp = tempdir(CLEANUP => 1);
    my $script = qq{set -euo pipefail\nsource "$root/install.sh"\n}
               . qq{SOURCE_DIR="$root"\nSYSTEMD_DIR="$sd"\n}
               . join('', map { "install_unit $_\n" } @units);
    is(system('bash', '-c', $script), 0, 'install.sh install_unit runs');
    for my $u (@units) {
        render('/usr/local/bin', '/usr/local/sbin', $u, "$cmp/$u");
        is(slurp("$sd/$u"), slurp("$cmp/$u"), "install.sh installs $u rendered for /usr/local");
        is(((stat("$sd/$u"))[2] & 07777), 0644, "install.sh installs $u mode 0644");
    }
}

# debian/rules maps every canonical unit to a debhelper-named file.
{
    my $rules = slurp("$root/debian/rules");
    my ($block) = $rules =~ /^UNITS\s*:=\s*((?:.*\\\n)*.*)$/m;
    ok($block, 'debian/rules defines UNITS') or $block = '';
    my %map = $block =~ /(\S+?)=(\S+?)(?=\s|\\|$)/g;
    is_deeply([sort values %map], [sort @units], 'debian/rules UNITS covers every canonical unit exactly');
    for my $dest (sort keys %map) {
        like($dest, qr/^(?:ctrl-exec-(?:agent|dispatcher)\.)?ctrl-exec-[a-z-]+\.(?:service|timer)$/, "debian target name $dest is debhelper-shaped");
    }
}

# Parse check: render against stub executables so systemd-analyze can resolve them.
SKIP: {
    my $sa = '';
    for my $p (split /:/, $ENV{PATH}) { $sa = "$p/systemd-analyze", last if -x "$p/systemd-analyze" }
    skip 'systemd-analyze not available', 1 unless $sa;
    my $w = tempdir(CLEANUP => 1);
    mkdir "$w/bin"; mkdir "$w/sbin";
    for my $b (qw(ctrl-exec-agent ctrl-exec-api ctrl-exec-dispatcher)) {
        open(my $fh, '>', "$w/bin/$b") or die; print $fh "#!/bin/sh\n"; close $fh; chmod 0755, "$w/bin/$b";
    }
    open(my $fh, '>', "$w/sbin/ctrl-exec-exec") or die; print $fh "#!/bin/sh\n"; close $fh; chmod 0755, "$w/sbin/ctrl-exec-exec";
    mkdir "$w/u";
    render("$w/bin", "$w/sbin", $_, "$w/u/$_") for @units;
    my $out = `$sa verify $w/u/*.service $w/u/*.timer 2>&1`;
    is($? >> 8, 0, 'systemd-analyze verify accepts every rendered unit') or diag($out);
}

done_testing;
