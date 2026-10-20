#!/usr/bin/perl
# t/dispatcher-conf-dir.t
#
# The dispatcher's config directory is /etc/ctrl-exec-dispatcher (T-008); the
# old /etc/ctrl-exec is still found, with a warning, when it is the only one, so
# a half-migrated host keeps working. When both exist the new one wins. The
# directories are pointed at temp dirs through the package variables.

use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use FindBin    qw($Bin);
use lib "$Bin/../lib";

use Exec::DispatcherConfig qw();
use Exec::CA qw();

is $Exec::DispatcherConfig::CONF_DIR,   '/etc/ctrl-exec-dispatcher', 'new default dir';
is $Exec::DispatcherConfig::LEGACY_DIR, '/etc/ctrl-exec',            'legacy dir named';

my $root = tempdir(CLEANUP => 1);
my ($new, $old) = ("$root/ctrl-exec-dispatcher", "$root/ctrl-exec");
local $Exec::DispatcherConfig::CONF_DIR   = $new;
local $Exec::DispatcherConfig::LEGACY_DIR = $old;

sub capture {
    my ($code) = @_;
    my @w;
    local $SIG{__WARN__} = sub { push @w, @_ };
    local $Exec::DispatcherConfig::WARNED = 0;
    my $r = $code->();
    return ($r, \@w);
}

# Neither exists: a fresh install gets the new name, silently.
{
    my ($d, $w) = capture(sub { Exec::DispatcherConfig::conf_dir() });
    is $d, $new, 'neither dir: new path';
    is scalar(@$w), 0, 'neither dir: no warning';
    my ($p) = capture(sub { Exec::DispatcherConfig::conf_path() });
    is $p, "$new/ctrl-exec.conf", 'neither dir: conf_path is under the new dir';
}

# Only the old dir: found, with a warning naming both paths.
mkdir $old or die;
{
    my ($d, $w) = capture(sub { Exec::DispatcherConfig::conf_dir() });
    is $d, $old, 'old dir only: old path is used';
    is scalar(@$w), 1, 'old dir only: one warning';
    like $w->[0], qr/\Q$old\E.*\Q$new\E/s, 'warning names the old and the new path';
    my ($p) = capture(sub { Exec::DispatcherConfig::conf_path() });
    is $p, "$old/ctrl-exec.conf", 'old dir only: conf_path under the old dir';
    my ($d2, $w2) = capture(sub { Exec::DispatcherConfig::conf_dir(); Exec::DispatcherConfig::conf_dir() });
    is scalar(@$w2), 1, 'warns once per process, not per call';
}

# The CA module follows the same resolution for its default directory.
{
    open my $fh, '>', "$old/ca.crt" or die; print $fh "OLDCA\n"; close $fh;
    my ($pem, $w) = capture(sub { Exec::CA::read_ca_cert() });
    like $pem, qr/OLDCA/, 'Exec::CA default dir falls back to the old dir';
    is scalar(@$w), 1, 'and warns';
}

# Both exist: the new one wins, no warning.
mkdir $new or die;
open my $fh, '>', "$new/ca.crt" or die; print $fh "NEWCA\n"; close $fh;
{
    my ($d, $w) = capture(sub { Exec::DispatcherConfig::conf_dir() });
    is $d, $new, 'both dirs: new wins';
    is scalar(@$w), 0, 'both dirs: no warning';
    my ($pem) = capture(sub { Exec::CA::read_ca_cert() });
    like $pem, qr/NEWCA/, 'Exec::CA reads the new dir when both exist';
}

# Old path a symlink to the new dir (the migrated state): new path, no warning.
{
    my $r2 = tempdir(CLEANUP => 1);
    mkdir "$r2/new" or die;
    symlink "$r2/new", "$r2/old" or die;
    local $Exec::DispatcherConfig::CONF_DIR   = "$r2/new";
    local $Exec::DispatcherConfig::LEGACY_DIR = "$r2/old";
    my ($d, $w) = capture(sub { Exec::DispatcherConfig::conf_dir() });
    is $d, "$r2/new", 'symlinked legacy: new path';
    is scalar(@$w), 0, 'symlinked legacy: no warning';
}

done_testing;
