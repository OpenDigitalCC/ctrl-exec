#!/usr/bin/perl
# t/dispatcher-conf-dir.t
#
# The dispatcher's config directory is /etc/ctrl-exec-dispatcher (T-008). A
# real /etc/ctrl-exec is refused (T-047), never silently used or ignored: the
# fallback to it let a host run on the wrong config (or a second CA). Only the
# migration symlink the installers leave, pointing at the new directory, is
# accepted. The directories are pointed at temp dirs through the package
# variables.

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

sub fresh_root {
    my $root = tempdir(CLEANUP => 1);
    return ($root, "$root/ctrl-exec-dispatcher", "$root/ctrl-exec");
}

sub resolve {
    my ($new, $old, $code) = @_;
    local $Exec::DispatcherConfig::CONF_DIR   = $new;
    local $Exec::DispatcherConfig::LEGACY_DIR = $old;
    my @w;
    local $SIG{__WARN__} = sub { push @w, @_ };
    my $r = eval { $code->() };
    return ($r, $@, \@w);
}

sub like_refusal {
    my ($err, $old, $new, $name) = @_;
    like $err, qr/\Q$old\E/, "$name: names the old path";
    like $err, qr/\Q$new\E/, "$name: names the new path";
    like $err, qr/\bmv\b|move/i, "$name: says how to move it";
    like $err, qr/ctrl-exec\.conf/, "$name: says to fix the paths in ctrl-exec.conf";
    like $err, qr/mount/i, "$name: says what to change in a container";
}

# Neither exists: a fresh install gets the new name, silently.
{
    my ($root, $new, $old) = fresh_root();
    my ($d, $err, $w) = resolve($new, $old, sub { Exec::DispatcherConfig::conf_dir() });
    is $d, $new, 'neither dir: new path';
    is $err, '', 'neither dir: no error';
    is scalar(@$w), 0, 'neither dir: no warning';
    my ($p) = resolve($new, $old, sub { Exec::DispatcherConfig::conf_path() });
    is $p, "$new/ctrl-exec.conf", 'neither dir: conf_path is under the new dir';
}

# Only the new dir: fine.
{
    my ($root, $new, $old) = fresh_root();
    mkdir $new or die;
    my ($d, $err) = resolve($new, $old, sub { Exec::DispatcherConfig::conf_dir() });
    is $d, $new, 'new dir only: new path';
    is $err, '', 'new dir only: no error';
}

# A real old dir alone: refuse (no silent fallback).
{
    my ($root, $new, $old) = fresh_root();
    mkdir $old or die;
    my ($d, $err, $w) = resolve($new, $old, sub { Exec::DispatcherConfig::conf_dir() });
    ok !defined $d, 'old dir only: conf_dir does not return';
    like_refusal($err, $old, $new, 'old dir only');
    my ($p, $perr) = resolve($new, $old, sub { Exec::DispatcherConfig::conf_path() });
    ok !defined $p && $perr =~ /\Q$old\E/, 'old dir only: conf_path refuses too';
}

# A real old dir beside the new one: refuse (the new one is not preferred).
{
    my ($root, $new, $old) = fresh_root();
    mkdir $old or die;
    mkdir $new or die;
    my ($d, $err) = resolve($new, $old, sub { Exec::DispatcherConfig::conf_dir() });
    ok !defined $d, 'both real dirs: conf_dir does not return';
    like_refusal($err, $old, $new, 'both real dirs');
}

# The CA module follows the same resolution for its default directory.
{
    my ($root, $new, $old) = fresh_root();
    mkdir $old or die;
    mkdir $new or die;
    open my $fh, '>', "$new/ca.crt" or die; print $fh "NEWCA\n"; close $fh;
    my ($pem, $err) = resolve($new, $old, sub { Exec::CA::read_ca_cert() });
    ok !defined $pem, 'Exec::CA default dir does not read the new dir beside a real old one';
    like $err, qr/\Q$old\E/, 'and says why';
}

# Old path a symlink to the new dir (the migrated state): runs, no warning.
{
    my ($root, $new, $old) = fresh_root();
    mkdir $new or die;
    symlink $new, $old or die;
    open my $fh, '>', "$new/ca.crt" or die; print $fh "NEWCA\n"; close $fh;
    my ($d, $err, $w) = resolve($new, $old, sub { Exec::DispatcherConfig::conf_dir() });
    is $d, $new, 'symlinked legacy: new path';
    is $err, '', 'symlinked legacy: no error';
    is scalar(@$w), 0, 'symlinked legacy: no warning';
    my ($pem) = resolve($new, $old, sub { Exec::CA::read_ca_cert() });
    like $pem, qr/NEWCA/, 'symlinked legacy: Exec::CA reads the new dir';
}

# A relative symlink to the new dir is the same thing.
{
    my ($root, $new, $old) = fresh_root();
    mkdir $new or die;
    symlink 'ctrl-exec-dispatcher', $old or die;
    my ($d, $err) = resolve($new, $old, sub { Exec::DispatcherConfig::conf_dir() });
    is $d, $new, 'relative symlink to the new dir: accepted';
}

# A symlink to somewhere else, or a dangling one, is not the migration symlink.
{
    my ($root, $new, $old) = fresh_root();
    mkdir $new or die;
    mkdir "$root/elsewhere" or die;
    symlink "$root/elsewhere", $old or die;
    my ($d, $err) = resolve($new, $old, sub { Exec::DispatcherConfig::conf_dir() });
    ok !defined $d, 'symlink to another dir: refused';
    like_refusal($err, $old, $new, 'symlink elsewhere');
}
{
    my ($root, $new, $old) = fresh_root();
    mkdir $new or die;
    symlink "$root/gone", $old or die;
    my ($d, $err) = resolve($new, $old, sub { Exec::DispatcherConfig::conf_dir() });
    ok !defined $d, 'dangling symlink: refused';
    like $err, qr/\Q$old\E/, 'dangling symlink: names the old path';
}
{
    # Resolves to the new path, which a fresh install is about to create: fine.
    my ($root, $new, $old) = fresh_root();
    symlink $new, $old or die;
    my ($d, $err) = resolve($new, $old, sub { Exec::DispatcherConfig::conf_dir() });
    is $d, $new, 'symlink to the (not yet created) new dir: accepted';
}

# The binaries surface the refusal cleanly: non-zero exit, message on stderr,
# nothing run. Both are started with the temp dirs through the package
# variables via a small driver.
{
    my ($root, $new, $old) = fresh_root();
    mkdir $old or die;
    for my $bin (qw(ctrl-exec-dispatcher ctrl-exec-api)) {
        my $out = qx{$^X -I$Bin/../lib -e '
            use Exec::DispatcherConfig;
            \$Exec::DispatcherConfig::CONF_DIR = q{$new};
            \$Exec::DispatcherConfig::LEGACY_DIR = q{$old};
            \@ARGV = (\$ARGV[0] eq q{ctrl-exec-api}) ? () : (q{list-agents});
            do q{$Bin/../bin/$bin}; die \$@ if \$@;
            main::main() if q{$bin} eq q{ctrl-exec-dispatcher};
        ' $bin 2>&1 >/dev/null};
        my $status = $? >> 8;
        is $status, 78, "$bin: exits 78 (EX_CONFIG)";
        like $out, qr/\Q$old\E.*\Q$new\E/s, "$bin: the message is on stderr";
    }
}

done_testing;
