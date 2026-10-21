#!/usr/bin/perl
# t/install-migrate.t
#
# install.sh has no DESTDIR/root prefix, so the 0.13 upgrade migrations (T-008)
# are tested as the isolated helper functions they are: the script is sourced
# (main does not run) and migrate_dispatcher_conf_dir / migrate_legacy_executor
# are called with their directory variables pointed at a temp tree. systemctl is
# a stub on PATH that records its calls and answers is-active / is-enabled from
# marker files, so no real unit is touched.

use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use File::Temp qw(tempdir);
use File::Path qw(make_path);

my $install_sh = "$Bin/../install.sh";

sub slurp { open(my $fh, '<', $_[0]) or return ''; local $/; <$fh> }
sub spew  { open(my $fh, '>', $_[0]) or die "$_[0]: $!"; print $fh $_[1]; close $fh }

# A temp host: etc/, sbin/, systemd/, state/ (marker files) and a stub systemctl.
sub host {
    my $r = tempdir(CLEANUP => 1);
    make_path("$r/etc", "$r/sbin", "$r/systemd", "$r/state", "$r/stubbin");
    spew("$r/stubbin/systemctl", <<'STUB');
#!/bin/sh
echo "systemctl $*" >> "$STATE/calls"
case "$1" in
    is-active)  [ -e "$STATE/active.$3" ] ;;
    is-enabled) [ -e "$STATE/enabled.$3" ] ;;
    *) exit 0 ;;
esac
STUB
    chmod 0755, "$r/stubbin/systemctl";
    return $r;
}

sub run {
    my ($r, $body) = @_;
    my $script = <<"END";
set -euo pipefail
source "$install_sh"
EXEC_CONF_DIR="$r/etc/ctrl-exec-dispatcher"
LEGACY_EXEC_CONF_DIR="$r/etc/ctrl-exec"
LIB_DIR="$Bin/../lib"
SBIN_DIR="$r/sbin"
SYSTEMD_DIR="$r/systemd"
HAS_SYSTEMD=true
$body
END
    local $ENV{PATH} = "$r/stubbin:$ENV{PATH}";
    local $ENV{STATE} = "$r/state";
    my $out = `bash -c '$script' 2>&1`;
    return ($? >> 8, $out);
}
# bash -c with the script in single quotes: escape any single quote.
{ no warnings 'redefine';
  my $orig = \&run;
  *run = sub { my ($r, $b) = @_; $b =~ s/'/'\\''/g; return $orig->($r, $b) }; }

# --- config dir: old only -> moved, symlink left, paths rewritten ---
{
    my $r = host();
    make_path("$r/etc/ctrl-exec");
    spew("$r/etc/ctrl-exec/ctrl-exec.conf",
         "cert = $r/etc/ctrl-exec/dispatcher.crt\nkey  = $r/etc/ctrl-exec/dispatcher.key\nca = /elsewhere/ca.crt\n");
    spew("$r/etc/ctrl-exec/ca.key", "KEY\n");
    my ($rc, $out) = run($r, 'migrate_dispatcher_conf_dir');
    is $rc, 0, 'conf dir: migration succeeds' or diag($out);
    ok -d "$r/etc/ctrl-exec-dispatcher", 'conf dir: new directory exists';
    is slurp("$r/etc/ctrl-exec-dispatcher/ca.key"), "KEY\n", 'conf dir: contents moved';
    ok -l "$r/etc/ctrl-exec", 'conf dir: old path is now a symlink';
    is readlink("$r/etc/ctrl-exec"), "$r/etc/ctrl-exec-dispatcher", 'conf dir: symlink points at the new dir';
    my $conf = slurp("$r/etc/ctrl-exec-dispatcher/ctrl-exec.conf");
    like $conf, qr{^cert = \Q$r\E/etc/ctrl-exec-dispatcher/dispatcher\.crt$}m, 'conf dir: cert path rewritten';
    like $conf, qr{^key  = \Q$r\E/etc/ctrl-exec-dispatcher/dispatcher\.key$}m, 'conf dir: key path rewritten';
    like $conf, qr{^ca = /elsewhere/ca\.crt$}m, 'conf dir: an unrelated path is untouched';
    ok -f "$r/etc/ctrl-exec-dispatcher/ctrl-exec.conf.pre-0.13", 'conf dir: previous config kept';
    my ($rc2) = run($r, 'migrate_dispatcher_conf_dir');
    is $rc2, 0, 'conf dir: second run is a no-op (symlink, not a directory)';
    is slurp("$r/etc/ctrl-exec-dispatcher/ctrl-exec.conf"), $conf, 'conf dir: second run leaves the config alone';
}

# --- config dir: old real, new seeded (no CA) -> moved, seeded kept aside ---
{
    my $r = host();
    make_path("$r/etc/ctrl-exec", "$r/etc/ctrl-exec-dispatcher");
    spew("$r/etc/ctrl-exec/ctrl-exec.conf", "cert = $r/etc/ctrl-exec/dispatcher.crt\n");
    spew("$r/etc/ctrl-exec/ca.key", "OLD\n");
    spew("$r/etc/ctrl-exec-dispatcher/ctrl-exec.conf", "# seeded\n");
    my ($rc, $out) = run($r, 'migrate_dispatcher_conf_dir');
    is $rc, 0, 'seeded new: exits 0' or diag($out);
    is slurp("$r/etc/ctrl-exec-dispatcher/ca.key"), "OLD\n", 'seeded new: real config moved in';
    ok -l "$r/etc/ctrl-exec", 'seeded new: symlink left';
    is slurp("$r/etc/ctrl-exec-dispatcher.seeded/ctrl-exec.conf"), "# seeded\n", 'seeded new: seeded dir kept aside';
}

# --- config dir: both hold a CA -> nothing moved, says so ---
{
    my $r = host();
    make_path("$r/etc/ctrl-exec", "$r/etc/ctrl-exec-dispatcher");
    for my $d ("$r/etc/ctrl-exec", "$r/etc/ctrl-exec-dispatcher") {
        spew("$d/ctrl-exec.conf", "cert = $d/dispatcher.crt\n");
        spew("$d/ca.key", "K\n");
    }
    my ($rc, $out) = run($r, 'migrate_dispatcher_conf_dir');
    is $rc, 0, 'both dirs: exits 0';
    like $out, qr/leaving \S+ alone/, 'both dirs: says so';
    ok !-l "$r/etc/ctrl-exec", 'both dirs: old directory left as a real directory';
    ok -f "$r/etc/ctrl-exec/ca.key", 'both dirs: old contents untouched';
}

# --- config dir: fresh install (neither) -> nothing created ---
{
    my $r = host();
    my ($rc) = run($r, 'migrate_dispatcher_conf_dir');
    is $rc, 0, 'fresh: exits 0';
    ok !-e "$r/etc/ctrl-exec" && !-e "$r/etc/ctrl-exec-dispatcher", 'fresh: migration creates nothing';
}

# --- executor: old unit active and enabled -> removed, new enabled and started ---
{
    my $r = host();
    spew("$r/sbin/ctrl-exec-exec", "old\n");
    spew("$r/sbin/ctrl-exec-executor", "new\n");
    spew("$r/systemd/ctrl-exec-exec.service", "[Unit]\n");
    spew("$r/systemd/ctrl-exec-executor.service", "[Unit]\n");
    spew("$r/state/active.ctrl-exec-exec.service", '');
    spew("$r/state/enabled.ctrl-exec-exec.service", '');
    my ($rc, $out) = run($r, 'migrate_legacy_executor');
    is $rc, 0, 'executor: migration succeeds' or diag($out);
    ok !-e "$r/sbin/ctrl-exec-exec", 'executor: old binary removed';
    ok !-e "$r/systemd/ctrl-exec-exec.service", 'executor: old unit file removed';
    ok -e "$r/sbin/ctrl-exec-executor" && -e "$r/systemd/ctrl-exec-executor.service", 'executor: new binary and unit kept';
    my $calls = slurp("$r/state/calls");
    like $calls, qr/^systemctl stop ctrl-exec-exec\.service$/m,        'executor: old unit stopped';
    like $calls, qr/^systemctl disable ctrl-exec-exec\.service$/m,     'executor: old unit disabled';
    like $calls, qr/^systemctl enable ctrl-exec-executor\.service$/m,  'executor: new unit enabled';
    like $calls, qr/^systemctl start ctrl-exec-executor\.service$/m,   'executor: new unit started';
}

# --- executor: old unit installed but neither enabled nor running -> not started ---
{
    my $r = host();
    spew("$r/sbin/ctrl-exec-exec", "old\n");
    spew("$r/systemd/ctrl-exec-exec.service", "[Unit]\n");
    my ($rc) = run($r, 'migrate_legacy_executor');
    is $rc, 0, 'executor (idle): migration succeeds';
    ok !-e "$r/sbin/ctrl-exec-exec" && !-e "$r/systemd/ctrl-exec-exec.service", 'executor (idle): old files removed';
    my $calls = slurp("$r/state/calls");
    unlike $calls, qr/^systemctl (?:enable|start|stop|disable) /m, 'executor (idle): nothing enabled, started or stopped';
}

# --- executor: fresh install -> no-op, no systemctl calls ---
{
    my $r = host();
    my ($rc) = run($r, 'migrate_legacy_executor');
    is $rc, 0, 'executor (fresh): exits 0';
    is slurp("$r/state/calls"), '', 'executor (fresh): no systemctl calls';
}

done_testing;
