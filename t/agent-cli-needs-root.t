#!/usr/bin/perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use FindBin qw($Bin);

# R-006 / T-006: the agent's operator commands read root-only files. Run
# unprivileged, they used to report a configuration error (or "not paired")
# when the real cause was a permission error. They must say the command needs
# root (sudo) and name the file. A genuine config error must be unchanged.

plan skip_all => 'running as root: permission errors cannot be provoked'
    if $> == 0;

my $agent = "$Bin/../bin/ctrl-exec-agent";
my $lib   = "$Bin/../lib";

my $dir  = tempdir(CLEANUP => 1);
my $conf_dir = "$dir/conf";          # stands in for the 0750 root:agent /etc dir
mkdir $conf_dir or die "mkdir: $!";
my $conf  = "$conf_dir/agent.conf";
my $allow = "$conf_dir/scripts.conf";
_write($conf, "port = 7443\ncert = $conf_dir/agent.crt\nkey = $conf_dir/agent.key\nca = $conf_dir/ca.crt\n");
_write($allow, "");
chmod 0000, $conf_dir or die "chmod: $!";

for my $mode (qw(self-check self-ping pairing-status)) {
    my ($out, $rc) = _run($mode, $conf, $allow);
    isnt $rc, 0, "$mode: exits non-zero";
    like $out, qr/needs root/i,          "$mode: says it needs root";
    like $out, qr/sudo ctrl-exec-agent \Q$mode\E/, "$mode: shows the sudo form";
    like $out, qr/\Q$conf_dir\E/,        "$mode: names the unreadable path";
    unlike $out, qr/Config error|Not paired|missing file/i,
        "$mode: does not masquerade as a config / pairing error";
}

{
    my ($out, $rc) = _run('serve', $conf, $allow);
    is $rc, 78, 'serve: exits EX_CONFIG so systemd does not loop';
    like $out, qr/Permission denied/i, 'serve: names the permission problem';
    like $out, qr/\Q$conf_dir\E/,      'serve: names the unreadable path';
    unlike $out, qr/configuration error/i, 'serve: not framed as a configuration error';
}

# Control: a real configuration error (readable file, bad content) is unchanged.
chmod 0755, $conf_dir;
_write($conf, "port = notanumber\n");
{
    my ($out, $rc) = _run('self-check', $conf, $allow);
    isnt $rc, 0, 'real config error: still fails';
    like $out, qr/Config error/, 'real config error: still reported as one';
    unlike $out, qr/needs root/i, 'real config error: not blamed on root';
}

done_testing;

sub _write { my ($p, $c) = @_; open my $fh, '>', $p or die "$p: $!"; print $fh $c; close $fh }
sub _q { my ($s) = @_; $s =~ s/'/'\\''/g; return "'$s'" }
sub _run {
    my ($mode, $conf, $allow) = @_;
    my $cmd = sprintf('%s -I%s %s --config %s --allowlist %s %s 2>&1',
        $^X, _q($lib), _q($agent), _q($conf), _q($allow), $mode);
    my $out = qx{$cmd};
    return ($out, $? >> 8);
}
