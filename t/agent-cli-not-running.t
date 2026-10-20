#!/usr/bin/perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use IO::Socket::INET;
use FindBin qw($Bin);

# R-002 / T-007: commands that need the running agent must say plainly that it
# is not running, and how to start it, instead of failing obscurely. The check
# is a plain TCP probe of the configured port, so it needs no root.

my $agent = "$Bin/../bin/ctrl-exec-agent";
my $lib   = "$Bin/../lib";
my $dir   = tempdir(CLEANUP => 1);

# A port nothing is listening on: bind, note it, release.
my $l = IO::Socket::INET->new(Listen => 1, LocalAddr => '127.0.0.1', LocalPort => 0)
    or plan skip_all => "cannot allocate a port: $!";
my $port = $l->sockport;
close $l;

my $conf  = "$dir/agent.conf";
my $allow = "$dir/scripts.conf";
_write($conf, "port = $port\ncert = $dir/agent.crt\nkey = $dir/agent.key\nca = $dir/ca.crt\n");
_write($allow, "");

{
    my ($out, $rc) = _run('self-ping');
    isnt $rc, 0, 'self-ping: exits non-zero with the agent stopped';
    like $out, qr/ctrl-exec-agent is not running/, 'self-ping: says the agent is not running';
    like $out, qr/start it with:\s*\n?\s*(sudo )?(systemctl start ctrl-exec-agent|\/etc\/init\.d\/ctrl-exec-agent start|ctrl-exec-agent serve)/i,
        'self-ping: says how to start it';
    like $out, qr/\b$port\b/, 'self-ping: names the port checked';
    unlike $out, qr/not paired|Cannot self-ping/i, 'self-ping: no unrelated pairing complaint';
}

{
    my ($out, $rc) = _run('self-check');
    like $out, qr/ctrl-exec-agent is not running/, 'self-check: notes the agent is not running';
    like $out, qr/Allowlist OK/, 'self-check: still runs its local checks';
}

# With something listening, the not-running message must not appear.
my $srv = IO::Socket::INET->new(Listen => 5, LocalAddr => '127.0.0.1', LocalPort => $port)
    or plan skip_all => "cannot re-bind $port: $!";
{
    my ($out, $rc) = _run('self-check');
    unlike $out, qr/is not running/, 'listener present: no not-running message';
    like $out, qr/running/, 'listener present: reports running';
}
close $srv;

done_testing;

sub _write { my ($p, $c) = @_; open my $fh, '>', $p or die "$p: $!"; print $fh $c; close $fh }
sub _q { my ($s) = @_; $s =~ s/'/'\\''/g; return "'$s'" }
sub _run {
    my ($mode) = @_;
    my $cmd = sprintf('%s -I%s %s --config %s --allowlist %s %s 2>&1',
        $^X, _q($lib), _q($agent), _q($conf), _q($allow), $mode);
    my $out = qx{$cmd};
    return ($out, $? >> 8);
}
