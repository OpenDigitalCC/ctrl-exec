#!/usr/bin/perl
# t/agent-executor-absent.t
#
# T-028: with executor_socket set but the executor absent (no socket) or dead
# (stale socket file, nothing listening), a run must fail with a specific error
# that names the executor and how to start it - not a bare "connect" error - and
# the probe used by `self-check` must report the same.
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use FindBin    qw($Bin);
use lib "$Bin/../lib";
use IO::Socket::UNIX;

use Exec::Agent::ExecClient qw();

my $tmp = tempdir(CLEANUP => 1);

# Absent socket
{
    my $r = Exec::Agent::ExecClient::run(
        socket => "$tmp/none.sock", reqid => 'r1', dispatcher_id => 'd',
        script => 's', args => [], stdin => '{}');
    is $r->{exit}, -1, 'absent: run fails (exit -1)';
    like $r->{error}, qr/ctrl-exec-executor is not available/, 'absent: error names the executor';
    like $r->{error}, qr/socket does not exist: \Q$tmp\E\/none\.sock/, 'absent: error says the socket is missing, with its path';
    like $r->{error}, qr/systemctl start ctrl-exec-executor\.service/, 'absent: error says how to start it';
    like $r->{error}, qr/install gcc and libcap-dev/, 'absent: error mentions the tarball-without-gcc cause';
    ok $r->{executor_unavailable}, 'absent: flagged for the caller to log';
    unlike $r->{error}, qr/^executor unreachable/, 'absent: not the old generic message';

    my $p = Exec::Agent::ExecClient::probe("$tmp/none.sock");
    like $p, qr/ctrl-exec-executor is not available/, 'absent: self-check probe reports it';
}

# Stale socket file, nobody listening
{
    my $path = "$tmp/stale.sock";
    my $l = IO::Socket::UNIX->new(Local => $path, Listen => 1) or die $!;
    close $l;                       # file remains, listener gone
    ok -S $path, 'stale socket file present';
    my $r = Exec::Agent::ExecClient::run(
        socket => $path, reqid => 'r2', dispatcher_id => 'd',
        script => 's', args => [], stdin => '{}');
    is $r->{exit}, -1, 'refused: run fails';
    like $r->{error}, qr/nothing is listening on the socket/, 'refused: error says nothing is listening';
    like $r->{error}, qr/systemctl start ctrl-exec-executor\.service/, 'refused: error says how to start it';
}

# A live listener -> probe is clean
{
    my $path = "$tmp/live.sock";
    my $l = IO::Socket::UNIX->new(Local => $path, Listen => 1) or die $!;
    is scalar(Exec::Agent::ExecClient::probe($path)), undef, 'live: probe is clean';
}

# `cea self-check` with executor_socket set: reports the missing executor and
# exits non-zero; with a live listener it reports OK; unset, it says profiles
# are not applied.
{
    my $agent = "$Bin/../bin/ctrl-exec-agent";
    my $lib   = "$Bin/../lib";
    my $dir   = tempdir(CLEANUP => 1);
    my $allow = "$dir/scripts.conf";
    sub _w { my ($p, $c) = @_; open my $fh, '>', $p or die "$p: $!"; print $fh $c; close $fh }
    _w($allow, '');
    sub _check {
        my ($extra) = @_;
        _w("$dir/agent.conf", "port = 1\ncert = $dir/agent.crt\nkey = $dir/agent.key\nca = $dir/ca.crt\n$extra");
        my $out = qx{$^X -I$lib $agent --config $dir/agent.conf --allowlist $allow self-check 2>&1};
        return ($out, $? >> 8);
    }
    my ($out, $rc) = _check("executor_socket = $dir/missing.sock\n");
    like $out, qr/Executor: NOT AVAILABLE - ctrl-exec-executor is not available/, 'self-check: reports the missing executor';
    like $out, qr/systemctl start ctrl-exec-executor\.service/, 'self-check: says how to start it';
    isnt $rc, 0, 'self-check: exits non-zero when the executor is missing';

    my $path = "$dir/live.sock";
    my $l = IO::Socket::UNIX->new(Local => $path, Listen => 1) or die $!;
    ($out, $rc) = _check("executor_socket = $path\n");
    like $out, qr/Executor: OK/, 'self-check: executor reachable -> OK';

    ($out, $rc) = _check("");
    like $out, qr/Executor: not configured.*profiles are NOT applied/, 'self-check: unset -> says profiles not applied';
    is $rc, 0, 'self-check: unset executor is not an error';
}

done_testing;
