#!/usr/bin/perl
# t/agent-probe.t
#
# T-035: the handshake-probe limit must block the actual prober. The TLS
# handshake used to happen inside $server->accept, so a failed handshake left no
# connected socket and was recorded under the peer name 'unknown' - a block that
# applied to nobody. The agent now accepts the TCP connection first, learns the
# peer address, and does the handshake on the accepted socket (with a timeout),
# so the failure is counted under the prober's own address.
#
# Runs a real agent on a loopback port; the "different addresses" are 127.0.0.x,
# all local on Linux.

use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/../lib", "$Bin/lib";
use Time::HiRes qw(time);

require AgentRig;
plan skip_all => 'openssl not available' unless AgentRig::available();

my $rig = AgentRig->new();
$rig->start or BAIL_OUT('rig agent did not start: ' . $rig->log_text);

is $rig->request(as => 'trusted', from => '127.0.0.1'), 200,
    'a normal client (paired dispatcher) is served';
is $rig->request(as => 'untrusted', from => '127.0.0.2'), 403,
    'a CA-signed but unpaired peer completes the handshake and is refused by the request gate';

# Three failed handshakes (a certificate from a CA the agent does not trust)
# from one address.
my $from = $rig->log_len;
for my $i (1 .. 3) {
    is $rig->request(as => 'rogue', from => '127.0.0.5'), undef,
        "probe $i from 127.0.0.5: handshake fails, no HTTP reply";
}
ok $rig->wait_log(qr/ACTION=rate-block PEER=127\.0\.0\.5 REASON=probe/, 5, $from),
    'the probe block is placed on the prober\'s address';
my $log = substr($rig->log_text, $from);
like $log, qr/ACTION=tls-failure PEER=127\.0\.0\.5\b/,
    'each failed handshake is logged under the prober\'s address';
unlike $log, qr/PEER=unknown/, 'nothing is recorded under "unknown"';

is $rig->request(as => 'untrusted', from => '127.0.0.5'), 429,
    'the fourth connection from the prober is refused for the probe block (429)';
is $rig->request(as => 'untrusted', from => '127.0.0.6'), 403,
    'another address is unaffected';
is $rig->request(as => 'trusted', from => '127.0.0.1'), 200,
    'a normal client is still served';
is $rig->request(as => 'trusted', from => '127.0.0.5'), 200,
    'a paired dispatcher is exempt from the block even from the prober\'s address (0.12.4 exemption kept)';

# A silent client (TCP connect, no ClientHello) must not stall the accept loop
# beyond the handshake timeout, and is counted under its own address.
{
    my $from = $rig->log_len;
    my $silent = $rig->silent_connect(from => '127.0.0.7');
    ok $silent, 'silent TCP client connected';
    my $t0 = time;
    is $rig->request(as => 'trusted', from => '127.0.0.1'), 200,
        'a normal client is served while a silent client holds a connection';
    my $took = time - $t0;
    cmp_ok $took, '<', 9, "and is not stalled beyond the handshake timeout (took ${\ sprintf('%.1f', $took)}s)";
    ok $rig->wait_log(qr/ACTION=tls-failure PEER=127\.0\.0\.7\b/, 8, $from),
        'the silent client\'s abandoned handshake is counted under its address';
    close $silent;
}

# allowed_ips is applied before any TLS cost: a refused address never reaches
# the handshake, so it is logged ip-block and not tls-failure.
{
    $rig->set_conf("allowed_ips = 127.0.0.1\n");
    $rig->hup;
    $rig->wait_log(qr/Reloading agent\.conf/, 5);
    my $from = $rig->log_len;
    is $rig->request(as => 'rogue', from => '127.0.0.8'), undef, 'refused address gets no reply';
    ok $rig->wait_log(qr/ACTION=ip-block PEER=127\.0\.0\.8\b/, 5, $from), 'logged as ip-block';
    unlike substr($rig->log_text, $from), qr/tls-failure PEER=127\.0\.0\.8/,
        'no TLS work is done for it';
    is $rig->request(as => 'trusted', from => '127.0.0.1'), 200, 'allowed address served';
}

ok $rig->alive, 'agent survived all of it';
$rig->stop;
done_testing;
