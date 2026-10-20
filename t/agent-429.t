#!/usr/bin/perl
# t/agent-429.t
#
# T-043: when the limiter refuses a connection the agent answers 429 and closes.
# It used to close without reading the request, so a client that had already
# written its request (unread data on close) could get a TCP reset that
# discarded the 429 before it was read. The agent now half-closes after the
# reply and drains what the client sent, bounded in bytes and time.
#
# Runs a real agent on a loopback port. 127.0.0.5 is put under a probe block
# (three failed handshakes), then connects with a TLS client certificate that
# the handshake accepts but the volume exemption does not cover.

use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/../lib", "$Bin/lib";
use Time::HiRes qw(time sleep);
use IO::Socket::SSL;

require AgentRig;
plan skip_all => 'openssl not available' unless AgentRig::available();

my $rig = AgentRig->new();
$rig->start or BAIL_OUT('rig agent did not start: ' . $rig->log_text);

my $from = $rig->log_len;
$rig->request(as => 'rogue', from => '127.0.0.5') for 1 .. 3;
$rig->wait_log(qr/ACTION=rate-block PEER=127\.0\.0\.5 REASON=probe/, 5, $from)
    or BAIL_OUT('could not put 127.0.0.5 under a block: ' . $rig->log_text);

# Connect as an unpaired client from the blocked address, write a request of
# $size body bytes, optionally pause, then read the reply. Returns
# ($status, $body-text) or () when no HTTP reply was readable.
sub blocked_client {
    my (%o) = @_;
    my $d = $rig->{dir};
    local $SIG{PIPE} = 'IGNORE';
    my $c = IO::Socket::SSL->new(
        PeerAddr        => '127.0.0.1',
        PeerPort        => $rig->{port},
        LocalAddr       => '127.0.0.5',
        SSL_cert_file   => "$d/untrusted.crt",
        SSL_key_file    => "$d/untrusted.key",
        SSL_ca_file     => "$d/ca.crt",
        SSL_verify_mode => SSL_VERIFY_NONE,
        Timeout         => 15,
    ) or return;
    my $body = 'x' x ($o{size} // 2);
    print $c "POST /ping HTTP/1.0\r\nContent-Length: " . length($body) . "\r\n\r\n$body";
    sleep $o{pause} if $o{pause};
    my $reply = '';
    while (defined(my $l = <$c>)) { $reply .= $l }
    close $c;
    return unless $reply =~ m{^HTTP/\S+\s+(\d+)};
    return ($1 + 0, $reply);
}

# A full request written first, then read, 50 times: the 429 body arrives every time.
{
    my ($ok, $bad) = (0, 0);
    for (1 .. 50) {
        my ($st, $text) = blocked_client(size => 2);
        ($st // 0) == 429 && $text =~ /rate limited/ ? $ok++ : $bad++;
    }
    is $bad, 0, "small request: all 50 got the 429 body ($ok ok)";
}

# A request bigger than the socket buffers cannot be absorbed by the kernel, so
# an agent that closes unread resets the connection every time.
{
    my ($ok, $bad) = (0, 0);
    for (1 .. 10) {
        my ($st, $text) = blocked_client(size => 40_000, pause => 0.05);
        ($st // 0) == 429 && $text =~ /rate limited/ ? $ok++ : $bad++;
    }
    is $bad, 0, "40 KB request: all 10 got the 429 body ($ok ok)";
}

# A client that completes the handshake and then says nothing and reads nothing
# does not hold the accept loop beyond the drain bound (1 s).
{
    my $d = $rig->{dir};
    my $slow = IO::Socket::SSL->new(
        PeerAddr => '127.0.0.1', PeerPort => $rig->{port}, LocalAddr => '127.0.0.5',
        SSL_cert_file => "$d/untrusted.crt", SSL_key_file => "$d/untrusted.key",
        SSL_ca_file => "$d/ca.crt", SSL_verify_mode => SSL_VERIFY_NONE, Timeout => 15,
    );
    ok $slow, 'silent client connected and completed the handshake';
    my $t0 = time;
    is $rig->request(as => 'trusted', from => '127.0.0.1'), 200,
        'a normal client is served while the silent blocked client is being drained';
    my $took = time - $t0;
    cmp_ok $took, '<', 2.5, sprintf('and waits no longer than the drain bound (%.2fs)', $took);
    close $slow;

    # A client dripping a byte at a time cannot extend the bound either.
    my $drip = IO::Socket::SSL->new(
        PeerAddr => '127.0.0.1', PeerPort => $rig->{port}, LocalAddr => '127.0.0.5',
        SSL_cert_file => "$d/untrusted.crt", SSL_key_file => "$d/untrusted.key",
        SSL_ca_file => "$d/ca.crt", SSL_verify_mode => SSL_VERIFY_NONE, Timeout => 15,
    );
    my $kid = fork // die;
    if (!$kid) {
        local $SIG{PIPE} = 'IGNORE';
        for (1 .. 40) { syswrite($drip, 'x') or last; sleep 0.2 }
        exit 0;
    }
    $t0 = time;
    is $rig->request(as => 'trusted', from => '127.0.0.1'), 200,
        'a normal client is served while a dripping blocked client is being drained';
    $took = time - $t0;
    cmp_ok $took, '<', 2.5, sprintf('and the drip does not extend the bound (%.2fs)', $took);
    kill 'TERM', $kid;
    waitpid $kid, 0;
}

ok $rig->alive, 'agent survived';
$rig->stop;
done_testing;
