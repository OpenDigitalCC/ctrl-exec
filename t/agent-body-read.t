#!/usr/bin/perl
# t/agent-body-read.t  (T-089)
#
# The agent reads the whole request body (R-034). A real agent on a loopback
# TLS port gets a ~100 KB POST /run: one read on a TLS connection returns at
# most 16 KiB, which used to cut the body and answer "invalid JSON". And a body
# that ends before Content-Length never reaches a handler, even when what did
# arrive happens to be valid JSON.

use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/../lib", "$Bin/lib";
use JSON::PP qw(encode_json decode_json);
use IO::Socket::SSL;

require AgentRig;
plan skip_all => 'openssl not available' unless AgentRig::available();

my $rig = AgentRig->new();
$rig->start or BAIL_OUT('rig agent did not start: ' . $rig->log_text);

# A 100 KB confidential input: the answer must come from the run handler
# (here: the script is not on the allowlist), not from a JSON decode failure.
my $body = encode_json({ script => 'ingest', args => [], input => { blob => 'x' x 100_000 } });
my ($status, $resp) = $rig->call('POST', '/run', $body);
ok defined $status, 'the agent answered';
unlike $resp // '', qr/invalid JSON/, 'a 100,000-byte body was read whole';
my $d = eval { decode_json($resp // '') } // {};
is $d->{script} // $d->{error} // '', 'ingest', 'the run handler saw the request (it named the script)'
    or diag $resp;

# Valid JSON that arrives short: the peer declares 50,000 bytes, sends 40 and
# ends. No handler may act on it.
{
    local $SIG{PIPE} = 'IGNORE';
    my $dir = $rig->{dir};
    my $c = IO::Socket::SSL->new(
        PeerAddr => '127.0.0.1', PeerPort => $rig->{port},
        SSL_cert_file => "$dir/trusted.crt", SSL_key_file => "$dir/trusted.key",
        SSL_ca_file => "$dir/ca.crt", SSL_verify_mode => SSL_VERIFY_NONE, Timeout => 15,
    ) or BAIL_OUT("connect: $SSL_ERROR");
    my $short = '{"script":"truncated-probe","args":[]}';
    print $c "POST /run HTTP/1.0\r\nContent-Length: 50000\r\n\r\n$short";
    CORE::shutdown($c, 1);
    local $/;
    my $r = <$c> // '';
    close $c;
    unlike $r, qr{^HTTP/1\.0 200 }, 'a short body is not answered as a run';
    select undef, undef, undef, 0.5;
    unlike $rig->log_text, qr/truncated-probe/, 'the run handler never saw the truncated body';
}

done_testing;
