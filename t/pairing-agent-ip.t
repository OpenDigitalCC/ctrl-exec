#!/usr/bin/perl
use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/../lib";

use Exec::Pairing qw();

# An agent now self-reports its source IP in the pairing request so the
# dispatcher can register a reachable address even when a NAT in front of it
# (e.g. Docker) rewrites the connection's source IP to the gateway. These
# tests cover the validation and precedence that drive that.

subtest '_valid_ip: accepts IP literals, rejects junk' => sub {
    is Exec::Pairing::_valid_ip('192.168.1.10'), '192.168.1.10', 'IPv4';
    is Exec::Pairing::_valid_ip('172.18.0.1'),   '172.18.0.1',   'IPv4 (docker gateway)';
    is Exec::Pairing::_valid_ip('2001:db8::1'),  '2001:db8::1',  'IPv6';
    is Exec::Pairing::_valid_ip('fe80::1'),      'fe80::1',      'IPv6 link-local';
    is Exec::Pairing::_valid_ip(undef),     undef, 'undef rejected';
    is Exec::Pairing::_valid_ip(''),        undef, 'empty rejected';
    is Exec::Pairing::_valid_ip('unknown'), undef, "'unknown' rejected";
    is Exec::Pairing::_valid_ip('agent.example.com'), undef, 'hostname rejected';
};

subtest '_effective_ip: operator override > queued value' => sub {
    # approve_request calls _effective_ip($opts{ip}, $req->{ip}); the queued
    # $req->{ip} is already reported-or-peer from request time.
    is Exec::Pairing::_effective_ip('10.0.0.5', '192.168.1.10'), '10.0.0.5',
        'approve --ip overrides the queued value';
    is Exec::Pairing::_effective_ip(undef, '192.168.1.10'), '192.168.1.10',
        'queued value used when no override';
    is Exec::Pairing::_effective_ip('not-an-ip', '192.168.1.10'), '192.168.1.10',
        'invalid override is skipped; next valid candidate wins';
    is Exec::Pairing::_effective_ip(undef, undef), '',
        'empty string when nothing is valid';
};

subtest 'request-time precedence: agent-reported beats the NAT source' => sub {
    my $peer     = '172.18.0.1';     # docker gateway (the rewritten source)
    my $reported = '192.168.1.10';   # agent's real source address

    # This mirrors $reported_ip // $peer_ip in _handle_pair_request.
    is( (Exec::Pairing::_valid_ip($reported) // $peer), '192.168.1.10',
        'agent-reported IP is registered, not the NAT gateway' );
    is( (Exec::Pairing::_valid_ip('garbage') // $peer), '172.18.0.1',
        'an invalid reported value falls back to the connection source' );
};

done_testing;
