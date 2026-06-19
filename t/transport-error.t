#!/usr/bin/perl
use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/../lib";

require Exec::Engine;

# _transport_error rewrites recognised network failures into status-like
# messages, and leaves anything else (notably real HTTP statuses) untouched.

sub xlate { Exec::Engine::_transport_error($_[0], 'web01', 7443) }

subtest 'DNS resolution failures' => sub {
    like xlate("500 Can't connect to web01:7443 (Bad hostname)"),
        qr/did not resolve/, 'bad hostname';
    like xlate("500 Can't connect to web01:7443 (Name or service not known)"),
        qr/did not resolve/, 'name or service not known';
    like xlate("Temporary failure in name resolution"),
        qr/did not resolve/, 'temporary resolver failure';
};

subtest 'connection refused names the port and likely cause' => sub {
    my $m = xlate("500 Can't connect to web01:7443 (Connection refused)");
    like $m, qr/connection refused/i, 'states refused';
    like $m, qr/7443/,                'names the port';
    like $m, qr/agent not running/,   'suggests the likely cause';
};

subtest 'unreachable and timeout' => sub {
    like xlate("500 Can't connect (No route to host)"),   qr/unreachable/, 'no route';
    like xlate("Network is unreachable"),                 qr/unreachable/, 'network down';
    like xlate("500 Can't connect to web01:7443 (timeout)"), qr/timed out/, 'connect timeout';
};

subtest 'TLS failures' => sub {
    like xlate("500 Can't connect (SSL connect attempt failed)"),
        qr/TLS handshake/, 'ssl connect';
    like xlate("certificate verify failed"),
        qr/TLS handshake/, 'cert verify';
};

subtest 'real HTTP statuses and unknowns pass through unchanged' => sub {
    is xlate("403 Forbidden"),             "403 Forbidden",             'auth status untouched';
    is xlate("500 Internal Server Error"), "500 Internal Server Error", 'agent 500 untouched';
    is xlate("no response"),               "no response",               'unknown untouched';
};

subtest 'host name is interpolated' => sub {
    like Exec::Engine::_transport_error("Connection refused", 'db-7', 7443),
        qr/'db-7'/, 'uses the given host';
};

done_testing;
