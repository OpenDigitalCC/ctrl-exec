#!/usr/bin/perl
# t/api-request.t  (TC-003)
#
# Component tests for the dispatcher HTTP API request layer
# (Exec::API::_handle_connection), driven over an in-memory socketpair. The
# request path - the auth gate's position (BEFORE routing), the 400/413/431
# boundary responses, and the 404 fall-through - was previously exercised only
# by the live integration suite. These are security-relevant boundaries: the
# auth gate must sit before routing so no endpoint (not even /health) is reached
# unauthenticated, and the size caps must reject before the body is read.
#
# Exec::Auth::check is stubbed so this tests the API WIRING, not Auth's policy
# (which t/auth.t covers).

use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/../lib";
use IO::Socket::UNIX qw();

use Exec::API  qw();
use Exec::Auth qw();
use Exec::Log  qw();

Exec::Log::init('test');

my $AUTH_OK = 1;
{
    no warnings 'redefine';
    *Exec::Log::log_action     = sub {};
    *Exec::Auth::check         = sub { return { ok => $AUTH_OK, reason => 'stub' }; };
    *Exec::Auth::deny_fields   = sub { return { error => 'forbidden' }; };
}

sub drive {
    my (%opt) = @_;
    $AUTH_OK = exists $opt{auth_ok} ? $opt{auth_ok} : 1;
    my ($client, $server) = IO::Socket::UNIX->socketpair(
        IO::Socket::AF_UNIX(), IO::Socket::SOCK_STREAM(), 0) or die "socketpair: $!";
    print $client $opt{request} // '';
    $client->shutdown(1);
    Exec::API::_handle_connection($server, $opt{peer} // '127.0.0.1', $opt{config} // {});
    $server->close;
    local $/;
    my $resp = <$client> // '';
    $client->close;
    return $resp;
}

# --- boundary responses: rejected before the auth gate / body read -----------

subtest 'empty request -> 400' => sub {
    like drive(request => ''), qr{^HTTP/1\.0 400 }, 'empty request is a 400';
};

subtest 'header flood -> 431' => sub {
    my $req = "GET /health HTTP/1.0\r\n" . ("X-Pad: y\r\n" x 40) . "\r\n";
    like drive(request => $req), qr{^HTTP/1\.0 431 }, 'over 32 headers is a 431';
};

subtest 'oversized Content-Length -> 413 (before the body is read)' => sub {
    my $req = "POST /run HTTP/1.0\r\nContent-Length: 2000000\r\n\r\n";
    like drive(request => $req), qr{^HTTP/1\.0 413 }, 'a body over 1 MiB is a 413';
};

# --- the auth gate sits BEFORE routing ---------------------------------------

subtest 'auth denial -> 403 even for /health (gate precedes routing)' => sub {
    my $resp = drive(request => "GET /health HTTP/1.0\r\n\r\n", auth_ok => 0);
    like $resp, qr{^HTTP/1\.0 403 }, 'a denied request never reaches the route';
};

subtest 'auth allowed: /health routes and returns 200' => sub {
    my $resp = drive(request => "GET /health HTTP/1.0\r\n\r\n", auth_ok => 1);
    like $resp, qr{^HTTP/1\.0 200 }, '/health is served once authorised';
    like $resp, qr/"version"/,       'health body carries the version';
};

# --- routing fall-through ----------------------------------------------------

subtest 'unknown route (authorised) -> 404' => sub {
    my $resp = drive(request => "GET /nope HTTP/1.0\r\n\r\n", auth_ok => 1);
    like $resp, qr{^HTTP/1\.0 404 }, 'an unknown path 404s rather than mis-routing';
};

done_testing;
