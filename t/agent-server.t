#!/usr/bin/perl
# t/agent-server.t  (TC-002)
#
# Component tests for the agent's HTTP request handler (Exec::Agent::Server),
# driven over an in-memory socketpair - no network, no SSL. This is the agent's
# primary authorisation gate (serial-mismatch 403, revoked-cert deny) plus the
# request-boundary responses (400/413/431). Previously the module's only test
# (agent-modulino.t) merely asserted the handler subs were defined - a coverage
# illusion - so the enforcement wiring that turns a trust decision into a 403
# was exercised only by the live root integration suite.

use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/../lib";
use IO::Socket::UNIX qw();

use Exec::Agent::Server qw();
use Exec::Log           qw();

Exec::Log::init('test');

# Capture log_action calls (the gate logs serial-reject / revoked-cert).
my @logs;
{
    no warnings 'redefine';
    *Exec::Log::log_action = sub { push @logs, $_[1] };
}

# Drive handle_connection with a request string and return the raw HTTP response.
sub drive {
    my (%opt) = @_;
    my ($client, $server) = IO::Socket::UNIX->socketpair(
        IO::Socket::AF_UNIX(), IO::Socket::SOCK_STREAM(), 0) or die "socketpair: $!";
    print $client $opt{request} // '';
    $client->shutdown(1);   # EOF on the write side so the handler's reads end
    Exec::Agent::Server::handle_connection(
        $server,
        $opt{peer}        // '10.0.0.5',
        $opt{allowlist}   // {},
        $opt{config}      // {},
        $opt{revoked}     // {},
        $opt{trusted}     // {},
        $opt{peer_serial} // '',
        $opt{schemas}     // {},
        $opt{version}     // '9.9.9',
    );
    $server->close;
    local $/;
    my $resp = <$client> // '';
    $client->close;
    return $resp;
}

# --- _require_dispatcher: the trusted-serial gate in isolation ---------------

subtest '_require_dispatcher: trusted serial returns the dispatcher id, no 403' => sub {
    my $out = '';
    open my $conn, '>', \$out or die $!;
    my $id = Exec::Agent::Server::_require_dispatcher(
        $conn, '10.0.0.5', 'deadbeef', { deadbeef => 'disp-1' }, 'r1');
    close $conn;
    is $id, 'disp-1', 'returns the mapped dispatcher id';
    is $out, '', 'writes nothing (no rejection)';
};

subtest '_require_dispatcher: untrusted serial -> 403, logged, undef' => sub {
    @logs = ();
    my $out = '';
    open my $conn, '>', \$out or die $!;
    my $id = Exec::Agent::Server::_require_dispatcher(
        $conn, '10.0.0.9', 'cafef00d', { deadbeef => 'disp-1' }, 'r2');
    close $conn;
    is $id, undef, 'returns undef for an untrusted serial';
    like $out, qr{^HTTP/1\.0 403 }, 'sends a 403';
    like $out, qr/serial mismatch/, 'with a serial-mismatch body';
    ok( (grep { ($_->{ACTION} // '') eq 'serial-reject' } @logs),
        'logs a serial-reject' );
};

# --- handle_connection: revoked cert is denied before anything else ----------

subtest 'revoked serial -> 403 certificate revoked' => sub {
    @logs = ();
    my $resp = drive(
        peer_serial => 'deadbeef',
        revoked     => { deadbeef => 1 },
        request     => "POST /run HTTP/1.0\r\n\r\n",
    );
    like $resp, qr{^HTTP/1\.0 403 }, '403 for a revoked cert';
    like $resp, qr/certificate revoked/, 'revoked-cert body';
    ok( (grep { ($_->{ACTION} // '') eq 'revoked-cert' } @logs), 'logs revoked-cert' );
};

# --- handle_connection: request-boundary responses ---------------------------

subtest 'empty request -> 400' => sub {
    my $resp = drive(request => '');
    like $resp, qr{^HTTP/1\.0 400 }, 'empty request is a 400';
};

subtest 'too many headers -> 431' => sub {
    my $req = "POST /run HTTP/1.0\r\n" . ("X-Pad: y\r\n" x 40) . "\r\n";
    my $resp = drive(request => $req, peer_serial => 'deadbeef',
                     trusted => { deadbeef => 'disp-1' });
    like $resp, qr{^HTTP/1\.0 431 }, 'header flood is a 431';
};

subtest 'oversized body -> 413' => sub {
    my $req = "POST /run HTTP/1.0\r\nContent-Length: 2000000\r\n\r\n";
    my $resp = drive(request => $req, peer_serial => 'deadbeef',
                     trusted => { deadbeef => 'disp-1' });
    like $resp, qr{^HTTP/1\.0 413 }, 'a body over 1 MiB is rejected with 413';
};

# --- handle_connection: the gate is wired into /run --------------------------

subtest 'POST /run with an untrusted serial -> 403 serial mismatch' => sub {
    my $resp = drive(
        request     => "POST /run HTTP/1.0\r\nContent-Length: 2\r\n\r\n{}",
        peer_serial => 'cafef00d',
        trusted     => { deadbeef => 'disp-1' },
    );
    like $resp, qr{^HTTP/1\.0 403 }, '/run is gated';
    like $resp, qr/serial mismatch/, 'an untrusted dispatcher cannot run';
};

subtest 'POST /run with a trusted serial passes the gate' => sub {
    my $resp = drive(
        request     => "POST /run HTTP/1.0\r\nContent-Length: 2\r\n\r\n{}",
        peer_serial => 'deadbeef',
        trusted     => { deadbeef => 'disp-1' },
    );
    unlike $resp, qr/serial mismatch/,
        'a trusted dispatcher is not rejected at the serial gate';
};

done_testing;
