#!/usr/bin/perl
# t/engine-old-cert-hint.t
#
# T-068, the dispatcher's side. A dispatcher certificate issued before 0.14 on
# an OpenSSL 1.1 host carries no Authority Key Identifier; an agent that also
# trusts another CA with the same name refuses it at the TLS handshake. When a
# connection to an agent fails that way and this dispatcher's own certificate
# has no AKI, the error the operator sees says so and names the fix. With an
# AKI, or for any other failure, the error is what it was. The error stays one
# string in the same field: the result's shape does not change.

use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/../lib", "$Bin/lib";

require AgentRig;
plan skip_all => 'openssl not available' unless AgentRig::available();
require Exec::Engine;

my $HINT = qr/\Qthis dispatcher's certificate predates 0.14 (it has no Authority Key Identifier)\E.*
              \Qrun 'ctrl-exec-dispatcher rotate-cert'\E/xs;

# One rig for the certificates: the leaves with AKIs (default) and without.
my $with    = AgentRig->new();
my $without = AgentRig->new(aki => 0);
my %cfg = (
    with    => { cert => "$with->{dir}/trusted.crt",    key => "$with->{dir}/trusted.key" },
    without => { cert => "$without->{dir}/trusted.crt", key => "$without->{dir}/trusted.key" },
);

sub xlate { Exec::Engine::_transport_error($_[0], 'agent-01', 7443, $_[1]) }

subtest 'the error text: only for a certificate without an AKI, only for a refusal' => sub {
    my $tls    = "500 Can't connect to agent-01:7443 (SSL connect attempt failed error:0A000418:SSL routines::tlsv1 alert unknown ca)";
    my $closed = '500 Server closed connection without sending any data back';
    my $m = xlate($tls, $cfg{without});
    like $m, qr/\ATLS handshake with 'agent-01' failed - certificate or trust mismatch/,
        'TLS failure: the existing text comes first';
    like $m, $HINT, 'TLS failure, certificate without an AKI: the hint follows';
    like xlate($closed, $cfg{without}), qr/\A\Q$closed\E/, 'closed with no reply: as before, first';
    like xlate($closed, $cfg{without}), $HINT,
        'closed with no reply (how TLS 1.3 shows a refused client certificate): the hint';

    is xlate($tls, $cfg{with}), "TLS handshake with 'agent-01' failed - certificate or trust mismatch",
        'certificate with an AKI: unchanged';
    is xlate($closed, $cfg{with}), $closed, 'closed, certificate with an AKI: unchanged';
    my $status = '500 Status read failed: ';
    like xlate($status, $cfg{without}), qr/\A\Q$status\E/,
        'older LWP wording of the same close (Debian 11): as before, first';
    like xlate($status, $cfg{without}), $HINT, 'older LWP wording: the hint';
    is xlate($status, $cfg{with}), $status, 'older LWP wording, certificate with an AKI: unchanged';
    like xlate('500 read failed: ', $cfg{without}), $HINT,
        'older LWP wording after a request body (Ubuntu 20.04 run): the hint';
    is xlate($tls), "TLS handshake with 'agent-01' failed - certificate or trust mismatch",
        'no config: unchanged';
    is xlate($tls, { cert => "$without->{dir}/missing.crt" }),
        "TLS handshake with 'agent-01' failed - certificate or trust mismatch",
        'an unreadable certificate: unchanged';
    unlike xlate("500 Can't connect to agent-01:7443 (Connection refused)", $cfg{without}), $HINT,
        'connection refused: no hint';
    unlike xlate('500 read timeout', $cfg{without}), $HINT, 'a timeout: no hint';
};

# A real agent with two same-named CAs refusing a pre-0.14 dispatcher
# certificate (the T-067 case), reached through the per-host workers the CLI
# and the API use. They are called directly: ping_all forks, and the rig's
# agent belongs to this process.
subtest 'a live refusal reaches the operator with the hint' => sub {
    my $rig = AgentRig->new(second_ca => 1, aki => 0, extra_conf => "rate_limit_disable = 1\n");
    my $d   = $rig->{dir};
    $rig->start or BAIL_OUT('rig agent did not start: ' . $rig->log_text);
    my $config = sub {
        my ($as) = @_;
        return { cert => "$d/$as.crt", key => "$d/$as.key", ca => "$d/ca.crt",
                 registry_dir => "$d/registry" };
    };
    my %at = (host => '127.0.0.1', port => $rig->{port}, reqid => 'aaaaaaaaaaaaaaaa');

    my $ok = Exec::Engine::_ping_one(%at, config => $config->('trusted'));
    is $ok->{status}, 'ok', 'dispatcher 1 (its CA first of the name) pings' or diag explain $ok;

    my $r = Exec::Engine::_ping_one(%at, config => $config->('d2'));
    is $r->{status}, 'error', 'dispatcher 2 is refused';
    like $r->{error}, $HINT, 'ping: the error carries the hint';
    is_deeply [ sort keys %$r ], [ sort qw(host status error rtt) ], 'the result has the same fields';

    $r = Exec::Engine::_dispatch_one(%at, script => 'ok', config => $config->('d2'));
    like $r->{error}, $HINT, 'run: the error carries the hint';
    $r = Exec::Engine::_capabilities_one(%at, config => $config->('d2'));
    like $r->{error}, $HINT, 'capabilities: the error carries the hint';
    $r = Exec::Engine::_rotate_one(%at, serial => 'abcd', action => 'add', config => $config->('d2'));
    like $r->{error}, $HINT, 'rotate-serial: the error carries the hint';
    $r = Exec::Engine::_result_one(%at, config => $config->('d2'));
    like $r->{error}, $HINT, 'result: the error carries the hint';
    ok $rig->alive, 'agent survived';
    $rig->stop;
};

subtest 'a refusal of a certificate with an AKI: no hint' => sub {
    my $rig = AgentRig->new(extra_conf => "rate_limit_disable = 1\n");
    my $d   = $rig->{dir};
    $rig->start or BAIL_OUT('rig agent did not start: ' . $rig->log_text);
    my $r = Exec::Engine::_ping_one(host => '127.0.0.1', port => $rig->{port}, reqid => 'bbbbbbbbbbbbbbbb',
        config => { cert => "$d/rogue.crt", key => "$d/rogue.key", ca => "$d/ca.crt" });
    is $r->{status}, 'error', 'a foreign CA\'s certificate is refused';
    unlike $r->{error}, $HINT, 'without the hint: its certificate has an AKI';
    $rig->stop;
};

done_testing;
