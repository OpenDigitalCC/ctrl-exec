#!/usr/bin/perl
# rotate-serial.t
#
# The built-in /rotate-serial control-plane operation (handle_rotate_serial in
# ctrl-exec-agent) maintains the trusted-dispatcher map during cert rotation,
# replacing the old update-ctrl-exec-serial script. The handler runs in the agent
# front-end (NOT the executor), and derives the dispatcher identity from the
# CALLER's authenticated serial - never from the request - so a dispatcher can
# only add/retire serials under its own identity.
#
# The handler itself needs an mTLS connection to drive end-to-end (covered by the
# on-host integration test). Here we test the trust-map operations it performs and
# the security rule it enforces: identity comes from the caller, and retire is
# scoped to serials the caller owns - the property that makes rotation a safely
# chained trust rather than a way to inject a foreign serial.
#
# Since 0.14 (T-061) the map is keyed by issuing CA and serial: the handler adds
# a serial under the CA that issued the caller's certificate and retires only
# under it. CA fingerprints here are stand-ins; agent-ca-bundle.t drives the
# real handler over mTLS with two CAs.

use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);

use lib 'lib';
use Exec::Agent::AgentPairing;

my $tmpdir = tempdir(CLEANUP => 1);

my $CA1 = 'a' x 64;
my $CA2 = 'b' x 64;

# The view of the map for callers whose cert $ca issued (default $CA1).
sub load {
    my ($path, $ca) = @_;
    return Exec::Agent::AgentPairing::trusted_for_issuers(
        Exec::Agent::AgentPairing::load_trusted_dispatchers(path => $path), [ $ca // $CA1 ]);
}

# Mirror the handler's ADD: the new serial is stored under the caller's derived
# id and the caller's issuing CA.
sub rotate_add {
    my ($path, $serial, $caller_id, $ca) = @_;
    Exec::Agent::AgentPairing::add_trusted_dispatcher(
        path => $path, serial => $serial, id => $caller_id, issuer => $ca // $CA1);
}

# Mirror the handler's RETIRE: refuse to remove a serial owned by another
# identity under the caller's CA.
sub rotate_remove {
    my ($path, $serial, $caller_id, $ca) = @_;
    my $hex = Exec::CertInfo::serial_to_hex($serial);
    my $map = load($path, $ca);
    die "serial not owned by '$caller_id'\n"
        if exists $map->{$hex} && $map->{$hex} ne $caller_id;
    Exec::Agent::AgentPairing::remove_trusted_dispatcher(
        path => $path, serial => $serial, issuer => $ca // $CA1);
}

subtest 'overlap: new serial added under the same identity, both trusted' => sub {
    my $path = "$tmpdir/overlap";
    rotate_add($path, '1111aaaa', 'dispatcher-a');   # original, from pairing
    rotate_add($path, '2222bbbb', 'dispatcher-a');   # rotation broadcast (add)
    my $map = load($path);
    is $map->{'1111aaaa'}, 'dispatcher-a', 'old serial still trusted during overlap';
    is $map->{'2222bbbb'}, 'dispatcher-a', 'new serial trusted under the SAME identity';
};

subtest 'retire: the old serial is removed after the overlap window' => sub {
    my $path = "$tmpdir/retire";
    rotate_add($path, '1111aaaa', 'dispatcher-a');
    rotate_add($path, '2222bbbb', 'dispatcher-a');
    rotate_remove($path, '1111aaaa', 'dispatcher-a'); # caller now authed by 2222bbbb -> id a
    my $map = load($path);
    ok !exists $map->{'1111aaaa'}, 'old serial retired';
    is $map->{'2222bbbb'}, 'dispatcher-a', 'current serial remains';
};

subtest 'a dispatcher cannot retire another dispatcher serial' => sub {
    my $path = "$tmpdir/cross";
    rotate_add($path, 'aaaa0001', 'dispatcher-a');
    rotate_add($path, 'bbbb0002', 'dispatcher-b');
    my $died = !eval { rotate_remove($path, 'aaaa0001', 'dispatcher-b'); 1 };
    ok $died, 'cross-identity retire is rejected';
    like $@, qr/not owned/, 'rejected as not-owned';
    is load($path)->{'aaaa0001'}, 'dispatcher-a', "dispatcher-a's serial untouched";
};

subtest 'retire of an absent serial is a no-op (idempotent)' => sub {
    my $path = "$tmpdir/absent";
    rotate_add($path, 'cccc0003', 'dispatcher-a');
    ok eval { rotate_remove($path, 'dddd0004', 'dispatcher-a'); 1 },
        'retiring an absent serial does not die';
    is load($path)->{'cccc0003'}, 'dispatcher-a', 'existing entry intact';
};

subtest 'rotation keeps the issuer: add and retire act under the caller\'s CA' => sub {
    my $path = "$tmpdir/issuer";
    rotate_add($path, 'eeee0005', 'dispatcher-a', $CA1);
    rotate_add($path, 'eeee0005', 'dispatcher-b', $CA2);   # same serial, other CA
    rotate_add($path, 'ffff0006', 'dispatcher-b', $CA2);   # b rotates
    is load($path, $CA2)->{'ffff0006'}, 'dispatcher-b', 'new serial under CA2';
    ok !exists load($path, $CA1)->{'ffff0006'}, 'and not under CA1';
    ok eval { rotate_remove($path, 'eeee0005', 'dispatcher-b', $CA2); 1 },
        'b retires its old serial';
    is load($path, $CA1)->{'eeee0005'}, 'dispatcher-a',
        'the same serial under CA1 (dispatcher-a) is untouched';
    ok !exists load($path, $CA2)->{'eeee0005'}, 'gone under CA2';
};

done_testing;
