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

use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);

use lib 'lib';
use Exec::Agent::AgentPairing;

my $tmpdir = tempdir(CLEANUP => 1);

sub load { Exec::Agent::AgentPairing::load_trusted_dispatchers(path => $_[0]) }

# Mirror the handler's ADD: the new serial is stored under the caller's derived id.
sub rotate_add {
    my ($path, $serial, $caller_id) = @_;
    Exec::Agent::AgentPairing::add_trusted_dispatcher(
        path => $path, serial => $serial, id => $caller_id);
}

# Mirror the handler's RETIRE: refuse to remove a serial owned by another identity.
sub rotate_remove {
    my ($path, $serial, $caller_id) = @_;
    my $hex = Exec::CertInfo::serial_to_hex($serial);
    my $map = load($path);
    die "serial not owned by '$caller_id'\n"
        if exists $map->{$hex} && $map->{$hex} ne $caller_id;
    Exec::Agent::AgentPairing::remove_trusted_dispatcher(path => $path, serial => $serial);
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

done_testing;
