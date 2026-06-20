#!/usr/bin/perl
# t/random.t
#
# Contract tests for Exec::Random::hex_bytes, the single /dev/urandom reader
# behind every reqid and nonce. It must return exactly $n bytes as 2*$n hex
# characters and must not repeat across calls (entropy sanity).

use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/../lib";

use Exec::Random qw();

subtest 'hex_bytes: returns 2*n lowercase hex characters' => sub {
    my $h = Exec::Random::hex_bytes(8);
    like $h, qr/^[0-9a-f]{16}$/, '8 bytes -> 16 hex chars';
    is length(Exec::Random::hex_bytes(16)), 32, '16 bytes -> 32 hex chars';
    is length(Exec::Random::hex_bytes(4)),  8,  '4 bytes -> 8 hex chars';
};

subtest 'hex_bytes: successive calls differ' => sub {
    my %seen;
    $seen{ Exec::Random::hex_bytes(8) }++ for 1 .. 20;
    is scalar(keys %seen), 20, '20 draws are all distinct';
};

done_testing;
