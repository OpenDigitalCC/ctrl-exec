#!/usr/bin/perl
# t/digest.t
#
# Known-answer tests for Exec::Digest. The pairing code is computed
# INDEPENDENTLY by the agent and the dispatcher and the operator compares the
# two displays, so the algorithm (sha256 of the CSR, first 4 bytes as a uint32
# mod 1,000,000) must never drift. A refactor changing the unpack, modulo or
# substr offset would silently make the two sides disagree; these fixed vectors
# catch that.

use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/../lib";

use Exec::Digest qw();

# sha256("abc")  = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
# sha256("")     = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
subtest 'sha256_hex: known-answer vectors' => sub {
    is Exec::Digest::sha256_hex('abc'),
       'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
       'sha256("abc")';
    is Exec::Digest::sha256_hex(''),
       'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
       'sha256("")';
};

# sha256("abc") first 4 bytes = ba 78 16 bf = 0xba7816bf = 3128432319;
# 3128432319 % 1_000_000 = 432319.
subtest 'pairing_code: known-answer for "abc"' => sub {
    is Exec::Digest::pairing_code('abc'), '432319',
       'pairing code of "abc" is the documented 432319';
};

subtest 'pairing_code: deterministic and always 6 digits' => sub {
    my $a = Exec::Digest::pairing_code('-----BEGIN CERTIFICATE REQUEST-----x');
    my $b = Exec::Digest::pairing_code('-----BEGIN CERTIFICATE REQUEST-----x');
    is $a, $b, 'same input -> same code';
    like $a, qr/^\d{6}$/, 'exactly six digits (zero-padded)';
};

subtest 'pairing_code: distinct CSRs generally differ' => sub {
    isnt Exec::Digest::pairing_code('csr-one'),
         Exec::Digest::pairing_code('csr-two'),
         'different CSRs produce different codes';
};

done_testing;
