#!/usr/bin/perl
# t/serial-normalisation.t
#
# Unit tests for serial_to_hex, serial_revoked, and load_revoked_serials
# in Exec::Agent::AgentPairing.
#
# serial_to_hex is a private function (_serial_to_hex is how handle_capabilities
# calls it) but is also called as serial_to_hex from serial_revoked. Tests
# call it as Exec::Agent::AgentPairing::serial_to_hex, which is the public
# name. If the agent code is calling _serial_to_hex that is a separate bug
# noted in SECURITY-FINDINGS.md.

use strict;
use warnings;
use Test::More;
use File::Temp qw(tempfile);
use FindBin qw($Bin);
use lib "$Bin/../lib";

use Exec::Agent::AgentPairing qw();
use Exec::Log qw();

# Initialise syslog handle so load_revoked_serials and other functions
# that call log_action do not hit the uninitialised fallback path.
Exec::Log::init('test');

# ---------------------------------------------------------------------------
# serial_to_hex: basic hex input
# ---------------------------------------------------------------------------

subtest 'serial_to_hex: lowercase hex passthrough' => sub {
    is Exec::Agent::AgentPairing::serial_to_hex('deadbeef'), 'deadbeef',
        'lowercase hex returned unchanged';
};

subtest 'serial_to_hex: uppercase hex normalised to lowercase' => sub {
    is Exec::Agent::AgentPairing::serial_to_hex('DEADBEEF'), 'deadbeef',
        'uppercase hex lowercased';
};

subtest 'serial_to_hex: mixed case normalised' => sub {
    is Exec::Agent::AgentPairing::serial_to_hex('DeAdBeEf'), 'deadbeef',
        'mixed case lowercased';
};

# Leading-zero canonicalisation: a stored serial carrying an insignificant
# leading 00 byte (e.g. migrated from a pre-0.9.0 single-serial file) must
# normalise to the same minimal hex the live readers produce, or it never
# matches and the dispatcher is rejected as a serial mismatch.
subtest 'serial_to_hex: leading 00 byte stripped' => sub {
    is Exec::Agent::AgentPairing::serial_to_hex('00aabbccdd'), 'aabbccdd',
        'leading 00 byte dropped';
    is Exec::Agent::AgentPairing::serial_to_hex('0000aabbccdd'), 'aabbccdd',
        'multiple leading zero bytes dropped';
    is Exec::Agent::AgentPairing::serial_to_hex('00DEADBEEF'), 'deadbeef',
        'leading 00 dropped and lowercased';
};

subtest 'serial_to_hex: stored leading-00 matches live minimal hex' => sub {
    # The exact failure mode: openssl/Net::SSLeay emit 'aabbccdd'; an older
    # migrated entry stored '00aabbccdd'. Both must resolve to one key.
    is Exec::Agent::AgentPairing::serial_to_hex('00aabbccdd'),
       Exec::Agent::AgentPairing::serial_to_hex('aabbccdd'),
       'migrated and live forms canonicalise identically';
};

subtest 'serial_to_hex: an all-zero serial keeps one digit' => sub {
    is Exec::Agent::AgentPairing::serial_to_hex('00'), '0',
        'all-zero serial does not strip to empty';
};

# ---------------------------------------------------------------------------
# serial_to_hex: 0x prefix
# ---------------------------------------------------------------------------

subtest 'serial_to_hex: 0x prefix stripped' => sub {
    is Exec::Agent::AgentPairing::serial_to_hex('0xDEADBEEF'), 'deadbeef',
        '0x prefix stripped and lowercased';
};

subtest 'serial_to_hex: 0X uppercase prefix stripped' => sub {
    is Exec::Agent::AgentPairing::serial_to_hex('0XDEADBEEF'), 'deadbeef',
        '0X prefix stripped';
};

# ---------------------------------------------------------------------------
# serial_to_hex: serial= prefix (openssl x509 -serial output)
# ---------------------------------------------------------------------------

subtest 'serial_to_hex: serial= prefix stripped' => sub {
    is Exec::Agent::AgentPairing::serial_to_hex('serial=DEADBEEF'), 'deadbeef',
        'serial= prefix stripped';
};

subtest 'serial_to_hex: Serial= mixed-case prefix stripped' => sub {
    is Exec::Agent::AgentPairing::serial_to_hex('Serial=DEADBEEF'), 'deadbeef',
        'Serial= mixed-case prefix stripped';
};

# ---------------------------------------------------------------------------
# serial_to_hex: decimal input
# ---------------------------------------------------------------------------

subtest 'serial_to_hex: decimal 3735928559 = 0xDEADBEEF' => sub {
    is Exec::Agent::AgentPairing::serial_to_hex('3735928559'), 'deadbeef',
        'decimal converted to hex';
};

subtest 'serial_to_hex: decimal 255 -> ff' => sub {
    is Exec::Agent::AgentPairing::serial_to_hex('255'), 'ff',
        '255 decimal -> ff';
};

subtest 'serial_to_hex: decimal 256 -> 100' => sub {
    is Exec::Agent::AgentPairing::serial_to_hex('256'), '100',
        '256 decimal -> 100';
};

# ---------------------------------------------------------------------------
# serial_to_hex: large decimal (>64-bit, requires Math::BigInt)
# ---------------------------------------------------------------------------

subtest 'serial_to_hex: large decimal serial >64-bit' => sub {
    # python3: hex(1234567890123456789012345678901234567890)
    # = '0x3a0c92075c0dbf3b8acbc5f96ce3f0ad2'
    my $decimal  = '1234567890123456789012345678901234567890';
    my $expected = '3a0c92075c0dbf3b8acbc5f96ce3f0ad2';
    my $result   = eval { Exec::Agent::AgentPairing::serial_to_hex($decimal) };
    if ($@) {
        skip "Math::BigInt not available: $@", 1;
        return;
    }
    is lc($result), $expected, 'large decimal converted correctly via Math::BigInt';
};

subtest 'serial_to_hex: large hex serial round-trips unchanged' => sub {
    my $hex    = 'a3f9b2c10001deadbeef0102030405060708090a';
    my $result = Exec::Agent::AgentPairing::serial_to_hex($hex);
    is $result, $hex, 'large hex serial returned unchanged';
};

# ---------------------------------------------------------------------------
# serial_to_hex: colon-separated hex (some IO::Socket::SSL versions)
# ---------------------------------------------------------------------------

subtest 'serial_to_hex: colon-separated hex DE:AD:BE:EF' => sub {
    my $result = Exec::Agent::AgentPairing::serial_to_hex('DE:AD:BE:EF');
    is $result, 'deadbeef', 'colon-separated hex normalised';
};

subtest 'serial_to_hex: colon-separated with leading zero byte 00:DE:AD:BE:EF' => sub {
    my $result = Exec::Agent::AgentPairing::serial_to_hex('00:DE:AD:BE:EF');
    is $result, 'deadbeef', 'leading zero byte in colon-separated stripped';
};

subtest 'serial_to_hex: colon-separated lowercase ca:fe:ba:be' => sub {
    my $result = Exec::Agent::AgentPairing::serial_to_hex('ca:fe:ba:be');
    is $result, 'cafebabe', 'lowercase colon-separated normalised';
};

# ---------------------------------------------------------------------------
# serial_to_hex: edge cases
# ---------------------------------------------------------------------------

subtest 'serial_to_hex: zero decimal' => sub {
    my $result = Exec::Agent::AgentPairing::serial_to_hex('0');
    like $result, qr/^0+$/, "zero decimal -> '0'";
};

subtest 'serial_to_hex: empty string returns empty string' => sub {
    is Exec::Agent::AgentPairing::serial_to_hex(''), '', 'empty string -> empty string';
};

subtest 'serial_to_hex: undef returns empty string' => sub {
    is Exec::Agent::AgentPairing::serial_to_hex(undef), '', 'undef -> empty string';
};

# ---------------------------------------------------------------------------
# serial_to_hex: consistency checks
# ---------------------------------------------------------------------------

subtest 'serial_to_hex: decimal and hex of same value produce identical output' => sub {
    # 4294967295 = 0xFFFFFFFF
    my $from_decimal = Exec::Agent::AgentPairing::serial_to_hex('4294967295');
    my $from_hex     = Exec::Agent::AgentPairing::serial_to_hex('FFFFFFFF');
    is $from_decimal, $from_hex,
        'decimal and hex of same serial produce identical output';
};

subtest 'serial_to_hex: 0x-prefixed and plain hex produce identical output' => sub {
    my $with    = Exec::Agent::AgentPairing::serial_to_hex('0xCAFEBABE');
    my $without = Exec::Agent::AgentPairing::serial_to_hex('CAFEBABE');
    is $with, $without, '0x-prefixed and plain hex identical';
};

subtest 'serial_to_hex: serial= prefix and plain hex produce identical output' => sub {
    my $prefixed = Exec::Agent::AgentPairing::serial_to_hex('serial=CAFEBABE');
    my $plain    = Exec::Agent::AgentPairing::serial_to_hex('CAFEBABE');
    is $prefixed, $plain, 'serial= prefix and plain hex identical';
};

# ---------------------------------------------------------------------------
# serial_to_hex: output format invariants
# ---------------------------------------------------------------------------

subtest 'serial_to_hex: output is always lowercase' => sub {
    for my $input ('ABCDEF01', '0xABCDEF', 'serial=ABCDEF') {
        my $result = Exec::Agent::AgentPairing::serial_to_hex($input);
        next unless length $result;
        is lc($result), $result, "output is lowercase for '$input'";
    }
};

subtest 'serial_to_hex: output has no 0x prefix' => sub {
    my $result = Exec::Agent::AgentPairing::serial_to_hex('0xDEADBEEF');
    unlike $result, qr/^0x/i, 'no 0x prefix in output';
};

# ---------------------------------------------------------------------------
# load_revoked_serials
# ---------------------------------------------------------------------------

subtest 'load_revoked_serials: absent file returns empty hashref' => sub {
    my $revoked = Exec::Agent::AgentPairing::load_revoked_serials(
        path => '/nonexistent/revoked-serials'
    );
    is ref $revoked, 'HASH', 'returns hashref';
    is scalar keys %$revoked, 0, 'empty when file absent';
};

subtest 'load_revoked_serials: parses hex serials correctly' => sub {
    my ($fh, $path) = tempfile(UNLINK => 1);
    print $fh "deadbeef\ncafebabe\n";
    close $fh;

    my $revoked = Exec::Agent::AgentPairing::load_revoked_serials(path => $path);
    ok $revoked->{deadbeef}, 'deadbeef in revoked set';
    ok $revoked->{cafebabe}, 'cafebabe in revoked set';
    is scalar keys %$revoked, 2, 'exactly 2 entries';
};

subtest 'load_revoked_serials: strips # comments' => sub {
    my ($fh, $path) = tempfile(UNLINK => 1);
    print $fh "# this is a comment\ndeadbeef\n# another comment\n";
    close $fh;

    my $revoked = Exec::Agent::AgentPairing::load_revoked_serials(path => $path);
    ok  $revoked->{deadbeef}, 'valid serial present';
    ok !$revoked->{'# this is a comment'}, 'comment line not in set';
    is scalar keys %$revoked, 1, 'only 1 entry';
};

subtest 'load_revoked_serials: strips blank lines' => sub {
    my ($fh, $path) = tempfile(UNLINK => 1);
    print $fh "\ndeadbeef\n\n\ncafebabe\n\n";
    close $fh;

    my $revoked = Exec::Agent::AgentPairing::load_revoked_serials(path => $path);
    is scalar keys %$revoked, 2, 'blank lines not counted as entries';
};

subtest 'load_revoked_serials: normalises uppercase to lowercase' => sub {
    my ($fh, $path) = tempfile(UNLINK => 1);
    print $fh "DEADBEEF\nCAFEBABE\n";
    close $fh;

    my $revoked = Exec::Agent::AgentPairing::load_revoked_serials(path => $path);
    ok $revoked->{deadbeef}, 'uppercase normalised to lowercase deadbeef';
    ok $revoked->{cafebabe}, 'uppercase normalised to lowercase cafebabe';
    ok !$revoked->{DEADBEEF}, 'uppercase key not stored';
};

subtest 'load_revoked_serials: strips serial= prefix' => sub {
    my ($fh, $path) = tempfile(UNLINK => 1);
    print $fh "serial=DEADBEEF\nSerial=CAFEBABE\n";
    close $fh;

    my $revoked = Exec::Agent::AgentPairing::load_revoked_serials(path => $path);
    ok $revoked->{deadbeef}, 'serial= prefix stripped';
    ok $revoked->{cafebabe}, 'Serial= mixed-case prefix stripped';
};

subtest 'load_revoked_serials: decimal serial normalised to hex' => sub {
    my ($fh, $path) = tempfile(UNLINK => 1);
    # 12345678 decimal = 0xBC614E
    print $fh "deadbeef\nnot-a-serial\n12345678\n";
    close $fh;

    my $revoked = Exec::Agent::AgentPairing::load_revoked_serials(path => $path);
    ok  $revoked->{deadbeef}, 'valid hex serial present';
    ok !$revoked->{'not-a-serial'}, 'invalid line rejected';
    ok !$revoked->{12345678},  'decimal not stored as raw digits';
    ok  $revoked->{bc614e},    'decimal 12345678 normalised to hex bc614e';
};

subtest 'load_revoked_serials: colon-separated entries normalised' => sub {
    my ($fh, $path) = tempfile(UNLINK => 1);
    print $fh "DE:AD:BE:EF\nCA:FE:BA:BE\n";
    close $fh;

    my $revoked = Exec::Agent::AgentPairing::load_revoked_serials(path => $path);
    ok  $revoked->{deadbeef}, 'colon-separated DE:AD:BE:EF stored as deadbeef';
    ok  $revoked->{cafebabe}, 'colon-separated CA:FE:BA:BE stored as cafebabe';
    ok !$revoked->{'de:ad:be:ef'}, 'colon form not stored verbatim';
};

subtest 'load_revoked_serials: 0x-prefixed entries normalised' => sub {
    my ($fh, $path) = tempfile(UNLINK => 1);
    print $fh "0xDEADBEEF\n0xcafebabe\n";
    close $fh;

    my $revoked = Exec::Agent::AgentPairing::load_revoked_serials(path => $path);
    ok  $revoked->{deadbeef}, '0xDEADBEEF stored as deadbeef';
    ok  $revoked->{cafebabe}, '0xcafebabe stored as cafebabe';
};

subtest 'load_revoked_serials: serial_revoked matches colon-form peer serial against file entry' => sub {
    # End-to-end: file written with plain hex, peer cert returns colon form.
    # Both must normalise to the same key.
    my ($fh, $path) = tempfile(UNLINK => 1);
    print $fh "deadbeef\n";
    close $fh;

    my $revoked = Exec::Agent::AgentPairing::load_revoked_serials(path => $path);
    is Exec::Agent::AgentPairing::serial_revoked('DE:AD:BE:EF', $revoked), 1,
        'colon-form peer serial matches plain-hex revocation entry';
};

subtest 'load_revoked_serials: serial_revoked matches decimal peer serial against file entry' => sub {
    # File written with hex, peer cert serial arrives as decimal string.
    my ($fh, $path) = tempfile(UNLINK => 1);
    print $fh "deadbeef\n";
    close $fh;

    my $revoked = Exec::Agent::AgentPairing::load_revoked_serials(path => $path);
    # 3735928559 decimal = 0xDEADBEEF
    is Exec::Agent::AgentPairing::serial_revoked('3735928559', $revoked), 1,
        'decimal peer serial matches hex revocation entry';
};

subtest 'load_revoked_serials: inline comments stripped' => sub {
    my ($fh, $path) = tempfile(UNLINK => 1);
    print $fh "deadbeef  # revoked 2025-01-01\ncafebabe # another\n";
    close $fh;

    my $revoked = Exec::Agent::AgentPairing::load_revoked_serials(path => $path);
    ok  $revoked->{deadbeef}, 'serial with inline comment parsed';
    ok  $revoked->{cafebabe}, 'second serial with inline comment parsed';
    ok !exists $revoked->{'deadbeef  '}, 'no trailing whitespace in key';
};

# ---------------------------------------------------------------------------
# serial_revoked
# ---------------------------------------------------------------------------

subtest 'serial_revoked: returns false for empty revocation list' => sub {
    my $revoked = {};
    is Exec::Agent::AgentPairing::serial_revoked('deadbeef', $revoked), 0,
        'not revoked against empty set';
};

subtest 'serial_revoked: returns false when serial not in list' => sub {
    my $revoked = { cafebabe => 1 };
    is Exec::Agent::AgentPairing::serial_revoked('deadbeef', $revoked), 0,
        'different serial not revoked';
};

subtest 'serial_revoked: returns true when serial is in list' => sub {
    my $revoked = { deadbeef => 1 };
    is Exec::Agent::AgentPairing::serial_revoked('deadbeef', $revoked), 1,
        'matching serial is revoked';
};

subtest 'serial_revoked: normalises input before lookup' => sub {
    my $revoked = { deadbeef => 1 };
    is Exec::Agent::AgentPairing::serial_revoked('DEADBEEF', $revoked), 1,
        'uppercase serial normalised and found';
};

subtest 'serial_revoked: returns false for undef serial' => sub {
    my $revoked = { deadbeef => 1 };
    is Exec::Agent::AgentPairing::serial_revoked(undef, $revoked), 0,
        'undef serial returns false';
};

subtest 'serial_revoked: returns false for undef revoked list' => sub {
    is Exec::Agent::AgentPairing::serial_revoked('deadbeef', undef), 0,
        'undef revoked list returns false';
};

done_testing;
