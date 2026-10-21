#!/usr/bin/perl
# t/agent-ca-bundle.t
#
# T-061, on a real agent: its CA file is a bundle of two dispatcher CAs with the
# same subject name, and the trusted-dispatcher map is keyed by issuing CA and
# serial. Two dispatchers with different CAs both run; a certificate from the
# second CA carrying the first dispatcher's serial is refused; rotation records
# the caller's CA; revocation under one CA leaves the same serial under the
# other running, while an old serial-only line refuses it everywhere. A
# single-CA agent with a pre-0.14 map keeps its dispatcher and has the map
# upgraded in place.

use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/../lib", "$Bin/lib";
use JSON qw(encode_json decode_json);

require AgentRig;
plan skip_all => 'openssl not available' unless AgentRig::available();

sub slurp {
    my ($path) = @_;
    open my $fh, '<', $path or die "read $path: $!";
    local $/;
    return scalar <$fh>;
}

sub spew {
    my ($path, $text) = @_;
    open my $fh, '>', $path or die "write $path: $!";
    print $fh $text;
    close $fh;
}

subtest 'two dispatcher CAs on one agent' => sub {
    my $rig = AgentRig->new(second_ca => 1);
    my $d   = $rig->{dir};
    my $f1  = AgentRig::fingerprint("$d/ca.crt");
    my $f2  = AgentRig::fingerprint("$d/ca2.crt");
    $rig->start or BAIL_OUT('rig agent did not start: ' . $rig->log_text);

    is $rig->request(as => 'trusted'), 200, 'dispatcher 1 (ca, serial 0x3ea) runs';
    is $rig->request(as => 'd2'),      200, 'dispatcher 2 (ca2, serial 0x7d2) runs';

    my $from = $rig->log_len;
    is $rig->request(as => 'evil'), 403,
        'a ca2 certificate carrying dispatcher 1\'s serial is refused';
    ok $rig->wait_log(qr/ACTION=serial-reject .*PEER_SERIAL=0*3ea\b/, 5, $from),
        'logged as a serial reject' or diag substr($rig->log_text, $from);
    my ($st, $body) = $rig->call('GET', '/capabilities', '', as => 'evil');
    is $st, 403, 'and refused discovery';

    # Rotation as d2 records the new serial under ca2.
    ($st, $body) = $rig->call('POST', '/rotate-serial',
        encode_json({ serial => 'abcd', action => 'add' }), as => 'd2');
    is $st, 200, 'rotate add answered';
    is decode_json($body)->{status}, 'ok', 'rotate add ok' or diag $body;
    like slurp("$d/dispatchers"), qr/^\Q$f2\E abcd d2$/m, 'new serial recorded under ca2';
    unlike slurp("$d/dispatchers"), qr/^\Q$f1\E abcd/m, 'and not under ca';

    ($st, $body) = $rig->call('POST', '/rotate-serial',
        encode_json({ serial => '3ea', action => 'remove' }), as => 'd2');
    like slurp("$d/dispatchers"), qr/^\Q$f1\E 3ea test-dispatcher$/m,
        'd2 retiring 0x3ea does not touch dispatcher 1\'s entry under ca';

    ($st, $body) = $rig->call('POST', '/rotate-serial',
        encode_json({ serial => 'abcd', action => 'remove' }), as => 'd2');
    is decode_json($body)->{status}, 'ok', 'rotate retire ok' or diag $body;
    unlike slurp("$d/dispatchers"), qr/ abcd /, 'retired serial gone';

    # Revocation keyed by CA.
    spew("$d/revoked", "$f1 7d2\n");
    $from = $rig->log_len;
    $rig->hup;
    $rig->wait_log(qr/ACTION=allowlist-reload/, 5, $from);
    is $rig->request(as => 'd2'), 200, 'serial 0x7d2 revoked under ca: d2 under ca2 still runs';

    spew("$d/revoked", "$f2 7d2\n");
    $from = $rig->log_len;
    $rig->hup;
    $rig->wait_log(qr/ACTION=allowlist-reload/, 5, $from);
    $from = $rig->log_len;
    isnt $rig->request(as => 'd2') // 0, 200, 'revoked under ca2: d2 refused';
    ok $rig->wait_log(qr/ACTION=revoked-cert .*SERIAL=0*7d2\b/, 5, $from),
        'as a revoked certificate';
    is $rig->request(as => 'trusted'), 200, 'dispatcher 1 unaffected';

    spew("$d/revoked", "7d2\n");
    $from = $rig->log_len;
    $rig->hup;
    $rig->wait_log(qr/ACTION=allowlist-reload/, 5, $from);
    $from = $rig->log_len;
    isnt $rig->request(as => 'd2') // 0, 200, 'an old serial-only revocation still refuses';
    ok $rig->wait_log(qr/ACTION=revoked-cert .*SERIAL=0*7d2\b/, 5, $from),
        'as a revoked certificate';

    ok $rig->alive, 'agent survived';
    $rig->stop;
};

subtest 'a pre-0.14 agent: one CA, two-field map' => sub {
    my $rig = AgentRig->new();
    my $d   = $rig->{dir};
    my $f1  = AgentRig::fingerprint("$d/ca.crt");
    is slurp("$d/dispatchers"), "3ea test-dispatcher\n", 'map starts in the old form';
    $rig->start or BAIL_OUT('rig agent did not start: ' . $rig->log_text);

    is $rig->request(as => 'trusted'), 200, 'its dispatcher still runs, no manual step';
    like slurp("$d/dispatchers"), qr/^\Q$f1\E 3ea test-dispatcher$/m,
        'map upgraded in place with the CA fingerprint';
    like $rig->log_text, qr/ACTION=trusted-map-upgrade/, 'the upgrade is logged';
    is $rig->request(as => 'untrusted'), 403, 'an unpaired cert from the same CA is still refused';
    $rig->stop;
};

done_testing;
