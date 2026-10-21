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

# Certificates as 0.13.2 issued them on an OpenSSL 1.1 host: no key identifiers.
sub has_aki {
    my ($path) = @_;
    return scalar(`openssl x509 -noout -text -in $path 2>/dev/null`) =~ /Authority Key Identifier/ ? 1 : 0;
}

subtest 'a pre-0.14 agent: one CA, two-field map' => sub {
    my $rig = AgentRig->new(aki => 0);
    my $d   = $rig->{dir};
    my $f1  = AgentRig::fingerprint("$d/ca.crt");
    is has_aki("$d/trusted.crt") + has_aki("$d/agent.crt"), 0,
        'its certificates carry no AKI, as a 1.1 host issued them before 0.14';
    is slurp("$d/dispatchers"), "3ea test-dispatcher\n", 'map starts in the old form';
    $rig->start or BAIL_OUT('rig agent did not start: ' . $rig->log_text);

    is $rig->request(as => 'trusted'), 200, 'its dispatcher still runs, no manual step';
    like slurp("$d/dispatchers"), qr/^\Q$f1\E 3ea test-dispatcher$/m,
        'map upgraded in place with the CA fingerprint';
    like $rig->log_text, qr/ACTION=trusted-map-upgrade/, 'the upgrade is logged';
    is $rig->request(as => 'untrusted'), 403, 'an unpaired cert from the same CA is still refused';
    isnt $rig->request(as => 'rogue') // 0, 200, 'a cert from another CA fails the handshake';
    $rig->stop;
};

# Two CAs with one name (both made before 0.14) and dispatcher certificates
# without an AKI (issued before 0.14 on an OpenSSL 1.1 host): the TLS chain is
# built by name, so the second dispatcher's certificate is checked against the
# first CA and fails, on every OpenSSL version. That stays a refusal - nothing
# is accepted that OpenSSL did not verify - and the first dispatcher is
# unaffected. The certificate the second dispatcher's CA issues from 0.14 on
# (rotate-cert) carries an AKI and is accepted (the first subtest).
subtest 'same-named CAs, certificates without an AKI: refused, not accepted' => sub {
    my $rig = AgentRig->new(second_ca => 1, aki => 0);
    my $d   = $rig->{dir};
    is has_aki("$d/d2.crt"), 0, 'd2 carries no AKI';
    $rig->start or BAIL_OUT('rig agent did not start: ' . $rig->log_text);
    is $rig->request(as => 'trusted'), 200, 'dispatcher 1 (first CA of the name) runs';
    my $from = $rig->log_len;
    isnt $rig->request(as => 'd2') // 0, 200, 'dispatcher 2 is refused';
    my $line = $rig->wait_log(qr/ACTION=tls-failure .*certificate verify failed/, 5, $from);
    ok $line, 'at the handshake, as a verify failure' or diag substr($rig->log_text, $from);
    # T-068: the log line says why and what to do.
    like $line, qr/REASON="[^"]*certificate verify failed - \Qthe dispatcher certificate (serial 7d2) predates 0.14: it has no Authority Key Identifier and its CA has the same name (CN=ca) as another CA this agent trusts, so it is not compatible. Upgrade that dispatcher to 0.14 or later and run 'ctrl-exec-dispatcher rotate-cert'\E/,
        'the reason names the cause (a pre-0.14 certificate, a same-named CA) and the fix';
    like $line, qr/an upgrade alone keeps the old certificate\), then pair this agent with it again/,
        'and that an upgrade alone is not enough';
    ok $rig->alive, 'agent survived';
    $rig->stop;
};

# T-068: the same-name explanation is given only for that cause. A certificate
# no trusted CA signed - from a stranger's CA with the same name, or from a CA
# with another name - is refused as before, with OpenSSL's reason alone.
subtest 'a refusal for any other reason carries no same-name explanation' => sub {
    my $rig = AgentRig->new(second_ca => 1, aki => 0);
    my $d   = $rig->{dir};
    AgentRig::_make_ca($d, 'ca3', 'ca');                     # not in the bundle, same name
    AgentRig::_make_leaf($d, 'ca3', 'stranger', 3003, aki => 0);
    $rig->start or BAIL_OUT('rig agent did not start: ' . $rig->log_text);
    for my $as (qw(stranger rogue)) {
        my $from = $rig->log_len;
        isnt $rig->request(as => $as) // 0, 200, "$as is refused";
        my $line = $rig->wait_log(qr/ACTION=tls-failure .*certificate verify failed/, 5, $from);
        ok $line, "$as: at the handshake" or diag substr($rig->log_text, $from);
        unlike $line // '', qr/predates 0\.14/, "$as: no same-name explanation";
    }
    is $rig->request(as => 'trusted'), 200, 'dispatcher 1 still runs';
    $rig->stop;
};

# T-068: the way out. The refused dispatcher, upgraded, rotates its certificate
# (rotate-cert issues it with Exec::CA::generate_dispatcher_cert, which adds the
# key identifiers): the agent's TLS handshake now accepts it, as it already
# trusts that dispatcher's CA. Its new serial is not in the agent's map - the
# rotation broadcast could not reach an agent that refused the old certificate
# - so the agent answers 403 until it is paired with that dispatcher again
# (pairing records the serial under the CA that issued it, as below). Nothing
# changes for the first dispatcher.
subtest 'same-named CAs: after rotate-cert and pairing again, the dispatcher runs' => sub {
    require Exec::CA;
    require Exec::Agent::AgentPairing;
    require Exec::CertInfo;
    my $rig = AgentRig->new(second_ca => 1, aki => 0);
    my $d   = $rig->{dir};
    my $f2  = AgentRig::fingerprint("$d/ca2.crt");
    $rig->start or BAIL_OUT('rig agent did not start: ' . $rig->log_text);
    isnt $rig->request(as => 'd2') // 0, 200, 'the pre-0.14 certificate is refused';

    mkdir "$d/ca2dir" or die "mkdir: $!";
    system("cp $d/ca2.crt $d/ca2dir/ca.crt && cp $d/ca2.key $d/ca2dir/ca.key") == 0 or die;
    Exec::CA::generate_dispatcher_cert(ca_dir => "$d/ca2dir", cert => "$d/d2new.crt",
        key => "$d/d2new.key", bits => 2048, days => 2);
    is has_aki("$d/d2new.crt"), 1, 'the rotated certificate carries an AKI';

    my $from = $rig->log_len;
    is $rig->request(as => 'd2new'), 403, 'the rotated certificate passes the handshake';
    ok $rig->wait_log(qr/ACTION=serial-reject /, 5, $from),
        'and is refused only for its serial, not yet in the map' or diag substr($rig->log_text, $from);

    my $serial = Exec::CertInfo::serial_from_path("$d/d2new.crt");
    Exec::Agent::AgentPairing::add_trusted_dispatcher(path => "$d/dispatchers",
        serial => $serial, id => 'd2', issuer => $f2, ca_path => $rig->{ca_file});
    $from = $rig->log_len;
    $rig->hup;
    ok $rig->wait_log(qr/ACTION=allowlist-reload/, 5, $from), 'agent reloaded the map';
    is $rig->request(as => 'd2new'), 200, 'paired again: the dispatcher runs';
    is $rig->request(as => 'trusted'), 200, 'dispatcher 1 still runs';
    $rig->stop;
};

done_testing;
