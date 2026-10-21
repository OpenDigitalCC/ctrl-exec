#!/usr/bin/perl
# t/agent-trust-issuer.t
#
# T-061: the agent trusts a bundle of dispatcher CAs, and the trusted-dispatcher
# map and the revocation list are keyed by issuing CA and serial. Covers the CA
# bundle (pairing appends, de-duplicated by fingerprint), issuer resolution from
# a certificate, the issuer-keyed map and its in-place upgrade from the pre-0.14
# two-field form, issuer-keyed revocation with the old serial-only form still
# applying to every CA, and renewal validation pinned to the live cert's CA.
#
# The two CAs here have the same subject name (two CAs made with the defaults
# are both "ctrl-exec CA"), so nothing below can pass by matching names.

use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/../lib", "$Bin/lib";
use File::Temp qw(tempdir);

use Exec::Agent::AgentPairing qw();
use Exec::CertInfo qw();

require AgentRig;
plan skip_all => 'openssl not available' unless AgentRig::available();

my $d = tempdir(CLEANUP => 1);

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

# Two dispatcher CAs with one subject name, and a third.
AgentRig::_make_ca($d, 'ca1', 'ctrl-exec-CA');
AgentRig::_make_ca($d, 'ca2', 'ctrl-exec-CA');
AgentRig::_make_ca($d, 'ca3', 'ctrl-exec-CA');
AgentRig::_make_leaf($d, 'ca1', 'd1',   1002);   # dispatcher d1
AgentRig::_make_leaf($d, 'ca2', 'd2',   2002);   # dispatcher d2
AgentRig::_make_leaf($d, 'ca2', 'evil', 1002);   # ca2 cert with d1's serial
AgentRig::_make_leaf($d, 'ca1', 'agent', 1001);  # the agent's own cert

my %fpr = map { $_ => AgentRig::fingerprint("$d/$_.crt") } qw(ca1 ca2 ca3);
my %pem = map { $_ => slurp("$d/$_.crt") } qw(ca1 ca2 ca3);
isnt $fpr{ca1}, $fpr{ca2}, 'the two CAs have different fingerprints';

spew("$d/bundle12.crt", $pem{ca1} . $pem{ca2});

# ---------------------------------------------------------------------------
# CA bundle and issuer resolution
# ---------------------------------------------------------------------------

subtest 'pem_fingerprint and load_ca_bundle agree with openssl' => sub {
    is Exec::Agent::AgentPairing::pem_fingerprint($pem{ca1}), $fpr{ca1}, 'one PEM';
    is Exec::CertInfo::fingerprint_from_path("$d/ca1.crt"), $fpr{ca1},
        'Exec::CertInfo computes the same value';
    is_deeply [ Exec::Agent::AgentPairing::ca_bundle_fingerprints("$d/bundle12.crt") ],
        [ $fpr{ca1}, $fpr{ca2} ], 'bundle: both CAs, in file order';
    is_deeply [ Exec::Agent::AgentPairing::ca_bundle_fingerprints("$d/absent.crt") ],
        [], 'absent bundle: none';
};

my $bundle = Exec::Agent::AgentPairing::load_ca_bundle("$d/bundle12.crt");

subtest 'cert_issuers names the CA that signed the cert, not one with its name' => sub {
    is_deeply [ Exec::Agent::AgentPairing::pem_issuers(slurp("$d/d1.crt"), $bundle) ],
        [ $fpr{ca1} ], 'd1: ca1';
    is_deeply [ Exec::Agent::AgentPairing::pem_issuers(slurp("$d/d2.crt"), $bundle) ],
        [ $fpr{ca2} ], 'd2: ca2';
    is_deeply [ Exec::Agent::AgentPairing::pem_issuers(slurp("$d/evil.crt"), $bundle) ],
        [ $fpr{ca2} ], 'evil (ca2, d1 serial): ca2 only';
    my $only1 = Exec::Agent::AgentPairing::load_ca_bundle("$d/ca1.crt");
    is_deeply [ Exec::Agent::AgentPairing::pem_issuers(slurp("$d/evil.crt"), $only1) ],
        [], 'evil against a bundle without ca2: no issuer, despite the same issuer name';
    Exec::Agent::AgentPairing::free_ca_bundle($only1);
};

# ---------------------------------------------------------------------------
# The refusal at the centre of T-061
# ---------------------------------------------------------------------------

subtest 'a second CA\'s cert carrying a trusted serial is refused' => sub {
    my $path = "$d/map-refuse";
    Exec::Agent::AgentPairing::add_trusted_dispatcher(
        path => $path, serial => '1002', id => 'd1', issuer => $fpr{ca1});
    Exec::Agent::AgentPairing::add_trusted_dispatcher(
        path => $path, serial => '2002', id => 'd2', issuer => $fpr{ca2});
    my $map = Exec::Agent::AgentPairing::load_trusted_dispatchers(path => $path);

    my $resolve = sub {
        my ($leaf) = @_;
        my $pem     = slurp("$d/$leaf.crt");
        my @issuers = Exec::Agent::AgentPairing::pem_issuers($pem, $bundle);
        my $serial  = Exec::CertInfo::serial_from_path("$d/$leaf.crt");
        my $view    = Exec::Agent::AgentPairing::trusted_for_issuers($map, \@issuers);
        return scalar Exec::Agent::AgentPairing::dispatcher_trusted($serial, $view);
    };
    is $resolve->('d1'),   'd1',  'd1 (ca1, 0x3ea) is d1';
    is $resolve->('d2'),   'd2',  'd2 (ca2, 0x7d2) is d2';
    is $resolve->('evil'), undef, 'evil (ca2, 0x3ea) is nobody';
    is scalar Exec::Agent::AgentPairing::dispatcher_trusted('3ea', $map), undef,
        'the raw issuer-keyed map never matches a bare serial';
};

# ---------------------------------------------------------------------------
# Map format and upgrade
# ---------------------------------------------------------------------------

subtest 'issuer-keyed lines load; malformed ones are skipped' => sub {
    my $path = "$d/map-parse";
    spew($path, "# comment\n"
              . "$fpr{ca1} 3EA d1\n"
              . uc($fpr{ca2}) . " 0x7d2 d2   # trailing comment\n"
              . "abcd 3ea short-fpr\n"
              . "$fpr{ca1} 3ea bad/id\n"
              . "$fpr{ca1} 3ea d1 extra\n");
    my $map = Exec::Agent::AgentPairing::load_trusted_dispatchers(path => $path);
    is_deeply $map, { "$fpr{ca1} 3ea" => 'd1', "$fpr{ca2} 7d2" => 'd2' },
        'two good lines; short fingerprint, bad id and extra field skipped';
};

subtest 'a pre-0.14 map is upgraded in place against the single CA' => sub {
    my $path = "$d/map-old";
    spew($path, "# old\n3ea automation\nff human\n");
    my $map = Exec::Agent::AgentPairing::load_trusted_dispatchers(
        path => $path, ca_path => "$d/ca1.crt");
    is_deeply $map, { "$fpr{ca1} 3ea" => 'automation', "$fpr{ca1} ff" => 'human' },
        'entries carry the fingerprint of the current CA';
    like slurp($path), qr/^\Q$fpr{ca1}\E 3ea automation$/m, 'file rewritten in the new form';
    unlike slurp($path), qr/^3ea /m, 'no two-field line left';
    is_deeply Exec::Agent::AgentPairing::load_trusted_dispatchers(path => $path), $map,
        'the upgraded file loads the same without the CA';

    my $view = Exec::Agent::AgentPairing::trusted_for_issuers($map, [ $fpr{ca1} ]);
    is scalar Exec::Agent::AgentPairing::dispatcher_trusted('3ea', $view), 'automation',
        'the existing dispatcher is still trusted';
    $view = Exec::Agent::AgentPairing::trusted_for_issuers($map, [ $fpr{ca2} ]);
    is scalar Exec::Agent::AgentPairing::dispatcher_trusted('3ea', $view), undef,
        'and only under its CA';
};

subtest 'without a readable CA a pre-0.14 line keeps working as before' => sub {
    my $path = "$d/map-old-noca";
    spew($path, "3ea automation\n");
    my $map = Exec::Agent::AgentPairing::load_trusted_dispatchers(
        path => $path, ca_path => "$d/absent.crt");
    is_deeply $map, { '3ea' => 'automation' }, 'kept serial-only in memory';
    is slurp($path), "3ea automation\n", 'file untouched';
    my $view = Exec::Agent::AgentPairing::trusted_for_issuers($map, []);
    is scalar Exec::Agent::AgentPairing::dispatcher_trusted('3ea', $view), 'automation',
        'still trusted';
};

subtest 'a pre-0.14 line against a bundle of two keeps what was accepted before' => sub {
    my $path = "$d/map-old-two";
    spew($path, "3ea automation\n");
    my $map = Exec::Agent::AgentPairing::load_trusted_dispatchers(
        path => $path, ca_path => "$d/bundle12.crt");
    is_deeply $map, { "$fpr{ca1} 3ea" => 'automation', "$fpr{ca2} 3ea" => 'automation' },
        'one entry per CA in the bundle';
};

subtest 'add and remove need the issuing CA and act under it only' => sub {
    my $path = "$d/map-addrm";
    eval { Exec::Agent::AgentPairing::add_trusted_dispatcher(
        path => $path, serial => '3ea', id => 'd1') };
    like $@, qr/issuing CA fingerprint required/, 'add without issuer dies';
    ok !-e $path, 'and writes nothing';

    Exec::Agent::AgentPairing::add_trusted_dispatcher(
        path => $path, serial => '3ea', id => 'd1', issuer => $fpr{ca1});
    Exec::Agent::AgentPairing::add_trusted_dispatcher(
        path => $path, serial => '3ea', id => 'd2', issuer => $fpr{ca2});
    is Exec::Agent::AgentPairing::remove_trusted_dispatcher(
        path => $path, serial => '3ea', issuer => $fpr{ca2}), 1, 'removed under ca2';
    is_deeply Exec::Agent::AgentPairing::load_trusted_dispatchers(path => $path),
        { "$fpr{ca1} 3ea" => 'd1' }, 'the same serial under ca1 is untouched';
    is Exec::Agent::AgentPairing::remove_trusted_dispatcher(
        path => $path, serial => '3ea', issuer => $fpr{ca3}), 0, 'absent under ca3: no-op';
};

# ---------------------------------------------------------------------------
# Revocation
# ---------------------------------------------------------------------------

subtest 'revocation is keyed by CA; a serial-only line still revokes everywhere' => sub {
    my $path = "$d/revoked";
    spew($path, "$fpr{ca1} 7d2\n");
    my $rev = Exec::Agent::AgentPairing::load_revoked_serials(path => $path);
    my $v1  = Exec::Agent::AgentPairing::revoked_for_issuers($rev, [ $fpr{ca1} ]);
    my $v2  = Exec::Agent::AgentPairing::revoked_for_issuers($rev, [ $fpr{ca2} ]);
    ok  Exec::Agent::AgentPairing::serial_revoked('2002', $v1), 'revoked under ca1';
    ok !Exec::Agent::AgentPairing::serial_revoked('2002', $v2), 'the same serial under ca2 runs';

    spew($path, "serial=07D2\n");
    $rev = Exec::Agent::AgentPairing::load_revoked_serials(path => $path);
    for my $ca (qw(ca1 ca2 ca3)) {
        my $v = Exec::Agent::AgentPairing::revoked_for_issuers($rev, [ $fpr{$ca} ]);
        ok Exec::Agent::AgentPairing::serial_revoked('2002', $v),
            "old serial-only line revokes under $ca";
    }
    my $none = Exec::Agent::AgentPairing::revoked_for_issuers($rev, []);
    ok Exec::Agent::AgentPairing::serial_revoked('2002', $none),
        'and for a peer whose issuer is unknown';
};

# ---------------------------------------------------------------------------
# Pairing: store_certs
# ---------------------------------------------------------------------------

sub pair {
    my ($dir, $map, $ca, $serial, $id) = @_;
    local $SIG{__WARN__} = sub { };   # no ctrl-exec-agent group here
    Exec::Agent::AgentPairing::store_certs(
        cert_pem => "agent cert\n", key_pem => "agent key\n", ca_pem => $pem{$ca},
        dispatcher_serial => $serial, dispatcher_id => $id,
        cert_dir => $dir, trusted_path => $map, group => 'no-such-group-t061',
    );
}

subtest 'pairing appends the CA to the bundle and records the issuer' => sub {
    my $cd  = tempdir(DIR => $d);
    my $map = "$cd/state/dispatchers";
    pair($cd, $map, 'ca1', '3ea', 'd1');
    is slurp("$cd/ca.crt"), $pem{ca1} =~ s/\s*\z/\n/r, 'first pairing: ca.crt is the one CA';
    is_deeply Exec::Agent::AgentPairing::load_trusted_dispatchers(path => $map),
        { "$fpr{ca1} 3ea" => 'd1' }, 'map entry under ca1';

    pair($cd, $map, 'ca2', '7d2', 'd2');
    is_deeply [ Exec::Agent::AgentPairing::ca_bundle_fingerprints("$cd/ca.crt") ],
        [ $fpr{ca1}, $fpr{ca2} ], 'second dispatcher: its CA appended, the first kept first';
    is_deeply Exec::Agent::AgentPairing::load_trusted_dispatchers(path => $map),
        { "$fpr{ca1} 3ea" => 'd1', "$fpr{ca2} 7d2" => 'd2' }, 'both dispatchers trusted';
    is system("openssl verify -CAfile $cd/ca.crt $d/d1.crt $d/d2.crt >/dev/null 2>&1"), 0,
        'the bundle verifies both dispatchers';

    my $before = slurp("$cd/ca.crt");
    pair($cd, $map, 'ca1', '3eb', 'd1');
    is slurp("$cd/ca.crt"), $before, 're-pairing under a CA already held: bundle unchanged';
    is_deeply Exec::Agent::AgentPairing::load_trusted_dispatchers(path => $map),
        { "$fpr{ca1} 3ea" => 'd1', "$fpr{ca1} 3eb" => 'd1', "$fpr{ca2} 7d2" => 'd2' },
        'same CA: the new serial is added beside the old';

    pair($cd, $map, 'ca3', '3ec', 'd1');
    is_deeply Exec::Agent::AgentPairing::load_trusted_dispatchers(path => $map),
        { "$fpr{ca3} 3ec" => 'd1', "$fpr{ca2} 7d2" => 'd2' },
        'd1 re-paired under a new CA: its entries under the old CA end; d2 untouched';
};

subtest 'pairing a second dispatcher on a pre-0.14 agent' => sub {
    my $cd  = tempdir(DIR => $d);
    my $map = "$cd/dispatchers";
    spew("$cd/ca.crt", $pem{ca1});
    spew($map, "3ea automation\n");
    pair($cd, $map, 'ca2', '7d2', 'd2');
    is_deeply Exec::Agent::AgentPairing::load_trusted_dispatchers(path => $map),
        { "$fpr{ca1} 3ea" => 'automation', "$fpr{ca2} 7d2" => 'd2' },
        'the old entry is upgraded under the old CA only, before the new CA joins';
};

# ---------------------------------------------------------------------------
# Renewal validation against a bundle
# ---------------------------------------------------------------------------

subtest 'a renewed cert must come from the CA of the live cert' => sub {
    # With key identifiers, as the CA issues a renewed cert, so on OpenSSL 1.1
    # too the ca2 cert is refused by the pin and not by the same-name trap.
    spew("$d/renew.ext", AgentRig::key_id_ext(1));
    for my $ca (qw(ca1 ca2)) {
        system("openssl req -new -key $d/agent.key -subj /CN=agent -out $d/renew.csr 2>/dev/null") == 0 or die;
        system("openssl x509 -req -in $d/renew.csr -CA $d/$ca.crt -CAkey $d/$ca.key "
             . "-set_serial 0x5$ca -days 2 -extfile $d/renew.ext -out $d/renew-$ca.crt 2>/dev/null") == 0 or die;
    }
    my %o = (ca_path => "$d/bundle12.crt", key_path => "$d/agent.key",
             cert_path => "$d/agent.crt");
    my ($ok, $why) = Exec::Agent::AgentPairing::validate_cert(
        %o, cert_pem => slurp("$d/renew-ca1.crt"));
    ok $ok, 'renewal from the live cert\'s CA is accepted' or diag $why;
    ($ok, $why) = Exec::Agent::AgentPairing::validate_cert(
        %o, cert_pem => slurp("$d/renew-ca2.crt"));
    ok !$ok, 'renewal from another trusted CA is refused';
    like $why, qr/does not verify/, 'as not verifying against the agent CA';
    ($ok) = Exec::Agent::AgentPairing::validate_cert(
        ca_path => "$d/ca1.crt", key_path => "$d/agent.key",
        cert_path => "$d/agent.crt", cert_pem => slurp("$d/renew-ca1.crt"));
    ok $ok, 'a single-CA file behaves as before';
};

Exec::Agent::AgentPairing::free_ca_bundle($bundle);
done_testing;
