#!/usr/bin/perl
# t/ca-random-serials.t
#
# T-023: every certificate the CA issues carries a random serial (the serial is
# the trust identity), in the canonical form serial_to_hex produces, and an
# existing CA directory with a sequential ca.serial still issues and verifies.

use strict;
use warnings;
use feature qw(signatures);
no warnings qw(experimental::signatures);
use Math::BigInt;
use Test::More;
use File::Temp qw(tempdir);
use FindBin    qw($Bin);
use lib "$Bin/../lib";

use Exec::CA    qw();
use Exec::CertInfo qw();
use Exec::Agent::AgentPairing qw();
use Exec::Log   qw();
use Net::SSLeay qw();

Exec::Log::init('test');

plan skip_all => 'openssl not available' unless system('openssl version >/dev/null 2>&1') == 0;

# --- random_serial itself ---
subtest 'random_serial shape' => sub {
    my %seen;
    for (1 .. 200) {
        my $s = Exec::CA::random_serial();
        like $s, qr/\A[0-9a-f]{32}\z/, 'lowercase hex, 32 digits' or last;
        unlike $s, qr/\A0/, 'no leading zero (canonical form)' or last;
        ok hex(substr $s, 0, 2) < 0x80, 'top bit clear (positive INTEGER)' or last;
        is Exec::CertInfo::serial_to_hex($s), $s, 'already canonical' or last;
        $seen{$s}++;
    }
    is scalar(keys %seen), 200, '200 draws all distinct';
};

# --- real issue ---
my $ca = tempdir(CLEANUP => 1);
Exec::CA::generate_ca(ca_dir => $ca, days => 1, bits => 2048, cn => 'T023 CA');

sub cert_serial_hex ($pem_path) {
    open my $fh, '<', $pem_path or die "$pem_path: $!";
    local $/; my $pem = <$fh>;
    my $bio  = Net::SSLeay::BIO_new(Net::SSLeay::BIO_s_mem());
    Net::SSLeay::BIO_write($bio, $pem);
    my $x509 = Net::SSLeay::PEM_read_bio_X509($bio);
    Net::SSLeay::BIO_free($bio);
    # Same extraction as Exec::Agent::Server::peer_serial.
    my $hex = lc Net::SSLeay::P_ASN1_INTEGER_get_hex(Net::SSLeay::X509_get_serialNumber($x509));
    Net::SSLeay::X509_free($x509);
    return $hex;
}

sub make_csr ($dir, $name) {
    system('openssl', 'genrsa', '-out', "$dir/$name.key", 2048) == 0 or die;
    system("openssl req -new -key $dir/$name.key -out $dir/$name.csr -subj /CN=$name 2>/dev/null") == 0 or die;
    open my $fh, '<', "$dir/$name.csr" or die; local $/; return scalar <$fh>;
}

my $w = tempdir(CLEANUP => 1);

subtest 'CA cert, dispatcher cert and signed CSRs carry random serials' => sub {
    Exec::CA::generate_dispatcher_cert(ca_dir => $ca, days => 1, bits => 2048,
        cert => "$w/d.crt", key => "$w/d.key");
    Exec::CA::sign_csr(csr_pem => make_csr($w, 'a1'), ca_dir => $ca, days => 1, out_path => "$w/a1.crt");
    Exec::CA::sign_csr(csr_pem => make_csr($w, 'a2'), ca_dir => $ca, days => 1, out_path => "$w/a2.crt");

    my %s = map { $_ => cert_serial_hex("$w/$_.crt") } qw(d a1 a2);
    $s{ca} = cert_serial_hex("$ca/ca.crt");
    my %uniq = map { $_ => 1 } values %s;
    is scalar(keys %uniq), 4, 'all four serials differ';
    for my $k (sort keys %s) {
        unlike $s{$k}, qr/\A0/, "$k: no leading zero";
        cmp_ok length($s{$k}), '>=', 16, "$k: at least 64 bits (" . length($s{$k}) . " hex digits)";
        cmp_ok length($s{$k}), '<=', 40, "$k: within 20 octets";
        isnt $s{$k}, '1', "$k: not the sequential seed";
    }
    for my $k (qw(d a1 a2)) {
        is length($s{$k}), 32, "$k: 32 hex digits";
        ok hex(substr $s{$k}, 0, 2) < 0x80, "$k: positive";
    }

    # Canonical form round-trips through every comparison path.
    my $sx = $s{a1};
    is Exec::CertInfo::serial_from_path("$w/a1.crt"), $sx, 'serial_from_path agrees with peer_serial-style extraction';
    is Exec::CertInfo::serial_to_hex(uc $sx), $sx, 'upper case canonicalises';
    is Exec::CertInfo::serial_to_hex("0x" . uc $sx), $sx, '0x prefix canonicalises';
    is Exec::CertInfo::serial_to_hex("serial=" . uc $sx), $sx, 'serial= prefix canonicalises';
    (my $colon = $sx) =~ s/(..)(?=.)/$1:/g;
    is Exec::CertInfo::serial_to_hex($colon), $sx, 'colon form canonicalises';
    is Exec::CertInfo::serial_to_hex(Math::BigInt->from_hex($sx)->bstr), $sx, 'decimal form canonicalises';

    # Trusted-dispatcher map and revocation list.
    my $tf = "$w/trusted";
    Exec::Agent::AgentPairing::add_trusted_dispatcher(path => $tf, serial => uc $sx, id => 'automation');
    my $trusted = Exec::Agent::AgentPairing::load_trusted_dispatchers(path => $tf);
    is scalar(Exec::Agent::AgentPairing::dispatcher_trusted($sx, $trusted)), 'automation', 'trusted lookup by peer-style serial';
    is scalar(Exec::Agent::AgentPairing::dispatcher_trusted($s{a2}, $trusted)), undef, 'other serial not trusted';

    my $rf = "$w/revoked";
    open my $fh, '>', $rf or die; print $fh "serial=" . uc($s{a2}) . "\n"; close $fh;
    my $rev = Exec::Agent::AgentPairing::load_revoked_serials(path => $rf);
    ok  Exec::Agent::AgentPairing::serial_revoked($s{a2}, $rev), 'revoked serial matches';
    ok !Exec::Agent::AgentPairing::serial_revoked($sx, $rev),    'other serial not revoked';

    # Chain verifies.
    is system("openssl verify -CAfile $ca/ca.crt $w/a1.crt >/dev/null 2>&1"), 0, 'signed cert verifies against CA';
};

subtest 'existing CA dir with a sequential ca.serial still issues and verifies' => sub {
    my $old = tempdir(CLEANUP => 1);
    for my $f (qw(ca.key ca.crt)) { system('cp', "$ca/$f", "$old/$f") == 0 or die }
    open my $fh, '>', "$old/ca.serial" or die; print $fh "0A\n"; close $fh;   # legacy counter
    my $pem = Exec::CA::sign_csr(csr_pem => make_csr($w, 'legacy'), ca_dir => $old, days => 1,
                                 out_path => "$w/legacy.crt");
    like $pem, qr/BEGIN CERTIFICATE/, 'issued';
    my $s = cert_serial_hex("$w/legacy.crt");
    is length($s), 32, 'new cert is random, not the legacy counter';
    is system("openssl verify -CAfile $old/ca.crt $w/legacy.crt >/dev/null 2>&1"), 0, 'verifies';
    open $fh, '<', "$old/ca.serial" or die; local $/; my $c = <$fh>;
    is $c, "0A\n", 'ca.serial left untouched';

    # And with ca.serial absent entirely (signing must not depend on it).
    unlink "$old/ca.serial";
    eval { Exec::CA::sign_csr(csr_pem => make_csr($w, 'nofile'), ca_dir => $old, days => 1) };
    is $@, '', 'issues without a ca.serial file';
};

done_testing;
