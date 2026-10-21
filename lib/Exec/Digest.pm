package Exec::Digest;

# Shared SHA-256 helpers via openssl (no Digest::SHA dependency, which is absent
# on minimal Perl installs like OpenWrt). The pairing code in particular was
# duplicated byte-for-byte in the agent and the dispatcher and MUST stay
# identical - both sides compute it independently and the operator compares the
# two displays - so it lives in exactly one place here.

use strict;
use warnings;
use feature      qw(signatures);
no warnings      qw(experimental::signatures);
use File::Temp qw(tempfile);
use Exporter   qw(import);

our @EXPORT_OK = qw(pairing_code pairing_code_v2 pairing_code_for
                    canonical_csr canonical_cert sha256_hex);

# Pairing code versions. The agent states the version it computed in its
# pairing request (code_version); a request without one comes from an agent
# older than 0.13 and gets v1.
#
#   v1  sha256(csr_pem)                      - transcription check only: a relay
#                                              that forwards the CSR unchanged
#                                              shows the operator the same code.
#   v2  sha256(csr_pem || dispatcher_fpr)    - dispatcher_fpr is the 32-byte
#                                              SHA-256 of the DER of the
#                                              certificate the agent saw on the
#                                              pairing connection. A relay that
#                                              terminates TLS presents its own
#                                              certificate, so the agent's code
#                                              differs from the dispatcher's.
#
# Keep-certificate form (T-062): an agent that already holds a certificate and
# pairs with another dispatcher sends that certificate and its issuing CA with
# the CSR. The code is then computed, in either version, over the CSR followed
# by the certificate and the CA PEM exactly as sent (pairing_input), so a relay
# cannot swap the certificate or CA while passing the CSR through unchanged.
#
# Both truncate the same way: first 4 bytes as a uint32 modulo 1,000,000, six
# digits, so operators see the same format whichever version is shown.

# 6-digit v1 pairing confirmation code from a CSR PEM. Dies if openssl fails.
sub pairing_code ($csr_pem) {
    return _code_of($csr_pem);
}

# 6-digit v2 pairing confirmation code from a CSR PEM and the dispatcher
# certificate fingerprint (64 hex characters, either case). Dies on a malformed
# fingerprint or if openssl fails.
sub pairing_code_v2 ($csr_pem, $fpr_hex) {
    die "pairing code v2: dispatcher fingerprint must be 64 hex characters\n"
        unless defined $fpr_hex && $fpr_hex =~ /\A[0-9A-Fa-f]{64}\z/;
    return _code_of($csr_pem . pack('H*', $fpr_hex));
}

# The code for a given version: 1 or 2. Dies on any other version, or on v2
# without a fingerprint.
sub pairing_code_for ($version, $csr_pem, $fpr_hex = undef) {
    return pairing_code($csr_pem) if $version eq '1';
    if ($version eq '2') {
        die "pairing code v2 needs the dispatcher fingerprint\n"
            unless defined $fpr_hex;
        return pairing_code_v2($csr_pem, $fpr_hex);
    }
    die "unsupported pairing code version '$version'\n";
}

# The bytes the pairing code is computed over: the CSR, then (keep-certificate
# form) the agent certificate and its CA as sent.
sub pairing_input ($csr_pem, $agent_cert = undef, $agent_ca = undef) {
    return $csr_pem unless defined $agent_cert;
    return $csr_pem . $agent_cert . ($agent_ca // '');
}

# The CSR as openssl writes it (re-encoded PEM), or undef if openssl cannot
# parse it. openssl ignores text around the PEM block, so the dispatcher
# requires a received CSR to equal this form: otherwise a relay could append
# text to the agent's CSR, which changes the hashed bytes but not the request
# that is signed, and try variants until the codes on both sides matched.
sub canonical_csr ($csr_pem) {
    my ($fh, $path) = tempfile(UNLINK => 1);
    print $fh $csr_pem;
    close $fh;
    my $out = `openssl req -in \Q$path\E -outform PEM 2>/dev/null`;
    return unless $? == 0 && defined $out
        && $out =~ /\A-----BEGIN CERTIFICATE REQUEST-----\n/;
    return $out;
}

# One certificate as openssl writes it (re-encoded PEM), or undef if openssl
# cannot parse it. The keep-certificate pairing request (T-062) carries the
# agent's certificate and its issuing CA; both are hashed into the pairing code,
# so, as for the CSR, the dispatcher requires each to be exactly this form.
sub canonical_cert ($pem) {
    my ($fh, $path) = tempfile(UNLINK => 1);
    print $fh $pem // '';
    close $fh;
    my $out = `openssl x509 -in \Q$path\E -outform PEM 2>/dev/null`;
    return unless $? == 0 && defined $out
        && $out =~ /\A-----BEGIN CERTIFICATE-----\n/;
    return $out;
}

# sha256 of the bytes, first 4 bytes as a uint32 modulo 1,000,000.
sub _code_of ($bytes) {
    my ($fh, $path) = tempfile(UNLINK => 1);
    binmode $fh;
    print $fh $bytes;
    close $fh;
    my $digest = `openssl dgst -sha256 -binary \Q$path\E 2>/dev/null`;
    die "openssl dgst failed\n" unless length($digest) == 32;
    return sprintf '%06d', unpack('N', substr($digest, 0, 4)) % 1_000_000;
}

# Hex SHA-256 of a string, or undef on failure.
sub sha256_hex ($data) {
    my ($fh, $path) = tempfile(UNLINK => 1);
    binmode $fh;
    print {$fh} $data;
    close $fh;
    my $out = `openssl dgst -sha256 \Q$path\E 2>/dev/null`;
    return $out =~ /([0-9a-f]{64})/ ? $1 : undef;
}

1;
