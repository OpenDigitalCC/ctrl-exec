package Exec::Digest;

# Shared SHA-256 helpers via openssl (no Digest::SHA dependency, which is absent
# on minimal Perl installs like OpenWrt). The pairing code in particular was
# duplicated byte-for-byte in the agent and the dispatcher and MUST stay
# identical - both sides compute it independently and the operator compares the
# two displays - so it lives in exactly one place here.

use strict;
use warnings;
use File::Temp qw(tempfile);
use Exporter   qw(import);

our @EXPORT_OK = qw(pairing_code sha256_hex);

# 6-digit pairing confirmation code from a CSR PEM: sha256 of the CSR, first 4
# bytes as a uint32 modulo 1,000,000. Dies if openssl fails.
sub pairing_code {
    my ($csr_pem) = @_;
    my ($fh, $path) = tempfile(UNLINK => 1);
    print $fh $csr_pem;
    close $fh;
    my $digest = `openssl dgst -sha256 -binary \Q$path\E 2>/dev/null`;
    die "openssl dgst failed\n" unless length($digest) == 32;
    return sprintf '%06d', unpack('N', substr($digest, 0, 4)) % 1_000_000;
}

# Hex SHA-256 of a string, or undef on failure.
sub sha256_hex {
    my ($data) = @_;
    my ($fh, $path) = tempfile(UNLINK => 1);
    binmode $fh;
    print {$fh} $data;
    close $fh;
    my $out = `openssl dgst -sha256 \Q$path\E 2>/dev/null`;
    return $out =~ /([0-9a-f]{64})/ ? $1 : undef;
}

1;
