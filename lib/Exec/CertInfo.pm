package Exec::CertInfo;

# Shared cert inspection. The "openssl x509 -noout -enddate -> notAfter" parse was
# reimplemented in four modules with subtly different quoting (one interpolated
# the temp path unquoted). Consolidated here so the shell-quoting and parse live
# in one place.

use strict;
use warnings;
use File::Temp qw(tempfile);
use Exporter   qw(import);

our @EXPORT_OK = qw(expiry_from_path expiry_from_pem);

# Return the cert's notAfter date string (openssl form, e.g. "Jun  7 16:28:00
# 2028 GMT"), or undef if the file is unreadable / not a cert.
sub expiry_from_path {
    my ($path) = @_;
    my $out = `openssl x509 -noout -enddate -in \Q$path\E 2>/dev/null`;
    return unless defined $out && $out =~ /notAfter=(.+)/;
    (my $date = $1) =~ s/\s+\z//;
    return $date;
}

# As expiry_from_path, but for a cert held in a PEM string (written to a private
# temp file first).
sub expiry_from_pem {
    my ($pem) = @_;
    my ($fh, $path) = tempfile(SUFFIX => '.crt', UNLINK => 1);
    print $fh $pem;
    close $fh;
    return expiry_from_path($path);
}

# Normalise a serial number to lowercase hex.
# Accepts either a decimal string (from IO::Socket::SSL peer_certificate)
# or a hex string (from openssl x509 -serial output).
# Hex strings are identified by non-decimal characters or a leading 0x.
sub serial_to_hex {
    my ($serial) = @_;
    return '' unless defined $serial && length $serial;
    $serial =~ s/^0x//i;
    $serial =~ s/^serial=//i;

    # Strip colon separators (e.g. DE:AD:BE:EF from IO::Socket::SSL).
    # OpenSSL prepends a 00 byte to positive-integer DER serials; strip it.
    if ($serial =~ /:/) {
        $serial =~ s/://g;
        $serial = lc $serial;
        $serial =~ s/^(?:00)+(?=.{2})//;  # strip leading 00 bytes (keep at least 2 hex chars)
        return $serial;
    }

    $serial = lc $serial;

    # A pure decimal string must be converted. Test explicitly: decimal strings
    # contain only [0-9] and cannot contain [a-f], but digits-only strings also
    # satisfy \A[0-9a-f]+\z so we must check for decimal first.
    if ($serial =~ /\A[0-9]+\z/) {
        # Cert serials can be up to 20 bytes (160 bits), requiring bignum
        # arithmetic. We do not use sprintf '%x' because Perl's native integer
        # coercion silently loses precision for large decimal strings.
        require Math::BigInt;
        return lc( Math::BigInt->new($serial)->as_hex =~ s/^0x//r );
    }

    # If it contains only valid hex characters it is already hex. Strip any
    # insignificant leading zeros first so a value carrying a leading 00 byte -
    # a serial migrated from an older single-serial file, or a hand-edited map
    # entry - canonicalises to the same key the live readers produce. Both
    # `openssl x509 -serial` and Net::SSLeay::P_ASN1_INTEGER_get_hex emit minimal
    # hex with no leading zero, so without this strip '00aabb...' (stored) never
    # matches a live 'aabb...' and every request from that dispatcher is rejected
    # as a serial mismatch. (The colon-separated branch above already strips its
    # leading 00 byte; this keeps the plain-hex branch consistent with it.)
    if ($serial =~ /\A[0-9a-f]+\z/) {
        $serial =~ s/\A0+(?=[0-9a-f])//;
        return $serial;
    }

    # Contains non-hex characters - treat as large decimal via bignum.
    require Math::BigInt;
    return lc( Math::BigInt->new($serial)->as_hex =~ s/^0x//r );
}

1;
