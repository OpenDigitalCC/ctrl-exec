package Exec::CertInfo;

# Shared cert inspection. The "openssl x509 -noout -enddate -> notAfter" parse was
# reimplemented in four modules with subtly different quoting (one interpolated
# the temp path unquoted). Consolidated here so the shell-quoting and parse live
# in one place. This module is also the single home for serial canonicalisation
# (serial_to_hex) - the trust key behind every dispatcher-trusted/serial-revoked
# decision. serial_to_hex is intentionally NOT in @EXPORT_OK: every caller uses
# the fully-qualified name, matching the project's no-default-exports convention.

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

# Return the cert's serial as canonical lowercase hex (via serial_to_hex), or
# undef if the file is unreadable or carries no serial. The single reader the
# dispatcher's approve and rotate paths share - the twin of expiry_from_path,
# so the openssl shell-quoting and the serial-regex live in one place. A drift
# between two copies here causes a permanent "serial mismatch" rejection.
sub serial_from_path {
    my ($path) = @_;
    my $out = `openssl x509 -noout -serial -in \Q$path\E 2>/dev/null`;
    return unless defined $out && $out =~ /serial=([0-9A-Fa-f]+)/;
    return serial_to_hex($1);
}

# Parse an openssl notAfter string ("Mon DD HH:MM:SS YYYY GMT", as produced by
# expiry_from_path) to a Unix epoch (UTC), or undef if it cannot be parsed. The
# single notAfter->epoch parser: the renewal-due check (Engine) and the
# days-remaining check (Rotation) previously parsed this string two different
# ways (Time::Piece strptime vs a manual timegm) that could disagree on the same
# cert. timegm because the date is UTC; an explicit month map because strptime
# '%b' is locale-sensitive.
sub expiry_epoch {
    my ($date_str) = @_;
    return unless defined $date_str;
    my %months = qw(Jan 0 Feb 1 Mar 2 Apr 3 May 4 Jun 5
                    Jul 6 Aug 7 Sep 8 Oct 9 Nov 10 Dec 11);
    return unless $date_str =~ /(\w+)\s+(\d+)\s+(\d+):(\d+):(\d+)\s+(\d{4})\s+GMT/;
    my ($mon, $day, $h, $m, $s, $yr) = ($1, $2, $3, $4, $5, $6);
    return unless exists $months{$mon};
    require Time::Local;
    return Time::Local::timegm($s, $m, $h, $day, $months{$mon}, $yr - 1900);
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

    # Strip colon separators (e.g. DE:AD:BE:EF from IO::Socket::SSL or a serial
    # pasted from `openssl x509 -text`). A colon form is always hex bytes, so it
    # must use the SAME leading-zero strip as the plain-hex branch below - not a
    # byte-pair strip, which diverges for any serial whose top byte is 0x01-0x0f
    # (e.g. "00:0a" -> "0a" but the live plain-hex "0a" -> "a", a silent
    # trust-key mismatch). One strip, one canonical form.
    if ($serial =~ /:/) {
        $serial =~ s/://g;
        $serial = lc $serial;
        $serial =~ s/\A0+(?=[0-9a-f])//;
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
    # as a serial mismatch. (The colon-separated branch above strips leading
    # zeros the same way, so both branches yield one canonical form.)
    if ($serial =~ /\A[0-9a-f]+\z/) {
        $serial =~ s/\A0+(?=[0-9a-f])//;
        return $serial;
    }

    # Contains non-hex characters - treat as large decimal via bignum.
    require Math::BigInt;
    return lc( Math::BigInt->new($serial)->as_hex =~ s/^0x//r );
}

1;
