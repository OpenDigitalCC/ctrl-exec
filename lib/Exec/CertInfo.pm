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
use feature      qw(signatures);
no warnings      qw(experimental::signatures);
use File::Temp qw(tempfile);
use Exporter   qw(import);

our @EXPORT_OK = qw(expiry_from_path expiry_from_pem);

# Return the cert's notAfter date string (openssl form, e.g. "Jun  7 16:28:00
# 2028 GMT"), or undef if the file is unreadable / not a cert.
sub expiry_from_path ($path) {
    my $out = `openssl x509 -noout -enddate -in \Q$path\E 2>/dev/null`;
    return unless defined $out && $out =~ /notAfter=(.+)/;
    (my $date = $1) =~ s/\s+\z//;
    return $date;
}

# As expiry_from_path, but for a cert held in a PEM string (written to a private
# temp file first).
sub expiry_from_pem ($pem) {
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
sub serial_from_path ($path) {
    my $out = `openssl x509 -noout -serial -in \Q$path\E 2>/dev/null`;
    return unless defined $out && $out =~ /serial=([0-9A-Fa-f]+)/;
    return serial_to_hex($1);
}

# Return the SHA-256 fingerprint of the cert (the digest of its DER encoding) as
# 64 lowercase hex characters, or undef if the file is unreadable or not a cert.
# For a file holding a chain this is the first cert, which is the one a TLS
# server loaded from it presents. The dispatcher binds the v2 pairing code to
# this value; the agent computes the same digest from the certificate it saw on
# the pairing connection (Exec::Agent::AgentPairing::submit_pairing_request).
sub fingerprint_from_path ($path) {
    my $out = `openssl x509 -noout -fingerprint -sha256 -in \Q$path\E 2>/dev/null`;
    return unless defined $out && $out =~ /=\s*((?:[0-9A-Fa-f]{2}:){31}[0-9A-Fa-f]{2})\s*$/m;
    (my $hex = lc $1) =~ s/://g;
    return $hex;
}

# As fingerprint_from_path, for a certificate held in a PEM string.
sub fingerprint_from_pem ($pem) {
    my $path = _pem_tempfile($pem);
    return fingerprint_from_path($path);
}

# The subject of a certificate held in a PEM string, in RFC 2253 form
# ("CN=ctrl-exec CA d1 1a2b3c4d"), or undef.
sub subject_from_pem ($pem) {
    my $path = _pem_tempfile($pem);
    my $out = `openssl x509 -noout -subject -nameopt RFC2253 -in \Q$path\E 2>/dev/null`;
    return unless defined $out && $out =~ /^subject=\s*(.*?)\s*$/m;
    return $1;
}

# The public key (PEM) of a certificate ('x509') or a certificate request
# ('req') held in a PEM string, or undef. Two values are compared to tell
# whether a certificate and a CSR carry the same key.
sub public_key_from_pem ($pem, $kind = 'x509') {
    my $path = _pem_tempfile($pem);
    my $cmd  = $kind eq 'req' ? 'req' : 'x509';
    my $out = `openssl $cmd -noout -pubkey -in \Q$path\E 2>/dev/null`;
    return unless $? == 0 && defined $out && $out =~ /-----BEGIN PUBLIC KEY-----/;
    return $out;
}

# Whether the certificate $leaf_pem was issued by the CA certificate $ca_pem,
# with that CA as the only trust anchor (nothing from a system store): full
# X.509 verification - signature, validity dates, the CA's constraints.
# Returns undef when it verifies, or the reason it does not.
sub verify_issued_by ($leaf_pem, $ca_pem) {
    require IO::Socket::SSL;   # loads and initialises Net::SSLeay
    my ($leaf, $ca) = map { _x509($_) } $leaf_pem, $ca_pem;
    unless ($leaf && $ca) {
        Net::SSLeay::X509_free($_) for grep { $_ } $leaf, $ca;
        return 'not a readable certificate';
    }
    my $store = Net::SSLeay::X509_STORE_new();
    my $ctx   = Net::SSLeay::X509_STORE_CTX_new();
    my ($ok, $err);
    Net::SSLeay::X509_STORE_add_cert($store, $ca);
    Net::SSLeay::X509_STORE_set_flags($store, Net::SSLeay::X509_V_FLAG_PARTIAL_CHAIN());
    if (Net::SSLeay::X509_STORE_CTX_init($ctx, $store, $leaf)) {
        $ok  = Net::SSLeay::X509_verify_cert($ctx) == 1;
        $err = Net::SSLeay::X509_verify_cert_error_string(
            Net::SSLeay::X509_STORE_CTX_get_error($ctx));
    }
    Net::SSLeay::X509_STORE_CTX_free($ctx);
    Net::SSLeay::X509_STORE_free($store);
    Net::SSLeay::X509_free($_) for $leaf, $ca;
    Net::SSLeay::ERR_clear_error();
    return if $ok;
    return $err // 'verification could not run';
}

sub _x509 ($pem) {
    my $bio = Net::SSLeay::BIO_new(Net::SSLeay::BIO_s_mem()) or return;
    Net::SSLeay::BIO_write($bio, $pem // '');
    my $x509 = Net::SSLeay::PEM_read_bio_X509($bio);
    Net::SSLeay::BIO_free($bio);
    return $x509 || undef;
}

# A private temp file holding $pem (removed at exit), for the openssl CLI.
sub _pem_tempfile ($pem) {
    my ($fh, $path) = tempfile(SUFFIX => '.pem', UNLINK => 1);
    print $fh $pem // '';
    close $fh;
    return $path;
}

# Parse a SHA-256 certificate fingerprint as an operator types or pastes it:
# "SHA256:" then 64 hex digits, with or without colons between the bytes, in
# either case. The prefix may be left off, so the colon form openssl prints
# (`openssl x509 -fingerprint -sha256`) is accepted as it stands once the
# "sha256 Fingerprint=" label is dropped. Returns 64 lowercase hex characters,
# or undef for anything else (a SHA-1 length, a stray character, an empty value).
sub parse_sha256_fingerprint ($str) {
    return unless defined $str;
    (my $s = $str) =~ s/^\s+|\s+$//g;
    $s =~ s/\ASHA-?256://i;
    return unless $s =~ /\A(?:[0-9A-Fa-f]{64}|(?:[0-9A-Fa-f]{2}:){31}[0-9A-Fa-f]{2})\z/;
    $s =~ s/://g;
    return lc $s;
}

# The display form of a SHA-256 fingerprint (64 hex characters): "SHA256:"
# then lowercase hex without colons, the form the pairing-mode banner and
# 'ctrl-exec-dispatcher ca-fingerprint' print and request-pairing accepts.
sub format_sha256_fingerprint ($hex) {
    return 'SHA256:' . lc $hex;
}

# Parse an openssl notAfter string ("Mon DD HH:MM:SS YYYY GMT", as produced by
# expiry_from_path) to a Unix epoch (UTC), or undef if it cannot be parsed. The
# single notAfter->epoch parser: the renewal-due check (Engine) and the
# days-remaining check (Rotation) previously parsed this string two different
# ways (Time::Piece strptime vs a manual timegm) that could disagree on the same
# cert. timegm because the date is UTC; an explicit month map because strptime
# '%b' is locale-sensitive.
sub expiry_epoch ($date_str = undef) {
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
sub serial_to_hex ($serial) {
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
