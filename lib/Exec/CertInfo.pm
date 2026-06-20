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

1;
