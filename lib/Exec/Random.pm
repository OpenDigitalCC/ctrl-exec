package Exec::Random;

# Cryptographically-unpredictable hex from /dev/urandom. Perl's rand() is not
# suitable for nonces/reqids that guard against replay, so the dispatcher and
# agent read /dev/urandom directly - this was duplicated in both.

use strict;
use warnings;
use Carp     qw(croak);
use Exporter qw(import);

our @EXPORT_OK = qw(hex_bytes);

# $n random bytes as lowercase hex. Croaks if /dev/urandom cannot be read; a
# caller that must not fail (e.g. a best-effort correlation id) should catch it
# or keep its own fallback.
sub hex_bytes {
    my ($n) = @_;
    open my $fh, '<:raw', '/dev/urandom'
        or croak "Cannot open /dev/urandom: $!";
    my $buf;
    read $fh, $buf, $n;
    close $fh;
    return unpack 'H*', $buf;
}

1;
