package Exec::Random;

# Cryptographically-unpredictable hex from /dev/urandom. Perl's rand() is not
# suitable for nonces/reqids that guard against replay, so the dispatcher and
# agent read /dev/urandom directly - this was duplicated in both.

use strict;
use warnings;
use Carp     qw(croak);
use Exporter qw(import);

our @EXPORT_OK = qw(hex_bytes);

# $n random bytes as lowercase hex. Croaks if /dev/urandom cannot be opened OR
# returns a short read - fail closed rather than hand back a shorter, weaker
# token. There is deliberately no rand() fallback: these bytes guard reqids and
# nonces against guessing/replay, and Perl's rand() is not cryptographic.
sub hex_bytes {
    my ($n) = @_;
    open my $fh, '<:raw', '/dev/urandom'
        or croak "Cannot open /dev/urandom: $!";
    my $got = read $fh, my $buf, $n;
    close $fh;
    croak "Short read from /dev/urandom: wanted $n bytes, got "
        . (defined $got ? $got : 'undef')
        unless defined $got && $got == $n;
    return unpack 'H*', $buf;
}

1;
