package Exec::Input;

use strict;
use warnings;
use feature      qw(signatures);
no warnings      qw(experimental::signatures);

# Confidential run input (T-013): the shape both the API and the agent accept.
# One validator so the dispatcher and the agent refuse exactly the same
# requests. Errors name fields, never values.

use constant {
    MAX_FIELDS        => 32,
    DEFAULT_MAX_BYTES => 1048576,
};

my $NAME_RE = qr/\A[A-Za-z0-9_.-]{1,64}\z/;

# Request bodies other than input stay well under this; a request that may carry
# input is allowed this much plus the input limit. JSON escaping grows a value
# (a PEM's newlines slightly; control characters up to six-fold), so this
# headroom suits text such as keys and certificates.
use constant BODY_OVERHEAD => 1048576;

# The configured input limit: max_input_bytes when a positive integer, else the
# default.
sub max_bytes ($config) {
    my $v = $config->{max_input_bytes};
    return (defined $v && $v =~ /\A[1-9][0-9]*\z/) ? $v : DEFAULT_MAX_BYTES;
}

# The largest request body to read (API and agent alike).
sub max_body ($config) {
    return BODY_OVERHEAD + max_bytes($config);
}

# Validate a decoded 'input' value from a request body.
#
#   $input     - the value of the 'input' key (undef when absent)
#   $max_bytes - total value bytes allowed (default DEFAULT_MAX_BYTES)
#
# Returns:
#   { ok => 1, names => [sorted names], bytes => $total }   (names [] when absent)
#   { ok => 0, error => $str }
sub validate ($input, $max_bytes = undef) {
    $max_bytes //= DEFAULT_MAX_BYTES;
    return { ok => 1, names => [], bytes => 0 } unless defined $input;
    return { ok => 0, error => 'input must be an object of named string fields' }
        unless ref $input eq 'HASH';

    my @names = sort keys %$input;
    return { ok => 0, error => 'input has more than ' . MAX_FIELDS . ' fields' }
        if @names > MAX_FIELDS;

    my $bytes = 0;
    for my $name (@names) {
        return { ok => 0, error => 'input field name is invalid (allowed: A-Z a-z 0-9 _ . -, 1-64 characters)' }
            unless $name =~ $NAME_RE && $name ne '.' && $name ne '..';
        my $v = $input->{$name};
        return { ok => 0, error => "input field '$name' must be a string" }
            if !defined $v || ref $v;
        # Values are character strings (decoded JSON); count the UTF-8 bytes
        # they travel as.
        my $copy = $v;
        utf8::encode($copy);
        $bytes += length $copy;
    }
    return { ok => 0, error => "input exceeds $max_bytes bytes" }
        if $bytes > $max_bytes;

    return { ok => 1, names => \@names, bytes => $bytes };
}

1;
