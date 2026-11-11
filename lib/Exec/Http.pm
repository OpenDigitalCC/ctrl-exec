package Exec::Http;

# One place for the HTTP/1.0 JSON response framing shared by the three small
# servers (the dispatcher API, the agent, the pairing listener). They previously
# each hand-rolled an identical writer with its own status-phrase table, which
# had drifted (e.g. 413 was "Payload Too Large" in one and "Content Too Large" in
# another, and 500 was missing from one). Clients key on the numeric status, so
# the drift was cosmetic - but a single table removes the maintenance hazard.

use strict;
use warnings;
use feature      qw(signatures);
no warnings      qw(experimental::signatures);
use JSON qw(encode_json);
use Socket qw(SOL_SOCKET SO_RCVTIMEO);
use Errno  qw(EINTR);

my %PHRASE = (
    200 => 'OK',
    202 => 'Accepted',
    400 => 'Bad Request',
    403 => 'Forbidden',
    404 => 'Not Found',
    409 => 'Conflict',
    413 => 'Content Too Large',
    429 => 'Too Many Requests',
    431 => 'Request Header Fields Too Large',
    500 => 'Internal Server Error',
    503 => 'Service Unavailable',
);

# Validate the `args` of a /run request. Returns undef when args is an array
# whose every element is a defined plain scalar (string or number), else an error
# message. References (including JSON booleans) and undef are refused: they would
# stringify to "HASH(0x...)" / warn at the exec boundary. The agent applies this
# as the real boundary; the dispatcher API applies it so the caller fails early.
sub args_problem ($args) {
    return 'args must be an array' unless ref $args eq 'ARRAY';
    for my $a (@$args) {
        return 'args must be an array of strings or numbers'
            if !defined $a || ref $a;
    }
    return;
}

# Read exactly $len body bytes from $conn. Returns the body, or undef when the
# peer closed or the connection failed first: a short body is never returned,
# so no caller can act on a truncated request.
#
# One `read` is not enough on a TLS connection: IO::Socket::SSL's tied read
# returns at most one TLS record (16 KiB), so a body larger than that arrived
# cut short (R-034). A plain or unix socket's buffered read fills the request
# itself, but the same loop serves all of them.
#
# The wait on each read is bounded by $idle seconds (SO_RCVTIMEO on the
# socket, so it needs no alarm and does not disturb one a caller holds): a peer
# that stops sending mid-body ends the read instead of holding the handler. The
# bound is per read, not for the whole body.
sub read_body ($conn, $len, $idle = 30) {
    return '' unless $len > 0;
    # Restore the socket's own receive timeout afterwards: a caller (the pairing
    # client waits minutes for approval on the same socket) keeps its own.
    my $prev = getsockopt($conn, SOL_SOCKET, SO_RCVTIMEO) // pack('l! l!', 0, 0);
    setsockopt($conn, SOL_SOCKET, SO_RCVTIMEO, pack('l! l!', $idle, 0));
    my $body = '';
    while (length($body) < $len) {
        my $n = read($conn, $body, $len - length($body), length($body));
        if (!defined $n) { next if $! == EINTR; last }
        last if $n == 0;
    }
    setsockopt($conn, SOL_SOCKET, SO_RCVTIMEO, $prev);
    return length($body) == $len ? $body : undef;
}

# Write a raw (already-serialised) JSON body as an HTTP/1.0 response.
sub send_raw ($conn, $code, $body) {
    my $phrase = $PHRASE{$code} // 'Unknown';
    print $conn
        "HTTP/1.0 $code $phrase\r\n",
        "Content-Type: application/json\r\n",
        "Content-Length: ", length($body), "\r\n",
        "\r\n",
        $body;
}

# Encode $data as JSON and write it as an HTTP/1.0 response.
sub send_json ($conn, $code, $data) {
    send_raw($conn, $code, encode_json($data));
}

1;
