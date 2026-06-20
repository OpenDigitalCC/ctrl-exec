package Exec::Http;

# One place for the HTTP/1.0 JSON response framing shared by the three small
# servers (the dispatcher API, the agent, the pairing listener). They previously
# each hand-rolled an identical writer with its own status-phrase table, which
# had drifted (e.g. 413 was "Payload Too Large" in one and "Content Too Large" in
# another, and 500 was missing from one). Clients key on the numeric status, so
# the drift was cosmetic - but a single table removes the maintenance hazard.

use strict;
use warnings;
use JSON qw(encode_json);

my %PHRASE = (
    200 => 'OK',
    202 => 'Accepted',
    400 => 'Bad Request',
    403 => 'Forbidden',
    404 => 'Not Found',
    409 => 'Conflict',
    413 => 'Content Too Large',
    431 => 'Request Header Fields Too Large',
    500 => 'Internal Server Error',
    503 => 'Service Unavailable',
);

# Write a raw (already-serialised) JSON body as an HTTP/1.0 response.
sub send_raw {
    my ($conn, $code, $body) = @_;
    my $phrase = $PHRASE{$code} // 'Unknown';
    print $conn
        "HTTP/1.0 $code $phrase\r\n",
        "Content-Type: application/json\r\n",
        "Content-Length: ", length($body), "\r\n",
        "\r\n",
        $body;
}

# Encode $data as JSON and write it as an HTTP/1.0 response.
sub send_json {
    my ($conn, $code, $data) = @_;
    send_raw($conn, $code, encode_json($data));
}

1;
