use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/../lib";

use Exec::Http qw();

# Exact wire framing of the shared HTTP/1.0 JSON writer the three servers use.

sub capture {
    my ($code) = @_;
    open my $fh, '>', \my $buf or die "open scalar fh: $!";
    $code->($fh);
    close $fh;
    return $buf;
}

is
    capture(sub { Exec::Http::send_raw($_[0], 413, 'BODY') }),
    "HTTP/1.0 413 Content Too Large\r\n"
        . "Content-Type: application/json\r\n"
        . "Content-Length: 4\r\n\r\nBODY",
    'send_raw frames an HTTP/1.0 response exactly';

is
    capture(sub { Exec::Http::send_json($_[0], 404, { error => 'x' }) }),
    qq{HTTP/1.0 404 Not Found\r\n}
        . "Content-Type: application/json\r\n"
        . "Content-Length: 13\r\n\r\n"
        . '{"error":"x"}',
    'send_json encodes and frames';

like capture(sub { Exec::Http::send_raw($_[0], 200, '{}') }),
    qr{^HTTP/1\.0 200 OK\r\n}, '200 OK';
like capture(sub { Exec::Http::send_raw($_[0], 500, '{}') }),
    qr{^HTTP/1\.0 500 Internal Server Error\r\n}, '500 phrase present';
like capture(sub { Exec::Http::send_raw($_[0], 499, '{}') }),
    qr{^HTTP/1\.0 499 Unknown\r\n}, 'unknown code falls back to a generic phrase';

done_testing;
