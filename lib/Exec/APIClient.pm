package Exec::APIClient;

# T-080: a small HTTP/1.1 client for the dispatcher API's unix socket
# (api_socket), so `ced run|ping` can reach the API for a user who cannot read
# dispatcher.key. Core Perl only (IO::Socket::UNIX, JSON). One request per
# connection: the API answers HTTP/1.0 and closes.
#
#   my $r = Exec::APIClient::request($path, 'POST', '/run', { hosts => [...] });
#   # { status => 200, data => {...decoded JSON...} }  or  { error => "..." }
#
# A failure to connect (service down, stale socket file, no permission) is
# returned as { error }, never thrown, so the caller can fall back to its own
# message. A reply that is not HTTP carrying JSON is also an { error }.

use strict;
use warnings;
use feature      qw(signatures);
no warnings      qw(experimental::signatures);
use IO::Socket::UNIX qw();
use JSON         qw(encode_json decode_json);

# Why this user cannot use the socket at $path, or undef when it looks usable
# (a socket file this user may write to, which is what connect(2) needs).
sub unusable_reason ($path) {
    return 'it is not an absolute path' unless defined $path && $path =~ m{^/};
    return "$path does not exist (is ctrl-exec-api running?)" unless -e $path;
    return "$path is not a socket" unless -S _;
    return "this user may not connect to $path (it is mode 0660 in api_socket_group)"
        unless -w $path;
    return;
}

sub request ($path, $method, $url, $data = undef) {
    my $sock = IO::Socket::UNIX->new(Peer => $path, Type => IO::Socket::UNIX::SOCK_STREAM())
        or return { error => "cannot connect to $path: $!" };

    my $body = defined $data ? encode_json($data) : '';
    print $sock "$method $url HTTP/1.1\r\n",
                "Host: localhost\r\n",
                "Connection: close\r\n",
                "Accept: application/json\r\n",
                (defined $data ? ("Content-Type: application/json\r\n") : ()),
                "Content-Length: ", length($body), "\r\n",
                "\r\n",
                $body
        or return { error => "cannot send to $path: $!" };
    $sock->shutdown(1);    # the request is complete; the reply ends at EOF

    my $raw = do { local $/; <$sock> };
    close $sock;
    return { error => "no reply from $path" } unless defined $raw && length $raw;

    my ($head, $payload) = split /\r?\n\r?\n/, $raw, 2;
    return { error => "the reply from $path is not HTTP" }
        unless $head =~ m{^HTTP/\d\.\d\s+(\d{3})};
    my $status = $1;
    my $json = eval { decode_json($payload // '') };
    return { status => $status, error => "the reply from $path is not JSON" }
        unless ref $json eq 'HASH';
    return { status => $status, data => $json };
}

1;
