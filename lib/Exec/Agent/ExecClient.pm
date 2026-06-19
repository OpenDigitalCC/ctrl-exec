package Exec::Agent::ExecClient;

# Front-end -> executor client. The unprivileged agent serve loop uses this to
# hand an authorised run to the privileged executor (ctrl-exec-exec) over its
# unix socket, and to read back the captured result. The executor re-derives the
# script path and profile from its own root-owned config and applies the profile
# before exec; this side only frames the request and parses the response.
#
# Wire framing (big-endian, length-prefixed throughout; see src/ctrl-exec-exec.c):
#   request:  [u32 total][field reqid][field disp][field script][field stdin]
#             [u32 argc] argc*[field arg]      where field = [u32 len][bytes]
#   response: [i32 exit][field stdout][field stderr]

use strict;
use warnings;
use Carp qw(croak);
use IO::Socket::UNIX qw();

sub _field { pack('N', length $_[0]) . $_[0] }

sub _read_all {
    my ($sock, $n) = @_;
    my $buf = '';
    while (length $buf < $n) {
        my $r = $sock->sysread(my $chunk, $n - length $buf);
        return undef unless defined $r && $r > 0;   # closed / error
        $buf .= $chunk;
    }
    return $buf;
}

sub _read_field {
    my ($sock) = @_;
    my $lh = _read_all($sock, 4) // return undef;
    my $len = unpack 'N', $lh;
    return '' if $len == 0;
    return _read_all($sock, $len);
}

# run(%opts): socket, reqid, dispatcher_id, script, args (arrayref), stdin
# Returns { exit, stdout, stderr } or { exit => -1, error => ... } on a
# transport failure (so the caller can report it like any other run error).
sub run {
    my (%o) = @_;
    my $path = $o{socket} or croak "socket required";
    my $script = defined $o{script} ? $o{script} : croak "script required";
    my @args = @{ $o{args} // [] };
    my $stdin = defined $o{stdin} ? $o{stdin} : '';
    my $reqid = $o{reqid} // '';
    my $disp  = $o{dispatcher_id} // '';

    my $sock = IO::Socket::UNIX->new(Peer => $path, Type => IO::Socket::UNIX::SOCK_STREAM())
        or return { exit => -1, error => "executor unreachable: $!" };
    binmode $sock;

    my $inner = _field($reqid) . _field($disp) . _field($script) . _field($stdin)
              . pack('N', scalar @args) . join('', map { _field($_) } @args);
    my $frame = pack('N', length $inner) . $inner;

    {
        local $SIG{PIPE} = 'IGNORE';
        my $w = $sock->syswrite($frame);
        return { exit => -1, error => "executor write failed: $!" }
            unless defined $w && $w == length $frame;
    }

    my $eh = _read_all($sock, 4)
        // return { exit => -1, error => 'executor closed before responding' };
    my $exit = unpack 'l>', $eh;                  # signed 32-bit big-endian
    my $out  = _read_field($sock);
    my $err  = _read_field($sock);
    return { exit => -1, error => 'truncated executor response' }
        unless defined $out && defined $err;

    return { exit => $exit, stdout => $out, stderr => $err };
}

1;
