package Exec::Agent::ExecClient;

# Front-end -> executor client. The unprivileged agent serve loop uses this to
# hand an authorised run to the privileged executor (ctrl-exec-executor) over its
# unix socket, and to read back the captured result. The executor re-derives the
# script path and profile from its own root-owned config and applies the profile
# before exec; this side only frames the request and parses the response.
#
# Wire framing (big-endian, length-prefixed throughout; see src/ctrl-exec-executor.c):
#   request v1: [u32 total][field reqid][field disp][field script][field stdin]
#               [u32 argc] argc*[field arg]      where field = [u32 len][bytes]
#   request v2: [u32 total][u32 FRAME_V2_MAGIC][field reqid][field disp]
#               [field script][field stdin][field context]
#               [u32 argc] argc*[field arg]
#               [u32 nfields] nfields*([field name][field value])
#   response:   [i32 exit][field stdout][field stderr]
#
# v2 carries confidential run input (T-013): stdin is the context JSON for an
# input=context script (with 'input' when there is input), context is the JSON
# for CTRL_EXEC_CONTEXT (no input, no token), and the fields are the input as
# UTF-8 bytes. The executor picks which to deliver from its own scripts.conf.
# v1 is sent when there is nothing new to say (no input, and the script is
# input=context here), so such runs work with an executor of either age. An
# executor that predates v2 fails the magic as a field length and replies
# "executor: malformed request" without running anything; run() reports that
# as an executor without input support.

use strict;
use warnings;
use feature      qw(signatures);
no warnings      qw(experimental::signatures);
use Carp qw(croak);
use IO::Socket::UNIX qw();
use Errno qw(ENOENT ECONNREFUSED EACCES EPERM);

# The message for "cannot reach the executor". Names the executor, the socket and
# the cause, and says how to start it - so an operator reading a failed run does
# not have to guess that "connection refused" means the executor service is down.
sub unavailable_message ($path, $errno) {
    my $why = $errno == ENOENT       ? 'the socket does not exist'
            : $errno == ECONNREFUSED ? 'nothing is listening on the socket'
            : $errno == EACCES || $errno == EPERM
                                     ? 'permission denied on the socket'
            :                          do { local $! = $errno; "$!" };
    return "ctrl-exec-executor is not available ($why: $path). This agent has "
         . "executor_socket set, so every run goes through the executor and none "
         . "can proceed without it. Start it: systemctl start "
         . "ctrl-exec-executor.service (on a tarball install without gcc the "
         . "executor was never built: install gcc and libcap-dev, re-run "
         . "install.sh --agent). Or comment out executor_socket in agent.conf to "
         . "run without per-script profiles.";
}

# probe($path): undef when the executor accepts a connection, otherwise the
# unavailable_message. Used by self-check; opens and closes a connection only.
sub probe ($path) {
    my $sock = IO::Socket::UNIX->new(Peer => $path, Type => IO::Socket::UNIX::SOCK_STREAM());
    return unavailable_message($path, $! + 0) unless $sock;
    close $sock;
    return undef;
}

sub _field ($s) { pack('N', length $s) . $s }

use constant {
    FRAME_V2_MAGIC => 0xCE0E0002,
    MAX_FRAME      => 16 * 1024 * 1024,    # the executor's request cap
};

# The old executor's reply to a frame it cannot parse.
my $OLD_EXECUTOR_REPLY = "executor: malformed request\n";

sub old_executor_message () {
    return "ctrl-exec-executor does not support run input: it is older than this "
         . "agent. Restart ctrl-exec-executor.service so the upgraded executor "
         . "runs (input, and scripts declared input=raw, raw:<name> or fields, "
         . "need it).";
}

sub _read_all ($sock, $n) {
    my $buf = '';
    while (length $buf < $n) {
        my $r = $sock->sysread(my $chunk, $n - length $buf);
        return undef unless defined $r && $r > 0;   # closed / error
        $buf .= $chunk;
    }
    return $buf;
}

sub _read_field ($sock) {
    my $lh = _read_all($sock, 4) // return undef;
    my $len = unpack 'N', $lh;
    return '' if $len == 0;
    return _read_all($sock, $len);
}

# run(%opts): socket, reqid, dispatcher_id, script, args (arrayref), stdin,
# and for a v2 frame (T-013) context and/or input:
#   context - the JSON for CTRL_EXEC_CONTEXT (bytes; no input, no token)
#   input   - hashref of named string fields (character strings)
# A v2 frame is sent when either is given. Returns { exit, stdout, stderr } or
# { exit => -1, error => ... } on a transport failure or a refusal before the
# executor ran anything (so the caller can report it like any other run error).
sub run (%o) {
    my $path = $o{socket} or croak "socket required";
    my $script = defined $o{script} ? $o{script} : croak "script required";
    my @args = @{ $o{args} // [] };
    my $stdin = defined $o{stdin} ? $o{stdin} : '';
    my $reqid = $o{reqid} // '';
    my $disp  = $o{dispatcher_id} // '';
    my $v2    = defined $o{context} || defined $o{input};

    my $inner;
    if ($v2) {
        my $input = $o{input} // {};
        my $fields = '';
        for my $name (sort keys %$input) {
            my $bytes = $input->{$name};
            utf8::encode($bytes);
            $fields .= _field($name) . _field($bytes);
        }
        $inner = pack('N', FRAME_V2_MAGIC)
               . _field($reqid) . _field($disp) . _field($script) . _field($stdin)
               . _field($o{context} // '')
               . pack('N', scalar @args) . join('', map { _field($_) } @args)
               . pack('N', scalar keys %$input) . $fields;
    }
    else {
        $inner = _field($reqid) . _field($disp) . _field($script) . _field($stdin)
               . pack('N', scalar @args) . join('', map { _field($_) } @args);
    }
    # The executor drops a larger request without a reply; say why here.
    return { exit => -1, error => 'request too large for the executor ('
                                . length($inner) . ' bytes; the limit is ' . MAX_FRAME . ')' }
        if length $inner > MAX_FRAME;

    my $sock = IO::Socket::UNIX->new(Peer => $path, Type => IO::Socket::UNIX::SOCK_STREAM())
        or return { exit => -1, error => unavailable_message($path, $! + 0),
                    executor_unavailable => 1 };
    binmode $sock;

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

    return { exit => -1, error => old_executor_message(), executor_no_input => 1 }
        if $v2 && $exit == -1 && $out eq '' && $err eq $OLD_EXECUTOR_REPLY;

    return { exit => $exit, stdout => $out, stderr => $err };
}

1;
