package Exec::API;

use strict;
use warnings;
use feature      qw(signatures);
no warnings      qw(experimental::signatures);
use JSON       qw(encode_json decode_json);
use POSIX      qw(WNOHANG);
use Carp       qw(croak);
use Socket     qw(SOL_SOCKET SOCK_STREAM);
use IO::Select       ();
use IO::Socket::INET ();
use IO::Socket::UNIX ();

use Exec::Http     qw();
use Exec::Log      qw();
use Exec::Engine   qw();
use Exec::Auth     qw();
use Exec::Lock     qw();
use Exec::Registry qw();
use Exec::RunStore qw();
use Exec::Input    qw();

my $OPENAPI_PATH = '/usr/local/lib/ctrl-exec/Exec/openapi.json';
my $VERSION_FILE = '/usr/local/lib/ctrl-exec/VERSION';

# Request bounds, mirroring the agent server (bin/ctrl-exec-agent). Without
# these an attacker-supplied Content-Length or a flood of header lines is read
# into memory before the auth gate runs - a pre-authentication DoS.
my $MAX_HEADERS = 32;
# The body limit is Exec::Input::max_body: 1 MiB plus max_input_bytes, so a run
# carrying the largest permitted input is not refused before it is validated.

my $VERSION = do {
    if (open my $fh, '<', $VERSION_FILE) {
        my $v = <$fh>; chomp $v; $v;
    } else {
        'unknown';
    }
};


# Work out which listeners the configuration asks for, without opening any.
# Returns { ok => 1, socket => {...} | undef, tcp => {...} | undef } or
# { ok => 0, error => $message }. Pure apart from group lookups and loading the
# TLS files, so bin/ctrl-exec-api can refuse a bad configuration (exit 78)
# before binding.
#
# Listeners (T-013 piece 6):
#   api_socket = <path>        a unix socket, mode 0660, for same-host callers.
#   api_socket_group = <group> the socket's group (default: the server's own
#                              group); file permissions decide who may call.
#   api_bind / api_port        the TCP listener (default 127.0.0.1:7445).
#                              api_port = off turns it off.
#   api_tls_cert / api_tls_key switch the TCP listener to TLS (both or neither).
# Both listeners may run at once; they share one request handler and auth path.
# A configuration that names no listener, half a TLS pair, an unreadable TLS
# file or pair, or an unknown group is refused rather than guessed at.
sub listen_plan ($config) {
    my %c = map { my $v = $config->{$_}; ($_ => (defined $v && length $v ? $v : undef)) }
            qw(api_socket api_socket_group api_port api_bind api_tls_cert api_tls_key);
    my $fail = sub ($msg) { return { ok => 0, error => $msg } };

    # api_cert / api_key were renamed api_tls_cert / api_tls_key. The old names
    # are refused, not aliased: a silent alias would keep two spellings alive.
    for my $old (qw(api_cert api_key)) {
        my $v = $config->{$old};
        next unless defined $v && length $v;
        (my $new = $old) =~ s/^api_/api_tls_/;
        return $fail->("$old is no longer a setting: it is now $new (rename it in the API configuration)");
    }

    my $tcp_on = 1;
    my $port   = $c{api_port} // 7445;
    if ($port eq 'off') {
        $tcp_on = 0;
    }
    elsif ($port !~ /^\d+$/ || $port < 1 || $port > 65535) {
        return $fail->("api_port must be a port number (1-65535) or 'off', not '$port'");
    }

    my $socket;
    if (defined(my $path = $c{api_socket})) {
        return $fail->("api_socket must be an absolute path, not '$path'")
            unless $path =~ m{^/} && $path !~ m{/$};
        # sun_path holds 108 bytes including the terminating NUL.
        return $fail->("api_socket path is too long (at most 107 bytes): '$path'")
            if length($path) > 107;
        my $gid;
        if (defined(my $g = $c{api_socket_group})) {
            $gid = $g =~ /^\d+$/ ? $g : getgrnam($g);
            return $fail->("api_socket_group '$g' is not a known group")
                unless defined $gid && defined getgrgid($gid);
        }
        $socket = { path => $path, group => $c{api_socket_group}, gid => $gid };
    }
    elsif (defined $c{api_socket_group}) {
        return $fail->("api_socket_group is set but api_socket is not");
    }

    my $tls;
    if (defined $c{api_tls_cert} || defined $c{api_tls_key}) {
        return $fail->("api_tls_cert and api_tls_key must be set together (TLS needs both)")
            unless defined $c{api_tls_cert} && defined $c{api_tls_key};
        return $fail->("api_tls_cert/api_tls_key configure TLS for the TCP listener, but api_port = off")
            unless $tcp_on;
        for my $k (qw(api_tls_cert api_tls_key)) {
            return $fail->("$k '$c{$k}' is not a readable file")
                unless -f $c{$k} && -r _;
        }
        $tls = { cert => $c{api_tls_cert}, key => $c{api_tls_key} };
        # Load the pair now: a certificate and key that do not match, or a file
        # that is not PEM, is a configuration error like a missing file.
        eval { _make_tls_context($tls); 1 } or do {
            (my $e = $@) =~ s/\s+\z//;
            return $fail->($e);
        };
    }

    return $fail->("no API listener configured: set api_socket, or remove api_port = off")
        unless $socket || $tcp_on;

    my $tcp = $tcp_on
        ? { bind => $c{api_bind} // '127.0.0.1', port => $port, tls => $tls }
        : undef;
    return { ok => 1, socket => $socket, tcp => $tcp };
}

# Start the API server. Blocks until SIGTERM or SIGINT.
#
# Required opts:
#   config => \%config    (cert, key, ca, and the listener keys above)
#
# Listens on the unix socket and/or the TCP port that listen_plan describes.
sub run (%opts) {
    my $config = $opts{config} or croak "config required";

    my $plan = listen_plan($config);
    die "ctrl-exec-api: $plan->{error}\n" unless $plan->{ok};

    # The "listening on" lines say the server is ready: write them at once,
    # not when a buffer fills (stdout is a pipe or file under a supervisor).
    STDOUT->autoflush(1);

    # Each listener: { sock, kind => unix|tcp|tls, ... }.
    my @listeners;
    my $socket_id;    # [dev, ino] of the socket file we created, for removal
    if (my $s = $plan->{socket}) {
        my $srv = _make_unix_server($s->{path}, $s->{gid});
        my @st  = stat $s->{path};
        $socket_id = [ @st[0, 1] ];
        push @listeners, { sock => $srv, kind => 'unix', path => $s->{path} };
        Exec::Log::log_action('INFO', {
            ACTION => 'api-start',
            SOCKET => $s->{path},
            GROUP  => scalar(getgrgid($st[5])) // $st[5],
            MODE   => sprintf('%04o', $st[2] & 07777),
        });
        print "ctrl-exec API listening on unix socket $s->{path}\n";
    }
    if (my $t = $plan->{tcp}) {
        my $srv = _make_server($t->{port}, $t->{bind});
        my $ctx = $t->{tls} ? _make_tls_context($t->{tls}) : undef;
        push @listeners, { sock => $srv, kind => ($ctx ? 'tls' : 'tcp'), ctx => $ctx };
        Exec::Log::log_action('INFO', {
            ACTION   => 'api-start',
            PORT     => $t->{port},
            BIND     => $t->{bind},
            TLS      => ($ctx ? 'yes' : 'no'),
        });
        print "ctrl-exec API listening on $t->{bind}:$t->{port}"
            . ($ctx ? " (TLS)" : " (plain HTTP)") . "\n";
    }

    # Remove our socket file on a clean stop - only in the parent (children
    # inherit this handler) and only if the file is still the one we created.
    my $parent = $$;
    $SIG{INT} = $SIG{TERM} = sub {
        if ($$ == $parent) {
            Exec::Log::log_action('INFO', { ACTION => 'api-stop' });
            if ($socket_id) {
                my $path = $plan->{socket}{path};
                my @st = lstat $path;
                unlink $path
                    if @st && -S _ && $st[0] == $socket_id->[0] && $st[1] == $socket_id->[1];
            }
            print "\nAPI server stopped.\n";
        }
        exit 0;
    };

    # Bound concurrent request handlers so a connection flood cannot fork
    # unbounded processes (handlers run as the service user; on a non-loopback
    # api_bind this is the exposed surface). The default is generous - only a
    # flood reaches it - and configurable via api_max_children. $live is kept
    # accurate by one increment per fork and one decrement per reap; the order
    # of the two (parent vs SIGCHLD) does not matter, each happens exactly once.
    my $max_children = $config->{api_max_children} // 64;
    my $live = 0;

    # Reap children as they finish.
    $SIG{CHLD} = sub {
        while (waitpid(-1, WNOHANG) > 0) { $live-- }
    };

    my %by_fd = map { (fileno($_->{sock}) => $_) } @listeners;
    my $select = IO::Select->new(map { $_->{sock} } @listeners);

    while (1) {
        # can_read returns empty when a signal (SIGCHLD) interrupts it.
        for my $ready ($select->can_read) {
            my $l    = $by_fd{ fileno $ready };
            my $conn = $ready->accept or next;

            # The caller: an IP for TCP; for the socket, the socket itself plus
            # the peer's uid from the kernel (SO_PEERCRED), which the auth hook
            # gets as ENVEXEC_PEER_UID.
            my ($peer, $peer_uid);
            if ($l->{kind} eq 'unix') {
                $peer     = "unix:$l->{path}";
                $peer_uid = _peer_uid($conn);
            }
            else {
                $peer = $conn->peerhost // 'unknown';
            }

            if ($live >= $max_children) {
                Exec::Log::log_action('WARNING',
                    { ACTION => 'api-overload', PEER => $peer, LIVE => $live });
                # A TLS caller cannot read a plain-text reply; just close it.
                _send_error($conn, 503, 'service unavailable',
                            'too many concurrent requests') unless $l->{kind} eq 'tls';
                $conn->close;
                next;
            }

            my $pid = fork();
            unless (defined $pid) {
                warn "fork failed: $!\n";
                _send_error($conn, 500, 'server error', 'fork failed')
                    unless $l->{kind} eq 'tls';
                $conn->close;
                next;
            }

            if ($pid == 0) {
                # Child: handle request and exit. The TLS handshake happens here,
                # not in the parent, so a slow or silent TLS client holds up only
                # its own handler, never the accept loop.
                $_->{sock}->close for @listeners;
                if ($l->{kind} eq 'tls') {
                    $conn = _start_tls($conn, $l->{ctx}, $peer) or exit 0;
                }
                _handle_connection($conn, $peer, $config, $peer_uid);
                if ($l->{kind} eq 'tls') {
                    $conn->close(SSL_no_shutdown => 1);
                } else {
                    $conn->close;
                }
                exit 0;
            }

            # Parent: count the live child and release our copy of the connection
            $live++;
            $conn->close;
        }
    }
}

# --- private ---

sub _make_server ($port, $bind) {
    my $srv = IO::Socket::INET->new(
        LocalAddr => $bind,
        LocalPort => $port,
        Listen    => 10,
        ReuseAddr => 1,
        Proto     => 'tcp',
    ) or die "Cannot start API server on $bind:$port: $!\n";
    return $srv;
}

# Load the operator's TLS certificate and key once at start-up, so a bad pair
# stops the server with a clear error instead of failing every handshake.
sub _make_tls_context ($tls) {
    require IO::Socket::SSL;
    require Exec::TLS;
    my $ctx = IO::Socket::SSL::SSL_Context->new(
        SSL_server      => 1,
        SSL_cert_file   => $tls->{cert},
        SSL_key_file    => $tls->{key},
        SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_NONE(),
        Exec::TLS::hardening(),
    ) or die "Cannot load API TLS certificate/key ($tls->{cert}, $tls->{key}): "
           . "$IO::Socket::SSL::SSL_ERROR\n";
    return $ctx;
}

# Upgrade an accepted TCP connection to TLS (in the handler child). Returns the
# TLS socket, or undef after logging when the handshake fails or times out.
sub _start_tls ($conn, $ctx, $peer) {
    my $ok = IO::Socket::SSL->start_SSL($conn,
        SSL_server    => 1,
        SSL_reuse_ctx => $ctx,
        Timeout       => 30,
    );
    return $conn if $ok;
    Exec::Log::log_action('WARNING', {
        ACTION => 'api-tls',
        RESULT => 'handshake-failed',
        PEER   => $peer,
        ERROR  => ($IO::Socket::SSL::SSL_ERROR // 'unknown'),
    });
    return undef;
}

# Create the unix socket listener at $path, mode 0660, group $gid (when given).
#
# An existing path is handled without guessing: a regular file, directory or
# symlink (even one pointing at a socket) is never removed - start-up stops. A
# socket that answers belongs to a running server - start-up stops. A socket
# nothing answers (connection refused) was left by a crash and is replaced.
sub _make_unix_server ($path, $gid) {
    if (lstat $path) {
        die "Cannot start API socket: $path exists and is not a socket; not removing it\n"
            unless -S _;
        my $probe = IO::Socket::UNIX->new(Peer => $path, Type => SOCK_STREAM);
        if ($probe) {
            close $probe;
            die "Cannot start API socket: $path is in use by another process\n";
        }
        die "Cannot start API socket: cannot check existing socket $path: $!\n"
            unless $!{ECONNREFUSED};
        unlink $path
            or die "Cannot start API socket: cannot remove stale socket $path: $!\n";
        Exec::Log::log_action('INFO',
            { ACTION => 'api-start', SOCKET => $path, RESULT => 'stale-socket-removed' });
    }

    # Created 0660 from the start (umask), never briefly wider.
    my $old_umask = umask 0117;
    my $srv = IO::Socket::UNIX->new(Local => $path, Type => SOCK_STREAM, Listen => 10);
    my $err = $!;
    umask $old_umask;
    $srv or die "Cannot start API socket on $path: $err\n";

    if (defined $gid && !chown(-1, $gid, $path)) {
        my $e = $!;
        unlink $path;
        die "Cannot set group $gid on API socket $path: $e"
          . " (the API's user must be a member of api_socket_group)\n";
    }
    unless (chmod 0660, $path) {
        my $e = $!;
        unlink $path;
        die "Cannot set mode 0660 on API socket $path: $e\n";
    }
    return $srv;
}

# The connecting process's uid on a unix socket (Linux SO_PEERCRED: struct ucred
# { pid_t pid; uid_t uid; gid_t gid; }), or undef where unavailable.
sub _peer_uid ($conn) {
    my $cred = eval { getsockopt($conn, SOL_SOCKET, Socket::SO_PEERCRED()) }
        or return undef;
    my (undef, $uid) = unpack 'iI', $cred;
    return $uid;
}

# The connecting process's uid when the caller came in on the unix socket
# (undef for TCP). Set per connection; every auth check passes it to the hook.
our $PEER_UID;

sub _handle_connection ($conn, $peer, $config, $peer_uid = undef) {
    local $PEER_UID = $peer_uid;

    # Read request line
    my $request_line = <$conn>;
    unless ($request_line) {
        _send_error($conn, 400, 'bad request', 'empty request');
        return;
    }
    chomp $request_line;
    $request_line =~ s/\r$//;

    my ($method, $path) = split ' ', $request_line;
    $method = uc($method // '');
    $path   = $path // '/';

    # Read headers, bounded by header count and declared body size so an
    # oversized Content-Length or a flood of header lines cannot exhaust memory
    # before the auth gate. Both limits reject before any body is read.
    my $content_length = 0;
    my $header_count   = 0;
    my $auth_token     = '';   # Authorization: Bearer <token>, for GET /status
    while (my $line = <$conn>) {
        $line =~ s/\r?\n$//;
        last if $line eq '';
        if (++$header_count > $MAX_HEADERS) {
            _send_error($conn, 431, 'request header fields too large',
                        "more than $MAX_HEADERS header lines");
            return;
        }
        if ($line =~ /^Content-Length:\s*(\d+)/i) {
            $content_length = $1;
        }
        elsif ($line =~ /^Authorization:\s*Bearer\s+(\S+)/i) {
            $auth_token = $1;
        }
    }

    my $max_body = Exec::Input::max_body($config);
    if ($content_length > $max_body) {
        _send_error($conn, 413, 'payload too large',
                    "body exceeds $max_body bytes");
        return;
    }

    # Read body
    my $body = '';
    if ($content_length > 0) {
        read $conn, $body, $content_length;
    }

    Exec::Log::log_action('INFO', {
        ACTION => 'api-request',
        METHOD => $method,
        PATH   => $path,
        PEER   => $peer,
        (defined $peer_uid ? (UID => $peer_uid) : ()),
        LEN    => $content_length,
    });

    # All endpoints pass through auth.
    # The auth hook (or api_auth_default) decides what is permitted.
    # Operators who want public endpoints (e.g. /health) configure the hook
    # to pass those paths selectively.
    my $auth = Exec::Auth::check(
        action    => 'api',
        script    => '',
        hosts     => [],
        args      => [],
        username  => '',
        token     => ($body =~ /^\{/ ? do {
            my $b = eval { decode_json($body) } // {};
            $b->{token} // ''
        } : ''),
        source_ip => $peer,
        peer_uid  => $PEER_UID,
        config    => $config,
    );
    unless ($auth->{ok}) {
        _send_auth_denied($conn, $auth, $config);
        return;
    }

    # Route
    if ($path eq '/' && $method eq 'GET') {
        _handle_index($conn, $config);
    }
    elsif ($path eq '/openapi.json' && $method eq 'GET') {
        _handle_openapi($conn);
    }
    elsif ($path eq '/openapi-live.json' && $method eq 'GET') {
        _handle_openapi_live($conn, $peer, $config);
    }
    elsif ($path eq '/health' && $method eq 'GET') {
        _handle_health($conn);
    }
    elsif ($path eq '/ping' && $method eq 'POST') {
        _handle_ping($conn, $peer, $body, $config);
    }
    elsif ($path eq '/run' && $method eq 'POST') {
        _handle_run($conn, $peer, $body, $config);
    }
    elsif ($path eq '/discovery' && $method =~ /^(GET|POST)$/) {
        _handle_discovery($conn, $peer, $body, $config);
    }
    elsif ($path =~ m{^/status/([a-f0-9]+)$} && $method eq 'GET') {
        _handle_status($conn, $1, $peer, $auth_token, $config);
    }
    else {
        _send_error($conn, 404, 'not found', "no route for $method $path");
    }
}

sub _handle_health ($conn) {
    _send_json($conn, 200, { ok => JSON::true, version => $VERSION });
}

sub _handle_ping ($conn, $peer, $body, $config) {

    my $req = _parse_body($conn, $body) or return;

    my $hosts = $req->{hosts};
    unless (ref $hosts eq 'ARRAY' && @$hosts) {
        _send_error($conn, 400, 'bad request', 'hosts must be a non-empty array');
        return;
    }

    my $username = $req->{username} // '';
    my $token    = $req->{token}    // '';

    my $auth = Exec::Auth::check(
        action    => 'ping',
        hosts     => $hosts,
        username  => $username,
        token     => $token,
        source_ip => $peer,
        peer_uid  => $PEER_UID,
        config    => $config,
    );
    unless ($auth->{ok}) {
        _send_auth_denied($conn, $auth, $config);
        return;
    }

    # The API server's SIGCHLD reaper is inherited by request-handler children.
    # Engine forks grandchildren and collects them with waitpid. Without this
    # guard the reaper steals grandchildren before waitpid can collect them,
    # returning a partial results array. local restores the handler on scope exit.
    my $resolved = _resolve_or_404($conn, $hosts) or return;

    local $SIG{CHLD} = 'DEFAULT';
    my $results = Exec::Engine::ping_all(
        hosts  => $resolved->{hosts},
        config => $config,
        renew  => 0,   # the API server runs unprivileged and cannot sign (no CA key);
                       # cert renewal is driven by `ced maintain` (root) instead.
    );

    _send_json($conn, 200, { ok => JSON::true, results => $results });
}

sub _handle_run ($conn, $peer, $body, $config) {

    my $req = _parse_body($conn, $body) or return;

    my $hosts  = $req->{hosts};
    my $script = $req->{script};
    my $args   = $req->{args} // [];

    unless (ref $hosts eq 'ARRAY' && @$hosts) {
        _send_error($conn, 400, 'bad request', 'hosts must be a non-empty array');
        return;
    }
    unless ($script && $script =~ /^[\w-]+$/) {
        _send_error($conn, 400, 'bad request', 'script name required (alphanumeric and hyphens only)');
        return;
    }
    if (defined(my $problem = Exec::Http::args_problem($args))) {
        _send_error($conn, 400, 'bad request', $problem);
        return;
    }

    # Confidential input (T-013): validated before any hook or dispatch. The
    # values travel only to the agents; everything else here sees the field
    # names and a total size.
    my $input = $req->{input};
    my $iv    = Exec::Input::validate($input, Exec::Input::max_bytes($config));
    unless ($iv->{ok}) {
        _send_error($conn, 400, 'bad request', $iv->{error});
        return;
    }

    my $username = $req->{username} // '';
    my $token    = $req->{token}    // '';
    my $async    = $req->{async} ? 1 : 0;

    my $auth = Exec::Auth::check(
        action    => 'run',
        script    => $script,
        hosts     => $hosts,
        args      => $args,
        input_names => $iv->{names},
        input_bytes => $iv->{bytes},
        username  => $username,
        token     => $token,
        source_ip => $peer,
        peer_uid  => $PEER_UID,
        config    => $config,
    );
    unless ($auth->{ok}) {
        _send_auth_denied($conn, $auth, $config);
        return;
    }

    my $lock = Exec::Lock::check_available(
        hosts  => $hosts,
        script => $script,
    );
    unless ($lock->{ok}) {
        _send_json($conn, 409, {
            ok        => JSON::false,
            error     => 'locked',
            code      => 4,
            conflicts => $lock->{conflicts},
        });
        return;
    }

    my $resolved = _resolve_or_404($conn, $hosts) or return;

    my $reqid = Exec::Engine::gen_reqid();
    # The API server's SIGCHLD reaper is inherited by request-handler children.
    # Engine forks grandchildren and collects them with waitpid. Without this
    # guard the reaper steals grandchildren before waitpid can collect them,
    # returning a partial results array. local restores the handler on scope exit.
    local $SIG{CHLD} = 'DEFAULT';
    my $results = Exec::Engine::dispatch_all(
        hosts    => $resolved->{hosts},
        script   => $script,
        args     => $args,
        reqid    => $reqid,
        username => $username,
        token    => $token,
        config   => $config,
        async    => $async,
        (defined $input ? (input => $input) : ()),
    );

    if ($async) {
        # Each agent has accepted (or refused) a detached job. Record the
        # reqid -> host map; the caller polls GET /status/<reqid> for results.
        Exec::RunStore::record_async(
            reqid => $reqid, script => $script, dispatch_results => $results,
            submitter => _submitter($username, $peer),
        );
        _send_json($conn, 202, {
            ok => JSON::true, reqid => $reqid, async => JSON::true, results => $results,
        });
        return;
    }

    Exec::RunStore::record_sync(
        reqid => $reqid, script => $script, hosts => $hosts, results => $results,
        submitter => _submitter($username, $peer),
    );

    _send_json($conn, 200, { ok => JSON::true, reqid => $reqid, results => $results });
}

sub _handle_discovery ($conn, $peer, $body, $config) {

    # Optional body: { "hosts": [...], "username": "...", "token": "..." }
    # If no hosts specified, use the full agent registry
    my $req = {};
    if ($body && length $body) {
        $req = eval { decode_json($body) } // {};
    }

    my $hosts    = $req->{hosts};
    my $username = $req->{username} // '';
    my $token    = $req->{token}    // '';

    # Default to all registered agents
    unless (ref $hosts eq 'ARRAY' && @$hosts) {
        $hosts = Exec::Registry::list_hostnames();
    }

    unless (@$hosts) {
        _send_json($conn, 200, { ok => JSON::true, hosts => {} });
        return;
    }

    my $auth = Exec::Auth::check(
        action    => 'ping',    # discovery uses ping privilege level
        hosts     => $hosts,
        username  => $username,
        token     => $token,
        source_ip => $peer,
        peer_uid  => $PEER_UID,
        config    => $config,
    );
    unless ($auth->{ok}) {
        _send_auth_denied($conn, $auth, $config);
        return;
    }

    # The API server's SIGCHLD reaper is inherited by request-handler children.
    # Engine forks grandchildren and collects them with waitpid. Without this
    # guard the reaper steals grandchildren before waitpid can collect them,
    # returning a partial results array. local restores the handler on scope exit.
    # Resolve registry names to connect targets through the same path as
    # ping/run, keying results by the canonical registry name.
    my $resolved = _resolve_or_404($conn, $hosts) or return;

    local $SIG{CHLD} = 'DEFAULT';
    my $results = Exec::Engine::capabilities_all(
        hosts  => $resolved->{hosts},
        config => $config,
    );

    # Reshape from array to hash keyed by the canonical (registry) hostname.
    my %by_host;
    for my $r (@$results) {
        my $h = $r->{host} or next;
        $by_host{$h} = $r;
        # Cache the live tags in the registry so list-agents --tags can filter
        # offline (Option C). No-op for hosts that are not registered.
        if (($r->{status} // '') eq 'ok' && ref $r->{tags} eq 'HASH') {
            eval { Exec::Registry::update_agent_tags(hostname => $h, tags => $r->{tags}) };
        }
    }

    _send_json($conn, 200, { ok => JSON::true, hosts => \%by_host });
}

sub _handle_index ($conn, $config) {
    _send_json($conn, 200, {
        name      => 'ctrl-exec-api',
        version   => $VERSION,
        spec      => '/openapi.json',
        live_spec => '/openapi-live.json',
        endpoints => [
            { method => 'GET',  path => '/health'           },
            { method => 'POST', path => '/ping'              },
            { method => 'POST', path => '/run'               },
            { method => 'GET',  path => '/discovery'         },
            { method => 'POST', path => '/discovery'         },
            { method => 'GET',  path => '/status/{reqid}'    },
            { method => 'GET',  path => '/openapi.json'      },
            { method => 'GET',  path => '/openapi-live.json' },
        ],
    });
}

sub _handle_openapi ($conn) {
    unless (-f $OPENAPI_PATH) {
        _send_error($conn, 404, 'not found', 'openapi.json not installed');
        return;
    }
    open my $fh, '<', $OPENAPI_PATH
        or do { _send_error($conn, 500, 'server error', "cannot read spec: $!"); return; };
    local $/;
    my $body = <$fh>;
    close $fh;
    Exec::Http::send_raw($conn, 200, $body);
}

sub _handle_openapi_live ($conn, $peer, $config) {

    unless (-f $OPENAPI_PATH) {
        _send_error($conn, 404, 'not found', 'openapi.json not installed');
        return;
    }
    my $spec = eval {
        open my $fh, '<', $OPENAPI_PATH or die "cannot read: $!";
        local $/;
        decode_json(scalar <$fh>);
    };
    if ($@ || !$spec) {
        _send_error($conn, 500, 'server error', "cannot parse base spec: $@");
        return;
    }

    my $hostnames = Exec::Registry::list_hostnames();

    my $results = [];
    if (@$hostnames) {
        # The API server's SIGCHLD reaper is inherited by request-handler children.
        # Engine forks grandchildren and collects them with waitpid. Without this
        # guard the reaper steals grandchildren before waitpid can collect them,
        # returning a partial results array. local restores the handler on scope exit.
        local $SIG{CHLD} = 'DEFAULT';
        # All names come from the registry, so resolution never has unknowns.
        my $resolved = Exec::Registry::resolve_dispatch($hostnames);
        $results = Exec::Engine::capabilities_all(
            hosts  => $resolved->{hosts} // [],
            config => $config,
        );
    }

    _build_live_spec($spec, $hostnames, $results);

    my $base_version = $spec->{info}{version} // $VERSION;
    $base_version =~ s/\+\d+$//;
    $spec->{info}{version} = $base_version . '+' . time();

    my $body = encode_json($spec);
    Exec::Http::send_raw($conn, 200, $body);
}

# Augment a parsed OpenAPI spec in place with live discovery data: inject the
# discovered host/script enums into the request schemas, and surface each
# script's advertised schema sidecar as an `x-ctrl-exec-scripts` vendor
# extension. Pure (no IO) so it is unit-testable.
#
# The extension carries the sidecar schema *verbatim*, grouped by schema
# version so fleet drift is visible. Per the schema-sidecar contract, core only
# surfaces the schema here - it does not interpret `arguments`/`argv` or fold
# them into the `/run` request contract (whose `args` stays a positional array).
# Standard tooling ignores `x-` fields; the data is informational.
sub _build_live_spec ($spec, $hostnames, $results) {
    $hostnames //= [];
    $results   //= [];

    # Collect script names and group hosts/schema by (name, schema_version).
    my %seen;
    my %by_script;   # name => { version_key => { hosts => {h=>1}, schema, schema_version } }
    for my $r (@$results) {
        next unless ($r->{status} // '') eq 'ok';
        next unless ref $r->{scripts} eq 'ARRAY';
        my $host = $r->{host} // next;
        for my $s (@{ $r->{scripts} }) {
            my $name = $s->{name} or next;
            $seen{$name} = 1;
            my $ver  = $s->{schema_version};
            my $key  = defined $ver ? $ver : "\0none";
            my $slot = $by_script{$name}{$key} ||= { hosts => {} };
            $slot->{hosts}{$host}   = 1;
            $slot->{schema_version} = $ver if defined $ver;
            $slot->{schema}         = $s->{schema}
                if defined $s->{schema} && !exists $slot->{schema};
        }
    }
    my @scripts = sort keys %seen;

    # Inject the host enum into every hosts-array request body.
    for my $path_key (qw(/ping /run /discovery)) {
        for my $method_key (qw(post get)) {
            my $op = $spec->{paths}{$path_key}{$method_key} or next;
            my $body_schema = eval {
                $op->{requestBody}{content}{'application/json'}{schema}
            } or next;
            if (my $ref = $body_schema->{'$ref'}) {
                my $name = (split '/', $ref)[-1];
                $body_schema = $spec->{components}{schemas}{$name} or next;
            }
            if (ref $body_schema->{properties}{hosts} eq 'HASH') {
                $body_schema->{properties}{hosts}{items}{enum} =
                    @$hostnames ? $hostnames : undef;
            }
        }
    }

    return $spec unless @scripts;

    # Inject the script enum into the /run body schema.
    my $run_schema_name = eval {
        my $ref = $spec->{paths}{'/run'}{post}{requestBody}
                      {content}{'application/json'}{schema}{'$ref'};
        (split '/', $ref)[-1];
    };
    if ($run_schema_name &&
        ref $spec->{components}{schemas}{$run_schema_name} eq 'HASH') {
        $spec->{components}{schemas}{$run_schema_name}
              {properties}{script}{enum} = \@scripts;
    }

    # Surface advertised schema sidecars, grouped by version, verbatim.
    my %ext;
    for my $name (@scripts) {
        my @variants;
        for my $key (sort keys %{ $by_script{$name} }) {
            my $slot = $by_script{$name}{$key};
            my $v = { hosts => [ sort keys %{ $slot->{hosts} } ] };
            $v->{schema_version} = $slot->{schema_version}
                if defined $slot->{schema_version};
            $v->{schema} = $slot->{schema} if exists $slot->{schema};
            push @variants, $v;
        }
        $ext{$name} = \@variants;
    }
    $spec->{'x-ctrl-exec-scripts'} = \%ext;

    return $spec;
}

# Who submitted a run, as stored with its record. peer_uid (the unix-socket
# caller's uid) is stored only when the run came over the socket, so a TCP
# record is unchanged. It is for the auth hook on a later /status, never echoed.
sub _submitter ($username, $peer) {
    return {
        username  => $username,
        source_ip => $peer,
        (defined $PEER_UID ? (peer_uid => $PEER_UID + 0) : ()),
    };
}

sub _handle_status ($conn, $reqid, $peer, $auth_token, $config) {

    Exec::RunStore::purge();

    # For an async record this fetches any still-pending host results, merges
    # them, and persists; for a sync record it returns the stored result as-is.
    # The Engine forks grandchildren during the fetch and reaps them with
    # waitpid - guard the inherited SIGCHLD reaper so it does not steal them.
    local $SIG{CHLD} = 'DEFAULT';
    my $record = eval {
        Exec::RunStore::aggregate(reqid => $reqid, config => $config);
    };
    if ($@) {
        _log_status_read('ERR', 'error', $reqid, $peer, undef);
        _send_error($conn, 500, 'server error', 'cannot read result');
        return;
    }
    unless ($record) {
        _log_status_read('INFO', 'not-found', $reqid, $peer, undef);
        _send_error($conn, 404, 'not found', "no result for reqid $reqid");
        return;
    }

    # Per-result authorization. The blanket pre-route gate runs before the reqid
    # is even parsed and has no notion of who submitted the run; this check gives
    # the hook the reqid and the recorded submitter so it can owner-gate - return
    # a run's output only to a caller it authorises (e.g. one whose token maps to
    # the submitter, or from the submitter's IP). With no hook configured the
    # api_auth_default applies (the same default the pre-route gate enforced), so
    # possession of the unguessable 64-bit reqid remains the capability.
    my $auth = Exec::Auth::check(
        action    => 'status',
        reqid     => $reqid,
        submitter => $record->{submitter},
        token     => $auth_token,
        source_ip => $peer,
        peer_uid  => $PEER_UID,
        config    => $config,
    );
    unless ($auth->{ok}) {
        # Deny as 404, not 403: do not reveal to an unauthorised caller that the
        # reqid exists (no distinction between "not yours" and "no such run").
        # The log (the operator's) does distinguish them.
        _log_status_read('WARNING', 'denied', $reqid, $peer, $record->{submitter});
        _send_error($conn, 404, 'not found', "no result for reqid $reqid");
        return;
    }

    _log_status_read('INFO', 'served', $reqid, $peer, $record->{submitter});

    # Never echo the internal submitter record back to the caller.
    my %public = %$record;
    delete $public{submitter};
    _send_json($conn, 200, { ok => JSON::true, %public });
}

# Audit line for every GET /status read: who read which run, and the outcome
# (served / denied / not-found / error). USER is the username the auth hook was
# given - a GET carries none, so it is normally (none); IP identifies the caller.
# SUBMITTER is the recorded submitter, for comparison. Never the token and never
# any of the run's output.
sub _log_status_read ($level, $result, $reqid, $peer, $submitter) {
    my $sub = ref $submitter eq 'HASH' ? ($submitter->{username} // '') : '';
    $sub =~ s/[[:cntrl:]]/?/g;    # submitter is caller-supplied: keep the line one line
    Exec::Log::log_action($level, {
        ACTION    => 'status-read',
        RESULT    => $result,
        USER      => '(none)',
        IP        => $peer,
        REQID     => $reqid,
        SUBMITTER => length $sub ? $sub : '(none)',
    });
}

sub _parse_body ($conn, $body) {
    unless ($body && length $body) {
        _send_error($conn, 400, 'bad request', 'request body required');
        return undef;
    }
    my $req = eval { decode_json($body) };
    if ($@ || ref $req ne 'HASH') {
        _send_error($conn, 400, 'bad request', 'invalid JSON body');
        return undef;
    }
    return $req;
}

sub _send_json ($conn, $status, $data) {
    Exec::Http::send_json($conn, $status, $data);
}

# Send the standard 403 auth-denial (with the hook's deny fields). Used by every
# endpoint that gates on the auth hook except /status, which denies as 404.
sub _send_auth_denied ($conn, $auth, $config) {
    _send_json($conn, 403, {
        ok => JSON::false,
        %{ Exec::Auth::deny_fields($auth, $config) },
    });
}

# Resolve a host list to dispatch targets, or send a 404 and return undef. On
# success returns the full resolve_dispatch result (callers read ->{hosts}).
sub _resolve_or_404 ($conn, $hosts) {
    my $resolved = Exec::Registry::resolve_dispatch($hosts);
    return $resolved if $resolved->{ok};
    _send_error($conn, 404, 'unknown agent',
        'not a registered agent: ' . join(', ', @{ $resolved->{unknown} }));
    return undef;
}

sub _send_error ($conn, $status, $error, $detail = undef) {
    _send_json($conn, $status, {
        ok    => JSON::false,
        error => $error,
        ($detail ? (detail => $detail) : ()),
    });
}

1;
