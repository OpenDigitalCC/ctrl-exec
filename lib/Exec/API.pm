package Exec::API;

use strict;
use warnings;
use JSON       qw(encode_json decode_json);
use File::Path qw(make_path);
use POSIX      qw(WNOHANG);
use Carp       qw(croak);

use Exec::Log      qw();
use Exec::Engine   qw();
use Exec::Auth     qw();
use Exec::Lock     qw();
use Exec::Registry qw();

my $RUNS_DIR     = '/var/lib/ctrl-exec/runs';
my $RUNS_TTL     = 86400;    # seconds; results older than this are purged
my $OPENAPI_PATH = '/usr/local/lib/ctrl-exec/Exec/openapi.json';
my $VERSION_FILE = '/usr/local/lib/ctrl-exec/VERSION';

my $VERSION = do {
    if (open my $fh, '<', $VERSION_FILE) {
        my $v = <$fh>; chomp $v; $v;
    } else {
        'unknown';
    }
};


# Start the API server. Blocks until SIGTERM or SIGINT.
#
# Required opts:
#   config => \%config    (cert, key, ca, and optional api_port, api_cert, api_key)
#
# The server listens on api_port (default 7445).
# TLS is enabled if api_cert and api_key are both present in config.
# Plain HTTP is used otherwise.
sub run {
    my (%opts) = @_;
    my $config = $opts{config} or croak "config required";

    my $port     = $config->{api_port}  // 7445;
    my $bind     = $config->{api_bind}  // '127.0.0.1';
    my $api_cert = $config->{api_cert}  // '';
    my $api_key  = $config->{api_key}   // '';
    my $use_tls  = ($api_cert && $api_key && -f $api_cert && -f $api_key);

    my $server = _make_server($port, $bind, $use_tls, $api_cert, $api_key);

    Exec::Log::log_action('INFO', {
        ACTION   => 'api-start',
        PORT     => $port,
        BIND     => $bind,
        TLS      => ($use_tls ? 'yes' : 'no'),
    });

    print "ctrl-exec API listening on $bind:$port"
        . ($use_tls ? " (TLS)" : " (plain HTTP)") . "\n";

    $SIG{INT} = $SIG{TERM} = sub {
        Exec::Log::log_action('INFO', { ACTION => 'api-stop' });
        print "\nAPI server stopped.\n";
        exit 0;
    };

    # Reap children as they finish
    $SIG{CHLD} = sub {
        while (waitpid(-1, WNOHANG) > 0) {}
    };

    while (1) {
        my $conn = $server->accept or next;
        my $peer = $use_tls ? $conn->peerhost : $conn->peerhost;
        $peer //= 'unknown';

        my $pid = fork();
        unless (defined $pid) {
            warn "fork failed: $!\n";
            _send_error($conn, 500, 'server error', 'fork failed');
            $conn->close;
            next;
        }

        if ($pid == 0) {
            # Child: handle request and exit
            $server->close;
            _handle_connection($conn, $peer, $config);
            if ($use_tls) {
                $conn->close(SSL_no_shutdown => 1);
            } else {
                $conn->close;
            }
            exit 0;
        }

        # Parent: release our copy of the connection
        if ($use_tls) {
            $conn->close(SSL_no_shutdown => 1);
        } else {
            $conn->close;
        }
    }
}

# --- private ---

sub _make_server {
    my ($port, $bind, $use_tls, $cert, $key) = @_;

    if ($use_tls) {
        require IO::Socket::SSL;
        my $srv = IO::Socket::SSL->new(
            LocalAddr       => $bind,
            LocalPort       => $port,
            Listen          => 10,
            ReuseAddr       => 1,
            SSL_cert_file   => $cert,
            SSL_key_file    => $key,
            SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_NONE(),
        ) or die "Cannot start TLS API server on $bind:$port: "
               . "$IO::Socket::SSL::SSL_ERROR\n";
        return $srv;
    }
    else {
        require IO::Socket::INET;
        my $srv = IO::Socket::INET->new(
            LocalAddr => $bind,
            LocalPort => $port,
            Listen    => 10,
            ReuseAddr => 1,
            Proto     => 'tcp',
        ) or die "Cannot start API server on $bind:$port: $!\n";
        return $srv;
    }
}

sub _handle_connection {
    my ($conn, $peer, $config) = @_;

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

    # Read headers
    my $content_length = 0;
    while (my $line = <$conn>) {
        $line =~ s/\r?\n$//;
        last if $line eq '';
        if ($line =~ /^Content-Length:\s*(\d+)/i) {
            $content_length = $1;
        }
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
        config    => $config,
    );
    unless ($auth->{ok}) {
        _send_json($conn, 403, {
            ok    => JSON::false,
            error => $auth->{reason},
            code  => $auth->{code},
        });
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
        _handle_status($conn, $1);
    }
    else {
        _send_error($conn, 404, 'not found', "no route for $method $path");
    }
}

sub _handle_health {
    my ($conn) = @_;
    _send_json($conn, 200, { ok => JSON::true, version => $VERSION });
}

sub _handle_ping {
    my ($conn, $peer, $body, $config) = @_;

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
        config    => $config,
    );
    unless ($auth->{ok}) {
        _send_json($conn, 403, {
            ok    => JSON::false,
            error => $auth->{reason},
            code  => $auth->{code},
        });
        return;
    }

    # The API server's SIGCHLD reaper is inherited by request-handler children.
    # Engine forks grandchildren and collects them with waitpid. Without this
    # guard the reaper steals grandchildren before waitpid can collect them,
    # returning a partial results array. local restores the handler on scope exit.
    local $SIG{CHLD} = 'DEFAULT';
    my $results = Exec::Engine::ping_all(
        hosts  => $hosts,
        config => $config,
    );

    _send_json($conn, 200, { ok => JSON::true, results => $results });
}

sub _handle_run {
    my ($conn, $peer, $body, $config) = @_;

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
    unless (ref $args eq 'ARRAY') {
        _send_error($conn, 400, 'bad request', 'args must be an array');
        return;
    }

    my $username = $req->{username} // '';
    my $token    = $req->{token}    // '';

    my $auth = Exec::Auth::check(
        action    => 'run',
        script    => $script,
        hosts     => $hosts,
        args      => $args,
        username  => $username,
        token     => $token,
        source_ip => $peer,
        config    => $config,
    );
    unless ($auth->{ok}) {
        _send_json($conn, 403, {
            ok    => JSON::false,
            error => $auth->{reason},
            code  => $auth->{code},
        });
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

    my $reqid = Exec::Engine::gen_reqid();
    # The API server's SIGCHLD reaper is inherited by request-handler children.
    # Engine forks grandchildren and collects them with waitpid. Without this
    # guard the reaper steals grandchildren before waitpid can collect them,
    # returning a partial results array. local restores the handler on scope exit.
    local $SIG{CHLD} = 'DEFAULT';
    my $results = Exec::Engine::dispatch_all(
        hosts    => $hosts,
        script   => $script,
        args     => $args,
        reqid    => $reqid,
        username => $username,
        token    => $token,
        config   => $config,
    );

    _store_run_result($reqid, $script, $hosts, $results);

    _send_json($conn, 200, { ok => JSON::true, reqid => $reqid, results => $results });
}

sub _handle_discovery {
    my ($conn, $peer, $body, $config) = @_;

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
        config    => $config,
    );
    unless ($auth->{ok}) {
        _send_json($conn, 403, {
            ok    => JSON::false,
            error => $auth->{reason},
            code  => $auth->{code},
        });
        return;
    }

    # The API server's SIGCHLD reaper is inherited by request-handler children.
    # Engine forks grandchildren and collects them with waitpid. Without this
    # guard the reaper steals grandchildren before waitpid can collect them,
    # returning a partial results array. local restores the handler on scope exit.
    # Resolve each registry name to its connect target (lookup_by + stored
    # port) while keying results by the canonical registry name.
    my @entries = map {
        m/:\d+$/
            ? $_
            : { name => $_, target => Exec::Registry::resolve_target(hostname => $_) }
    } @$hosts;

    local $SIG{CHLD} = 'DEFAULT';
    my $results = Exec::Engine::capabilities_all(
        hosts  => \@entries,
        config => $config,
    );

    # Reshape from array to hash keyed by the canonical (registry) hostname.
    my %by_host;
    for my $r (@$results) {
        my $h = $r->{host} or next;
        $by_host{$h} = $r;
    }

    _send_json($conn, 200, { ok => JSON::true, hosts => \%by_host });
}

sub _handle_index {
    my ($conn, $config) = @_;
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

sub _handle_openapi {
    my ($conn) = @_;
    unless (-f $OPENAPI_PATH) {
        _send_error($conn, 404, 'not found', 'openapi.json not installed');
        return;
    }
    open my $fh, '<', $OPENAPI_PATH
        or do { _send_error($conn, 500, 'server error', "cannot read spec: $!"); return; };
    local $/;
    my $body = <$fh>;
    close $fh;
    print $conn
        "HTTP/1.0 200 OK\r\n",
        "Content-Type: application/json\r\n",
        "Content-Length: ", length($body), "\r\n",
        "\r\n",
        $body;
}

sub _handle_openapi_live {
    my ($conn, $peer, $config) = @_;

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

    my @scripts;
    if (@$hostnames) {
        # The API server's SIGCHLD reaper is inherited by request-handler children.
        # Engine forks grandchildren and collects them with waitpid. Without this
        # guard the reaper steals grandchildren before waitpid can collect them,
        # returning a partial results array. local restores the handler on scope exit.
        local $SIG{CHLD} = 'DEFAULT';
        my @entries = map {
            { name => $_, target => Exec::Registry::resolve_target(hostname => $_) }
        } @$hostnames;
        my $results = Exec::Engine::capabilities_all(
            hosts  => \@entries,
            config => $config,
        );
        my %seen;
        for my $r (@$results) {
            next unless ($r->{status} // '') eq 'ok';
            next unless ref $r->{scripts} eq 'ARRAY';
            for my $s (@{ $r->{scripts} }) {
                my $name = $s->{name} or next;
                $seen{$name} = 1;
            }
        }
        @scripts = sort keys %seen;
    }

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

    if (@scripts) {
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
    }

    my $base_version = $spec->{info}{version} // $VERSION;
    $base_version =~ s/\+\d+$//;
    $spec->{info}{version} = $base_version . '+' . time();

    my $body = encode_json($spec);
    print $conn
        "HTTP/1.0 200 OK\r\n",
        "Content-Type: application/json\r\n",
        "Content-Length: ", length($body), "\r\n",
        "\r\n",
        $body;
}

sub _handle_status {
    my ($conn, $reqid) = @_;

    _purge_old_runs();

    my $file = "$RUNS_DIR/$reqid.json";
    unless (-f $file) {
        _send_error($conn, 404, 'not found', "no result for reqid $reqid");
        return;
    }

    open my $fh, '<', $file
        or do { _send_error($conn, 500, 'server error', "cannot read result: $!"); return; };
    local $/;
    my $raw = <$fh>;
    close $fh;

    my $record = eval { decode_json($raw) };
    if ($@ || !$record) {
        _send_error($conn, 500, 'server error', 'corrupt result record');
        return;
    }

    _send_json($conn, 200, { ok => JSON::true, %$record });
}

sub _store_run_result {
    my ($reqid, $script, $hosts, $results) = @_;

    unless (-d $RUNS_DIR) {
        eval { File::Path::make_path($RUNS_DIR, { mode => 0750 }) };
        if ($@) {
            Exec::Log::log_action('WARNING', {
                ACTION => 'run-store-fail',
                REQID  => $reqid,
                ERROR  => "cannot create $RUNS_DIR: $@",
            });
            return;
        }
    }

    my $record = encode_json({
        reqid     => $reqid,
        script    => $script,
        hosts     => $hosts,
        results   => $results,
        completed => time(),
    });

    my $file = "$RUNS_DIR/$reqid.json";
    if (open my $fh, '>', $file) {
        print $fh $record;
        close $fh;
        chmod 0640, $file;
    }
    else {
        Exec::Log::log_action('WARNING', {
            ACTION => 'run-store-fail',
            REQID  => $reqid,
            ERROR  => "cannot write $file: $!",
        });
    }
}

sub _purge_old_runs {
    return unless -d $RUNS_DIR;
    my $cutoff = time() - $RUNS_TTL;
    opendir my $dh, $RUNS_DIR or return;
    while (my $entry = readdir $dh) {
        next unless $entry =~ /^[a-f0-9]+\.json$/;
        my $file = "$RUNS_DIR/$entry";
        my $mtime = (stat $file)[9] // 0;
        unlink $file if $mtime < $cutoff;
    }
    closedir $dh;
}

sub _parse_body {
    my ($conn, $body) = @_;
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

sub _send_json {
    my ($conn, $status, $data) = @_;
    my $body   = encode_json($data);
    my $phrase = _status_phrase($status);
    print $conn
        "HTTP/1.0 $status $phrase\r\n",
        "Content-Type: application/json\r\n",
        "Content-Length: ", length($body), "\r\n",
        "\r\n",
        $body;
}

sub _send_error {
    my ($conn, $status, $error, $detail) = @_;
    _send_json($conn, $status, {
        ok    => JSON::false,
        error => $error,
        ($detail ? (detail => $detail) : ()),
    });
}

sub _status_phrase {
    my ($code) = @_;
    my %phrases = (
        200 => 'OK',
        400 => 'Bad Request',
        403 => 'Forbidden',
        404 => 'Not Found',
        409 => 'Conflict',
        500 => 'Internal Server Error',
    );
    return $phrases{$code} // 'Unknown';
}

1;
