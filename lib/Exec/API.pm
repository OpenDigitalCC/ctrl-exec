package Exec::API;

use strict;
use warnings;
use JSON       qw(encode_json decode_json);
use POSIX      qw(WNOHANG);
use Carp       qw(croak);

use Exec::Http     qw();
use Exec::Log      qw();
use Exec::Engine   qw();
use Exec::Auth     qw();
use Exec::Lock     qw();
use Exec::Registry qw();
use Exec::RunStore qw();

my $OPENAPI_PATH = '/usr/local/lib/ctrl-exec/Exec/openapi.json';
my $VERSION_FILE = '/usr/local/lib/ctrl-exec/VERSION';

# Request bounds, mirroring the agent server (bin/ctrl-exec-agent). Without
# these an attacker-supplied Content-Length or a flood of header lines is read
# into memory before the auth gate runs - a pre-authentication DoS.
my $MAX_HEADERS = 32;
my $MAX_BODY    = 1_048_576;   # 1 MiB; the largest legitimate body is well under

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
        require Exec::TLS;
        my $srv = IO::Socket::SSL->new(
            LocalAddr       => $bind,
            LocalPort       => $port,
            Listen          => 10,
            ReuseAddr       => 1,
            SSL_cert_file   => $cert,
            SSL_key_file    => $key,
            SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_NONE(),
            Exec::TLS::hardening(),
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

    if ($content_length > $MAX_BODY) {
        _send_error($conn, 413, 'payload too large',
                    "body exceeds $MAX_BODY bytes");
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
            ok => JSON::false,
            %{ Exec::Auth::deny_fields($auth, $config) },
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
        _handle_status($conn, $1, $peer, $auth_token, $config);
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
            ok => JSON::false,
            %{ Exec::Auth::deny_fields($auth, $config) },
        });
        return;
    }

    # The API server's SIGCHLD reaper is inherited by request-handler children.
    # Engine forks grandchildren and collects them with waitpid. Without this
    # guard the reaper steals grandchildren before waitpid can collect them,
    # returning a partial results array. local restores the handler on scope exit.
    my $resolved = Exec::Registry::resolve_dispatch($hosts);
    unless ($resolved->{ok}) {
        _send_error($conn, 404, 'unknown agent',
            'not a registered agent: ' . join(', ', @{ $resolved->{unknown} }));
        return;
    }

    local $SIG{CHLD} = 'DEFAULT';
    my $results = Exec::Engine::ping_all(
        hosts  => $resolved->{hosts},
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
    my $async    = $req->{async} ? 1 : 0;

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
            ok => JSON::false,
            %{ Exec::Auth::deny_fields($auth, $config) },
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

    my $resolved = Exec::Registry::resolve_dispatch($hosts);
    unless ($resolved->{ok}) {
        _send_error($conn, 404, 'unknown agent',
            'not a registered agent: ' . join(', ', @{ $resolved->{unknown} }));
        return;
    }

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
    );

    if ($async) {
        # Each agent has accepted (or refused) a detached job. Record the
        # reqid -> host map; the caller polls GET /status/<reqid> for results.
        Exec::RunStore::record_async(
            reqid => $reqid, script => $script, dispatch_results => $results,
            submitter => { username => $username, source_ip => $peer },
        );
        _send_json($conn, 202, {
            ok => JSON::true, reqid => $reqid, async => JSON::true, results => $results,
        });
        return;
    }

    Exec::RunStore::record_sync(
        reqid => $reqid, script => $script, hosts => $hosts, results => $results,
        submitter => { username => $username, source_ip => $peer },
    );

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
            ok => JSON::false,
            %{ Exec::Auth::deny_fields($auth, $config) },
        });
        return;
    }

    # The API server's SIGCHLD reaper is inherited by request-handler children.
    # Engine forks grandchildren and collects them with waitpid. Without this
    # guard the reaper steals grandchildren before waitpid can collect them,
    # returning a partial results array. local restores the handler on scope exit.
    # Resolve registry names to connect targets through the same path as
    # ping/run, keying results by the canonical registry name.
    my $resolved = Exec::Registry::resolve_dispatch($hosts);
    unless ($resolved->{ok}) {
        _send_error($conn, 404, 'unknown agent',
            'not a registered agent: ' . join(', ', @{ $resolved->{unknown} }));
        return;
    }

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
    print $conn
        "HTTP/1.0 200 OK\r\n",
        "Content-Type: application/json\r\n",
        "Content-Length: ", length($body), "\r\n",
        "\r\n",
        $body;
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
sub _build_live_spec {
    my ($spec, $hostnames, $results) = @_;
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

sub _handle_status {
    my ($conn, $reqid, $peer, $auth_token, $config) = @_;

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
        _send_error($conn, 500, 'server error', 'cannot read result');
        return;
    }
    unless ($record) {
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
        config    => $config,
    );
    unless ($auth->{ok}) {
        # Deny as 404, not 403: do not reveal to an unauthorised caller that the
        # reqid exists (no distinction between "not yours" and "no such run").
        _send_error($conn, 404, 'not found', "no result for reqid $reqid");
        return;
    }

    # Never echo the internal submitter record back to the caller.
    my %public = %$record;
    delete $public{submitter};
    _send_json($conn, 200, { ok => JSON::true, %public });
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
    Exec::Http::send_json($conn, $status, $data);
}

sub _send_error {
    my ($conn, $status, $error, $detail) = @_;
    _send_json($conn, $status, {
        ok    => JSON::false,
        error => $error,
        ($detail ? (detail => $detail) : ()),
    });
}

1;
