package Exec::Agent::Server;

# The agent's HTTP request handlers, extracted from bin/ctrl-exec-agent so the
# request-handling core is a testable library rather than inline in a ~1500-line
# program. The bin keeps the CLI/exit-code modes and the accept loop; this module
# owns handle_connection and the per-endpoint handlers plus their small response
# helpers. The runtime version is threaded in from the bin (which carries the
# install-stamped $VERSION) so this module needs no packaging-coupled version
# lookup.

use strict;
use warnings;
use JSON                      qw(encode_json decode_json);
use Sys::Hostname             qw(hostname);

use Exec::Agent::Config       qw();
use Exec::Agent::Runner       qw();
use Exec::Agent::AsyncRunner  qw();
use Exec::Agent::Schema       qw();
use Exec::Agent::AgentPairing qw();
use Exec::Agent::ExecClient   qw();
use Exec::Auth                qw();
use Exec::Http                qw();
use Exec::Log                 qw();

# --- connection handler (runs in forked child) ---
# Reads raw HTTP/1.0 request from IO::Socket::SSL, dispatches, sends response.

sub handle_connection {
    my ($conn, $peer, $allowlist, $config, $revoked, $trusted, $peer_serial, $schemas, $version) = @_;

    # $peer_serial is extracted before fork() in the accept loop - after the
    # parent closes its copy of $conn the SSL object is invalid in the child.
    $peer_serial //= '';

    if (length $peer_serial &&
        Exec::Agent::AgentPairing::serial_revoked($peer_serial, $revoked)) {
        Exec::Log::log_action('WARNING', {
            ACTION => 'revoked-cert',
            PEER   => $peer,
            SERIAL => $peer_serial,
        });
        _send_raw($conn, 403, encode_json({ error => 'certificate revoked' }));
        return;
    }

    # Read request line
    my $request_line = <$conn>;
    unless ($request_line) {
        _send_raw($conn, 400, encode_json({ error => 'empty request' }));
        return;
    }
    chomp $request_line;
    $request_line =~ s/\r//;

    my ($method, $path) = split ' ', $request_line;

    my %headers;
    my $header_count = 0;
    while (my $line = <$conn>) {
        $line =~ s/\r\n$//;
        $line =~ s/\n$//;
        last if $line eq '';
        if (++$header_count > 32) {
            _send_raw($conn, 431, encode_json({ error => 'too many headers' }));
            return;
        }
        if ($line =~ /^([^:]+):\s*(.*)$/) {
            $headers{ lc $1 } = $2;
        }
    }

    # Read body
    my $body = '';
    if (my $len = $headers{'content-length'}) {
        if ($len > 1_048_576) {
            _send_raw($conn, 413, encode_json({ error => 'request too large' }));
            return;
        }
        read $conn, $body, $len;
    }

    if ($method eq 'POST' && $path eq '/run') {
        handle_run($conn, $body, $peer, $allowlist, $config, $trusted, $peer_serial);
    }
    elsif ($method eq 'POST' && $path eq '/ping') {
        handle_ping($conn, $body, $peer, $config, $trusted, $peer_serial, $version);
    }
    elsif ($method eq 'GET' && $path eq '/capabilities') {
        handle_capabilities($conn, $peer, $allowlist, $config, $trusted, $peer_serial, $schemas, $version);
    }
    elsif ($method eq 'GET' && $path =~ m{^/result/([A-Za-z0-9_-]+)\z}) {
        handle_result($conn, $1, $peer, $config, $trusted, $peer_serial);
    }
    elsif ($method eq 'POST' && $path eq '/rotate-serial') {
        handle_rotate_serial($conn, $body, $peer, $config, $trusted, $peer_serial);
    }
    elsif ($method eq 'POST' && $path eq '/renew') {
        handle_renew($conn, $body, $peer, $config);
    }
    elsif ($method eq 'POST' && $path eq '/renew-complete') {
        handle_renew_complete($conn, $body, $peer, $config);
    }
    else {
        _send_raw($conn, 404, encode_json({ error => 'not found' }));
    }
}

# Cert-rotation control-plane operation: trust (or retire) a dispatcher serial.
# This is a built-in the front-end performs directly - NOT a script and NOT run
# via the executor - so it works in both modes, and the trust map (which the
# executor keeps read-only for every action) is only ever written here, by the
# agent's own authenticated, hook-gated handler.
#
# The dispatcher identity is derived from the CALLER's authenticated serial, never
# from the request body: a dispatcher can only add/retire serials under its own
# identity. This chains trust - each new serial is authorised by the
# currently-trusted one, back to the original human-approved pairing.
sub handle_rotate_serial {
    my ($conn, $body, $peer, $config, $trusted, $peer_serial) = @_;

    my $dispatcher = Exec::Agent::AgentPairing::dispatcher_trusted($peer_serial, $trusted);
    unless (defined $dispatcher) {
        _send_raw($conn, 403, encode_json({ error => 'serial mismatch', status => 'forbidden' }));
        Exec::Log::log_action('WARNING', {
            ACTION => 'serial-reject', PEER => $peer, PEER_SERIAL => $peer_serial,
        });
        return;
    }

    my $data       = eval { decode_json($body) } // {};
    my $new_serial = $data->{serial};
    my $action     = $data->{action} // 'add';
    unless (defined $new_serial && length $new_serial) {
        _send_json($conn, { status => 'error', error => 'serial required' });
        return;
    }
    unless ($action eq 'add' || $action eq 'remove') {
        _send_json($conn, { status => 'error', error => "invalid action '$action'" });
        return;
    }

    # Auth hook (action 'rotate'), so operators can gate rotation per dispatcher.
    if ($config->{auth_hook}) {
        my $auth = Exec::Auth::check(
            action            => 'rotate',
            config            => $config,
            script            => '',
            args              => [ $action, $new_serial ],
            username          => '',
            token             => $data->{token} // '',
            source_ip         => $peer,
            dispatcher        => $dispatcher,
            dispatcher_serial => $peer_serial,
        );
        unless ($auth->{ok}) {
            Exec::Log::log_action('WARNING', {
                ACTION => 'rotate-deny', DISPATCHER => $dispatcher, REASON => $auth->{reason},
            });
            _send_raw($conn, 403, encode_json({ error => 'not authorised: ' . $auth->{reason} }));
            return;
        }
    }

    my $trusted_path = $config->{trusted_dispatchers_path}
                    // '/var/lib/ctrl-exec-agent/ctrl-exec-dispatchers';

    my $ok = eval {
        if ($action eq 'add') {
            Exec::Agent::AgentPairing::add_trusted_dispatcher(
                path => $trusted_path, serial => $new_serial, id => $dispatcher);
        }
        else {
            # Retire: only a serial that currently belongs to THIS dispatcher's
            # identity - never another dispatcher's, and a no-op if absent.
            my $hex = Exec::Agent::AgentPairing::serial_to_hex($new_serial);
            my $map = Exec::Agent::AgentPairing::load_trusted_dispatchers(path => $trusted_path);
            die "serial not owned by '$dispatcher'\n"
                if exists $map->{$hex} && $map->{$hex} ne $dispatcher;
            Exec::Agent::AgentPairing::remove_trusted_dispatcher(
                path => $trusted_path, serial => $new_serial);
        }
        1;
    };
    unless ($ok) {
        my $err = $@ || 'rotation failed'; chomp $err;
        Exec::Log::log_action('ERR', {
            ACTION => 'rotate-fail', DISPATCHER => $dispatcher, ERROR => $err,
        });
        _send_json($conn, { status => 'error', error => $err });
        return;
    }

    # Make the running agent (this child's parent) reload its in-memory trust map
    # so the change takes effect for subsequent connections - same mechanism the
    # operator's SIGHUP reload uses.
    kill 'HUP', getppid();

    Exec::Log::log_action('INFO', {
        ACTION => 'rotate', DISPATCHER => $dispatcher,
        SERIAL_ACTION => $action, SERIAL => $new_serial, PEER => $peer,
    });
    _send_json($conn, {
        status => 'ok', action => $action, serial => $new_serial, dispatcher => $dispatcher,
    });
}

sub handle_run {
    my ($conn, $body, $peer, $allowlist, $config, $trusted, $peer_serial) = @_;

    my $dispatcher = Exec::Agent::AgentPairing::dispatcher_trusted($peer_serial, $trusted);
    unless (defined $dispatcher) {
        _send_raw($conn, 403, encode_json({ error => 'serial mismatch', status => 'forbidden' }));
        Exec::Log::log_action('WARNING', {
            ACTION      => 'serial-reject',
            PEER        => $peer,
            PEER_SERIAL => $peer_serial,
            REQID       => '(none)',
        });
        return;
    }

    my $data = eval { decode_json($body) };
    if ($@) {
        _send_json($conn, { exit => -1, error => 'invalid JSON' });
        return;
    }

    my $name     = $data->{script}   // '';
    my $args     = $data->{args}     // [];
    my $reqid    = $data->{reqid}    // '';
    my $username = $data->{username} // '';
    my $token    = $data->{token}    // '';

    unless (ref $args eq 'ARRAY') {
        _send_json($conn, { exit => -1, error => 'args must be an array', reqid => $reqid });
        return;
    }

    my $script_path = Exec::Agent::Config::validate_script(
        $name, $allowlist, $config->{script_dirs}
    );

    unless ($script_path) {
        Exec::Log::log_action('WARNING', {
            ACTION => 'deny',
            SCRIPT => $name,
            PEER   => $peer,
            REQID  => $reqid,
        });
        _send_json($conn, {
            script => $name,
            exit   => -1,
            error  => 'script not permitted',
            reqid  => $reqid,
        });
        return;
    }

    # Agent auth hook - called after allowlist validation
    if ($config->{auth_hook}) {
        my $auth = Exec::Auth::check(
            action            => 'run',
            config            => $config,
            script            => $name,
            args              => $args,
            username          => $username,
            token             => $token,
            source_ip         => $peer,
            dispatcher        => $dispatcher,
            dispatcher_serial => $peer_serial,
        );
        unless ($auth->{ok}) {
            Exec::Log::log_action('WARNING', {
                ACTION     => 'deny',
                REASON     => $auth->{reason},
                SCRIPT     => $name,
                PEER       => $peer,
                DISPATCHER => $dispatcher,
                REQID      => $reqid,
            });
            _send_json($conn, {
                script => $name,
                exit   => -1,
                error  => 'not authorised: ' . $auth->{reason},
                reqid  => $reqid,
            });
            return;
        }
    }

    my $context = {
        script     => $name,
        args       => $args,
        reqid      => $reqid,
        peer_ip    => $peer,
        username   => $username,
        token      => $token,
        dispatcher => $dispatcher,
        timestamp  => POSIX::strftime('%Y-%m-%dT%H:%M:%SZ', gmtime),
    };

    # Asynchronous path: start the script detached, persist its result to the
    # agent's run store keyed by reqid, and return 202 immediately. The caller
    # fetches the result later via GET /result/<reqid>. A valid reqid is
    # required because it is the store key.
    if ($data->{async}) {
        # Async runs still go through the in-process AsyncRunner, which would not
        # apply the script's security profile. Rather than silently run an async
        # job with the wrong (front-end) privilege, refuse it while the executor
        # is configured. Async-through-executor is a follow-on (2c).
        if ($config->{executor_socket}) {
            _send_json($conn, {
                script => $name, exit => -1, reqid => $reqid,
                error  => 'async runs are not yet supported with the executor '
                        . '(privilege separation); run synchronously',
            });
            return;
        }
        unless (length $reqid && $reqid =~ /^[A-Za-z0-9_-]+\z/) {
            _send_json($conn, {
                script => $name, exit => -1, reqid => $reqid,
                error  => 'async run requires a valid reqid',
            });
            return;
        }

        my $sub = Exec::Agent::AsyncRunner::submit(
            reqid         => $reqid,
            script        => $name,
            script_path   => $script_path,
            args          => $args,
            context       => $context,
            owner         => $dispatcher,
            runs_dir      => _async_runs_dir($config),
            stdin_timeout => $config->{stdin_timeout} // 10,
        );

        if (!$sub->{ok} && ($sub->{reason} // '') eq 'busy') {
            Exec::Log::log_action('WARNING', {
                ACTION => 'run-async-busy',
                SCRIPT => $name,
                PEER   => $peer,
                REQID  => $reqid,
            });
            _send_raw($conn, 409, encode_json({
                script => $name, status => 'busy', reqid => $reqid,
                error  => 'script already running',
            }));
            return;
        }
        if (!$sub->{ok}) {
            _send_json($conn, {
                script => $name, exit => -1, reqid => $reqid,
                error  => 'could not start async job',
            });
            return;
        }

        Exec::Log::log_action('INFO', {
            ACTION     => 'run-async',
            SCRIPT     => $name,
            PEER       => $peer,
            DISPATCHER => $dispatcher,
            REQID      => $reqid,
        });
        _send_raw($conn, 202, encode_json({
            script => $name, status => 'accepted', reqid => $reqid,
        }));
        return;
    }

    # Run path. With an executor_socket configured (privilege separation), hand
    # the run to the privileged executor, which re-derives the path and profile
    # from its own config and applies the profile before exec. Otherwise run it
    # directly (legacy, unprivileged-front-end-only). The executor resolves the
    # script by name; the context JSON goes to the script's stdin as before.
    my $result;
    if ($config->{executor_socket}) {
        require Exec::Agent::ExecClient;
        my $r = Exec::Agent::ExecClient::run(
            socket        => $config->{executor_socket},
            reqid         => $reqid,
            dispatcher_id => $dispatcher,
            script        => $name,
            args          => $args,
            stdin         => encode_json($context),
        );
        $result = {
            exit   => $r->{exit},
            stdout => $r->{stdout} // '',
            stderr => $r->{stderr} // ($r->{error} // ''),
        };
    }
    else {
        $result = Exec::Agent::Runner::run_script(
            $script_path, $args, $context,
            $config->{stdin_timeout} // 10,
        );
    }

    Exec::Log::log_action('INFO', {
        ACTION     => 'run',
        SCRIPT     => $name,
        EXIT       => $result->{exit},
        PEER       => $peer,
        DISPATCHER => $dispatcher,
        REQID      => $reqid,
    });

    _send_json($conn, {
        script => $name,
        exit   => $result->{exit},
        stdout => $result->{stdout},
        stderr => $result->{stderr},
        reqid  => $reqid,
    });
}

sub handle_ping {
    my ($conn, $body, $peer, $config, $trusted, $peer_serial, $version) = @_;

    my $dispatcher = Exec::Agent::AgentPairing::dispatcher_trusted($peer_serial, $trusted);
    unless (defined $dispatcher) {
        _send_raw($conn, 403, encode_json({ error => 'serial mismatch', status => 'forbidden' }));
        Exec::Log::log_action('WARNING', {
            ACTION      => 'serial-reject',
            PEER        => $peer,
            PEER_SERIAL => $peer_serial,
            REQID       => '(none)',
        });
        return;
    }

    my $data  = eval { decode_json($body) } // {};
    my $reqid = $data->{reqid} // '';

    my $status = Exec::Agent::AgentPairing::pairing_status();

    Exec::Log::log_action('INFO', {
        ACTION     => 'ping',
        PEER       => $peer,
        DISPATCHER => $dispatcher,
        REQID      => $reqid,
    });

    # Report whether a renewed cert is already staged (awaiting the next restart
    # to be adopted), so the dispatcher does not re-renew on every maintenance run
    # while a cert sits staged - the live expiry still reads old until restart.
    my $staged_path = ($config && $config->{cert_staging_path})
                   // '/var/lib/ctrl-exec-agent/agent.crt.staged';

    _send_json($conn, {
        status  => 'ok',
        host    => fqdn(),
        version => $version,
        expiry  => $status->{expiry} // 'unknown',
        staged  => (-f $staged_path ? JSON::true : JSON::false),
        reqid   => $reqid,
    });
}

# POST /renew - the dispatcher asks the agent to begin a cert renewal. The agent
# generates a CSR from its EXISTING key (key continuity preserved - no new key)
# carrying its current identity (CN), and returns it. Intentionally exempt from
# the trusted-dispatcher map check: during a dispatcher cert rotation the caller
# may present a new serial not yet in the map. mTLS with a CA-signed cert still
# applies (enforced at the TLS layer). See docs/SECURITY.md, Cert Rotation.
sub handle_renew {
    my ($conn, $body, $peer, $config) = @_;

    my $data  = eval { decode_json($body) } // {};
    my $reqid = $data->{reqid} // '';

    my $key = $config->{key};
    unless (defined $key && -f $key) {
        _send_json($conn, { status => 'error', error => 'agent key not available' });
        return;
    }

    my $r = eval {
        Exec::Agent::AgentPairing::generate_csr_only(hostname => fqdn(), key_path => $key);
    };
    if (!$r || !$r->{csr_pem}) {
        Exec::Log::log_action('ERR', {
            ACTION => 'renew', PEER => $peer, REQID => $reqid,
            ERROR  => ($@ || 'CSR generation failed'),
        });
        _send_json($conn, { status => 'error', error => 'could not generate CSR' });
        return;
    }

    Exec::Log::log_action('INFO', {
        ACTION => 'renew', PEER => $peer, REQID => $reqid, STATUS => 'csr-generated',
    });
    _send_json($conn, { status => 'ok', csr => $r->{csr_pem}, reqid => $reqid });
}

# POST /renew-complete - the dispatcher delivers the signed cert. The agent
# validates it (verifies against its CA and that the public key matches its own
# key) and writes it, atomically, to the staging file in its own writable state
# dir. The cert is public material the agent owns, so it stages it itself - no
# privileged writer needed. The live cert (root-owned) is replaced from the
# staged copy by a root step at the next agent start (promote-cert), and the
# server adopts it on that restart. The existing cert stays valid in the meantime
# (renewal runs well before expiry). Exempt from the trusted-map check; mTLS
# still applies.
sub handle_renew_complete {
    my ($conn, $body, $peer, $config) = @_;

    my $data  = eval { decode_json($body) } // {};
    my $reqid = $data->{reqid} // '';
    my $cert  = $data->{cert};

    unless (defined $cert && length $cert) {
        _send_json($conn, { status => 'error', error => 'cert required' });
        return;
    }

    my $staged = $config->{cert_staging_path}
              // '/var/lib/ctrl-exec-agent/agent.crt.staged';

    my $r = Exec::Agent::AgentPairing::stage_renewed_cert(
        cert_pem    => $cert,
        ca_path     => $config->{ca},
        key_path    => $config->{key},
        staged_path => $staged,
    );

    if ($r->{ok}) {
        Exec::Log::log_action('INFO', {
            ACTION => 'renew-complete', PEER => $peer, REQID => $reqid, STATUS => 'cert-staged',
        });
        _send_json($conn, { status => 'ok', reqid => $reqid, staged => JSON::true });
    }
    else {
        Exec::Log::log_action('ERR', {
            ACTION => 'renew-complete', PEER => $peer, REQID => $reqid, ERROR => $r->{error},
        });
        _send_json($conn, { status => 'error', error => $r->{error} });
    }
}

sub handle_capabilities {
    my ($conn, $peer, $allowlist, $config, $trusted, $peer_serial, $schemas, $version) = @_;

    $peer_serial //= '';
    $trusted     //= {};
    $schemas     //= {};

    # Restrict /capabilities to a trusted dispatcher cert.
    # Each entry in the trusted-dispatcher map was recorded at pairing time from
    # the dispatcher's own cert. Any CA-signed peer whose serial is not in the
    # map is rejected - this closes lateral reconnaissance from a compromised
    # agent peer. The resolved identity also attributes the discovery.
    #
    # Fail closed when the map is empty (agent not yet paired, or its map was
    # lost): an empty map means no dispatcher is trusted, so the allowlist - the
    # script names, paths and schemas - is not disclosed to any CA-signed peer.
    # This matches /run, /ping, /rotate-serial and /result, which all hard-deny
    # on an unresolved dispatcher. Re-pair to repopulate the map.
    my $dispatcher = Exec::Agent::AgentPairing::dispatcher_trusted($peer_serial, $trusted);
    unless (defined $dispatcher) {
        Exec::Log::log_action('WARNING', {
            ACTION      => 'capabilities-deny',
            PEER        => $peer,
            PEER_SERIAL => $peer_serial,
            REASON      => (%$trusted ? 'serial-mismatch'
                                      : 'no trusted dispatchers stored'),
        });
        _send_raw($conn, 403, encode_json({ error => 'forbidden' }));
        return;
    }

    # Auth hook - called after serial check, before building scripts list.
    # username and token are not present on /capabilities requests (no body);
    # hooks that require a token will correctly deny unauthenticated callers.
    if ($config->{auth_hook}) {
        my $auth = Exec::Auth::check(
            action            => 'discovery',
            config            => $config,
            script            => '',
            args              => [],
            username          => '',
            token             => '',
            source_ip         => $peer,
            dispatcher        => $dispatcher,
            dispatcher_serial => $peer_serial,
        );
        unless ($auth->{ok}) {
            Exec::Log::log_action('WARNING', {
                ACTION     => 'capabilities-deny',
                PEER       => $peer,
                DISPATCHER => $dispatcher,
                REASON     => $auth->{reason},
            });
            _send_raw($conn, 403, encode_json({ error => 'not authorised' }));
            return;
        }
    }

    my @scripts;
    for my $name (sort keys %$allowlist) {
        my $path  = Exec::Agent::Config::validate_script($name, $allowlist);
        my $entry = {
            name       => $name,
            path       => $path,
            executable => ((defined $path && -x $path) ? JSON::true : JSON::false),
            profile    => Exec::Agent::Config::script_profile($name, $allowlist),
        };
        # Advertise the script's schema sidecar when present (the agent only
        # transports it; the consumer interprets it). See docs/SCHEMA-SIDECAR.md.
        if (my $sc = $schemas->{$name}) {
            $entry->{schema}         = $sc->{schema};
            $entry->{schema_version} = $sc->{schema_version};
        }
        push @scripts, $entry;
    }

    Exec::Log::log_action('INFO', {
        ACTION     => 'capabilities',
        PEER       => $peer,
        DISPATCHER => $dispatcher,
        SCRIPTS    => scalar @scripts,
    });

    _send_json($conn, {
        status  => 'ok',
        host    => fqdn(),
        version => $version,
        scripts => \@scripts,
        tags    => $config->{tags} // {},
    });
}

# Return the stored result for an async run keyed by reqid.
# Gated by the same dispatcher-serial check as /run: only the genuine
# ctrl-exec cert may fetch results. The reqid is a 64-bit unguessable token,
# so an agent only holds a result for a reqid it actually ran.
#
# Responses:
#   200 { status => 'running', ... }   job still detached
#   200 { status => 'done', exit, stdout, stderr, ... }
#   404 { status => 'unknown' }        no record (never ran here, or TTL-purged)
sub handle_result {
    my ($conn, $reqid, $peer, $config, $trusted, $peer_serial) = @_;

    my $dispatcher = Exec::Agent::AgentPairing::dispatcher_trusted($peer_serial, $trusted);
    unless (defined $dispatcher) {
        _send_raw($conn, 403, encode_json({ error => 'serial mismatch', status => 'forbidden' }));
        Exec::Log::log_action('WARNING', {
            ACTION      => 'serial-reject',
            PEER        => $peer,
            PEER_SERIAL => $peer_serial,
            REQID       => $reqid,
        });
        return;
    }

    my $record = Exec::Agent::AsyncRunner::result($reqid, _async_runs_dir($config), $dispatcher);

    unless ($record) {
        Exec::Log::log_action('INFO', {
            ACTION     => 'result-miss',
            PEER       => $peer,
            DISPATCHER => $dispatcher,
            REQID      => $reqid,
        });
        _send_raw($conn, 404, encode_json({ status => 'unknown', reqid => $reqid }));
        return;
    }

    # Owner-gate: a run's result is returned only to the dispatcher that
    # submitted it. A trusted-but-different dispatcher is answered exactly as if
    # the reqid were unknown - never confirming the run exists, and never
    # disclosing another dispatcher's output.
    unless (Exec::Agent::AsyncRunner::owned_by($record, $dispatcher)) {
        Exec::Log::log_action('WARNING', {
            ACTION     => 'result-deny',
            PEER       => $peer,
            DISPATCHER => $dispatcher,
            REQID      => $reqid,
            REASON     => 'not-owner',
        });
        _send_raw($conn, 404, encode_json({ status => 'unknown', reqid => $reqid }));
        return;
    }

    Exec::Log::log_action('INFO', {
        ACTION     => 'result',
        PEER       => $peer,
        DISPATCHER => $dispatcher,
        REQID      => $reqid,
        STATUS     => $record->{status} // 'unknown',
    });
    _send_json($conn, $record);
}

# Resolve the agent-side async run store directory from config, with the
# packaged default.
sub _async_runs_dir {
    my ($config) = @_;
    return $config->{async_runs_dir} // '/var/lib/ctrl-exec-agent/runs';
}

# Extract the peer certificate serial number from an IO::Socket::SSL
# connection as a lowercase hex string.
# IO::Socket::SSL's peer_certificate('serialNumber') is not supported in
# all versions - use Net::SSLeay directly to read the ASN1 integer.
# Returns '' if no peer cert or serial cannot be read.
sub _peer_serial {
    my ($conn) = @_;
    my $ssl  = eval { $conn->_get_ssl_object } or return '';
    my $cert = eval { Net::SSLeay::get_peer_certificate($ssl) } or return '';
    my $asn1 = eval { Net::SSLeay::X509_get_serialNumber($cert) } or return '';
    my $hex  = eval { Net::SSLeay::P_ASN1_INTEGER_get_hex($asn1) } // '';
    return lc $hex;
}

sub _send_json {
    my ($conn, $data) = @_;
    _send_raw($conn, 200, encode_json($data));
}

sub _send_raw {
    my ($conn, $code, $body) = @_;
    Exec::Http::send_raw($conn, $code, $body);
}


# The agent's fully-qualified hostname. This is the value reported at pairing -
# which becomes the dispatcher's registry key and, under lookup_by=hostname, the
# address it connects back on - and the self-reported host in run/capabilities
# responses. A bare short hostname (what Sys::Hostname::hostname returns on most
# hosts) does not resolve across subdomains, so a dispatcher on a different
# network cannot reach the agent by it; an FQDN also stays consistent if the
# dispatcher itself moves. Prefer Net::Domain::hostfqdn(); fall back to the short
# name only when no domain is configured. Memoised - the name does not change
# while the process runs, and the serve path calls this per request.
my $FQDN;
sub fqdn {
    return $FQDN if defined $FQDN;
    my $f = eval { require Net::Domain; Net::Domain::hostfqdn() };
    $FQDN = (defined $f && length $f && $f =~ /\./) ? $f : hostname();
    return $FQDN;
}

1;
