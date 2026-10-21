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
use feature                   qw(signatures);
no warnings                   qw(experimental::signatures);
use JSON                      qw(encode_json decode_json);
use Sys::Hostname             qw(hostname);
use POSIX                      qw();
use Time::HiRes               qw();
use Errno                     qw(EINTR EAGAIN EWOULDBLOCK ECONNABORTED EBADF EINVAL ENOTSOCK);

use Exec::Agent::Config       qw();
use Exec::Agent::Runner       qw();
use Exec::Agent::AsyncRunner  qw();
use Exec::Agent::Schema       qw();
use Exec::Agent::AgentPairing qw();
use Exec::Agent::ExecClient   qw();
use Exec::CertInfo            qw();
use Exec::Auth                qw();
use Exec::Http                qw();
use Exec::Input               qw();
use Exec::Log                 qw();

# --- connection handler (runs in forked child) ---
# Reads raw HTTP/1.0 request from IO::Socket::SSL, dispatches, sends response.

# Authenticate the calling dispatcher by its cert serial against the trusted map.
# Returns the dispatcher id on success. On a serial mismatch it sends the 403,
# logs a serial-reject (with the request's reqid, or '(none)' where there is none
# yet), and returns undef - the caller then returns. The single place run/ping/
# rotate-serial/result enforce the trusted-serial gate.
sub _require_dispatcher ($conn, $peer, $peer_serial, $trusted, $reqid = undef) {
    my $dispatcher = Exec::Agent::AgentPairing::dispatcher_trusted($peer_serial, $trusted);
    return $dispatcher if defined $dispatcher;
    _send_raw($conn, 403, encode_json({ error => 'serial mismatch', status => 'forbidden' }));
    Exec::Log::log_action('WARNING', {
        ACTION      => 'serial-reject',
        PEER        => $peer,
        PEER_SERIAL => $peer_serial,
        REQID       => (defined $reqid ? $reqid : '(none)'),
    });
    return;
}

sub handle_connection ($conn, $peer, $allowlist, $config, $revoked, $trusted, $peer_serial = undef, $schemas = undef, $version = undef, $skipped = undef) {
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
        # Room for confidential run input (T-013); same limit as the API.
        if ($len > Exec::Input::max_body($config)) {
            _send_raw($conn, 413, encode_json({ error => 'request too large' }));
            return;
        }
        read $conn, $body, $len;
    }

    if ($method eq 'POST' && $path eq '/run') {
        handle_run($conn, $body, $peer, $allowlist, $config, $trusted, $peer_serial, $skipped);
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
sub handle_rotate_serial ($conn, $body, $peer, $config, $trusted, $peer_serial) {
    my $dispatcher = _require_dispatcher($conn, $peer, $peer_serial, $trusted);
    return unless defined $dispatcher;

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
            my $hex = Exec::CertInfo::serial_to_hex($new_serial);
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

sub handle_run ($conn, $body, $peer, $allowlist, $config, $trusted, $peer_serial, $skipped = undef) {
    my $dispatcher = _require_dispatcher($conn, $peer, $peer_serial, $trusted);
    return unless defined $dispatcher;

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

    # Real boundary for args typing: refuse refs/undef before allowlist, auth
    # or exec ever see them.
    if (defined(my $problem = Exec::Http::args_problem($args))) {
        _send_json($conn, { exit => -1, error => $problem, reqid => $reqid });
        return;
    }

    # Confidential input (T-013): refuse a bad shape or size before the allowlist,
    # any hook or exec. Errors name fields, never values; nothing below logs,
    # records or forwards the values except the delivery to the script.
    my $input = $data->{input};
    my $iv = Exec::Input::validate($input, Exec::Input::max_bytes($config));
    unless ($iv->{ok}) {
        Exec::Log::log_action('WARNING', {
            ACTION => 'deny', REASON => 'invalid input', SCRIPT => $name,
            PEER => $peer, REQID => $reqid,
        });
        _send_json($conn, {
            script => $name, exit => -1, reqid => $reqid,
            error  => 'invalid input: ' . $iv->{error},
        });
        return;
    }
    $input = undef unless @{ $iv->{names} };   # {} is no input

    my $script_path = Exec::Agent::Config::validate_script(
        $name, $allowlist, $config->{script_dirs}
    );
    # Re-apply the ownership rule at run time (T-045) when script_ownership is
    # strict: the script or a directory on its path may have changed since the
    # allowlist was loaded. Without an executor this is the enforcement; with
    # one, the executor enforces the same rule and this only refuses early, with
    # the same reason. With 'warn' (T-054, the default) a script that breaks the
    # rule runs; the reason was logged when the allowlist was loaded, and is not
    # logged again on each run.
    my $ownership = $config->{script_ownership} // 'warn';
    $script_path = undef
        if $script_path && $ownership eq 'strict'
        && defined Exec::Agent::Config::script_owner_problem($script_path);

    unless ($script_path) {
        # Say why (T-044): the reason a scripts.conf entry was skipped, or that
        # the name is not in scripts.conf at all.
        my $why = Exec::Agent::Config::not_permitted_reason(
            $name, $allowlist, $skipped, $config->{script_dirs}, $ownership
        );
        Exec::Log::log_action('WARNING', {
            ACTION => 'deny',
            SCRIPT => $name,
            PEER   => $peer,
            REQID  => $reqid,
        });
        _send_json($conn, {
            script => $name,
            exit   => -1,
            error  => "script not permitted: $why",
            reqid  => $reqid,
        });
        return;
    }

    # The script's declared input mode must be satisfiable by this request.
    my $input_mode = Exec::Agent::Config::script_input_mode($name, $allowlist);
    if (defined(my $why = _input_mode_problem($input_mode, $iv->{names}))) {
        Exec::Log::log_action('WARNING', {
            ACTION => 'deny', REASON => 'input does not fit mode', SCRIPT => $name,
            PEER => $peer, REQID => $reqid,
        });
        _send_json($conn, {
            script => $name, exit => -1, reqid => $reqid,
            error  => "invalid input: $why",
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
            input_names       => $iv->{names},
            input_bytes       => $iv->{bytes},
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
    # Confidential output (T-053): a script declared output=confidential in
    # scripts.conf has its stdout and stderr returned to the caller and marked
    # so the dispatcher does not store them. Nothing on the agent logs them.
    my $confidential = Exec::Agent::Config::script_output_mode($name, $allowlist) eq 'confidential';

    if ($data->{async}) {
        # An async result exists to be stored (here until fetched, then in the
        # dispatcher's run store until polled), so a script whose output must
        # never be stored cannot run async. Refused before anything is started
        # or recorded.
        if ($confidential) {
            Exec::Log::log_action('WARNING', {
                ACTION => 'deny', REASON => 'async run of an output=confidential script',
                SCRIPT => $name, PEER => $peer, REQID => $reqid,
            });
            _send_json($conn, {
                script => $name, exit => -1, reqid => $reqid,
                error  => "script '$name' is output=confidential: its output is never "
                        . 'stored, so it cannot run async; run it synchronously',
            });
            return;
        }
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
            input         => $input,
            input_mode    => $input_mode,
            input_tmpdir  => $config->{input_dir},
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
        # Confidential input (T-013): the executor takes the input mode from its
        # own scripts.conf, so it is given everything any mode needs, built as
        # Runner builds it: the stdin JSON for input=context (with 'input' when
        # there is any), the CTRL_EXEC_CONTEXT JSON for raw and fields (no input,
        # and no token: the environment reaches every child the script starts),
        # and the fields. With no input for an input=context script the frame
        # is the old one, so such runs work with an executor of either age.
        my %frame_input;
        if ($input || $input_mode ne 'context') {
            my %ctx = %$context;
            delete $ctx{token};
            %frame_input = (context => encode_json(\%ctx), input => $input // {});
        }
        my $r = Exec::Agent::ExecClient::run(
            socket        => $config->{executor_socket},
            reqid         => $reqid,
            dispatcher_id => $dispatcher,
            script        => $name,
            args          => $args,
            stdin         => encode_json($input ? { %$context, input => $input } : $context),
            %frame_input,
        );
        if ($r->{executor_no_input}) {
            Exec::Log::log_action('ERR', {
                ACTION => 'deny', REASON => 'executor does not support input',
                SCRIPT => $name, PEER => $peer, REQID => $reqid,
            });
            _send_json($conn, {
                script => $name, exit => -1, reqid => $reqid, error => $r->{error},
            });
            return;
        }
        if ($r->{executor_unavailable}) {
            Exec::Log::log_action('ERR', {
                ACTION => 'executor-unavailable',
                SCRIPT => $name,
                PEER   => $peer,
                REQID  => $reqid,
                ERROR  => $r->{error},
            });
        }
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
            { mode => $input_mode, input => $input, tmpdir => $config->{input_dir} },
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
        ($confidential ? (output_confidential => JSON::true) : ()),
    });
}

# Why the request's input fields cannot be delivered in the script's input mode
# (undef when they can). Names fields, never values.
sub _input_mode_problem ($mode, $names) {
    if ($mode eq 'raw') {
        return 'script takes input=raw: exactly one input field is required, got ' . scalar(@$names)
            unless @$names == 1;
    }
    elsif ($mode =~ /\Araw:(.+)\z/s) {
        my $want = $1;
        return "script takes input=raw:$want but input field '$want' is missing"
            unless grep { $_ eq $want } @$names;
    }
    return;
}

sub handle_ping ($conn, $body, $peer, $config, $trusted, $peer_serial, $version) {
    my $dispatcher = _require_dispatcher($conn, $peer, $peer_serial, $trusted);
    return unless defined $dispatcher;

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
sub handle_renew ($conn, $body, $peer, $config) {
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
sub handle_renew_complete ($conn, $body, $peer, $config) {
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

sub handle_capabilities ($conn, $peer, $allowlist, $config, $trusted, $peer_serial = undef, $schemas = undef, $version = undef) {
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
            profile    => scalar(Exec::Agent::Config::script_profile($name, $allowlist)),
            input      => Exec::Agent::Config::script_input_mode($name, $allowlist),
            output     => Exec::Agent::Config::script_output_mode($name, $allowlist),
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
sub handle_result ($conn, $reqid, $peer, $config, $trusted, $peer_serial) {
    my $dispatcher = _require_dispatcher($conn, $peer, $peer_serial, $trusted, $reqid);
    return unless defined $dispatcher;

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
sub _async_runs_dir ($config) {
    return $config->{async_runs_dir} // '/var/lib/ctrl-exec-agent/runs';
}

# Extract the peer certificate serial number from an IO::Socket::SSL
# connection as a lowercase hex string.
# IO::Socket::SSL's peer_certificate('serialNumber') is not supported in
# all versions - use Net::SSLeay directly to read the ASN1 integer.
# Returns '' if no peer cert or serial cannot be read.
#
# Public (not _private): the agent's accept loop calls this from the bin BEFORE
# it forks - the serial must be read in the parent while the SSL object is still
# valid - so it is part of this module's cross-package interface alongside
# handle_connection, not an internal helper.
sub peer_serial ($conn) {
    my $ssl  = eval { $conn->_get_ssl_object } or return '';
    # SSL_get_peer_certificate hands back a counted reference that the caller
    # owns and must X509_free. This runs in the long-lived accept-loop parent
    # once per connection; without the free it leaked one parsed certificate
    # per connection (~230 MB RSS after two weeks of dashboard polling).
    my $cert = eval { Net::SSLeay::get_peer_certificate($ssl) } or return '';
    my $hex  = eval {
        my $asn1 = Net::SSLeay::X509_get_serialNumber($cert) or die "no serial\n";
        Net::SSLeay::P_ASN1_INTEGER_get_hex($asn1);
    } // '';
    Net::SSLeay::X509_free($cert);
    return lc $hex;
}

# Bounds for draining a refused connection (see drain_refused).
use constant DRAIN_MAX_BYTES => 65536;
use constant DRAIN_TIMEOUT   => 1;

# After a refusal (the 429) has been written on $conn: send close_notify, half-
# close the write side, then read and discard whatever the client already sent
# until it closes, DRAIN_MAX_BYTES have arrived or DRAIN_TIMEOUT seconds (in
# total, not per read) have passed. Closing a socket with unread data makes the
# kernel send a reset, which can discard the reply before the client reads it.
# This runs in the accept-loop parent, so the bound is also the longest one
# refused client can hold the loop. The raw descriptor is read, not the SSL
# handle: the bytes are discarded, so they need not be decrypted.
sub drain_refused ($conn) {
    my $fd = fileno($conn);
    return unless defined $fd;
    my $ssl = eval { $conn->_get_ssl_object };
    eval { Net::SSLeay::shutdown($ssl) } if $ssl;
    shutdown($conn, 1);
    my $got = 0;
    my $buf;
    my $deadline = Time::HiRes::time() + DRAIN_TIMEOUT;
    while ($got < DRAIN_MAX_BYTES) {
        my $left = $deadline - Time::HiRes::time();
        last if $left <= 0;
        my $rin = '';
        vec($rin, $fd, 1) = 1;
        my $n = select(my $rout = $rin, undef, undef, $left);
        next if $n < 0 && $! == EINTR;
        last if $n <= 0;
        my $r = POSIX::read($fd, $buf, 4096);
        last if !defined $r && $! != EINTR && $! != EAGAIN;
        last if defined $r && $r == 0;
        $got += $r if $r;
    }
    return;
}

# Seconds the serve loop allows a connecting peer to complete the TLS handshake
# (the whole handshake, not each read). It runs in the accept-loop parent, so
# this is also the longest one silent client can hold the loop for everyone else.
use constant HANDSHAKE_TIMEOUT => 5;

# Classify a failed $server->accept for the serve loop. $errno is $!+0 captured
# IMMEDIATELY after accept returned undef (any later call clobbers it), $ssl_err
# is $IO::Socket::SSL::SSL_ERROR at that moment. Returns:
#   'retry'     - interrupted or transient (EINTR from a SIGHUP reload, EAGAIN,
#                 ECONNABORTED): go straight back to accept.
#   'fatal'     - the listening socket itself is gone/invalid (EBADF, EINVAL,
#                 ENOTSOCK): nothing further can be accepted, exit the loop.
#   'handshake' - everything else: a peer that failed the TLS handshake, or a
#                 peer-side reset mid-handshake. Count it for the probe limit
#                 and carry on serving.
# The pre-0.12.4 loop asked the LISTENING socket for its peerhost before testing
# $!, which always sets ENOTCONN, so every failed accept - a stranger's bad
# handshake, or the EINTR a reload produces - looked fatal and stopped the agent.
sub accept_failure_action ($errno, $ssl_err) {
    $errno   //= 0;
    $ssl_err //= '';
    return 'retry' if $errno == EINTR || $errno == EAGAIN
                   || $errno == EWOULDBLOCK || $errno == ECONNABORTED;
    return 'fatal' if $errno == EBADF || $errno == EINVAL || $errno == ENOTSOCK;
    return 'handshake';
}

sub _send_json ($conn, $data) {
    _send_raw($conn, 200, encode_json($data));
}

sub _send_raw ($conn, $code, $body) {
    Exec::Http::send_raw($conn, $code, $body);
}


# What identifies the on-disk state of the given files (T-059): device, inode,
# size, modification and change time (sub-second), or 'missing'. The serve loop
# keeps the signature of agent.conf and scripts.conf as last read and reloads
# both when it differs, so an edit is picked up at the next connection - by a
# rename (new inode), an in-place write (size, mtime) or a chmod (ctime).
sub config_files_signature (@paths) {
    return join '|', map {
        my @st = Time::HiRes::stat($_);
        @st ? join(':', @st[0, 1, 7, 9, 10]) : 'missing';
    } @paths;
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
