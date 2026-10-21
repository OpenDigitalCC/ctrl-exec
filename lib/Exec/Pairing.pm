package Exec::Pairing;

use strict;
use warnings;
use feature      qw(signatures);
no warnings      qw(experimental::signatures);
use File::Path  qw(make_path);
use File::Temp  qw(tempfile);
use Fcntl       qw(:flock);
use JSON        qw(encode_json decode_json);
use POSIX       qw(strftime);
use Carp        qw(croak);
use Exec::CertInfo qw();
use Exec::Digest   qw();
use Exec::FileUtil qw(slurp);
use Exec::Random   qw();
use Sys::Hostname qw(hostname);
use Exec::Pairing::Identity qw();

use Exec::RateLimit qw();
use Exec::Http      qw();
use Exec::DispatcherConfig qw();


my $PAIRING_DIR = '/var/lib/ctrl-exec/pairing';

# Upper bound on a pairing request body before we read it. The only legitimate
# body is a JSON wrapper around a CSR (itself capped at 10 KiB by sign_csr), so
# 64 KiB is generous. The pairing port is unauthenticated by design (bootstrap),
# so without this an attacker could declare a huge Content-Length and make the
# child buffer it - a memory-exhaustion DoS. Mirrors the operational server's
# pre-read cap.
my $MAX_PAIR_BODY = 64 * 1024;

# Cache of the dispatcher's served-cert serial, keyed by path + mtime. approve
# reads it on every approval; long-running interactive pairing mode re-forked
# openssl per approval. The cert changes only on rotation, which rewrites the
# file (new mtime) and invalidates the entry, so the cache is always correct.
my %DISP_SERIAL_CACHE;
sub _cached_disp_serial ($cert_path) {
    return '' unless defined $cert_path && -f $cert_path;
    my $mtime = (stat $cert_path)[9] // 0;
    my $c = $DISP_SERIAL_CACHE{$cert_path};
    return $c->{serial} if $c && $c->{mtime} == $mtime;
    my $serial = Exec::CertInfo::serial_from_path($cert_path) // '';
    $DISP_SERIAL_CACHE{$cert_path} = { mtime => $mtime, serial => $serial };
    return $serial;
}


# Build a rate-limit config hashref for the pairing port from the dispatcher
# config. The pairing port reuses the operational-port volume limiter
# (Exec::RateLimit); it is volume-only, since the pairing listener requires no
# client certificate and so has no TLS-handshake-failure (probe) vector.
#
# Recognised keys in ctrl-exec.conf:
#   pairing_rate_limit_disable = 1                  disable rate limiting
#   pairing_rate_limit_volume  = limit/window/block e.g. 10/60/300
#
# Absent or malformed values leave the Exec::RateLimit defaults in place.
# Returns a hashref suitable as the third argument to Exec::RateLimit::check.
sub build_rate_config ($config = undef) {
    $config //= {};

    my %rl;
    if ($config->{pairing_rate_limit_disable}
        && $config->{pairing_rate_limit_disable} =~ /^[1y]/i) {
        $rl{disabled} = 1;
    }

    if (my $raw = $config->{pairing_rate_limit_volume}) {
        if (my $t = Exec::RateLimit::parse_limit_spec($raw)) {
            @rl{qw(volume_limit volume_window volume_block)} = @$t;
        }
        # Malformed value: fall back to defaults silently.
    }

    return \%rl;
}

# Resolve this dispatcher's stable identity, delivered to agents at pairing and
# at cert rotation so they attribute and authorise per dispatcher. Explicit
# ctrl-exec.conf 'dispatcher_id' wins; otherwise the host's name. Sanitised to
# the agent's valid_dispatcher_id charset (start alphanumeric, then
# [A-Za-z0-9._-], capped at 64) so the agent never rejects it. Because the id is
# stable across cert rotation - it is not derived from the serial - the agent
# maps a rotated serial to the same identity, leaving trust and attribution
# undisturbed.
sub resolve_dispatcher_id ($config = undef) {
    $config //= {};
    my $id = $config->{dispatcher_id};
    $id = hostname() unless defined $id && length $id;
    $id //= '';
    $id =~ s/[^A-Za-z0-9._-]/-/g;   # map disallowed chars to hyphen
    $id =~ s/^[^A-Za-z0-9]+//;      # must start alphanumeric
    $id = substr($id, 0, 64);
    $id = 'dispatcher' unless length $id;
    return $id;
}

# Start pairing mode - listen on port for agent CSR requests
# Blocks until interrupted (SIGINT/SIGTERM)
sub run_pairing_mode (%opts) {
    my $port      = $opts{port}      // 7444;
    my $ca_dir    = $opts{ca_dir}    // Exec::DispatcherConfig::conf_dir();
    my $cert      = $opts{cert}      or croak "cert required";
    my $key       = $opts{key}       or croak "key required";
    my $log_fn    = $opts{log_fn}    // sub {};
    my $max_queue = $opts{max_queue} // 10;
    my $rate_config = $opts{rate_limit} // {};
    # Absolute session timeout (seconds). When set, pairing mode auto-stops
    # after this many seconds so an unattended or backgrounded window cannot be
    # left open indefinitely. undef/0 means no timeout (legacy behaviour).
    my $timeout   = $opts{timeout};
    my $deadline  = ($timeout && $timeout > 0) ? time + $timeout : undef;
    # This dispatcher's stable identity, threaded to interactive approvals so
    # agents paired here record who paired them (see approve_request).
    my $dispatcher_id = $opts{dispatcher_id} // '';
    # Queue directory; overridable so the listener can be exercised in tests
    # without writing under /var/lib.
    my $pairing_dir = $opts{pairing_dir} // $PAIRING_DIR;

    make_path($pairing_dir) unless -d $pairing_dir;

    _expire_stale_requests($pairing_dir);

    require IO::Socket::SSL;
    require IO::Select;

    # The CA that issued the served certificate. Verified pairing (T-041): an
    # agent run with --dispatcher-fingerprint checks the listener's certificate
    # chains to the CA with that fingerprint, so the listener sends the CA
    # certificate after its own. When the CA cannot be used (absent, or it did
    # not issue the served cert) the listener serves as before and the banner
    # says verified pairing is unavailable.
    my $ca = ca_fingerprint(ca_dir => $ca_dir, cert => $cert);
    $log_fn->({ ACTION => 'pairing-ca-unavailable', REASON => $ca->{error} })
        unless $ca->{ok};

    # Pairing port: TLS server cert only, no client cert required
    require Exec::TLS;
    my $server = IO::Socket::SSL->new(
        LocalPort       => $port,
        Listen          => 5,
        ReuseAddr       => 1,
        SSL_cert_file   => $cert,
        SSL_key_file    => $key,
        SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_NONE(),
        ($ca->{ok} ? (SSL_create_ctx_callback => sub ($ctx) {
            _add_chain_cert($ctx, $ca->{ca_file});
        }) : ()),
        Exec::TLS::hardening(),
    ) or die "Cannot start pairing server: $IO::Socket::SSL::SSL_ERROR\n";
    # The port actually bound: the same as asked for, except for port 0 (any
    # free port, which the tests use), where the log and banner show the real one.
    $port = $server->sockport;

    # Fingerprint of the certificate this listener presents, read from the same
    # file it was just loaded from (and once, so a rotation that rewrites the
    # file mid-session cannot make it disagree with what agents see). The v2
    # pairing code binds to it; see Exec::Digest.
    my $cert_fpr = Exec::CertInfo::fingerprint_from_path($cert)
        // die "Cannot fingerprint the pairing certificate '$cert'\n";

    $log_fn->({ ACTION => 'pairing-mode-start', PORT => $port });

    my $interactive = -t STDIN;
    local $| = 1 if $interactive;  # unbuffered output so prompts appear immediately

    my $auto = $deadline ? " (auto-stops in ${timeout}s)" : "";
    if ($interactive) {
        print "Pairing mode active on port $port$auto. Ctrl-C or 'quit' to stop.\n";
    }
    else {
        print "Pairing mode active on port $port$auto. Ctrl-C to stop.\n";
    }
    print "$_\n" for verified_pairing_lines($ca, $port);
    if ($interactive) {
        print "Waiting for pairing requests...\n";
    }
    else {
        print "Use 'ctrl-exec-dispatcher list-requests' to see pending requests.\n";
    }

    # Stop reason is set by a signal, the deadline, or the interactive 'quit'
    # command; the loop exits on it and a single cleanup path logs and returns
    # (so the caller can reap its renewal-check child on every exit).
    my $stopped = '';
    # local: the handlers end with this sub, so after it returns a signal
    # reaches the caller's own handling (it reaps the renewal-check child).
    my $stop = sub { $stopped ||= 'signal'; };
    local @SIG{qw(INT TERM)} = ($stop, $stop);

    my $sel = IO::Select->new($server);
    $sel->add(\*STDIN) if $interactive;

    # Per-IP rate-limit state for the pairing port, kept in the parent loop.
    my %rate_state;

    while (!$stopped) {
        # Poll at most every 5 seconds to reap finished children, but never
        # sleep past the session deadline.
        my $wait = 5;
        if ($deadline) {
            my $remaining = $deadline - time;
            if ($remaining <= 0) { $stopped = 'timeout'; last; }
            $wait = $remaining if $remaining < $wait;
        }
        my @ready = $sel->can_read($wait);
        last if $stopped;   # a signal arrived during can_read

        waitpid -1, POSIX::WNOHANG();

        for my $fh (@ready) {
            if ($fh == $server) {
                # Incoming pairing connection
                my $conn = $server->accept or next;
                my $peer_ip = $conn->peerhost // 'unknown';

                # Per-IP rate limit (volume) before forking, mirroring the
                # operational port. Exec::RateLimit::check logs the block.
                if (Exec::RateLimit::check($peer_ip, \%rate_state, $rate_config)) {
                    $conn->close(SSL_no_shutdown => 1);
                    next;
                }
                Exec::RateLimit::record_connection($peer_ip, \%rate_state);

                my $pid = fork();
                if (!defined $pid) {
                    warn "fork failed: $!\n";
                    $conn->close;
                    next;
                }
                if ($pid == 0) {
                    $server->close;
                    _handle_pair_request($conn, $peer_ip, $log_fn, $max_queue, $pairing_dir, $cert_fpr);
                    $conn->close;
                    exit 0;
                }
                $conn->close(SSL_no_shutdown => 1);

                if ($interactive) {
                    # Wait (bounded) for the child to write the new queue file,
                    # then prompt. The child writes it early in
                    # _handle_pair_request (before it blocks awaiting approve/deny),
                    # so polling for the file to appear normally returns in tens of
                    # milliseconds - faster than the old fixed 1s sleep, and more
                    # robust than a timing assumption: it waits (up to ~1s) until
                    # the request is actually queued, without complicating the
                    # fork/select loop with a child->parent pipe. A rejected
                    # request (no file written) simply falls through at the cap.
                    my $before = () = glob "$pairing_dir/*.json";
                    for (1 .. 20) {
                        last if (() = glob "$pairing_dir/*.json") > $before;
                        select undef, undef, undef, 0.05;
                    }
                    _interactive_prompt($log_fn);
                }
            }
            elsif ($interactive) {
                # Operator typed a command
                my $line = <STDIN>;
                unless (defined $line) {
                    # EOF on STDIN - drop back to non-interactive
                    $sel->remove(\*STDIN);
                    $interactive = 0;
                    next;
                }
                chomp $line;
                $line =~ s/^\s+|\s+$//g;
                next unless length $line;

                if ($line eq 'quit' || $line eq 'q') {
                    $stopped = 'quit';
                    last;
                }
                elsif ($line eq 'list' || $line eq 'l') {
                    _interactive_prompt($log_fn);
                }
                elsif ($line =~ /^a(\d+)$/) {
                    _interactive_approve($1, $log_fn, $dispatcher_id, $cert);
                }
                elsif ($line =~ /^d(\d+)$/) {
                    _interactive_deny($1, $log_fn);
                }
                elsif ($line =~ /^[aA]$/) {
                    # Shorthand approve when only one request pending
                    my $reqs = list_requests();
                    if (@$reqs == 1) {
                        _do_approve($reqs->[0]{id}, $log_fn, $dispatcher_id, $cert);
                    }
                    elsif (@$reqs == 0) {
                        print "No pending requests.\n";
                    }
                    else {
                        print "Multiple requests pending - use a1, a2, etc.\n";
                        _print_queue($reqs);
                    }
                }
                elsif ($line =~ /^[dD]$/) {
                    # Shorthand deny when only one request pending
                    my $reqs = list_requests();
                    if (@$reqs == 1) {
                        _do_deny($reqs->[0]{id}, $log_fn);
                    }
                    elsif (@$reqs == 0) {
                        print "No pending requests.\n";
                    }
                    else {
                        print "Multiple requests pending - use d1, d2, etc.\n";
                        _print_queue($reqs);
                    }
                }
                elsif ($line eq 's' || $line eq 'skip') {
                    print "Skipped. Request remains pending.\n";
                }
                else {
                    print "Unknown command '$line'. Commands: a/d/s/list/quit or a1/d1 for multiple.\n";
                }
            }
        }
    }

    # Single cleanup path for every stop reason (signal, deadline, or quit).
    if ($stopped eq 'timeout') {
        print "\nPairing mode timed out after ${timeout}s. Stopped.\n";
        $log_fn->({ ACTION => 'pairing-mode-timeout', PORT => $port });
    }
    else {
        print "\nPairing mode stopped.\n";
        $log_fn->({ ACTION => 'pairing-mode-stop' });
    }
    return $stopped;
}

# The SHA-256 fingerprint of this dispatcher's CA certificate ($ca_dir/ca.crt,
# the CA that signs agent certificates and is delivered to them at pairing),
# for verified pairing (T-041). It is stable across rotation of the dispatcher
# certificate, which the same CA reissues. When cert is given, the CA must have
# issued it - otherwise an agent checking the fingerprint could never pair, and
# the fingerprint is not offered.
# Returns { ok => 1, fpr => '<64 hex>', ca_file => $path }
#      or { ok => 0, error => '...' }
sub ca_fingerprint (%opts) {
    my $ca_dir  = $opts{ca_dir} // Exec::DispatcherConfig::conf_dir();
    my $ca_file = "$ca_dir/ca.crt";
    return { ok => 0, error => "no CA certificate at $ca_file" } unless -f $ca_file;
    my $fpr = Exec::CertInfo::fingerprint_from_path($ca_file)
        // return { ok => 0, error => "cannot read the CA certificate $ca_file" };
    if (defined(my $cert = $opts{cert})) {
        my $out = `openssl verify -CAfile \Q$ca_file\E \Q$cert\E 2>&1`;
        return { ok => 0, error => "the served certificate $cert was not "
                                 . "issued by the CA $ca_file" }
            unless $? == 0;
    }
    return { ok => 1, fpr => $fpr, ca_file => $ca_file };
}

# The agent command for verified pairing with this dispatcher, ready to paste.
# The host is this host's name, which the operator may need to replace with the
# name or address the agent reaches it by.
sub agent_pairing_command ($fpr, $port = 7444, $host = undef) {
    $host //= hostname();
    return "ctrl-exec-agent request-pairing --dispatcher $host"
         . ($port == 7444 ? '' : " --port $port")
         . ' --dispatcher-fingerprint '
         . Exec::CertInfo::format_sha256_fingerprint($fpr);
}

# Banner lines about verified pairing for the pairing-mode start: the CA
# fingerprint and the agent command, or why they are unavailable. $ca is the
# result of ca_fingerprint.
sub verified_pairing_lines ($ca, $port = 7444) {
    return ("Verified pairing unavailable: $ca->{error}.") unless $ca->{ok};
    return (
        'Dispatcher CA fingerprint: '
            . Exec::CertInfo::format_sha256_fingerprint($ca->{fpr}),
        'On the agent (verified pairing; use it on any untrusted network):',
        '    ' . agent_pairing_command($ca->{fpr}, $port),
    );
}

# Add the CA certificate in $ca_file to the chain a TLS context sends after its
# own certificate (SSL_create_ctx_callback). The context takes ownership.
sub _add_chain_cert ($ctx, $ca_file) {
    require Net::SSLeay;
    my $bio = Net::SSLeay::BIO_new_file($ca_file, 'r')
        or die "Cannot open CA certificate '$ca_file'\n";
    my $x509 = Net::SSLeay::PEM_read_bio_X509($bio);
    Net::SSLeay::BIO_free($bio);
    die "Cannot read CA certificate '$ca_file'\n" unless $x509;
    Net::SSLeay::CTX_add_extra_chain_cert($ctx, $x509)
        or die "Cannot add CA certificate '$ca_file' to the pairing chain\n";
}

# Return list of pending requests sorted by received time
sub list_requests (%opts) {
    my $dir = $opts{pairing_dir} // $PAIRING_DIR;
    return [] unless -d $dir;

    _expire_stale_requests($dir);

    my @requests;
    opendir my $dh, $dir or croak "Cannot open '$dir': $!";
    while (my $f = readdir $dh) {
        next unless $f =~ /^([a-f0-9]+)\.json$/;
        my $id   = $1;
        my $path = "$dir/$f";
        my $data = eval { decode_json(slurp($path)) };
        next if $@;
        push @requests, $data;
    }
    closedir $dh;

    return [ sort { $a->{received} cmp $b->{received} } @requests ];
}

# Approve a pending request: sign CSR, deliver cert to waiting agent
# The agent's connection is held in a response file keyed by reqid
sub approve_request (%opts) {
    my $reqid       = $opts{reqid}       or croak "reqid required";
    my $ca_dir      = $opts{ca_dir}      // Exec::DispatcherConfig::conf_dir();
    my $pairing_dir = $opts{pairing_dir} // $PAIRING_DIR;
    my $log_fn      = $opts{log_fn}      // sub {};
    # This dispatcher's stable identity, delivered to the agent so it can key
    # permission and attribution on it (serials rotate; the identity does not).
    my $dispatcher_id = $opts{dispatcher_id} // '';
    # The cert this dispatcher actually presents to agents (ctrl-exec.conf
    # 'cert'). Its serial is what the agent records and checks on every request,
    # so it MUST be read from the same file the dispatcher serves with - never a
    # hardcoded name. Required: callers pass $config->{cert}. A wrong/missing
    # path yields an empty serial, no trust entry, and a permanent "serial
    # mismatch", which the empty-serial warning below flags at approve time.
    my $dispatcher_cert = $opts{dispatcher_cert}
        or croak "dispatcher_cert required (the served cert path, ctrl-exec.conf 'cert')";

    my $req_file = "$pairing_dir/$reqid.json";
    -f $req_file or croak "No pending request '$reqid'";

    my $req = decode_json(slurp($req_file));

    # Dispatch-resolution preferences: operator override (approve flags) wins
    # over the agent-suggested/reported value in the request; then the default.
    my $lookup_by = _effective_lookup_by($opts{lookup_by}, $req->{lookup_by});
    my $port      = _effective_port($opts{port}, $req->{port});
    my $ip        = _effective_ip($opts{ip}, $req->{ip});

    require Exec::CA;

    # Keep-certificate request (T-062): nothing is signed. The agent keeps the
    # certificate another dispatcher's CA issued; this dispatcher pins that CA
    # in this agent's registry entry and verifies the agent against it alone
    # (Exec::Engine). When the CA is this dispatcher's own (an agent re-pairing
    # with the dispatcher that issued its certificate) nothing is pinned: the
    # agent is an ordinary agent of this dispatcher, which renews it as before.
    my $keep = defined $req->{agent_cert} && length $req->{agent_cert};
    my ($cert_pem, $pin_ca);
    if ($keep) {
        $cert_pem = $req->{agent_cert};
        my $own = Exec::CertInfo::fingerprint_from_path("$ca_dir/ca.crt") // '';
        $pin_ca = ($req->{agent_ca_fpr} // '') ne $own;
    }
    else {
        # Serialise concurrent signing through an exclusive lock on ca.serial.
        # Prevents duplicate serial numbers when multiple pairing approvals race.
        my $serial_file = "$ca_dir/ca.serial";
        open my $serial_lock, '<', $serial_file
            or croak "Cannot open serial file for locking: $!";
        flock $serial_lock, LOCK_EX
            or croak "Cannot lock serial file: $!";

        $cert_pem = Exec::CA::sign_csr(
            csr_pem => $req->{csr},
            ca_dir  => $ca_dir,
        );

        flock $serial_lock, LOCK_UN;
        close $serial_lock;
    }
    my $ca_pem = Exec::CA::read_ca_cert(ca_dir => $ca_dir);

    # Read the dispatcher cert serial so the agent can store it and use it
    # to restrict /capabilities to the genuine ctrl-exec only. Cached by
    # path+mtime so a run of interactive approvals does not re-fork openssl each
    # time (the cert only changes on rotation, which changes the file's mtime).
    my $disp_cert   = $dispatcher_cert;
    my $disp_serial = _cached_disp_serial($disp_cert);
    # An empty serial means the agent is paired but trusts no serial for this
    # dispatcher, so it rejects every subsequent request as a "serial mismatch".
    # That is almost always a wrong/missing 'cert' path - surface it now, at the
    # one moment the operator can fix it, rather than leaving a silent failure.
    unless (length $disp_serial) {
        warn "WARNING: could not read this dispatcher's cert serial from "
           . "'$disp_cert'.\n"
           . "  The agent will trust no serial for this dispatcher and will "
           . "reject every\n  request as a 'serial mismatch'. Check the 'cert' "
           . "setting in ctrl-exec.conf\n  points to the cert this dispatcher "
           . "serves with, then re-pair.\n";
    }

    # Extract cert expiry for the registry record
    my $expiry = _cert_expiry_from_pem($cert_pem);

    # Write approval response - the waiting child process reads this
    my $resp_file = "$pairing_dir/$reqid.approved";
    _write_file($resp_file, encode_json({
        status          => 'approved',
        ($keep ? (cert_mode => 'keep') : (cert => $cert_pem)),
        ca              => $ca_pem,
        nonce           => $req->{nonce} // '',
        dispatcher_serial => $disp_serial,
        dispatcher_id   => $dispatcher_id,
    }));

    # Persist agent record - source of truth for all paired agents
    require Exec::Registry;
    Exec::Registry::register_agent(
        registry_dir      => $opts{registry_dir},
        hostname          => $req->{hostname},
        ip                => $ip,
        paired            => strftime('%Y-%m-%dT%H:%M:%SZ', gmtime),
        expiry            => $expiry // '',
        reqid             => $reqid,
        lookup_by         => $lookup_by,
        port              => $port,
        dispatcher_serial => $disp_serial,
        serial_status     => (length $disp_serial ? 'current' : 'unknown'),
        serial_confirmed  => (length $disp_serial
                                ? strftime('%Y-%m-%dT%H:%M:%SZ', gmtime)
                                : ''),
        ($pin_ca ? (agent_ca     => $req->{agent_ca},
                    agent_ca_fpr => $req->{agent_ca_fpr}) : ()),
    );

    $log_fn->({ ACTION => 'pair-approve', AGENT => $req->{hostname}, REQID => $reqid,
        ($keep ? (CERT_MODE => 'keep', AGENT_CA => $req->{agent_ca_fpr} // '',
                  PINNED => ($pin_ca ? 1 : 0)) : ()) });

    # Report exactly what was registered and how the dispatcher will reach it,
    # then how to change it without re-pairing. edit-agent only rewrites the
    # registry record - dispatch auth is CA-based (the agent cert CN is not
    # checked), so renaming or switching to IP needs no new certificate.
    my $name = $req->{hostname};
    my $addr = ($lookup_by eq 'hostname') ? $name : ($ip // '?');
    print "Approved '$name' ($reqid). Cert delivered on next poll.\n";
    printf "  Code:        %s\n", code_label($req);
    print "$_\n" for kept_cert_lines($req, $pin_ca);
    printf "  Registered:  %s   lookup_by=%s   addr=%s:%s\n",
        $name, $lookup_by, $addr, ($port // '?');
    if (length($req->{source_ip} // '') || $req->{reverse_confirmed}) {
        print "  If this dispatcher cannot reach it by that, fix without re-pairing:\n";
        printf "    ctrl-exec-dispatcher edit-agent %s --lookup-by ip --ip %s\n",
            $name, $req->{source_ip}
            if length($req->{source_ip} // '');
        printf "    ctrl-exec-dispatcher edit-agent %s --rename %s\n",
            $name, $req->{reverse_dns}
            if $req->{reverse_confirmed} && length($req->{reverse_dns} // '')
               && lc $req->{reverse_dns} ne lc $name;
    }
}

# Deny and remove a pending request
sub deny_request (%opts) {
    my $reqid       = $opts{reqid}       or croak "reqid required";
    my $pairing_dir = $opts{pairing_dir} // $PAIRING_DIR;
    my $log_fn      = $opts{log_fn}      // sub {};

    my $req_file = "$pairing_dir/$reqid.json";
    -f $req_file or croak "No pending request '$reqid'";

    my $req = eval { decode_json(slurp($req_file)) } // {};

    # Write denial so any waiting child can respond to agent
    my $resp_file = "$pairing_dir/$reqid.denied";
    _write_file($resp_file, encode_json({
        status => 'denied',
        reason => 'rejected by operator',
    }));

    unlink $req_file;

    $log_fn->({ ACTION => 'pair-deny', AGENT => $req->{hostname} // '?', REQID => $reqid });
    print "Denied request '$reqid'.\n";
}

# --- private ---

# Return $v if it is a valid lookup_by value ('ip' or 'hostname'), else undef.
# Used to sanitise the optional agent-suggested hint off the wire.
sub _valid_lookup_by ($v) {
    return (defined $v && ($v eq 'ip' || $v eq 'hostname')) ? $v : undef;
}

# Effective lookup_by for an approval: operator override wins over the
# agent-suggested value; default 'hostname'. Returns 'ip' or 'hostname'.
sub _effective_lookup_by ($override, $suggested) {
    for my $v ($override, $suggested) {
        return $v if defined $v && ($v eq 'ip' || $v eq 'hostname');
    }
    return 'hostname';
}

# Return $v as an integer if it is a valid TCP port (1..65535), else undef.
sub _valid_port ($v) {
    return (defined $v && $v =~ /^\d+$/ && $v >= 1 && $v <= 65535)
        ? int($v) : undef;
}

# Effective operational port for an approval: operator override
# (approve --agent-port) wins over the agent-reported port; default 7443.
sub _effective_port ($override, $reported) {
    for my $v ($override, $reported) {
        my $p = _valid_port($v);
        return $p if defined $p;
    }
    return 7443;
}

# Return $v if it looks like an IPv4 or IPv6 literal, else undef. Rejects empty,
# 'unknown', and hostnames so a garbage agent-reported value is never stored as
# an address. Deliberately loose - a sanity check, not full address validation.
sub _valid_ip ($v) {
    return unless defined $v && length $v;
    return $v if $v =~ /^\d{1,3}(?:\.\d{1,3}){3}$/;      # IPv4
    return $v if $v =~ /^[0-9A-Fa-f:]+:[0-9A-Fa-f:]+$/;  # IPv6 (loose)
    return;
}

# Effective IP for an approval, in priority order: operator override
# (approve --ip) wins over the value queued at request time (the agent's
# self-reported source IP, falling back to the connection source). '' if none.
sub _effective_ip (@candidates) {
    for my $v (@candidates) {
        my $ip = _valid_ip($v);
        return $ip if defined $ip;
    }
    return '';
}

# --- interactive pairing helpers ---

# Display pending requests and prompt for a command.
# Called when a new request arrives or the operator types 'list'.
sub _interactive_prompt ($log_fn) {
    my $reqs = list_requests();

    if (!@$reqs) {
        print "No pending pairing requests.\n";
        print "Waiting... (Commands: list, quit)\n";
        return;
    }

    if (@$reqs == 1) {
        my $r = $reqs->[0];
        print "\n";
        printf "Pairing request from %s (%s) - ID: %s\n",
            $r->{hostname} // '?', $r->{ip} // '?', $r->{id} // '?';
        printf "  Code:     %s   (verify this matches the agent display)\n",
            code_label($r);
        print "$_\n" for code_note($r);
        printf "  Received: %s\n", $r->{received} // '?';
        print "$_\n" for kept_cert_lines($r);
        print "$_\n" for Exec::Pairing::Identity::identity_lines($r);
        if (my $rec = Exec::Pairing::Identity::identity_recommendation($r)) {
            print "$rec\n";
        }
        print "Accept, Deny, or Skip? [a/d/s]: ";
    }
    else {
        print "\n";
        printf "%d pending pairing requests:\n", scalar @$reqs;
        _print_queue($reqs);
        print "Command (a1/d1/a2/d2/list/quit): ";
    }
}

# Print a numbered queue of pending requests.
sub _print_queue ($reqs) {
    my $i = 1;
    for my $r (@$reqs) {
        printf "  [%d] %-30s  %-16s  code: %s  %s\n",
            $i++,
            $r->{hostname} // '?',
            $r->{ip}       // '?',
            code_label($r),
            $r->{received} // '?';
    }
}

# Approve the Nth request in the current queue (1-based index).
sub _interactive_approve ($n, $log_fn, $dispatcher_id, $dispatcher_cert) {
    my $reqs = list_requests();
    my $r    = $reqs->[$n - 1];
    unless ($r) {
        print "No request at position $n.\n";
        return;
    }
    _do_approve($r->{id}, $log_fn, $dispatcher_id, $dispatcher_cert);
}

# Deny the Nth request in the current queue (1-based index).
sub _interactive_deny ($n, $log_fn) {
    my $reqs = list_requests();
    my $r    = $reqs->[$n - 1];
    unless ($r) {
        print "No request at position $n.\n";
        return;
    }
    _do_deny($r->{id}, $log_fn);
}

# Approve a request by reqid, with error handling for interactive context.
sub _do_approve ($reqid, $log_fn, $dispatcher_id, $dispatcher_cert) {
    eval {
        approve_request(
            reqid           => $reqid,
            dispatcher_id   => $dispatcher_id,
            dispatcher_cert => $dispatcher_cert,
            log_fn          => $log_fn,
        );
    };
    if ($@) {
        chomp(my $err = $@);
        print "Approve failed: $err\n";
    }
    else {
        print "Waiting for next request... (Ctrl-C to exit pairing mode)\n";
    }
}

# Deny a request by reqid, with error handling for interactive context.
sub _do_deny ($reqid, $log_fn) {
    eval {
        deny_request(
            reqid  => $reqid,
            log_fn => $log_fn,
        );
    };
    if ($@) {
        chomp(my $err = $@);
        print "Deny failed: $err\n";
    }
    else {
        print "Waiting for next request... (Ctrl-C to exit pairing mode)\n";
    }
}

# $cert_fpr is the SHA-256 fingerprint of the certificate the pairing listener
# presents (run_pairing_mode); the v2 code binds to it.
sub _handle_pair_request ($conn, $peer_ip, $log_fn, $max_queue = undef, $pairing_dir = undef, $cert_fpr = undef) {
    $max_queue  //= 10;
    $pairing_dir //= $PAIRING_DIR;

    # Read raw HTTP request
    my $raw = '';
    while (my $line = <$conn>) {
        $raw .= $line;
        last if $raw =~ /\r\n\r\n/;
    }

    my ($content_length) = $raw =~ /Content-Length:\s*(\d+)/i;
    if ($content_length && $content_length > $MAX_PAIR_BODY) {
        _send_raw($conn, encode_json({ status => 'error', reason => 'request too large' }));
        $log_fn->({ ACTION => 'pair-reject', IP => $peer_ip, REASON => 'body-too-large' });
        return;
    }
    my $body = '';
    if ($content_length) {
        read $conn, $body, $content_length;
    }

    my $data = eval { decode_json($body) };
    unless ($data && ref $data eq 'HASH' && $data->{csr} && $data->{hostname}) {
        _send_raw($conn, encode_json({ status => 'error', reason => 'invalid request' }));
        return;
    }

    # The hostname becomes the registry key (a filename). Reject anything that
    # is not a plain agent name/hostname so a hostile pairing client cannot
    # traverse out of the registry directory on approval.
    require Exec::Registry;
    unless (Exec::Registry::valid_agent_name($data->{hostname})) {
        _send_raw($conn, encode_json({ status => 'error', reason => 'invalid hostname' }));
        $log_fn->({ ACTION => 'pair-reject', IP => $peer_ip, REASON => 'invalid-hostname' });
        return;
    }

    # The CSR must be exactly as openssl writes it. openssl ignores text around
    # the PEM block, so extra text would change the bytes the code is computed
    # from without changing the request that is signed - letting a relay try
    # variants until its code matched the agent's. Agents send openssl's own
    # output, so a genuine request always passes.
    my $canonical = Exec::Digest::canonical_csr($data->{csr});
    unless (defined $canonical && $canonical eq $data->{csr}) {
        my $why = defined $canonical ? 'non-canonical-csr' : 'invalid-csr';
        _send_raw($conn, encode_json({ status => 'error',
            reason => (defined $canonical ? 'CSR has unexpected extra content'
                                          : 'invalid CSR') }));
        $log_fn->({ ACTION => 'pair-reject', IP => $peer_ip, REASON => $why });
        return;
    }

    # Keep-certificate form (T-062): an agent already paired with another
    # dispatcher sends its certificate and the CA that issued it with the CSR,
    # and keeps them. This dispatcher signs nothing for it; on approval it pins
    # that CA for this agent alone. The CSR (made from the agent's existing key)
    # proves the agent holds the key of the certificate it presents.
    my $kept;
    if (defined $data->{agent_cert} || defined $data->{agent_ca}) {
        $kept = check_kept_cert($data->{csr}, $data->{agent_cert}, $data->{agent_ca});
        unless ($kept->{ok}) {
            _send_raw($conn, encode_json({ status => 'error',
                reason => "agent certificate refused: $kept->{error}" }));
            $log_fn->({ ACTION => 'pair-reject', IP => $peer_ip,
                REASON => 'kept-cert-invalid', ERROR => $kept->{error} });
            return;
        }
    }

    # Code version: the agent states the one it computed. None means an agent
    # older than 0.13, which computes v1. Anything else is refused rather than
    # shown as a code the agent does not display.
    my $code_version = $data->{code_version} // 1;
    unless (($code_version eq '1' || $code_version eq '2')
            && ($code_version eq '1' || defined $cert_fpr)) {
        _send_raw($conn, encode_json({ status => 'error',
            reason => 'unsupported pairing code version' }));
        $log_fn->({ ACTION => 'pair-reject', IP => $peer_ip,
            REASON => 'unsupported-code-version' });
        return;
    }
    $code_version = int $code_version;

    my $reqid      = _gen_reqid();
    my $hostname   = $data->{hostname};
    my $csr        = $data->{csr};
    my $nonce      = $data->{nonce} // '';
    my $lookup_by  = _valid_lookup_by($data->{lookup_by});  # agent-suggested hint
    my $agent_port = _valid_port($data->{port});            # agent-reported serve port
    my $reported_ip = _valid_ip($data->{ip});               # agent-reported source IP
    # The address to register: the agent's self-reported source IP when valid,
    # else the connection's source IP (unreliable behind NAT). An operator can
    # still override it at 'approve --ip'.
    my $eff_ip     = $reported_ip // $peer_ip;
    my $received   = strftime('%Y-%m-%dT%H:%M:%SZ', gmtime);
    my $code       = _pairing_code($code_version,
        Exec::Digest::pairing_input($csr, ($kept ? @$data{qw(agent_cert agent_ca)} : ())),
        $cert_fpr);

    # Resolve the network's canonical name for the connection's source IP once,
    # now, so the operator can see how this dispatcher resolves the agent before
    # approving (and so list-requests/approve never block on DNS). Bounded by a
    # short timeout; absent/slow PTR just yields no reverse name.
    my $rev = Exec::Pairing::Identity::reverse_lookup($peer_ip);

    # Queue depth check - expire stale entries first, then count remaining
    _expire_stale_requests($pairing_dir);
    my @pending = glob "$pairing_dir/*.json";
    if (@pending >= $max_queue) {
        _send_raw($conn, encode_json({
            status => 'error',
            reason => 'pairing queue full',
        }));
        $log_fn->({ ACTION => 'pair-reject', IP => $peer_ip, REASON => 'queue-full' });
        return;
    }

    # Queue the request
    make_path($pairing_dir) unless -d $pairing_dir;
    _write_file("$pairing_dir/$reqid.json", encode_json({
        id        => $reqid,
        hostname  => $hostname,
        ip        => $eff_ip,
        source_ip => $peer_ip,
        csr       => $csr,
        nonce     => $nonce,
        lookup_by => $lookup_by,
        port      => $agent_port,
        received  => $received,
        code      => $code,
        code_version => $code_version,
        reverse_dns       => ($rev ? $rev->{ptr} : ''),
        reverse_confirmed => ($rev && $rev->{confirmed} ? 1 : 0),
        ($kept ? (
            agent_cert       => $data->{agent_cert},
            agent_ca         => $data->{agent_ca},
            agent_cert_fpr   => $kept->{cert_fpr},
            agent_ca_fpr     => $kept->{ca_fpr},
            agent_ca_subject => $kept->{ca_subject},
        ) : ()),
    }));

    $log_fn->({ ACTION => 'pair-request', AGENT => $hostname, IP => $peer_ip,
        ($reported_ip ? (REPORTED_IP => $reported_ip) : ()),
        REQID => $reqid, CODE_VERSION => $code_version, STATUS => 'pending',
        ($kept ? (CERT_MODE => 'keep', AGENT_CA => $kept->{ca_fpr}) : ()) });
    print "Pairing request queued: $hostname ($eff_ip) - ID: $reqid\n";

    # Send reqid to agent immediately so orchestrators can use it to call
    # 'ctrl-exec-dispatcher approve <reqid>' without waiting for the connection to close.
    # The agent reads this first response, extracts the reqid, then reads
    # a second response for the approval or denial.
    # code_version tells a 0.13+ agent this dispatcher computed the code version
    # it asked for; older agents ignore the extra field.
    # cert_mode tells a 0.14+ agent that sent its certificate that this
    # dispatcher will keep it rather than sign the CSR; an agent that gets no
    # such confirmation (a dispatcher before 0.14) withdraws.
    _send_raw($conn, encode_json({ status => 'pending', reqid => $reqid,
        code_version => $code_version, ($kept ? (cert_mode => 'keep') : ()) }));

    # Poll for approval or denial (max 10 minutes)
    my $resp_approved = "$pairing_dir/$reqid.approved";
    my $resp_denied   = "$pairing_dir/$reqid.denied";
    my $deadline      = time + 600;

    while (time < $deadline) {
        if (-f $resp_approved) {
            my $resp = slurp($resp_approved);
            _send_raw($conn, $resp);
            unlink $resp_approved;
            unlink "$pairing_dir/$reqid.json";
            return;
        }
        if (-f $resp_denied) {
            my $resp = slurp($resp_denied);
            _send_raw($conn, $resp);
            unlink $resp_denied;
            return;
        }
        sleep 2;
    }

    # Timeout
    _send_raw($conn, encode_json({ status => 'denied', reason => 'approval timeout' }));
    unlink "$pairing_dir/$reqid.json";
}

sub _send_raw ($conn, $body) {
    Exec::Http::send_raw($conn, 200, $body);
}

sub _gen_reqid () {
    return Exec::Random::hex_bytes(8);
}

# Delete pending .json request files older than 10 minutes that have no
# corresponding .approved or .denied response. These are left behind by
# failed pairing attempts (e.g. run without sudo on the agent side).
sub _expire_stale_requests ($pairing_dir) {
    my $cutoff = time() - 600;
    opendir my $dh, $pairing_dir or return;
    while (my $f = readdir $dh) {
        next unless $f =~ /^([a-f0-9]+)\.json$/;
        my $base = $1;
        my $path = "$pairing_dir/$f";
        next if -f "$pairing_dir/$base.approved";
        next if -f "$pairing_dir/$base.denied";
        unlink $path if (stat $path)[9] < $cutoff;
    }
    closedir $dh;
}

sub _write_file ($path, $content) {
    return Exec::FileUtil::write_atomic($path, $content);
}

# Compute the 6-digit confirmation code of the given version (see
# Exec::Digest). Identical computation to the agent side - both derive the code
# independently, the agent from the certificate it saw and the dispatcher from
# the certificate it presents, so no extra round-trip is required. The operator
# verifies both displays match before approving.
sub _pairing_code ($version, $csr_pem, $cert_fpr = undef) {
    return Exec::Digest::pairing_code_for($version, $csr_pem, $cert_fpr);
}

# A pending request's code for display, with its version so an operator can
# tell a bound v2 code from the weaker v1 code of an agent older than 0.13. A
# record without a version was queued as v1 (before 0.13).
sub code_label ($r) {
    my $code = $r->{code} // '??????';
    return ($r->{code_version} // 1) == 2
        ? "$code (v2)"
        : "$code (v1, pre-0.13 agent)";
}

# Explanation printed under a v1 code in the single-request interactive
# prompt, where there is room for it; nothing for v2.
sub code_note ($r) {
    return () if ($r->{code_version} // 1) == 2;
    return "  Note:     a v1 code (agent older than 0.13) is not bound to this "
         . "dispatcher,\n            so a matching code does not rule out a relay.";
}

# Check a keep-certificate pairing request (T-062): $cert and $ca are the
# agent's certificate and the CA that issued it, each one canonical PEM
# certificate (they are hashed into the pairing code); the CSR, made from the
# agent's existing key, carries the certificate's public key and a valid
# self-signature (so the sender holds that key); and the certificate verifies
# with that CA as the only trust anchor.
# Returns { ok => 1, cert_fpr, ca_fpr, ca_subject, expiry }
#      or { ok => 0, error => '...' }
sub check_kept_cert ($csr, $cert, $ca) {
    for ([certificate => $cert], [CA => $ca]) {
        my ($what, $pem) = @$_;
        return { ok => 0, error => "no $what" } unless defined $pem && !ref $pem && length $pem;
        my $canon = Exec::Digest::canonical_cert($pem);
        return { ok => 0, error => "the $what is not exactly one PEM certificate" }
            unless defined $canon && $canon eq $pem;
    }
    my $req_key  = Exec::CertInfo::public_key_from_pem($csr, 'req');
    my $cert_key = Exec::CertInfo::public_key_from_pem($cert);
    return { ok => 0, error => "the certificate's key is not the CSR's key" }
        unless defined $req_key && defined $cert_key && $req_key eq $cert_key;
    my $tmp = File::Temp->new(SUFFIX => '.csr', UNLINK => 1);
    print $tmp $csr;
    close $tmp;
    my $out = `openssl req -verify -noout -in \Q${\ $tmp->filename}\E 2>&1`;
    return { ok => 0, error => 'the CSR signature does not verify' } unless $? == 0;
    my $why = Exec::CertInfo::verify_issued_by($cert, $ca);
    return { ok => 0, error => "the certificate does not verify against its CA ($why)" }
        if defined $why;
    return {
        ok         => 1,
        cert_fpr   => Exec::CertInfo::fingerprint_from_pem($cert) // '',
        ca_fpr     => Exec::CertInfo::fingerprint_from_pem($ca)   // '',
        ca_subject => Exec::CertInfo::subject_from_pem($ca)       // '',
        expiry     => Exec::CertInfo::expiry_from_pem($cert)      // '',
    };
}

# Lines describing a keep-certificate request for the operator (list-requests,
# the interactive prompt, approve): the agent's certificate and the CA it
# chains to, by fingerprint, so what is approved is what is seen. Empty for an
# ordinary (CSR) request. $pinned, when known (approve), says what happens.
sub kept_cert_lines ($r, $pinned = undef) {
    return () unless defined $r->{agent_cert} && length $r->{agent_cert};
    my @l = (
        '  Keeps cert: ' . Exec::CertInfo::format_sha256_fingerprint($r->{agent_cert_fpr} // ''),
        '  Issued by:  ' . Exec::CertInfo::format_sha256_fingerprint($r->{agent_ca_fpr} // '')
            . (length($r->{agent_ca_subject} // '') ? " ($r->{agent_ca_subject})" : ''),
    );
    if (defined $pinned) {
        push @l, $pinned
            ? '  This dispatcher verifies this agent against that CA (pinned for it '
              . "alone)\n  and does not renew its certificate; the issuing dispatcher does."
            : "  That is this dispatcher's own CA: an ordinary agent of this dispatcher.";
    }
    else {
        push @l, '  The agent keeps that certificate (already paired with another '
               . 'dispatcher);\n  approving pins its CA for this agent alone.';
    }
    return @l;
}

# Extract the notAfter date from a PEM cert string (via Exec::CertInfo).
sub _cert_expiry_from_pem ($cert_pem) {
    return Exec::CertInfo::expiry_from_pem($cert_pem);
}

1;
