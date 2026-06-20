package Exec::Pairing;

use strict;
use warnings;
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
sub _cached_disp_serial {
    my ($cert_path) = @_;
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
sub build_rate_config {
    my ($config) = @_;
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
sub resolve_dispatcher_id {
    my ($config) = @_;
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
sub run_pairing_mode {
    my (%opts) = @_;
    my $port      = $opts{port}      // 7444;
    my $ca_dir    = $opts{ca_dir}    // '/etc/ctrl-exec';
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

    # Pairing port: TLS server cert only, no client cert required
    require Exec::TLS;
    my $server = IO::Socket::SSL->new(
        LocalPort       => $port,
        Listen          => 5,
        ReuseAddr       => 1,
        SSL_cert_file   => $cert,
        SSL_key_file    => $key,
        SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_NONE(),
        Exec::TLS::hardening(),
    ) or die "Cannot start pairing server: $IO::Socket::SSL::SSL_ERROR\n";

    $log_fn->({ ACTION => 'pairing-mode-start', PORT => $port });

    my $interactive = -t STDIN;
    local $| = 1 if $interactive;  # unbuffered output so prompts appear immediately

    my $auto = $deadline ? " (auto-stops in ${timeout}s)" : "";
    if ($interactive) {
        print "Pairing mode active on port $port$auto. Ctrl-C or 'quit' to stop.\n";
        print "Waiting for pairing requests...\n";
    }
    else {
        print "Pairing mode active on port $port$auto. Ctrl-C to stop.\n";
        print "Use 'ctrl-exec-dispatcher list-requests' to see pending requests.\n";
    }

    # Stop reason is set by a signal, the deadline, or the interactive 'quit'
    # command; the loop exits on it and a single cleanup path logs and returns
    # (so the caller can reap its renewal-check child on every exit).
    my $stopped = '';
    $SIG{INT} = $SIG{TERM} = sub { $stopped ||= 'signal'; };

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
                    _handle_pair_request($conn, $peer_ip, $log_fn, $max_queue, $pairing_dir);
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

# Return list of pending requests sorted by received time
sub list_requests {
    my (%opts) = @_;
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
sub approve_request {
    my (%opts) = @_;
    my $reqid       = $opts{reqid}       or croak "reqid required";
    my $ca_dir      = $opts{ca_dir}      // '/etc/ctrl-exec';
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

    # Serialise concurrent signing through an exclusive lock on ca.serial.
    # Prevents duplicate serial numbers when multiple pairing approvals race.
    my $serial_file = "$ca_dir/ca.serial";
    open my $serial_lock, '<', $serial_file
        or croak "Cannot open serial file for locking: $!";
    flock $serial_lock, LOCK_EX
        or croak "Cannot lock serial file: $!";

    my $cert_pem = Exec::CA::sign_csr(
        csr_pem => $req->{csr},
        ca_dir  => $ca_dir,
    );

    flock $serial_lock, LOCK_UN;
    close $serial_lock;
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
        cert            => $cert_pem,
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
    );

    $log_fn->({ ACTION => 'pair-approve', AGENT => $req->{hostname}, REQID => $reqid });

    # Report exactly what was registered and how the dispatcher will reach it,
    # then how to change it without re-pairing. edit-agent only rewrites the
    # registry record - dispatch auth is CA-based (the agent cert CN is not
    # checked), so renaming or switching to IP needs no new certificate.
    my $name = $req->{hostname};
    my $addr = ($lookup_by eq 'hostname') ? $name : ($ip // '?');
    print "Approved '$name' ($reqid). Cert delivered on next poll.\n";
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
sub deny_request {
    my (%opts) = @_;
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
sub _valid_lookup_by {
    my ($v) = @_;
    return (defined $v && ($v eq 'ip' || $v eq 'hostname')) ? $v : undef;
}

# Effective lookup_by for an approval: operator override wins over the
# agent-suggested value; default 'hostname'. Returns 'ip' or 'hostname'.
sub _effective_lookup_by {
    my ($override, $suggested) = @_;
    for my $v ($override, $suggested) {
        return $v if defined $v && ($v eq 'ip' || $v eq 'hostname');
    }
    return 'hostname';
}

# Return $v as an integer if it is a valid TCP port (1..65535), else undef.
sub _valid_port {
    my ($v) = @_;
    return (defined $v && $v =~ /^\d+$/ && $v >= 1 && $v <= 65535)
        ? int($v) : undef;
}

# Effective operational port for an approval: operator override
# (approve --agent-port) wins over the agent-reported port; default 7443.
sub _effective_port {
    my ($override, $reported) = @_;
    for my $v ($override, $reported) {
        my $p = _valid_port($v);
        return $p if defined $p;
    }
    return 7443;
}

# Return $v if it looks like an IPv4 or IPv6 literal, else undef. Rejects empty,
# 'unknown', and hostnames so a garbage agent-reported value is never stored as
# an address. Deliberately loose - a sanity check, not full address validation.
sub _valid_ip {
    my ($v) = @_;
    return undef unless defined $v && length $v;
    return $v if $v =~ /^\d{1,3}(?:\.\d{1,3}){3}$/;      # IPv4
    return $v if $v =~ /^[0-9A-Fa-f:]+:[0-9A-Fa-f:]+$/;  # IPv6 (loose)
    return undef;
}

# Effective IP for an approval, in priority order: operator override
# (approve --ip) wins over the value queued at request time (the agent's
# self-reported source IP, falling back to the connection source). '' if none.
sub _effective_ip {
    my (@candidates) = @_;
    for my $v (@candidates) {
        my $ip = _valid_ip($v);
        return $ip if defined $ip;
    }
    return '';
}

# --- interactive pairing helpers ---

# Display pending requests and prompt for a command.
# Called when a new request arrives or the operator types 'list'.
sub _interactive_prompt {
    my ($log_fn) = @_;
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
            $r->{code} // '??????';
        printf "  Received: %s\n", $r->{received} // '?';
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
sub _print_queue {
    my ($reqs) = @_;
    my $i = 1;
    for my $r (@$reqs) {
        printf "  [%d] %-30s  %-16s  code: %s  %s\n",
            $i++,
            $r->{hostname} // '?',
            $r->{ip}       // '?',
            $r->{code}     // '??????',
            $r->{received} // '?';
    }
}

# Approve the Nth request in the current queue (1-based index).
sub _interactive_approve {
    my ($n, $log_fn, $dispatcher_id, $dispatcher_cert) = @_;
    my $reqs = list_requests();
    my $r    = $reqs->[$n - 1];
    unless ($r) {
        print "No request at position $n.\n";
        return;
    }
    _do_approve($r->{id}, $log_fn, $dispatcher_id, $dispatcher_cert);
}

# Deny the Nth request in the current queue (1-based index).
sub _interactive_deny {
    my ($n, $log_fn) = @_;
    my $reqs = list_requests();
    my $r    = $reqs->[$n - 1];
    unless ($r) {
        print "No request at position $n.\n";
        return;
    }
    _do_deny($r->{id}, $log_fn);
}

# Approve a request by reqid, with error handling for interactive context.
sub _do_approve {
    my ($reqid, $log_fn, $dispatcher_id, $dispatcher_cert) = @_;
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
sub _do_deny {
    my ($reqid, $log_fn) = @_;
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

sub _handle_pair_request {
    my ($conn, $peer_ip, $log_fn, $max_queue, $pairing_dir) = @_;
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
    unless ($data && $data->{csr} && $data->{hostname}) {
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
    my $code       = _pairing_code($csr);

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
        reverse_dns       => ($rev ? $rev->{ptr} : ''),
        reverse_confirmed => ($rev && $rev->{confirmed} ? 1 : 0),
    }));

    $log_fn->({ ACTION => 'pair-request', AGENT => $hostname, IP => $peer_ip,
        ($reported_ip ? (REPORTED_IP => $reported_ip) : ()),
        REQID => $reqid, STATUS => 'pending' });
    print "Pairing request queued: $hostname ($eff_ip) - ID: $reqid\n";

    # Send reqid to agent immediately so orchestrators can use it to call
    # 'ctrl-exec-dispatcher approve <reqid>' without waiting for the connection to close.
    # The agent reads this first response, extracts the reqid, then reads
    # a second response for the approval or denial.
    _send_raw($conn, encode_json({ status => 'pending', reqid => $reqid }));

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

sub _send_raw {
    my ($conn, $body) = @_;
    Exec::Http::send_raw($conn, 200, $body);
}

sub _gen_reqid {
    return Exec::Random::hex_bytes(8);
}

# Delete pending .json request files older than 10 minutes that have no
# corresponding .approved or .denied response. These are left behind by
# failed pairing attempts (e.g. run without sudo on the agent side).
sub _expire_stale_requests {
    my ($pairing_dir) = @_;
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

sub _write_file {
    my ($path, $content) = @_;
    return Exec::FileUtil::write_atomic($path, $content);
}

# Compute a 6-digit confirmation code from a CSR PEM string.
# Identical computation to the agent side - both derive the code from the
# CSR content independently so no extra round-trip is required.
# The operator verifies both displays match before approving.
sub _pairing_code {
    return Exec::Digest::pairing_code($_[0]);
}

# Extract the notAfter date from a PEM cert string (via Exec::CertInfo).
sub _cert_expiry_from_pem {
    return Exec::CertInfo::expiry_from_pem($_[0]);
}

1;
