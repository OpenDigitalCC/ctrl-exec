package Exec::Pairing;

use strict;
use warnings;
use File::Path  qw(make_path);
use File::Temp  qw(tempfile);
use Fcntl       qw(:flock);
use JSON        qw(encode_json decode_json);
use POSIX       qw(strftime);
use Carp        qw(croak);

use Exec::RateLimit qw();


my $PAIRING_DIR = '/var/lib/ctrl-exec/pairing';


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
        my ($limit, $window, $block) = split m{/}, $raw, 3;
        if (defined $limit  && $limit  =~ /^\d+$/ &&
            defined $window && $window =~ /^\d+$/ &&
            defined $block  && $block  =~ /^\d+$/) {
            $rl{volume_limit}  = int($limit);
            $rl{volume_window} = int($window);
            $rl{volume_block}  = int($block);
        }
        # Malformed value: fall back to defaults silently.
    }

    return \%rl;
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

    make_path($PAIRING_DIR) unless -d $PAIRING_DIR;

    _expire_stale_requests($PAIRING_DIR);

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

    if ($interactive) {
        print "Pairing mode active on port $port. Ctrl-C or 'quit' to stop.\n";
        print "Waiting for pairing requests...\n";
    }
    else {
        print "Pairing mode active on port $port. Ctrl-C to stop.\n";
        print "Use 'ctrl-exec-dispatcher list-requests' to see pending requests.\n";
    }

    $SIG{INT} = $SIG{TERM} = sub {
        $log_fn->({ ACTION => 'pairing-mode-stop' });
        print "\nPairing mode stopped.\n";
        exit 0;
    };

    my $sel = IO::Select->new($server);
    $sel->add(\*STDIN) if $interactive;

    # Per-IP rate-limit state for the pairing port, kept in the parent loop.
    my %rate_state;

    while (1) {
        # Block until the server socket or STDIN is ready.
        # Timeout every 5 seconds to reap finished children.
        my @ready = $sel->can_read(5);

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
                Exec::RateLimit::record_connection($peer_ip, \%rate_state, $rate_config);

                my $pid = fork();
                if (!defined $pid) {
                    warn "fork failed: $!\n";
                    $conn->close;
                    next;
                }
                if ($pid == 0) {
                    $server->close;
                    _handle_pair_request($conn, $peer_ip, $log_fn, $max_queue, $PAIRING_DIR);
                    $conn->close;
                    exit 0;
                }
                $conn->close(SSL_no_shutdown => 1);

                if ($interactive) {
                    # Brief pause so the child can write the queue file
                    # before we read it for display.
                    # Known limitation: this is a timing assumption, not a
                    # synchronisation guarantee. On a heavily loaded system
                    # the child may not have written the file within 1 second.
                    # A pipe-based signal from child to parent would be more
                    # robust but significantly complicates the fork pattern.
                    sleep 1;
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
                    $log_fn->({ ACTION => 'pairing-mode-stop' });
                    print "Pairing mode stopped.\n";
                    exit 0;
                }
                elsif ($line eq 'list' || $line eq 'l') {
                    _interactive_prompt($log_fn);
                }
                elsif ($line =~ /^a(\d+)$/) {
                    _interactive_approve($1, $log_fn);
                }
                elsif ($line =~ /^d(\d+)$/) {
                    _interactive_deny($1, $log_fn);
                }
                elsif ($line =~ /^[aA]$/) {
                    # Shorthand approve when only one request pending
                    my $reqs = list_requests();
                    if (@$reqs == 1) {
                        _do_approve($reqs->[0]{id}, $log_fn);
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
        my $data = eval { decode_json(_slurp($path)) };
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

    my $req_file = "$pairing_dir/$reqid.json";
    -f $req_file or croak "No pending request '$reqid'";

    my $req = decode_json(_slurp($req_file));

    # Dispatch-resolution preferences: operator override (approve flags) wins
    # over the agent-suggested/reported value in the request; then the default.
    my $lookup_by = _effective_lookup_by($opts{lookup_by}, $req->{lookup_by});
    my $port      = _effective_port($opts{port}, $req->{port});

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

    # Read the ctrl-exec cert serial so the agent can store it and use it
    # to restrict /capabilities to the genuine ctrl-exec only.
    my $disp_cert = "$ca_dir/ctrl-exec.crt";
    my $disp_serial = '';
    if (-f $disp_cert) {
        my $out = `openssl x509 -noout -serial -in \Q$disp_cert\E 2>/dev/null`;
        if (defined $out && $out =~ /serial=([0-9A-Fa-f]+)/) {
            $disp_serial = lc $1;
        }
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
    }));

    # Persist agent record - source of truth for all paired agents
    require Exec::Registry;
    Exec::Registry::register_agent(
        hostname          => $req->{hostname},
        ip                => $req->{ip},
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
    print "Approved '$req->{hostname}' ($reqid). Cert delivered on next poll.\n";
}

# Deny and remove a pending request
sub deny_request {
    my (%opts) = @_;
    my $reqid       = $opts{reqid}       or croak "reqid required";
    my $pairing_dir = $opts{pairing_dir} // $PAIRING_DIR;
    my $log_fn      = $opts{log_fn}      // sub {};

    my $req_file = "$pairing_dir/$reqid.json";
    -f $req_file or croak "No pending request '$reqid'";

    my $req = eval { decode_json(_slurp($req_file)) } // {};

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
    my ($n, $log_fn) = @_;
    my $reqs = list_requests();
    my $r    = $reqs->[$n - 1];
    unless ($r) {
        print "No request at position $n.\n";
        return;
    }
    _do_approve($r->{id}, $log_fn);
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
    my ($reqid, $log_fn) = @_;
    eval {
        approve_request(
            reqid  => $reqid,
            log_fn => $log_fn,
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
    my $received   = strftime('%Y-%m-%dT%H:%M:%SZ', gmtime);
    my $code       = _pairing_code($csr);

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
        ip        => $peer_ip,
        csr       => $csr,
        nonce     => $nonce,
        lookup_by => $lookup_by,
        port      => $agent_port,
        received  => $received,
        code      => $code,
    }));

    $log_fn->({ ACTION => 'pair-request', AGENT => $hostname, IP => $peer_ip, REQID => $reqid, STATUS => 'pending' });
    print "Pairing request queued: $hostname ($peer_ip) - ID: $reqid\n";

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
            my $resp = _slurp($resp_approved);
            _send_raw($conn, $resp);
            unlink $resp_approved;
            unlink "$pairing_dir/$reqid.json";
            return;
        }
        if (-f $resp_denied) {
            my $resp = _slurp($resp_denied);
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
    print $conn
        "HTTP/1.0 200 OK\r\n",
        "Content-Type: application/json\r\n",
        "Content-Length: ", length($body), "\r\n",
        "\r\n",
        $body;
}

sub _gen_reqid {
    open my $fh, '<:raw', '/dev/urandom'
        or die "Cannot open /dev/urandom: $!";
    my $buf;
    sysread $fh, $buf, 8;
    close $fh;
    return unpack 'H*', $buf;
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

sub _slurp {
    my ($path) = @_;
    open my $fh, '<', $path or croak "Cannot read '$path': $!";
    local $/;
    return scalar <$fh>;
}

sub _write_file {
    my ($path, $content) = @_;
    open my $fh, '>', $path or croak "Cannot write '$path': $!";
    print $fh $content;
    close $fh;
}

# Compute a 6-digit confirmation code from a CSR PEM string.
# Identical computation to the agent side - both derive the code from the
# CSR content independently so no extra round-trip is required.
# The operator verifies both displays match before approving.
sub _pairing_code {
    my ($csr_pem) = @_;
    # Use openssl for SHA256 - consistent with agent side and avoids
    # Digest::SHA dependency. Both sides must produce identical output.
    require File::Temp;
    my ($tmp_fh, $tmp_path) = File::Temp::tempfile(UNLINK => 1);
    print $tmp_fh $csr_pem;
    close $tmp_fh;
    my $digest = `openssl dgst -sha256 -binary \Q$tmp_path\E 2>/dev/null`;
    die "openssl dgst failed\n" unless length($digest) == 32;
    my $n = unpack('N', substr($digest, 0, 4)) % 1_000_000;
    return sprintf '%06d', $n;
}

# Extract the notAfter date from a PEM cert string.
# Writes to a temp file, calls openssl x509 -noout -enddate.
# Returns the date string, or undef on failure.
sub _cert_expiry_from_pem {
    my ($cert_pem) = @_;
    my ($fh, $path) = tempfile(SUFFIX => '.crt', UNLINK => 1);
    print $fh $cert_pem;
    close $fh;
    my $out = `openssl x509 -noout -enddate -in \Q$path\E 2>/dev/null`;
    return unless defined $out && $out =~ /notAfter=(.+)/;
    my $date = $1;
    chomp $date;
    return $date;
}

1;
