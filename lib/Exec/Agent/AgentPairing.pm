package Exec::Agent::AgentPairing;

use strict;
use warnings;
use File::Temp qw(tempfile tempdir);
use File::Basename qw(dirname);
use File::Path qw(make_path);
use Carp qw(croak);
use Exec::Log qw();


# Generate a private key and CSR using openssl
# Returns hashref: { key_pem => '...', csr_pem => '...' }
# or dies on failure
sub generate_key_and_csr {
    my (%opts) = @_;
    my $hostname  = $opts{hostname}  or croak "hostname required";
    my $bits      = $opts{bits}      // 4096;

    my $tmpdir = tempdir(CLEANUP => 1);
    my $key_file = "$tmpdir/agent.key";
    my $csr_file = "$tmpdir/agent.csr";

    _run_or_die(
        'openssl', 'genrsa',
        '-out', $key_file,
        $bits
    );

    _run_or_die(
        'openssl', 'req',
        '-new',
        '-key',     $key_file,
        '-out',     $csr_file,
        '-subj',    "/CN=$hostname",
    );

    my $key_pem = _slurp($key_file);
    my $csr_pem = _slurp($csr_file);

    return { key_pem => $key_pem, csr_pem => $csr_pem };
}

# Generate a CSR from the existing agent key, without generating a new key.
# Used for cert renewal - key continuity is preserved.
# Returns hashref: { csr_pem => '...' } or dies on failure.
sub generate_csr_only {
    my (%opts) = @_;
    my $hostname = $opts{hostname}  or croak "hostname required";
    my $key_path = $opts{key_path}  or croak "key_path required";

    croak "Key file not found at '$key_path'" unless -f $key_path;

    my $tmpdir   = tempdir(CLEANUP => 1);
    my $csr_file = "$tmpdir/agent.csr";

    _run_or_die(
        'openssl', 'req',
        '-new',
        '-key',  $key_path,
        '-out',  $csr_file,
        '-subj', "/CN=$hostname",
    );

    my $csr_pem = _slurp($csr_file);
    return { csr_pem => $csr_pem };
}


# cert_dir defaults to /etc/ctrl-exec-agent
sub store_certs {
    my (%opts) = @_;
    my $cert_pem          = $opts{cert_pem}          or croak "cert_pem required";
    my $ca_pem            = $opts{ca_pem}             or croak "ca_pem required";
    my $key_pem           = $opts{key_pem}            or croak "key_pem required";
    my $dispatcher_serial = $opts{dispatcher_serial}  // '';
    my $dispatcher_id     = $opts{dispatcher_id}      // '';
    my $cert_dir          = $opts{cert_dir}            // '/etc/ctrl-exec-agent';
    my $group             = $opts{group}               // 'ctrl-exec-agent';
    # The trusted-dispatcher map lives in the agent-writable state directory, not
    # the root-owned config dir, so the agent can update it during cert rotation
    # (over the run channel, as the service user) without re-pairing. Secrets
    # (key/cert/CA) stay in the root-owned config dir.
    my $trusted_path      = $opts{trusted_path}        // '/var/lib/ctrl-exec-agent/ctrl-exec-dispatchers';

    _write_file("$cert_dir/agent.crt", $cert_pem, 0640);
    _write_file("$cert_dir/agent.key", $key_pem,  0640);
    _write_file("$cert_dir/ca.crt",   $ca_pem,   0644);

    # Record the approving dispatcher in the trusted-dispatcher map, keyed by its
    # cert serial and carrying its stable identity. Appended, not overwritten, so
    # an agent already paired with one dispatcher keeps trusting it when a second
    # one pairs. The map gates /run, /ping, /result and /capabilities and drives
    # per-call attribution. See load_trusted_dispatchers / dispatcher_trusted.
    if (length $dispatcher_serial) {
        # Pairing runs as root; make sure the state directory exists and is owned
        # by the service user so later in-place rewrites (cert rotation) succeed.
        _ensure_owned_dir(dirname($trusted_path), $group);
        add_trusted_dispatcher(
            path   => $trusted_path,
            serial => $dispatcher_serial,
            id     => (length $dispatcher_id ? $dispatcher_id : $dispatcher_serial),
        );
    }

    # Set group ownership so the service user can read the certs
    my $gid = getgrnam($group);
    if (defined $gid) {
        chown 0, $gid, "$cert_dir/agent.crt",
                       "$cert_dir/agent.key",
                       "$cert_dir/ca.crt";
        # ctrl-exec-dispatchers is world-readable (0644) - no group ownership needed
    }
    else {
        warn "store_certs: group '$group' not found - set ownership manually\n";
    }
}

# Check whether the agent has been paired
# Returns hashref: { paired => 1, expiry => 'YYYY-MM-DD' }
#               or { paired => 0, reason => '...' }
sub pairing_status {
    my (%opts) = @_;
    my $cert_dir = $opts{cert_dir} // '/etc/ctrl-exec-agent';
    my $cert     = "$cert_dir/agent.crt";
    my $key      = "$cert_dir/agent.key";
    my $ca       = "$cert_dir/ca.crt";

    for my $f ($cert, $key, $ca) {
        unless (-f $f) {
            return { paired => 0, reason => "missing file: $f" };
        }
    }

    # Extract expiry date from cert
    my $expiry = _cert_expiry($cert);
    unless (defined $expiry) {
        return { paired => 0, reason => "cannot parse cert: $cert" };
    }

    return { paired => 1, expiry => $expiry };
}

# Two-phase pairing: submit CSR, get reqid, keep socket open.
# Returns { ok => 1, reqid => '...', sock => $sock, nonce => '...' }
#      or { ok => 0, error => '...' }
sub submit_pairing_request {
    my (%opts) = @_;
    my $dispatcher_host = $opts{'ctrl-exec'} or croak "ctrl-exec required";
    my $port            = $opts{port}       // 7444;
    my $csr_pem         = $opts{csr_pem}    or croak "csr_pem required";
    my $hostname        = $opts{hostname}   or croak "hostname required";
    my $ca_cert         = $opts{ca_cert};
    my $lookup_by       = $opts{lookup_by};    # optional dispatch-resolution hint
    my $agent_port      = $opts{agent_port};   # agent's operational serve port

    require IO::Socket::SSL;
    require JSON;

    my $nonce = _gen_nonce();

    my %ssl_opts = (
        PeerHost        => $dispatcher_host,
        PeerPort        => $port,
        Timeout         => 660,
        SSL_verify_mode => $ca_cert
            ? IO::Socket::SSL::SSL_VERIFY_PEER()
            : IO::Socket::SSL::SSL_VERIFY_NONE(),
    );
    $ssl_opts{SSL_ca_file} = $ca_cert if $ca_cert;

    my $sock = IO::Socket::SSL->new(%ssl_opts)
        or return { ok => 0, error => "connect failed: $IO::Socket::SSL::SSL_ERROR" };

    my %request = (
        hostname => $hostname,
        csr      => $csr_pem,
        nonce    => $nonce,
    );
    $request{lookup_by} = $lookup_by  if defined $lookup_by;
    $request{port}      = $agent_port if defined $agent_port;
    # Report our own source address. The dispatcher prefers this over the
    # connection's source IP, which a NAT in front of it (e.g. Docker) rewrites
    # to the gateway address, so every agent would otherwise register the same.
    my $source_ip = $sock->sockhost;
    $request{ip} = $source_ip if defined $source_ip && length $source_ip;
    my $payload = JSON::encode_json(\%request);

    print $sock "POST /pair HTTP/1.0\r\n",
                "Content-Type: application/json\r\n",
                "Content-Length: ", length($payload), "\r\n",
                "\r\n",
                $payload;

    # Read the immediate acknowledgement: {status: pending, reqid: ...}
    my $status_line = <$sock>;
    return { ok => 0, error => "no response from ctrl-exec" } unless $status_line;

    my $content_length;
    while (my $line = <$sock>) {
        $line =~ s/\r\n$//;
        $line =~ s/\n$//;
        last if $line eq '';
        if ($line =~ /^Content-Length:\s*(\d+)/i) {
            $content_length = $1;
        }
    }

    return { ok => 0, error => "no Content-Length in pairing acknowledgement" }
        unless defined $content_length;

    my $body = '';
    read $sock, $body, $content_length;

    return { ok => 0, error => "empty acknowledgement body" } unless length $body;

    my $data = eval { JSON::decode_json($body) };
    return { ok => 0, error => "bad JSON in acknowledgement: $@" } if $@;

    if (($data->{status} // '') eq 'error') {
        return { ok => 0, error => $data->{reason} // 'ctrl-exec returned error' };
    }

    unless (($data->{status} // '') eq 'pending' && $data->{reqid}) {
        return { ok => 0, error => "unexpected acknowledgement: $body" };
    }

    # Socket stays open - ctrl-exec polls for approval and sends final response
    return {
        ok    => 1,
        reqid => $data->{reqid},
        sock  => $sock,
        nonce => $nonce,
    };
}

# Read the final approval/denial response on the open pairing socket.
# Call after submit_pairing_request succeeds.
# Returns { ok => 1, cert_pem => '...', ca_pem => '...', dispatcher_serial => '...' }
#      or { ok => 0, error => '...' }
sub await_pairing_result {
    my (%opts) = @_;
    my $sock  = $opts{sock}  or croak "sock required";
    my $nonce = $opts{nonce} or croak "nonce required";

    my $content_length;
    while (my $line = <$sock>) {
        $line =~ s/\r\n$//;
        $line =~ s/\n$//;
        last if $line eq '';
        if ($line =~ /^Content-Length:\s*(\d+)/i) {
            $content_length = $1;
        }
    }

    return { ok => 0, error => "no Content-Length in pairing result" }
        unless defined $content_length;

    my $body = '';
    read $sock, $body, $content_length;
    close $sock;

    return { ok => 0, error => "empty result body" } unless length $body;

    my $data = eval { JSON::decode_json($body) };
    return { ok => 0, error => "bad JSON in result: $@" } if $@;

    if (($data->{status} // '') eq 'approved') {
        if (($data->{nonce} // '') ne $nonce) {
            return { ok => 0, error => 'nonce mismatch in pairing result' };
        }
        return {
            ok                => 1,
            cert_pem          => $data->{cert},
            ca_pem            => $data->{ca},
            dispatcher_serial => $data->{dispatcher_serial} // '',
            dispatcher_id     => $data->{dispatcher_id}     // '',
        };
    }

    return { ok => 0, error => $data->{reason} // 'denied' };
}

# Validate a dispatcher identity label - the stable per-dispatcher key used for
# permission and attribution. Must start with an alphanumeric and contain only
# letters, digits, dot, hyphen, underscore, capped at 64 chars, so it is safe in
# a syslog line, an env var value, a map-file token, and an async run-owner tag.
# Serials rotate; this identity does not, so per-dispatcher policy keys on it.
sub valid_dispatcher_id {
    my ($id) = @_;
    return defined $id && $id =~ /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}\z/ ? 1 : 0;
}

# Load the trusted-dispatcher map: the set of dispatcher cert serials this agent
# accepts, each mapped to that dispatcher's stable identity. Tolerates an absent
# file (returns {}). One entry per line: "<serial> <id>". The serial is
# normalised to lowercase hex (serial_to_hex) so a decimal serial off the wire
# matches a hex map entry; the id is validated. Lines beginning with # are
# comments; malformed lines are skipped.
#
# Returns hashref: { '<hex-serial>' => '<id>', ... }
sub load_trusted_dispatchers {
    my (%opts) = @_;
    my $path = $opts{path} or croak "path required";

    my %trusted;
    return \%trusted unless -f $path;

    open my $fh, '<', $path
        or do { warn "Cannot read trusted dispatchers '$path': $!\n"; return \%trusted; };
    while (my $line = <$fh>) {
        chomp $line;
        $line =~ s/#.*$//;        # strip comments
        $line =~ s/^\s+|\s+$//g;  # strip surrounding whitespace
        next unless length $line;
        my ($serial, $id) = split /\s+/, $line, 2;
        $serial = serial_to_hex($serial // '');
        next unless length $serial;
        next unless defined $id && valid_dispatcher_id($id);
        $trusted{$serial} = $id;
    }
    close $fh;

    return \%trusted;
}

# Resolve a connecting peer's cert serial to its trusted dispatcher identity.
# Returns the id string when the serial is trusted, or undef when it is not (or
# when either input is empty). Normalises the serial the same way the loader
# does, so a decimal serial from IO::Socket::SSL matches a hex map entry.
sub dispatcher_trusted {
    my ($peer_serial, $trusted) = @_;
    return undef unless ref $trusted eq 'HASH';
    my $hex = serial_to_hex($peer_serial // '');
    return undef unless length $hex;
    my $id = $trusted->{$hex};
    return (defined $id && length $id) ? $id : undef;
}

# Add or update one trusted-dispatcher entry, preserving every other entry.
# This is the append-enrolment primitive: pairing a second dispatcher adds its
# serial without unpairing the first; re-pairing the same dispatcher (new serial
# after rotation/re-key) adds the new serial. Writes the file atomically. Dies
# on an unusable serial or an invalid id.
#
# Required opts:
#   path   => $str
#   serial => $str   (any form accepted by serial_to_hex)
#   id     => $str   (must satisfy valid_dispatcher_id)
sub add_trusted_dispatcher {
    my (%opts) = @_;
    my $path = $opts{path} or croak "path required";
    my $hex  = serial_to_hex($opts{serial} // '');
    croak "invalid dispatcher serial" unless length $hex;
    my $id   = $opts{id};
    croak "invalid dispatcher id '" . ($id // '') . "'"
        unless valid_dispatcher_id($id);

    my $trusted = load_trusted_dispatchers(path => $path);
    $trusted->{$hex} = $id;

    my $content = "# ctrl-exec trusted dispatchers: <serial> <id>, one per line.\n"
                . "# Managed by pairing - do not edit by hand.\n";
    for my $s (sort keys %$trusted) {
        $content .= "$s $trusted->{$s}\n";
    }
    _write_file($path, $content, 0644);
    return $trusted;
}

# Remove one trusted-dispatcher entry by serial, preserving every other entry.
# This is the "remove" half of add-then-remove cert rotation: once agents have
# adopted a dispatcher's new serial and the overlap window has passed, the old
# serial is removed so the retired cert is no longer trusted. A no-op (returns 0)
# if the serial is absent or the file does not exist; returns 1 when an entry was
# removed. Writes atomically.
#
# Required opts:
#   path   => $str
#   serial => $str   (any form accepted by serial_to_hex)
sub remove_trusted_dispatcher {
    my (%opts) = @_;
    my $path = $opts{path} or croak "path required";
    my $hex  = serial_to_hex($opts{serial} // '');
    croak "invalid dispatcher serial" unless length $hex;

    return 0 unless -f $path;
    my $trusted = load_trusted_dispatchers(path => $path);
    return 0 unless exists $trusted->{$hex};
    delete $trusted->{$hex};

    my $content = "# ctrl-exec trusted dispatchers: <serial> <id>, one per line.\n"
                . "# Managed by pairing - do not edit by hand.\n";
    for my $s (sort keys %$trusted) {
        $content .= "$s $trusted->{$s}\n";
    }
    _write_file($path, $content, 0644);
    return 1;
}

# Load the revoked serials file into a hashref keyed by lowercase hex serial.
# Tolerates absent file - returns empty hashref.
# Format: one serial per line, hex string (as output by openssl x509 -serial,
# with or without "serial=" prefix, upper or lower case - all normalised).
# Lines beginning with # are treated as comments and ignored.
#
# Returns hashref: { 'aabbcc...' => 1, ... }
sub load_revoked_serials {
    my (%opts) = @_;
    my $path = $opts{path} or croak "path required";

    my %revoked;
    unless (-f $path) {
        Exec::Log::log_action('INFO', {
            ACTION => 'revoked-serials-absent',
            PATH   => $path,
            REASON => 'file not found - no serials revoked',
        });
        return \%revoked;
    }

    open my $fh, '<', $path
        or do { warn "Cannot read revoked serials '$path': $!\n"; return \%revoked; };

    while (my $line = <$fh>) {
        chomp $line;
        $line =~ s/#.*$//;       # strip comments
        $line =~ s/^\s+|\s+$//g; # strip whitespace
        next unless length $line;
        $line = serial_to_hex($line);
        next unless length $line;
        $revoked{$line} = 1;
    }
    close $fh;

    return \%revoked;
}

# Return true if the given serial (lowercase hex from _peer_serial,
# or any format accepted by serial_to_hex) is in the revoked set.
# Normalises the input to lowercase hex before checking.
sub serial_revoked {
    my ($serial, $revoked) = @_;
    return 0 unless defined $serial && ref $revoked eq 'HASH';
    my $hex = serial_to_hex($serial);
    return exists $revoked->{$hex} ? 1 : 0;
}

# --- private helpers ---

# Normalise a serial number to lowercase hex.
# Accepts either a decimal string (from IO::Socket::SSL peer_certificate)
# or a hex string (from openssl x509 -serial output).
# Hex strings are identified by non-decimal characters or a leading 0x.
sub serial_to_hex {
    my ($serial) = @_;
    return '' unless defined $serial && length $serial;
    $serial =~ s/^0x//i;
    $serial =~ s/^serial=//i;

    # Strip colon separators (e.g. DE:AD:BE:EF from IO::Socket::SSL).
    # OpenSSL prepends a 00 byte to positive-integer DER serials; strip it.
    if ($serial =~ /:/) {
        $serial =~ s/://g;
        $serial = lc $serial;
        $serial =~ s/^(?:00)+(?=.{2})//;  # strip leading 00 bytes (keep at least 2 hex chars)
        return $serial;
    }

    $serial = lc $serial;

    # A pure decimal string must be converted. Test explicitly: decimal strings
    # contain only [0-9] and cannot contain [a-f], but digits-only strings also
    # satisfy \A[0-9a-f]+\z so we must check for decimal first.
    if ($serial =~ /\A[0-9]+\z/) {
        # Cert serials can be up to 20 bytes (160 bits), requiring bignum
        # arithmetic. We do not use sprintf '%x' because Perl's native integer
        # coercion silently loses precision for large decimal strings.
        require Math::BigInt;
        return lc( Math::BigInt->new($serial)->as_hex =~ s/^0x//r );
    }

    # If it contains only valid hex characters it is already hex. Strip any
    # insignificant leading zeros first so a value carrying a leading 00 byte -
    # a serial migrated from an older single-serial file, or a hand-edited map
    # entry - canonicalises to the same key the live readers produce. Both
    # `openssl x509 -serial` and Net::SSLeay::P_ASN1_INTEGER_get_hex emit minimal
    # hex with no leading zero, so without this strip '00aabb...' (stored) never
    # matches a live 'aabb...' and every request from that dispatcher is rejected
    # as a serial mismatch. (The colon-separated branch above already strips its
    # leading 00 byte; this keeps the plain-hex branch consistent with it.)
    if ($serial =~ /\A[0-9a-f]+\z/) {
        $serial =~ s/\A0+(?=[0-9a-f])//;
        return $serial;
    }

    # Contains non-hex characters - treat as large decimal via bignum.
    require Math::BigInt;
    return lc( Math::BigInt->new($serial)->as_hex =~ s/^0x//r );
}

sub _gen_nonce {
    # Use /dev/urandom for cryptographically unpredictable nonces.
    # Perl's rand() is not cryptographically random and must not be used
    # for nonces intended to prevent replay attacks.
    open my $fh, '<:raw', '/dev/urandom'
        or croak "Cannot open /dev/urandom: $!";
    read $fh, my $bytes, 16;
    close $fh;
    return unpack 'H*', $bytes;
}

sub _run_or_die {
    my @cmd = @_;
    system(@cmd) == 0
        or croak "Command failed (@cmd): $?";
}

# Validate a candidate (renewed) cert before adopting it: it must verify against
# the agent's CA and its public key must match the agent's existing private key
# (renewal preserves the key). The cert is public material, so this is a
# robustness gate - never adopt a cert that would not actually work, and never
# let a buggy or hostile delivery overwrite a working cert - not a secret
# boundary. Returns (1) on success or (0, $reason).
sub validate_cert {
    my (%o) = @_;
    my $cert_pem = defined $o{cert_pem} ? $o{cert_pem} : croak "cert_pem required";
    my $ca_path  = $o{ca_path}  or croak "ca_path required";
    my $key_path = $o{key_path} or croak "key_path required";

    return (0, "CA cert not found at '$ca_path'")  unless -f $ca_path;
    return (0, "agent key not found at '$key_path'") unless -f $key_path;

    my ($cfh, $cpath) = tempfile(SUFFIX => '.crt', UNLINK => 1);
    print $cfh $cert_pem;
    close $cfh;

    # 1. Verify against the agent's CA. A 127 exit means openssl is not on PATH -
    # report that distinctly so a hands-free renewal failure is not misattributed
    # to a bad cert. Either way this fails closed (no adoption).
    my $vout = `openssl verify -CAfile \Q$ca_path\E \Q$cpath\E 2>&1`;
    return (0, "openssl not available") if ($? >> 8) == 127;
    return (0, "renewed cert does not verify against the agent CA")
        unless $? == 0;

    # 2. Public key of the cert must equal the public key of the agent's key.
    my $cpub = `openssl x509 -in \Q$cpath\E -noout -pubkey 2>/dev/null`;
    my $kpub = `openssl pkey -in \Q$key_path\E -pubout 2>/dev/null`;
    return (0, "renewed cert public key does not match the agent key")
        unless length($cpub // '') && length($kpub // '') && $cpub eq $kpub;

    return (1, undef);
}

# Stage a renewed cert (runs as the unprivileged agent): validate it, then write
# it atomically to $staged_path (in the agent-writable state dir). The live cert
# is NOT touched here - it is promoted at the next agent start (promote_staged_cert).
# Returns { ok => 1 } or { ok => 0, error => ... }.
sub stage_renewed_cert {
    my (%o) = @_;
    my $cert_pem    = defined $o{cert_pem} ? $o{cert_pem} : croak "cert_pem required";
    my $staged_path = $o{staged_path} or croak "staged_path required";

    my ($ok, $reason) = validate_cert(
        cert_pem => $cert_pem, ca_path => $o{ca_path}, key_path => $o{key_path});
    return { ok => 0, error => $reason } unless $ok;

    eval { _write_file($staged_path, $cert_pem, 0640); 1 }
        or return { ok => 0, error => "could not stage cert: $@" };
    return { ok => 1 };
}

# Promote a staged cert to the live cert path (runs as root, at agent start). If
# a staged cert exists and validates, install it atomically (preserving the live
# cert's owner/group so the service user keeps read access) and remove the staged
# file. A staged cert that fails validation is dropped without touching the live
# cert, so a bad delivery can never wedge promotion or break the running agent.
# Returns { ok => 1, promoted => 0|1 } or { ok => 0, error => ... }.
sub promote_staged_cert {
    my (%o) = @_;
    my $staged_path = $o{staged_path} or croak "staged_path required";
    my $cert_path   = $o{cert_path}   or croak "cert_path required";

    return { ok => 1, promoted => 0 } unless -f $staged_path;

    my $cert_pem = eval { _slurp($staged_path) };
    return { ok => 0, error => "cannot read staged cert: $@" } unless defined $cert_pem;

    my ($valid, $reason) = validate_cert(
        cert_pem => $cert_pem, ca_path => $o{ca_path}, key_path => $o{key_path});
    unless ($valid) {
        unlink $staged_path;
        return { ok => 0, error => $reason };
    }

    my @st = stat($cert_path);   # capture owner/group before replacing
    eval { _write_file($cert_path, $cert_pem, 0640); 1 }
        or return { ok => 0, error => "could not install cert: $@" };
    # Restore the live cert's prior owner:group (root:agent-group) so the service
    # user keeps read access. Skipped only if there was no prior cert - which does
    # not happen in practice, as pairing writes the live cert before any renewal.
    chown $st[4], $st[5], $cert_path if @st;
    unlink $staged_path;
    return { ok => 1, promoted => 1 };
}

# Ensure a directory exists and, when run as root with the service account
# present, is owned by it (0750) so the non-root agent can rewrite files in it
# later. Best-effort: a missing user/group or a failed chown (e.g. non-root in
# tests) is left to the caller's packaging to settle, not fatal here.
sub _ensure_owned_dir {
    my ($dir, $account) = @_;
    make_path($dir) unless -d $dir;
    my $uid = getpwnam($account);
    my $gid = getgrnam($account);
    if (defined $uid || defined $gid) {
        chown((defined $uid ? $uid : -1), (defined $gid ? $gid : -1), $dir);
    }
    chmod 0750, $dir;
}

sub _slurp {
    my ($path) = @_;
    open my $fh, '<', $path or croak "Cannot read '$path': $!";
    local $/;
    return scalar <$fh>;
}

sub _write_file {
    my ($path, $content, $mode) = @_;
    my $dir = dirname($path);
    croak "Directory '$dir' does not exist" unless -d $dir;

    my ($tmp_fh, $tmp_path) = tempfile(DIR => $dir, UNLINK => 0);
    print $tmp_fh $content;
    close $tmp_fh;

    chmod $mode, $tmp_path;
    rename $tmp_path, $path
        or do { unlink $tmp_path; croak "rename failed for '$path': $!" };
}

sub _cert_expiry {
    my ($cert_path) = @_;
    my $out = `openssl x509 -noout -enddate -in \Q$cert_path\E 2>/dev/null`;
    return unless defined $out && $out =~ /notAfter=(.+)/;
    my $date_str = $1;
    chomp $date_str;
    return $date_str;
}

1;
