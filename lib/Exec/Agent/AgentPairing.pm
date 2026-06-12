package Exec::Agent::AgentPairing;

use strict;
use warnings;
use File::Temp qw(tempfile tempdir);
use File::Basename qw(dirname);
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
    my $cert_dir          = $opts{cert_dir}            // '/etc/ctrl-exec-agent';
    my $group             = $opts{group}               // 'ctrl-exec-agent';

    _write_file("$cert_dir/agent.crt", $cert_pem, 0640);
    _write_file("$cert_dir/agent.key", $key_pem,  0640);
    _write_file("$cert_dir/ca.crt",   $ca_pem,   0644);

    # Store dispatcher cert serial for capabilities access control.
    # The agent uses this to restrict /capabilities to the genuine ctrl-exec
    # only, preventing lateral reconnaissance from a compromised agent peer.
    if (length $dispatcher_serial) {
        _write_file("$cert_dir/ctrl-exec-serial", $dispatcher_serial . "\n", 0644);
    }

    # Set group ownership so the service user can read the certs
    my $gid = getgrnam($group);
    if (defined $gid) {
        chown 0, $gid, "$cert_dir/agent.crt",
                       "$cert_dir/agent.key",
                       "$cert_dir/ca.crt";
        # ctrl-exec-serial is world-readable (0644) - no group ownership needed
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
        };
    }

    return { ok => 0, error => $data->{reason} // 'denied' };
}

# Connect to ctrl-exec pairing port, send CSR, wait for approval
# Returns hashref: { ok => 1, cert_pem => '...', ca_pem => '...' }
#               or { ok => 0, error => '...' }
sub request_pairing {
    my (%opts) = @_;
    my $dispatcher_host = $opts{'ctrl-exec'} or croak "ctrl-exec required";
    my $port            = $opts{port}       // 7444;
    my $csr_pem         = $opts{csr_pem}    or croak "csr_pem required";
    my $hostname        = $opts{hostname}   or croak "hostname required";
    my $ca_cert         = $opts{ca_cert};   # optional: verify dispatcher cert

    require IO::Socket::SSL;
    require JSON;

    # Generate a per-request nonce to verify the response is for this specific
    # request and not a replayed or misrouted one.
    my $nonce = _gen_nonce();

    my %ssl_opts = (
        PeerHost        => $dispatcher_host,
        PeerPort        => $port,
        Timeout         => 660,    # 11 minutes - longer than ctrl-exec's 10 min poll window
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
    # Report our own source address (see the foreground path for why).
    my $source_ip = $sock->sockhost;
    $request{ip} = $source_ip if defined $source_ip && length $source_ip;
    my $payload = JSON::encode_json(\%request);

    print $sock "POST /pair HTTP/1.0\r\n",
                "Content-Type: application/json\r\n",
                "Content-Length: ", length($payload), "\r\n",
                "\r\n",
                $payload;

    # Read HTTP response headers line by line
    my $status_line = <$sock>;
    return { ok => 0, error => "no response from ctrl-exec" } unless $status_line;

    my $content_length;
    while (my $line = <$sock>) {
        $line =~ s/\r\n$//;
        $line =~ s/\n$//;
        last if $line eq '';   # blank line = end of headers
        if ($line =~ /^Content-Length:\s*(\d+)/i) {
            $content_length = $1;
        }
    }

    return { ok => 0, error => "no Content-Length in pairing response" }
        unless defined $content_length;

    # Read exactly content_length bytes - no waiting for EOF
    my $body = '';
    read $sock, $body, $content_length;
    close $sock;

    return { ok => 0, error => "empty response body" } unless length $body;

    my $data = eval { JSON::decode_json($body) };
    return { ok => 0, error => "bad JSON: $@" } if $@;

    if ($data->{status} eq 'approved') {
        if (($data->{nonce} // '') ne $nonce) {
            return { ok => 0, error => 'nonce mismatch in pairing response' };
        }
        return {
            ok                => 1,
            cert_pem          => $data->{cert},
            ca_pem            => $data->{ca},
            dispatcher_serial => $data->{dispatcher_serial} // '',
        };
    }

    return { ok => 0, error => $data->{reason} // 'denied' };
}

# Load the stored dispatcher cert serial from file.
# Returns lowercase hex string, or empty string if file absent or unreadable.
# File contains a single line written by store_certs at pairing time.
sub load_dispatcher_serial {
    my (%opts) = @_;
    my $path = $opts{path} or croak "path required";

    return '' unless -f $path;

    open my $fh, '<', $path
        or do { warn "Cannot read dispatcher serial '$path': $!\n"; return ''; };
    my $line = <$fh>;
    close $fh;

    return '' unless defined $line;
    $line =~ s/\s+//g;
    $line = lc $line;
    return $line =~ /^[0-9a-f]+$/ ? $line : '';
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

    # If it contains only valid hex characters it is already hex.
    if ($serial =~ /\A[0-9a-f]+\z/) {
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
