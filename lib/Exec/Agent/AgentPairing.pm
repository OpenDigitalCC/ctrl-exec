package Exec::Agent::AgentPairing;

use strict;
use warnings;
use feature      qw(signatures);
no warnings      qw(experimental::signatures);
use File::Temp qw(tempfile tempdir);
use File::Basename qw(dirname);
use File::Path qw(make_path);
use Carp qw(croak);
use Exec::CertInfo qw();
use Exec::Cmd      qw();
use Exec::Digest   qw();
use Exec::FileUtil qw(slurp);
use Exec::Log qw();
use Exec::Random qw();


# Generate a private key and CSR using openssl
# Returns hashref: { key_pem => '...', csr_pem => '...' }
# or dies on failure
sub generate_key_and_csr (%opts) {
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

    my $key_pem = slurp($key_file);
    my $csr_pem = slurp($csr_file);

    return { key_pem => $key_pem, csr_pem => $csr_pem };
}

# Generate a CSR from the existing agent key, without generating a new key.
# Used for cert renewal - key continuity is preserved.
# Returns hashref: { csr_pem => '...' } or dies on failure.
sub generate_csr_only (%opts) {
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

    my $csr_pem = slurp($csr_file);
    return { csr_pem => $csr_pem };
}


# The agent's current identity, for pairing with another dispatcher without a
# new key (T-062): its certificate, its key and the CA in its bundle that issued
# the certificate. Returned only when all three files are there, the
# certificate verifies against that CA today (signature and dates) and its
# public key is the key's. Otherwise the agent pairs as an unpaired one does
# (new key, CSR signed by the dispatcher).
# Returns { cert_pem, ca_pem, ca_fpr, key_path } or undef.
sub kept_identity (%opts) {
    my $cert_dir = $opts{cert_dir} // '/etc/ctrl-exec-agent';
    my ($cert, $key, $ca) = map { "$cert_dir/$_" } qw(agent.crt agent.key ca.crt);
    return unless -f $cert && -f $key && -f $ca;
    my $cert_pem = Exec::FileUtil::slurp_maybe($cert) // return;
    # Sent as openssl writes them: the dispatcher hashes them into the pairing
    # code and requires exactly that form.
    ($cert_pem) = pem_certs($cert_pem) or return;
    $cert_pem = Exec::Digest::canonical_cert($cert_pem) // return;

    my $bundle = load_ca_bundle($ca);
    my @fprs   = pem_issuers($cert_pem, $bundle);
    my ($issuer) = grep { $_->{fpr} eq ($fprs[0] // '') } @$bundle;
    my $ca_pem = $issuer ? Exec::Digest::canonical_cert($issuer->{pem}) : undef;
    free_ca_bundle($bundle);
    return unless defined $ca_pem;
    return if defined Exec::CertInfo::verify_issued_by($cert_pem, $ca_pem);

    my $kpub = `openssl pkey -in \Q$key\E -pubout 2>/dev/null`;
    my $cpub = Exec::CertInfo::public_key_from_pem($cert_pem);
    return unless length($kpub // '') && defined $cpub && $kpub eq $cpub;

    return { cert_pem => $cert_pem, ca_pem => $ca_pem, ca_fpr => $fprs[0],
             key_path => $key };
}

# The ids in the trusted-dispatcher map at $path, sorted, each once.
sub trusted_dispatcher_ids ($path, $ca_path = undef) {
    return () unless defined $path && -f $path;
    my $trusted = load_trusted_dispatchers(path => $path, ca_path => $ca_path);
    my %ids = map { $_ => 1 } values %$trusted;
    my @ids = sort keys %ids;
    return @ids;
}

# cert_dir defaults to /etc/ctrl-exec-agent
#
# keep_cert => 1 (keep-certificate pairing, T-062): the agent keeps its key and
# certificate; only the dispatcher's CA joins the bundle and the dispatcher
# joins the trusted map. cert_pem and key_pem are not taken.
sub store_certs (%opts) {
    my $keep              = $opts{keep_cert} ? 1 : 0;
    my $cert_pem          = $keep ? undef : ($opts{cert_pem} or croak "cert_pem required");
    my $ca_pem            = $opts{ca_pem}             or croak "ca_pem required";
    my $key_pem           = $keep ? undef : ($opts{key_pem}  or croak "key_pem required");
    my $dispatcher_serial = $opts{dispatcher_serial}  // '';
    my $dispatcher_id     = $opts{dispatcher_id}      // '';
    my $cert_dir          = $opts{cert_dir}            // '/etc/ctrl-exec-agent';
    my $group             = $opts{group}               // 'ctrl-exec-agent';
    # The trusted-dispatcher map lives in the agent-writable state directory, not
    # the root-owned config dir, so the agent can update it during cert rotation
    # (over the run channel, as the service user) without re-pairing. Secrets
    # (key/cert/CA) stay in the root-owned config dir.
    my $trusted_path      = $opts{trusted_path}        // '/var/lib/ctrl-exec-agent/ctrl-exec-dispatchers';
    my $ca_path           = "$cert_dir/ca.crt";

    # Refuse a CA that is not a certificate before anything is written, so a
    # bad delivery cannot leave a half-stored pairing behind.
    my @ca_pems = pem_certs($ca_pem);
    croak "ca_pem holds no certificate" unless @ca_pems;
    defined pem_fingerprint($_) or croak "ca_pem holds an unreadable certificate"
        for @ca_pems;

    # A map written before 0.14 carries no issuing CA. Bring it to the issuer-
    # keyed form against the CA bundle as it is NOW, before this dispatcher's CA
    # joins it: an existing entry belongs to the CA(s) the agent trusted when it
    # was written, never to the dispatcher pairing now.
    load_trusted_dispatchers(path => $trusted_path, ca_path => $ca_path)
        if -f $trusted_path;

    unless ($keep) {
        _write_file("$cert_dir/agent.crt", $cert_pem, 0640);
        _write_file("$cert_dir/agent.key", $key_pem,  0640);
    }

    # ca.crt is the agent's CA bundle: the dispatcher's CA is appended (once,
    # by fingerprint), not written over the CAs of dispatchers paired before.
    my @issuers = add_to_ca_bundle(path => $ca_path, pem => $ca_pem);

    # Record the approving dispatcher in the trusted-dispatcher map, keyed by its
    # issuing CA and cert serial and carrying its stable identity. Appended, not
    # overwritten, so an agent already paired with one dispatcher keeps trusting
    # it when a second one pairs. The map gates /run, /ping, /result and
    # /capabilities and drives per-call attribution. See load_trusted_dispatchers
    # / dispatcher_trusted.
    if (length $dispatcher_serial) {
        # Pairing runs as root; make sure the state directory exists and is owned
        # by the service user so later in-place rewrites (cert rotation) succeed.
        _ensure_owned_dir(dirname($trusted_path), $group);
        # supersede: a re-pair of the same identity under a different CA ends
        # that identity's trust under its old CA, as overwriting ca.crt did.
        add_trusted_dispatcher(
            path      => $trusted_path,
            serial    => $dispatcher_serial,
            id        => (length $dispatcher_id ? $dispatcher_id : $dispatcher_serial),
            issuer    => \@issuers,
            supersede => 1,
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
sub pairing_status (%opts) {
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

# The pairing code version this agent computes and states in its request.
# See Exec::Digest for the versions.
our $PAIRING_CODE_VERSION = 2;

# Two-phase pairing: submit CSR, get reqid, keep socket open.
# Returns { ok => 1, reqid => '...', sock => $sock, nonce => '...',
#           code => '123456', code_version => 2,
#           dispatcher_fpr => '<64 hex>', dispatcher_confirms_v2 => 0|1 }
#      or { ok => 0, error => '...' }
#
# code is the v2 pairing code, bound to the certificate presented on THIS
# connection: the operator compares it with the dispatcher's display. A relay
# that terminates TLS presents a different certificate, so the codes differ.
# dispatcher_confirms_v2 is false when the acknowledgement does not echo the
# code version - a dispatcher older than 0.13, which shows a v1 code instead.
sub submit_pairing_request (%opts) {
    my $dispatcher_host = $opts{'ctrl-exec'} or croak "ctrl-exec required";
    my $port            = $opts{port}       // 7444;
    my $csr_pem         = $opts{csr_pem}    or croak "csr_pem required";
    my $hostname        = $opts{hostname}   or croak "hostname required";
    my $ca_cert         = $opts{ca_cert};
    my $lookup_by       = $opts{lookup_by};    # optional dispatch-resolution hint
    my $agent_port      = $opts{agent_port};   # agent's operational serve port
    # Seconds allowed for the TCP connect and the TLS handshake. The default is
    # generous for a slow dispatcher host; tests pass a few seconds.
    my $timeout         = $opts{timeout}    // 660;
    # Keep-certificate form (T-062): the agent's current certificate and the CA
    # that issued it, sent with a CSR made from the same key.
    my $agent_cert      = $opts{agent_cert};
    my $agent_ca        = $opts{agent_ca};
    croak "agent_cert and agent_ca go together"
        if (defined $agent_cert) != (defined $agent_ca);

    require IO::Socket::SSL;
    require JSON;

    my $nonce = _gen_nonce();

    my %ssl_opts = (
        PeerHost        => $dispatcher_host,
        PeerPort        => $port,
        Timeout         => $timeout,
        SSL_verify_mode => $ca_cert
            ? IO::Socket::SSL::SSL_VERIFY_PEER()
            : IO::Socket::SSL::SSL_VERIFY_NONE(),
    );
    $ssl_opts{SSL_ca_file} = $ca_cert if $ca_cert;

    my $sock = IO::Socket::SSL->new(%ssl_opts)
        or return { ok => 0, error => "connect failed: $IO::Socket::SSL::SSL_ERROR" };

    # SHA-256 of the DER of the certificate the dispatcher (or whatever answered)
    # presented on this connection - the value the v2 code binds to.
    my $fpr_bin = eval { $sock->get_fingerprint_bin('sha256') };
    return { ok => 0, error => "cannot fingerprint the dispatcher certificate" }
        unless defined $fpr_bin && length $fpr_bin == 32;
    my $dispatcher_fpr = unpack 'H*', $fpr_bin;

    # Verified pairing (T-041): with the dispatcher's CA fingerprint, the
    # certificate this connection presented must chain to that CA. Checked here,
    # after the handshake and before anything is sent, so a listener that fails
    # it never receives the CSR.
    if (defined(my $want = $opts{dispatcher_ca_fpr})) {
        my $why = verify_dispatcher_ca($sock, $want);
        if (defined $why) {
            $sock->close(SSL_no_shutdown => 1);
            return { ok => 0, verify_failed => 1, error => $why };
        }
    }

    my $code = eval {
        Exec::Digest::pairing_code_for($PAIRING_CODE_VERSION,
            Exec::Digest::pairing_input($csr_pem, $agent_cert, $agent_ca), $dispatcher_fpr)
    } // return { ok => 0, error => "cannot compute the pairing code: $@" };

    my %request = (
        hostname => $hostname,
        csr      => $csr_pem,
        nonce    => $nonce,
        code_version => $PAIRING_CODE_VERSION,
    );
    @request{qw(agent_cert agent_ca)} = ($agent_cert, $agent_ca) if defined $agent_cert;
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

    # A dispatcher before 0.14 ignores the certificate and would sign the CSR,
    # and the new certificate would replace the one the dispatchers this agent
    # is already paired with verify. Withdraw instead: nothing is stored.
    if (defined $agent_cert && ($data->{cert_mode} // '') ne 'keep') {
        $sock->close(SSL_no_shutdown => 1);
        return { ok => 0, keep_unsupported => 1, reqid => $data->{reqid},
            error => "the dispatcher did not accept this agent's existing "
                   . "certificate: it is probably older than 0.14, and pairing "
                   . "would replace the certificate the dispatchers this agent is "
                   . "already paired with verify. Request $data->{reqid} on that "
                   . "dispatcher can be denied." };
    }

    # Socket stays open - ctrl-exec polls for approval and sends final response
    return {
        ok    => 1,
        reqid => $data->{reqid},
        sock  => $sock,
        nonce => $nonce,
        code           => $code,
        code_version   => $PAIRING_CODE_VERSION,
        dispatcher_fpr => $dispatcher_fpr,
        dispatcher_confirms_v2 => (($data->{code_version} // '') eq '2' ? 1 : 0),
        cert_mode      => (defined $agent_cert ? 'keep' : 'new'),
    };
}

# Check that the certificate a pairing connection presented chains to the CA
# whose SHA-256 fingerprint is $want_fpr (64 lowercase hex). The dispatcher
# sends its CA certificate after its own; the CA is found in the presented
# chain by fingerprint and used as the only trust anchor for a full X.509
# verification of the presented certificate (signature, validity dates, CA
# constraints). Holding the CA certificate alone is not enough - it is public -
# the presented certificate must be one that CA issued, and the TLS handshake
# has already proved the peer holds that certificate's key.
# Returns undef when verified, or the reason it is not.
sub verify_dispatcher_ca ($sock, $want_fpr) {
    require Net::SSLeay;
    my $want_disp = Exec::CertInfo::format_sha256_fingerprint($want_fpr);
    my $leaf  = $sock->peer_certificate;
    my @chain = $sock->peer_certificates;
    return "the dispatcher presented no certificate" unless $leaf && @chain;

    my ($anchor, @seen);
    for my $x (@chain) {
        my $fpr = unpack 'H*', (Net::SSLeay::X509_digest($x,
            Net::SSLeay::EVP_get_digestbyname('sha256')) // '');
        push @seen, $fpr;
        $anchor //= $x if $fpr eq lc $want_fpr;
    }
    unless ($anchor) {
        return "the dispatcher's certificate does not chain to the expected CA.\n"
             . "  expected CA: $want_disp\n"
             . join('', map { "  seen:        " . Exec::CertInfo::format_sha256_fingerprint($_) . "\n" } @seen)
             . "The CSR was not sent. Check the fingerprint with "
             . "'ctrl-exec-dispatcher ca-fingerprint' on the dispatcher; a "
             . "dispatcher before 0.14 does not send its CA, so it cannot be "
             . "verified.";
    }

    my $store = Net::SSLeay::X509_STORE_new();
    my $sk    = Net::SSLeay::sk_X509_new_null();
    my $ctx   = Net::SSLeay::X509_STORE_CTX_new();
    my ($ok, $err);
    Net::SSLeay::X509_STORE_add_cert($store, $anchor);
    # The pinned certificate is the trust anchor whether or not it is
    # self-signed, so verification never reaches past it to a system store.
    Net::SSLeay::X509_STORE_set_flags($store, Net::SSLeay::X509_V_FLAG_PARTIAL_CHAIN());
    Net::SSLeay::sk_X509_push($sk, $_) for @chain[1 .. $#chain];
    if (Net::SSLeay::X509_STORE_CTX_init($ctx, $store, $leaf, $sk)) {
        $ok  = Net::SSLeay::X509_verify_cert($ctx) == 1;
        $err = Net::SSLeay::X509_verify_cert_error_string(
            Net::SSLeay::X509_STORE_CTX_get_error($ctx));
    }
    Net::SSLeay::X509_STORE_CTX_free($ctx);
    Net::SSLeay::sk_X509_free($sk);
    Net::SSLeay::X509_STORE_free($store);
    return if $ok;
    return "the dispatcher's certificate is not issued by the expected CA "
         . "(" . ($err // 'verification could not run') . ").\n"
         . "  expected CA: $want_disp\n"
         . "  seen:        " . Exec::CertInfo::format_sha256_fingerprint($seen[0])
         . " (presented certificate)\n"
         . "The CSR was not sent.";
}

# Read the final approval/denial response on the open pairing socket.
# Call after submit_pairing_request succeeds.
# Returns { ok => 1, cert_pem => '...', ca_pem => '...', dispatcher_serial => '...' }
#      or { ok => 0, error => '...' }
#
# Optional:
#   cert_mode         => 'keep'   the request kept the agent's certificate: the
#                                 approval must say so and carry no certificate
#   dispatcher_ca_fpr => '<hex>'  verified pairing (T-041): the CA delivered at
#                                 approval must be that CA, and only that CA
sub await_pairing_result (%opts) {
    my $sock  = $opts{sock}  or croak "sock required";
    my $nonce = $opts{nonce} or croak "nonce required";
    my $keep  = ($opts{cert_mode} // '') eq 'keep';

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
        if ($keep && (($data->{cert_mode} // '') ne 'keep' || defined $data->{cert})) {
            return { ok => 0, error => 'the dispatcher accepted this agent\'s '
                . 'certificate but its approval did not keep it; nothing was stored' };
        }
        if (defined(my $want = $opts{dispatcher_ca_fpr})) {
            my $why = check_delivered_ca($data->{ca}, $want);
            return { ok => 0, verify_failed => 1, error => $why } if defined $why;
        }
        return {
            ok                => 1,
            cert_mode         => ($keep ? 'keep' : 'new'),
            cert_pem          => $data->{cert},
            ca_pem            => $data->{ca},
            dispatcher_serial => $data->{dispatcher_serial} // '',
            dispatcher_id     => $data->{dispatcher_id}     // '',
        };
    }

    return { ok => 0, error => $data->{reason} // 'denied' };
}

# Verified pairing (T-041) at approval: the CA certificate(s) the dispatcher
# delivered for the agent's bundle must be exactly the CA whose fingerprint the
# operator gave - the one the pairing connection was verified against. Returns
# undef when it is, or the reason it is not.
sub check_delivered_ca ($ca_pem, $want_fpr) {
    my @pems = pem_certs($ca_pem // '');
    my @fprs = map { pem_fingerprint($_) // 'unreadable' } @pems;
    return if @fprs && !grep { $_ ne lc $want_fpr } @fprs;
    return "the CA delivered at approval is not the expected CA.\n"
         . "  expected CA: " . Exec::CertInfo::format_sha256_fingerprint(lc $want_fpr) . "\n"
         . join('', map { "  delivered:   " . ($_ eq 'unreadable' ? $_
                : Exec::CertInfo::format_sha256_fingerprint($_)) . "\n" } @fprs)
         . (@fprs ? '' : "  delivered:   none\n")
         . "Nothing was stored.";
}

# Validate a dispatcher identity label - the stable per-dispatcher key used for
# permission and attribution. Must start with an alphanumeric and contain only
# letters, digits, dot, hyphen, underscore, capped at 64 chars, so it is safe in
# a syslog line, an env var value, a map-file token, and an async run-owner tag.
# Serials rotate; this identity does not, so per-dispatcher policy keys on it.
sub valid_dispatcher_id ($id) {
    return defined $id && $id =~ /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}\z/ ? 1 : 0;
}

# --- CA bundle -------------------------------------------------------------
#
# The agent's CA file (agent.conf 'ca', /etc/ctrl-exec-agent/ca.crt) is a
# bundle: one PEM certificate per dispatcher CA the agent trusts. An install
# paired before 0.14 holds one PEM, which is a bundle of one, so nothing moves on
# upgrade. The TLS listener, self-ping and renewal validation all read it as a
# CA file, and OpenSSL takes every certificate in it.
#
# A CA is named by its fingerprint: the SHA-256 of the certificate's DER, as 64
# lowercase hex characters (Exec::CertInfo::fingerprint_from_path computes the
# same value from a file).

# The PEM certificate blocks in $text, in order.
sub pem_certs ($text) {
    return () unless defined $text;
    return $text =~ /(-----BEGIN CERTIFICATE-----\r?\n.*?-----END CERTIFICATE-----)/gs;
}

sub _valid_fpr ($fpr) {
    return defined $fpr && $fpr =~ /\A[0-9a-f]{64}\z/ ? 1 : 0;
}

# Parse one PEM certificate into a Net::SSLeay X509 the caller frees, or undef.
sub _x509_from_pem ($pem) {
    require IO::Socket::SSL;   # loads and initialises Net::SSLeay
    my $bio = Net::SSLeay::BIO_new(Net::SSLeay::BIO_s_mem()) or return;
    Net::SSLeay::BIO_write($bio, $pem);
    my $x509 = Net::SSLeay::PEM_read_bio_X509($bio);
    Net::SSLeay::BIO_free($bio);
    Net::SSLeay::ERR_clear_error() unless $x509;
    return $x509 || undef;
}

sub _x509_fpr ($x509) {
    my $f = Net::SSLeay::X509_get_fingerprint($x509, 'sha256') // '';
    $f =~ s/://g;
    $f = lc $f;
    return _valid_fpr($f) ? $f : undef;
}

# Fingerprint of one PEM certificate, or undef when it does not parse.
sub pem_fingerprint ($pem) {
    my $x509 = _x509_from_pem($pem) or return;
    my $fpr  = _x509_fpr($x509);
    Net::SSLeay::X509_free($x509);
    return $fpr;
}

# Load the CA bundle at $path: [ { fpr => '<64 hex>', pem => '...', x509 => ... } ]
# in file order, one per distinct certificate. An absent or unreadable file, or
# a block that does not parse, contributes nothing. The X509 handles are owned
# by the caller: release them with free_ca_bundle.
sub load_ca_bundle ($path) {
    my @bundle;
    my $text = defined $path ? Exec::FileUtil::slurp_maybe($path) : undef;
    my %seen;
    for my $pem (pem_certs($text)) {
        my $x509 = _x509_from_pem($pem) or next;
        my $fpr  = _x509_fpr($x509);
        if (!defined $fpr || $seen{$fpr}++) {
            Net::SSLeay::X509_free($x509);
            next;
        }
        push @bundle, { fpr => $fpr, pem => $pem, x509 => $x509 };
    }
    return \@bundle;
}

sub free_ca_bundle ($bundle) {
    return unless ref $bundle eq 'ARRAY';
    for my $ca (@$bundle) {
        Net::SSLeay::X509_free(delete $ca->{x509}) if $ca->{x509};
    }
}

# The fingerprints of the CAs in the bundle at $path, in file order.
sub ca_bundle_fingerprints ($path) {
    my $bundle = load_ca_bundle($path);
    my @fprs   = map { $_->{fpr} } @$bundle;
    free_ca_bundle($bundle);
    return @fprs;
}

# The fingerprints of the bundle CAs that issued the certificate $x509 (a
# Net::SSLeay X509): the CA's subject is the certificate's issuer AND the
# certificate's signature verifies under the CA's public key. Matching on the
# name alone would not do: every dispatcher CA made with the defaults is called
# "ctrl-exec CA". Normally one fingerprint; two only when one key signs two CA
# certificates (a re-issued CA). Empty when no CA in the bundle issued it.
sub cert_issuers ($x509, $bundle) {
    return () unless $x509 && ref $bundle eq 'ARRAY';
    my $issuer = Net::SSLeay::X509_get_issuer_name($x509);
    my @fprs;
    for my $ca (@$bundle) {
        next unless $ca->{x509};
        next unless Net::SSLeay::X509_NAME_cmp(
            $issuer, Net::SSLeay::X509_get_subject_name($ca->{x509})) == 0;
        my $pkey = Net::SSLeay::X509_get_pubkey($ca->{x509}) or next;
        my $ok   = Net::SSLeay::X509_verify($x509, $pkey);
        Net::SSLeay::EVP_PKEY_free($pkey);
        push @fprs, $ca->{fpr} if defined $ok && $ok == 1;
    }
    # A failed verify leaves an entry on OpenSSL's per-thread error queue;
    # clear it so it cannot surface in a later, unrelated TLS call in this
    # process (the accept loop calls this for every connection).
    Net::SSLeay::ERR_clear_error();
    return @fprs;
}

# As cert_issuers, for a certificate in PEM form.
sub pem_issuers ($pem, $bundle) {
    my $x509 = _x509_from_pem($pem // '') or return ();
    my @fprs = cert_issuers($x509, $bundle);
    Net::SSLeay::X509_free($x509);
    return @fprs;
}

# Add the CA certificate(s) in $opts{pem} to the bundle at $opts{path}, each
# once: a certificate whose fingerprint is already in the bundle is not added
# again. Existing content is kept as it is and the new certificates are
# appended, so the CAs already trusted keep their place. The file is not
# rewritten when nothing is new. Returns the fingerprints of the certificates in
# $opts{pem}. Dies when $opts{pem} holds no readable certificate.
sub add_to_ca_bundle (%opts) {
    my $path = $opts{path} or croak "path required";
    my @new  = pem_certs($opts{pem});
    croak "no CA certificate to add" unless @new;

    my $existing = Exec::FileUtil::slurp_maybe($path) // '';
    my %have;
    for my $pem (pem_certs($existing)) {
        my $f = pem_fingerprint($pem);
        $have{$f} = 1 if defined $f;
    }

    my (@fprs, %listed);
    my $append = '';
    for my $pem (@new) {
        my $f = pem_fingerprint($pem) // croak "unreadable CA certificate";
        push @fprs, $f unless $listed{$f}++;
        next if $have{$f}++;
        $append .= "$pem\n";
    }

    if (length $append) {
        $existing .= "\n" if length $existing && $existing !~ /\n\z/;
        _write_file($path, $existing . $append, 0644);
    }
    return @fprs;
}

# --- trusted-dispatcher map ------------------------------------------------
#
# The dispatchers this agent accepts. One entry per line:
#
#   <ca-fpr> <hex-serial> <dispatcher-id>
#
# <ca-fpr> is the fingerprint of the CA in the bundle that issued the
# dispatcher's certificate. A connecting peer is a trusted dispatcher only when
# both its issuing CA and its serial match an entry, so a certificate from
# another trusted CA that carries the same serial is refused. Before 0.14 a line
# was "<hex-serial> <dispatcher-id>"; such a line is upgraded in place on first
# load (see load_trusted_dispatchers).
#
# In memory the map is { '<ca-fpr> <hex-serial>' => '<id>' }. A pre-0.14 line
# that could not be upgraded (no CA bundle readable) stays { '<hex-serial>' =>
# '<id>' } and matches that serial under any CA, as it did before. The request
# handlers work on the view for one peer's issuing CA (trusted_for_issuers),
# keyed by serial alone, and dispatcher_trusted resolves within that view.

# Read the map file. Returns (\%map, \@legacy), @legacy being [hex, id] pairs
# from pre-0.14 two-field lines.
sub _read_trusted ($path) {
    my (%trusted, @legacy);
    return (\%trusted, \@legacy) unless -f $path;

    open my $fh, '<', $path
        or do { warn "Cannot read trusted dispatchers '$path': $!\n"; return (\%trusted, \@legacy); };
    while (my $line = <$fh>) {
        chomp $line;
        $line =~ s/#.*$//;        # strip comments
        $line =~ s/^\s+|\s+$//g;  # strip surrounding whitespace
        next unless length $line;
        my @f = split /\s+/, $line;
        if (@f == 3) {
            my ($fpr, $serial, $id) = @f;
            $fpr    = lc $fpr;
            $serial = Exec::CertInfo::serial_to_hex($serial);
            next unless _valid_fpr($fpr) && length $serial && valid_dispatcher_id($id);
            $trusted{"$fpr $serial"} = $id;
        }
        elsif (@f == 2) {
            my ($serial, $id) = @f;
            $serial = Exec::CertInfo::serial_to_hex($serial);
            next unless length $serial && valid_dispatcher_id($id);
            push @legacy, [ $serial, $id ];
        }
        # anything else is malformed and skipped
    }
    close $fh;
    return (\%trusted, \@legacy);
}

sub _write_trusted ($path, $trusted) {
    my $content = "# ctrl-exec trusted dispatchers: <ca-fingerprint> <serial> <id>, one per line.\n"
                . "# Managed by pairing - do not edit by hand.\n";
    for my $k (sort keys %$trusted) {
        $content .= "$k $trusted->{$k}\n";
    }
    _write_file($path, $content, 0644);
}

# Load the trusted-dispatcher map. Tolerates an absent file (returns {}).
# Serials are normalised to lowercase hex (serial_to_hex) and ids validated;
# lines beginning with # are comments; malformed lines are skipped.
#
# Upgrade: with ca_path (the agent's CA bundle), each pre-0.14 two-field line is
# given the issuing CA it had - the CA the agent trusted when the line was
# written, which is the CA in the bundle - and the file is rewritten in the new
# form. A bundle that somehow holds several CAs gives the line one entry per
# CA, which is exactly what the agent accepted before. Rewriting is best effort:
# when the file cannot be written, the upgrade holds in memory, is logged, and is
# tried again on the next load. Without ca_path, or with no readable CA, a
# two-field line is kept as it was (matching its serial under any CA).
#
# Returns hashref: { '<ca-fpr> <hex-serial>' => '<id>', ... }
sub load_trusted_dispatchers (%opts) {
    my $path = $opts{path} or croak "path required";

    my ($trusted, $legacy) = _read_trusted($path);
    return $trusted unless @$legacy;

    my @fprs = defined $opts{ca_path} ? ca_bundle_fingerprints($opts{ca_path}) : ();
    unless (@fprs) {
        $trusted->{ $_->[0] } //= $_->[1] for @$legacy;
        return $trusted;
    }

    for my $e (@$legacy) {
        $trusted->{"$_ $e->[0]"} //= $e->[1] for @fprs;
    }
    if (eval { _write_trusted($path, $trusted); 1 }) {
        Exec::Log::log_action('INFO', {
            ACTION  => 'trusted-map-upgrade',
            PATH    => $path,
            ENTRIES => scalar(@$legacy),
            CA      => join(',', @fprs),
        });
    }
    else {
        my $err = $@ || 'write failed'; $err =~ s/\s+\z//;
        Exec::Log::log_action('WARNING', {
            ACTION => 'trusted-map-upgrade',
            PATH   => $path,
            ERROR  => $err,
        });
    }
    return $trusted;
}

sub _issuer_list ($issuer) {
    my @list = ref $issuer eq 'ARRAY' ? @$issuer : (defined $issuer ? ($issuer) : ());
    my %seen;
    return grep { _valid_fpr($_) && !$seen{$_}++ } map { lc } @list;
}

# The part of a loaded map that applies to a peer whose certificate the CAs
# @$issuers issued (Server::peer_issuers): { '<hex-serial>' => '<id>' }. Entries
# under any other CA are left out. A pre-0.14 entry that could not be upgraded
# applies whatever the issuer, as before. dispatcher_trusted resolves within
# this view.
sub trusted_for_issuers ($trusted, $issuers) {
    my %want = map { $_ => 1 } _issuer_list($issuers);
    my %view;
    return \%view unless ref $trusted eq 'HASH';
    # Un-upgraded lines first, so an issuer-keyed entry for the same serial
    # overwrites them.
    for my $k (sort { ($a =~ / /) <=> ($b =~ / /) || $a cmp $b } keys %$trusted) {
        if ($k =~ /\A([0-9a-f]{64}) (\S+)\z/) {
            $view{$2} = $trusted->{$k} if $want{$1};
        }
        elsif ($k !~ / /) {
            $view{$k} //= $trusted->{$k};
        }
    }
    return \%view;
}

# Resolve a connecting peer's cert serial to its trusted dispatcher identity,
# within the view for that peer's issuing CA (trusted_for_issuers). Returns the
# id string when the serial is trusted, or undef when it is not (or when either
# input is empty). Normalises the serial the same way the loader does, so a
# decimal serial from IO::Socket::SSL matches a hex map entry.
sub dispatcher_trusted ($peer_serial, $trusted) {
    return unless ref $trusted eq 'HASH';
    my $hex = Exec::CertInfo::serial_to_hex($peer_serial // '');
    return unless length $hex;
    my $id = $trusted->{$hex};
    return (defined $id && length $id) ? $id : undef;
}

# Add or update one trusted-dispatcher entry, preserving every other entry.
# This is the append-enrolment primitive: pairing a second dispatcher adds its
# serial without unpairing the first; re-pairing the same dispatcher (new serial
# after rotation/re-key) adds the new serial. Writes the file atomically. Dies
# on an unusable serial, an invalid id or no issuing CA.
#
# Required opts:
#   path   => $str
#   serial => $str   (any form accepted by serial_to_hex)
#   id     => $str   (must satisfy valid_dispatcher_id)
#   issuer => $fpr or [ $fpr, ... ]  (the CA(s) that issued that serial)
# Optional:
#   ca_path   => $str  (CA bundle, to upgrade a pre-0.14 map on the way)
#   supersede => 1     (drop this id's entries under any other CA: pairing)
sub add_trusted_dispatcher (%opts) {
    my $path = $opts{path} or croak "path required";
    my $hex  = Exec::CertInfo::serial_to_hex($opts{serial} // '');
    croak "invalid dispatcher serial" unless length $hex;
    my $id   = $opts{id};
    croak "invalid dispatcher id '" . ($id // '') . "'"
        unless valid_dispatcher_id($id);
    my @issuers = _issuer_list($opts{issuer});
    croak "issuing CA fingerprint required" unless @issuers;

    my $trusted = load_trusted_dispatchers(path => $path, ca_path => $opts{ca_path});
    if ($opts{supersede}) {
        my %keep = map { $_ => 1 } @issuers;
        for my $k (keys %$trusted) {
            next unless $trusted->{$k} eq $id;
            my ($fpr) = $k =~ /\A(\S+) /;
            delete $trusted->{$k} unless defined $fpr && $keep{$fpr};
        }
    }
    $trusted->{"$_ $hex"} = $id for @issuers;

    _write_trusted($path, $trusted);
    return $trusted;
}

# Remove one trusted-dispatcher entry by issuing CA and serial, preserving every
# other entry. This is the "remove" half of add-then-remove cert rotation: once
# agents have adopted a dispatcher's new serial and the overlap window has
# passed, the old serial is removed so the retired cert is no longer trusted. An
# un-upgraded pre-0.14 line for the serial goes too. A no-op (returns 0) if the
# serial is absent or the file does not exist; returns 1 when an entry was
# removed. Writes atomically.
#
# Required opts:
#   path   => $str
#   serial => $str   (any form accepted by serial_to_hex)
#   issuer => $fpr or [ $fpr, ... ]
# Optional:
#   ca_path => $str  (CA bundle, to upgrade a pre-0.14 map on the way)
sub remove_trusted_dispatcher (%opts) {
    my $path = $opts{path} or croak "path required";
    my $hex  = Exec::CertInfo::serial_to_hex($opts{serial} // '');
    croak "invalid dispatcher serial" unless length $hex;
    my @issuers = _issuer_list($opts{issuer});
    croak "issuing CA fingerprint required" unless @issuers;

    return 0 unless -f $path;
    my $trusted = load_trusted_dispatchers(path => $path, ca_path => $opts{ca_path});
    my $removed = 0;
    for my $k ($hex, map { "$_ $hex" } @issuers) {
        $removed++ if defined delete $trusted->{$k};
    }
    return 0 unless $removed;

    _write_trusted($path, $trusted);
    return 1;
}

# --- remove / list dispatchers (operator commands) ---------------------------

# Remove the CA certificates whose fingerprints are in @$fprs from the bundle at
# $path, keeping the others as they are, in order. The file is rewritten
# atomically. Dies when that would leave the bundle with no certificate: an
# empty CA file is not one the TLS listener can start with. Returns the
# fingerprints actually removed.
sub remove_from_ca_bundle (%opts) {
    my $path = $opts{path} or croak "path required";
    my %drop = map { $_ => 1 } grep { _valid_fpr($_) } @{ $opts{fprs} // [] };

    my (@keep, @gone);
    for my $pem (pem_certs(Exec::FileUtil::slurp_maybe($path))) {
        my $f = pem_fingerprint($pem);
        if (defined $f && $drop{$f}) { push @gone, $f; next }
        push @keep, $pem;
    }
    return () unless @gone;
    croak "removing these would leave '$path' with no CA certificate"
        unless @keep;

    _write_file($path, join("\n", @keep) . "\n", 0644);
    return @gone;
}

# The trusted dispatchers as a list sorted by id then CA:
#   [ { id => 'd1', ca => '<fpr>' | undef, serials => [ '3ea', ... ] }, ... ]
# one element per (id, CA). ca is undef for a pre-0.14 line that could not be
# upgraded (no CA bundle). Opts: path (the map), ca_path (to upgrade it).
sub list_trusted_dispatchers (%opts) {
    my $path = $opts{path} or croak "path required";
    my $trusted = load_trusted_dispatchers(path => $path, ca_path => $opts{ca_path});
    my %group;
    for my $k (keys %$trusted) {
        my ($fpr, $serial) = $k =~ / / ? split(/ /, $k, 2) : (undef, $k);
        push @{ $group{ $trusted->{$k} }{ $fpr // '' } }, $serial;
    }
    my @list;
    for my $id (sort keys %group) {
        for my $ca (sort keys %{ $group{$id} }) {
            push @list, {
                id      => $id,
                ca      => length $ca ? $ca : undef,
                serials => [ sort @{ $group{$id}{$ca} } ],
            };
        }
    }
    return @list;
}

# The agent stops trusting dispatcher $opts{id}: every map entry for it goes,
# then each CA those entries were under goes from the bundle unless an entry that
# stays is under it, or it is the last CA in the bundle (the bundle is never
# left empty; the map is what then refuses everyone). The map is written
# first, so a failure part-way leaves trust withdrawn, never extended. Dies,
# naming the known ids, when the id has no entry.
#
# Opts: path (map), ca_path (bundle), id.
# Returns { entries => N, cas_removed => [fpr...], cas_kept => [fpr...],
#           cas_kept_last => [fpr...], remaining => N }
#   cas_kept      CAs of the removed entries that another dispatcher still uses
#   cas_kept_last CAs kept only because the bundle may not be left empty
#   remaining     map entries left
sub remove_dispatcher (%opts) {
    my $path = $opts{path} or croak "path required";
    my $id   = $opts{id};
    croak "dispatcher id required" unless defined $id && length $id;

    my $trusted = load_trusted_dispatchers(path => $path, ca_path => $opts{ca_path});
    my @mine = grep { $trusted->{$_} eq $id } keys %$trusted;
    unless (@mine) {
        my %ids = map { $_ => 1 } values %$trusted;
        croak "unknown dispatcher '$id' (known: "
            . (%ids ? join(', ', sort keys %ids) : 'none') . ")";
    }

    my %cas;
    for my $k (@mine) {
        $cas{$1} = 1 if $k =~ /\A([0-9a-f]{64}) /;
        delete $trusted->{$k};
    }
    my %still = map { /\A([0-9a-f]{64}) / ? ($1 => 1) : () } keys %$trusted;
    my @cas_kept = sort grep {  $still{$_} } keys %cas;
    my @drop     = sort grep { !$still{$_} } keys %cas;

    _write_trusted($path, $trusted);

    my (@removed, @kept_last);
    if (@drop && defined $opts{ca_path}) {
        my %drop = map { $_ => 1 } @drop;
        my @left = grep { !$drop{$_} } ca_bundle_fingerprints($opts{ca_path});
        if (@left) {
            @removed = remove_from_ca_bundle(path => $opts{ca_path}, fprs => \@drop);
        }
        else {
            @kept_last = @drop;
        }
    }
    return {
        entries       => scalar(@mine),
        cas_removed   => \@removed,
        cas_kept      => \@cas_kept,
        cas_kept_last => \@kept_last,
        remaining     => scalar(keys %$trusted),
    };
}

# --- revoked serials -------------------------------------------------------

# Load the revoked serials file. Tolerates an absent file - returns an empty
# hashref. One entry per line, either:
#
#   <ca-fpr> <serial>   the serial is revoked under that issuing CA only
#   <serial>            the serial is revoked under every CA (the pre-0.14
#                       form, still accepted: an existing revocation never
#                       loosens)
#
# The serial is a hex string as output by openssl x509 -serial, with or without
# a "serial=" prefix, upper or lower case - all normalised. Lines beginning with
# # are treated as comments and ignored.
#
# Returns hashref: { '<ca-fpr> <hex>' => 1, '<hex>' => 1, ... }. Check a peer
# with serial_revoked against revoked_for_issuers(...) for its issuing CA.
sub load_revoked_serials (%opts) {
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
        my @f = split /\s+/, $line;
        if (@f == 2 && _valid_fpr(lc $f[0])) {
            my $hex = Exec::CertInfo::serial_to_hex($f[1]);
            $revoked{ lc($f[0]) . " $hex" } = 1 if length $hex;
            next;
        }
        # The whole line, as before 0.14.
        $line = Exec::CertInfo::serial_to_hex($line);
        next unless length $line;
        $revoked{$line} = 1;
    }
    close $fh;

    return \%revoked;
}

# The part of a loaded revocation list that applies to a peer whose certificate
# the CAs @$issuers issued: { '<hex>' => 1 }, holding the serials revoked under
# those CAs and every serial revoked under any CA.
sub revoked_for_issuers ($revoked, $issuers) {
    my %want = map { $_ => 1 } _issuer_list($issuers);
    my %view;
    return \%view unless ref $revoked eq 'HASH';
    for my $k (keys %$revoked) {
        if ($k =~ /\A([0-9a-f]{64}) (\S+)\z/) {
            $view{$2} = 1 if $want{$1};
        }
        elsif ($k !~ / /) {
            $view{$k} = 1;
        }
    }
    return \%view;
}

# Return true if the given serial (lowercase hex from _peer_serial,
# or any format accepted by serial_to_hex) is in the revoked set - the view
# for the peer's issuing CA (revoked_for_issuers), or a serial-only list.
# Normalises the input to lowercase hex before checking.
sub serial_revoked ($serial, $revoked) {
    return 0 unless defined $serial && ref $revoked eq 'HASH';
    my $hex = Exec::CertInfo::serial_to_hex($serial);
    return exists $revoked->{$hex} ? 1 : 0;
}

# --- private helpers ---


sub _gen_nonce {
    # 16 bytes of /dev/urandom (via Exec::Random) - replay-guard nonces must be
    # cryptographically unpredictable, so rand() must not be used.
    return Exec::Random::hex_bytes(16);
}

sub _run_or_die (@args) {
    return Exec::Cmd::run_or_die(@args);
}

# Validate a candidate (renewed) cert before adopting it: it must verify against
# the agent's CA and its public key must match the agent's existing private key
# (renewal preserves the key). The cert is public material, so this is a
# robustness gate - never adopt a cert that would not actually work, and never
# let a buggy or hostile delivery overwrite a working cert - not a secret
# boundary. Returns (1) on success or (0, $reason).
sub validate_cert (%o) {
    my $cert_pem = defined $o{cert_pem} ? $o{cert_pem} : croak "cert_pem required";
    my $ca_path  = $o{ca_path}  or croak "ca_path required";
    my $key_path = $o{key_path} or croak "key_path required";

    return (0, "CA cert not found at '$ca_path'")  unless -f $ca_path;
    return (0, "agent key not found at '$key_path'") unless -f $key_path;

    my ($cfh, $cpath) = tempfile(SUFFIX => '.crt', UNLINK => 1);
    print $cfh $cert_pem;
    close $cfh;

    # The CA file is a bundle (one CA per paired dispatcher). A renewed cert
    # must come from the CA that issued the agent's live cert (cert_path), so
    # one dispatcher cannot swap the agent onto its own CA and cut off the
    # others. When the live cert's issuer is not found in the bundle, the whole
    # bundle is used, as with a single CA before 0.14.
    my $ca_file = $ca_path;
    my $live    = defined $o{cert_path} ? Exec::FileUtil::slurp_maybe($o{cert_path}) : undef;
    if (defined $live) {
        my $bundle = load_ca_bundle($ca_path);
        if (@$bundle > 1) {
            my %own = map { $_ => 1 } pem_issuers($live, $bundle);
            if (%own) {
                my ($afh, $apath) = tempfile(SUFFIX => '.crt', UNLINK => 1);
                print $afh map { "$_->{pem}\n" } grep { $own{ $_->{fpr} } } @$bundle;
                close $afh;
                $ca_file = $apath;
            }
        }
        free_ca_bundle($bundle);
    }

    # 1. Verify against the agent's CA. A 127 exit means openssl is not on PATH -
    # report that distinctly so a hands-free renewal failure is not misattributed
    # to a bad cert. Either way this fails closed (no adoption).
    my $vout = `openssl verify -CAfile \Q$ca_file\E \Q$cpath\E 2>&1`;
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
sub stage_renewed_cert (%o) {
    my $cert_pem    = defined $o{cert_pem} ? $o{cert_pem} : croak "cert_pem required";
    my $staged_path = $o{staged_path} or croak "staged_path required";

    my ($ok, $reason) = validate_cert(
        cert_pem => $cert_pem, ca_path => $o{ca_path}, key_path => $o{key_path},
        cert_path => $o{cert_path});
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
sub promote_staged_cert (%o) {
    my $staged_path = $o{staged_path} or croak "staged_path required";
    my $cert_path   = $o{cert_path}   or croak "cert_path required";

    return { ok => 1, promoted => 0 } unless -f $staged_path;

    my $cert_pem = eval { slurp($staged_path) };
    return { ok => 0, error => "cannot read staged cert: $@" } unless defined $cert_pem;

    my ($valid, $reason) = validate_cert(
        cert_pem => $cert_pem, ca_path => $o{ca_path}, key_path => $o{key_path},
        cert_path => $cert_path);
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
sub _ensure_owned_dir ($dir, $account) {
    make_path($dir) unless -d $dir;
    my $uid = getpwnam($account);
    my $gid = getgrnam($account);
    if (defined $uid || defined $gid) {
        chown((defined $uid ? $uid : -1), (defined $gid ? $gid : -1), $dir);
    }
    chmod 0750, $dir;
}

sub _write_file ($path, $content, $mode) {
    return Exec::FileUtil::write_atomic($path, $content, mode => $mode, make_dir => 0);
}

sub _cert_expiry ($cert) {
    return Exec::CertInfo::expiry_from_path($cert);
}

1;
