#!/usr/bin/perl
# t/pairing-code-binding.t
#
# T-022: the pairing confirmation code (v2) is bound to the dispatcher
# certificate the agent saw on the pairing connection:
#
#   v2 = first 4 bytes of sha256(csr_pem || sha256(DER of dispatcher cert))
#        as a uint32 mod 1,000,000, six digits
#
# A man in the middle that terminates the agent's TLS shows the agent its own
# certificate, so the agent's code no longer matches the one the dispatcher
# shows for the relayed CSR. Agents older than 0.13 send no code_version and
# keep getting the v1 code (sha256 of the CSR alone), labelled as such.

use strict;
use warnings;
use feature qw(signatures);
no warnings qw(experimental::signatures);
use Test::More;
use File::Temp  qw(tempdir);
use JSON        qw(encode_json decode_json);
use FindBin     qw($Bin);
use lib         "$Bin/../lib";

use Exec::Digest  qw();
use Exec::CertInfo qw();
use Exec::Pairing qw();
use Exec::Agent::AgentPairing qw();

plan skip_all => 'openssl not available'
    unless system('openssl version >/dev/null 2>&1') == 0;

my $dir = tempdir(CLEANUP => 1);

# A real CSR, as the agent generates it (openssl output, canonical PEM).
sub gen_csr ($name) {
    system('openssl', 'genrsa', '-out', "$dir/$name.key", '2048',
        ) == 0 or die "genrsa failed";
    system('openssl', 'req', '-new', '-key', "$dir/$name.key",
        '-out', "$dir/$name.csr", '-subj', "/CN=$name") == 0
        or die "req failed";
    open my $fh, '<', "$dir/$name.csr" or die $!;
    local $/;
    return scalar <$fh>;
}

# A self-signed server cert, standing in for a dispatcher (or a relay).
sub gen_cert ($name) {
    system('openssl', 'req', '-x509', '-newkey', 'rsa:2048',
        '-keyout', "$dir/$name.key", '-out', "$dir/$name.crt", '-days', '1',
        '-nodes', '-subj', "/CN=$name", '-quiet') == 0
        or die "cert generation failed";
    return ("$dir/$name.crt", "$dir/$name.key");
}

{
    # Silence the generation chatter of older openssl builds.
    open my $save, '>&', \*STDERR or die;
    open STDERR, '>', '/dev/null';
    gen_csr('agent-one');
    gen_cert('dispatcher');
    gen_cert('relay');
    open STDERR, '>&', $save;
}
my $csr = do { open my $fh, '<', "$dir/agent-one.csr" or die; local $/; <$fh> };
my ($disp_crt, $disp_key)   = ("$dir/dispatcher.crt", "$dir/dispatcher.key");
my ($relay_crt, $relay_key) = ("$dir/relay.crt", "$dir/relay.key");

my $disp_fpr  = Exec::CertInfo::fingerprint_from_path($disp_crt);
my $relay_fpr = Exec::CertInfo::fingerprint_from_path($relay_crt);

# --- fingerprint -----------------------------------------------------------

subtest 'fingerprint_from_path: sha256 of the DER, lowercase hex' => sub {
    like $disp_fpr, qr/\A[0-9a-f]{64}\z/, '64 lowercase hex characters';
    my $der = `openssl x509 -in \Q$disp_crt\E -outform DER 2>/dev/null`;
    is $disp_fpr, Exec::Digest::sha256_hex($der),
        'equals sha256 of the certificate DER';
    isnt $disp_fpr, $relay_fpr, 'different certs, different fingerprints';
    is Exec::CertInfo::fingerprint_from_path("$dir/absent.crt"), undef,
        'undef for a missing file';
};

# --- the codes ---------------------------------------------------------------

subtest 'v2: same CSR and dispatcher cert give the same code' => sub {
    my $a = Exec::Digest::pairing_code_v2($csr, $disp_fpr);
    my $b = Exec::Digest::pairing_code_v2($csr, $disp_fpr);
    like $a, qr/\A\d{6}\z/, 'six digits, as v1';
    is $a, $b, 'deterministic';
};

subtest 'relay: a different dispatcher certificate gives a different code' => sub {
    # The agent behind a relay computes its code with the relay's fingerprint;
    # the real dispatcher computes it with its own, for the same CSR.
    isnt Exec::Digest::pairing_code_v2($csr, $relay_fpr),
         Exec::Digest::pairing_code_v2($csr, $disp_fpr),
         'agent code (relay cert) differs from dispatcher code (own cert)';
    isnt Exec::Digest::pairing_code_v2($csr, $disp_fpr),
         Exec::Digest::pairing_code($csr),
         'v2 differs from the v1 code of the same CSR';
};

subtest 'pairing_code_for: version dispatch' => sub {
    is Exec::Digest::pairing_code_for(1, $csr), Exec::Digest::pairing_code($csr),
        'v1 is sha256(csr) only';
    is Exec::Digest::pairing_code_for(2, $csr, $disp_fpr),
       Exec::Digest::pairing_code_v2($csr, $disp_fpr), 'v2';
    eval { Exec::Digest::pairing_code_for(2, $csr, undef) };
    like $@, qr/fingerprint/, 'v2 without a fingerprint dies';
    eval { Exec::Digest::pairing_code_for(3, $csr, $disp_fpr) };
    like $@, qr/version/, 'unknown version dies';
};

# --- dispatcher request handling --------------------------------------------

sub pair_request (%f) {
    my $body = encode_json({ hostname => 'agent-one', nonce => 'aabb', %f });
    return "POST /pair HTTP/1.0\r\nContent-Type: application/json\r\n"
         . "Content-Length: " . length($body) . "\r\n\r\n" . $body;
}

# Run _handle_pair_request on a socketpair, denying any queued request at once
# so the handler's approval poll returns. Returns (ack, queued record, logs).
sub handle ($request, $cert_fpr) {
    my $pdir = tempdir(CLEANUP => 1);
    require IO::Socket::UNIX;
    my ($client, $server) = IO::Socket::UNIX->socketpair(
        IO::Socket::AF_UNIX(), IO::Socket::SOCK_STREAM(), 0) or die $!;
    print $client $request;
    $client->shutdown(1);

    my $queued;
    my $pid = fork() // die "fork: $!";
    if ($pid == 0) {
        for (1 .. 100) {
            for my $f (glob "$pdir/*.json") {
                (my $b = $f) =~ s/\.json$//;
                open my $fh, '>', "$b.denied" or next;
                print $fh encode_json({ status => 'denied', reason => 'test' });
                close $fh;
                exit 0;
            }
            select undef, undef, undef, 0.05;
        }
        exit 0;
    }

    my @logs;
    {
        local *STDOUT;
        open STDOUT, '>', '/dev/null';
        Exec::Pairing::_handle_pair_request($server, '127.0.0.1',
            sub { push @logs, $_[0] }, 10, $pdir, $cert_fpr);
    }
    waitpid $pid, 0;
    $server->close;
    my ($json) = glob "$pdir/*.json";
    $queued = $json ? decode_json(do { open my $fh, '<', $json; local $/; <$fh> }) : undef;

    local $/;
    my $raw = <$client> // '';
    my ($ack) = $raw =~ /\r\n\r\n(\{.*?\})/s;
    return ((eval { decode_json($ack // '') } // { _raw => $raw }), $queued, \@logs);
}

subtest 'v2 request: queued code is v2 over the listener cert' => sub {
    my ($ack, $q) = handle(pair_request(csr => $csr, code_version => 2), $disp_fpr);
    is $ack->{status}, 'pending', 'request accepted';
    is $ack->{code_version}, 2, 'acknowledgement confirms code v2';
    ok $q, 'request queued';
    is $q->{code_version}, 2, 'queued as v2';
    is $q->{code}, Exec::Digest::pairing_code_v2($csr, $disp_fpr),
        'queued code is v2 bound to the dispatcher fingerprint';
};

subtest 'old-style request (no code_version) still gets v1' => sub {
    my ($ack, $q) = handle(pair_request(csr => $csr), $disp_fpr);
    is $ack->{status}, 'pending', 'request accepted';
    ok $q, 'request queued';
    is $q->{code_version}, 1, 'queued as v1';
    is $q->{code}, Exec::Digest::pairing_code($csr), 'queued code is sha256(csr) only';
};

subtest 'unsupported code_version is rejected' => sub {
    my ($ack, $q, $logs) = handle(pair_request(csr => $csr, code_version => 3), $disp_fpr);
    is $ack->{status}, 'error', 'error response';
    like $ack->{reason}, qr/code version/, 'reason names the code version';
    ok !$q, 'nothing queued';
};

subtest 'a CSR with appended text is rejected (no free code grinding)' => sub {
    # openssl ignores text after the END line, so without this check a relay
    # could append junk to the agent's CSR and vary it until the dispatcher's
    # code matched the agent's - about a million cheap hashes.
    my ($ack, $q, $logs) = handle(
        pair_request(csr => $csr . "junk-000123\n", code_version => 2), $disp_fpr);
    is $ack->{status}, 'error', 'error response';
    like $ack->{reason}, qr/csr/i, 'reason names the CSR';
    ok !$q, 'nothing queued';
    ok( (grep { ($_->{REASON} // '') eq 'non-canonical-csr' } @$logs),
        'logged as non-canonical-csr' );

    ($ack, $q) = handle(pair_request(
        csr => "-----BEGIN CERTIFICATE REQUEST-----\nYQ==\n-----END CERTIFICATE REQUEST-----\n"),
        $disp_fpr);
    is $ack->{status}, 'error', 'an unparseable CSR is rejected too';
};

# --- display labels -----------------------------------------------------------

subtest 'code_label says which version a code is' => sub {
    like Exec::Pairing::code_label({ code => '123456', code_version => 2 }),
        qr/\A123456 \(v2\)\z/, 'v2 label';
    like Exec::Pairing::code_label({ code => '123456', code_version => 1 }),
        qr/\A123456 \(v1\b.*0\.13/, 'v1 label names the pre-0.13 agent';
    like Exec::Pairing::code_label({ code => '123456' }),
        qr/\(v1\b/, 'a record with no version (queued before upgrade) is v1';
};

# --- end to end over a real pairing listener, direct and through a relay ----

my $port = 39000 + $$ % 500;

sub start_dispatcher ($pdir) {
    my $pid = fork() // die "fork: $!";
    if ($pid == 0) {
        open STDIN,  '<', '/dev/null';
        open STDOUT, '>', "$pdir.out";
        Exec::Pairing::run_pairing_mode(
            port => $port, cert => $disp_crt, key => $disp_key,
            pairing_dir => $pdir, timeout => 30, log_fn => sub { },
        );
        exit 0;
    }
    for (1 .. 50) {
        last if IO::Socket::INET->new(PeerAddr => "127.0.0.1:$port");
        select undef, undef, undef, 0.1;
    }
    return $pid;
}

# A relay: terminates the agent's TLS with its own cert and forwards the
# plaintext to the real dispatcher, unchanged in both directions.
sub start_relay ($rport) {
    my $pid = fork() // die "fork: $!";
    return $pid if $pid;
    require IO::Socket::SSL;
    require IO::Select;
    my $l = IO::Socket::SSL->new(LocalAddr => '127.0.0.1', LocalPort => $rport,
        Listen => 1, ReuseAddr => 1, SSL_cert_file => $relay_crt,
        SSL_key_file => $relay_key) or exit 1;
    # Skip the plain-TCP readiness probe: take the first TLS client.
    my $a;
    for (1 .. 5) { last if $a = $l->accept; }
    exit 1 unless $a;
    my $d = IO::Socket::SSL->new(PeerHost => '127.0.0.1', PeerPort => $port,
        SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_NONE()) or exit 1;
    my $sel = IO::Select->new($a, $d);
    while (my @r = $sel->can_read(20)) {
        for my $s (@r) {
            my $n = sysread $s, my $buf, 16384;
            exit 0 unless $n;
            syswrite(($s == $a ? $d : $a), $buf);
        }
    }
    exit 0;
}

# Deny every queued request, then wait for the listener's handler children to
# pick the denial up (they unlink it once sent) so none outlives the test.
sub deny_all ($pdir) {
    for my $f (glob "$pdir/*.json") {
        (my $b = $f) =~ s/\.json$//;
        open my $fh, '>', "$b.denied" or next;
        print $fh encode_json({ status => 'denied', reason => 'test' });
        close $fh;
    }
    for (1 .. 60) {
        last unless () = glob "$pdir/*.denied";
        select undef, undef, undef, 0.1;
    }
}

sub queued ($pdir) {
    for (1 .. 50) {
        my ($f) = glob "$pdir/*.json";
        return decode_json(do { open my $fh, '<', $f; local $/; <$fh> }) if $f;
        select undef, undef, undef, 0.1;
    }
    return undef;
}

require IO::Socket::INET;

subtest 'end to end: agent and dispatcher show the same v2 code' => sub {
    my $pdir = "$dir/pair-direct";
    my $dpid = start_dispatcher($pdir);
    my $sub = Exec::Agent::AgentPairing::submit_pairing_request(
        'ctrl-exec' => '127.0.0.1', port => $port,
        csr_pem => $csr, hostname => 'agent-one');
    unless ($sub->{ok}) {
        kill 'TERM', $dpid; waitpid $dpid, 0;
        plan skip_all => "pairing listener unavailable: $sub->{error}";
    }
    my $q = queued($pdir);
    deny_all($pdir);
    close $sub->{sock};
    kill 'TERM', $dpid; waitpid $dpid, 0;

    is $sub->{code_version}, 2, 'agent computes v2';
    ok $sub->{dispatcher_confirms_v2}, 'dispatcher acknowledged v2';
    is $sub->{dispatcher_fpr}, $disp_fpr,
        'agent saw the fingerprint the dispatcher computed from its cert file';
    is $q->{code_version}, 2, 'dispatcher queued v2';
    is $sub->{code}, $q->{code}, 'agent code equals dispatcher code';
};

subtest 'end to end: through a relay the codes differ' => sub {
    my $pdir  = "$dir/pair-relay";
    my $rport = $port + 1;
    my $dpid  = start_dispatcher($pdir);
    my $rpid  = start_relay($rport);
    for (1 .. 50) {
        last if IO::Socket::INET->new(PeerAddr => "127.0.0.1:$rport");
        select undef, undef, undef, 0.1;
    }
    my $sub = Exec::Agent::AgentPairing::submit_pairing_request(
        'ctrl-exec' => '127.0.0.1', port => $rport,
        csr_pem => $csr, hostname => 'agent-one');
    my $q = $sub->{ok} ? queued($pdir) : undef;
    deny_all($pdir);
    close $sub->{sock} if $sub->{sock};
    kill 'TERM', $rpid; waitpid $rpid, 0;
    kill 'TERM', $dpid; waitpid $dpid, 0;
    plan skip_all => "relay unavailable: " . ($sub->{error} // '?') unless $sub->{ok};

    is $sub->{dispatcher_fpr}, $relay_fpr, 'agent saw the relay certificate';
    ok $q, 'the relayed CSR reached the dispatcher';
    is $q->{code_version}, 2, 'queued as v2';
    isnt $sub->{code}, $q->{code}, 'agent code differs from dispatcher code';
    is $sub->{code}, Exec::Digest::pairing_code_v2($csr, $relay_fpr),
        'agent code is bound to the relay certificate';
};

done_testing;
