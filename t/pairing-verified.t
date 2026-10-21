#!/usr/bin/perl
# t/pairing-verified.t
#
# T-041: verified pairing. With request-pairing --dispatcher-fingerprint (the
# SHA-256 of the dispatcher's CA certificate), the agent checks that the
# certificate presented on the pairing connection chains to that CA, and stops
# before sending its CSR when it does not. The pairing listener sends its CA
# certificate after its own so the check can be made; the pairing-mode banner
# and 'ctrl-exec-dispatcher ca-fingerprint' give the fingerprint. Without the
# flag pairing runs as before.

use strict;
use warnings;
use feature qw(signatures);
no warnings qw(experimental::signatures);
use Test::More;
use File::Temp  qw(tempdir);
use JSON        qw(encode_json decode_json);
use FindBin     qw($Bin);
use POSIX       qw();
use Sys::Hostname qw(hostname);
use lib         "$Bin/../lib", "$Bin/lib";
use ChildGuard  qw(guarded_fork);

use Exec::CA       qw();
use Exec::CertInfo qw();
use Exec::Pairing  qw();
use Exec::Agent::AgentPairing qw();

plan skip_all => 'openssl not available'
    unless system('openssl version >/dev/null 2>&1') == 0;

my $dir = ChildGuard::dir(tempdir(CLEANUP => 1));
ChildGuard::deadline(240);

my $STEP = 30;   # seconds any one end-to-end subtest may take

# --- fixtures: the dispatcher's CA and cert, a rogue CA and cert, a CSR -----

sub quiet ($code) {
    open my $save, '>&', \*STDERR or die;
    open STDERR, '>', '/dev/null';
    my @r = eval { $code->() };
    my $err = $@;
    open STDERR, '>&', $save;
    die $err if $err;
    return @r;
}

sub slurp_file ($p) { open my $fh, '<', $p or die "$p: $!"; local $/; return scalar <$fh> }

my $ca_dir    = "$dir/ca";
my $rogue_dir = "$dir/rogue";
mkdir $_ or die for $ca_dir, $rogue_dir;
quiet(sub {
    for my $d ($ca_dir, $rogue_dir) {
        Exec::CA::generate_ca(ca_dir => $d, bits => 2048);
        Exec::CA::generate_dispatcher_cert(ca_dir => $d, bits => 2048,
            cert => "$d/dispatcher.crt", key => "$d/dispatcher.key");
    }
    system('openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes',
        '-keyout', "$dir/agent.key", '-out', "$dir/agent.csr",
        '-subj', '/CN=agent-01') == 0 or die "csr failed";
});
my $csr       = slurp_file("$dir/agent.csr");
my $disp_crt  = "$ca_dir/dispatcher.crt";
my $disp_key  = "$ca_dir/dispatcher.key";
my $ca_fpr    = Exec::CertInfo::fingerprint_from_path("$ca_dir/ca.crt");
my $rogue_fpr = Exec::CertInfo::fingerprint_from_path("$rogue_dir/ca.crt");
my $leaf_fpr  = Exec::CertInfo::fingerprint_from_path($disp_crt);

# A relay's chain files: its own cert with its own CA, and its own cert with
# the real dispatcher's CA after it (the CA certificate is public, so a relay
# can present it).
{
    open my $fh, '>', "$dir/rogue-chain.crt" or die;
    print $fh slurp_file("$rogue_dir/dispatcher.crt"), slurp_file("$rogue_dir/ca.crt");
    close $fh;
    open $fh, '>', "$dir/impostor-chain.crt" or die;
    print $fh slurp_file("$rogue_dir/dispatcher.crt"), slurp_file("$ca_dir/ca.crt");
    close $fh;
}

# --- fingerprint parsing ----------------------------------------------------

subtest 'parse_sha256_fingerprint: the forms an operator pastes' => sub {
    my $hex   = $ca_fpr;
    my $colon = join ':', map { uc } unpack '(A2)*', $hex;
    is Exec::CertInfo::parse_sha256_fingerprint("SHA256:$hex"), $hex, 'SHA256:<hex>';
    is Exec::CertInfo::parse_sha256_fingerprint('sha256:' . uc $hex), $hex,
        'prefix and digits in either case';
    is Exec::CertInfo::parse_sha256_fingerprint("SHA256:$colon"), $hex, 'with colons';
    is Exec::CertInfo::parse_sha256_fingerprint($colon), $hex,
        'openssl colon form without the prefix';
    is Exec::CertInfo::parse_sha256_fingerprint(" SHA256:$hex\n"), $hex,
        'surrounding white space';
    is Exec::CertInfo::format_sha256_fingerprint($hex), "SHA256:$hex", 'display form';
    for my $bad ('', 'SHA256:', 'SHA256:' . substr($hex, 0, 40), "SHA256:${hex}00",
                 'SHA256:' . ('g' x 64), "SHA1:$hex", "SHA256: $hex x", undef) {
        is Exec::CertInfo::parse_sha256_fingerprint($bad), undef,
            'refused: ' . ($bad // 'undef');
    }
};

# --- the dispatcher's CA fingerprint ----------------------------------------

subtest 'ca_fingerprint: the CA that issued the served certificate' => sub {
    my $r = Exec::Pairing::ca_fingerprint(ca_dir => $ca_dir, cert => $disp_crt);
    ok $r->{ok}, 'available' or diag $r->{error};
    is $r->{fpr}, $ca_fpr, 'the fingerprint of ca.crt';
    isnt $r->{fpr}, $leaf_fpr, 'not the dispatcher certificate';

    $r = Exec::Pairing::ca_fingerprint(ca_dir => $ca_dir,
        cert => "$rogue_dir/dispatcher.crt");
    ok !$r->{ok}, 'unavailable when ca.crt did not issue the served certificate';
    like $r->{error}, qr/not issued by the CA/, 'and says why';

    $r = Exec::Pairing::ca_fingerprint(ca_dir => "$dir/absent");
    ok !$r->{ok}, 'unavailable without a CA certificate';
    like $r->{error}, qr/no CA certificate/, 'and says why';

    my $cmd = Exec::Pairing::agent_pairing_command($ca_fpr, 7444, 'd1.example.com');
    is $cmd, "ctrl-exec-agent request-pairing --dispatcher d1.example.com "
           . "--dispatcher-fingerprint SHA256:$ca_fpr", 'agent command, default port';
    like Exec::Pairing::agent_pairing_command($ca_fpr, 7555, 'd1.example.com'),
        qr/--dispatcher d1\.example\.com --port 7555 --dispatcher-fingerprint /,
        'agent command names a non-default port';
};

subtest 'ced ca-fingerprint prints the fingerprint on its own' => sub {
    my $conf = "$dir/ctrl-exec.conf";
    open my $fh, '>', $conf or die;
    print $fh "cert = $disp_crt\nkey = $disp_key\nca = $ca_dir/ca.crt\n";
    close $fh;
    my $drive = sub ($cadir) {
        my $out = qx{$^X -I$Bin/../lib -e '
            use Exec::DispatcherConfig;
            \$Exec::DispatcherConfig::CONF_DIR = q{$cadir};
            \$Exec::DispatcherConfig::LEGACY_DIR = q{$dir/no-legacy};
            \@ARGV = (q{--config}, q{$conf}, q{ca-fingerprint});
            do q{$Bin/../bin/ctrl-exec-dispatcher}; die \$@ if \$@;
            main::main();
        ' 2>&1};
        return ($out, $? >> 8);
    };
    my ($out, $rc) = $drive->($ca_dir);
    is $rc, 0, 'exit 0';
    is $out, "SHA256:$ca_fpr\n", 'one line: SHA256:<hex>';
    ($out, $rc) = $drive->("$dir/absent");
    isnt $rc, 0, 'fails without a CA';
    like $out, qr/no CA certificate/, 'with the reason';
};

# --- listeners --------------------------------------------------------------

require IO::Socket::SSL;
require IO::Select;

# Fork a pairing listener on a free port. Returns (pid, port).
sub start_dispatcher ($pdir, $cadir = $ca_dir) {
    pipe my $r, my $w or die "pipe: $!";
    my $pid = guarded_fork() // die "fork: $!";
    if ($pid == 0) {
        close $r;
        $w->autoflush(1);
        open STDIN,  '<', '/dev/null';
        open STDOUT, '>', "$pdir.out";
        eval {
            Exec::Pairing::run_pairing_mode(
                port => 0, cert => $disp_crt, key => $disp_key,
                ca_dir => $cadir, pairing_dir => $pdir, timeout => $STEP,
                log_fn => sub ($e) {
                    print $w "$e->{PORT}\n" if $e->{ACTION} eq 'pairing-mode-start';
                },
            );
        };
        print STDERR "pairing listener: $@" if $@;
        POSIX::_exit($@ ? 1 : 0);
    }
    close $w;
    my $port;
    $port = <$r> if IO::Select->new($r)->can_read(10);
    close $r;
    chomp $port if defined $port;
    return ($pid, (defined $port && $port =~ /\A\d+\z/ ? $port : undef));
}

# A man in the middle that presents $chain_file and forwards nothing: it
# accepts one TLS connection and records how many bytes the agent sent on it.
# Returns (pid, port, count file).
sub start_mitm ($chain_file, $key_file) {
    my $l = IO::Socket::SSL->new(LocalAddr => '127.0.0.1', LocalPort => 0,
        Listen => 1, SSL_cert_file => $chain_file, SSL_key_file => $key_file)
        or die "mitm listener: $IO::Socket::SSL::SSL_ERROR\n";
    my $port  = $l->sockport;
    my $count = "$dir/mitm-$port.count";
    my $pid = guarded_fork() // die "fork: $!";
    if ($pid) {
        close $l;
        return ($pid, $port, $count);
    }
    alarm $STEP;
    my $a = $l->accept or POSIX::_exit(1);
    my $n = 0;
    while (IO::Select->new($a)->can_read(5)) {
        my $got = sysread $a, my $buf, 16384;
        last unless $got;
        $n += $got;
    }
    open my $fh, '>', $count or POSIX::_exit(1);
    print $fh "$n\n";
    close $fh;
    POSIX::_exit(0);
}

sub stop_helper ($pid) {
    return unless $pid;
    kill 'KILL', -$pid, $pid;
    waitpid $pid, 0;
}

sub queued ($pdir, $tries = 50) {
    for (1 .. $tries) {
        my ($f) = glob "$pdir/*.json";
        return decode_json(slurp_file($f)) if $f;
        select undef, undef, undef, 0.1;
    }
    return undef;
}

sub submit ($port, $fpr = undef) {
    return Exec::Agent::AgentPairing::submit_pairing_request(
        'ctrl-exec' => '127.0.0.1', port => $port, timeout => 10,
        csr_pem => $csr, hostname => 'agent-01',
        (defined $fpr ? (dispatcher_ca_fpr => $fpr) : ()));
}

sub bounded ($code) {
    local $SIG{ALRM} = sub { die "timed out after ${STEP}s\n" };
    alarm $STEP;
    my $ok  = eval { $code->(); 1 };
    my $err = $@;
    alarm 0;
    return $ok ? undef : ($err || 'failed');
}

# Bytes the man in the middle received, once it has finished.
sub mitm_bytes ($pid, $count) {
    waitpid $pid, 0;
    return -f $count ? (slurp_file($count) =~ /(\d+)/)[0] : undef;
}

# --- the listener sends its CA ----------------------------------------------

subtest 'pairing listener presents its CA after its own certificate' => sub {
    my $pdir = "$dir/pair-chain";
    my ($dpid, $port) = start_dispatcher($pdir);
    my @fprs;
    my $err = !$port ? 'the pairing listener did not start' : bounded(sub {
        my $c = IO::Socket::SSL->new(PeerHost => '127.0.0.1', PeerPort => $port,
            Timeout => 10, SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_NONE())
            or die "connect: $IO::Socket::SSL::SSL_ERROR\n";
        @fprs = map { unpack 'H*', $c->get_fingerprint_bin('sha256', $_) }
            $c->peer_certificates;
        $c->close(SSL_no_shutdown => 1);
    });
    stop_helper($dpid);
    ok !$err, 'connected' or diag $err;
    is_deeply \@fprs, [ $leaf_fpr, $ca_fpr ], 'chain: dispatcher certificate, then CA';

    my $banner = -f "$pdir.out" ? slurp_file("$pdir.out") : '';
    like $banner, qr/Dispatcher CA fingerprint: SHA256:$ca_fpr$/m,
        'banner prints the CA fingerprint';
    like $banner,
        qr/^    ctrl-exec-agent request-pairing --dispatcher \Q${\ hostname()}\E --port $port --dispatcher-fingerprint SHA256:$ca_fpr$/m,
        'banner prints the agent command with the fingerprint';
    like $banner, qr/untrusted network/, 'and says to use it on any untrusted network';
};

subtest 'without a usable CA the listener serves as before and says so' => sub {
    my $pdir = "$dir/pair-noca";
    my ($dpid, $port) = start_dispatcher($pdir, "$dir/absent");
    my $sub;
    my $err = !$port ? 'the pairing listener did not start'
            : bounded(sub { $sub = submit($port) });
    close $sub->{sock} if $sub && $sub->{sock};
    stop_helper($dpid);
    ok !$err, 'exchange completed' or diag $err;
    ok $sub && $sub->{ok}, 'unverified pairing still works';
    my $banner = -f "$pdir.out" ? slurp_file("$pdir.out") : '';
    like $banner, qr/Verified pairing unavailable: no CA certificate/, 'banner says why';
    unlike $banner, qr/--dispatcher-fingerprint/, 'and offers no command';
};

# --- the agent's check ------------------------------------------------------

subtest 'right fingerprint: verified, and pairs end to end' => sub {
    my $pdir = "$dir/pair-ok";
    my $rdir = "$dir/registry-ok";
    mkdir $rdir;
    my ($dpid, $port) = start_dispatcher($pdir);
    my ($sub, $q, $res);
    my $err = !$port ? 'the pairing listener did not start' : bounded(sub {
        $sub = submit($port, $ca_fpr);
        die "submit: $sub->{error}\n" unless $sub->{ok};
        $q = queued($pdir) or die "nothing queued\n";
        open my $save, '>&', \*STDOUT or die;
        open STDOUT, '>', '/dev/null';
        my $ok = eval {
            Exec::Pairing::approve_request(reqid => $q->{id}, ca_dir => $ca_dir,
                pairing_dir => $pdir, registry_dir => $rdir,
                dispatcher_cert => $disp_crt, dispatcher_id => 'd1');
            1;
        };
        my $e = $@;
        open STDOUT, '>&', $save;
        die $e unless $ok;
        $res = Exec::Agent::AgentPairing::await_pairing_result(
            sock => $sub->{sock}, nonce => $sub->{nonce});
    });
    stop_helper($dpid);

    ok !$err, 'exchange completed' or diag $err;
    ok $sub && $sub->{ok}, 'request accepted after verification'
        or diag $sub ? $sub->{error} : 'no response';
    is $sub->{code}, $q->{code}, 'agent and dispatcher codes match';
    ok $res && $res->{ok}, 'approved and delivered' or diag $res ? $res->{error} : '';
    is $res->{dispatcher_id}, 'd1', 'from the dispatcher';
    is $res->{ca_pem}, slurp_file("$ca_dir/ca.crt"), 'the CA delivered is the one verified';
};

subtest 'wrong fingerprint: refused before the CSR is sent' => sub {
    my $pdir = "$dir/pair-wrong";
    my ($dpid, $port) = start_dispatcher($pdir);
    my ($sub, $q);
    my $err = !$port ? 'the pairing listener did not start' : bounded(sub {
        $sub = submit($port, $rogue_fpr);
        $q = queued($pdir, 10);
    });
    stop_helper($dpid);
    ok !$err, 'exchange completed' or diag $err;
    ok $sub && !$sub->{ok}, 'refused';
    ok $sub->{verify_failed}, 'as a verification failure';
    like $sub->{error}, qr/expected CA: SHA256:$rogue_fpr/, 'names the expected fingerprint';
    like $sub->{error}, qr/seen: +SHA256:$ca_fpr/, 'names the fingerprints seen';
    like $sub->{error}, qr/CSR was not sent/, 'says the CSR was not sent';
    ok !$q, 'the dispatcher queued nothing';
};

subtest 'man in the middle with its own CA: refused, nothing sent' => sub {
    my ($mpid, $mport, $count) = start_mitm("$dir/rogue-chain.crt", "$rogue_dir/dispatcher.key");
    my $sub;
    my $err = bounded(sub { $sub = submit($mport, $ca_fpr) });
    my $bytes = mitm_bytes($mpid, $count);
    ok !$err, 'exchange completed' or diag $err;
    ok $sub && !$sub->{ok} && $sub->{verify_failed}, 'refused as a verification failure';
    like $sub->{error}, qr/does not chain to the expected CA/, 'the CA is not in the chain';
    is $bytes, 0, 'the man in the middle received nothing (no CSR)';
};

subtest 'man in the middle presenting the real CA certificate: refused, nothing sent' => sub {
    my ($mpid, $mport, $count) = start_mitm("$dir/impostor-chain.crt", "$rogue_dir/dispatcher.key");
    my $sub;
    my $err = bounded(sub { $sub = submit($mport, $ca_fpr) });
    my $bytes = mitm_bytes($mpid, $count);
    ok !$err, 'exchange completed' or diag $err;
    ok $sub && !$sub->{ok} && $sub->{verify_failed}, 'refused as a verification failure';
    like $sub->{error}, qr/not issued by the expected CA/,
        'the CA certificate alone does not pass';
    is $bytes, 0, 'the man in the middle received nothing (no CSR)';
};

subtest 'no fingerprint: pairs as before, even through the same man in the middle' => sub {
    my $pdir = "$dir/pair-noflag";
    my ($dpid, $port) = start_dispatcher($pdir);
    my ($sub, $q);
    my $err = !$port ? 'the pairing listener did not start' : bounded(sub {
        $sub = submit($port);
        $q = queued($pdir) if $sub->{ok};
    });
    close $sub->{sock} if $sub && $sub->{sock};
    stop_helper($dpid);
    ok !$err, 'exchange completed' or diag $err;
    ok $sub && $sub->{ok}, 'request accepted';
    is $sub->{code}, $q->{code}, 'codes match';

    # The unverified path sends the CSR to whatever answers - what the flag stops.
    my ($mpid, $mport, $count) = start_mitm("$dir/rogue-chain.crt", "$rogue_dir/dispatcher.key");
    $err = bounded(sub { $sub = submit($mport) });
    my $bytes = mitm_bytes($mpid, $count);
    cmp_ok $bytes // 0, '>', length($csr), 'without the flag the CSR reaches a relay';
};

# --- the CLI ----------------------------------------------------------------

subtest 'request-pairing refuses a malformed fingerprint before connecting' => sub {
    require IO::Socket::INET;
    my $l = IO::Socket::INET->new(LocalAddr => '127.0.0.1', LocalPort => 0,
        Listen => 5, Blocking => 0) or die "listen: $!";
    my $port = $l->sockport;
    for my $bad ('SHA256:xyz', 'SHA1:' . ('a' x 40), 'abc') {
        my $out = qx{$^X -I$Bin/../lib $Bin/../bin/ctrl-exec-agent request-pairing --dispatcher 127.0.0.1 --port $port --dispatcher-fingerprint '$bad' 2>&1};
        isnt $? >> 8, 0, "exit non-zero: $bad";
        like $out, qr/--dispatcher-fingerprint must be SHA256:/, "names the expected form: $bad";
    }
    ok !$l->accept, 'nothing connected to the dispatcher port';
    close $l;
};

done_testing;
