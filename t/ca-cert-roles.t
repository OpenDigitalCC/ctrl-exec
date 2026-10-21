#!/usr/bin/perl
# t/ca-cert-roles.t
#
# T-066: from 0.14 the dispatcher CA marks every certificate it issues with its
# role - 'dispatcher' (setup-ctrl-exec, rotation) or 'agent' (pairing approval,
# renewal) - in a non-critical private extension the CA sets from the code path
# that signs, never from the CSR. Exec::CertInfo::cert_role reads it back
# (verified pairing and doctor use it). Certificates issued before 0.14 carry no
# mark and gain it at their next renewal or rotation; nothing is reissued on
# upgrade. The mark must not disturb a TLS handshake in either direction.

use strict;
use warnings;
use feature qw(signatures);
no warnings qw(experimental::signatures);
use Test::More;
use File::Temp  qw(tempdir);
use File::Path  qw(make_path);
use JSON        qw(encode_json);
use FindBin     qw($Bin);
use POSIX       qw();
use lib         "$Bin/../lib", "$Bin/lib";
use ChildGuard  qw(guarded_fork);

use Exec::CA       qw();
use Exec::CertInfo qw();
use Exec::Digest   qw();
use Exec::Engine   qw();
use Exec::Pairing  qw();
use Exec::Rotation qw();
use Exec::Agent::AgentPairing qw();

plan skip_all => 'openssl not available'
    unless system('openssl version >/dev/null 2>&1') == 0;

my $dir = ChildGuard::dir(tempdir(CLEANUP => 1));
ChildGuard::deadline(180);

my $OID = '2.25.266442206991433179228746487034237142618';

sub quiet ($code) {
    open my $save, '>&', \*STDERR or die;
    open STDERR, '>', '/dev/null';
    my @r = eval { $code->() };
    my $err = $@;
    open STDERR, '>&', $save;
    die $err if $err;
    return wantarray ? @r : $r[0];
}

sub slurp ($p) { open my $fh, '<', $p or die "$p: $!"; local $/; return scalar <$fh> }
sub spit ($p, $c) { open my $fh, '>', $p or die "$p: $!"; print $fh $c; close $fh }
sub run_ok (@cmd) { quiet(sub { system(@cmd) == 0 or die "@cmd failed\n" }) }

# A certificate as a CA issued it before 0.14: openssl x509 -req with the
# pre-0.14 extfile (CA:FALSE, SKI, AKI, no role).
sub sign_unmarked ($ca, $csr_path, $out) {
    spit("$dir/old.ext", "basicConstraints=CA:FALSE\nsubjectKeyIdentifier=hash\n"
                       . "authorityKeyIdentifier=keyid,issuer\n");
    run_ok('openssl', 'x509', '-req', '-in', $csr_path, '-CA', "$ca/ca.crt",
        '-CAkey', "$ca/ca.key", '-set_serial', '0x' . Exec::CA::random_serial(),
        '-out', $out, '-days', 30, '-extfile', "$dir/old.ext");
    return slurp($out);
}

# The role extensions of a certificate, as [critical, value] pairs.
sub role_exts ($pem) {
    require IO::Socket::SSL;
    my $bio = Net::SSLeay::BIO_new(Net::SSLeay::BIO_s_mem());
    Net::SSLeay::BIO_write($bio, $pem);
    my $x = Net::SSLeay::PEM_read_bio_X509($bio);
    Net::SSLeay::BIO_free($bio);
    my @r;
    for my $i (0 .. Net::SSLeay::X509_get_ext_count($x) - 1) {
        my $e = Net::SSLeay::X509_get_ext($x, $i);
        next unless Net::SSLeay::OBJ_obj2txt(Net::SSLeay::X509_EXTENSION_get_object($e), 1) eq $OID;
        my $der = Net::SSLeay::P_ASN1_STRING_get(Net::SSLeay::X509_EXTENSION_get_data($e));
        push @r, [ Net::SSLeay::X509_EXTENSION_get_critical($e), substr($der, 2) ];
    }
    Net::SSLeay::X509_free($x);
    return @r;
}

# --- fixtures ---------------------------------------------------------------

my $ca = "$dir/ca";
make_path($ca);
quiet(sub {
    Exec::CA::generate_ca(ca_dir => $ca, bits => 2048);
    Exec::CA::generate_dispatcher_cert(ca_dir => $ca, bits => 2048,
        cert => "$ca/dispatcher.crt", key => "$ca/dispatcher.key");
});
my $agent = quiet(sub {
    Exec::Agent::AgentPairing::generate_key_and_csr(hostname => 'agent-01', bits => 2048) });
spit("$dir/agent.key", $agent->{key_pem});
spit("$dir/agent.csr", $agent->{csr_pem});
my $agent_crt = quiet(sub { Exec::CA::sign_csr(csr_pem => $agent->{csr_pem}, ca_dir => $ca) });
spit("$dir/agent.crt", $agent_crt);
my $disp_crt = slurp("$ca/dispatcher.crt");

# --- what the CA writes -----------------------------------------------------

is $Exec::CertInfo::ROLE_OID, $OID, 'the role OID (2.25 UUID arc)';

subtest 'the dispatcher certificate is marked dispatcher' => sub {
    is Exec::CertInfo::cert_role($disp_crt), 'dispatcher', 'cert_role';
    is_deeply [ role_exts($disp_crt) ], [ [ 0, 'dispatcher' ] ],
        'one role extension, non-critical';
};

subtest 'an agent certificate (pairing approval) is marked agent' => sub {
    is Exec::CertInfo::cert_role($agent_crt), 'agent', 'cert_role';
    is_deeply [ role_exts($agent_crt) ], [ [ 0, 'agent' ] ],
        'one role extension, non-critical';
    my $text = quiet(sub { scalar `openssl x509 -noout -text -in $dir/agent.crt` });
    like $text, qr/CA:FALSE/, 'still CA:FALSE';
    like $text, qr/Authority Key Identifier/, 'still carries the AKI';
};

subtest 'a CSR asking for the dispatcher role gets an agent certificate' => sub {
    spit("$dir/greedy.cnf", "[req]\ndistinguished_name=dn\nreq_extensions=ext\n[dn]\n"
        . "[ext]\n$OID=ASN1:UTF8String:dispatcher\nbasicConstraints=CA:TRUE\n");
    run_ok('openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes',
        '-keyout', "$dir/greedy.key", '-out', "$dir/greedy.csr",
        '-subj', '/CN=agent-02', '-config', "$dir/greedy.cnf");
    my $req = quiet(sub { scalar `openssl req -noout -text -in $dir/greedy.csr` });
    like $req, qr/\Q$OID\E/, 'the CSR does ask for a role';
    my $crt = quiet(sub { Exec::CA::sign_csr(csr_pem => slurp("$dir/greedy.csr"), ca_dir => $ca) });
    is Exec::CertInfo::cert_role($crt), 'agent', 'the certificate is marked agent';
    is_deeply [ role_exts($crt) ], [ [ 0, 'agent' ] ], 'and carries only the CA\'s mark';
    spit("$dir/greedy.crt", $crt);
    unlike quiet(sub { scalar `openssl x509 -noout -text -in $dir/greedy.crt` }), qr/CA:TRUE/,
        'nothing else from the CSR is copied either';
};

subtest 'cert_role: unmarked, unknown and unreadable' => sub {
    my $old = sign_unmarked($ca, "$dir/agent.csr", "$dir/old-agent.crt");
    is Exec::CertInfo::cert_role($old), undef, 'a pre-0.14 certificate is unmarked';
    is Exec::CertInfo::cert_role(slurp("$ca/ca.crt")), undef, 'the CA itself is unmarked';
    spit("$dir/odd.ext", "$OID=ASN1:UTF8String:operator\n");
    run_ok('openssl', 'x509', '-req', '-in', "$dir/agent.csr", '-CA', "$ca/ca.crt",
        '-CAkey', "$ca/ca.key", '-set_serial', '0x51', '-out', "$dir/odd.crt",
        '-days', 1, '-extfile', "$dir/odd.ext");
    is Exec::CertInfo::cert_role(slurp("$dir/odd.crt")), 'unknown', 'another value is unknown';
    spit("$dir/int.ext", "$OID=ASN1:INTEGER:1\n");
    run_ok('openssl', 'x509', '-req', '-in', "$dir/agent.csr", '-CA', "$ca/ca.crt",
        '-CAkey', "$ca/ca.key", '-set_serial', '0x52', '-out', "$dir/int.crt",
        '-days', 1, '-extfile', "$dir/int.ext");
    is Exec::CertInfo::cert_role(slurp("$dir/int.crt")), 'unknown', 'a non-string value is unknown';
    is Exec::CertInfo::cert_role("junk\n"), undef, 'not a certificate: undef';
    is Exec::CertInfo::cert_role(undef), undef, 'undef: undef';
};

# --- renewal and rotation add the mark -------------------------------------

{
    package FakeResp;
    sub new { my ($c, %a) = @_; bless {%a}, $c }
    sub is_success  { 1 }
    sub content     { $_[0]{content} }
    sub status_line { '200 OK' }
    package FakeUA;
    sub new { my ($c, %a) = @_; bless {%a}, $c }
    sub post {
        my ($s, $url, %a) = @_;
        return FakeResp->new(content => JSON::encode_json({ csr => $s->{csr} }))
            if $url =~ m{/renew\z};
        $s->{delivered} = JSON::decode_json($a{Content})->{cert};
        return FakeResp->new(content => '{"status":"ok"}');
    }
}

subtest 'renewal of an unmarked agent certificate marks it agent' => sub {
    my $old = sign_unmarked($ca, "$dir/agent.csr", "$dir/old-agent.crt");
    is Exec::CertInfo::cert_role($old), undef, 'the certificate in use is unmarked';
    # The agent's /renew answer: a CSR from its existing key.
    my $csr = quiet(sub { Exec::Agent::AgentPairing::generate_csr_only(
        hostname => 'agent-01', key_path => "$dir/agent.key") })->{csr_pem};
    my $ua = FakeUA->new(csr => $csr);
    no warnings 'redefine';
    local *Exec::Engine::_build_ua = sub { $ua };
    local *Exec::Log::log_action   = sub { };
    local *Exec::Registry::update_expiry = sub { };
    my $ok = eval {
        Exec::Engine::_renew_one(host => '127.0.0.1', port => 7443, name => 'agent-01',
            reqid => 'r1', config => { ca_dir => $ca, cert_days => 30 });
        1;
    };
    ok $ok, 'renewed' or diag $@;
    ok defined $ua->{delivered}, 'a certificate was delivered';
    is Exec::CertInfo::cert_role($ua->{delivered} // ''), 'agent', 'marked agent';
    my ($ok2, $why) = Exec::Agent::AgentPairing::validate_cert(cert_pem => $ua->{delivered},
        ca_path => "$ca/ca.crt", key_path => "$dir/agent.key");
    ok $ok2, 'and the agent accepts it as its renewal' or diag $why;
};

subtest 'rotation of an unmarked dispatcher certificate marks it dispatcher' => sub {
    my $d = "$dir/rot";
    make_path("$d/agents");
    quiet(sub { Exec::CA::generate_ca(ca_dir => $d, bits => 2048) });
    run_ok('openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes',
        '-keyout', "$d/dispatcher.key", '-out', "$d/dispatcher.csr",
        '-subj', '/CN=ctrl-exec-dispatcher');
    sign_unmarked($d, "$d/dispatcher.csr", "$d/dispatcher.crt");
    is Exec::CertInfo::cert_role(slurp("$d/dispatcher.crt")), undef,
        'the dispatcher certificate in use is unmarked';
    my $r = quiet(sub { Exec::Rotation::_do_rotation(config => {
        ca_dir => $d, cert => "$d/dispatcher.crt", key => "$d/dispatcher.key",
        rotation_file => "$d/rotation.json", registry_dir => "$d/agents",
        cert_days => 30, cert_renewal_days => 10, cert_overlap_days => 5,
        service_user => scalar getpwuid($<) }) });
    ok $r->{rotated}, 'rotated' or diag $r->{error};
    is Exec::CertInfo::cert_role(slurp("$d/dispatcher.crt")), 'dispatcher',
        'the rotated certificate is marked dispatcher';
};

# --- keep-cert pairing (T-062) takes agent certificates, marked or not -------

subtest 'check_kept_cert accepts an agent-marked and an unmarked certificate' => sub {
    my $csr = $agent->{csr_pem};
    my $ca_pem = Exec::Digest::canonical_cert(slurp("$ca/ca.crt"));
    for ([ marked => $agent_crt ],
         [ unmarked => sign_unmarked($ca, "$dir/agent.csr", "$dir/old-agent.crt") ]) {
        my ($what, $pem) = @$_;
        my $r = Exec::Pairing::check_kept_cert($csr, Exec::Digest::canonical_cert($pem), $ca_pem);
        ok $r->{ok}, "$what agent certificate accepted" or diag $r->{error};
    }
};

# --- TLS handshakes with marked certificates --------------------------------

require IO::Socket::SSL;
require Exec::TLS;

# mTLS on loopback: $srv serves with its certificate and requires a client
# certificate from the CA; the client verifies the server against the CA.
# Returns undef on success or the error.
sub handshake ($srv, $cli) {
    my $l = IO::Socket::SSL->new(LocalAddr => '127.0.0.1', LocalPort => 0, Listen => 1,
        SSL_cert_file => $srv->[0], SSL_key_file => $srv->[1],
        SSL_ca_file => "$ca/ca.crt",
        SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_PEER()
                         | IO::Socket::SSL::SSL_VERIFY_FAIL_IF_NO_PEER_CERT(),
        Exec::TLS::hardening())
        or return "listen: $IO::Socket::SSL::SSL_ERROR";
    my $port = $l->sockport;
    my $pid = guarded_fork() // die "fork: $!";
    if ($pid == 0) {
        alarm 20;
        my $c = $l->accept;
        print $c "hello\n" if $c;
        close $c if $c;
        POSIX::_exit($c ? 0 : 1);
    }
    close $l;
    my $c = IO::Socket::SSL->new(PeerHost => '127.0.0.1', PeerPort => $port, Timeout => 10,
        SSL_cert_file => $cli->[0], SSL_key_file => $cli->[1],
        SSL_ca_file => "$ca/ca.crt", SSL_verifycn_name => 'ignored',
        SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_PEER(),
        SSL_verifycn_scheme => 'none');
    my $err = $c ? undef : "connect: $IO::Socket::SSL::SSL_ERROR";
    my $line = $c ? <$c> : undef;
    close $c if $c;
    waitpid $pid, 0;
    return $err // ($? == 0 && ($line // '') eq "hello\n" ? undef : 'server side failed');
}

subtest 'handshakes: marked certificates work in both directions' => sub {
    my $a = [ "$dir/agent.crt", "$dir/agent.key" ];
    my $d = [ "$ca/dispatcher.crt", "$ca/dispatcher.key" ];
    is handshake($a, $d), undef, 'agent serves (7443), dispatcher is the client';
    is handshake($d, $a), undef, 'dispatcher serves (pairing port), agent is the client';
};

done_testing;
