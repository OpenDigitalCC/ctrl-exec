#!/usr/bin/perl
# t/pairing-keep-cert.t
#
# T-062: an agent already paired with dispatcher A (its own CA) pairs with
# dispatcher B (its own CA) the way an operator pairs any agent - the agent's
# request, B's approval - without a key or CA file copied. The agent keeps its
# key and certificate and presents them with their CA; B pins that CA for this
# agent alone. Both dispatchers then run scripts on the agent, with no agent
# restart. B refuses this agent presenting a certificate from another CA; A
# renewing the agent's certificate keeps B working; B never renews it. A
# dispatcher before 0.14 (no keep confirmation) makes the agent withdraw.

use strict;
use warnings;
use feature qw(signatures);
no warnings qw(experimental::signatures);
use Test::More;
use File::Temp  qw(tempdir);
use JSON        qw(encode_json decode_json);
use FindBin     qw($Bin);
use POSIX       qw(WNOHANG);
use Time::HiRes qw(sleep time);
use IO::Socket::INET;
use lib         "$Bin/../lib", "$Bin/lib";
use ChildGuard  qw(guarded_fork);

use Exec::CA       qw();
use Exec::CertInfo qw();
use Exec::Digest   qw();
use Exec::Engine   qw();
use Exec::Pairing  qw();
use Exec::Registry qw();
use Exec::Agent::AgentPairing qw();

plan skip_all => 'openssl not available'
    unless system('openssl version >/dev/null 2>&1') == 0;

# The agent's name: its FQDN, which is what it puts in a renewal CSR (and the
# renewing dispatcher binds the CN to the registry name).
require Exec::Agent::Server;
my $NAME = Exec::Agent::Server::fqdn();
my $dir = ChildGuard::dir(tempdir(CLEANUP => !$ENV{T062_KEEP}));
ChildGuard::deadline(300);
my $STEP = 40;

sub slurp ($p) { open my $fh, '<', $p or die "$p: $!"; local $/; return scalar <$fh> }
sub spew ($p, $t) { open my $fh, '>', $p or die "$p: $!"; print $fh $t; close $fh }

# Run $code with STDOUT and STDERR to /dev/null (approve prints; openssl and
# the group warning of store_certs write to stderr).
sub quiet ($code) {
    open my $so, '>&', \*STDOUT or die;
    open my $se, '>&', \*STDERR or die;
    open STDOUT, '>', '/dev/null';
    open STDERR, '>', '/dev/null';
    my @r = eval { $code->() };
    my $err = $@;
    open STDOUT, '>&', $so;
    open STDERR, '>&', $se;
    die $err if $err;
    return wantarray ? @r : $r[0];
}

sub bounded ($code) {
    local $SIG{ALRM} = sub { die "timed out after ${STEP}s\n" };
    alarm $STEP;
    my $ok  = eval { $code->(); 1 };
    my $err = $@;
    alarm 0;
    return $ok ? undef : ($err || 'failed');
}

sub free_port {
    my $s = IO::Socket::INET->new(LocalAddr => '127.0.0.1', LocalPort => 0, Listen => 1)
        or die "no free port: $!";
    my $p = $s->sockport;
    close $s;
    return $p;
}

# --- two dispatchers, each with its own CA ----------------------------------

sub dispatcher ($id) {
    my $d = "$dir/$id";
    mkdir $d or die;
    mkdir "$d/registry" or die;
    quiet(sub {
        Exec::CA::generate_ca(ca_dir => $d, bits => 2048, id => $id);
        Exec::CA::generate_dispatcher_cert(ca_dir => $d, bits => 2048,
            cert => "$d/dispatcher.crt", key => "$d/dispatcher.key");
    });
    return {
        id => $id, dir => $d, ca_fpr => Exec::CertInfo::fingerprint_from_path("$d/ca.crt"),
        config => { cert => "$d/dispatcher.crt", key => "$d/dispatcher.key",
                    ca => "$d/ca.crt", ca_dir => $d, registry_dir => "$d/registry",
                    max_parallel => 2, timeout => 20 },
    };
}

my $A = dispatcher('dA');
my $B = dispatcher('dB');

# --- pairing plumbing --------------------------------------------------------

require IO::Select;

sub start_listener ($D) {
    my $pdir = "$D->{dir}/pairing-" . int(rand 1e9);
    pipe my $r, my $w or die "pipe: $!";
    my $pid = guarded_fork() // die "fork: $!";
    if ($pid == 0) {
        close $r;
        $w->autoflush(1);
        open STDIN,  '<', '/dev/null';
        open STDOUT, '>', "$pdir.out";
        eval {
            Exec::Pairing::run_pairing_mode(
                port => 0, cert => $D->{config}{cert}, key => $D->{config}{key},
                ca_dir => $D->{dir}, pairing_dir => $pdir, timeout => $STEP,
                dispatcher_id => $D->{id},
                log_fn => sub ($e) {
                    print $w "$e->{PORT}\n" if $e->{ACTION} eq 'pairing-mode-start';
                },
            );
        };
        POSIX::_exit($@ ? 1 : 0);
    }
    close $w;
    my $port;
    $port = <$r> if IO::Select->new($r)->can_read(15);
    close $r;
    chomp $port if defined $port;
    die "pairing listener did not start\n" unless defined $port && $port =~ /\A\d+\z/;
    return ($pid, $port, $pdir);
}

sub stop_pid ($pid) {
    return unless $pid;
    kill 'TERM', -$pid, $pid;
    waitpid $pid, 0;
}

sub queued ($pdir) {
    for (1 .. 100) {
        my ($f) = glob "$pdir/*.json";
        if ($f) { my $q = eval { decode_json(slurp($f)) }; return $q if $q }
        sleep 0.1;
    }
    return undef;
}

# Pair with dispatcher $D. %o: csr, key_pem (fresh) or kept (keep form),
# fpr (verified pairing). Returns { sub, q, res, approve_out }.
sub pair_with ($D, %o) {
    my ($pid, $port, $pdir) = start_listener($D);
    my %out;
    my $err = bounded(sub {
        my $sub = $out{sub} = Exec::Agent::AgentPairing::submit_pairing_request(
            'ctrl-exec' => '127.0.0.1', port => $port, timeout => 10,
            csr_pem => $o{csr}, hostname => $NAME,
            ($o{fpr} ? (dispatcher_ca_fpr => $o{fpr}) : ()),
            ($o{kept} ? (agent_cert => $o{kept}{cert_pem}, agent_ca => $o{kept}{ca_pem}) : ()));
        die "submit: $sub->{error}\n" unless $sub->{ok};
        my $q = $out{q} = queued($pdir) or die "nothing queued\n";
        my $outfile = "$pdir.approve";
        open my $so, '>&', \*STDOUT or die;
        open STDOUT, '>', $outfile or die;
        my $ok = eval {
            Exec::Pairing::approve_request(reqid => $q->{id}, ca_dir => $D->{dir},
                pairing_dir => $pdir, registry_dir => $D->{config}{registry_dir},
                dispatcher_cert => $D->{config}{cert}, dispatcher_id => $D->{id});
            1;
        };
        my $e = $@;
        open STDOUT, '>&', $so;
        die $e unless $ok;
        $out{approve_out} = slurp($outfile);
        $out{res} = Exec::Agent::AgentPairing::await_pairing_result(
            sock => $sub->{sock}, nonce => $sub->{nonce},
            cert_mode => $sub->{cert_mode},
            ($o{expect_fpr} ? (dispatcher_ca_fpr => $o{expect_fpr}) : ()));
    });
    stop_pid($pid);
    die "pairing with $D->{id}: $err" if $err;
    return \%out;
}

# --- the agent ---------------------------------------------------------------

my $AD   = "$dir/agent";
mkdir $AD or die;
mkdir "$AD/state" or die;
my $MAP  = "$AD/state/dispatchers";
my $PORT = free_port();
spew("$AD/hello.sh", "#!/bin/sh\necho \"hello from agent args=\$*\"\n");
chmod 0755, "$AD/hello.sh";
spew("$AD/scripts.conf", "hello = $AD/hello.sh\n");
spew("$AD/agent.conf", <<"END");
port = $PORT
cert = $AD/agent.crt
key  = $AD/agent.key
ca   = $AD/ca.crt
trusted_dispatchers_path = $MAP
revoked_serials = $AD/revoked
async_runs_dir = $AD/runs
cert_staging_path = $AD/agent.crt.staged

[profile default]
END

my $agent_pid;
sub agent_start {
    my $pid = guarded_fork() // die "fork: $!";
    if ($pid == 0) {
        open STDERR, '>>', "$AD/agent.log" or die;
        open STDOUT, '>>', "$AD/agent.log" or die;
        exec $^X, "-I$Bin/../lib", "-I$Bin/lib", '-MNoSyslog', "$Bin/../bin/ctrl-exec-agent",
            '--config', "$AD/agent.conf", '--allowlist', "$AD/scripts.conf", 'serve'
            or die "exec: $!";
    }
    $agent_pid = $pid;
    my $deadline = time + 15;
    while (time < $deadline) {
        my $s = IO::Socket::INET->new(PeerAddr => '127.0.0.1', PeerPort => $PORT);
        if ($s) { close $s; return 1 }
        return 0 if waitpid($pid, WNOHANG) > 0;
        sleep 0.1;
    }
    return 0;
}
sub agent_stop { return unless $agent_pid; kill 'TERM', $agent_pid; waitpid $agent_pid, 0; $agent_pid = undef }
# Stopped by ChildGuard however the test ends; no END block here, which every
# forked Engine worker would run too.

my $TARGET = [ { name => $NAME, target => "127.0.0.1:$PORT" } ];

sub run_from ($D, $name = $NAME, $target = "127.0.0.1:$PORT") {
    my $r = quiet(sub { Exec::Engine::dispatch_all(
        hosts => [ { name => $name, target => $target } ], script => 'hello',
        args => [ $D->{id} ], config => $D->{config}) });
    return $r->[0];
}

sub ping_from ($D, $name = $NAME, $target = "127.0.0.1:$PORT", %o) {
    my $r = quiet(sub { Exec::Engine::ping_all(
        hosts => [ { name => $name, target => $target } ],
        config => { %{ $D->{config} }, %o }) });
    return $r->[0];
}

# --- 1. fresh pairing with A, as today ---------------------------------------

my $fresh = Exec::Agent::AgentPairing::generate_key_and_csr(hostname => $NAME, bits => 2048);
subtest 'fresh pairing with A behaves as before' => sub {
    my $p = pair_with($A, csr => $fresh->{csr_pem});
    is $p->{sub}{cert_mode}, 'new', 'an ordinary request';
    ok !exists $p->{q}{agent_cert}, 'nothing kept in the queue';
    is $p->{sub}{code}, $p->{q}{code}, 'codes match';
    ok $p->{res}{ok}, 'approved' or diag $p->{res}{error};
    is $p->{res}{cert_mode}, 'new', 'a new certificate delivered';
    quiet(sub { Exec::Agent::AgentPairing::store_certs(
        cert_pem => $p->{res}{cert_pem}, key_pem => $fresh->{key_pem},
        ca_pem => $p->{res}{ca_pem}, dispatcher_serial => $p->{res}{dispatcher_serial},
        dispatcher_id => $p->{res}{dispatcher_id}, cert_dir => $AD,
        trusted_path => $MAP, group => 'no-such-group-t062') });
    is Exec::CertInfo::verify_issued_by(slurp("$AD/agent.crt"), slurp("$A->{dir}/ca.crt")),
        undef, "the agent's certificate is from A's CA";
    like `openssl x509 -noout -text -in $AD/agent.crt`, qr/Authority Key Identifier/,
        'and carries an AKI';
    my $rec = Exec::Registry::get_agent(hostname => $NAME,
        registry_dir => $A->{config}{registry_dir});
    ok $rec && !exists $rec->{agent_ca}, "A's registry entry pins nothing";
};

ok agent_start(), 'agent started' or BAIL_OUT(slurp("$AD/agent.log"));

subtest 'A runs a script' => sub {
    my $r = run_from($A);
    is $r->{exit}, 0, 'exit 0' or diag explain $r;
    like $r->{stdout} // '', qr/hello from agent args=dA/, 'output';
    my $r2 = run_from($B);
    isnt $r2->{exit} // -1, 0, 'B, not yet paired, cannot' or diag explain $r2;
};

# --- 2. keep-certificate pairing with B ---------------------------------------

my $crt_before = slurp("$AD/agent.crt");
my $key_before = slurp("$AD/agent.key");
my $kept = Exec::Agent::AgentPairing::kept_identity(cert_dir => $AD);

subtest 'the agent offers its current identity' => sub {
    ok $kept, 'kept identity available';
    is $kept->{cert_pem}, $crt_before, 'its certificate';
    is $kept->{ca_fpr}, $A->{ca_fpr}, "issued by A's CA";
    is $kept->{ca_pem}, slurp("$A->{dir}/ca.crt"), "and A's CA certificate";
    is $kept->{key_path}, "$AD/agent.key", 'its key';
};

my $log_from = length slurp("$AD/agent.log");
subtest 'pairing with B keeps the key and certificate, pins A\'s CA on B' => sub {
    my $csr = Exec::Agent::AgentPairing::generate_csr_only(
        hostname => $NAME, key_path => $kept->{key_path})->{csr_pem};
    my $p = pair_with($B, csr => $csr, kept => $kept,
        fpr => $B->{ca_fpr}, expect_fpr => $B->{ca_fpr});
    is $p->{sub}{cert_mode}, 'keep', 'B confirmed it keeps the certificate';
    is $p->{sub}{code}, $p->{q}{code}, 'agent and dispatcher codes match';
    isnt $p->{q}{code}, Exec::Digest::pairing_code_for(2, $csr,
        Exec::CertInfo::fingerprint_from_path($B->{config}{cert})),
        'the code covers the certificate, not the CSR alone';
    is $p->{q}{agent_ca_fpr}, $A->{ca_fpr}, 'queued with the issuing CA fingerprint';
    my @lines = Exec::Pairing::kept_cert_lines($p->{q});
    like "@lines", qr/Issued by:  SHA256:$A->{ca_fpr} \(CN=ctrl-exec CA dA /,
        'list-requests shows the issuing CA';
    like $p->{approve_out}, qr/verifies this agent against that CA/, 'approve says it pins';
    ok $p->{res}{ok}, 'approved' or diag $p->{res}{error};
    is $p->{res}{cert_mode}, 'keep', 'approval keeps the certificate';
    ok !defined $p->{res}{cert_pem}, 'no certificate delivered';

    quiet(sub { Exec::Agent::AgentPairing::store_certs(keep_cert => 1,
        ca_pem => $p->{res}{ca_pem}, dispatcher_serial => $p->{res}{dispatcher_serial},
        dispatcher_id => $p->{res}{dispatcher_id}, cert_dir => $AD,
        trusted_path => $MAP, group => 'no-such-group-t062') });
    is slurp("$AD/agent.crt"), $crt_before, 'agent.crt unchanged';
    is slurp("$AD/agent.key"), $key_before, 'agent.key unchanged';
    is_deeply [ Exec::Agent::AgentPairing::ca_bundle_fingerprints("$AD/ca.crt") ],
        [ $A->{ca_fpr}, $B->{ca_fpr} ], 'bundle: A\'s CA, then B\'s';
    is_deeply [ Exec::Agent::AgentPairing::trusted_dispatcher_ids($MAP) ], [ 'dA', 'dB' ],
        'both dispatchers trusted';

    my $rec = Exec::Registry::get_agent(hostname => $NAME,
        registry_dir => $B->{config}{registry_dir});
    is $rec->{agent_ca}, slurp("$A->{dir}/ca.crt"), "B's registry entry pins A's CA";
    is $rec->{agent_ca_fpr}, $A->{ca_fpr}, 'with its fingerprint';
};

subtest 'both dispatchers run, with no agent restart' => sub {
    my $rb = run_from($B);
    is $rb->{exit}, 0, 'B runs' or diag explain($rb), diag(substr(slurp("$AD/agent.log"), $log_from));
    like $rb->{stdout} // '', qr/args=dB/, 'B output';
    my $ra = run_from($A);
    is $ra->{exit}, 0, 'A still runs' or diag explain $ra;
    like substr(slurp("$AD/agent.log"), $log_from), qr/ACTION=ca-bundle-reload/,
        'the agent reloaded its CA bundle';
    ok kill(0, $agent_pid), 'same agent process';
};

subtest 'B never holds A\'s key or the agent\'s key' => sub {
    # A line from the middle of each key: the first lines of two keys of the
    # same type share their encoded header.
    my ($a_key) = (split /\n/, slurp("$A->{dir}/ca.key"))[5];
    my ($g_key) = (split /\n/, $key_before)[5];
    ok length($a_key) > 40 && length($g_key) > 40, 'key lines to look for';
    my @hits = grep { my $t = slurp($_); index($t, $a_key) >= 0 || index($t, $g_key) >= 0 }
        grep { -f } glob("$B->{dir}/* $B->{dir}/*/* $B->{dir}/*/*/*");
    is_deeply \@hits, [], 'no file of B holds either key';
};

# --- 3. B verifies this agent against the pinned CA only ----------------------

subtest 'B refuses this agent presenting a certificate from another CA' => sub {
    # An impostor agent: certificate from B's own CA, trusting B. B's global CA
    # would accept it; the CA pinned for the entry does not.
    my $ID = "$dir/impostor";
    mkdir $ID or die;
    my $ik = Exec::Agent::AgentPairing::generate_key_and_csr(hostname => $NAME, bits => 2048);
    my $icrt = quiet(sub { Exec::CA::sign_csr(csr_pem => $ik->{csr_pem}, ca_dir => $B->{dir}) });
    spew("$ID/agent.crt", $icrt);
    spew("$ID/agent.key", $ik->{key_pem});
    spew("$ID/ca.crt", slurp("$B->{dir}/ca.crt"));
    my $bserial = Exec::CertInfo::serial_from_path($B->{config}{cert});
    spew("$ID/dispatchers", "$B->{ca_fpr} $bserial dB\n");
    my $iport = free_port();
    spew("$ID/agent.conf", "port = $iport\ncert = $ID/agent.crt\nkey = $ID/agent.key\n"
        . "ca = $ID/ca.crt\ntrusted_dispatchers_path = $ID/dispatchers\n"
        . "revoked_serials = $ID/revoked\nasync_runs_dir = $ID/runs\n\n[profile default]\n");
    my $pid = guarded_fork() // die;
    if ($pid == 0) {
        open STDERR, '>>', "$ID/agent.log"; open STDOUT, '>>', "$ID/agent.log";
        exec $^X, "-I$Bin/../lib", "-I$Bin/lib", '-MNoSyslog', "$Bin/../bin/ctrl-exec-agent",
            '--config', "$ID/agent.conf", '--allowlist', "$AD/scripts.conf", 'serve';
        die;
    }
    my $up = 0;
    for (1 .. 150) {
        if (IO::Socket::INET->new(PeerAddr => '127.0.0.1', PeerPort => $iport)) { $up = 1; last }
        sleep 0.1;
    }
    ok $up, 'impostor started';

    my $rec = Exec::Registry::get_agent(hostname => $NAME,
        registry_dir => $B->{config}{registry_dir});
    my $r = ping_from($B, $NAME, "127.0.0.1:$iport");
    is $r->{status}, 'error', 'refused under the pinned CA' or diag explain $r;

    # Control: the same impostor under an entry with no pin is accepted, so the
    # refusal above is the pin.
    Exec::Registry::register_agent(hostname => 'plain-entry', ip => '127.0.0.1',
        registry_dir => $B->{config}{registry_dir});
    $r = ping_from($B, 'plain-entry', "127.0.0.1:$iport");
    is $r->{status}, 'ok', 'an unpinned entry trusts B\'s own CA (control)' or diag explain $r;

    # And the real agent under a pin for a CA that did not issue it: refused.
    Exec::Registry::register_agent(hostname => 'wrong-pin', ip => '127.0.0.1',
        agent_ca => slurp("$B->{dir}/ca.crt"), agent_ca_fpr => $B->{ca_fpr},
        registry_dir => $B->{config}{registry_dir});
    $r = ping_from($B, 'wrong-pin');
    is $r->{status}, 'error', 'the real agent under a pin for another CA is refused';
    kill 'TERM', $pid;
    waitpid $pid, 0;
};

# --- 4. renewal stays with A and keeps B working ------------------------------

subtest 'B does not renew a pinned agent' => sub {
    # cert_days of 100000 makes any certificate past half-life: renewal "due".
    my $r = ping_from($B, $NAME, "127.0.0.1:$PORT", cert_days => 100000);
    is $r->{status}, 'ok', 'B pings' or diag explain $r;
    ok !-f "$AD/agent.crt.staged", 'and stages no renewal';
};

subtest 'renewal by A keeps B working' => sub {
    my $old = Exec::CertInfo::serial_from_path("$AD/agent.crt");
    my $err = bounded(sub { quiet(sub { Exec::Engine::_renew_one(host => '127.0.0.1',
        port => $PORT, name => $NAME, config => $A->{config}, reqid => 'r1') }) });
    ok !$err, 'A renewed' or diag $err;
    ok -f "$AD/agent.crt.staged", 'renewed certificate staged';
    agent_stop();
    my $p = Exec::Agent::AgentPairing::promote_staged_cert(staged_path => "$AD/agent.crt.staged",
        cert_path => "$AD/agent.crt", ca_path => "$AD/ca.crt", key_path => "$AD/agent.key");
    ok $p->{promoted}, 'promoted at the agent start' or diag $p->{error};
    my $new = Exec::CertInfo::serial_from_path("$AD/agent.crt");
    isnt $new, $old, 'new certificate';
    ok agent_start(), 'agent restarted';
    is run_from($A)->{exit}, 0, 'A runs';
    is run_from($B)->{exit}, 0, 'B runs: it pins the CA, not the certificate';
};

# --- 5. re-pairing with the issuing dispatcher pins nothing --------------------

subtest 'keep-form re-pair with A itself: an ordinary agent of A' => sub {
    my $k = Exec::Agent::AgentPairing::kept_identity(cert_dir => $AD);
    my $csr = Exec::Agent::AgentPairing::generate_csr_only(
        hostname => $NAME, key_path => $k->{key_path})->{csr_pem};
    my $p = pair_with($A, csr => $csr, kept => $k);
    ok $p->{res}{ok}, 'approved';
    like $p->{approve_out}, qr/this dispatcher's own CA/, 'approve says so';
    my $rec = Exec::Registry::get_agent(hostname => $NAME,
        registry_dir => $A->{config}{registry_dir});
    ok !exists $rec->{agent_ca}, 'no pin, so A keeps renewing it';
};

agent_stop();

# --- 6. checks on each side -----------------------------------------------------

subtest 'dispatcher: check_kept_cert' => sub {
    my $k   = Exec::Agent::AgentPairing::kept_identity(cert_dir => $AD);
    my $csr = Exec::Agent::AgentPairing::generate_csr_only(
        hostname => $NAME, key_path => $k->{key_path})->{csr_pem};
    my $ok = Exec::Pairing::check_kept_cert($csr, $k->{cert_pem}, $k->{ca_pem});
    ok $ok->{ok}, 'the real identity passes' or diag $ok->{error};
    is $ok->{ca_fpr}, $A->{ca_fpr}, 'CA fingerprint';

    my $other = Exec::Agent::AgentPairing::generate_key_and_csr(hostname => 'x', bits => 2048);
    my $r = Exec::Pairing::check_kept_cert($other->{csr_pem}, $k->{cert_pem}, $k->{ca_pem});
    like $r->{error}, qr/not the CSR's key/, 'a certificate without the CSR key is refused';
    $r = Exec::Pairing::check_kept_cert($csr, $k->{cert_pem}, slurp("$B->{dir}/ca.crt"));
    like $r->{error}, qr/does not verify against its CA/, 'a CA that did not issue it is refused';
    $r = Exec::Pairing::check_kept_cert($csr, "junk\n$k->{cert_pem}", $k->{ca_pem});
    like $r->{error}, qr/not exactly one PEM/, 'extra text around the certificate is refused';
    $r = Exec::Pairing::check_kept_cert($csr, $k->{cert_pem}, $k->{ca_pem} . $k->{ca_pem});
    like $r->{error}, qr/not exactly one PEM/, 'two CAs are refused';
    $r = Exec::Pairing::check_kept_cert($csr, $k->{cert_pem}, undef);
    ok !$r->{ok}, 'a missing CA is refused';
};

subtest 'agent: the delivered CA must be the verified one' => sub {
    my $pa = slurp("$A->{dir}/ca.crt");
    my $pb = slurp("$B->{dir}/ca.crt");
    is Exec::Agent::AgentPairing::check_delivered_ca($pb, $B->{ca_fpr}), undef, 'match';
    like Exec::Agent::AgentPairing::check_delivered_ca($pa, $B->{ca_fpr}),
        qr/not the expected CA.*delivered:   SHA256:$A->{ca_fpr}/s, 'another CA is refused';
    like Exec::Agent::AgentPairing::check_delivered_ca($pb . $pa, $B->{ca_fpr}),
        qr/not the expected CA/, 'an extra CA is refused';
    like Exec::Agent::AgentPairing::check_delivered_ca('', $B->{ca_fpr}),
        qr/delivered:   none/, 'none is refused';
};

subtest 'agent: a dispatcher before 0.14 makes it withdraw' => sub {
    # A listener that answers as a 0.13 dispatcher: pending, with no cert_mode.
    require IO::Socket::SSL;
    my $l = IO::Socket::SSL->new(LocalAddr => '127.0.0.1', LocalPort => 0, Listen => 1,
        SSL_cert_file => $B->{config}{cert}, SSL_key_file => $B->{config}{key})
        or die "listener: $IO::Socket::SSL::SSL_ERROR";
    my $port = $l->sockport;
    my $pid = guarded_fork() // die;
    if ($pid == 0) {
        alarm $STEP;
        my $c = $l->accept or POSIX::_exit(1);
        my $raw = '';
        while (my $line = <$c>) { $raw .= $line; last if $raw =~ /\r\n\r\n/ }
        my ($n) = $raw =~ /Content-Length:\s*(\d+)/i;
        my $body = '';
        read $c, $body, $n;
        my $ack = encode_json({ status => 'pending', reqid => 'abcd1234', code_version => 2 });
        print $c "HTTP/1.0 200 OK\r\nContent-Length: " . length($ack) . "\r\n\r\n$ack";
        sleep 2;
        POSIX::_exit(0);
    }
    close $l;
    my $k   = Exec::Agent::AgentPairing::kept_identity(cert_dir => $AD);
    my $csr = Exec::Agent::AgentPairing::generate_csr_only(
        hostname => $NAME, key_path => $k->{key_path})->{csr_pem};
    my $sub;
    my $err = bounded(sub { $sub = Exec::Agent::AgentPairing::submit_pairing_request(
        'ctrl-exec' => '127.0.0.1', port => $port, timeout => 10, csr_pem => $csr,
        hostname => $NAME, agent_cert => $k->{cert_pem}, agent_ca => $k->{ca_pem}) });
    stop_pid($pid);
    ok !$err, 'exchange completed' or diag $err;
    ok !$sub->{ok}, 'not paired';
    ok $sub->{keep_unsupported}, 'as a dispatcher that does not keep the certificate';
    like $sub->{error}, qr/older than 0\.14/, 'and says why';
};

done_testing;
