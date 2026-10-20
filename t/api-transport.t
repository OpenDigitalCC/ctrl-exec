#!/usr/bin/perl
# t/api-transport.t  (T-013 piece 6)
#
# The API's listeners: a unix socket (mode 0660, configurable group, stale-file
# handling, the caller recorded as the socket with its peer uid), an optional
# TLS TCP listener with an operator-provided certificate, both at once, and the
# start-up refusals for a configuration that names no listener or a bad
# combination. Real servers are started from Exec::API::run in a child process.

use strict;
use warnings;
use feature qw(signatures);
no warnings qw(experimental::signatures);
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/../lib";
use lib "$Bin/lib";
use File::Temp qw(tempdir);
use IO::Socket::INET ();
use IO::Socket::UNIX ();
use Socket qw(SOCK_STREAM);
use POSIX qw(WNOHANG);
use Time::HiRes qw(sleep);
use JSON::PP qw(decode_json);
use Errno qw(EACCES);

use Exec::API qw();

my $tmp = tempdir(CLEANUP => 1);
my %LIVE;
END { kill 'TERM', keys %LIVE if %LIVE; }

sub slurp ($p) { open my $fh, '<', $p or return ''; local $/; scalar <$fh> // '' }
sub spew ($p, $c) { open my $fh, '>', $p or die "$p: $!"; print $fh $c; close $fh; $p }

sub free_port {
    my $s = IO::Socket::INET->new(LocalAddr => '127.0.0.1', LocalPort => 0, Listen => 1)
        or die "no free port: $!";
    my $p = $s->sockport;
    close $s;
    return $p;
}

my $n = 0;
# Start Exec::API::run with %conf in a child; stdout/stderr go to files.
sub start_api (%conf) {
    my $id  = ++$n;
    my $out = "$tmp/api-$id.out";
    my $err = "$tmp/api-$id.err";
    my $pid = fork // die "fork: $!";
    if (!$pid) {
        open STDOUT, '>', $out or die;
        open STDERR, '>', $err or die;
        STDOUT->autoflush(0);    # as under a supervisor: the server must flush
        Exec::API::run(config => {
            cert => 'x', key => 'x', ca => 'x', api_auth_default => 'allow', %conf,
        });
        exit 0;
    }
    $LIVE{$pid} = 1;
    return { pid => $pid, out => $out, err => $err };
}

# Wait until the API says it is listening on everything it will (or exits).
sub wait_ready ($api, $lines = 1) {
    for (1 .. 100) {
        my @l = grep { /listening on/ } split /\n/, slurp($api->{out});
        return 1 if @l >= $lines;
        if (waitpid($api->{pid}, WNOHANG) == $api->{pid}) {
            delete $LIVE{ $api->{pid} };
            $api->{exit} = $? >> 8;
            return 0;
        }
        sleep 0.05;
    }
    return 0;
}

# The child's exit status and stderr when start-up is expected to fail.
sub wait_exit ($api) {
    for (1 .. 100) {
        if (waitpid($api->{pid}, WNOHANG) == $api->{pid}) {
            delete $LIVE{ $api->{pid} };
            return ($? >> 8, slurp($api->{err}));
        }
        sleep 0.05;
    }
    stop($api);
    return (undef, slurp($api->{err}));
}

sub stop ($api) {
    return unless $LIVE{ $api->{pid} };
    kill 'TERM', $api->{pid};
    waitpid $api->{pid}, 0;
    delete $LIVE{ $api->{pid} };
}

# One HTTP/1.0 GET over an already-connected socket; returns (status, body).
sub http_get ($sock, $path = '/health') {
    print $sock "GET $path HTTP/1.0\r\nHost: x\r\n\r\n";
    local $/;
    my $resp = <$sock> // '';
    my ($status) = $resp =~ m{^HTTP/1\.\d (\d+)};
    my (undef, $body) = split /\r\n\r\n/, $resp, 2;
    return ($status // 0, $body // '');
}

sub unix_get ($path, $url = '/health') {
    my $s = IO::Socket::UNIX->new(Peer => $path, Type => SOCK_STREAM) or return (0, "$!");
    return http_get($s, $url);
}

sub tcp_get ($port, $url = '/health') {
    my $s = IO::Socket::INET->new(PeerAddr => '127.0.0.1', PeerPort => $port) or return (0, "$!");
    return http_get($s, $url);
}

# ---------------------------------------------------------------------------
# listen_plan: which listeners, and the refusals (no binding)
# ---------------------------------------------------------------------------

my $cert_dummy = spew("$tmp/dummy.crt", "x");
my $key_dummy  = spew("$tmp/dummy.key", "x");
my ($primary_gid) = split ' ', $(;
my ($other_gid) = grep { $_ != $primary_gid } split ' ', $);

subtest 'listen_plan' => sub {
    my $p = Exec::API::listen_plan({});
    ok($p->{ok}, 'nothing set: accepted');
    is_deeply($p->{tcp}, { bind => '127.0.0.1', port => 7445, tls => undef },
        'nothing set: TCP on 127.0.0.1:7445 as before');
    is($p->{socket}, undef, 'nothing set: no socket');

    $p = Exec::API::listen_plan({ api_socket => '/run/x/api.sock', api_port => 'off' });
    ok($p->{ok} && !$p->{tcp} && $p->{socket}{path} eq '/run/x/api.sock',
        'socket only (api_port = off)');

    $p = Exec::API::listen_plan({ api_socket => '/run/x/api.sock' });
    ok($p->{ok} && $p->{tcp} && $p->{socket}, 'socket and TCP together');

    $p = Exec::API::listen_plan({ api_cert => $cert_dummy, api_key => $key_dummy });
    ok(!$p->{ok}, 'TLS files that are not a certificate and key: refused');
    like($p->{error} // '', qr/Cannot load API TLS certificate\/key/, '  with a clear reason');

    my @bad = (
        [ { api_port => 'off' },                          qr/no API listener configured/ ],
        [ { api_port => '0' },                            qr/api_port must be a port number/ ],
        [ { api_port => '70000' },                        qr/api_port must be a port number/ ],
        [ { api_port => '7445 # comment' },               qr/api_port must be a port number/ ],
        [ { api_socket => 'relative.sock' },              qr/must be an absolute path/ ],
        [ { api_socket => '/run/x/' },                    qr/must be an absolute path/ ],
        [ { api_socket => '/' . ('a' x 120) },            qr/too long/ ],
        [ { api_socket_group => 'users' },                qr/api_socket_group is set but api_socket is not/ ],
        [ { api_socket => '/run/x.sock', api_socket_group => 'no-such-group-t013' },
                                                          qr/not a known group/ ],
        [ { api_cert => $cert_dummy },                    qr/must be set together/ ],
        [ { api_key  => $key_dummy },                     qr/must be set together/ ],
        [ { api_cert => "$tmp/missing.crt", api_key => $key_dummy }, qr/api_cert .* not a readable file/ ],
        [ { api_cert => $cert_dummy, api_key => "$tmp/missing.key" }, qr/api_key .* not a readable file/ ],
        [ { api_socket => '/run/x.sock', api_port => 'off',
            api_cert => $cert_dummy, api_key => $key_dummy }, qr/api_port = off/ ],
    );
    for my $b (@bad) {
        my ($conf, $re) = @$b;
        my $r = Exec::API::listen_plan($conf);
        ok(!$r->{ok}, 'refused: ' . join(', ', map { "$_=$conf->{$_}" } sort keys %$conf));
        like($r->{error} // '', $re, '  with a clear reason');
    }
};

# ---------------------------------------------------------------------------
# The unix socket
# ---------------------------------------------------------------------------

subtest 'socket: mode 0660, configured group, caller recorded as the socket' => sub {
    plan skip_all => 'needs a supplementary group to test api_socket_group'
        unless defined $other_gid;
    my $sock = "$tmp/api-a.sock";
    my $hook = spew("$tmp/hook.sh",
        "#!/bin/sh\nenv > '$tmp/hook.env'\ncat > '$tmp/hook.json'\nexit 0\n");
    chmod 0755, $hook;

    my $api = start_api(api_socket => $sock, api_socket_group => $other_gid,
                        api_port => 'off', auth_hook => $hook);
    ok(wait_ready($api), 'API started on the socket') or diag slurp($api->{err});

    my @st = stat $sock;
    ok(-S $sock, 'socket file exists');
    is(sprintf('%04o', $st[2] & 07777), '0660', 'mode 0660');
    is($st[5], $other_gid, "group is api_socket_group ($other_gid)");

    my ($code, $body) = unix_get($sock);
    is($code, 200, 'GET /health over the socket');
    like($body, qr/"ok"\s*:\s*true/, 'health body');

    my %env = map { /^(ENVEXEC_\w+)=(.*)$/ ? ($1 => $2) : () } split /\n/, slurp("$tmp/hook.env");
    is($env{ENVEXEC_SOURCE_IP}, "unix:$sock", 'hook: caller recorded as the socket');
    is($env{ENVEXEC_PEER_UID}, $<, 'hook: ENVEXEC_PEER_UID is the caller uid (SO_PEERCRED)');
    my $ctx = eval { decode_json(slurp("$tmp/hook.json")) } // {};
    is($ctx->{peer_uid}, $<, 'hook stdin: peer_uid');
    is($ctx->{source_ip}, "unix:$sock", 'hook stdin: source_ip');

    like(slurp($api->{err}), qr/ACTION=api-request .*PEER=unix:\Q$sock\E UID=$</,
        'request log line names the socket and uid');

    # Permissions decide who may call. Without root another user cannot be
    # tried, so take the permission away from this one: connect is refused.
    SKIP: {
        skip 'root ignores file permissions', 2 if $< == 0;
        chmod 0, $sock;
        my $c = IO::Socket::UNIX->new(Peer => $sock, Type => SOCK_STREAM);
        my $errno = $! + 0;
        ok(!$c, 'a caller without permission on the socket cannot connect');
        is($errno, EACCES, '  EACCES');
        chmod 0660, $sock;
    }

    stop($api);
    ok(!-e $sock, 'socket file removed on a clean stop');
};

subtest 'socket: default group is the server\'s own' => sub {
    my $sock = "$tmp/api-b.sock";
    my $api  = start_api(api_socket => $sock, api_port => 'off');
    ok(wait_ready($api), 'started') or diag slurp($api->{err});
    is((stat $sock)[5], $primary_gid, 'group is the process group');
    is(sprintf('%04o', (stat $sock)[2] & 07777), '0660', 'mode 0660');
    stop($api);
};

subtest 'socket: a TCP caller has no peer uid' => sub {
    my $port = free_port();
    my $hook = spew("$tmp/hook2.sh", "#!/bin/sh\nenv > '$tmp/hook2.env'\nexit 0\n");
    chmod 0755, $hook;
    my $api = start_api(api_port => $port, auth_hook => $hook);
    ok(wait_ready($api), 'started') or diag slurp($api->{err});
    my ($code) = tcp_get($port);
    is($code, 200, 'GET /health over TCP');
    my %env = map { /^(ENVEXEC_\w+)=(.*)$/ ? ($1 => $2) : () } split /\n/, slurp("$tmp/hook2.env");
    is($env{ENVEXEC_SOURCE_IP}, '127.0.0.1', 'source ip');
    is($env{ENVEXEC_PEER_UID}, '', 'ENVEXEC_PEER_UID empty');
    stop($api);
};

subtest 'stale socket file: replaced' => sub {
    my $sock = "$tmp/stale.sock";
    {
        my $s = IO::Socket::UNIX->new(Local => $sock, Type => SOCK_STREAM, Listen => 1) or die $!;
        close $s;    # the file stays, nothing listens: what a crash leaves
    }
    ok(-S $sock, 'stale socket file present');
    my $api = start_api(api_socket => $sock, api_port => 'off');
    ok(wait_ready($api), 'API started over a stale socket') or diag slurp($api->{err});
    is((unix_get($sock))[0], 200, 'and answers on it');
    like(slurp($api->{err}), qr/stale-socket-removed/, 'removal logged');
    stop($api);
};

subtest 'socket path that is not a socket: never removed' => sub {
    my $file = spew("$tmp/plain-file", "keep me\n");
    my ($rc, $err) = wait_exit(start_api(api_socket => $file, api_port => 'off'));
    isnt($rc, 0, 'regular file: start-up refused');
    like($err, qr/exists and is not a socket; not removing it/, '  clear error');
    is(slurp($file), "keep me\n", '  file untouched');

    mkdir "$tmp/a-dir";
    ($rc, $err) = wait_exit(start_api(api_socket => "$tmp/a-dir", api_port => 'off'));
    isnt($rc, 0, 'directory: refused');
    ok(-d "$tmp/a-dir", '  directory untouched');

    # A symlink is not followed, even to a stale socket it could replace.
    my $target = "$tmp/target.sock";
    { my $s = IO::Socket::UNIX->new(Local => $target, Type => SOCK_STREAM, Listen => 1) or die $!; close $s; }
    symlink $target, "$tmp/link.sock" or die $!;
    ($rc, $err) = wait_exit(start_api(api_socket => "$tmp/link.sock", api_port => 'off'));
    isnt($rc, 0, 'symlink to a socket: refused');
    like($err, qr/not a socket/, '  clear error');
    ok(-l "$tmp/link.sock", '  symlink untouched');
    ok(-S $target, '  its target untouched');
};

subtest 'socket in use by a running server: refused, left alone' => sub {
    my $sock = "$tmp/live.sock";
    my $holder = IO::Socket::UNIX->new(Local => $sock, Type => SOCK_STREAM, Listen => 5) or die $!;
    my ($rc, $err) = wait_exit(start_api(api_socket => $sock, api_port => 'off'));
    isnt($rc, 0, 'start-up refused');
    like($err, qr/is in use by another process/, '  clear error');
    ok(-S $sock, '  live socket untouched');
    close $holder;
};

# ---------------------------------------------------------------------------
# TLS with an operator-provided certificate (a test CA made here)
# ---------------------------------------------------------------------------

SKIP: {
    skip 'openssl not available', 1 unless system('openssl version >/dev/null 2>&1') == 0;
    eval { require IO::Socket::SSL; 1 } or skip 'IO::Socket::SSL not available', 1;

    my $d = "$tmp/pki";
    mkdir $d;
    my $sh = sub ($cmd) { system("$cmd 2>/dev/null") == 0 or die "failed: $cmd" };
    for my $ca (qw(ca rogue)) {
        $sh->("openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes "
            . "-keyout $d/$ca.key -out $d/$ca.crt -subj /CN=test-$ca -days 2");
    }
    spew("$d/api.ext", "subjectAltName=IP:127.0.0.1,DNS:localhost\nextendedKeyUsage=serverAuth\n");
    $sh->("openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes "
        . "-keyout $d/api.key -out $d/api.csr -subj /CN=localhost");
    $sh->("openssl x509 -req -in $d/api.csr -CA $d/ca.crt -CAkey $d/ca.key -set_serial 7 "
        . "-out $d/api.crt -days 2 -extfile $d/api.ext");

    my $tls_get = sub ($port, $ca) {
        my $s = IO::Socket::SSL->new(
            PeerAddr            => '127.0.0.1',
            PeerPort            => $port,
            SSL_ca_file         => $ca,
            SSL_verify_mode     => IO::Socket::SSL::SSL_VERIFY_PEER(),
            SSL_verifycn_scheme => 'http',
            SSL_verifycn_name   => '127.0.0.1',
        ) or return (0, $IO::Socket::SSL::SSL_ERROR);
        return http_get($s);
    };

    subtest 'TLS round trip, verified against the test CA' => sub {
        my $port = free_port();
        my $p = Exec::API::listen_plan({ api_port => $port,
            api_cert => "$d/api.crt", api_key => "$d/api.key" });
        is_deeply($p->{tcp}{tls}, { cert => "$d/api.crt", key => "$d/api.key" },
            'listen_plan: TLS pair accepted');
        my $api  = start_api(api_port => $port, api_cert => "$d/api.crt", api_key => "$d/api.key");
        ok(wait_ready($api), 'TLS API started') or diag slurp($api->{err});
        like(slurp($api->{out}), qr/127\.0\.0\.1:$port \(TLS\)/, 'reports TLS');

        my ($code, $body) = $tls_get->($port, "$d/ca.crt");
        is($code, 200, 'GET /health over verified TLS');
        like($body, qr/"ok"\s*:\s*true/, 'body');

        ($code, $body) = $tls_get->($port, "$d/rogue.crt");
        is($code, 0, 'a client trusting another CA refuses the server');

        my ($plain) = tcp_get($port);
        is($plain, 0, 'plain HTTP to the TLS listener gets no HTTP response');

        # The listener still serves after a failed handshake (it happened in a child).
        ($code) = $tls_get->($port, "$d/ca.crt");
        is($code, 200, 'still serving after bad clients');
        like(slurp($api->{err}), qr/ACTION=api-tls .*RESULT=handshake-failed/,
            'failed handshake logged');
        stop($api);
    };

    subtest 'socket and TLS listeners together' => sub {
        my $port = free_port();
        my $sock = "$tmp/both.sock";
        my $api  = start_api(api_socket => $sock, api_port => $port,
                             api_cert => "$d/api.crt", api_key => "$d/api.key");
        ok(wait_ready($api, 2), 'both listeners up') or diag slurp($api->{err});
        is((unix_get($sock))[0], 200, 'socket answers');
        is(($tls_get->($port, "$d/ca.crt"))[0], 200, 'TLS answers');
        stop($api);
        ok(!-e $sock, 'socket removed on stop');
    };

    subtest 'a certificate that does not load stops start-up' => sub {
        my $port = free_port();
        my ($rc, $err) = wait_exit(start_api(api_port => $port,
            api_cert => "$d/api.crt", api_key => "$d/rogue.key"));
        isnt($rc, 0, 'mismatched key: refused');
        like($err, qr/Cannot load API TLS certificate\/key/, '  clear error');

        my $conf = spew("$tmp/badtls.conf", "cert = x\nkey = x\nca = x\n"
            . "api_port = $port\napi_cert = $d/api.crt\napi_key = $d/rogue.key\n");
        my $out = `'$^X' -I'$Bin/../lib' -I'$Bin/lib' -MNoSyslog '$Bin/../bin/ctrl-exec-api' --config '$conf' 2>&1`;
        is($? >> 8, 78, 'bin/ctrl-exec-api: exit 78');
        like($out, qr/Cannot load API TLS certificate\/key/, '  names the problem');
    };
}

# ---------------------------------------------------------------------------
# bin/ctrl-exec-api refuses a bad listener configuration with exit 78
# ---------------------------------------------------------------------------

subtest 'bin/ctrl-exec-api: bad combination exits 78 (EX_CONFIG)' => sub {
    my $conf = spew("$tmp/bad.conf",
        "cert = x\nkey = x\nca = x\napi_port = off\napi_auth_default = allow\n");
    my $out = `'$^X' -I'$Bin/../lib' -I'$Bin/lib' -MNoSyslog '$Bin/../bin/ctrl-exec-api' --config '$conf' 2>&1`;
    is($? >> 8, 78, 'exit 78');
    like($out, qr/no API listener configured: set api_socket, or remove api_port = off/,
        'names the problem');

    $conf = spew("$tmp/bad2.conf",
        "cert = x\nkey = x\nca = x\napi_cert = $cert_dummy\n");
    $out = `'$^X' -I'$Bin/../lib' -I'$Bin/lib' -MNoSyslog '$Bin/../bin/ctrl-exec-api' --config '$conf' 2>&1`;
    is($? >> 8, 78, 'half a TLS pair: exit 78');
    like($out, qr/api_cert and api_key must be set together/, 'names the problem');
};

done_testing;
