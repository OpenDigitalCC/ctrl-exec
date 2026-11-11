#!/usr/bin/perl
# t/api-body-read.t  (T-089)
#
# The API reads the whole request body (R-034): a ~100 KB POST /run over its
# unix socket and over its TLS listener reaches dispatch intact, and a body
# that ends before Content-Length is answered 400 and never dispatched.
# Exec::Engine::dispatch_all is stubbed to record the input it was given.

use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/../lib", "$Bin/lib";
use File::Temp qw(tempdir);
use IO::Socket::SSL;
use IO::Socket::UNIX ();
use IO::Socket::INET ();
use Socket qw(SOCK_STREAM);
use JSON::PP qw(encode_json);
use Digest::MD5 qw(md5_hex);

require AgentRig;
require ChildGuard;
plan skip_all => 'openssl not available' unless AgentRig::available();

use Exec::API qw();

my $r = tempdir('cexXXXX', TMPDIR => 1, CLEANUP => 1);
ChildGuard::dir($r);
AgentRig::_make_ca($r, 'ca');
AgentRig::_make_leaf($r, 'ca', 'srv', 21);
my $sock = "$r/api.sock";
my $port = do { my $s = IO::Socket::INET->new(LocalAddr => '127.0.0.1', LocalPort => 0, Listen => 1); my $p = $s->sockport; close $s; $p };

sub slurp { open my $f, '<', $_[0] or return ''; local $/; scalar <$f> }

my $pid = ChildGuard::guarded_fork() // die "fork: $!";
if ($pid == 0) {
    open STDOUT, '>', '/dev/null';
    {
        no warnings 'redefine';
        *Exec::Log::log_action = sub { 1 };
        *Exec::RunStore::record_sync = sub { 1 };
        *Exec::Lock::check_available = sub { { ok => 1 } };
        *Exec::Registry::resolve_dispatch = sub { { ok => 1, hosts => $_[0] } };
        *Exec::Engine::dispatch_all = sub {
            my (%o) = @_;
            open my $fh, '>>', "$r/dispatched" or die;
            print $fh length($o{input}{blob}), ' ', md5_hex($o{input}{blob}), "\n";
            close $fh;
            return [ { host => 'agent-01', exit => 0, rtt => '1ms', reqid => 'r', stdout => '', stderr => '' } ];
        };
    }
    Exec::API::run(config => {
        api_socket => $sock, api_port => $port, api_bind => '127.0.0.1',
        api_tls_cert => "$r/srv.crt", api_tls_key => "$r/srv.key",
        api_auth_default => 'allow', cert => 'x', key => 'x', ca => 'x',
    });
    exit 0;
}
for (1 .. 100) { last if -S $sock; select undef, undef, undef, 0.1 }
plan skip_all => 'fixture API did not start' unless -S $sock;
select undef, undef, undef, 0.3;

my $blob = join '', map { chr(97 + ($_ * 7) % 26) } 0 .. 99_999;
my $req  = encode_json({ hosts => ['agent-01'], script => 'ingest', input => { blob => $blob } });

sub conn { $_[0] eq 'unix'
    ? IO::Socket::UNIX->new(Peer => $sock, Type => SOCK_STREAM)
    : IO::Socket::SSL->new(PeerAddr => '127.0.0.1', PeerPort => $port, SSL_verify_mode => SSL_VERIFY_NONE) }

sub post {
    my ($kind, $body, $declared, $close_early) = @_;
    my $c = conn($kind) or die "connect $kind: " . ($SSL_ERROR // $!);
    print $c "POST /run HTTP/1.0\r\nContent-Length: $declared\r\n\r\n$body";
    if ($close_early) { CORE::shutdown($c, 1) }   # TCP half-close: the body ends here
    local $/;
    my $resp = <$c> // '';
    close $c;
    return $resp;
}

for my $kind (qw(unix tls)) {
    unlink "$r/dispatched";
    my $resp = post($kind, $req, length $req);
    like $resp, qr{^HTTP/1\.0 200 }, "$kind: a " . length($req) . "-byte body is accepted";
    is slurp("$r/dispatched"), length($blob) . ' ' . md5_hex($blob) . "\n", "$kind: dispatch got the input whole";

    unlink "$r/dispatched";
    $resp = post($kind, substr($req, 0, 40_000), length $req, 1);
    if ($kind eq 'unix') {
        like $resp, qr{^HTTP/1\.0 400 .*request body incomplete}s, "$kind: a body that ends early is a 400";
    } else {
        # OpenSSL treats an end without close_notify as a fatal error, so the
        # reply cannot be written back on that connection; the peer is gone.
        unlike $resp, qr{^HTTP/1\.0 200 }, "$kind: a body that ends early is not answered as a success";
    }
    ok !-e "$r/dispatched", "$kind: and nothing was dispatched";
}

kill 'TERM', $pid;
waitpid $pid, 0;
done_testing;
