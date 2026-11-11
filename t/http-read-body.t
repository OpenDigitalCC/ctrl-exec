#!/usr/bin/perl
# t/http-read-body.t  (T-089)
#
# Exec::Http::read_body reads a whole request body. One `read` on a TLS
# connection returns at most one TLS record (16 KiB), so a bigger body arrived
# cut short (R-034). Tested here over a real TLS socket pair (certificates from
# the AgentRig helpers), a unix socket, and a body that ends early.

use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/../lib", "$Bin/lib";
use File::Temp qw(tempdir);
use IO::Socket::SSL;
use IO::Socket::INET ();
use IO::Socket::UNIX ();
use Socket qw(SOCK_STREAM);
use Time::HiRes qw(time);

require AgentRig;
require ChildGuard;
plan skip_all => 'openssl not available' unless AgentRig::available();

use Exec::Http qw();

my $dir = ChildGuard::dir(tempdir(CLEANUP => 1));
AgentRig::_make_ca($dir, 'ca');
AgentRig::_make_leaf($dir, 'ca', 'srv', 11);

# Run $server_code->($conn) in a child for one connection; the child writes what
# it read to $out. Returns the pid.
sub serve {
    my ($listen, $out, $want, $idle) = @_;
    my $pid = ChildGuard::guarded_fork() // die "fork: $!";
    return $pid if $pid;
    $SIG{PIPE} = 'IGNORE';   # the peer has gone: a TLS reply to its close must not kill us
    my $c = $listen->accept or do { open my $f, '>', $out; print $f "accept failed: $SSL_ERROR $!\n"; exit 1 };
    my $line = <$c>;                       # the request line, as the servers do
    my $hdr  = <$c>;                       # "Content-Length: N"
    my $blank = <$c>;
    my $body = Exec::Http::read_body($c, $want, $idle);
    open my $fh, '>', $out or exit 2;
    print $fh defined $body ? "ok\n$body" : "short\n";
    close $fh;
    exit 0;
}

sub slurp { open my $f, '<', $_[0] or return ''; local $/; scalar <$f> }

my $big = join '', map { chr(65 + $_ % 26) } 0 .. 99_999;    # 100,000 bytes

subtest 'TLS: a 100 KB body arrives whole' => sub {
    my $l = IO::Socket::SSL->new(
        Listen => 1, LocalAddr => '127.0.0.1', LocalPort => 0,
        SSL_cert_file => "$dir/srv.crt", SSL_key_file => "$dir/srv.key",
        SSL_verify_mode => SSL_VERIFY_NONE) or die "listen: $SSL_ERROR";
    my $out = "$dir/tls.out";
    my $pid = serve($l, $out, length $big, 10);
    my $c = IO::Socket::SSL->new(PeerAddr => '127.0.0.1', PeerPort => $l->sockport,
        SSL_verify_mode => SSL_VERIFY_NONE) or die "connect: $SSL_ERROR";
    print $c "POST /run HTTP/1.0\r\nContent-Length: " . length($big) . "\r\n\r\n";
    print $c $big;
    waitpid $pid, 0;
    my $got = slurp($out);
    is substr($got, 0, 3), "ok\n", 'read_body returned a body';
    ok substr($got, 3) eq $big, 'every one of the 100,000 bytes arrived';
};

subtest 'unix socket: a 100 KB body arrives whole' => sub {
    my $path = "$dir/b.sock";
    my $l = IO::Socket::UNIX->new(Local => $path, Type => SOCK_STREAM, Listen => 1) or die $!;
    my $out = "$dir/unix.out";
    my $pid = serve($l, $out, length $big, 10);
    my $c = IO::Socket::UNIX->new(Peer => $path, Type => SOCK_STREAM) or die $!;
    print $c "POST /run HTTP/1.0\r\nContent-Length: " . length($big) . "\r\n\r\n";
    print $c $big;
    waitpid $pid, 0;
    my $got = slurp($out);
    ok substr($got, 0, 3) eq "ok\n" && substr($got, 3) eq $big, 'whole body';
};

subtest 'a body that ends early is refused, not returned short' => sub {
    for my $kind (qw(tls unix)) {
        my ($l, $c);
        if ($kind eq 'tls') {
            $l = IO::Socket::SSL->new(Listen => 1, LocalAddr => '127.0.0.1', LocalPort => 0,
                SSL_cert_file => "$dir/srv.crt", SSL_key_file => "$dir/srv.key",
                SSL_verify_mode => SSL_VERIFY_NONE) or die;
        } else {
            $l = IO::Socket::UNIX->new(Local => "$dir/s.sock", Type => SOCK_STREAM, Listen => 1) or die;
        }
        my $out = "$dir/short-$kind.out";
        my $pid = serve($l, $out, 50_000, 10);
        $c = $kind eq 'tls'
            ? IO::Socket::SSL->new(PeerAddr => '127.0.0.1', PeerPort => $l->sockport, SSL_verify_mode => SSL_VERIFY_NONE)
            : IO::Socket::UNIX->new(Peer => "$dir/s.sock", Type => SOCK_STREAM);
        print $c "POST /run HTTP/1.0\r\nContent-Length: 50000\r\n\r\n", 'x' x 20_000;
        $kind eq 'tls' ? $c->close : close $c;     # the peer goes away early
        waitpid $pid, 0;
        is slurp($out), "short\n", "$kind: undef, no truncated body" or diag "child status $?";
        unlink "$dir/s.sock";
    }
};

subtest 'a peer that stalls mid-body is bounded by the idle timeout' => sub {
    my $l = IO::Socket::UNIX->new(Local => "$dir/t.sock", Type => SOCK_STREAM, Listen => 1) or die;
    my $out = "$dir/stall.out";
    my $pid = serve($l, $out, 1000, 1);
    my $c = IO::Socket::UNIX->new(Peer => "$dir/t.sock", Type => SOCK_STREAM) or die;
    print $c "POST /run HTTP/1.0\r\nContent-Length: 1000\r\n\r\n", 'x' x 10;
    my $t0 = time;
    waitpid $pid, 0;                        # $c stays open: only the timeout ends it
    ok time - $t0 < 5, 'the read gave up after about the idle second';
    is slurp($out), "short\n", 'and refused the partial body';
};

subtest 'TLS: a peer that stalls mid-body is bounded too' => sub {
    my $l = IO::Socket::SSL->new(Listen => 1, LocalAddr => '127.0.0.1', LocalPort => 0,
        SSL_cert_file => "$dir/srv.crt", SSL_key_file => "$dir/srv.key",
        SSL_verify_mode => SSL_VERIFY_NONE) or die;
    my $out = "$dir/stall-tls.out";
    my $pid = serve($l, $out, 1000, 1);
    my $c = IO::Socket::SSL->new(PeerAddr => '127.0.0.1', PeerPort => $l->sockport,
        SSL_verify_mode => SSL_VERIFY_NONE) or die;
    print $c "POST /run HTTP/1.0\r\nContent-Length: 1000\r\n\r\n", 'x' x 10;
    my $t0 = time;
    waitpid $pid, 0;
    ok time - $t0 < 5, 'the read gave up after about the idle second';
    is slurp($out), "short\n", 'and refused the partial body';
};

done_testing;
