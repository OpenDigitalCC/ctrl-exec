package AgentRig;
# A throwaway real agent for the serve-loop tests: its own CA, agent cert,
# trusted and untrusted client certs, a rogue CA, and an agent process started
# from bin/ctrl-exec-agent on a loopback port. The agent's stderr (where
# Exec::Log writes when syslog is not open) is captured so tests can read the
# log. Needs openssl; callers skip when rig() returns undef.

use strict;
use warnings;
use File::Temp qw(tempdir);
use FindBin    qw($Bin);
use IO::Socket::INET;
use IO::Socket::SSL;
use POSIX      qw(WNOHANG);
use Time::HiRes qw(sleep time);

# Agents are started with ChildGuard, so a test that dies leaves none behind.
use ChildGuard ();

sub available { return system('openssl version >/dev/null 2>&1') == 0 }

sub _sh {
    my @cmd = @_;
    system(@cmd) == 0 or die "failed: @cmd\n";
}

sub _free_port {
    my $s = IO::Socket::INET->new(LocalAddr => '127.0.0.1', LocalPort => 0, Listen => 1)
        or die "no free port: $!";
    my $p = $s->sockport;
    close $s;
    return $p;
}

sub _slurp {
    my ($p) = @_;
    open my $fh, '<', $p or return '';
    local $/;
    return scalar <$fh>;
}

sub _make_ca {
    my ($dir, $name, $cn) = @_;
    $cn //= $name;
    _sh("openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes "
      . "-keyout $dir/$name.key -out $dir/$name.crt -subj /CN=$cn -days 2 2>/dev/null");
}

# SHA-256 fingerprint of a cert file: 64 lowercase hex characters.
sub fingerprint {
    my ($path) = @_;
    my $out = `openssl x509 -noout -fingerprint -sha256 -in $path 2>/dev/null`;
    $out =~ /=\s*([0-9A-Fa-f:]+)/ or die "no fingerprint for $path\n";
    (my $f = lc $1) =~ s/://g;
    return $f;
}

sub _make_leaf {
    my ($dir, $ca, $name, $serial) = @_;
    open my $x, '>', "$dir/$name.ext" or die;
    print $x "subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth,clientAuth\n";
    close $x;
    _sh("openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes "
      . "-keyout $dir/$name.key -out $dir/$name.csr -subj /CN=$name 2>/dev/null");
    _sh("openssl x509 -req -in $dir/$name.csr -CA $dir/$ca.crt -CAkey $dir/$ca.key "
      . "-set_serial $serial -out $dir/$name.crt -days 2 -extfile $dir/$name.ext 2>/dev/null");
}

# new(extra_conf => "key = value\n...", allowlist => "name = /path\n",
#     second_ca => 1)
#
# second_ca: the agent's CA file is a bundle of 'ca' and 'ca2' (a second
# dispatcher CA with the SAME subject name as 'ca', as two CAs made with the
# defaults have), 'd2' is a dispatcher certificate from ca2 (serial 2002, in
# the map as d2), and 'evil' is a ca2 certificate carrying the serial of
# 'trusted' (1002). The map is written in the issuer-keyed form.
sub new {
    my ($class, %o) = @_;
    my $dir = ChildGuard::dir(tempdir(CLEANUP => 1));
    _make_ca($dir, 'ca');
    _make_ca($dir, 'rogue-ca');
    _make_leaf($dir, 'ca', 'agent',     1001);
    _make_leaf($dir, 'ca', 'trusted',   1002);   # in the trusted-dispatcher map
    _make_leaf($dir, 'ca', 'untrusted', 1003);   # CA-signed, not paired
    _make_leaf($dir, 'rogue-ca', 'rogue', 1004); # fails the agent's handshake

    my $ca_file = "$dir/ca.crt";
    open my $t, '>', "$dir/dispatchers" or die;
    if ($o{second_ca}) {
        _make_ca($dir, 'ca2', 'ca');
        _make_leaf($dir, 'ca2', 'd2',   2002);
        _make_leaf($dir, 'ca2', 'evil', 1002);
        $ca_file = "$dir/bundle.crt";
        system("cat $dir/ca.crt $dir/ca2.crt > $ca_file") == 0 or die;
        my ($f1, $f2) = (fingerprint("$dir/ca.crt"), fingerprint("$dir/ca2.crt"));
        print $t "$f1 3ea test-dispatcher\n";     # 0x3ea == 1002
        print $t "$f2 7d2 d2\n";                  # 0x7d2 == 2002
    }
    else {
        print $t "3ea test-dispatcher\n";         # 0x3ea == 1002, pre-0.14 form
    }
    close $t;

    my $self = bless {
        dir => $dir, port => _free_port(), log => "$dir/agent.log",
        conf => "$dir/agent.conf", allow => "$dir/scripts.conf", pid => undef,
        ca_file => $ca_file,
    }, $class;
    $self->set_conf($o{extra_conf} // '');
    open my $a, '>', $self->{allow} or die;
    print $a $o{allowlist} // '';
    close $a;
    return $self;
}

# (Re)write agent.conf: the fixed rig keys, then $extra (top-level keys), then
# $profiles (sections).
sub set_conf {
    my ($self, $extra, $profiles) = @_;
    my $d = $self->{dir};
    $profiles //= "[profile default]\n";
    open my $c, '>', $self->{conf} or die;
    print $c <<"END";
port = $self->{port}
cert = $d/agent.crt
key  = $d/agent.key
ca   = $self->{ca_file}
trusted_dispatchers_path = $d/dispatchers
revoked_serials = $d/revoked
async_runs_dir = $d/runs
$extra
$profiles
END
    close $c;
}

sub start {
    my ($self) = @_;
    my $pid = ChildGuard::guarded_fork() // die "fork: $!";
    if ($pid == 0) {
        open STDERR, '>>', $self->{log} or die;
        open STDOUT, '>>', $self->{log} or die;
        exec $^X, "-I$Bin/../lib", "-I$Bin/lib", '-MNoSyslog', "$Bin/../bin/ctrl-exec-agent",
            '--config', $self->{conf}, '--allowlist', $self->{allow}, 'serve'
            or die "exec: $!";
    }
    $self->{pid} = $pid;
    my $deadline = time + 15;
    while (time < $deadline) {
        my $s = IO::Socket::INET->new(PeerAddr => '127.0.0.1', PeerPort => $self->{port});
        if ($s) { close $s; return 1 }
        return 0 if waitpid($pid, WNOHANG) > 0;
        sleep 0.1;
    }
    return 0;
}

sub hup { my ($self) = @_; kill 'HUP', $self->{pid}; }

sub stop {
    my ($self) = @_;
    return unless $self->{pid};
    kill 'TERM', $self->{pid};
    waitpid($self->{pid}, 0);
    $self->{pid} = undef;
}

sub alive { my ($self) = @_; return $self->{pid} && kill 0, $self->{pid} }

sub log_text { return _slurp($_[0]{log}) }

# Wait until the log matches $re (counting from byte offset $from); returns the
# matching text or undef after $secs.
sub wait_log {
    my ($self, $re, $secs, $from) = @_;
    my $deadline = time + ($secs // 5);
    while (time < $deadline) {
        my $t = substr($self->log_text, $from // 0);
        return $t if $t =~ $re;
        sleep 0.05;
    }
    return undef;
}

sub log_len { return length $_[0]->log_text }

# request(as => 'trusted'|'untrusted'|'rogue', from => '127.0.0.x')
# Returns the HTTP status code, or undef when the handshake or read failed
# (no HTTP reply: the agent dropped or rejected the connection).
sub request {
    my ($self, %o) = @_;
    my $as = $o{as} // 'trusted';
    my $d  = $self->{dir};
    local $SIG{PIPE} = 'IGNORE';   # the agent may close on us mid-write
    my $c = IO::Socket::SSL->new(
        PeerAddr        => '127.0.0.1',
        PeerPort        => $self->{port},
        ($o{from} ? (LocalAddr => $o{from}) : ()),
        SSL_cert_file   => "$d/$as.crt",
        SSL_key_file    => "$d/$as.key",
        SSL_ca_file     => "$d/ca.crt",
        SSL_verify_mode => SSL_VERIFY_NONE,
        Timeout         => 15,
    ) or return undef;
    my $body = '{}';
    print $c "POST /ping HTTP/1.0\r\nContent-Length: " . length($body) . "\r\n\r\n$body";
    my $line = <$c>;
    close $c;
    return undef unless defined $line && $line =~ m{^HTTP/\S+\s+(\d+)};
    return $1 + 0;
}

# call($method, $path, $body, as => ...): one request as a dispatcher.
# Returns (status, response body), or () when there was no HTTP reply.
sub call {
    my ($self, $method, $path, $body, %o) = @_;
    my $as = $o{as} // 'trusted';
    my $d  = $self->{dir};
    local $SIG{PIPE} = 'IGNORE';
    my $c = IO::Socket::SSL->new(
        PeerAddr        => '127.0.0.1',
        PeerPort        => $self->{port},
        SSL_cert_file   => "$d/$as.crt",
        SSL_key_file    => "$d/$as.key",
        SSL_ca_file     => "$d/ca.crt",
        SSL_verify_mode => SSL_VERIFY_NONE,
        Timeout         => 15,
    ) or return;
    $body //= '';
    print $c "$method $path HTTP/1.0\r\nContent-Length: " . length($body) . "\r\n\r\n$body";
    local $/;
    my $resp = <$c> // '';
    close $c;
    return unless $resp =~ m{^HTTP/\S+\s+(\d+)};
    my $status = $1 + 0;
    $resp =~ s/\A.*?\r\n\r\n//s;
    return ($status, $resp);
}

# A TCP connection that never speaks TLS, held open; returns the socket.
sub silent_connect {
    my ($self, %o) = @_;
    return IO::Socket::INET->new(
        PeerAddr => '127.0.0.1', PeerPort => $self->{port},
        ($o{from} ? (LocalAddr => $o{from}) : ()),
    );
}

sub DESTROY { $_[0]->stop }

1;
