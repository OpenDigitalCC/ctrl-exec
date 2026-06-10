#!/usr/bin/perl
use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/../lib";

use Exec::Engine qw();

# --- parse_host ---

{
    my ($host, $port) = Exec::Engine::parse_host('myhost', 7443);
    is $host, 'myhost', 'parse_host: plain hostname';
    is $port, 7443,     'parse_host: plain hostname uses default port';
}

{
    my ($host, $port) = Exec::Engine::parse_host('myhost:9000', 7443);
    is $host, 'myhost', 'parse_host: host:port extracts host';
    is $port, 9000,     'parse_host: host:port extracts port';
}

{
    my ($host, $port) = Exec::Engine::parse_host('myhost', undef);
    is $port, 7443, 'parse_host: undef default_port falls back to 7443';
}

{
    my ($host, $port) = Exec::Engine::parse_host('192.168.1.1:8080', 7443);
    is $host, '192.168.1.1', 'parse_host: IP address with port';
    is $port, 8080,          'parse_host: IP address port extracted';
}

# --- gen_reqid ---

{
    my $id = Exec::Engine::gen_reqid();
    like $id, qr/^[0-9a-f]{16}$/, 'gen_reqid: 16 hex chars';
}

{
    my %seen;
    $seen{ Exec::Engine::gen_reqid() }++ for 1..20;
    ok scalar(keys %seen) > 1, 'gen_reqid: generates distinct values';
}

# --- dispatch_all argument validation ---

{
    eval { Exec::Engine::dispatch_all(script => 'x', config => {}) };
    like $@, qr/hosts required/, 'dispatch_all: dies without hosts';
}

{
    eval { Exec::Engine::dispatch_all(hosts => ['h'], config => {}) };
    like $@, qr/script required/, 'dispatch_all: dies without script';
}

{
    eval { Exec::Engine::dispatch_all(hosts => ['h'], script => 'x') };
    like $@, qr/config required/, 'dispatch_all: dies without config';
}

{
    eval { Exec::Engine::dispatch_all(hosts => 'not-an-array', script => 'x', config => {}) };
    like $@, qr/hosts must be an arrayref/, 'dispatch_all: dies if hosts not arrayref';
}

{
    eval { Exec::Engine::dispatch_all(hosts => ['h'], script => 'x', config => {}, args => 'bad') };
    like $@, qr/args must be an arrayref/, 'dispatch_all: dies if args not arrayref';
}

# --- ping_all argument validation ---

{
    eval { Exec::Engine::ping_all(config => {}) };
    like $@, qr/hosts required/, 'ping_all: dies without hosts';
}

{
    eval { Exec::Engine::ping_all(hosts => ['h']) };
    like $@, qr/config required/, 'ping_all: dies without config';
}

{
    eval { Exec::Engine::ping_all(hosts => 'bad', config => {}) };
    like $@, qr/hosts must be an arrayref/, 'ping_all: dies if hosts not arrayref';
}

# --- dispatch_all with mock agent ---
# Starts a minimal TCP server in a child that returns a canned JSON response.
# Uses plain HTTP (no TLS) by overriding the build_ua timeout and using http://

{
    # Patch _build_ua to return a plain HTTP UA (no TLS)
    no warnings 'redefine';
    local *Exec::Engine::_build_ua = sub {
        require LWP::UserAgent;
        return LWP::UserAgent->new(timeout => 5);
    };

    # Start a minimal HTTP server in a child
    use IO::Socket::INET;
    my $server = IO::Socket::INET->new(
        LocalAddr => '127.0.0.1',
        LocalPort => 0,
        Listen    => 1,
        ReuseAddr => 1,
    ) or BAIL_OUT("Cannot start mock server: $!");
    my $mock_port = $server->sockport;

    my $child = fork();
    BAIL_OUT("fork failed: $!") unless defined $child;

    if ($child == 0) {
        # Mock agent: accept one connection, return canned response
        my $conn = $server->accept;
        # Drain request
        while (my $line = <$conn>) {
            last if $line eq "\r\n";
        }
        my $body = '{"script":"hello","exit":0,"stdout":"hi\n","stderr":"","reqid":"aabbccdd"}';
        print $conn
            "HTTP/1.0 200 OK\r\n",
            "Content-Type: application/json\r\n",
            "Content-Length: ", length($body), "\r\n",
            "\r\n",
            $body;
        $conn->close;
        exit 0;
    }
    $server->close;

    # Override _dispatch_one to use http:// not https://
    local *Exec::Engine::_dispatch_one = sub {
        my (%opts) = @_;
        require LWP::UserAgent;
        require Time::HiRes;
        my $t0  = Time::HiRes::time();
        my $ua  = LWP::UserAgent->new(timeout => 5);
        my $payload = Exec::Engine::_json_encode({
            script => $opts{script},
            args   => $opts{args} // [],
            reqid  => $opts{reqid},
        });
        my $resp = $ua->post(
            "http://127.0.0.1:$mock_port/run",
            'Content-Type' => 'application/json',
            Content        => $payload,
        );
        my $rtt = sprintf '%.0fms', (Time::HiRes::time() - $t0) * 1000;
        my $result = eval { JSON::decode_json($resp->content) }
            // { exit => -1, error => 'bad json' };
        $result->{rtt}  = $rtt;
        $result->{host} //= $opts{host};
        return $result;
    };

    use JSON qw(decode_json);
    # Add a helper so the local sub above can encode
    *Exec::Engine::_json_encode = \&JSON::encode_json;

    my $results = Exec::Engine::dispatch_all(
        hosts  => ["127.0.0.1:$mock_port"],
        script => 'hello',
        config => {},
        reqid  => 'aabbccdd',
    );

    waitpid $child, 0;

    is scalar @$results, 1,          'dispatch_all: returns one result per host';
    is $results->[0]{exit},   0,     'dispatch_all: exit code from agent';
    is $results->[0]{stdout}, "hi\n",'dispatch_all: stdout from agent';
    is $results->[0]{script}, 'hello','dispatch_all: script echoed in result';
}

# --- _host_entry: canonical name vs connect target ---

{
    my ($name, $target) = Exec::Engine::_host_entry('web-01');
    is $name,   'web-01', '_host_entry: plain string is the name';
    is $target, 'web-01', '_host_entry: plain string is also the target';

    ($name, $target) = Exec::Engine::_host_entry({ name => 'web-01', target => '10.0.0.7:7450' });
    is $name,   'web-01',       '_host_entry: hashref name';
    is $target, '10.0.0.7:7450','_host_entry: hashref target';

    ($name, $target) = Exec::Engine::_host_entry({ name => 'only-name' });
    is $name,   'only-name', '_host_entry: name-only hashref name';
    is $target, 'only-name', '_host_entry: name-only hashref falls back to name for target';
}

# --- _canonicalise: host = canonical name, reported_hostname only when differs ---

{
    my $r = { status => 'ok', reported_hostname => 'web-01' };
    Exec::Engine::_canonicalise($r, 'web-01');
    is $r->{host}, 'web-01', '_canonicalise: sets canonical host';
    ok !exists $r->{reported_hostname}, '_canonicalise: drops reported equal to name';

    $r = { status => 'ok', reported_hostname => 'vm-7a3f' };
    Exec::Engine::_canonicalise($r, 'web-01');
    is $r->{host}, 'web-01', '_canonicalise: canonical host when reported differs';
    is $r->{reported_hostname}, 'vm-7a3f', '_canonicalise: keeps differing reported hostname';

    $r = { status => 'error', error => 'no response from child' };
    Exec::Engine::_canonicalise($r, 'web-01');
    is $r->{host}, 'web-01', '_canonicalise: sets host on error results too';
    ok !exists $r->{reported_hostname}, '_canonicalise: no reported when absent';

    $r = { status => 'ok', reported_hostname => '' };
    Exec::Engine::_canonicalise($r, 'web-01');
    ok !exists $r->{reported_hostname}, '_canonicalise: drops empty reported hostname';
}

done_testing;
