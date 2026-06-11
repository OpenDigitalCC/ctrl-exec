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

# --- async dispatch + result fetch ---
# A tiny mock UA lets us drive the real _dispatch_one / _result_one response
# handling (202/409/403/404/200) without networking or TLS.

{
    package MockUA;
    sub new { my ($c, %a) = @_; bless { %a }, $c }
    sub post { my ($s, @a) = @_; $s->{on_post}->(@a) }
    sub get  { my ($s, @a) = @_; $s->{on_get}->(@a) }
}

use HTTP::Response;

sub _resp {
    my ($code, $msg, $body) = @_;
    return HTTP::Response->new(
        $code, $msg, [ 'Content-Type' => 'application/json' ], $body,
    );
}

# _dispatch_one async: 202 Accepted -> status 'accepted', no exit/stdout
{
    no warnings 'redefine';
    my $sent_body;
    local *Exec::Engine::_build_ua = sub {
        MockUA->new(on_post => sub {
            my ($url, %h) = @_;
            $sent_body = $h{Content};
            return _resp(202, 'Accepted',
                '{"status":"accepted","reqid":"abc123def4567890","script":"backup"}');
        });
    };
    my $r = Exec::Engine::_dispatch_one(
        host => 'h', port => 7443, script => 'backup',
        reqid => 'abc123def4567890', config => {}, async => 1,
    );
    is   $r->{status}, 'accepted',          'async dispatch: 202 -> accepted';
    is   $r->{reqid},  'abc123def4567890',  'async dispatch: reqid echoed';
    ok   !exists $r->{exit},                'async dispatch: no exit on acceptance';
    like $sent_body, qr/"async"\s*:\s*true/, 'async dispatch: async flag sent in body';
}

# _dispatch_one async: 409 Conflict -> status 'busy' with error, not a transport failure
{
    no warnings 'redefine';
    local *Exec::Engine::_build_ua = sub {
        MockUA->new(on_post => sub {
            return _resp(409, 'Conflict',
                '{"status":"busy","error":"script already running"}');
        });
    };
    my $r = Exec::Engine::_dispatch_one(
        host => 'h', port => 7443, script => 'backup',
        reqid => 'r1', config => {}, async => 1,
    );
    is   $r->{status}, 'busy',                   'async dispatch: 409 -> busy';
    like $r->{error},  qr/already running/,       'async dispatch: busy carries agent message';
    ok   !exists $r->{exit},                      'async dispatch: busy has no exit';
}

# _dispatch_one async: 403 -> status 'error' (forbidden), distinct from busy
{
    no warnings 'redefine';
    local *Exec::Engine::_build_ua = sub {
        MockUA->new(on_post => sub {
            return _resp(403, 'Forbidden', '{"error":"serial mismatch"}');
        });
    };
    my $r = Exec::Engine::_dispatch_one(
        host => 'h', port => 7443, script => 'backup',
        reqid => 'r1', config => {}, async => 1,
    );
    is   $r->{status}, 'error',          'async dispatch: 403 -> error status';
    like $r->{error},  qr/forbidden/,     'async dispatch: 403 carries forbidden';
}

# _result_one: 200 done -> full result
{
    no warnings 'redefine';
    my $got_url;
    local *Exec::Engine::_build_ua = sub {
        MockUA->new(on_get => sub {
            ($got_url) = @_;
            return _resp(200, 'OK',
                '{"reqid":"r1","status":"done","script":"backup","exit":0,"stdout":"ok\n","stderr":""}');
        });
    };
    my $r = Exec::Engine::_result_one(host => 'h', port => 7443, reqid => 'r1', config => {});
    is   $r->{status}, 'done',  'result fetch: done status';
    is   $r->{exit},   0,       'result fetch: exit captured';
    is   $r->{stdout}, "ok\n",  'result fetch: stdout captured';
    like $got_url, qr{/result/r1\z}, 'result fetch: GET /result/<reqid>';
}

# _result_one: 200 running -> status running, no exit yet
{
    no warnings 'redefine';
    local *Exec::Engine::_build_ua = sub {
        MockUA->new(on_get => sub {
            return _resp(200, 'OK', '{"reqid":"r1","status":"running","script":"backup"}');
        });
    };
    my $r = Exec::Engine::_result_one(host => 'h', port => 7443, reqid => 'r1', config => {});
    is $r->{status}, 'running', 'result fetch: running status';
    ok !exists $r->{exit},      'result fetch: running has no exit yet';
}

# _result_one: 404 -> status 'unknown' (purged or never ran here), not an error
{
    no warnings 'redefine';
    local *Exec::Engine::_build_ua = sub {
        MockUA->new(on_get => sub {
            return _resp(404, 'Not Found', '{"status":"unknown","reqid":"r1"}');
        });
    };
    my $r = Exec::Engine::_result_one(host => 'h', port => 7443, reqid => 'r1', config => {});
    is $r->{status}, 'unknown', 'result fetch: 404 -> unknown';
    ok !exists $r->{error},     'result fetch: unknown is not an error';
}

# _result_one: 403 -> status 'error' (forbidden)
{
    no warnings 'redefine';
    local *Exec::Engine::_build_ua = sub {
        MockUA->new(on_get => sub {
            return _resp(403, 'Forbidden', '{"error":"serial mismatch"}');
        });
    };
    my $r = Exec::Engine::_result_one(host => 'h', port => 7443, reqid => 'r1', config => {});
    is   $r->{status}, 'error',      'result fetch: 403 -> error';
    like $r->{error},  qr/forbidden/, 'result fetch: 403 carries forbidden';
}

# dispatch_all threads async through to _dispatch_one
{
    no warnings 'redefine';
    local *Exec::Engine::_dispatch_one = sub {
        my (%o) = @_;
        return {
            host => $o{host}, script => $o{script},
            status => 'accepted', reqid => $o{reqid},
            got_async => ($o{async} ? 1 : 0),
        };
    };
    my $res = Exec::Engine::dispatch_all(
        hosts => ['h1'], script => 'x', config => {}, reqid => 'r9', async => 1,
    );
    is $res->[0]{status},    'accepted', 'dispatch_all async: acceptance returned';
    is $res->[0]{got_async}, 1,          'dispatch_all async: flag threaded to _dispatch_one';
}

# result_all argument validation
{
    eval { Exec::Engine::result_all(config => {}, reqid => 'r') };
    like $@, qr/hosts required/, 'result_all: dies without hosts';

    eval { Exec::Engine::result_all(hosts => ['h'], reqid => 'r') };
    like $@, qr/config required/, 'result_all: dies without config';

    eval { Exec::Engine::result_all(hosts => ['h'], config => {}) };
    like $@, qr/reqid required/, 'result_all: dies without reqid';

    eval { Exec::Engine::result_all(hosts => 'bad', config => {}, reqid => 'r') };
    like $@, qr/hosts must be an arrayref/, 'result_all: dies if hosts not arrayref';
}

# result_all aggregates per-host across the fork/collect plumbing
{
    no warnings 'redefine';
    local *Exec::Engine::_result_one = sub {
        my (%o) = @_;
        return $o{host} eq 'h1'
            ? { host => $o{host}, status => 'done', exit => 0, stdout => "ok\n", reqid => $o{reqid} }
            : { host => $o{host}, status => 'running', reqid => $o{reqid} };
    };
    my $res = Exec::Engine::result_all(hosts => ['h1', 'h2'], config => {}, reqid => 'r1');
    is scalar @$res, 2, 'result_all: one result per host';
    my %by = map { $_->{host} => $_ } @$res;
    is $by{h1}{status}, 'done',    'result_all: h1 done';
    is $by{h1}{exit},   0,         'result_all: h1 exit aggregated';
    is $by{h2}{status}, 'running', 'result_all: h2 still running';
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
