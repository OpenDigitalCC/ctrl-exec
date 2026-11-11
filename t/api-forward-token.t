#!/usr/bin/perl
# t/api-forward-token.t  (T-095)
#
# api_forward_token: the API always gives its own hook the caller's token, and
# by default forwards it to the agents. With api_forward_token = no the agents
# get an empty token (which the agent already treats as "no token"), for run
# and async run alike.

use strict;
use warnings;
use feature qw(signatures);
no warnings qw(experimental::signatures);
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/../lib";
use IO::Socket::UNIX qw();
use File::Temp qw(tempdir);
use JSON::PP qw(encode_json decode_json);
use POSIX ();

use Exec::API      qw();
use Exec::Auth     qw();
use Exec::Engine   qw();
use Exec::Lock     qw();
use Exec::Log      qw();
use Exec::Registry qw();
use Exec::RunStore qw();

my $tmp      = tempdir(CLEANUP => 1);
my $runs_dir = "$tmp/runs";
my $sent_dir = "$tmp/sent";
mkdir $sent_dir;
my @auth_calls;

{
    package MockUA;
    sub new { my ($c, %a) = @_; bless {%a}, $c }
    sub post {
        my ($s, $url, %h) = @_;
        my $n = "$url"; $n =~ s/\W+/_/g;
        open my $fh, '>', "$sent_dir/$n.$$" or die $!;
        print $fh $h{Content};
        close $fh;
        my $async = $h{Content} =~ /"async"\s*:\s*true/;
        return HTTP::Response->new($async ? 202 : 200, 'OK',
            [ 'Content-Type' => 'application/json' ],
            $async ? '{"status":"accepted","reqid":"r1"}'
                   : '{"exit":0,"stdout":"done","stderr":"","reqid":"r1"}');
    }
}
require HTTP::Response;

{
    no warnings 'redefine';
    *Exec::Log::log_action = sub ($level, $fields) { };
    *Exec::Auth::check = sub (%o) { push @auth_calls, { %o }; return { ok => 1, reason => 'stub' } };
    *Exec::Lock::check_available = sub { return { ok => 1 } };
    *Exec::Registry::resolve_dispatch = sub { return { ok => 1, hosts => ['h1', 'h2'] } };
    *Exec::Engine::_build_ua   = sub { MockUA->new };
    my $rs = \&Exec::RunStore::record_sync;
    my $ra = \&Exec::RunStore::record_async;
    *Exec::RunStore::record_sync  = sub (%o) { $rs->(%o, runs_dir => $runs_dir) };
    *Exec::RunStore::record_async = sub (%o) { $ra->(%o, runs_dir => $runs_dir) };
}

sub slurp { open my $fh, '<', $_[0] or die "$_[0]: $!"; local $/; <$fh> }

sub post_run ($req, $config) {
    @auth_calls = ();
    unlink glob "$sent_dir/*";
    my $body = encode_json($req);
    my ($client, $server) = IO::Socket::UNIX->socketpair(
        IO::Socket::AF_UNIX(), IO::Socket::SOCK_STREAM(), 0) or die "socketpair: $!";
    my $pid = fork() // die "fork: $!";
    if (!$pid) {
        $server->close;
        print $client "POST /run HTTP/1.0\r\nContent-Length: " . length($body) . "\r\n\r\n$body";
        $client->shutdown(1);
        local $/;
        my $resp = <$client> // '';
        open my $out, '>', "$tmp/resp.$$" or die $!;
        print $out $resp;
        close $out;
        POSIX::_exit(0);
    }
    Exec::API::_handle_connection($server, '127.0.0.1', $config);
    $server->close;
    $client->close;
    waitpid $pid, 0;
    my $resp = slurp("$tmp/resp.$pid");
    unlink "$tmp/resp.$pid";
    return $resp;
}

my %base = (hosts => ['h1', 'h2'], script => 's1', token => 'TOK-123', username => 'u1');

for my $case (
    [ 'default (unset)', {},                            'TOK-123' ],
    [ 'yes',             { api_forward_token => 'yes' }, 'TOK-123' ],
    [ 'unrecognised',    { api_forward_token => 'maybe' }, 'TOK-123' ],
    [ 'no',              { api_forward_token => 'no' }, ''        ],
    [ '0',               { api_forward_token => '0' },  ''        ],
    [ 'off',             { api_forward_token => 'off' }, ''       ],
    [ 'No (case)',       { api_forward_token => 'No' }, ''        ],
) {
    my ($name, $config, $want) = @$case;
    for my $async (0, 1) {
        my $label = "$name, " . ($async ? 'async' : 'sync');
        my $resp = post_run({ %base, ($async ? (async => JSON::PP::true) : ()) }, $config);
        like $resp, qr{^HTTP/1\.0 20[02] }, "$label: ok";
        my @run = grep { $_->{action} eq 'run' } @auth_calls;
        is scalar(@run), 1, "$label: run hook called";
        is $run[0]{token}, 'TOK-123', "$label: the API's own hook always gets the real token";
        my @sent = glob "$sent_dir/*";
        is scalar(@sent), 2, "$label: both agents sent a body";
        is decode_json(slurp($_))->{token}, $want, "$label: agent token" for @sent;
    }
}

done_testing;
