#!/usr/bin/perl
# t/api-run-output.t  (T-053)
#
# Confidential output on the dispatcher's API path: an agent result marked
# output_confidential reaches the POST /run caller with its stdout and stderr,
# but the run store keeps exit status and metadata only, a later GET /status
# shows no output, and no log line carries it. An unmarked result is stored
# whole, as before. An agent's refusal of an async run is recorded and logged
# as an error, not an acceptance.
#
# Exec::Auth::check, Exec::Log::log_action and the agent UA are stubbed; the run
# store is redirected to a temporary directory.

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

my $S_OUT = 'OUT-SENTINEL-api53-7d2f';
my $S_ERR = 'ERR-SENTINEL-api53-1a9c';
my $tmp      = tempdir(CLEANUP => 1);
my $runs_dir = "$tmp/runs";

# Log lines, read back from a file: the fan-out workers that log each
# agent's answer are forked children.
my $log_file = "$tmp/log";
my @log_lines;

{
    package MockUA;
    sub new { my ($c, %a) = @_; bless {%a}, $c }
    # The agent's answer, by script: 'secret' is declared output=confidential
    # on the agent, 'plain' is not. Async runs of 'secret' are refused.
    sub post {
        my ($s, $url, %h) = @_;
        my $req = JSON::PP::decode_json($h{Content});
        my $conf = $req->{script} eq 'secret';
        my $body;
        if ($req->{async}) {
            return HTTP::Response->new(202, 'Accepted', [ 'Content-Type' => 'application/json' ],
                '{"status":"accepted","reqid":"' . $req->{reqid} . '"}') unless $conf;
            $body = { script => 'secret', exit => -1, reqid => $req->{reqid},
                      error => "script 'secret' is output=confidential: its output is never stored, "
                             . 'so it cannot run async; run it synchronously' };
        }
        else {
            $body = { script => $req->{script}, exit => 0, stdout => "$S_OUT\n", stderr => "$S_ERR\n",
                      reqid => $req->{reqid}, ($conf ? (output_confidential => JSON::PP::true) : ()) };
        }
        return HTTP::Response->new(200, 'OK', [ 'Content-Type' => 'application/json' ],
                                   JSON::PP::encode_json($body));
    }
}
require HTTP::Response;

{
    no warnings 'redefine';
    *Exec::Log::log_action = sub ($level, $fields) {
        open my $fh, '>>', $log_file or die "$log_file: $!";
        print {$fh} join(' ', $level, map { "$_=" . ($fields->{$_} // '') } sort keys %$fields), "\n";
        close $fh;
    };
    *Exec::Auth::check = sub (%o) { return { ok => 1, reason => 'stub' } };
    *Exec::Auth::deny_fields   = sub { return { error => 'forbidden' } };
    *Exec::Lock::check_available = sub { return { ok => 1 } };
    *Exec::Registry::resolve_dispatch = sub { return { ok => 1, hosts => [ @{ $_[0] } ] } };
    *Exec::Engine::_build_ua   = sub { MockUA->new };
    my $rs = \&Exec::RunStore::record_sync;
    my $ra = \&Exec::RunStore::record_async;
    my $ag = \&Exec::RunStore::aggregate;
    *Exec::RunStore::record_sync  = sub (%o) { $rs->(%o, runs_dir => $runs_dir) };
    *Exec::RunStore::record_async = sub (%o) { $ra->(%o, runs_dir => $runs_dir) };
    *Exec::RunStore::aggregate    = sub (%o) { $ag->(%o, runs_dir => $runs_dir) };
    *Exec::RunStore::purge        = sub { 0 };
}

sub slurp { open my $fh, '<', $_[0] or die "$_[0]: $!"; local $/; <$fh> }

sub drive ($request) {
    unlink $log_file;
    my ($client, $server) = IO::Socket::UNIX->socketpair(
        IO::Socket::AF_UNIX(), IO::Socket::SOCK_STREAM(), 0) or die "socketpair: $!";
    my $pid = fork() // die "fork: $!";
    if (!$pid) {
        $server->close;
        print $client $request;
        $client->shutdown(1);
        local $/;
        my $resp = <$client> // '';
        open my $out, '>', "$tmp/resp.$$" or die $!;
        print $out $resp;
        close $out;
        POSIX::_exit(0);
    }
    Exec::API::_handle_connection($server, '127.0.0.1', {});
    $server->close;
    $client->close;
    waitpid $pid, 0;
    my $resp = slurp("$tmp/resp.$pid");
    unlink "$tmp/resp.$pid";
    @log_lines = -f $log_file ? split(/\n/, slurp($log_file)) : ();
    my ($head, $body) = split /\r\n\r\n/, $resp, 2;
    return ($head, decode_json($body));
}

sub post_run ($req) {
    my $body = encode_json($req);
    return drive("POST /run HTTP/1.0\r\nContent-Length: " . length($body) . "\r\n\r\n$body");
}

sub stored_text { join "\n", map { slurp($_) } glob "$runs_dir/*" }

subtest 'sync confidential: the caller gets the output; the store and logs do not' => sub {
    unlink glob "$runs_dir/*";
    my ($head, $r) = post_run({ hosts => ['h1', 'h2'], script => 'secret' });
    like $head, qr{^HTTP/1\.0 200 }, 'HTTP 200';
    is scalar @{ $r->{results} }, 2, 'two results';
    for my $res (@{ $r->{results} }) {
        like $res->{stdout}, qr/\Q$S_OUT\E/, "$res->{host}: stdout in the response";
        like $res->{stderr}, qr/\Q$S_ERR\E/, "$res->{host}: stderr in the response";
        is $res->{output_confidential}, JSON::PP::true, "$res->{host}: marked in the response";
    }
    my @files = glob "$runs_dir/*";
    is scalar @files, 1, 'the run is recorded';
    my $stored = stored_text();
    unlike $stored, qr/\Q$S_OUT\E|\Q$S_ERR\E/, 'no file under the runs dir holds the output';
    my $rec = decode_json($stored);
    is_deeply [ map { $_->{exit} } @{ $rec->{results} } ], [0, 0], 'exit status stored';
    ok !grep({ exists $_->{stdout} || exists $_->{stderr} } @{ $rec->{results} }), 'no stdout/stderr keys';
    ok scalar(@log_lines), 'the run is logged';
    is scalar(grep { /\Q$S_OUT\E|\Q$S_ERR\E/ } @log_lines), 0, 'no log line holds the output';

    my ($sh, $st) = drive("GET /status/$r->{reqid} HTTP/1.0\r\n\r\n");
    like $sh, qr{^HTTP/1\.0 200 }, 'GET /status: HTTP 200';
    is $st->{results}[0]{exit}, 0, 'GET /status: exit';
    ok $st->{results}[0]{output_confidential}, 'GET /status: marked';
    unlike encode_json($st), qr/\Q$S_OUT\E|\Q$S_ERR\E/, 'GET /status: no output';
    is scalar(grep { /\Q$S_OUT\E|\Q$S_ERR\E/ } @log_lines), 0, 'GET /status: no log line holds it';
};

subtest 'sync normal: stored whole, as before' => sub {
    unlink glob "$runs_dir/*";
    my ($head, $r) = post_run({ hosts => ['h1', 'h2'], script => 'plain' });
    like $r->{results}[0]{stdout}, qr/\Q$S_OUT\E/, 'stdout in the response';
    ok !exists $r->{results}[0]{output_confidential}, 'unmarked';
    my $rec = decode_json(stored_text());
    like $rec->{results}[0]{stdout}, qr/\Q$S_OUT\E/, 'stdout stored';
    like $rec->{results}[0]{stderr}, qr/\Q$S_ERR\E/, 'stderr stored';
};

subtest 'async confidential: the agent refuses; recorded and logged as an error' => sub {
    unlink glob "$runs_dir/*";
    my ($head, $r) = post_run({ hosts => ['h1'], script => 'secret', async => JSON::PP::true });
    like $head, qr{^HTTP/1\.0 202 }, 'HTTP 202 (per-host outcome inside)';
    like $r->{results}[0]{error}, qr/output=confidential.*run it synchronously/, 'the refusal reaches the caller';
    my $rec = decode_json(stored_text());
    is $rec->{hosts}{h1}{status}, 'error', 'stored as error, not pending';
    ok $rec->{complete}, 'nothing left to fetch';
    ok scalar(grep { /ACTION=run-async/ && /STATUS=error/ } @log_lines), 'logged STATUS=error';
    is scalar(grep { /ACTION=run-async/ && /STATUS=accepted/ } @log_lines), 0, 'never logged as accepted';
};

done_testing;
