#!/usr/bin/perl
# t/api-run-input.t  (T-013 piece 1)
#
# Confidential run input on the dispatcher side: POST /run accepts an optional
# 'input' object, validates it before any hook or dispatch, forwards it
# unchanged to each agent's /run body, and shows its values to nothing else -
# not the auth hook, not a log line, not the run store.
#
# Exec::Auth::check, Exec::Log::log_action and the agent UA are stubbed so the
# test sees exactly what each would have received.

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
use Data::Dumper;
use POSIX ();

use Exec::API      qw();
use Exec::Auth     qw();
use Exec::Engine   qw();
use Exec::Lock     qw();
use Exec::Log      qw();
use Exec::Registry qw();
use Exec::RunStore qw();

my $SENTINEL = 'SeNtInEl-7f3a91-do-not-leak';
my $tmp      = tempdir(CLEANUP => 1);
my $runs_dir = "$tmp/runs";
my $sent_dir = "$tmp/sent";
mkdir $sent_dir;

my (@auth_calls, @log_lines);

{
    package MockUA;
    sub new { my ($c, %a) = @_; bless {%a}, $c }
    sub post {
        my ($s, $url, %h) = @_;
        # The worker is a forked child: hand the body to the parent via a file.
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
    *Exec::Log::log_action = sub ($level, $fields) {
        push @log_lines, join ' ', $level, map { "$_=" . ($fields->{$_} // '') } sort keys %$fields;
    };
    *Exec::Auth::check = sub (%o) {
        push @auth_calls, { %o };
        return { ok => 1, reason => 'stub' };
    };
    *Exec::Auth::deny_fields   = sub { return { error => 'forbidden' } };
    *Exec::Lock::check_available = sub { return { ok => 1 } };
    *Exec::Registry::resolve_dispatch = sub { return { ok => 1, hosts => ['h1', 'h2'] } };
    *Exec::Engine::_build_ua   = sub { MockUA->new };
    my $rs = \&Exec::RunStore::record_sync;
    my $ra = \&Exec::RunStore::record_async;
    *Exec::RunStore::record_sync  = sub (%o) { $rs->(%o, runs_dir => $runs_dir) };
    *Exec::RunStore::record_async = sub (%o) { $ra->(%o, runs_dir => $runs_dir) };
}

sub drive {
    my (%opt) = @_;
    @auth_calls = ();
    @log_lines  = ();
    my ($client, $server) = IO::Socket::UNIX->socketpair(
        IO::Socket::AF_UNIX(), IO::Socket::SOCK_STREAM(), 0) or die "socketpair: $!";
    # A request larger than the socket buffer needs a concurrent writer.
    my $pid = fork() // die "fork: $!";
    if (!$pid) {
        $server->close;
        print $client $opt{request};
        $client->shutdown(1);
        local $/;
        my $resp = <$client> // '';
        open my $out, '>', "$tmp/resp.$$" or die $!;
        print $out $resp;
        close $out;
        POSIX::_exit(0);
    }
    Exec::API::_handle_connection($server, '127.0.0.1', $opt{config} // {});
    $server->close;
    $client->close;
    waitpid $pid, 0;
    my $resp = slurp("$tmp/resp.$pid");
    unlink "$tmp/resp.$pid";
    return $resp;
}

sub post_run {
    my ($req, %opt) = @_;
    my $body = ref $req ? encode_json($req) : $req;
    return drive(request => "POST /run HTTP/1.0\r\nContent-Length: " . length($body)
                            . "\r\n\r\n$body", %opt);
}

sub run_files { glob "$runs_dir/*.json" }

sub slurp { open my $fh, '<', $_[0] or die "$_[0]: $!"; local $/; <$fh> }

my %base = (hosts => ['h1', 'h2'], script => 's1', args => ['a']);

# --- 400s: every bad shape, before any hook or dispatch ----------------------

subtest 'bad input shapes are 400 before the hook or dispatch' => sub {
    my @cases = (
        [ 'a string',            "$SENTINEL"                         ],
        [ 'an array',            [ $SENTINEL ]                       ],
        [ 'a number',            42                                  ],
        [ 'a nested object',     { k => { v => $SENTINEL } }         ],
        [ 'an array field',      { k => [ $SENTINEL ] }              ],
        [ 'a null field',        { k => undef }                      ],
        [ 'a bad field name',    { 'bad name!' => $SENTINEL }        ],
        [ 'an empty field name', { '' => $SENTINEL }                 ],
        [ 'a dot name',          { '..' => $SENTINEL }               ],
        [ 'a long field name',   { ('n' x 65) => $SENTINEL }         ],
        [ 'too many fields',     { map { ("f$_" => $SENTINEL) } 1..33 } ],
    );
    for my $c (@cases) {
        my ($what, $input) = @$c;
        my $resp = post_run({ %base, input => $input });
        like $resp, qr{^HTTP/1\.0 400 }, "$what: 400";
        is scalar(grep { $_->{action} eq 'run' } @auth_calls), 0, "$what: run hook not reached";
        is scalar(grep { /ACTION=dispatch/ } @log_lines), 0, "$what: not dispatched";
        unlike $resp, qr/\Q$SENTINEL\E/, "$what: error does not echo a value";
    }

    my $resp = post_run({ %base, input => { k => 'x' x 101 } },
                        config => { max_input_bytes => 100 });
    like $resp, qr{^HTTP/1\.0 400 }, 'over max_input_bytes: 400';
    like $resp, qr/exceeds 100 bytes/, 'the limit is named';

    $resp = post_run({ %base, input => { k => 'x' x 100 } },
                     config => { max_input_bytes => 100 });
    like $resp, qr{^HTTP/1\.0 200 }, 'exactly max_input_bytes is accepted';
};

# --- body limit admits max_input_bytes plus overhead -------------------------

subtest 'API body limit admits a maximum-size input' => sub {
    my $big = 'x' x 1_048_576;
    my $resp = post_run({ %base, input => { blob => $big } });
    like $resp, qr{^HTTP/1\.0 200 }, 'default 1 MiB input passes the body limit';

    my $req = "POST /run HTTP/1.0\r\nContent-Length: 5000000\r\n\r\n";
    like drive(request => $req), qr{^HTTP/1\.0 413 }, 'a body over the limit is still 413';

    $req = "POST /run HTTP/1.0\r\nContent-Length: 1500000\r\n\r\n";
    unlike drive(request => $req, config => {}), qr{^HTTP/1\.0 413 },
        'a 1.5 MB body is admitted under the default';
    like drive(request => $req, config => { max_input_bytes => 10 }), qr{^HTTP/1\.0 413 },
        'with a small max_input_bytes the limit is correspondingly smaller';
};

# --- sync run: hook, agent body, logs, store ---------------------------------

my %input = (cert => "line1\nline2 $SENTINEL-cert", key => "$SENTINEL-key", 'ca.pem' => 'c');

subtest 'sync run with input' => sub {
    unlink $_ for glob("$sent_dir/*"), run_files();
    my $resp = post_run({ %base, input => \%input });
    like $resp, qr{^HTTP/1\.0 200 }, 'ok status';
    unlike $resp, qr/\Q$SENTINEL\E/, 'response carries no value';

    # The hook (the 'run' check; the first call is the generic 'api' gate)
    my ($run) = grep { $_->{action} eq 'run' } @auth_calls;
    ok $run, 'run hook was called';
    is_deeply $run->{input_names}, [ 'ca.pem', 'cert', 'key' ], 'hook sees sorted names';
    my $bytes = 0; $bytes += length for values %input;
    is $run->{input_bytes}, $bytes, 'hook sees total bytes';
    ok !exists $run->{input}, 'no input key passed to the hook';
    for my $call (@auth_calls) {
        unlike Dumper($call), qr/\Q$SENTINEL\E/, "auth call '$call->{action}' holds no value";
    }

    # The body each agent received
    my @sent = glob "$sent_dir/*";
    is scalar(@sent), 2, 'both hosts were sent a body';
    for my $f (@sent) {
        my $b = decode_json(slurp($f));
        is_deeply $b->{input}, \%input, 'agent body carries input unchanged';
        is $b->{script}, 's1', 'rest of the body is as before';
        ok !grep({ /\Q$SENTINEL\E/ } @{ $b->{args} }), 'args hold no value';
    }

    # Logs
    ok scalar(@log_lines), 'something was logged';
    is scalar(grep { /\Q$SENTINEL\E|line1/ } @log_lines), 0, 'no log line holds a value';

    # Run store
    my @recs = run_files();
    is scalar(@recs), 1, 'a run record was stored';
    unlike slurp($recs[0]), qr/\Q$SENTINEL\E/, 'stored record holds no value';
};

subtest 'async run with input' => sub {
    unlink $_ for glob("$sent_dir/*"), run_files();
    my $resp = post_run({ %base, async => JSON::PP::true, input => \%input });
    like $resp, qr{^HTTP/1\.0 202 }, 'accepted status';
    unlike $resp, qr/\Q$SENTINEL\E/, 'response carries no value';
    my @sent = glob "$sent_dir/*";
    is scalar(@sent), 2, 'both hosts were sent a body';
    for my $f (@sent) {
        my $b = decode_json(slurp($f));
        is_deeply $b->{input}, \%input, 'async agent body carries input';
        ok $b->{async}, 'async flag still sent';
    }
    is scalar(grep { /\Q$SENTINEL\E|line1/ } @log_lines), 0, 'no log line holds a value';
    my @recs = run_files();
    is scalar(@recs), 1, 'an async record was stored';
    unlike slurp($recs[0]), qr/\Q$SENTINEL\E/, 'async record holds no value';
};

# --- no input: the key is absent everywhere ----------------------------------

subtest 'no input: key omitted' => sub {
    unlink $_ for glob("$sent_dir/*"), run_files();
    my $resp = post_run({ %base });
    like $resp, qr{^HTTP/1\.0 200 }, 'ok status';
    my ($run) = grep { $_->{action} eq 'run' } @auth_calls;
    is_deeply $run->{input_names}, [], 'hook: no names';
    is $run->{input_bytes}, 0, 'hook: zero bytes';
    for my $f (glob "$sent_dir/*") {
        ok !exists decode_json(slurp($f))->{input}, 'agent body has no input key';
    }
    unlink $_ for glob("$sent_dir/*");
    post_run({ %base, input => {} });
    for my $f (glob "$sent_dir/*") {
        is_deeply decode_json(slurp($f))->{input}, {}, 'an empty object is forwarded as given';
    }
};

# --- the Engine itself -------------------------------------------------------

subtest 'Engine::dispatch_all rejects a non-hash input' => sub {
    eval { Exec::Engine::dispatch_all(hosts => ['h'], script => 's', config => {}, input => 'x') };
    like $@, qr/input must be a hashref/, 'croaks, without echoing the value';
};

done_testing;
