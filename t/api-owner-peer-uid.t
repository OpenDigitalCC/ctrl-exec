#!/usr/bin/perl
# t/api-owner-peer-uid.t  (T-052)
#
# The unix-socket caller's uid is stored with the run (in the submitter part of
# the record) and handed to the auth hook on a later GET /status as
# owner_peer_uid / ENVEXEC_OWNER_PEER_UID, beside the current caller's
# peer_uid, so a hook can allow "same uid as the starter". A run started over
# TCP has an empty owner uid; a record written before this change still loads.
# The uid is for hooks only: it never appears in a status response.
#
# A real hook script is run (Exec::Auth::check is not stubbed); only the
# dispatch to agents is stubbed.

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
use Exec::Engine   qw();
use Exec::Lock     qw();
use Exec::Log      qw();
use Exec::Registry qw();
use Exec::RunStore qw();

my $tmp      = tempdir(CLEANUP => 1);
my $runs_dir = "$tmp/runs";
mkdir $runs_dir;

sub slurp ($p) { open my $fh, '<', $p or return ''; local $/; scalar <$fh> // '' }
sub spew ($p, $c) { open my $fh, '>', $p or die "$p: $!"; print $fh $c; close $fh; $p }

{
    no warnings 'redefine';
    *Exec::Log::log_action      = sub ($level, $fields) { };
    *Exec::Lock::check_available = sub { return { ok => 1 } };
    *Exec::Registry::resolve_dispatch = sub { return { ok => 1, hosts => ['h1'] } };
    *Exec::Engine::dispatch_all = sub (%o) {
        return $o{async} ? [ { host => 'h1', status => 'accepted' } ]
                         : [ { host => 'h1', exit => 0, stdout => 'ok', stderr => '' } ];
    };
    my $rs = \&Exec::RunStore::record_sync;
    my $ra = \&Exec::RunStore::record_async;
    *Exec::RunStore::record_sync  = sub (%o) { $rs->(%o, runs_dir => $runs_dir) };
    *Exec::RunStore::record_async = sub (%o) { $ra->(%o, runs_dir => $runs_dir) };
    my $ld = \&Exec::RunStore::load;
    *Exec::RunStore::load = sub ($reqid, $dir = undef) { $ld->($reqid, $dir // $runs_dir) };
    my $ag = \&Exec::RunStore::aggregate;
    *Exec::RunStore::aggregate = sub (%o) { $ag->(%o, runs_dir => $runs_dir) };
}

# The hook records the action it was asked about, its environment and stdin.
my $hook = spew("$tmp/hook.sh", <<"SH");
#!/bin/sh
env > "$tmp/hook.\$ENVEXEC_ACTION.env"
cat > "$tmp/hook.\$ENVEXEC_ACTION.json"
exit 0
SH
chmod 0755, $hook;
my $config = { auth_hook => $hook, api_auth_default => 'allow' };

# Serve one request through the real connection handler, as a given caller.
sub drive ($request, $peer, $peer_uid) {
    my ($client, $server) = IO::Socket::UNIX->socketpair(
        IO::Socket::AF_UNIX(), IO::Socket::SOCK_STREAM(), 0) or die "socketpair: $!";
    my $pid = fork() // die "fork: $!";
    if (!$pid) {
        $server->close;
        print $client $request;
        $client->shutdown(1);
        local $/;
        my $resp = <$client> // '';
        spew("$tmp/resp.$$", $resp);
        POSIX::_exit(0);
    }
    Exec::API::_handle_connection($server, $peer, $config, $peer_uid);
    $server->close;
    $client->close;
    waitpid $pid, 0;
    my $resp = slurp("$tmp/resp.$pid");
    unlink "$tmp/resp.$pid";
    return $resp;
}

sub body_of ($resp) { my (undef, $b) = split /\r\n\r\n/, $resp, 2; return decode_json($b // '{}') }

sub post_run ($req, $peer, $peer_uid) {
    my $body = encode_json($req);
    return body_of(drive("POST /run HTTP/1.0\r\nContent-Length: " . length($body)
                         . "\r\n\r\n$body", $peer, $peer_uid));
}

sub get_status ($reqid, $peer, $peer_uid) {
    unlink glob("$tmp/hook.status.*");
    my $resp = drive("GET /status/$reqid HTTP/1.0\r\n\r\n", $peer, $peer_uid);
    my %env = map { /^(ENVEXEC_\w+)=(.*)$/ ? ($1 => $2) : () } split /\n/, slurp("$tmp/hook.status.env");
    my $ctx = eval { decode_json(slurp("$tmp/hook.status.json")) } // {};
    return ($resp, \%env, $ctx);
}

my %run = (hosts => ['h1'], script => 's1', args => []);
my $uid = $<;
my $sock = 'unix:/run/test.sock';

# --- a run started over the socket, read later over the socket ----------------
for my $async (0, 1) {
    my $label = $async ? 'async' : 'sync';
    my $r = post_run({ %run, async => ($async ? JSON::true : JSON::false) }, $sock, $uid);
    ok($r->{reqid}, "$label run started over the socket");

    my $rec = Exec::RunStore::load($r->{reqid});
    is($rec->{submitter}{peer_uid}, $uid, "$label: peer_uid stored with the submitter");

    my ($resp, $env, $ctx) = get_status($r->{reqid}, $sock, $uid + 1);
    like($resp, qr{^HTTP/1\.\d 200}, "$label: status served");
    is($env->{ENVEXEC_OWNER_PEER_UID}, $uid, "$label: ENVEXEC_OWNER_PEER_UID is the starter's uid");
    is($env->{ENVEXEC_PEER_UID}, $uid + 1, "$label: ENVEXEC_PEER_UID is the current caller's");
    is($ctx->{owner_peer_uid}, $uid, "$label: hook stdin owner_peer_uid");
    is($ctx->{peer_uid}, $uid + 1, "$label: hook stdin peer_uid");
    unlike($resp, qr/peer_uid/, "$label: the uid is not in the status response");
}

# --- a run started over TCP: no owner uid ------------------------------------
{
    my $r = post_run(\%run, '192.0.2.7', undef);
    my $rec = Exec::RunStore::load($r->{reqid});
    ok(!exists $rec->{submitter}{peer_uid}, 'TCP run: no peer_uid stored');

    my ($resp, $env, $ctx) = get_status($r->{reqid}, $sock, $uid);
    is($env->{ENVEXEC_OWNER_PEER_UID}, '', 'TCP run: ENVEXEC_OWNER_PEER_UID empty');
    ok(exists $ctx->{owner_peer_uid} && !defined $ctx->{owner_peer_uid}, 'TCP run: owner_peer_uid null');
    is($env->{ENVEXEC_PEER_UID}, $uid, 'TCP run: the caller\'s own peer_uid still passed');

    ($resp, $env, $ctx) = get_status($r->{reqid}, '192.0.2.7', undef);
    is($env->{ENVEXEC_PEER_UID}, '', 'TCP caller: peer_uid empty');
    is($env->{ENVEXEC_OWNER_PEER_UID}, '', 'TCP caller, TCP run: owner empty');
}

# --- a record written before the field existed -------------------------------
{
    my $reqid = 'abcdef0123456789';
    spew("$runs_dir/$reqid.json", encode_json({
        reqid => $reqid, script => 's1', mode => 'sync', hosts => ['h1'],
        results => [], completed => time(), complete => JSON::true,
        submitter => { username => 'old', source_ip => '192.0.2.9' },
    }));
    my $rec = Exec::RunStore::load($reqid);
    is($rec->{submitter}{username}, 'old', 'old record loads');
    my ($resp, $env, $ctx) = get_status($reqid, $sock, $uid);
    like($resp, qr{^HTTP/1\.\d 200}, 'old record: status served');
    is($env->{ENVEXEC_OWNER_PEER_UID}, '', 'old record: owner uid empty');
    is($env->{ENVEXEC_SUBMITTER}, 'old', 'old record: submitter username still passed');

    # And one with no submitter at all.
    my $r2 = 'abcdef0123456780';
    spew("$runs_dir/$r2.json", encode_json({
        reqid => $r2, script => 's1', mode => 'sync', hosts => ['h1'],
        results => [], completed => time(), complete => JSON::true,
    }));
    ($resp, $env, $ctx) = get_status($r2, $sock, $uid);
    like($resp, qr{^HTTP/1\.\d 200}, 'record with no submitter: status served');
    is($env->{ENVEXEC_OWNER_PEER_UID}, '', 'no submitter: owner uid empty');
}

done_testing;
