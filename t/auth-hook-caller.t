#!/usr/bin/perl
# t/auth-hook-caller.t  (T-093)
#
# The dispatcher-side auth hook is told who is asking: ENVEXEC_CALLER (cli |
# api) and, for api, ENVEXEC_LISTENER (unix | tcp | tls; empty for cli). Both
# come from the code path (ced, or the listener an API connection arrived on),
# never from the request. The agent-side hook is given neither.
#
# A real hook script is run (Exec::Auth::check is not stubbed).

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

my $tmp = tempdir(CLEANUP => 1);
mkdir "$tmp/runs";

sub slurp ($p) { open my $fh, '<', $p or return ''; local $/; scalar <$fh> // '' }
sub spew ($p, $c) { open my $fh, '>', $p or die "$p: $!"; print $fh $c; close $fh; $p }

{
    no warnings 'redefine';
    *Exec::Log::log_action        = sub ($level, $fields) { };
    *Exec::Lock::check_available  = sub { return { ok => 1 } };
    *Exec::Registry::resolve_dispatch = sub { return { ok => 1, hosts => ['h1'] } };
    *Exec::Engine::dispatch_all   = sub (%o) {
        return [ { host => 'h1', exit => 0, stdout => 'ok', stderr => '' } ];
    };
    *Exec::Engine::ping_all       = sub (%o) { return [ { host => 'h1', status => 'ok' } ] };
    *Exec::Registry::list_hostnames = sub (%o) { return ['h1'] };
    my $rs = \&Exec::RunStore::record_sync;
    *Exec::RunStore::record_sync  = sub (%o) { $rs->(%o, runs_dir => "$tmp/runs") };
    my $ag = \&Exec::RunStore::aggregate;
    *Exec::RunStore::aggregate = sub (%o) { $ag->(%o, runs_dir => "$tmp/runs") };
    my $ld = \&Exec::RunStore::load;
    *Exec::RunStore::load = sub ($reqid, $dir = undef) { $ld->($reqid, $dir // "$tmp/runs") };
}

spew("$tmp/runs/abcdef0123456789.json", encode_json({
    reqid => "abcdef0123456789", script => "s1", mode => "sync", hosts => ["h1"],
    results => [], completed => time(), complete => JSON::PP::true,
}));

# One line per hook call: ACTION CALLER=<v|unset> LISTENER=<v|unset>.
my $hook = spew("$tmp/hook.sh", <<"SH");
#!/bin/sh
echo "\$ENVEXEC_ACTION CALLER=\${ENVEXEC_CALLER-unset} LISTENER=\${ENVEXEC_LISTENER-unset}" >> "$tmp/calls"
cat > "$tmp/hook.json"
exit 0
SH
chmod 0755, $hook;
my $config = { auth_hook => $hook, api_auth_default => 'allow' };

sub calls () { my @l = split /\n/, slurp("$tmp/calls"); unlink "$tmp/calls"; return @l }

# --- Exec::Auth::check directly: the CLI, an API caller, the agent ------------
{
    my %base = (action => 'ping', config => $config, hosts => ['h1']);

    Exec::Auth::check(%base, caller => 'cli');
    is_deeply([calls()], ['ping CALLER=cli LISTENER='], 'ced: caller cli, listener empty');
    is(decode_json(slurp("$tmp/hook.json"))->{caller}, 'cli', 'hook stdin: caller');

    # A listener passed with a cli caller is not believed.
    Exec::Auth::check(%base, caller => 'cli', listener => 'tcp');
    is_deeply([calls()], ['ping CALLER=cli LISTENER='], 'cli: listener forced empty');

    for my $l (qw(unix tcp tls)) {
        Exec::Auth::check(%base, caller => 'api', listener => $l);
        is_deeply([calls()], ["ping CALLER=api LISTENER=$l"], "api on $l");
        is(decode_json(slurp("$tmp/hook.json"))->{listener}, $l, "hook stdin: listener $l");
    }

    # The agent side passes neither: neither variable is set, even if the
    # agent's own environment carries them.
    {
        local $ENV{ENVEXEC_CALLER}   = 'api';
        local $ENV{ENVEXEC_LISTENER} = 'unix';
        Exec::Auth::check(%base);
    }
    is_deeply([calls()], ['ping CALLER=unset LISTENER=unset'], 'agent side: unset, unchanged');
    my $ctx = decode_json(slurp("$tmp/hook.json"));
    ok(!exists $ctx->{caller} && !exists $ctx->{listener}, 'agent side: no new stdin fields');
}

# --- ced: both Exec::Auth::check calls in bin/ctrl-exec-dispatcher say 'cli' ---
{
    my $src = slurp("$Bin/../bin/ctrl-exec-dispatcher");
    my $n = () = $src =~ /Exec::Auth::check\(/g;
    my $c = () = $src =~ /caller\s*=>\s*'cli'/g;
    is($n, 2, 'ced has two auth checks (run, ping)');
    is($c, $n, '  each says caller cli');
}

# --- the API: the listener comes from the accept loop, not the request --------
sub drive ($request, $peer, $peer_uid, $listener) {
    my ($client, $server) = IO::Socket::UNIX->socketpair(
        IO::Socket::AF_UNIX(), IO::Socket::SOCK_STREAM(), 0) or die "socketpair: $!";
    my $pid = fork() // die "fork: $!";
    if (!$pid) {
        $server->close;
        print $client $request;
        $client->shutdown(1);
        local $/;
        my $resp = <$client> // '';
        POSIX::_exit(0);
    }
    Exec::API::_handle_connection($server, $peer, $config, $peer_uid, $listener);
    $server->close;
    $client->close;
    waitpid $pid, 0;
}

sub post ($path, $req, $peer, $uid, $listener) {
    my $body = encode_json($req);
    drive("POST $path HTTP/1.0\r\nContent-Length: " . length($body) . "\r\n\r\n$body",
          $peer, $uid, $listener);
}

my @cases = ([unix => 'unix:/run/t.sock', $<], [tcp => '192.0.2.7', undef], [tls => '192.0.2.8', undef]);
for my $case (@cases) {
    my ($listener, $peer, $uid) = @$case;
    # The request lies about who it is; the hook must still see the listener.
    my %lie = (caller => 'cli', listener => 'unix', ENVEXEC_CALLER => 'cli');

    post('/run', { hosts => ['h1'], script => 's1', args => [], %lie }, $peer, $uid, $listener);
    my @c = calls();
    ok(@c >= 2, "$listener: /run asks the hook (pre-gate and run)");
    is_deeply([ grep { $_ ne "run CALLER=api LISTENER=$listener" && $_ ne "api CALLER=api LISTENER=$listener" } @c ],
              [], "$listener: /run - every call is caller api, listener $listener");

    post('/ping', { hosts => ['h1'], %lie }, $peer, $uid, $listener);
    @c = calls();
    is_deeply([ grep { !/^(ping|api) CALLER=api LISTENER=\Q$listener\E$/ } @c ], [],
              "$listener: /ping - caller api, listener $listener");
    ok(scalar(@c), "$listener: /ping asked the hook");

    drive("GET /discovery HTTP/1.0\r\n\r\n", $peer, $uid, $listener);
    @c = calls();
    is_deeply([ grep { !/^(ping|api) CALLER=api LISTENER=\Q$listener\E$/ } @c ], [],
              "$listener: /discovery - caller api, listener $listener");

    drive("GET /status/abcdef0123456789 HTTP/1.0\r\n\r\n", $peer, $uid, $listener);
    @c = calls();
    is_deeply([ grep { !/^(status|api) CALLER=api LISTENER=\Q$listener\E$/ } @c ], [],
              "$listener: /status - caller api, listener $listener");
    ok((grep { /^status / } @c), "$listener: /status asked the hook");
}

done_testing;
