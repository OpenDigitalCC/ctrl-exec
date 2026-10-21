#!/usr/bin/perl
# t/agent-script-dispatchers.t  (T-063)
#
# scripts.conf 'dispatchers=<id>[,<id>...]' limits a script to the named
# dispatchers, by the id the agent resolved from its own trusted map for the
# connection (never anything the request says). A listed dispatcher runs it; any
# other is refused "script not permitted" naming the dispatcher, and does not
# see it in /capabilities. No option: every trusted dispatcher, as before. A bad
# value skips the entry; an id not in the trusted map is logged once per load
# and the entry kept; local self-check lists every script with its limit.

use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use FindBin    qw($Bin);
use lib "$Bin/../lib";
use IO::Socket::UNIX qw();
use JSON::PP qw(decode_json);

use Exec::Agent::Config qw();
use Exec::Agent::Server qw();
use Exec::Log           qw();

Exec::Log::init('test');
my @logs;
{
    no warnings 'redefine';
    *Exec::Log::log_action = sub { push @logs, { level => $_[0], %{ $_[1] } } };
}

my $dir = tempdir(CLEANUP => 1);
@Exec::Agent::Config::TRUSTED_OWNERS = (0, $>);
$Exec::Agent::Config::TRUSTED_TOP    = $dir;
umask 022;
mkdir "$dir/s" or die;
sub write_file { my ($p, $c, $m) = @_; open my $fh, '>', $p or die "$p: $!"; print $fh $c; close $fh; chmod $m, $p if $m }
for my $n (qw(open d1only both unknown)) {
    write_file("$dir/s/$n.sh", "#!/bin/sh\necho ran-$n\n", 0755);
}

my $allow = "$dir/scripts.conf";
write_file($allow, <<"CONF");
open    = $dir/s/open.sh
d1only  = dispatchers=d1 $dir/s/d1only.sh
both    = $dir/s/both.sh dispatchers=d2,d1
unknown = $dir/s/unknown.sh dispatchers=d1,dispatcher-9
nbsp    = $dir/s/open.sh\xc2\xa0dispatchers=d1
empty   = $dir/s/open.sh dispatchers=
trail   = $dir/s/open.sh dispatchers=d1,
dblcomma = $dir/s/open.sh dispatchers=d1,,d2
badid   = $dir/s/open.sh dispatchers=-d1
spaced  = $dir/s/open.sh dispatchers=d1, d2
toolong = $dir/s/open.sh dispatchers=${\ ('a' x 65)}
CONF

my ($allowlist, $skipped);
{
    local $SIG{__WARN__} = sub {};
    ($allowlist, $skipped) = Exec::Agent::Config::load_allowlist_full($allow, ["$dir/s"]);
}

# Two trusted dispatchers, as the per-CA view the accept loop hands a handler.
my %TRUSTED = (aa01 => 'd1', bb02 => 'd2', cc03 => 'd3');

sub request {
    my ($as, $req) = @_;
    my ($client, $server) = IO::Socket::UNIX->socketpair(
        IO::Socket::AF_UNIX(), IO::Socket::SOCK_STREAM(), 0) or die "socketpair: $!";
    print $client $req;
    $client->shutdown(1);
    Exec::Agent::Server::handle_connection(
        $server, '10.0.0.5', $allowlist, { script_dirs => ["$dir/s"] }, {},
        \%TRUSTED, $as, {}, '9.9.9', $skipped,
    );
    $server->close;
    local $/;
    my $resp = <$client> // '';
    $client->close;
    $resp =~ s/\A.*?\r\n\r\n//s;
    return decode_json($resp);
}
sub run_as {
    my ($serial, $name, %extra) = @_;
    my $body = JSON::PP->new->canonical->encode({ script => $name, args => [], reqid => 'r1', %extra });
    return request($serial, "POST /run HTTP/1.0\r\nContent-Length: " . length($body) . "\r\n\r\n$body");
}
sub listed_for {
    my ($serial) = @_;
    my $r = request($serial, "GET /capabilities HTTP/1.0\r\n\r\n");
    return [ sort map { $_->{name} } @{ $r->{scripts} } ];
}

subtest 'parser: dispatchers= is order-independent and recorded' => sub {
    is_deeply Exec::Agent::Config::script_dispatchers('d1only', $allowlist), ['d1'], 'before the path';
    is_deeply Exec::Agent::Config::script_dispatchers('both', $allowlist), ['d2', 'd1'], 'after the path, list kept';
    is Exec::Agent::Config::script_dispatchers('open', $allowlist), undef, 'absent: undef (every dispatcher)';
    is_deeply Exec::Agent::Config::script_dispatchers('nbsp', $allowlist), ['d1'],
        'a pasted NBSP before dispatchers= reads as a space';
};

subtest 'parser: a bad dispatchers= value skips the entry, with the reason' => sub {
    for my $n (qw(empty trail dblcomma badid toolong)) {
        ok !exists $allowlist->{$n}, "$n: not allowlisted";
        like $skipped->{$n}, qr/^its dispatchers= value '.*' is not a comma-separated list of dispatcher ids/,
            "$n: reason";
    }
    like $skipped->{spaced}, qr/more than one path/, 'a space after the comma splits the line (two paths)';
};

subtest 'run: a listed dispatcher runs the script' => sub {
    my $r = run_as('aa01', 'd1only');
    is $r->{exit}, 0, 'd1 runs d1only' or diag explain $r;
    like $r->{stdout}, qr/ran-d1only/, 'the script ran';
    $r = run_as('bb02', 'both');
    is $r->{exit}, 0, 'd2 runs both';
    $r = run_as('aa01', 'both');
    is $r->{exit}, 0, 'd1 runs both';
};

subtest 'run: another dispatcher is refused, naming it' => sub {
    @logs = ();
    my $r = run_as('bb02', 'd1only');
    is $r->{exit}, -1, 'd2 refused';
    is $r->{error}, "script not permitted: dispatcher 'd2' is not in its dispatchers= list",
        'reason names the dispatcher';
    ok !defined $r->{stdout} || $r->{stdout} !~ /ran-/, 'did not run';
    my ($deny) = grep { $_->{ACTION} eq 'deny' } @logs;
    ok $deny, 'logged as deny';
    is $deny->{DISPATCHER}, 'd2', 'log names the dispatcher';
    $r = run_as('cc03', 'both');
    is $r->{exit}, -1, 'd3 refused on both';
};

subtest 'run: the identity is the trusted map id, never the request' => sub {
    my $r = run_as('bb02', 'd1only', dispatcher => 'd1', dispatcher_id => 'd1');
    is $r->{exit}, -1, 'a claimed dispatcher in the body changes nothing';
    like $r->{error}, qr/dispatcher 'd2'/, 'still d2';
};

subtest 'run: no option = every trusted dispatcher' => sub {
    for my $s (qw(aa01 bb02 cc03)) {
        my $r = run_as($s, 'open');
        is $r->{exit}, 0, "$TRUSTED{$s} runs open";
    }
};

subtest 'discovery: a script limited to others is not listed' => sub {
    is_deeply listed_for('aa01'), [qw(both d1only nbsp open unknown)], 'd1 sees its scripts and the open one';
    is_deeply listed_for('bb02'), [qw(both open)], 'd2 does not see d1only or unknown';
    is_deeply listed_for('cc03'), [qw(open)], 'd3 sees only the open one';
};

subtest 'an id not in the trusted map is logged once per load, entry kept' => sub {
    ok exists $allowlist->{unknown}, 'entry kept';
    @logs = ();
    my $full = { 'f' x 64 . ' aa01' => 'd1', 'e' x 64 . ' bb02' => 'd2' };
    Exec::Agent::Config::log_unknown_dispatchers($allowlist, $full);
    my @w = grep { $_->{ACTION} eq 'allowlist-unknown-dispatcher' } @logs;
    is scalar @w, 1, 'one line';
    is $w[0]{level}, 'WARNING', 'WARNING';
    is $w[0]{SCRIPT}, 'unknown', 'names the script';
    is $w[0]{DISPATCHER}, 'dispatcher-9', 'names the id';
    @logs = ();
    Exec::Agent::Config::log_unknown_dispatchers($allowlist, { %$full, 'd' x 64 . ' 99' => 'dispatcher-9' });
    is scalar(grep { $_->{ACTION} eq 'allowlist-unknown-dispatcher' } @logs), 0,
        'paired later: nothing logged';
};

subtest 'self-check (local) lists every script with its limit' => sub {
    my $conf = "$dir/agent.conf";
    my $map  = "$dir/dispatchers";
    write_file($map, ('f' x 64) . " aa01 d1\n" . ('e' x 64) . " bb02 d2\n");
    write_file($conf, "port = 7443\ncert = /c.crt\nkey = /c.key\nca = /ca.crt\n"
                    . "script_dirs = $dir/s\ntrusted_dispatchers_path = $map\n[profile default]\n");
    my $agent = "$Bin/../bin/ctrl-exec-agent";
    my $seam = '@Exec::Agent::Config::TRUSTED_OWNERS = (0, $>);'
             . '$Exec::Agent::Config::TRUSTED_TOP = shift;'
             . 'my $a = shift; do $a or die $@ || $!; main()';
    my $cmd = join ' ', map { "'$_'" } $^X, "-I$Bin/../lib", '-MExec::Agent::Config',
                                        '-e', $seam, $dir, $agent, '--config', $conf,
                                        '--allowlist', $allow, 'self-check';
    my $out = `$cmd 2>&1`;
    like $out, qr{Script 'd1only': \S+  \(profile: default, dispatchers: d1\) \[ok\]}, 'limit shown';
    like $out, qr{Script 'both': \S+  \(profile: default, dispatchers: d2,d1\)}, 'list shown';
    like $out, qr{Script 'open': \S+  \(profile: default\) \[ok\]}, 'unlimited script as before';
    like $out, qr{Script 'unknown': .*\[warning: dispatcher 'dispatcher-9' is not in the trusted map\]},
        'an unknown id is pointed out';
    like $out, qr{Script 'empty': SKIPPED - its dispatchers= value}, 'a bad value is listed as skipped';
};

done_testing;
