use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/../lib";
use IO::Socket::UNIX qw();

use Exec::API      qw();
use Exec::Auth     qw();
use Exec::Log      qw();
use Exec::RunStore qw();

# T-030: every GET /status/{reqid} read is audited with one status-read line:
# caller (USER, IP), REQID, recorded SUBMITTER and RESULT. Response bodies are
# unchanged by the logging; no token and no output content reach the log.

my (@log, $AUTH_OK, %RECORDS);
{
    no warnings 'redefine';
    *Exec::Log::log_action   = sub { push @log, [ $_[0], { %{ $_[1] } } ] };
    *Exec::RunStore::purge   = sub { 0 };
    *Exec::RunStore::aggregate = sub { my %o = @_; return $RECORDS{ $o{reqid} } };
    *Exec::Auth::check       = sub { return { ok => $AUTH_OK } };
}

%RECORDS = (
    aabbccdd => {
        reqid => 'aabbccdd', complete => 1,
        hosts => { h => { stdout => 'TOP-SECRET-OUTPUT', exit => 0 } },
        submitter => { username => "alice", source_ip => '10.0.0.1' },
    },
    11223344 => {
        reqid => '11223344', complete => 1, hosts => {},
        submitter => { username => "al\nice", source_ip => '10.0.0.1' },
    },
);

sub read_status {
    my ($reqid, $auth_ok, $token) = @_;
    $AUTH_OK = $auth_ok;
    @log = ();
    my ($client, $server) = IO::Socket::UNIX->socketpair(
        IO::Socket::AF_UNIX(), IO::Socket::SOCK_STREAM(), 0) or die "socketpair: $!";
    Exec::API::_handle_status($server, $reqid, '192.0.2.9', $token // 'sekret-token', {});
    $server->close;
    local $/;
    my $resp = <$client>;
    $client->close;
    return $resp;
}

sub flat { join ' ', map { "$_=$_[0]{$_}" } sort keys %{ $_[0] } }

subtest 'served read' => sub {
    my $resp = read_status('aabbccdd', 1);
    like $resp, qr{^HTTP/1\.\d 200 }, 'status 200';
    like $resp, qr/TOP-SECRET-OUTPUT/, 'body carries the output';
    unlike $resp, qr/submitter/, 'body does not echo the submitter';
    is scalar(@log), 1, 'exactly one audit line';
    is $log[0][0], 'INFO', 'INFO';
    is_deeply $log[0][1], {
        ACTION => 'status-read', RESULT => 'served', USER => '(none)',
        IP => '192.0.2.9', REQID => 'aabbccdd', SUBMITTER => 'alice',
    }, 'fields';
};

subtest 'denied read' => sub {
    my $resp = read_status('aabbccdd', 0);
    like $resp, qr{^HTTP/1\.\d 404 }, 'status 404';
    like $resp, qr/no result for reqid aabbccdd/, 'body is the generic not-found text';
    unlike $resp, qr/TOP-SECRET-OUTPUT|alice/, 'body leaks nothing';
    is scalar(@log), 1, 'exactly one audit line';
    is $log[0][0], 'WARNING', 'WARNING';
    is $log[0][1]{RESULT},    'denied', 'RESULT=denied';
    is $log[0][1]{SUBMITTER}, 'alice',  'submitter recorded in the log';
    is $log[0][1]{IP},        '192.0.2.9', 'caller IP';
};

subtest 'unknown reqid' => sub {
    my $resp = read_status('deadbeef', 1);
    like $resp, qr{^HTTP/1\.\d 404 }, 'status 404';
    like $resp, qr/no result for reqid deadbeef/, 'same body shape as a denial';
    is scalar(@log), 1, 'exactly one audit line';
    is $log[0][0], 'INFO', 'INFO';
    is_deeply $log[0][1], {
        ACTION => 'status-read', RESULT => 'not-found', USER => '(none)',
        IP => '192.0.2.9', REQID => 'deadbeef', SUBMITTER => '(none)',
    }, 'fields';
};

subtest 'no secrets, one line' => sub {
    read_status('aabbccdd', 1, 'sekret-token');
    unlike flat($log[0][1]), qr/sekret-token|TOP-SECRET/, 'no token or output in the line';
    read_status('11223344', 1);
    is $log[0][1]{SUBMITTER}, 'al?ice', 'control characters in the submitter are neutralised';
};

done_testing;
