#!/usr/bin/perl
# t/agent-bind.t  (T-092)
#
# agent.conf `bind`: the one address the agent listens on. The rule
# (bind_problem), the refusal to start on an invalid value (exit 78, reason
# printed and logged), self-check showing it, a reload keeping the running
# value, and a real agent: bound to 127.0.0.1 a connection to another local
# address (127.0.0.2) is refused; unset, both are accepted.

use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use FindBin    qw($Bin);
use lib "$Bin/../lib", "$Bin/lib";
use IO::Socket::INET ();

use Exec::Agent::Config qw();

# --- the rule -----------------------------------------------------------------

for my $v ('127.0.0.1', '0.0.0.0', '192.0.2.10', '::1', '::', '2001:db8::1', 'fe80::1') {
    is scalar(Exec::Agent::Config::bind_problem($v)), undef, "valid: $v";
}
for my $v ('localhost', 'agent-01.example.com', '[::1]', '127.0.0.1:7443', '256.0.0.1',
           '127.0.0.1/8', '1.2.3', '010.0.0.1', 'fe80::1%eth0', 'not-an-address', '*') {
    like scalar(Exec::Agent::Config::bind_problem($v)), qr/IPv4 or IPv6/, "invalid: $v";
}

# --- config load --------------------------------------------------------------

my $dir  = tempdir(CLEANUP => 1);
my $base = "port = 7443\ncert = $dir/missing\nkey = $dir/missing\nca = $dir/missing\n";
sub write_file { my ($p, $c) = @_; open my $fh, '>', $p or die "$p: $!"; print $fh $c; close $fh }
sub load { write_file("$dir/agent.conf", $base . $_[0]); Exec::Agent::Config::load_config("$dir/agent.conf") }

ok !exists load('')->{bind}, 'unset: no bind key, nothing changes';
is load("bind = 127.0.0.1\n")->{bind}, '127.0.0.1', 'bind = 127.0.0.1 is kept';
is load("bind = ::1\n")->{bind}, '::1', 'bind = ::1 is kept';
eval { load("bind = localhost\n") };
like $@, qr/Invalid bind 'localhost'.*IPv4 or IPv6/, 'a host name dies at load with the reason';

# A reload that brings a bind change keeps the running value and says so.
{
    write_file("$dir/scripts.conf", '');
    local $SIG{__WARN__} = sub { };
    write_file("$dir/agent.conf", $base . "bind = 127.0.0.1\n");
    my $old = Exec::Agent::Config::load_config("$dir/agent.conf");
    write_file("$dir/agent.conf", $base . "bind = 127.0.0.2\n");
    my $plan = Exec::Agent::Config::reload_plan("$dir/agent.conf", "$dir/scripts.conf", $old, {}, {});
    is $plan->{config}{bind}, '127.0.0.1', 'reload keeps the running bind';
    ok scalar(grep { /'bind' changed.*restart/ } @{ $plan->{notes} }), 'and notes that a restart is needed';
}

# --- serve refuses an invalid value ------------------------------------------

my $bin = "$Bin/../bin/ctrl-exec-agent";
sub run_cmd {
    my ($mode, $conf) = @_;
    write_file("$dir/agent.conf", $base . $conf);
    write_file("$dir/scripts.conf", '');
    my $out = `$^X -I$Bin/../lib -I$Bin/lib -MNoSyslog $bin $mode --config $dir/agent.conf --allowlist $dir/scripts.conf 2>&1`;
    return ($? >> 8, $out);
}
{
    my ($code, $out) = run_cmd('serve', "bind = agent-01\n");
    is $code, 78, 'serve exits EX_CONFIG (78) on an invalid bind';
    like $out, qr/configuration error/i, 'and frames it as a configuration error';
    like $out, qr/Invalid bind 'agent-01'.*IPv4 or IPv6/, 'and shows the reason';
    like $out, qr/ACTION=config-error.*Invalid bind 'agent-01'/, 'and logs the reason';
    unlike $out, qr/not been paired/, 'before it reaches the pairing check';

    ($code, $out) = run_cmd('self-check', "bind = agent-01\n");
    isnt $code, 0, 'self-check fails on an invalid bind';
    like $out, qr/Invalid bind 'agent-01'/, 'and shows the reason';
}

# --- a real agent -------------------------------------------------------------

require AgentRig;
plan skip_all => 'openssl not available' unless AgentRig::available();

sub tcp_open {
    my ($addr, $port) = @_;
    my $s = IO::Socket::INET->new(PeerAddr => $addr, PeerPort => $port, Timeout => 3);
    return $s ? 1 : 0;
}

{
    my $rig = AgentRig->new(extra_conf => "bind = 127.0.0.1\n");
    $rig->start or BAIL_OUT('rig agent did not start: ' . $rig->log_text);
    is $rig->request(as => 'trusted'), 200, 'bound to 127.0.0.1: a request to 127.0.0.1 is served';
    ok !tcp_open('127.0.0.2', $rig->{port}), 'bound to 127.0.0.1: a connection to 127.0.0.2 is refused';
    like $rig->log_text, qr/ACTION=start .*BIND=127\.0\.0\.1/, 'the start line logs the bind address';
    $rig->stop;
}
{
    my $rig = AgentRig->new();
    $rig->start or BAIL_OUT('rig agent did not start: ' . $rig->log_text);
    is $rig->request(as => 'trusted'), 200, 'unset: 127.0.0.1 is served';
    ok tcp_open('127.0.0.2', $rig->{port}), 'unset: 127.0.0.2 is accepted too, as before';
    unlike $rig->log_text, qr/BIND=/, 'unset: the start line has no bind';
    $rig->stop;
}
{
    # An address that is not on this host: the listener cannot bind, and the
    # agent says so with the address, rather than falling back to every address.
    my $rig = AgentRig->new(extra_conf => "bind = 192.0.2.77\n");
    ok !$rig->start, 'an address not on this host: the agent does not start';
    like $rig->log_text, qr/Cannot start server on 192\.0\.2\.77/, 'and names the address';
}

done_testing;
