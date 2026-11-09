#!/usr/bin/perl
use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/../lib";

use Exec::Pairing qw();
use Exec::Pairing::Identity;

# T-079: when the requested name does not resolve from the dispatcher and
# nobody chose a lookup_by, approve registers lookup_by=ip. No real DNS: the
# unresolvable name is under .invalid (RFC 6761, never resolves) and the
# resolvable one is localhost (/etc/hosts).

my $F = \&Exec::Pairing::Identity::forward_lookup;
is $F->('t079-agent.invalid'), 0, 'forward_lookup: .invalid name -> 0';
is $F->('localhost'),          1, 'forward_lookup: localhost -> 1';
is scalar($F->(undef)), undef, 'forward_lookup: undef -> undef';
is scalar($F->('')),    undef, 'forward_lookup: empty -> undef';

my $L = \&Exec::Pairing::Identity::lookup_defaults_to_ip;
my %base = (hostname => 'agent-01.invalid', ip => '10.0.0.9', source_ip => '10.0.0.9');
ok  $L->({ %base, name_resolves => 0 }),               'unresolvable, no lookup_by -> ip';
ok !$L->({ %base, name_resolves => 1 }),               'resolvable -> hostname kept';
ok !$L->({ %base }),                                   'unknown (not recorded) -> unchanged';
ok !$L->({ %base, name_resolves => 0, lookup_by => 'hostname' }),
    'explicit agent --lookup-by hostname kept';
ok !$L->({ hostname => 'a', name_resolves => 0 }),     'no address to register by -> unchanged';

# End to end through approve (nothing is signed on a bad CA, so use the
# registry the same way the other approve tests do).
use File::Temp qw();
use JSON qw();
use Exec::CA qw();
use Exec::Registry qw();
use Exec::Agent::AgentPairing qw();
subtest 'approve registers by request' => sub {
    for my $c (
        [ 'unresolvable default', { name_resolves => 0 },                         undef,      'ip'       ],
        [ 'resolvable',           { name_resolves => 1 },                         undef,      'hostname' ],
        [ 'explicit hostname',    { name_resolves => 0, lookup_by => 'hostname' }, undef,      'hostname' ],
        [ 'approve override',     { name_resolves => 0 },                         'hostname', 'hostname' ],
    ) {
        my ($label, $extra, $override, $want) = @$c;
        my $got = _approve($extra, $override);
        is $got->{lookup_by}, $want, "$label -> $want";
        if ($label eq 'unresolvable default') {
            like $got->{out}, qr/Registered by IP: agent-01\.invalid does not resolve here/, 'approve says why';
            like $got->{out}, qr/edit-agent agent-01\.invalid --lookup-by hostname/, 'hint to switch back';
        }
        else { unlike $got->{out}, qr/Registered by IP/, "$label: no by-IP note" }
    }
};

{
    # The agent reports an address on another network (a second NIC): the
    # by-IP default registers the source IP, the one the dispatcher has seen.
    my $r = _approve({ name_resolves => 0, ip => '192.168.7.5', source_ip => '10.0.0.9' });
    is $r->{lookup_by}, 'ip', 'unresolvable default with a different reported IP: lookup_by ip';
    is $r->{ip}, '10.0.0.9', '... registered by the source IP, not the reported one';
}

done_testing;

sub _approve {
    my ($extra, $override) = @_;
    my $ca   = File::Temp::tempdir(CLEANUP => 1);
    my $pair = File::Temp::tempdir(CLEANUP => 1);
    my $reg  = File::Temp::tempdir(CLEANUP => 1);
    Exec::CA::generate_ca(ca_dir => $ca);
    Exec::CA::generate_dispatcher_cert(
        ca_dir => $ca, cert => "$ca/dispatcher.crt", key => "$ca/dispatcher.key");
    my $csr = Exec::Agent::AgentPairing::generate_key_and_csr(
        hostname => 'agent-01.invalid')->{csr_pem};
    open my $fh, '>', "$pair/abc123.json" or die $!;
    print $fh JSON::encode_json({ id => 'abc123', hostname => 'agent-01.invalid',
        ip => '10.0.0.9', source_ip => '10.0.0.9', csr => $csr, nonce => 'n',
        received => '2026-11-09T00:00:00Z', %$extra });
    close $fh;
    open my $save, '>&', \*STDOUT;
    my $out = '';
    close STDOUT; open STDOUT, '>', \$out or die;
    eval {
        Exec::Pairing::approve_request(reqid => 'abc123', ca_dir => $ca,
            pairing_dir => $pair, registry_dir => $reg,
            dispatcher_cert => "$ca/dispatcher.crt", dispatcher_id => 'd1',
            log_fn => sub {},
            (defined $override ? (lookup_by => $override) : ()));
    };
    my $err = $@;
    close STDOUT; open STDOUT, '>&', $save;
    diag $err if $err;
    my $rec = Exec::Registry::get_agent(registry_dir => $reg, hostname => 'agent-01.invalid') // {};
    $rec->{out} = $out;
    return $rec;
}
