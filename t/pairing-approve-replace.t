#!/usr/bin/perl
use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/../lib";

use File::Temp qw();
use JSON qw();
use Exec::CA qw();
use Exec::Pairing qw();
use Exec::Registry qw();
use Exec::Agent::AgentPairing qw();

# T-082: a request from the address of another registered agent is noted;
# approve --replace removes that other record once the new one is registered.

my $csr = Exec::Agent::AgentPairing::generate_key_and_csr(
    hostname => 'agent-02.example.com')->{csr_pem};

sub rig {
    my (%o) = @_;
    my %r = map { $_ => File::Temp::tempdir(CLEANUP => 1) } qw(ca pair reg);
    Exec::CA::generate_ca(ca_dir => $r{ca});
    Exec::CA::generate_dispatcher_cert(
        ca_dir => $r{ca}, cert => "$r{ca}/dispatcher.crt", key => "$r{ca}/dispatcher.key");
    for my $h (@{ $o{agents} // [] }) {
        Exec::Registry::register_agent(registry_dir => $r{reg}, hostname => $h->[0],
            ip => $h->[1], expiry => '2027-01-01T00:00:00Z');
    }
    open my $fh, '>', "$r{pair}/abc123.json" or die $!;
    print $fh JSON::encode_json({ id => 'abc123', hostname => 'agent-02.example.com',
        ip => '10.0.0.9', source_ip => $o{source_ip} // '10.0.0.9', csr => $csr,
        nonce => 'n', received => '2026-11-09T00:00:00Z', name_resolves => 1 });
    close $fh;
    return \%r;
}

sub approve {
    my ($r, %extra) = @_;
    my @log;
    open my $save, '>&', \*STDOUT;
    my $out = '';
    close STDOUT; open STDOUT, '>', \$out or die;
    eval {
        Exec::Pairing::approve_request(reqid => 'abc123', ca_dir => $r->{ca},
            pairing_dir => $r->{pair}, registry_dir => $r->{reg},
            dispatcher_cert => "$r->{ca}/dispatcher.crt", dispatcher_id => 'd1',
            log_fn => sub { push @log, $_[0] }, %extra);
    };
    my $err = $@;
    close STDOUT; open STDOUT, '>&', $save;
    return { out => $out, err => $err, log => \@log };
}

sub names { join ',', map { $_->{hostname} } @{ Exec::Registry::list_agents(registry_dir => $_[0]{reg}) } }

my @old = ([ 'agent-01.example.com', '10.0.0.9' ], [ 'other.example.com', '10.0.0.77' ]);

subtest 'note shown for a matching source IP only' => sub {
    my $r = rig(agents => \@old);
    my $req = JSON::decode_json(do { local (@ARGV, $/) = "$r->{pair}/abc123.json"; <> });
    my @n = Exec::Pairing::replace_note_lines($req, registry_dir => $r->{reg});
    is scalar @n, 1, 'one note';
    like $n[0], qr/^agent-01\.example\.com is registered at this address \(approve --replace to remove it\)$/, 'text';
    unlike $n[0], qr/other\.example\.com/, 'other address not named';

    my $r2 = rig(agents => \@old, source_ip => '10.0.0.50');
    my $req2 = { %$req, source_ip => '10.0.0.50' };
    is scalar(() = Exec::Pairing::replace_note_lines($req2, registry_dir => $r2->{reg})), 0, 'no match, no note';

    my $r3 = rig(agents => [ [ 'agent-02.example.com', '10.0.0.9' ] ]);
    is scalar(() = Exec::Pairing::replace_note_lines($req, registry_dir => $r3->{reg})), 0,
        'same name is an ordinary re-pair, no note';
};

subtest 'no flag, no removal' => sub {
    my $r = rig(agents => \@old);
    my $a = approve($r);
    is $a->{err}, '', 'approved';
    is names($r), 'agent-01.example.com,agent-02.example.com,other.example.com', 'nothing removed';
    like $a->{out}, qr/agent-01\.example\.com is registered at this address; not removed \(approve --replace removes it\)/, 'note in output';
    ok !(grep { $_->{ACTION} eq 'unpair' } @{ $a->{log} }), 'no unpair logged';
};

subtest '--replace removes the other record' => sub {
    my $r = rig(agents => \@old);
    my $a = approve($r, replace => 1);
    is $a->{err}, '', 'approved';
    is names($r), 'agent-02.example.com,other.example.com', 'old removed, new registered, unrelated kept';
    my ($u) = grep { $_->{ACTION} eq 'unpair' } @{ $a->{log} };
    is $u->{AGENT}, 'agent-01.example.com', 'unpair logged for the old agent';
    is $u->{REPLACED_BY}, 'agent-02.example.com', 'REPLACED_BY';
    like $a->{out}, qr/unregistered 'agent-01\.example\.com'/, 'says what was removed';
    like $a->{out}, qr/certificate remains valid until: 2027-01-01/, 'certificate warning';
};

subtest '--replace removes every match' => sub {
    my $r = rig(agents => [ @old, [ 'agent-03.example.com', '10.0.0.9' ] ]);
    my $a = approve($r, replace => 1);
    is names($r), 'agent-02.example.com,other.example.com', 'both removed';
    is scalar(grep { $_->{ACTION} eq 'unpair' } @{ $a->{log} }), 2, 'two unpairs logged';
    my $req = { source_ip => '10.0.0.9', hostname => 'x' };
    my $r2 = rig(agents => [ @old, [ 'agent-03.example.com', '10.0.0.9' ] ]);
    like( (Exec::Pairing::replace_note_lines($req, registry_dir => $r2->{reg}))[0],
        qr/^agent-01\.example\.com, agent-03\.example\.com are registered at this address \(approve --replace to remove them\)$/,
        'several listed' );
};

subtest 'failed approve removes nothing' => sub {
    my $r = rig(agents => \@old);
    my $a = approve($r, replace => 1, ca_dir => "$r->{ca}/missing");
    ok $a->{err}, 'approve failed';
    is names($r), 'agent-01.example.com,other.example.com', 'registry untouched';
    ok !(grep { $_->{ACTION} eq 'unpair' } @{ $a->{log} }), 'no unpair logged';
};

done_testing;
