#!/usr/bin/perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use File::Copy qw(copy);
use FindBin    qw($Bin);
use lib "$Bin/../lib";
use JSON       qw(decode_json);

use Exec::CA               qw();
use Exec::CertInfo         qw();
use Exec::Pairing          qw();
use Exec::Agent::AgentPairing qw();

# Regression: approve_request must read the dispatcher serial from the cert this
# dispatcher actually presents (config 'cert'), not a hardcoded dispatcher.crt.
# When they differ (e.g. a deployment whose cert is named ctrl-exec.crt), the
# old code stored an empty serial, so the agent trusted nothing and rejected
# every request as a "serial mismatch".

sub cert_serial {
    my ($path) = @_;
    my $out = `openssl x509 -noout -serial -in \Q$path\E 2>/dev/null`;
    # Canonicalise the same way the readers do (Exec::CertInfo::serial_to_hex) -
    # openssl can emit a leading 00 byte that the canonical form strips, so a raw
    # lc() here would not match the stored serial.
    return $out =~ /serial=([0-9A-Fa-f]+)/ ? Exec::CertInfo::serial_to_hex($1) : '';
}

my $ca   = tempdir(CLEANUP => 1);
my $pair = tempdir(CLEANUP => 1);
my $reg  = tempdir(CLEANUP => 1);

Exec::CA::generate_ca(ca_dir => $ca);

# First dispatcher cert -> dispatcher.crt (serial A). Save it as the deployment's
# actual presented cert under a *different* name, ctrl-exec.crt.
Exec::CA::generate_dispatcher_cert(
    ca_dir => $ca, cert => "$ca/dispatcher.crt", key => "$ca/dispatcher.key");
my $served_cert = "$ca/ctrl-exec.crt";
copy("$ca/dispatcher.crt", $served_cert) or die "copy: $!";
my $serial_served = cert_serial($served_cert);

# Re-key so the conventional dispatcher.crt now carries a DIFFERENT serial (B).
# A path-agnostic approve would deliver B; it must deliver the served A.
Exec::CA::generate_dispatcher_cert(
    ca_dir => $ca, cert => "$ca/dispatcher.crt", key => "$ca/dispatcher.key", force => 1);
my $serial_hardcoded = cert_serial("$ca/dispatcher.crt");

isnt $serial_served, $serial_hardcoded,
    'test setup: served cert and dispatcher.crt have distinct serials';
ok length $serial_served, 'served cert has a serial';

# Queue a pairing request with a real CSR.
sub queue_request {
    my ($id) = @_;
    my $pair_data = Exec::Agent::AgentPairing::generate_key_and_csr(hostname => 'test-agent');
    open my $fh, '>', "$pair/$id.json" or die $!;
    print $fh JSON::encode_json({
        id => $id, hostname => 'test-agent', csr => $pair_data->{csr_pem},
        nonce => 'n', source_ip => '10.0.0.6', ip => '10.0.0.6',
    });
    close $fh;
}

subtest 'serial comes from the configured (served) cert, not dispatcher.crt' => sub {
    queue_request('req1');
    Exec::Pairing::approve_request(
        reqid           => 'req1',
        ca_dir          => $ca,
        pairing_dir     => $pair,
        registry_dir    => $reg,
        dispatcher_cert => $served_cert,
        dispatcher_id   => 'disp-1',
        log_fn          => sub {},
    );
    my $approved = decode_json(do { local $/; open my $f, '<', "$pair/req1.approved" or die $!; <$f> });
    is $approved->{dispatcher_serial}, $serial_served,
        'approval delivers the served cert serial';
    isnt $approved->{dispatcher_serial}, $serial_hardcoded,
        'and not the hardcoded dispatcher.crt serial';
    my $rec = decode_json(do { local $/; open my $f, '<', "$reg/test-agent.json" or die $!; <$f> });
    is $rec->{dispatcher_serial}, $serial_served, 'registry records the served serial';
    is $rec->{serial_status}, 'current', 'serial_status current when serial known';
};

subtest 'missing cert path -> empty serial and a warning' => sub {
    queue_request('req2');
    my @warns;
    local $SIG{__WARN__} = sub { push @warns, $_[0] };
    Exec::Pairing::approve_request(
        reqid           => 'req2',
        ca_dir          => $ca,
        pairing_dir     => $pair,
        registry_dir    => $reg,
        dispatcher_cert => "$ca/does-not-exist.crt",
        dispatcher_id   => 'disp-1',
        log_fn          => sub {},
    );
    my $approved = decode_json(do { local $/; open my $f, '<', "$pair/req2.approved" or die $!; <$f> });
    is $approved->{dispatcher_serial}, '', 'empty serial when cert path is wrong';
    like "@warns", qr/serial mismatch/, 'warns that requests will be rejected';
};

done_testing;
