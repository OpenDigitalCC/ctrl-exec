#!/usr/bin/perl
# T-084: the agent's default name has no trailing dots and always has a valid
# form; the dispatcher refuses a new pairing request named 'host..' but a
# registry record already named that still loads.
use strict;
use warnings;
use feature qw(signatures);
no warnings qw(experimental::signatures);
use Test::More;
use File::Temp qw(tempdir);
use JSON       qw(encode_json decode_json);
use FindBin    qw($Bin);
use lib        "$Bin/../lib";

use Exec::Agent::Server qw();
use Exec::Pairing       qw();
use Exec::Registry      qw();
use Exec::Log           qw();

Exec::Log::init('test');
{ no warnings 'redefine'; *Exec::Log::log_action = sub {}; }

# --- fqdn() ---
my ($hostfqdn, $short);
{
    no warnings 'redefine';
    require Net::Domain;
    *Net::Domain::hostfqdn   = sub { $hostfqdn };
    *Exec::Agent::Server::hostname = sub { $short };
}
sub name_for ($f, $s = 'host') {
    ($hostfqdn, $short) = ($f, $s);
    $Exec::Agent::Server::FQDN = undef;
    return Exec::Agent::Server::fqdn();
}
is name_for('host..'),               'host', "'host..' becomes the short name";
is name_for('host.'),                'host', "'host.' becomes the short name";
is name_for('host.example.com'),     'host.example.com', 'a valid FQDN is unchanged';
is name_for('host.example.com.'),    'host.example.com', 'a rooted FQDN loses its dot';
is name_for('host', 'host'),         'host', 'no domain: hostname()';
is name_for(undef, 'short1'),        'short1', 'no hostfqdn: hostname()';
is name_for('bad_name.example.com', 'short2'), 'short2', 'invalid FQDN: hostname()';

# --- dispatcher: new request ---
my $d = tempdir(CLEANUP => 1);
my $CSR = do {
    system("openssl genrsa -out $d/k 2048 2>/dev/null") == 0
        && system("openssl req -new -key $d/k -out $d/c -subj /CN=x 2>/dev/null") == 0
        or die "openssl failed\n";
    open my $fh, '<', "$d/c" or die; local $/; <$fh>;
};
sub pair_reply ($hostname) {
    my $body = encode_json({ hostname => $hostname, csr => $CSR, nonce => 'aabbccddaabbccdd' });
    my $req = "POST /pair HTTP/1.0\r\nContent-Type: application/json\r\n"
            . "Content-Length: " . length($body) . "\r\n\r\n$body";
    require IO::Socket::UNIX;
    my ($client, $server) = IO::Socket::UNIX->socketpair(
        IO::Socket::AF_UNIX(), IO::Socket::SOCK_STREAM(), 0) or die "socketpair: $!";
    print $client $req;
    $client->shutdown(1);
    my @log;
    Exec::Pairing::_handle_pair_request($server, '127.0.0.1', sub { push @log, $_[0] }, 10, "$d/pairing-$hostname");
    $server->close;
    local $/;
    my $raw = <$client> // '';
    return ($raw, \@log);
}
for my $bad ('host..', 'host.', 'bad_name') {
    my ($raw, $log) = pair_reply($bad);
    like $raw, qr/invalid hostname/, "new request '$bad' refused";
    is $log->[0]{REASON}, 'invalid-hostname', "  logged invalid-hostname";
}

# --- registry: an existing record keeps loading ---
my $reg = "$d/registry";
Exec::Registry::register_agent(hostname => 'host..', ip => '192.0.2.5', registry_dir => $reg);
my $rec = Exec::Registry::get_agent(hostname => 'host..', registry_dir => $reg);
is $rec && $rec->{hostname}, 'host..', "registry record 'host..' still loads";
ok( (grep { $_ eq 'host..' } @{ Exec::Registry::list_hostnames(registry_dir => $reg) }), 'and is listed');
ok Exec::Registry::valid_agent_name('host..'), 'valid_agent_name unchanged';

done_testing;
