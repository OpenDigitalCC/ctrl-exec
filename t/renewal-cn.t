#!/usr/bin/perl
# T-084: a renewal CSR carries the CN of the agent's current certificate, so an
# agent registered as 'host..' or under 'request-pairing --name' renews under
# its registered name; with no usable certificate it falls back to fqdn().
use strict;
use feature qw(signatures);
use warnings;
use Test::More;
no warnings qw(experimental::signatures);
use File::Temp qw(tempdir);
use FindBin    qw($Bin);
use lib "$Bin/../lib";

use Exec::Agent::Server qw();

plan skip_all => 'openssl not available'
    unless system('openssl version >/dev/null 2>&1') == 0;

my $dir = tempdir(CLEANUP => 1);
no warnings 'redefine';
local *Exec::Agent::Server::fqdn = sub { 'fqdn-name.example.com' };

sub make_cert ($cn, $file) {
    system("openssl req -x509 -newkey rsa:2048 -nodes -keyout $dir/k.pem -out $file -days 2 -subj '/CN=$cn' >/dev/null 2>&1") == 0
        or die "openssl failed";
}

for my $cn ('host..', 'foo', 'agent-01.example.com') {
    make_cert($cn, "$dir/c.crt");
    my $name = Exec::Agent::Server::renewal_cn({ cert => "$dir/c.crt" });
    is $name, $cn, "CN '$cn' read from the certificate";
}

is Exec::Agent::Server::renewal_cn({ cert => "$dir/none.crt" }), 'fqdn-name.example.com',
    'missing certificate: fqdn()';
open my $fh, '>', "$dir/bad.crt" or die; print $fh "junk\n"; close $fh;
is Exec::Agent::Server::renewal_cn({ cert => "$dir/bad.crt" }), 'fqdn-name.example.com',
    'unreadable certificate: fqdn()';
is Exec::Agent::Server::renewal_cn({}), 'fqdn-name.example.com', 'no cert configured: fqdn()';

done_testing;
