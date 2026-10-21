#!/usr/bin/perl
# t/ca-subject-aki.t
#
# T-062: a new dispatcher CA gets a subject of its own - "ctrl-exec CA", the
# dispatcher id and a random suffix - instead of the shared "ctrl-exec CA", and
# every certificate the CA issues (agent and dispatcher) carries Subject and
# Authority Key Identifiers and CA:FALSE. An agent trusts a bundle of several
# dispatcher CAs; with two same-named CAs and a leaf without an AKI, OpenSSL
# can pick the wrong issuer.

use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use FindBin    qw($Bin);
use lib        "$Bin/../lib";
use Exec::CA       qw();
use Exec::CertInfo qw();

plan skip_all => 'openssl not available'
    unless system('openssl version >/dev/null 2>&1') == 0;

my $dir = tempdir(CLEANUP => 1);

sub quiet {
    my ($code) = @_;
    open my $se, '>&', \*STDERR or die;
    open STDERR, '>', '/dev/null';
    my @r = eval { $code->() };
    my $err = $@;
    open STDERR, '>&', $se;
    die $err if $err;
    return @r;
}
sub slurp { open my $fh, '<', $_[0] or die "$_[0]: $!"; local $/; return scalar <$fh> }

like Exec::CA::default_ca_cn('d1'), qr/\Actrl-exec CA d1 [0-9a-f]{8}\z/, 'id and random suffix';
isnt Exec::CA::default_ca_cn('d1'), Exec::CA::default_ca_cn('d1'),
    'two CAs for the same id differ';
like Exec::CA::default_ca_cn(), qr/\Actrl-exec CA [0-9a-f]{8}\z/, 'without an id';
like Exec::CA::default_ca_cn('bad id/x'), qr/\Actrl-exec CA [0-9a-f]{8}\z/,
    'an unusable id is left out';

my %subject;
for my $id (qw(d1 d2)) {
    my $d = "$dir/$id";
    mkdir $d or die;
    quiet(sub {
        Exec::CA::generate_ca(ca_dir => $d, bits => 2048, id => $id);
        Exec::CA::generate_dispatcher_cert(ca_dir => $d, bits => 2048,
            cert => "$d/dispatcher.crt", key => "$d/dispatcher.key");
    });
    $subject{$id} = Exec::CertInfo::subject_from_pem(slurp("$d/ca.crt"));
    like $subject{$id}, qr/\ACN=ctrl-exec CA $id [0-9a-f]{8}\z/, "$id CA subject ($subject{$id})";
}
isnt $subject{d1}, $subject{d2}, 'two dispatchers, two CA names';

{
    my $d = "$dir/explicit";
    mkdir $d or die;
    quiet(sub { Exec::CA::generate_ca(ca_dir => $d, bits => 2048, cn => 'My CA') });
    is Exec::CertInfo::subject_from_pem(slurp("$d/ca.crt")), 'CN=My CA', 'an explicit cn is kept';
}

my $disp = `openssl x509 -noout -text -in $dir/d1/dispatcher.crt`;
my $ca   = `openssl x509 -noout -text -in $dir/d1/ca.crt`;
my ($ca_ski) = $ca =~ /Subject Key Identifier:\s*\n\s*(\S+)/;
my ($aki)    = $disp =~ /Authority Key Identifier:\s*\n\s*(?:keyid:)?(\S+)/;
ok $ca_ski, 'the CA has a Subject Key Identifier';
is $aki, $ca_ski, "dispatcher certificate's AKI is the CA's key id";
like $disp, qr/Subject Key Identifier/, 'and it has its own SKI';
like $disp, qr/CA:FALSE/, 'and is not a CA';

quiet(sub { system('openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes',
    '-keyout', "$dir/a.key", '-out', "$dir/a.csr", '-subj', '/CN=agent-01') == 0 or die });
my ($agent) = quiet(sub { Exec::CA::sign_csr(csr_pem => slurp("$dir/a.csr"), ca_dir => "$dir/d1") });
open my $fh, '>', "$dir/a.crt" or die;
print $fh $agent;
close $fh;
my $text = `openssl x509 -noout -text -in $dir/a.crt`;
($aki) = $text =~ /Authority Key Identifier:\s*\n\s*(?:keyid:)?(\S+)/;
is $aki, $ca_ski, "agent certificate's AKI is the CA's key id";
like $text, qr/CA:FALSE/, 'agent certificate is not a CA';
is Exec::CertInfo::verify_issued_by($agent, slurp("$dir/d1/ca.crt")), undef, 'verifies under its CA';
like Exec::CertInfo::verify_issued_by($agent, slurp("$dir/d2/ca.crt")) // '', qr/\S/,
    'not under the other CA';

done_testing;
