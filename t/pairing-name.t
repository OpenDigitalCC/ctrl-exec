#!/usr/bin/perl
# t/pairing-name.t
#
# T-081: `request-pairing --name <name>` registers the agent under the name the
# operator chose instead of Net::Domain::hostfqdn(). The request carries it as
# its hostname and the CSR's CN is the same name. A name that is not a hostname
# is refused before any key is made or anything connects; without --name the
# request is named from the host's FQDN as before. Runs the real
# mode_request_pairing against a real pairing listener; the agent's /etc paths
# are redirected to a temp directory in a driver script.

use strict;
use warnings;
use feature qw(signatures);
no warnings qw(experimental::signatures);
use Test::More;
use File::Temp  qw(tempdir);
use JSON        qw(decode_json);
use FindBin     qw($Bin);
use POSIX       qw();
use Time::HiRes qw(sleep);
use lib         "$Bin/../lib", "$Bin/lib";
use ChildGuard  qw(guarded_fork);

use Exec::CA           qw();
use Exec::Pairing      qw();
use Exec::Agent::Server qw();

plan skip_all => 'openssl not available'
    unless system('openssl version >/dev/null 2>&1') == 0;

require IO::Select;

my $dir = ChildGuard::dir(tempdir(CLEANUP => 1));
ChildGuard::deadline(180);

sub slurp ($p) { open my $fh, '<', $p or die "$p: $!"; local $/; return scalar <$fh> }

my $ca_dir = "$dir/ca";
mkdir $ca_dir or die;
{
    open my $se, '>&', \*STDERR or die;
    open STDERR, '>', '/dev/null';
    Exec::CA::generate_ca(ca_dir => $ca_dir, bits => 2048);
    Exec::CA::generate_dispatcher_cert(ca_dir => $ca_dir, bits => 2048,
        cert => "$ca_dir/dispatcher.crt", key => "$ca_dir/dispatcher.key");
    open STDERR, '>&', $se;
}

my $pdir = "$dir/pairing";
pipe my $pr, my $pw or die;
my $lpid = guarded_fork() // die "fork: $!";
if ($lpid == 0) {
    close $pr;
    $pw->autoflush(1);
    open STDIN,  '<', '/dev/null';
    open STDOUT, '>', "$pdir.out";
    eval {
        Exec::Pairing::run_pairing_mode(
            port => 0, cert => "$ca_dir/dispatcher.crt", key => "$ca_dir/dispatcher.key",
            ca_dir => $ca_dir, pairing_dir => $pdir, timeout => 120,
            log_fn => sub ($e) { print $pw "$e->{PORT}\n" if $e->{ACTION} eq 'pairing-mode-start' },
        );
    };
    POSIX::_exit($@ ? 1 : 0);
}
close $pw;
my $port = IO::Select->new($pr)->can_read(15) ? scalar <$pr> : undef;
chomp $port if defined $port;
plan skip_all => 'pairing listener did not start' unless defined $port && $port =~ /\A\d+\z/;

# The driver loads bin/ctrl-exec-agent with its /etc and /var/lib paths
# pointed at the temp directory; the name (or "-") is its last argument.
my $agent = "$dir/agent";
mkdir $agent or die;
mkdir "$agent/state" or die;
my $driver = "$dir/driver.pl";
{
    open my $fh, '>', $driver or die;
    print $fh <<'PERL';
use strict; use warnings; use feature qw(signatures); no warnings qw(experimental::signatures);
my ($src, $agent, $port, $name) = @ARGV;
my $code = do { open my $in, "<", $src or die; local $/; <$in> };
$code =~ s{/etc/ctrl-exec-agent}{$agent}g;
$code =~ s{/var/lib/ctrl-exec-agent}{$agent/state}g;
eval "package main;\n#line 1 \"$src\"\n$code\n1" or die $@;
main::mode_request_pairing({ dispatcher => '127.0.0.1', port => $port,
    background => 1, timeout => 3,
    ($name ne '-' ? (name => $name) : ()) });
PERL
    close $fh;
}

sub run_agent ($name) {
    open my $save, '>&', \*STDERR or die;
    open STDERR, '>', "$dir/stderr";
    my $out = `$^X -I$Bin/../lib $driver $Bin/../bin/ctrl-exec-agent $agent $port \Q$name\E`;
    my $rc = $?;
    open STDERR, '>&', $save;
    return ($rc, $out, slurp("$dir/stderr"));
}

sub queued_for ($host) {
    for (1 .. 100) {
        for my $f (glob "$pdir/*.json") {
            my $q = eval { decode_json(slurp($f)) } or next;
            return ($q, $f) if ($q->{hostname} // '') eq $host;
        }
        sleep 0.1;
    }
    return;
}

sub csr_cn ($q) {
    my $f = "$dir/csr.pem";
    open my $fh, '>', $f or die;
    print $fh $q->{csr};
    close $fh;
    my $s = `openssl req -in \Q$f\E -noout -subject 2>&1`;
    return $s =~ m{CN\s*=\s*(\S+)} ? $1 : '';
}

# An invalid name: refused, non-zero, nothing queued, no connection made.
my @queued_before = glob "$pdir/*.json";
for my $bad ('bad_name', '-lead', 'trail-', 'a..b', 'a b', 'x' x 64, 'host.-x.example') {
    my ($rc, $out, $err) = run_agent($bad);
    isnt $rc, 0, "--name '$bad' exits non-zero";
    like $err, qr/--name must be a hostname/, "--name '$bad' is refused with a plain error";
    is $out, '', "--name '$bad' prints no request id";
}
is scalar(() = glob "$pdir/*.json"), scalar @queued_before, 'no invalid name reached the dispatcher';
ok !-e "$agent/agent.key", 'no key was made for an invalid name';

# A valid name, with and without a domain.
my ($rc, $out, $err) = run_agent('node-01.example.com');
is $rc, 0, '--name node-01.example.com is accepted' or diag $err;
like $out, qr/\A[0-9a-f]{8,}\n\z/, 'the request id is printed';
my ($q) = queued_for('node-01.example.com');
ok $q, 'the request carries the chosen name as its hostname';
is csr_cn($q // {}), 'node-01.example.com', 'the CSR CN is the chosen name';
unlike $err, qr/fully-qualified/, 'no FQDN warning when --name is given';

# Without --name: named from the FQDN, as before.
my $fqdn = Exec::Agent::Server::fqdn();
($rc, $out, $err) = run_agent('-');
is $rc, 0, 'without --name the request is made' or diag $err;
my ($d) = queued_for($fqdn);
ok $d, "without --name the request carries the FQDN ($fqdn)";
is csr_cn($d // {}), $fqdn, 'and the CSR CN is the FQDN';

# The listener may hold open connections from the waiting children; KILL it.
kill 'KILL', -$lpid, $lpid; waitpid $lpid, 0;
done_testing;
