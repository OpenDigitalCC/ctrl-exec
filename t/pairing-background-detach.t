#!/usr/bin/perl
# t/pairing-background-detach.t
#
# T-078: `reqid=$(ctrl-exec-agent request-pairing --background ...)` returns as
# soon as the request id is printed. The waiting child used to keep the
# caller's stdout, so $(...) read until the child exited (approval or timeout).
# The child now runs in its own session with stdin/stdout/stderr on /dev/null.
# Runs the real mode_request_pairing against a real pairing listener; the
# agent's /etc paths are redirected to a temp directory in a driver script.

use strict;
use warnings;
use feature qw(signatures);
no warnings qw(experimental::signatures);
use Test::More;
use File::Temp  qw(tempdir);
use JSON        qw(decode_json);
use FindBin     qw($Bin);
use POSIX       qw();
use Time::HiRes qw(sleep time);
use lib         "$Bin/../lib", "$Bin/lib";
use ChildGuard  qw(guarded_fork);

use Exec::CA      qw();
use Exec::Pairing qw();

plan skip_all => 'openssl not available'
    unless system('openssl version >/dev/null 2>&1') == 0;

require IO::Select;

my $dir = ChildGuard::dir(tempdir(CLEANUP => 1));
ChildGuard::deadline(120);
my $TIMEOUT = 8;   # the child's own wait; the failing case ends by it

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

# A real pairing listener on a free port.
my $pdir = "$dir/pairing";
my $rdir = "$dir/registry";
mkdir $rdir or die;
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
            ca_dir => $ca_dir, pairing_dir => $pdir, timeout => 60,
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
# pointed at the temp directory, and runs the request-pairing handler.
my $agent = "$dir/agent";
mkdir $agent or die;
mkdir "$agent/state" or die;
my $driver = "$dir/driver.pl";
{
    open my $fh, '>', $driver or die;
    print $fh <<'PERL';
use strict; use warnings; use feature qw(signatures); no warnings qw(experimental::signatures);
my ($src, $agent, $port, $timeout) = @ARGV;
my $code = do { open my $in, "<", $src or die; local $/; <$in> };
$code =~ s{/etc/ctrl-exec-agent}{$agent}g;
$code =~ s{/var/lib/ctrl-exec-agent}{$agent/state}g;
eval "package main;\n#line 1 \"$src\"\n$code\n1" or die $@;
require Exec::Agent::AgentPairing;
{
    no warnings 'redefine';
    my $orig = \&Exec::Agent::AgentPairing::store_certs;
    *Exec::Agent::AgentPairing::store_certs = sub (%o) {
        $orig->(%o, cert_dir => $agent, trusted_path => "$agent/state/dispatchers");
    };
}
mkdir "$agent/state";
main::mode_request_pairing({ dispatcher => '127.0.0.1', port => $port,
    background => 1, timeout => $timeout });
PERL
    close $fh;
}

sub queued {
    for (1 .. 100) {
        my ($f) = glob "$pdir/*.json";
        if ($f) { my $q = eval { decode_json(slurp($f)) }; return $q if $q }
        sleep 0.1;
    }
    return undef;
}

# Capture stdout through a pipe and read to EOF, as $(...) does. The agent
# generates a key first (seconds), so the clock starts when the request shows
# in the dispatcher's queue; the id is printed just after, and EOF must follow
# within 3 seconds of that. Gives up after 90 seconds in all.
open my $save_err, '>&', \*STDERR or die;
open STDERR, '>', '/dev/null';
my $t0 = time;
my $cpid = open(my $out, '-|', $^X, "-I$Bin/../lib", $driver,
    "$Bin/../bin/ctrl-exec-agent", $agent, $port, $TIMEOUT) or die "spawn: $!";
my ($buf, $eof, $tq, $took) = ('', 0, undef, undef);
my $sel = IO::Select->new($out);
while (time - $t0 < 90) {
    $tq //= time if glob "$pdir/*.json";
    if ($sel->can_read(0.1)) {
        my $n = sysread $out, $buf, 4096, length $buf;
        if (!$n) { $eof = 1; last }
    }
    last if defined $tq && time - $tq > 3 + $TIMEOUT;
}
$took = defined $tq ? time - $tq : undef;
open STDERR, '>&', $save_err;

ok defined $tq, "the request reached the dispatcher";
ok $eof && $took < 3, 'stdout reaches EOF within 3 seconds of the request being queued, as $(...) needs'
    or diag sprintf 'EOF %s, %.1fs after queuing (the child holds the caller\'s stdout)',
        ($eof ? 'reached' : 'not reached'), $took // -1;
like $buf, qr/\A[0-9a-f]{8,}\n\z/, 'what was read is the request id and nothing else';

# The child is still waiting: approve, and the certificate is stored.
my $q = queued();
ok $q, 'the request is queued at the dispatcher';
is $buf, ($q ? "$q->{id}\n" : ''), 'the id printed is the queued request id';

if ($q) {
    open my $so, '>&', \*STDOUT or die;
    open STDOUT, '>', '/dev/null';
    eval {
        Exec::Pairing::approve_request(reqid => $q->{id}, ca_dir => $ca_dir,
            pairing_dir => $pdir, registry_dir => $rdir,
            dispatcher_cert => "$ca_dir/dispatcher.crt", dispatcher_id => 'd1');
    };
    my $e = $@;
    open STDOUT, '>&', $so;
    ok !$e, 'approved' or diag $e;
}
my $stored = 0;
for (1 .. 100) { if (-s "$agent/agent.crt" && -s "$agent/ca.crt") { $stored = 1; last } sleep 0.1 }
ok $stored, 'the waiting child stored the certificate after approval';
like(($stored ? slurp("$agent/agent.crt") : ''), qr/BEGIN CERTIFICATE/, 'a certificate was written');

close $out;
kill 'TERM', -$lpid, $lpid; waitpid $lpid, 0;
done_testing;
