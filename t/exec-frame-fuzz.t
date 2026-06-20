#!/usr/bin/perl
# t/exec-frame-fuzz.t  (TC-007)
#
# Fuzz-lite for the executor's framed-request parser (handle_conn / take_field).
# The executor runs as root and reads a length-prefixed binary frame from the
# socket; the front-end is the only authorised peer, but the bounds checks
# (MAX_FRAME, the per-field length validation, MAX_ARGS, the argc check) are the
# defence if that peer is compromised or buggy. The happy-path round-trip test
# never feeds malformed frames - the exact inputs those checks exist to reject.
# Here we feed truncated / oversized / over-cap / length-overrun frames and
# assert the executor either replies "malformed request" or closes the
# connection, WITHOUT crashing or hanging, and that the serve loop survives
# (a valid request afterwards still works).

use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use FindBin    qw($Bin);
use lib "$Bin/../lib";
use POSIX qw();
use IO::Socket::UNIX qw();

my $cc = `command -v gcc 2>/dev/null`; chomp $cc;
plan skip_all => 'gcc not available' unless $cc && -x $cc;

my $TMP = tempdir(CLEANUP => 1);
my $BIN = "$TMP/ctrl-exec-exec";
system($cc, '-O2', '-o', $BIN, "$Bin/../src/ctrl-exec-exec.c", '-lcap') == 0
    or plan skip_all => 'could not compile src/ctrl-exec-exec.c';

my $script = "$TMP/ok.sh";
open my $sf, '>', $script or die $!;
print $sf "#!/bin/sh\necho alive\n";
close $sf;
chmod 0755, $script;

my $agent_conf = "$TMP/agent.conf";
open my $af, '>', $agent_conf or die $!;
print $af "port = 7443\ncert = /x\nkey = /y\nca = /z\nscript_dirs = $TMP\n[profile default]\n";
close $af;
my $scripts_conf = "$TMP/scripts.conf";
open my $cf, '>', $scripts_conf or die $!;
print $cf "ok = $script\n";
close $cf;

my $sock = "$TMP/exec.sock";
my $user = getpwuid($>);
my $pid  = fork();
die "fork: $!" unless defined $pid;
if ($pid == 0) {
    $ENV{CTRL_EXEC_EXEC_ALLOW_UNPRIV} = 1;
    exec($BIN, 'serve', $sock, $agent_conf, $scripts_conf, $user) or POSIX::_exit(127);
}
my $ready = 0;
for (1 .. 100) { if (-S $sock) { $ready = 1; last } select undef, undef, undef, 0.05 }
ok $ready, 'executor created its socket' or do { kill 'TERM', $pid; done_testing; exit };

# Frame helpers.
sub field { my ($s) = @_; return pack('N', length $s) . $s; }
sub framed { my $body = join('', @_); return pack('N', length $body) . $body; }

# Send raw bytes, half-close, read the whole reply (bounded by a timeout so a
# hang is a test failure, not an infinite wait). Returns { resp, timeout }.
sub exchange {
    my ($bytes) = @_;
    my $c = IO::Socket::UNIX->new(Peer => $sock, Type => IO::Socket::SOCK_STREAM())
        or return { resp => '', timeout => 0, connect_err => "$!" };
    $c->syswrite($bytes);
    $c->shutdown(1);            # signal EOF on our write side
    my $resp = '';
    my $timed_out = 0;
    eval {
        local $SIG{ALRM} = sub { die "timeout\n" };
        alarm 5;
        while (1) { my $buf; my $n = $c->sysread($buf, 65536); last if !$n; $resp .= $buf; }
        alarm 0;
        1;
    } or $timed_out = ($@ =~ /timeout/ ? 1 : 0);
    $c->close;
    return { resp => $resp, timeout => $timed_out };
}

# Pull the stderr field out of a [i32 exit][field out][field err] response.
sub resp_stderr {
    my ($resp) = @_;
    return '' if length($resp) < 12;
    my $olen = unpack('N', substr($resp, 4, 4));
    return '' if length($resp) < 8 + $olen + 4;
    my $elen = unpack('N', substr($resp, 8 + $olen, 4));
    return substr($resp, 12 + $olen, $elen);
}

# A well-formed request body (4 fields + argc=0), reused for the over-cap argc case.
my $good_head = field('reqid') . field('disp') . field('ok') . field('');

my @cases = (
    { name => 'total = 0',                bytes => pack('N', 0),                 expect => 'close' },
    { name => 'total > MAX_FRAME (17 MB)', bytes => pack('N', 17_000_000),       expect => 'close' },
    { name => 'truncated body (declares 100, sends 4)',
      bytes => pack('N', 100) . 'abcd',                                          expect => 'close' },
    { name => 'field length overruns the frame',
      bytes => framed(pack('N', 1000) . 'xxxx'),                                 expect => 'malformed' },
    { name => 'argc over MAX_ARGS',
      bytes => framed($good_head . pack('N', 9999)),                             expect => 'malformed' },
    { name => 'truncated arg field',
      bytes => framed($good_head . pack('N', 1) . pack('N', 50) . 'no'),         expect => 'malformed' },
);

for my $c (@cases) {
    my $r = exchange($c->{bytes});
    ok !$r->{timeout}, "$c->{name}: executor did not hang";
    if ($c->{expect} eq 'close') {
        is $r->{resp}, '', "$c->{name}: connection closed with no response";
    }
    else {
        like resp_stderr($r->{resp}), qr/malformed request/,
            "$c->{name}: rejected as malformed";
    }
}

# The serve loop must have survived every hostile frame: a valid request works.
subtest 'serve loop survives the fuzzing - a valid request still works' => sub {
    require Exec::Agent::ExecClient;
    my $r = Exec::Agent::ExecClient::run(
        socket => $sock, reqid => 'after', script => 'ok', args => []);
    is $r->{exit}, 0, 'valid request after fuzzing succeeds';
    like $r->{stdout}, qr/alive/, 'and the executor is still serving';
};

kill 'TERM', $pid; waitpid $pid, 0;
done_testing;
