#!/usr/bin/perl
# Per-profile `writable` enforcement, end to end. The executor's mount-namespace
# path only runs as root, so this skips unless run as root (e.g. sudo prove). It
# was validated on-host (Linux 6.12) when first added.
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use FindBin    qw($Bin);
use lib "$Bin/../lib";
use POSIX qw();

use Exec::Agent::ExecClient qw();

plan skip_all => 'must run as root (the executor mount-namespace path)' unless $> == 0;
my $cc = `command -v gcc 2>/dev/null`; chomp $cc;
plan skip_all => 'gcc not available' unless $cc && -x $cc;

# /var/tmp, not /tmp: the profile mounts a private tmpfs on /tmp which would
# shadow files placed under it.
my $TMP = tempdir(DIR => '/var/tmp', CLEANUP => 1);
my $BIN = "$TMP/ctrl-exec-exec";
system($cc, '-O2', '-o', $BIN, "$Bin/../src/ctrl-exec-exec.c", '-lcap') == 0
    or plan skip_all => 'could not compile the executor';

my $WOK     = "$TMP/writable";  mkdir $WOK;
my $OUTSIDE = "$TMP/outside";   mkdir $OUTSIDE;

my $probe = "$TMP/probe.sh";
open my $p, '>', $probe or die $!;
print $p <<'SH';
#!/bin/sh
if echo ok > "$1/f" 2>/dev/null;        then echo "INSIDE=ok";  else echo "INSIDE=denied";  fi
if echo ok > "$2/f" 2>/dev/null;        then echo "OUTSIDE=ok"; else echo "OUTSIDE=denied"; fi
if echo ok > /tmp/ce-probe 2>/dev/null; then echo "TMP=ok";    else echo "TMP=denied";    fi
SH
close $p;
chmod 0755, $probe;

my $agent_conf = "$TMP/agent.conf";
open my $a, '>', $agent_conf or die $!;
print $a "port = 7443\ncert = /x\nkey = /y\nca = /z\nscript_dirs = $TMP\n"
       . "[profile confined]\nwritable = $WOK\n";
close $a;
my $scripts_conf = "$TMP/scripts.conf";
open my $s, '>', $scripts_conf or die $!;
print $s "probe = $probe profile=confined\n";
close $s;

my $sock = "$TMP/exec.sock";
my $pid  = fork();
die "fork: $!" unless defined $pid;
if ($pid == 0) {
    exec($BIN, 'serve', $sock, $agent_conf, $scripts_conf, getpwuid($>)) or POSIX::_exit(127);
}
my $ready = 0;
for (1 .. 100) { if (-S $sock) { $ready = 1; last } select undef, undef, undef, 0.05 }
ok $ready, 'executor created its socket' or do { kill 'TERM', $pid; done_testing; exit };

my $r = Exec::Agent::ExecClient::run(
    socket => $sock, reqid => 'w1', script => 'probe', args => [$WOK, $OUTSIDE]);
kill 'TERM', $pid; waitpid $pid, 0;

my $out = $r->{stdout} // '';
like $out, qr/INSIDE=ok/,      'write inside the writable path succeeds';
like $out, qr/OUTSIDE=denied/, 'write outside is denied (read-only fs, even as root)';
like $out, qr/TMP=ok/,         'private /tmp is writable';

done_testing;
