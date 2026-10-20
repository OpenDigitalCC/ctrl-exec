#!/usr/bin/perl
# T-038: a script that exits without reading its stdin must not kill the writer.
#
# Exec::Agent::Runner writes the request context to the script's stdin. If the
# script has already exited, the write hits a pipe with no reader; with SIGPIPE
# at its default disposition that kills the writing process (the agent's
# per-connection handler in production). The context here (1 MiB) is larger
# than a pipe buffer, so the write must wait for the script to exit and then
# fail: the race always happens. The same race in the C executor was T-034
# (t/exec-sigpipe.t).
#
# Each run_script call is made in a forked child so that a SIGPIPE death is
# reported as a failed assertion instead of ending this test.
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use FindBin    qw($Bin);
use lib "$Bin/../lib";
use POSIX      qw(WIFSIGNALED WTERMSIG);
use JSON       qw(encode_json decode_json);

use Exec::Agent::Runner qw();

plan skip_all => '/proc/self/status not readable' unless -r '/proc/self/status';

my $TMP = tempdir(CLEANUP => 1);

sub script {
    my ($name, $body) = @_;
    my $p = "$TMP/$name";
    open my $fh, '>', $p or die $!;
    print $fh "#!/bin/sh\n$body";
    close $fh;
    chmod 0755, $p;
    return $p;
}

# Exits at once without reading stdin.
my $early = script('early.sh', "echo early-exit-ok\nexit 3\n");

# Reports whether SIGPIPE (signal 13, bit 12 of SigIgn) is ignored in the script
# (the shell's own status, read with builtins only).
my $disp = script('sigpipe.sh', <<'SH');
mask=0
while read -r k v; do [ "$k" = "SigIgn:" ] && mask=$v; done < /proc/$$/status
if [ $(( 0x$mask & 0x1000 )) -ne 0 ]; then echo sigpipe=ignored; else echo sigpipe=default; fi
SH

# Run run_script in a child; returns (wait status, result hashref or undef).
sub run_forked {
    my ($sigpipe, @args) = @_;
    pipe my $r, my $w or die $!;
    my $pid = fork();
    die "fork: $!" unless defined $pid;
    if ($pid == 0) {
        close $r;
        $SIG{PIPE} = $sigpipe;
        my $res = Exec::Agent::Runner::run_script(@args);
        print $w encode_json($res);
        close $w;
        POSIX::_exit(0);
    }
    close $w;
    my $out = do { local $/; <$r> };
    close $r;
    waitpid $pid, 0;
    return ($?, length($out // '') ? decode_json($out) : undef);
}

my $big = { payload => 'x' x (1024 * 1024) };     # larger than any pipe buffer

subtest 'script exits without reading stdin: writer survives' => sub {
    for my $n (1 .. 3) {
        my ($st, $res) = run_forked('DEFAULT', $early, [], $big, 10);
        ok !WIFSIGNALED($st), "run $n: writer not killed by a signal"
            or diag 'killed by signal ' . WTERMSIG($st);
        next unless $res;
        is $res->{exit}, 3, "run $n: the script's own exit code";
        like $res->{stdout}, qr/early-exit-ok/, "run $n: stdout delivered";
        is $res->{stderr}, '', "run $n: no error text";
    }
};

subtest 'script starts with SIGPIPE at its default disposition' => sub {
    for my $case ([ 'DEFAULT', 'agent has SIGPIPE default' ],
                  [ 'IGNORE',  'agent has SIGPIPE ignored' ]) {
        my ($st, $res) = run_forked($case->[0], $disp, [], { a => 1 }, 10);
        ok $res, "$case->[1]: result returned" or next;
        like $res->{stdout}, qr/sigpipe=default/, "$case->[1]: script has SIG_DFL";
    }
};

subtest 'caller SIGPIPE disposition is restored after the write' => sub {
    local $SIG{PIPE} = 'DEFAULT';
    Exec::Agent::Runner::run_script($early, [], { a => 1 }, 10);
    is $SIG{PIPE}, 'DEFAULT', 'handler unchanged';
};

done_testing;
