#!/usr/bin/perl
# T-090: the agent must read a script's stdout and stderr together. Reading one
# to EOF before the other deadlocks a script that fills the other pipe (64 KiB)
# first: the script blocks writing stderr, the agent blocks reading stdout.
# Each run is bounded by alarm so a regression fails instead of hanging.
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use FindBin    qw($Bin);
use lib "$Bin/../lib";

use Exec::Agent::Runner qw();

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

sub bounded {
    my ($code) = @_;
    my $res;
    my $ok = eval {
        local $SIG{ALRM} = sub { die "timeout\n" };
        alarm 20;
        $res = $code->();
        alarm 0;
        1;
    };
    alarm 0;
    return $ok ? $res : undef;
}

# 200 KB to stderr first, then a short stdout.
my $err_first = script('err-first.sh', "head -c 200000 /dev/zero | tr '\\0' e >&2\necho done\nexit 0\n");
my $res = bounded(sub { Exec::Agent::Runner::run_script($err_first, [], undef, 15) });
ok $res, 'stderr over 64 KiB before stdout returns (no deadlock)' or done_testing, exit 1;
is $res->{exit}, 0, 'exit code intact';
like $res->{stdout}, qr/^done/, 'stdout intact';
is length $res->{stderr}, 200000, 'all of stderr arrives';

# Both streams large, interleaved.
my $both = script('both.sh', <<'SH');
i=0
while [ $i -lt 40 ]; do
  head -c 10000 /dev/zero | tr '\0' o
  head -c 10000 /dev/zero | tr '\0' e >&2
  i=$((i + 1))
done
exit 2
SH
$res = bounded(sub { Exec::Agent::Runner::run_script($both, [], undef, 15) });
ok $res, 'large stdout and stderr together return';
is $res->{exit}, 2, 'exit code intact';
is length $res->{stdout}, 400000, 'all of stdout arrives';
is length $res->{stderr}, 400000, 'all of stderr arrives';

# Small output unchanged.
my $small = script('small.sh', "echo out\necho err >&2\nexit 0\n");
$res = bounded(sub { Exec::Agent::Runner::run_script($small, [], undef, 10) });
is_deeply [ @{$res}{qw(stdout stderr exit)} ], [ "out\n", "err\n", 0 ], 'small output unchanged';

done_testing;
