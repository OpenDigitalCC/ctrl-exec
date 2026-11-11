use strict;
use warnings;
use feature qw(signatures);
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/../lib";

use Exec::Engine qw();

# T-090: a worker writes its whole result to a pipe and exits. A result over the
# pipe buffer (64 KiB) blocks the worker until the parent reads, so a parent that
# reaps before reading deadlocks for good. Every case here is bounded by alarm so
# a regression fails the test instead of hanging the suite.

sub bounded ($secs, $code) {
    my @r;
    my $ok = eval {
        local $SIG{ALRM} = sub { die "timeout\n" };
        alarm $secs;
        @r = $code->();
        alarm 0;
        1;
    };
    alarm 0;
    return $ok ? @r : ();
}

# One worker, a result of about 1 MB.
my $big = 'x' x (1024 * 1024);
my ($one) = bounded(20, sub {
    Exec::Engine::_fan_out([['big', 'big:1']], 1, sub { return { ok => 1, data => $big } });
});
ok $one, 'a 1 MB result returns (no deadlock)';
is length($one->[0]{result}{data}), length($big), 'the 1 MB result arrives whole';
ok !exists $one->[0]{failure}, 'no failure reported for the 1 MB result';

# Several workers, each over 64 KiB, concurrently, plus a small one.
my @entries = map { ["h$_", "h$_:1"] } 1 .. 6;
my ($many) = bounded(30, sub {
    Exec::Engine::_fan_out(\@entries, 4, sub ($name, $target) {
        return { ok => 1, name => $name, data => $name x 40000 } unless $name eq 'h3';
        return { ok => 1, name => $name, data => 'small' };
    });
});
ok $many, 'fan-out of several results over 64 KiB returns';
is scalar @{ $many || [] }, 6, 'every host is represented';
for my $e (@{ $many || [] }) {
    my $n = $e->{name};
    is $e->{result}{name}, $n, "$n: result round-trips";
    is length $e->{result}{data}, ($n eq 'h3' ? 5 : length($n) * 40000), "$n: data intact";
}

# Small results unchanged, and a mixed batch: dies, signalled, exits, large.
my ($mix) = bounded(30, sub {
    Exec::Engine::_fan_out(
        [['died','d'],['killed','k'],['exit1','e'],['big','b'],['small','s']], 3, sub ($name, $target) {
            die "boom\n" if $name eq 'died';
            if ($name eq q(killed)) { kill q(TERM), $$; sleep 5; exit 0 }
            exit 1 if $name eq 'exit1';
            return { ok => 1, data => 'y' x 200000 } if $name eq 'big';
            return { ok => 1 };
        });
});
ok $mix, 'mixed batch returns';
my %m = map { $_->{name} => $_ } @{ $mix || [] };
like $m{died}{failure},   qr/^worker died: boom$/,                    'a dying worker still reports its message';
like $m{killed}{failure}, qr/^worker killed by signal 15$/,           'a signalled worker still reports the signal';
like $m{exit1}{failure},  qr/^worker exited 1 with no output$/,       'an exit without output still reports the code';
is length $m{big}{result}{data}, 200000,                              'the large result in the mix is intact';
ok $m{small}{result}{ok} && !exists $m{small}{failure},               'a small result is unchanged';

done_testing;
