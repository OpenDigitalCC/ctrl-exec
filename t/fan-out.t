use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/../lib";

use Exec::Engine qw();

# Exec::Engine::_fan_out runs a per-host worker across entries with bounded
# concurrency (forking, collecting JSON results over pipes). Verify correctness:
# every entry yields a result, the worker receives (name, target), results
# round-trip, and a small cap over more entries still returns them all (no loss,
# no deadlock).

my @entries = map { [ "host-$_", "host-$_:7443" ] } 1 .. 7;

my $out = Exec::Engine::_fan_out(\@entries, 2, sub {
    my ($name, $target) = @_;
    return { ok => 1, target => $target, doubled => "$name/$name" };
});

is scalar @$out, 7, 'all entries produced a result under a cap of 2';

my %by = map { $_->{name} => $_ } @$out;
is_deeply [ sort keys %by ], [ map { "host-$_" } 1 .. 7 ],
    'every entry is represented exactly once';
is $by{'host-3'}{target}, 'host-3:7443', 'fan-out carries the target through';
is $by{'host-3'}{result}{target}, 'host-3:7443', 'worker received the target; result round-trips';
is $by{'host-5'}{result}{doubled}, 'host-5/host-5', 'worker received the name';

# A worker that dies drops that entry to a null result rather than taking down
# the batch.
my $out2 = Exec::Engine::_fan_out([['a','a'],['b','b']], 4, sub {
    my ($name) = @_;
    die "boom\n" if $name eq 'a';
    return { ok => 1 };
});
is scalar @$out2, 2, 'both entries returned even when one worker dies';
my %by2 = map { $_->{name} => $_ } @$out2;
ok !defined $by2{a}{result}, 'a died -> null result';
like $by2{a}{failure}, qr/^worker died: boom$/, 'a died -> failure carries the die message';
ok $by2{b}{result}{ok}, 'b succeeded';
ok !exists $by2{b}{failure}, 'a successful worker has no failure field';

# A worker that exits without printing anything (exit code, no output) and one
# that is killed by a signal are both reported by reason, not left opaque. The
# API server's inherited TERM handler would have made the kill look like a
# clean exit 0 with an empty pipe; the worker resets INT/TERM to DEFAULT.
my $out3 = Exec::Engine::_fan_out([['exit1','exit1'],['killed','killed'],['ok','ok']], 4, sub {
    my ($name) = @_;
    if ($name eq 'exit1')  { exit 1 }
    if ($name eq 'killed') { kill 'TERM', $$; sleep 5; exit 0 }
    return { ok => 1 };
});
my %by3 = map { $_->{name} => $_ } @$out3;
ok !defined $by3{exit1}{result}, 'exit-without-output -> null result';
like $by3{exit1}{failure}, qr/^worker exited 1 with no output$/, 'exit-without-output -> reason names the exit code';
ok !defined $by3{killed}{result}, 'signalled worker -> null result';
like $by3{killed}{failure}, qr/^worker killed by signal 15$/, 'signalled worker -> reason names the signal (TERM not swallowed)';
ok $by3{ok}{result}{ok}, 'the surviving worker still returns normally';

# The suffix helper used by the 'no response from child' fallbacks.
is Exec::Engine::_lost({ failure => 'worker exited 2 with no output' }), ': worker exited 2 with no output', '_lost formats the suffix';
is Exec::Engine::_lost({}), '', '_lost is empty without a failure';

# _worker_outcome: the pure classifier.
my ($r, $f);
($r, $f) = Exec::Engine::_worker_outcome({ ok => 1 }, 0, 8);
is_deeply $r, { ok => 1 }, '_worker_outcome: hash result passes through';
ok !defined $f, '_worker_outcome: no failure on success';
($r, $f) = Exec::Engine::_worker_outcome(undef, 13, 0);
is $f, 'worker killed by signal 13', '_worker_outcome: SIGPIPE death named';
($r, $f) = Exec::Engine::_worker_outcome([1,2], 0, 5);
is $f, 'worker exited 0 with unparseable output', '_worker_outcome: non-object JSON is unparseable';

done_testing;
