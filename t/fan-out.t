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
ok $by2{b}{result}{ok}, 'b succeeded';

done_testing;
