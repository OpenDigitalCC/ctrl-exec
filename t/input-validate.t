#!/usr/bin/perl
# t/input-validate.t
#
# Exec::Input::validate - the confidential input shape shared by the API and
# the agent (T-013). Errors must never contain a value.

use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/../lib";

use Exec::Input qw();

my $V = \&Exec::Input::validate;

my $r = $V->(undef);
ok $r->{ok}, 'absent input is fine';
is_deeply $r->{names}, [], 'no names';
is $r->{bytes}, 0, 'no bytes';

$r = $V->({ key => 'abc', cert => "\x{e9}" });
ok $r->{ok}, 'two string fields';
is_deeply $r->{names}, ['cert', 'key'], 'names sorted';
is $r->{bytes}, 5, 'bytes counted UTF-8 encoded';

ok !$V->([ 'a' ])->{ok},          'array refused';
ok !$V->('SECRET')->{ok},         'string refused';
ok !$V->({ 'a/b' => 'x' })->{ok}, 'slash in name refused';
ok !$V->({ '..' => 'x' })->{ok},  '.. refused';
ok !$V->({ '' => 'x' })->{ok},    'empty name refused';
ok !$V->({ ('n' x 65) => 'x' })->{ok}, 'long name refused';
ok !$V->({ a => { b => 1 } })->{ok},   'nested value refused';
ok !$V->({ a => undef })->{ok},        'null value refused';

my %many = map { ("f$_" => 'x') } 1 .. 33;
ok !$V->(\%many)->{ok}, '33 fields refused';
delete $many{f33};
ok $V->(\%many)->{ok}, '32 fields accepted';

ok $V->({ a => 'x' x 10 }, 10)->{ok},  'at the byte limit';
$r = $V->({ a => 'SECRET' x 2 }, 10);
ok !$r->{ok}, 'over the byte limit';
unlike $r->{error}, qr/SECRET/, 'error carries no value';
$r = $V->({ a => { SECRET => 1 } });
unlike $r->{error}, qr/SECRET/, 'type error carries no value';

done_testing;
