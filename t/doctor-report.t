#!/usr/bin/perl
# t/doctor-report.t
#
# T-055: what both doctors share (Exec::Doctor) - the human form (one line per
# finding: severity, what, fix; one summary line; --brief lists problems only),
# the --json shape, the exit status (0 nothing to fix, 1 problems), one log line
# per finding (ACTION=doctor-finding), and --fix (an autofix that succeeds
# marks its finding fixed; one that fails leaves it as found, saying why).

use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/../lib";
use JSON qw(decode_json);

use Exec::Doctor qw();
use Exec::Log    qw();

my @logged;
{
    no warnings 'redefine';
    *Exec::Log::log_action = sub { push @logged, [ $_[0], { %{ $_[1] } } ]; 1 };
}

sub findings {
    return [
        Exec::Doctor::note('n1', 'A note.', 'do x'),
        Exec::Doctor::problem('p1', 'A problem.', 'sudo fix-it'),
        Exec::Doctor::note('n2', 'Nothing to run.'),
    ];
}

subtest 'human form' => sub {
    my $t = Exec::Doctor::to_text('prog', findings());
    is $t, "PROBLEM  A problem. Fix: sudo fix-it\n"
         . "note     A note. Fix: do x\n"
         . "note     Nothing to run.\n"
         . "prog doctor: 1 problem, 2 notes.\n",
        'problems first, one line each with the fix, then the summary';

    is Exec::Doctor::to_text('prog', findings(), brief => 1),
        "PROBLEM  A problem. Fix: sudo fix-it\nprog doctor: 1 problem, 2 notes.\n",
        'brief: problems only, notes counted';

    is Exec::Doctor::to_text('prog', [ Exec::Doctor::note('n', 'x') ], brief => 1),
        "prog doctor: no problems, 1 note (see them with: prog doctor).\n",
        'brief with nothing to fix: one line';
    is Exec::Doctor::to_text('prog', []), "prog doctor: no problems.\n", 'nothing found: one line';

    my $fixable = [ Exec::Doctor::note('n', 'x', 'y', autofix => sub { undef }) ];
    like Exec::Doctor::to_text('prog', $fixable), qr/\(some can be fixed with: prog doctor --fix\)\.\n\z/,
        'a fixable finding points at --fix';
};

subtest 'exit status' => sub {
    is Exec::Doctor::exit_status(findings()), 1, 'a problem: 1';
    is Exec::Doctor::exit_status([ Exec::Doctor::note('n', 'x') ]), 0, 'notes only: 0';
    is Exec::Doctor::exit_status([]), 0, 'nothing: 0';
    is Exec::Doctor::EXIT_USAGE(), 2, 'usage: 2';
};

subtest 'json' => sub {
    my $j = Exec::Doctor::to_json('prog', findings());
    like $j, qr/\A\{.*\}\n\z/s, 'one object, one line';
    unlike $j, qr/\n./, 'no inner newline';
    my $d = decode_json($j);
    is $d->{program}, 'prog', 'program';
    ok !$d->{ok}, 'ok false with a problem';
    is $d->{problems}, 1, 'problems';
    is $d->{notes}, 2, 'notes';
    is $d->{fixed}, 0, 'fixed';
    is scalar @{ $d->{findings} }, 3, 'every finding';
    is_deeply [ sort keys %{ $d->{findings}[1] } ], [qw(check fix fixed severity what)], 'finding keys';
    is_deeply { %{ $d->{findings}[1] }, fixed => 0 },
        { severity => 'problem', check => 'p1', what => 'A problem.', fix => 'sudo fix-it', fixed => 0 },
        'finding values';
    ok JSON::is_bool($d->{findings}[1]{fixed}) && JSON::is_bool($d->{ok}), 'booleans are JSON booleans';
    ok decode_json(Exec::Doctor::to_json('prog', []))->{ok}, 'ok true with nothing found';
};

subtest 'log: one line per finding' => sub {
    @logged = ();
    open my $null, '>', \my $out;
    my $old = select $null;
    my $rc = Exec::Doctor::report('prog', findings());
    select $old;
    is $rc, 1, 'report returns the exit status';
    is scalar @logged, 3, 'three findings, three log lines';
    is $logged[1][0], 'WARNING', 'a problem logs at WARNING';
    is $logged[0][0], 'INFO', 'a note logs at INFO';
    is_deeply $logged[1][1], { ACTION => 'doctor-finding', PROGRAM => 'prog', SEVERITY => 'problem',
        CHECK => 'p1', WHAT => 'A problem.', FIX => 'sudo fix-it' }, 'fields';
    is $logged[2][1]{FIX}, '-', 'no fix: -';
    like $out, qr/\APROBLEM/, 'human form on stdout';

    @logged = ();
    open $null, '>', \$out;
    $old = select $null;
    Exec::Doctor::report('prog', findings(), json => 1);
    select $old;
    is scalar @logged, 3, 'logged with --json too';
    ok eval { decode_json($out) }, 'stdout is only the JSON';
};

subtest '--fix' => sub {
    my $ran = 0;
    my $f = [
        Exec::Doctor::problem('a', 'Fixable.', 'cmd', autofix => sub { $ran++; undef }),
        Exec::Doctor::note('b', 'Fails.', 'cmd', autofix => sub { 'no permission' }),
        Exec::Doctor::note('c', 'Dies.', 'cmd', autofix => sub { die "boom\n" }),
        Exec::Doctor::problem('d', 'Manual.', 'cmd'),
    ];
    Exec::Doctor::apply_fixes($f);
    is $ran, 1, 'the autofix ran';
    ok $f->[0]{fixed}, 'fixed';
    ok !$f->[1]{fixed}, 'a failed fix is not fixed';
    like $f->[1]{what}, qr/\(--fix could not change it: no permission\)/, 'and says why';
    like $f->[2]{what}, qr/\(--fix could not change it: boom\)/, 'a fix that dies says why';
    ok !$f->[3]{fixed}, 'a finding without an autofix is left';
    is Exec::Doctor::exit_status($f), 1, 'the manual problem still counts';
    is Exec::Doctor::exit_status([ $f->[0] ]), 0, 'a fixed problem does not';
    my $t = Exec::Doctor::to_text('prog', $f);
    like $t, qr/^fixed    Fixable\.\n/m, 'fixed listed, without its fix';
    like $t, qr/prog doctor: 1 problem, 2 notes, 1 fixed\./, 'summary counts the fix';
    is decode_json(Exec::Doctor::to_json('prog', $f))->{fixed}, 1, 'json counts the fix';
};

done_testing;
