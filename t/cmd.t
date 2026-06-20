#!/usr/bin/perl
# t/cmd.t
#
# Contract tests for Exec::Cmd::run_or_die. Its whole reason to exist is to put
# the failed child's stderr into the die message (via an OS-level fd-2 redirect)
# - a bare `system()==0 or die` discards it. Pin both the success path and that
# the captured stderr reaches the croak.

use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/../lib";

use Exec::Cmd qw();

subtest 'run_or_die: returns without dying on success' => sub {
    my $ok = eval { Exec::Cmd::run_or_die('true'); 1 };
    ok $ok, 'a zero-exit command returns normally';
    is $@, '', 'no exception';
};

subtest 'run_or_die: croaks with the captured stderr on failure' => sub {
    eval { Exec::Cmd::run_or_die('sh', '-c', 'echo boom-from-child >&2; exit 3') };
    ok $@, 'a non-zero exit croaks';
    like $@, qr/boom-from-child/, "the child's stderr is in the die text";
    like $@, qr/exit/, 'the exit status is reported';
};

subtest 'run_or_die: restores the real stderr afterwards' => sub {
    # After a captured run, ordinary warnings must still reach the real fd 2.
    eval { Exec::Cmd::run_or_die('true') };
    my $captured = '';
    local $SIG{__WARN__} = sub { $captured .= $_[0] };
    warn "still-visible\n";
    like $captured, qr/still-visible/, 'warnings work after the fd-2 redirect is undone';
};

done_testing;
