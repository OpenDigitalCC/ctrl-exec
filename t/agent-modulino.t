use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/../lib";

# Loading bin/ctrl-exec-agent must NOT start the server (the `main() unless
# caller` modulino guard), and must make its handler subs available so they can
# be unit-tested directly. Before the guard, the 1356-line agent could only be
# exercised as a black box via spawned processes.

my $agent = "$Bin/../bin/ctrl-exec-agent";
ok(-e $agent, 'agent script present');

{
    # Silence the expected "Subroutine main redefined" / "used only once" noise
    # that arises from loading a program file into the test interpreter.
    local $SIG{__WARN__} = sub {};
    my $ok = do $agent;
    ok($ok, 'agent loads (require/do) without running main()')
        or diag("load error: " . ($@ || $!));
}

# The previously black-box-only handlers are now addressable.
for my $sub (qw(handle_run handle_ping handle_capabilities
                handle_rotate_serial handle_result handle_connection)) {
    ok(defined &{"main::$sub"}, "$sub is loadable for unit testing");
}

done_testing;
