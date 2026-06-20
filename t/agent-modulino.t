use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/../lib";

# Loading bin/ctrl-exec-agent must NOT start the server (the `main() unless
# caller` modulino guard). Its request handlers now live in Exec::Agent::Server
# (extracted from the bin); loading the agent pulls the module in, and the
# handlers are addressable as named subs for direct unit testing.

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

# The previously black-box-only handlers are now addressable in Exec::Agent::Server.
require Exec::Agent::Server;
for my $sub (qw(handle_run handle_ping handle_capabilities
                handle_rotate_serial handle_result handle_connection)) {
    ok(defined &{"Exec::Agent::Server::$sub"}, "$sub is loadable for unit testing");
}

done_testing;
