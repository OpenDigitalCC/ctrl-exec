use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use FindBin qw($Bin);
use lib "$Bin/../lib";

use Exec::Auth;

# A hung auth hook must not wedge the request handler: the hook is bounded by
# auth_hook_timeout, killed on timeout, and the request fails closed (S7).

my $dir  = tempdir(CLEANUP => 1);
my $hook = "$dir/sleepy-hook";
open my $fh, '>', $hook or die "cannot write hook: $!";
print $fh "#!/bin/sh\nsleep 30\n";
close $fh;
chmod 0755, $hook;

my $start = time;
my $res = Exec::Auth::check(
    action => 'run',
    script => 'noop',
    hosts  => ['host-1'],
    args   => [],
    config => { auth_hook => $hook, auth_hook_timeout => 1 },
);
my $elapsed = time - $start;

ok(!$res->{ok}, 'a hung hook is denied (fail closed)');
cmp_ok($elapsed, '<', 10,
    "timeout fired (took ${elapsed}s) well before the hook's 30s sleep");

# A prompt, allowing hook still authorises - the timeout does not break the
# normal path.
my $ok_hook = "$dir/ok-hook";
open my $ofh, '>', $ok_hook or die "cannot write hook: $!";
print $ofh "#!/bin/sh\nexit 0\n";
close $ofh;
chmod 0755, $ok_hook;

my $res2 = Exec::Auth::check(
    action => 'run',
    script => 'noop',
    hosts  => ['host-1'],
    args   => [],
    config => { auth_hook => $ok_hook, auth_hook_timeout => 5 },
);
ok($res2->{ok}, 'a prompt allowing hook still authorises under the timeout');

done_testing;
