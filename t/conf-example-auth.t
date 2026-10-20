#!/usr/bin/perl
# t/conf-example-auth.t
#
# T-046: a fresh install must fail closed. etc/ctrl-exec.conf.example is what
# the packages and install.sh seed as ctrl-exec.conf; it must not name an active
# auth_hook (the example hook ends `exit 0`), so that api_auth_default = deny
# applies to API requests until the operator writes a hook.

use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use FindBin    qw($Bin);
use lib "$Bin/../lib";

use Exec::DispatcherConfig qw();
use Exec::Auth qw();

my $example = "$Bin/../etc/ctrl-exec.conf.example";
ok -f $example, 'the example conf exists';

open my $fh, '<', $example or die "$example: $!";
my @lines = <$fh>;
close $fh;

is scalar(grep { /^\s*auth_hook\s*=/ } @lines), 0, 'no active auth_hook line';
ok scalar(grep { /^\s*#\s*auth_hook\s*=/ } @lines), 'a commented auth_hook example is present';
is scalar(grep { /^\s*api_auth_default\s*=\s*allow/i } @lines), 0, 'api_auth_default is not set to allow';

my $config = Exec::DispatcherConfig::load_config($example);
ok !$config->{auth_hook}, 'loaded as config: no auth_hook';

# Keep the audit lines out of the real syslog.
{
    no warnings 'redefine';
    *Exec::Log::log_action = sub { 1 };
}

my $api = Exec::Auth::check(
    action => 'run', config => $config, script => 'x', hosts => ['h'],
    caller => 'api',
);
ok !$api->{ok}, 'API run is denied by default with the shipped conf';
like $api->{reason}, qr/no auth hook configured/, 'denied for the missing hook';

my $cli = Exec::Auth::check(
    action => 'run', config => $config, script => 'x', hosts => ['h'],
    caller => 'cli',
);
ok $cli->{ok}, 'CLI run is still authorised (gated by system permissions)';

# The seeded example hook is a starting point only: it allows everything, so the
# conf must not reference it.
my $hook = "$Bin/../etc/auth-hook.example";
ok -f $hook, 'the example hook is still shipped';
unlike join('', @lines), qr/^\s*auth_hook\s*=\s*\S*auth-hook\s*$/m, 'conf does not activate it';

done_testing;
