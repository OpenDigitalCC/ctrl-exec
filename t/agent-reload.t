#!/usr/bin/perl
# t/agent-reload.t
#
# SIGHUP reloads agent.conf itself, not just the allowlist and friends. Before
# T-021 an operator who tightened agent.conf (allowed_ips, rate limits,
# max_children, auth_hook ...) and reloaded was not protected: $config was only
# read at startup. Covers the pure planner (Exec::Agent::Config::reload_plan)
# and, against a real running agent, that a tightened setting takes effect, a
# broken agent.conf leaves the old config in force and is logged, and a
# restart-only setting keeps its running value and logs that a restart is needed.

use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use FindBin    qw($Bin);
use lib "$Bin/../lib", "$Bin/lib";

use Exec::Agent::Config qw();

my $dir = tempdir(CLEANUP => 1);

sub write_file {
    my ($path, $text) = @_;
    open my $fh, '>', $path or die "write $path: $!";
    print $fh $text;
    close $fh;
}

my $conf  = "$dir/agent.conf";
my $allow = "$dir/scripts.conf";

sub conf_text {
    my (%o) = @_;
    return "port = " . ($o{port} // 7443) . "\n"
         . "cert = /c.crt\nkey = /c.key\nca = /ca.crt\n"
         . ($o{extra} // '')
         . "[profile default]\n" . ($o{profiles} // '');
}

# --- planner ---------------------------------------------------------------
write_file($conf, conf_text());
write_file($allow, "hello = /bin/true\n");
my $old_cfg   = Exec::Agent::Config::load_config($conf);
my $old_allow = Exec::Agent::Config::load_allowlist($allow);

subtest 'a tightened setting is in the planned config' => sub {
    write_file($conf, conf_text(extra => "allowed_ips = 10.0.0.1\nmax_children = 4\n"
                                       . "rate_limit_volume = 2/60/300\n"));
    my $plan = Exec::Agent::Config::reload_plan($conf, $allow, $old_cfg, $old_allow);
    is_deeply $plan->{notes}, [], 'no notes';
    is $plan->{config}{max_children}, 4, 'max_children picked up';
    is_deeply $plan->{config}{rate_limit}{volume_limit}, 2, 'rate limit picked up'
        or diag explain $plan->{config}{rate_limit};
    ok $plan->{config}{allowed_ips}, 'allowed_ips picked up';
    ok exists $plan->{allowlist}{hello}, 'allowlist reloaded alongside';
};

subtest 'broken agent.conf dies, so the caller keeps the old config' => sub {
    write_file($conf, "port = 7443\nthis line is not valid\n");
    my $plan = eval { Exec::Agent::Config::reload_plan($conf, $allow, $old_cfg, $old_allow) };
    ok !$plan, 'no plan';
    like $@, qr/Malformed config line/, 'error names the fault';
};

subtest 'a scripts.conf naming an undefined profile fails the whole reload' => sub {
    write_file($conf, conf_text());
    write_file($allow, "hello = /bin/true profile=ghost\n");
    my $plan = eval { Exec::Agent::Config::reload_plan($conf, $allow, $old_cfg, $old_allow) };
    ok !$plan, 'no plan';
    like $@, qr/undefined profile.*hello -> ghost/s, 'names the script and profile';
    write_file($allow, "hello = /bin/true\n");
};

subtest 'a profile removed from agent.conf that the running allowlist uses fails' => sub {
    write_file($conf, conf_text(profiles => "caps = CAP_KILL\n"));
    write_file($allow, "hello = /bin/true\n");
    my $cfg = Exec::Agent::Config::load_config($conf);
    write_file($conf, "port = 7443\ncert = /c.crt\nkey = /c.key\nca = /ca.crt\n"
                    . "[profile other]\n");
    # scripts.conf unreadable: previous allowlist (profile 'default') stays and
    # must still be satisfied by the new agent.conf, which no longer defines it
    unlink $allow;
    my $plan = eval { Exec::Agent::Config::reload_plan($conf, $allow, $cfg, $old_allow) };
    ok !$plan, 'no plan';
    like $@, qr/undefined profile/, 'previous allowlist re-checked against new config';
    write_file($allow, "hello = /bin/true\n");
};

subtest 'unreadable scripts.conf keeps the previous allowlist and notes it' => sub {
    write_file($conf, conf_text());
    unlink $allow;
    my $plan = eval { Exec::Agent::Config::reload_plan($conf, $allow, $old_cfg, $old_allow) };
    ok $plan, 'plan made' or diag $@;
    is $plan->{allowlist}, $old_allow, 'previous allowlist kept';
    like $plan->{notes}[0], qr/allowlist reload failed/, 'noted';
    write_file($allow, "hello = /bin/true\n");
};

subtest 'restart-only settings keep their running value and note it' => sub {
    write_file($conf, "port = 9999\ncert = /new.crt\nkey = /c.key\nca = /ca.crt\n"
                    . "max_children = 3\n[profile default]\n");
    my $plan = Exec::Agent::Config::reload_plan($conf, $allow, $old_cfg, $old_allow);
    is $plan->{config}{port}, 7443,         'port keeps the running value';
    is $plan->{config}{cert}, '/c.crt',     'cert keeps the running value';
    is $plan->{config}{key},  '/c.key',     'unchanged key unchanged';
    is $plan->{config}{max_children}, 3,    'hot setting still applied';
    is scalar @{ $plan->{notes} }, 2, 'one note per changed restart-only key';
    like $plan->{notes}[0], qr/'port'.*restart/, 'port note';
    like $plan->{notes}[1], qr/'cert'.*restart/, 'cert note';
};

# --- a running agent -------------------------------------------------------
require AgentRig;
plan skip_all => 'openssl not available' unless AgentRig::available();

my $rig = AgentRig->new(allowlist => "hello = /bin/true\n");
ok $rig->start, 'agent started' or BAIL_OUT('rig agent did not start: ' . $rig->log_text);
is $rig->request(as => 'trusted'), 200, 'trusted dispatcher served before any change';

# 1. tightened setting takes effect after HUP
{
    my $from = $rig->log_len;
    $rig->set_conf("allowed_ips = 10.9.9.9\n");
    is $rig->request(as => 'trusted'), 200, 'editing agent.conf alone changes nothing yet';
    $rig->hup;
    ok $rig->wait_log(qr/Reloading agent\.conf/, 5, $from), 'HUP handled';
    is $rig->request(as => 'trusted'), undef, 'no reply for a peer outside allowed_ips';
    ok $rig->wait_log(qr/ACTION=ip-block PEER=127\.0\.0\.1/, 5, $from),
        'allowed_ips tightened: connection from 127.0.0.1 refused (ip-block logged)';
}

# 2. broken agent.conf leaves the old (tight) config in force and logs
{
    my $from = $rig->log_len;
    write_file($rig->{conf}, "port = $rig->{port}\nthis is not valid\n");
    $rig->hup;
    ok $rig->wait_log(qr/agent\.conf reload failed.*Malformed/s, 5, $from), 'failure logged';
    ok $rig->wait_log(qr/ACTION=reload-fail/, 5, $from), 'reload-fail action logged';
    is $rig->request(as => 'trusted'), undef, 'old (tight) config still in force';
    ok $rig->alive, 'agent still running';
}

# 3. restoring a good, loose config via HUP works again
{
    my $from = $rig->log_len;
    $rig->set_conf("allowed_ips = 127.0.0.1\n");
    $rig->hup;
    my $ok;
    for (1 .. 40) {
        if (($rig->request(as => 'trusted') // 0) == 200) { $ok = 1; last }
        select undef, undef, undef, 0.1;
    }
    ok $ok, 'a corrected agent.conf is picked up by the next HUP';
}

# 4. restart-only setting: kept, logged
{
    my $from = $rig->log_len;
    $rig->set_conf("allowed_ips = 127.0.0.1\n");
    my $text = do { open my $fh, '<', $rig->{conf} or die; local $/; <$fh> };
    my $new  = $rig->{port} + 1;
    $text =~ s/^port = \d+/port = $new/m;
    write_file($rig->{conf}, $text);
    $rig->hup;
    ok $rig->wait_log(qr/'port' changed in agent\.conf but needs a restart/, 5, $from),
        'port change logged as needing a restart';
    is $rig->request(as => 'trusted'), 200, 'still serving on the old port';
}

$rig->stop;
done_testing;
