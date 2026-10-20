#!/usr/bin/perl
# t/agent-not-permitted.t  (T-044)
#
# A run refused as "script not permitted" says why: the reason a scripts.conf
# entry was skipped (path outside script_dirs, relative, two paths, over-long
# path or profile name, no path), or "not in scripts.conf" for a name the
# allowlist has never heard of. The reasons are carried across a SIGHUP reload
# (reload_plan), logged once per load, and listed by `self-check`.

use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use FindBin    qw($Bin);
use lib "$Bin/../lib";
use IO::Socket::UNIX qw();
use JSON::PP qw(decode_json);

use Exec::Agent::Config qw();
use Exec::Agent::Server qw();
use Exec::Log           qw();

Exec::Log::init('test');
my @logs;
{
    no warnings 'redefine';
    *Exec::Log::log_action = sub { push @logs, { level => $_[0], %{ $_[1] } } };
}

my $dir = tempdir(CLEANUP => 1);

# The scripts live in a tempdir owned by the test user under a world-writable
# /tmp; trust that user and that directory's ancestors (test seam, T-045) so the
# ownership rule does not skip them. t/agent-script-ownership.t tests the rule.
@Exec::Agent::Config::TRUSTED_OWNERS = (0, $>);
$Exec::Agent::Config::TRUSTED_TOP    = $dir;
umask 022;   # and create nothing group-writable (the host umask may be 002)
mkdir "$dir/good" or die;
sub write_file { my ($p, $c) = @_; open my $fh, '>', $p or die "$p: $!"; print $fh $c; close $fh }

my $long_path = '/good/' . ('x' x 4100);
my $long_prof = 'p' x 130;
my $conf_text = <<"CONF";
inside    = $dir/good/ok.sh
outside   = /srv/scripts/agent-cert-deploy.sh
relative  = scripts/rel.sh
twopaths  = $dir/good/a.sh $dir/good/b.sh
longpath  = $long_path
longprof  = $dir/good/ok.sh profile=$long_prof
CONF
my $allow = "$dir/scripts.conf";
write_file($allow, $conf_text);
my @dirs = ("$dir/good");

my $allowlist = {};
my $skipped   = {};
{
    local $SIG{__WARN__} = sub {};
    ($allowlist, $skipped) = Exec::Agent::Config::load_allowlist_full($allow, \@dirs);
}

# Drive a run request through the real handler and return the decoded reply.
sub run_reply {
    my ($name, %o) = @_;
    my $body = '{"script":"' . $name . '","args":[]}';
    my ($client, $server) = IO::Socket::UNIX->socketpair(
        IO::Socket::AF_UNIX(), IO::Socket::SOCK_STREAM(), 0) or die "socketpair: $!";
    print $client "POST /run HTTP/1.0\r\nContent-Length: " . length($body) . "\r\n\r\n$body";
    $client->shutdown(1);
    Exec::Agent::Server::handle_connection(
        $server, '10.0.0.5', $allowlist, { script_dirs => \@dirs }, {},
        { deadbeef => 'disp-1' }, 'deadbeef', {}, '9.9.9', $skipped,
    );
    $server->close;
    local $/;
    my $resp = <$client> // '';
    $client->close;
    $resp =~ s/\A.*?\r\n\r\n//s;
    return decode_json($resp);
}

subtest 'a permitted script is still in the allowlist' => sub {
    ok exists $allowlist->{inside}, 'inside script_dirs is kept';
    ok !exists $allowlist->{outside}, 'outside is not';
};

my %want = (
    outside  => qr{^script not permitted: '/srv/scripts/agent-cert-deploy\.sh' is not under script_dirs \(\Q$dir\E/good\)$},
    relative => qr{^script not permitted: 'scripts/rel\.sh' is not an absolute path$},
    twopaths => qr{^script not permitted: its scripts\.conf entry has more than one path \('\Q$dir\E/good/a\.sh' and '\Q$dir\E/good/b\.sh'\)$},
    longpath => qr{^script not permitted: its path is too long \(\d+ characters; the limit is 4095\)$},
    longprof => qr{^script not permitted: its profile name is too long \(130 characters; the limit is 127\)$},
);
for my $name (sort keys %want) {
    subtest "run of '$name' says why" => sub {
        my $r = run_reply($name);
        is $r->{exit}, -1, 'response shape: exit -1';
        is $r->{script}, $name, 'response shape: script';
        like $r->{error}, $want{$name}, 'error text names the path and the rule';
    };
}

subtest 'an unknown name is distinct' => sub {
    my $r = run_reply('nosuch');
    is $r->{exit}, -1, 'exit -1';
    is $r->{error}, 'script not permitted: not in scripts.conf', 'not in scripts.conf';
};

subtest 'a script that left script_dirs after load is refused with the rule' => sub {
    # in the allowlist (as if loaded without dirs) but outside the dirs now
    my $saved = $allowlist;
    $allowlist = { moved => { path => '/elsewhere/m.sh', profile => 'default' } };
    my $r = run_reply('moved');
    $allowlist = $saved;
    like $r->{error}, qr{^script not permitted: '/elsewhere/m\.sh' is not under script_dirs \(}, 'execution-time reason';
};

subtest 'skips are logged once per load, with the same reason' => sub {
    @logs = ();
    Exec::Agent::Config::log_skipped($skipped);
    my @skips = grep { $_->{ACTION} eq 'allowlist-skip' } @logs;
    is scalar @skips, scalar keys %$skipped, 'one line per skipped entry';
    is_deeply [ map { $_->{level} } @skips ], [ ('WARNING') x @skips ], 'WARNING';
    my %by = map { $_->{SCRIPT} => $_->{REASON} } @skips;
    is_deeply \%by, $skipped, 'reasons match what a run reports';
};

subtest 'reload_plan carries the reasons' => sub {
    my $conf = "$dir/agent.conf";
    write_file($conf, "port = 7443\ncert = /c.crt\nkey = /c.key\nca = /ca.crt\n"
                    . "script_dirs = $dir/good\n[profile default]\n");
    my $cfg = Exec::Agent::Config::load_config($conf);
    local $SIG{__WARN__} = sub {};
    my $plan = Exec::Agent::Config::reload_plan($conf, $allow, $cfg, $allowlist, $skipped);
    like $plan->{skipped}{outside}, qr{not under script_dirs}, 'skip reason in the plan';
    is_deeply [ sort keys %{ $plan->{skipped} } ], [ sort keys %$skipped ], 'every skip carried';

    # an edit to scripts.conf changes the reasons on the next reload
    write_file($allow, "inside = $dir/good/ok.sh\nrelative = nope.sh\n");
    $plan = Exec::Agent::Config::reload_plan($conf, $allow, $cfg, $allowlist, $skipped);
    is_deeply [ sort keys %{ $plan->{skipped} } ], ['relative'], 'reasons follow the new file';

    # an unreadable scripts.conf keeps the previous allowlist and its reasons
    unlink $allow;
    $plan = Exec::Agent::Config::reload_plan($conf, $allow, $cfg, $allowlist, $skipped);
    is_deeply $plan->{skipped}, $skipped, 'previous reasons kept with the previous allowlist';
    write_file($allow, $conf_text);
};

subtest 'self-check lists skipped entries with their reasons' => sub {
    my $conf = "$dir/agent.conf";
    my $agent = "$Bin/../bin/ctrl-exec-agent";
    # Load the modulino with the same ownership seam as above, then run it.
    my $seam = '@Exec::Agent::Config::TRUSTED_OWNERS = (0, $>);'
             . '$Exec::Agent::Config::TRUSTED_TOP = shift;'
             . 'my $a = shift; do $a or die $@ || $!; main()';
    my $cmd = join ' ', map { "'$_'" } $^X, "-I$Bin/../lib", '-MExec::Agent::Config',
                                        '-e', $seam, $dir, $agent, '--config', $conf,
                                        '--allowlist', $allow, 'self-check';
    my $out = `$cmd 2>&1`;
    like $out, qr{Script 'outside': SKIPPED - '/srv/scripts/agent-cert-deploy\.sh' is not under script_dirs \(\Q$dir\E/good\)}, 'outside listed';
    like $out, qr{Script 'relative': SKIPPED - 'scripts/rel\.sh' is not an absolute path}, 'relative listed';
    like $out, qr{Script 'twopaths': SKIPPED - .*more than one path}, 'two paths listed';
    unlike $out, qr{Script 'inside': SKIPPED}, 'permitted script not listed as skipped';
};

done_testing;
