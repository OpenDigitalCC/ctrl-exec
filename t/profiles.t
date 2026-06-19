#!/usr/bin/perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use FindBin    qw($Bin);
use lib "$Bin/../lib";

use Exec::Agent::Config qw();

my $DIR = tempdir(CLEANUP => 1);
my $REQUIRED = "port = 7443\ncert = /x.crt\nkey = /x.key\nca = /ca.crt\n";

sub agent_conf { my ($b) = @_; my $p = "$DIR/agent.$$." . (++our $n) . ".conf";
    open my $f, '>', $p or die $!; print $f $REQUIRED, $b; close $f; return $p }
sub scripts_conf { my ($b) = @_; my $p = "$DIR/scripts.$$." . (++our $m) . ".conf";
    open my $f, '>', $p or die $!; print $f $b; close $f; return $p }

subtest 'profile block parsed and normalised' => sub {
    my $c = Exec::Agent::Config::load_config(agent_conf(<<'EOF'));
[profile cert-deploy]
run_as = root
caps = CAP_CHOWN, CAP_KILL
writable = /etc/nginx/ssl:/srv/certificates
EOF
    my $p = $c->{profiles}{'cert-deploy'};
    is $p->{run_as}, 'root', 'run_as';
    is_deeply $p->{caps}, ['CAP_CHOWN','CAP_KILL'], 'caps split (comma/space)';
    is_deeply $p->{writable}, ['/etc/nginx/ssl','/srv/certificates'], 'writable split (colon)';
    is $p->{no_new_privileges}, 1, 'no_new_privileges defaults on';
};

subtest 'no_new_privileges can be turned off' => sub {
    my $c = Exec::Agent::Config::load_config(agent_conf(
        "[profile loose]\nno_new_privileges = no\n"));
    is $c->{profiles}{loose}{no_new_privileges}, 0, 'off';
};

subtest 'invalid profile fields croak at load' => sub {
    eval { Exec::Agent::Config::load_config(agent_conf("[profile x]\ncaps = NOPE\n")) };
    like $@, qr/invalid capability/, 'bad cap name';
    # An inline '# ...' comment after a value is a common mistake (the format
    # supports whole-line comments only); the error must say so, not just
    # "invalid capability '#'".
    eval { Exec::Agent::Config::load_config(
        agent_conf("[profile x]\ncaps = CAP_CHOWN  # and more\n")) };
    like $@, qr/inline '# \.\.\.' comments are not supported/,
        'inline comment on caps line gets an instructive hint';
    eval { Exec::Agent::Config::load_config(agent_conf("[profile x]\nwritable = rel/path\n")) };
    like $@, qr/writable path must be absolute/, 'relative writable';
    eval { Exec::Agent::Config::load_config(agent_conf("[profile x]\nrun_as = 1bad name\n")) };
    like $@, qr/invalid run_as/, 'bad run_as';
    eval { Exec::Agent::Config::load_config(agent_conf("[profile]\nrun_as = root\n")) };
    like $@, qr/Profile section needs a name/, 'unnamed profile section';
};

subtest 'scripts.conf profile= is order-independent' => sub {
    my $al = Exec::Agent::Config::load_allowlist(scripts_conf(<<'EOF'));
plain   = /opt/s/a.sh
after   = /opt/s/b.sh profile=cert-deploy
before  = profile=read-only /opt/s/c.sh
EOF
    is Exec::Agent::Config::script_profile('plain',  $al), 'default',     'unannotated -> default';
    is Exec::Agent::Config::script_profile('after',  $al), 'cert-deploy', 'profile after path';
    is Exec::Agent::Config::script_profile('before', $al), 'read-only',   'profile before path';
    is $al->{before}{path}, '/opt/s/c.sh', 'path still resolved when profile is first';
};

subtest 'two paths on a line are rejected' => sub {
    my @warn; local $SIG{__WARN__} = sub { push @warn, $_[0] };
    my $al = Exec::Agent::Config::load_allowlist(scripts_conf(
        "bad = /opt/a.sh /opt/b.sh\n"));
    ok !exists $al->{bad}, 'entry skipped';
    like "@warn", qr/more than one path/, 'warns';
};

subtest 'validate_profiles flags undefined profiles (fail-closed input)' => sub {
    my $c  = Exec::Agent::Config::load_config(agent_conf("[profile known]\nrun_as = root\n"));
    my $al = Exec::Agent::Config::load_allowlist(scripts_conf(<<'EOF'));
ok-default = /opt/s/a.sh
ok-known   = /opt/s/b.sh profile=known
bad        = /opt/s/c.sh profile=ghost
EOF
    my @bad = Exec::Agent::Config::validate_profiles($al, $c);
    is_deeply \@bad, ['bad -> ghost'], 'only the undefined-profile script is flagged';
};

done_testing;
