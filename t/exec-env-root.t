#!/usr/bin/perl
# t/exec-env-root.t  (T-004)
#
# The action's environment under the executor. The executor never passes on its
# own environment: the action gets a fixed PATH, plus HOME, USER and LOGNAME from
# the run_as user's passwd entry when the profile has a run_as with one. A
# numeric run_as with no passwd entry leaves the three unset. The loader and
# shell variables (LD_*, BASH_ENV, IFS, PERL5LIB) stay dropped.
#
# run_as needs the executor's privileged path, so this runs as root only (as
# t/exec-privilege-root.t). Off-host: inside the wedge rig container,
#
#     docker exec -w /opt/ctrl-exec <rig> prove -Ilib t/exec-env-root.t
#
# The executor here is started with a polluted environment, including HOME,
# USER and LOGNAME of its own, to show the action's values are set, not
# inherited.

use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use FindBin    qw($Bin);
use lib "$Bin/../lib";
use POSIX qw();

use Exec::Agent::ExecClient qw();

plan skip_all => 'must run as root (run_as needs the privileged path)' unless $> == 0;

my $cc = `command -v gcc 2>/dev/null`; chomp $cc;
plan skip_all => 'gcc not available' unless $cc && -x $cc;

my @nobody = getpwnam('nobody');
plan skip_all => 'no "nobody" user to drop to' unless @nobody;
my ($nobody_name, $nobody_home) = @nobody[0, 7];

# A numeric uid with no passwd entry.
my $orphan = 54321;
$orphan++ while defined getpwuid($orphan) && $orphan < 54400;
plan skip_all => 'no free uid for the numeric run_as case' if defined getpwuid($orphan);

# Under /run (root-owned, 0755): the executor refuses a script under a directory
# others can write (T-045), and /var/tmp is world-writable.
my $TMP = tempdir(DIR => '/run', CLEANUP => 1);
chmod 0755, $TMP;
my $BIN = "$TMP/ctrl-exec-executor";
system($cc, '-O2', '-o', $BIN, "$Bin/../src/ctrl-exec-executor.c", '-lcap') == 0
    or plan skip_all => 'could not compile the executor';

my $probe = "$TMP/probe.sh";
open my $p, '>', $probe or die $!;
print $p "#!/bin/sh\nenv\n";
close $p;
chmod 0755, $probe;

# The executor's own environment: what must NOT reach the action.
my %POLLUTED = (
    HOME            => '/caller-home',
    USER            => 'caller',
    LOGNAME         => 'caller',
    LD_LIBRARY_PATH => '/nonexistent-ld',
    BASH_ENV        => '/nonexistent-bash-env',
    IFS             => '%',
    PERL5LIB        => '/nonexistent-perl5lib',
    CE_MARKER       => 'leaked',
);

# Serve one profile, run the probe under it, return its environment as a hash
# (or { _no_run => reason }).
sub env_under_profile {
    my ($label, $body) = @_;
    my $agent_conf = "$TMP/agent.$label.conf";
    open my $a, '>', $agent_conf or die $!;
    print $a "port = 7443\ncert = /x\nkey = /y\nca = /z\nscript_dirs = $TMP\n"
           . "[profile $label]\n$body";
    close $a;
    my $scripts_conf = "$TMP/scripts.$label.conf";
    open my $s, '>', $scripts_conf or die $!;
    print $s "probe = $probe profile=$label\n";
    close $s;

    my $sock = "$TMP/exec.$label.sock";
    my $pid  = fork();
    die "fork: $!" unless defined $pid;
    if ($pid == 0) {
        open STDERR, '>', "$TMP/serve.$label.err";
        @ENV{ keys %POLLUTED } = values %POLLUTED;
        exec($BIN, 'serve', $sock, $agent_conf, $scripts_conf, 'root')
            or POSIX::_exit(127);
    }
    my $ready = 0;
    for (1 .. 100) { if (-S $sock) { $ready = 1; last } select undef, undef, undef, 0.05 }
    my $r = $ready
        ? Exec::Agent::ExecClient::run(socket => $sock, reqid => "e-$label",
                                       script => 'probe', args => [])
        : undef;
    kill 'TERM', $pid; waitpid $pid, 0;

    return { _no_run => 'executor did not serve' } unless $r;
    return { _no_run => "exit $r->{exit}: " . ($r->{stderr} // $r->{error} // '') }
        unless $r->{exit} == 0;
    my %env;
    for my $line (split /\n/, $r->{stdout} // '') {
        $env{$1} = $2 if $line =~ /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/;
    }
    return \%env;
}

sub dropped_ok {
    my ($env) = @_;
    for my $k (qw(LD_LIBRARY_PATH BASH_ENV IFS PERL5LIB CE_MARKER)) {
        ok !exists $env->{$k}, "$k is not passed to the action";
    }
    ok !grep({ /^LD_/ } keys %$env), 'no LD_* variable at all';
    is $env->{PATH}, '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
        'PATH is the fixed value';
}

subtest 'run_as by name: HOME, USER and LOGNAME from its passwd entry' => sub {
    my $env = env_under_profile('named', "run_as = nobody\n");
    ok !$env->{_no_run}, 'probe ran' or diag($env->{_no_run}), return;
    is $env->{HOME},    $nobody_home, "HOME is nobody's home ($nobody_home)";
    is $env->{USER},    $nobody_name, 'USER is the run_as user';
    is $env->{LOGNAME}, $nobody_name, 'LOGNAME is the run_as user';
    dropped_ok($env);
};

subtest 'numeric run_as with a passwd entry: the three from that entry' => sub {
    my $env = env_under_profile('numeric', "run_as = $nobody[2]\n");
    ok !$env->{_no_run}, 'probe ran' or diag($env->{_no_run}), return;
    is $env->{HOME},    $nobody_home, "HOME is uid $nobody[2]'s home";
    is $env->{USER},    $nobody_name, "USER is uid $nobody[2]'s name";
    is $env->{LOGNAME}, $nobody_name, "LOGNAME is uid $nobody[2]'s name";
    dropped_ok($env);
};

subtest 'numeric run_as with no passwd entry: the three are left unset' => sub {
    my $env = env_under_profile('orphan', "run_as = $orphan\n");
    ok !$env->{_no_run}, 'probe ran' or diag($env->{_no_run}), return;
    ok !exists $env->{$_}, "$_ is unset" for qw(HOME USER LOGNAME);
    dropped_ok($env);
};

subtest 'no run_as: the environment is PATH alone, as before' => sub {
    my $env = env_under_profile('noras', '');
    ok !$env->{_no_run}, 'probe ran' or diag($env->{_no_run}), return;
    ok !exists $env->{$_}, "$_ is unset" for qw(HOME USER LOGNAME);
    dropped_ok($env);
};

done_testing;
