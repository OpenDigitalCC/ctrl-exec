#!/usr/bin/perl
# Shared conformance test: the C executor (ctrl-exec-exec) and the Perl front-end
# (Exec::Agent::Config) must derive the IDENTICAL security decision for the same
# agent.conf/scripts.conf - same allow/deny, same resolved profile fields. If
# they ever diverge, the executor would apply a different privilege than the
# front-end authorised. Both parsers are exercised here against the same fixtures.
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use FindBin    qw($Bin);
use lib "$Bin/../lib";

use Exec::Agent::Config qw();

my $cc = `command -v gcc 2>/dev/null`; chomp $cc;
plan skip_all => 'gcc not available' unless $cc && -x $cc;

my $TMP = tempdir(CLEANUP => 1);
my $BIN = "$TMP/ctrl-exec-exec";
system($cc, '-O2', '-o', $BIN, "$Bin/../src/ctrl-exec-exec.c", '-lcap') == 0
    or plan skip_all => 'could not compile src/ctrl-exec-exec.c';

my $REQUIRED = "port = 7443\ncert = /x\nkey = /y\nca = /z\n";
my $n = 0;
sub wf { my ($body) = @_; my $p = "$TMP/f." . (++$n);
    open my $f, '>', $p or die $!; print $f $body; close $f; return $p }

# The C decision: stdout line, or CONFIG-ERROR on exit 2.
sub c_resolve {
    my ($a, $s, $name) = @_;
    my $out = `\Q$BIN\E resolve \Q$a\E \Q$s\E \Q$name\E 2>/dev/null`;
    return 'CONFIG-ERROR' if ($? >> 8) == 2;
    chomp $out;
    return $out;
}

# The Perl decision, formatted into the same canonical line as the C resolve.
sub perl_resolve {
    my ($a, $s, $name) = @_;
    local $SIG{__WARN__} = sub {};
    my $config = eval { Exec::Agent::Config::load_config($a) };
    return 'CONFIG-ERROR' if $@;
    # No script_dirs here so out-of-dir entries are still present; validate_script
    # applies the dir check below, mirroring the C (find then dir-check).
    my $al = Exec::Agent::Config::load_allowlist($s);
    return "DENY not-allowlisted" unless exists $al->{$name};
    my $path = Exec::Agent::Config::validate_script($name, $al, $config->{script_dirs});
    return "DENY not-in-script-dirs" unless defined $path;
    my $prof = Exec::Agent::Config::script_profile($name, $al);
    my $defined = ($prof eq 'default') || exists $config->{profiles}{$prof};
    return "DENY undefined-profile" unless $defined;
    my $p = $config->{profiles}{$prof};   # undef for the implicit default
    my $runas = $p ? ($p->{run_as} // '')            : '';
    my $nnp   = $p ? ($p->{no_new_privileges} // 1)   : 1;
    my $caps  = $p ? join(',', @{ $p->{caps}     // [] }) : '';
    my $writ  = $p ? join(':', @{ $p->{writable} // [] }) : '';
    return "OK path=$path|profile=$prof|run_as=$runas|nnp=$nnp|caps=$caps|writable=$writ";
}

# --- fixtures: each names the scripts to resolve against one config pair -------

my @fixtures = (
    {
        label   => 'default + defined profile + order-independent profile=',
        agent   => $REQUIRED . "script_dirs = /opt/s\n"
                 . "[profile cert-deploy]\nrun_as = root\ncaps = CAP_CHOWN, CAP_KILL\n"
                 . "writable = /etc/ssl:/srv/certificates\n",
        scripts => "status      = /opt/s/status.sh\n"
                 . "deploy-cert = /opt/s/deploy.sh profile=cert-deploy\n"
                 . "before      = profile=cert-deploy /opt/s/b.sh\n"
                 . "outside     = /elsewhere/x.sh\n"
                 . "ghost       = /opt/s/g.sh profile=nope\n"
                 . "relative    = opt/s/rel.sh\n",
        names   => [qw(status deploy-cert before outside ghost relative missing)],
    },
    {
        label   => 'no script_dirs => no dir restriction',
        agent   => $REQUIRED . "[profile p]\nrun_as = www-data\n",
        scripts => "anywhere = /var/tmp/a.sh profile=p\n",
        names   => [qw(anywhere)],
    },
    {
        label   => 'explicit [profile default] override + nnp off',
        agent   => $REQUIRED . "[profile default]\nrun_as = nobody\nno_new_privileges = no\n",
        scripts => "x = /opt/x.sh\n",
        names   => [qw(x)],
    },
    {
        label   => 'two paths on a line => skipped (not-allowlisted)',
        agent   => $REQUIRED,
        scripts => "bad = /opt/a.sh /opt/b.sh\ngood = /opt/g.sh\n",
        names   => [qw(bad good)],
    },
    {
        label   => 'config error: invalid capability (both must reject)',
        agent   => $REQUIRED . "[profile x]\ncaps = NOTCAP\n",
        scripts => "s = /opt/s.sh profile=x\n",
        names   => [qw(s)],
    },
    {
        label   => 'config error: out-of-range numeric run_as (both must reject)',
        agent   => $REQUIRED . "[profile big]\nrun_as = 99999999999999999999\n",
        scripts => "s = /opt/s.sh profile=big\n",
        names   => [qw(s)],
    },
    {
        label   => 'whole-line comments + mixed comma/space cap separators agree',
        agent   => $REQUIRED . "script_dirs = /opt/s\n"
                 . "# a comment line in agent.conf\n"
                 . "[profile mixed]\n"
                 . "run_as = www-data\n"
                 . "caps = CAP_CHOWN,CAP_KILL CAP_SETUID\n"
                 . "no_new_privileges = yes\n",
        scripts => "# a comment line in scripts.conf\n"
                 . "s = /opt/s/s.sh profile=mixed\n",
        names   => [qw(s)],
    },
);

for my $fx (@fixtures) {
    my $a = wf($fx->{agent});
    my $s = wf($fx->{scripts});
    subtest $fx->{label} => sub {
        for my $name (@{ $fx->{names} }) {
            my $perl = perl_resolve($a, $s, $name);
            my $c    = c_resolve($a, $s, $name);
            is $c, $perl, "'$name': C and Perl agree ($perl)";
        }
    };
}

done_testing;
