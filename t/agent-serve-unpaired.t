#!/usr/bin/perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use FindBin qw($Bin);

# When the agent is started before it has been paired, the certificate, key,
# and CA the TLS listener needs do not exist yet. The serve path must explain
# that the agent needs pairing and how to do it - not let IO::Socket::SSL die
# deep in its internals with a cryptic "SSL_cert_file ... can't be used".

my $agent = "$Bin/../bin/ctrl-exec-agent";
my $lib   = "$Bin/../lib";

my $dir   = tempdir(CLEANUP => 1);
my $conf  = "$dir/agent.conf";
my $allow = "$dir/scripts.conf";
my $missing = "$dir/no-such-dir";   # never created -> cert/key/ca absent

open my $cfh, '>', $conf or die "write $conf: $!";
print $cfh <<"END";
port = 7443
cert = $missing/agent.crt
key  = $missing/agent.key
ca   = $missing/ca.crt
END
close $cfh;

open my $afh, '>', $allow or die "write $allow: $!";   # empty allowlist
close $afh;

my $cmd = sprintf(
    '%s -I%s %s --config %s --allowlist %s serve 2>&1',
    $^X, _q($lib), _q($agent), _q($conf), _q($allow),
);
my $out = qx{$cmd};
my $rc  = $? >> 8;

isnt $rc, 0, 'serve without pairing exits non-zero';
like $out, qr/not been paired/i,
    'explains the agent has not been paired';
like $out, qr/request-pairing --dispatcher/,
    'tells the operator how to pair';
like $out, qr/pairing-status/,
    'points at pairing-status to check state';
unlike $out, qr/SSL_cert_file.*can't be used/i,
    'no raw IO::Socket::SSL croak leaks through';

done_testing;

# Minimal shell quoting for the paths we control (temp dirs, repo paths).
sub _q {
    my ($s) = @_;
    $s =~ s/'/'\\''/g;
    return "'$s'";
}
