use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use FindBin    qw($Bin);

# `ctrl-exec-agent cert-staged` exits 0 when a renewed cert is staged and 1
# otherwise, reading cert_staging_path from the config so the renew timer's
# restart decision honours an override. Black-box: run the binary and check its
# exit code.

my $agent = "$Bin/../bin/ctrl-exec-agent";
my $dir   = tempdir(CLEANUP => 1);
my $conf  = "$dir/agent.conf";
my $staged = "$dir/agent.crt.staged";

open my $c, '>', $conf or die $!;
print $c "port = 7443\ncert = /x\nkey = /y\nca = /z\n"
       . "cert_staging_path = $staged\n";
close $c;

my @cmd = ($^X, "-I$Bin/../lib", $agent, '--config', $conf, 'cert-staged');

is system(@cmd) >> 8, 1, 'cert-staged exits 1 when nothing is staged';

open my $s, '>', $staged or die $!;
print $s "-----BEGIN CERTIFICATE-----\n";
close $s;

is system(@cmd) >> 8, 0, 'cert-staged exits 0 when a cert is staged';

done_testing;
