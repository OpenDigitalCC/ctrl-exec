#!/usr/bin/perl
# t/exec-ownership-parity.t  (T-045)
#
# The script ownership rule is applied twice: by the root executor before every
# run (src/ctrl-exec-executor.c script_trust_check, the authority) and by the
# front end at allowlist load and before a run (Exec::Agent::Config::
# script_owner_check, which reports early and enforces in direct mode). The two
# must give the same verdict and the same reason for the same path. This test
# runs a corpus of paths through `ctrl-exec-executor check-path` and through the
# Perl walk and compares them line for line.
#
# Unprivileged: an ordinary user cannot create root-owned files, so the
# executor is compiled with -DCE_TEST_SEAM (test builds only) and both sides are
# pointed at the same seam: the test user is trusted like root, and the
# ancestors of the tempdir are not checked. A second pass trusts root alone, so
# the "owned by uid N, not root" reason is compared too. Host paths (/bin/sh,
# /etc/passwd, /tmp) are compared with no seam at all.
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use FindBin    qw($Bin);
use lib "$Bin/../lib";
use POSIX      qw(mkfifo);

use Exec::Agent::Config qw();

my $cc = `command -v gcc 2>/dev/null`; chomp $cc;
plan skip_all => 'gcc not available' unless $cc && -x $cc;

umask 022;
my $BUILD = tempdir(CLEANUP => 1);
my $BIN   = "$BUILD/ctrl-exec-executor";
system($cc, '-O2', '-DCE_TEST_SEAM', '-o', $BIN, "$Bin/../src/ctrl-exec-executor.c", '-lcap') == 0
    or plan skip_all => 'could not compile src/ctrl-exec-executor.c';

my $T = tempdir(CLEANUP => 1);
chmod 0755, $T;
sub wf { my ($p, $mode) = @_; open my $f, '>', $p or die "$p: $!";
         print $f "#!/bin/sh\nexit 0\n"; close $f; chmod $mode, $p }

mkdir "$T/good";  wf("$T/good/ok.sh", 0755);
wf("$T/good/gw.sh", 0775);
wf("$T/good/ww.sh", 0757);
wf("$T/good/ro.sh", 0444);
mkdir "$T/good/sub";
mkdir "$T/gw";    chmod 0775, "$T/gw";  wf("$T/gw/x.sh", 0755);
mkdir "$T/ww";    chmod 0777, "$T/ww";  wf("$T/ww/x.sh", 0755);
mkdir "$T/sticky"; chmod 01777, "$T/sticky"; wf("$T/sticky/x.sh", 0755);
symlink 'ok.sh',            "$T/good/rel-link";
symlink "$T/good/ok.sh",    "$T/good/abs-link";
symlink '../gw/x.sh',       "$T/good/up-link";
symlink 'loop',             "$T/good/loop";
symlink '../good',          "$T/good/dirlink";
symlink "$T/ww",            "$T/good/to-ww";
mkfifo("$T/good/fifo", 0644) or die "mkfifo: $!";

my @corpus = (
    "$T/good/ok.sh",                 # passes
    "$T/good/ro.sh",                 # read-only file passes
    "$T/good/gw.sh",                 # group-writable file
    "$T/good/ww.sh",                 # world-writable file
    "$T/gw/x.sh",                    # under a group-writable dir
    "$T/ww/x.sh",                    # under a world-writable dir
    "$T/sticky/x.sh",                # sticky does not help
    "$T/good/sub",                   # a directory is not a script
    "$T/good/fifo",                  # nor is a fifo
    "$T/good/ok.sh/x",               # a file in the middle of the path
    "$T/good/rel-link",              # relative link in a checked dir: followed
    "$T/good/abs-link",              # absolute link: followed
    "$T/good/up-link",               # link into a group-writable dir
    "$T/good/loop",                  # link loop
    "$T/good/dirlink/ok.sh",         # link as a directory component
    "$T/good/to-ww/x.sh",            # link to a world-writable dir
    "$T/good/../good/ok.sh",         # .. walks back up
    "$T/good/./ok.sh",
    "$T//good///ok.sh",
    "$T/good/",
    "$T/good/.",
    "$T/good/..",
    "$T/good/nope.sh",               # missing: no verdict
    "$T/none/x.sh",
    '/',
);

sub perl_line {
    my ($path) = @_;
    my ($v, $why) = Exec::Agent::Config::script_owner_check($path);
    return 'OK' if $v eq 'ok';
    return $v eq 'deny' ? "DENY $why" : 'UNKNOWN';
}
sub c_line {
    my ($path) = @_;
    my $out = `\Q$BIN\E check-path \Q$path\E`;
    chomp $out;
    $out = 'UNKNOWN' if $out =~ /^UNKNOWN /;   # the error texts differ ($! vs strerror)
    return $out;
}

subtest 'seam: test user trusted like root' => sub {
    local $ENV{CE_TEST_TRUSTED_UID} = $>;
    local $ENV{CE_TEST_TRUSTED_TOP} = $T;
    local @Exec::Agent::Config::TRUSTED_OWNERS = (0, $>);
    local $Exec::Agent::Config::TRUSTED_TOP    = $T;
    for my $p (@corpus) {
        is c_line($p), perl_line($p), "same verdict: $p";
    }
    # Spot-check that the verdicts are the intended ones, not merely equal.
    is perl_line("$T/good/ok.sh"),     'OK', 'a correctly owned script passes';
    is perl_line("$T/good/gw.sh"),     "DENY '$T/good/gw.sh' is group-writable", 'group-writable script';
    is perl_line("$T/ww/x.sh"),        "DENY '$T/ww' is world-writable", 'world-writable directory';
    is perl_line("$T/good/up-link"),   "DENY '$T/gw' is group-writable", 'link target is checked';
    is perl_line("$T/good/loop"),      "DENY '$T/good/loop' has too many levels of symbolic links", 'loop';
    is perl_line("$T/good/sub"),       "DENY '$T/good/sub' is not a regular file", 'directory';
    is perl_line("$T/good/ok.sh/x"),   "DENY '$T/good/ok.sh' is not a directory", 'file mid-path';
    is perl_line("$T/good/rel-link"),  'OK', 'link in a checked directory is followed';
    is perl_line("$T/good/nope.sh"),   'UNKNOWN', 'missing script: no verdict';
};

subtest 'root alone trusted' => sub {
    local $ENV{CE_TEST_TRUSTED_TOP} = $T;
    local @Exec::Agent::Config::TRUSTED_OWNERS = (0);
    local $Exec::Agent::Config::TRUSTED_TOP    = $T;
    delete local $ENV{CE_TEST_TRUSTED_UID};
    for my $p (@corpus) {
        is c_line($p), perl_line($p), "same verdict: $p";
    }
    is perl_line("$T/good/ok.sh"), "DENY '$T' is owned by uid $>, not root",
        'a directory owned by another user is refused'
        unless $> == 0;
};

subtest 'host paths, no seam' => sub {
    delete local $ENV{CE_TEST_TRUSTED_UID};
    delete local $ENV{CE_TEST_TRUSTED_TOP};
    for my $p ('/bin/sh', '/usr/bin/env', '/etc/passwd', '/tmp', '/tmp/x', $T, "$T/good/ok.sh",
               ($ENV{HOME} // '/root')) {
        is c_line($p), perl_line($p), "same verdict: $p";
    }
};

done_testing;
