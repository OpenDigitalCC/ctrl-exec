#!/usr/bin/perl
# t/file-util.t
#
# Contract tests for Exec::FileUtil. write_atomic is the single atomic
# temp+rename writer the whole codebase relies on for torn-read-free
# registry/run/cert files; a regression to a plain truncating write would not
# break any happy-path caller but would reintroduce the torn reads this module
# exists to prevent. Pin the contract: round-trip, file mode, the make_dir=>0
# croak, and that no temp residue is left behind.

use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use FindBin    qw($Bin);
use lib "$Bin/../lib";

use Exec::FileUtil qw();

subtest 'write_atomic: round-trips content' => sub {
    my $dir  = tempdir(CLEANUP => 1);
    my $path = "$dir/data.json";
    Exec::FileUtil::write_atomic($path, "hello\nworld\n");
    is Exec::FileUtil::slurp($path), "hello\nworld\n", 'content read back intact';
};

subtest 'write_atomic: honours the mode option' => sub {
    my $dir  = tempdir(CLEANUP => 1);
    my $path = "$dir/secret";
    Exec::FileUtil::write_atomic($path, "x", mode => 0600);
    my $perm = (stat $path)[2] & 07777;
    is $perm, 0600, 'final file has the requested 0600 mode';
};

subtest 'write_atomic: make_dir default creates the parent' => sub {
    my $dir  = tempdir(CLEANUP => 1);
    my $path = "$dir/a/b/c/data";
    Exec::FileUtil::write_atomic($path, "deep");
    ok -f $path, 'nested parent dirs created by default';
};

subtest 'write_atomic: make_dir=>0 croaks when the parent is absent' => sub {
    my $dir  = tempdir(CLEANUP => 1);
    my $path = "$dir/nope/data";
    eval { Exec::FileUtil::write_atomic($path, "x", make_dir => 0) };
    like $@, qr/does not exist/, 'croaks rather than silently creating the dir';
    ok !-e $path, 'nothing written';
};

subtest 'write_atomic: leaves no temp-file residue on success' => sub {
    my $dir  = tempdir(CLEANUP => 1);
    Exec::FileUtil::write_atomic("$dir/final", "x");
    opendir my $dh, $dir or die $!;
    my @files = grep { !/^\.\.?$/ } readdir $dh;
    closedir $dh;
    is_deeply [sort @files], ['final'],
        'only the final file remains; the temp file was renamed away';
};

subtest 'slurp vs slurp_maybe on a missing file' => sub {
    my $dir = tempdir(CLEANUP => 1);
    eval { Exec::FileUtil::slurp("$dir/absent") };
    like $@, qr/Cannot read/, 'slurp croaks on a missing file';
    is Exec::FileUtil::slurp_maybe("$dir/absent"), undef,
        'slurp_maybe returns undef on a missing file';
};

done_testing;
