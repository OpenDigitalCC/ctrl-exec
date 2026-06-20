#!/usr/bin/perl
# t/dispatcher-config.t
#
# Error-path tests for Exec::DispatcherConfig::load_config, the flat INI loader
# shared by ctrl-exec-dispatcher and ctrl-exec-api. Its safety property is
# fail-closed on a missing required key: a config without cert/key/ca must not
# load. That contract was previously unpinned.

use strict;
use warnings;
use Test::More;
use File::Temp qw(tempfile tempdir);
use FindBin    qw($Bin);
use lib "$Bin/../lib";

use Exec::DispatcherConfig qw();

sub write_conf {
    my ($body) = @_;
    my ($fh, $path) = tempfile(UNLINK => 1, SUFFIX => '.conf');
    print $fh $body;
    close $fh;
    return $path;
}

subtest 'load_config: parses keys and ignores comments/blanks' => sub {
    my $path = write_conf(<<'CONF');
# a comment
cert = /etc/ctrl-exec/dispatcher.crt
key  = /etc/ctrl-exec/dispatcher.key

ca   = /etc/ctrl-exec/ca.crt
dispatcher_id = disp-1
CONF
    my $c = Exec::DispatcherConfig::load_config($path);
    is $c->{cert}, '/etc/ctrl-exec/dispatcher.crt', 'cert parsed';
    is $c->{key},  '/etc/ctrl-exec/dispatcher.key', 'key parsed';
    is $c->{ca},   '/etc/ctrl-exec/ca.crt',         'ca parsed';
    is $c->{dispatcher_id}, 'disp-1',               'extra key parsed';
};

subtest 'load_config: dies when a required key is missing' => sub {
    my $path = write_conf("cert = /c\nkey = /k\n");   # no ca
    eval { Exec::DispatcherConfig::load_config($path) };
    like $@, qr/Missing 'ca'/, 'missing ca is fail-closed with a clear message';
};

subtest 'load_config: dies when the file cannot be opened' => sub {
    my $dir = tempdir(CLEANUP => 1);
    eval { Exec::DispatcherConfig::load_config("$dir/does-not-exist.conf") };
    like $@, qr/Cannot open config/, 'unreadable config dies';
};

done_testing;
