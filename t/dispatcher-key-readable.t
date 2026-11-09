#!/usr/bin/perl
# t/dispatcher-key-readable.t
#
# T-076: a user who cannot read dispatcher.key (a ctrl-exec group member; the key
# stays 0600 by design) gets a plain message from ced and a PROBLEM from doctor,
# not LWP's "SSL_key_file ... Permission denied"; commands that do not connect to
# agents are unchanged; an unknown short agent name gets a "did you mean" hint
# when exactly one registered name starts with "<name>.".
# Fixtures only: the config directories are the fixture's (DispatcherRoot).

use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/../lib", "$Bin/lib";
use File::Temp qw(tempdir);
use File::Path qw(make_path);
use JSON qw(decode_json encode_json);

use Exec::Doctor::Dispatcher qw();
use Exec::DispatcherConfig   qw();
use Exec::Registry           qw();
use Exec::Log                qw();
{ no warnings 'redefine'; *Exec::Log::log_action = sub { 1 }; }

sub spew { open my $fh, '>', $_[0] or die "$_[0]: $!"; print $fh $_[1]; close $fh }

sub fixture {
    my $r = tempdir(CLEANUP => 1);
    my $d = "$r/etc/ctrl-exec-dispatcher";
    make_path($d, "$r/agents");
    spew("$d/$_", "x\n") for qw(ca.crt dispatcher.crt);
    spew("$d/dispatcher.key", "x\n");
    chmod 0600, "$d/dispatcher.key";
    spew("$d/ctrl-exec.conf", "cert = $d/dispatcher.crt\nkey = $d/dispatcher.key\nca = $d/ca.crt\n"
       . "registry_dir = $r/agents\n");
    return { root => $r, dir => $d, conf => "$d/ctrl-exec.conf", key => "$d/dispatcher.key" };
}

# ced as a subprocess; returns (stdout, stderr, exit).
sub ced {
    my ($x, @args) = @_;
    local $ENV{CE_TEST_DISPATCHER_ROOT} = $x->{root};
    my $err = "$x->{root}/stderr";
    my @cmd = ($^X, "-I$Bin/../lib", "-I$Bin/lib", '-MNoSyslog', '-MDispatcherRoot',
               "$Bin/../bin/ctrl-exec-dispatcher", '--config', $x->{conf}, @args);
    open my $p, '-|', "@cmd 2>$err" or die "run: $!";
    local $/; my $out = <$p> // ''; close $p;
    my $rc = $? >> 8;
    open my $e, '<', $err or die; my $se = <$e> // ''; close $e;
    return ($out, $se, $rc);
}

sub doctor {
    my ($x) = @_;
    local $Exec::DispatcherConfig::CONF_DIR   = $x->{dir};
    local $Exec::DispatcherConfig::LEGACY_DIR = "$x->{root}/etc/ctrl-exec";
    local $Exec::Doctor::Dispatcher::DPKG_INFO = "$x->{root}/dpkg-info";
    return Exec::Doctor::Dispatcher::checks(config => $x->{conf});
}

my $me = scalar(getpwuid($>)) // $>;

SKIP: {
    skip 'root reads every file', 9 unless $>;

    subtest 'ced ping: unreadable key' => sub {
        my $x = fixture();
        chmod 0, $x->{key};
        my ($out, $err, $rc) = ced($x, 'ping', 'agent-01');
        is $rc, 1, 'exit 1';
        is $out, '', 'nothing on stdout';
        like $err, qr/cannot read \Q$x->{key}\E as \Q$me\E/, 'names the key and the user';
        like $err, qr/sudo.*API/s, 'says to use sudo or the API';
        unlike $err, qr/SSL_key_file|LWP/, 'nothing from LWP';
        chmod 0600, $x->{key};
    };

    subtest 'ced run: unreadable key' => sub {
        my $x = fixture();
        chmod 0, $x->{key};
        my ($out, $err, $rc) = ced($x, 'run', 'agent-01', 'backup');
        is $rc, 1, 'exit 1';
        like $err, qr/cannot read \Q$x->{key}\E as/, 'the same message' or diag $err;
        chmod 0600, $x->{key};
    };

    subtest 'a readable key does not trigger the message' => sub {
        my $x = fixture();
        my ($out, $err, $rc) = ced($x, 'ping', 'agent-01');
        unlike $err, qr/^Error: cannot read/m, 'no key message';
    };

    subtest 'doctor --json with an unreadable key: stdout stays JSON' => sub {
        my $x = fixture();
        chmod 0, $x->{key};
        my ($out, $err, $rc) = ced($x, 'doctor', '--json');
        my $j = eval { decode_json($out) };
        ok $j, 'stdout is JSON' or diag $out;
        unlike $err, qr/^Error: cannot read/m, 'no ced key message (the finding is logged, as always)';
        ok((grep { $_->{check} eq 'key-unreadable' && $_->{severity} eq 'problem' } @{ $j->{findings} }),
           'reports the key problem');
        is $rc, 1, 'exit 1';
        chmod 0600, $x->{key};
    };

    subtest 'doctor: unreadable key is a problem for this caller' => sub {
        my $x = fixture();
        chmod 0, $x->{key};
        my $f = doctor($x);
        my ($p) = grep { $_->{check} eq 'key-unreadable' } @$f;
        ok $p, 'a finding';
        is $p->{severity}, 'problem', 'a problem, not a note';
        like $p->{what}, qr/ced will not work for this user/, 'says ced will not work';
        like $p->{what}, qr/as \Q$me\E/, 'names the user';
        like $p->{fix}, qr/sudo.*API.*by design/s, 'sudo or the API; by design';
        chmod 0600, $x->{key};
        is_deeply [ grep { $_->{check} eq 'key-unreadable' } @{ doctor($x) } ], [], 'readable: no finding';
    };

    subtest 'doctor: a directory it cannot search is a problem for this caller' => sub {
        my $x = fixture();
        chmod 0, $x->{dir};
        my $f = doctor($x);
        chmod 0700, $x->{dir};
        is scalar(@$f), 1, 'one finding';
        is $f->[0]{severity}, 'problem', 'a problem';
        like $f->[0]{what}, qr/ced will not work for this user/, 'says why it matters';
    };

    subtest 'doctor: unreadable ctrl-exec.conf stays a note' => sub {
        my $x = fixture();
        chmod 0, $x->{conf};
        my $f = doctor($x);
        chmod 0600, $x->{conf};
        is_deeply [ map { $_->{severity} } @$f ], ['note'], 'unchanged';
    };

    subtest 'a command that does not connect gains no check' => sub {
        my $x = fixture();
        chmod 0, $x->{key};
        my ($out, $err, $rc) = ced($x, 'list-requests');
        unlike $err, qr/^Error: cannot read/m, 'no key message';
        chmod 0600, $x->{key};
    };
}

subtest 'did you mean' => sub {
    my $x = fixture();
    my $dir = "$x->{root}/agents";
    spew("$dir/$_.json", encode_json({ hostname => $_, ip => '192.0.2.1' }))
        for qw(web.example.com db1.example.com db1.example.net other-01);
    my $h = sub { Exec::Registry::did_you_mean([@_], registry_dir => $dir) };
    is $h->('web'), "Did you mean web.example.com?\n", 'one match';
    is $h->('web:7443'), "Did you mean web.example.com?\n", 'port ignored';
    is $h->('db1'), '', 'several matches: no hint';
    is $h->('nothing'), '', 'no match: no hint';
    is $h->('other'), '', 'a name without the dot is not a prefix match';
    is $h->('web', 'nothing'), "Did you mean web.example.com?\n", 'per reference';
};

done_testing;
