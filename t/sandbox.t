#!/usr/bin/perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use FindBin    qw($Bin);
use lib "$Bin/../lib";

use Exec::Agent::Sandbox qw();
use Exec::Agent::Config  qw();

# --- render_dropin: level -> filesystem-protection directives ---

subtest 'strict (default) with writable_paths' => sub {
    my $t = Exec::Agent::Sandbox::render_dropin(
        { sandbox => 'strict', writable_paths => ['/srv/certificates', '/var/log/app'] });
    like $t, qr/^\[Service\]/m,              'has [Service] section';
    like $t, qr/^ProtectSystem=strict$/m,    'ProtectSystem=strict';
    like $t, qr/^ProtectHome=yes$/m,         'ProtectHome=yes';
    like $t, qr{^ReadWritePaths=/srv/certificates$}m, 'first writable path';
    like $t, qr{^ReadWritePaths=/var/log/app$}m,      'second writable path';
    like $t, qr/Do not edit by hand/,        'carries a generated-file warning';
};

subtest 'default level is strict when sandbox key absent' => sub {
    my $t = Exec::Agent::Sandbox::render_dropin({});
    like $t, qr/^ProtectSystem=strict$/m, 'absent sandbox => strict';
};

subtest 'moderate maps to ProtectSystem=full' => sub {
    my $t = Exec::Agent::Sandbox::render_dropin({ sandbox => 'moderate' });
    like   $t, qr/^ProtectSystem=full$/m, 'ProtectSystem=full';
    like   $t, qr/^ProtectHome=yes$/m,    'home still protected';
    unlike $t, qr/ReadWritePaths/,        'no paths when none configured';
};

subtest 'off disables protection and ignores writable_paths' => sub {
    my $t = Exec::Agent::Sandbox::render_dropin(
        { sandbox => 'off', writable_paths => ['/srv/x'] });
    like   $t, qr/^ProtectSystem=no$/m,  'ProtectSystem=no';
    like   $t, qr/^ProtectHome=no$/m,    'ProtectHome=no';
    unlike $t, qr/ReadWritePaths/, 'ReadWritePaths redundant under no protection';
};

subtest 'invalid level croaks' => sub {
    eval { Exec::Agent::Sandbox::render_dropin({ sandbox => 'paranoid' }) };
    like $@, qr/invalid sandbox level/, 'unknown level rejected';
};

subtest 'valid_level' => sub {
    ok  Exec::Agent::Sandbox::valid_level($_), "$_ valid" for qw(strict moderate off);
    ok !Exec::Agent::Sandbox::valid_level('paranoid'), 'paranoid invalid';
    ok !Exec::Agent::Sandbox::valid_level(undef),      'undef invalid';
};

# --- Config parses and validates sandbox + writable_paths ---

sub write_conf {
    my ($body) = @_;
    my $dir = tempdir(CLEANUP => 1);
    open my $fh, '>', "$dir/agent.conf" or die $!;
    print $fh "port = 7443\ncert = /x.crt\nkey = /x.key\nca = /ca.crt\n$body";
    close $fh;
    return "$dir/agent.conf";
}

subtest 'Config: sandbox + writable_paths parsed' => sub {
    my $c = Exec::Agent::Config::load_config(
        write_conf("sandbox = moderate\nwritable_paths = /srv/a:/srv/b\n"));
    is $c->{sandbox}, 'moderate', 'sandbox kept';
    is_deeply $c->{writable_paths}, ['/srv/a', '/srv/b'], 'writable_paths split';
};

subtest 'Config: sandbox lowercased, absent writable_paths dropped' => sub {
    my $c = Exec::Agent::Config::load_config(write_conf("sandbox = STRICT\n"));
    is $c->{sandbox}, 'strict', 'level lowercased';
    ok !exists $c->{writable_paths}, 'absent writable_paths not present';
};

subtest 'Config: invalid sandbox level rejected at load' => sub {
    eval { Exec::Agent::Config::load_config(write_conf("sandbox = loose\n")) };
    like $@, qr/sandbox must be one of/, 'bad level croaks at load';
};

done_testing;
