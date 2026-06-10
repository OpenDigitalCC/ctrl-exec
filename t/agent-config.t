#!/usr/bin/perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempfile tempdir);
use FindBin qw($Bin);
use lib "$Bin/../lib";

use Exec::Agent::Config qw();

# --- load_config ---

sub write_temp {
    my ($content) = @_;
    my ($fh, $path) = tempfile(UNLINK => 1, SUFFIX => '.conf');
    print $fh $content;
    close $fh;
    return $path;
}

subtest 'load_config: valid config' => sub {
    my $path = write_temp(<<'END');
port = 7443
cert = /etc/ctrl-exec-agent/agent.crt
key  = /etc/ctrl-exec-agent/agent.key
ca   = /etc/ctrl-exec-agent/ca.crt
END
    my $c = Exec::Agent::Config::load_config($path);
    is $c->{port}, '7443',                          'port parsed';
    is $c->{cert}, '/etc/ctrl-exec-agent/agent.crt', 'cert parsed';
    is $c->{key},  '/etc/ctrl-exec-agent/agent.key', 'key parsed';
    is $c->{ca},   '/etc/ctrl-exec-agent/ca.crt',    'ca parsed';
};

subtest 'load_config: comments and blanks ignored' => sub {
    my $path = write_temp(<<'END');
# This is a comment
port = 7443

cert = /tmp/a.crt
key  = /tmp/a.key
ca   = /tmp/ca.crt
END
    my $c = eval { Exec::Agent::Config::load_config($path) };
    ok !$@, 'no error';
    is $c->{port}, '7443', 'port correct';
};

subtest 'load_config: missing required key dies' => sub {
    my $path = write_temp("port = 7443\ncert = /a.crt\nkey = /a.key\n");
    eval { Exec::Agent::Config::load_config($path) };
    like $@, qr/Missing required config key 'ca'/, 'dies on missing ca';
};

subtest 'load_config: non-numeric port dies' => sub {
    my $path = write_temp("port = abc\ncert=/a\nkey=/b\nca=/c\n");
    eval { Exec::Agent::Config::load_config($path) };
    like $@, qr/port must be numeric/, 'dies on bad port';
};

subtest 'load_config: malformed line dies' => sub {
    my $path = write_temp("port = 7443\ncert=/a\nkey=/b\nca=/c\nthis is bad\n");
    eval { Exec::Agent::Config::load_config($path) };
    like $@, qr/Malformed config line/, 'dies on bad line';
};

subtest 'load_config: missing file dies' => sub {
    eval { Exec::Agent::Config::load_config('/nonexistent/path.conf') };
    like $@, qr/Cannot open config/, 'dies on missing file';
};

# --- load_allowlist ---

subtest 'load_allowlist: valid entries' => sub {
    my $path = write_temp(<<'END');
# comment
backup-mysql = /opt/scripts/backup.sh
rotate-logs  = /opt/scripts/rotate.sh
END
    my $al = Exec::Agent::Config::load_allowlist($path);
    is $al->{'backup-mysql'}, '/opt/scripts/backup.sh', 'backup-mysql path';
    is $al->{'rotate-logs'},  '/opt/scripts/rotate.sh', 'rotate-logs path';
};

subtest 'load_allowlist: relative path skipped with warning' => sub {
    my $path = write_temp("bad-script = relative/path.sh\ngood = /abs/path.sh\n");
    my $warn = '';
    local $SIG{__WARN__} = sub { $warn .= $_[0] };
    my $al = Exec::Agent::Config::load_allowlist($path);
    ok !exists $al->{'bad-script'}, 'relative path not in allowlist';
    ok  exists $al->{'good'},       'absolute path accepted';
    like $warn, qr/must be absolute/, 'warning issued';
};

subtest 'load_allowlist: malformed line skipped with warning' => sub {
    my $path = write_temp("good = /abs/path.sh\nthis line is junk!!\n");
    my $warn = '';
    local $SIG{__WARN__} = sub { $warn .= $_[0] };
    my $al = Exec::Agent::Config::load_allowlist($path);
    is scalar keys %$al, 1, 'only valid entry kept';
    like $warn, qr/malformed/, 'warning issued';
};

subtest 'load_allowlist: empty file returns empty hashref' => sub {
    my $path = write_temp("# only comments\n\n");
    my $al = Exec::Agent::Config::load_allowlist($path);
    is ref $al, 'HASH',       'returns hashref';
    is scalar keys %$al, 0,   'empty';
};

# --- validate_script ---

subtest 'validate_script: permitted script returns path' => sub {
    my $al = { 'check-disk' => '/opt/check-disk.sh' };
    my $path = Exec::Agent::Config::validate_script('check-disk', $al);
    is $path, '/opt/check-disk.sh', 'correct path returned';
};

subtest 'validate_script: unknown script returns undef' => sub {
    my $al = { 'check-disk' => '/opt/check-disk.sh' };
    my $r = Exec::Agent::Config::validate_script('rm-rf', $al);
    ok !defined $r, 'undef for unknown script';
};

subtest 'validate_script: invalid characters returns undef' => sub {
    my $al = { 'check-disk' => '/opt/check-disk.sh' };
    for my $bad ('', '../etc/passwd', 'foo;bar', 'a b', 'foo/bar') {
        my $r = Exec::Agent::Config::validate_script($bad, $al);
        ok !defined $r, "undef for bad name '$bad'";
    }
};

subtest 'validate_script: undef name returns undef' => sub {
    my $al = { 'check-disk' => '/opt/check-disk.sh' };
    my $r = Exec::Agent::Config::validate_script(undef, $al);
    ok !defined $r, 'undef for undef name';
};

# --- [tags] section ---

subtest 'load_config: [tags] section parsed into tags hashref' => sub {
    my $path = write_temp(<<'END');
port = 7443
cert = /etc/ctrl-exec-agent/agent.crt
key  = /etc/ctrl-exec-agent/agent.key
ca   = /etc/ctrl-exec-agent/ca.crt

[tags]
env  = prod
role = db
site = london
END
    my $c = Exec::Agent::Config::load_config($path);
    is ref($c->{tags}), 'HASH',   'tags is a hashref';
    is $c->{tags}{env},  'prod',   'env tag parsed';
    is $c->{tags}{role}, 'db',     'role tag parsed';
    is $c->{tags}{site}, 'london', 'site tag parsed';
};

subtest 'load_config: [tags] section is optional' => sub {
    my $path = write_temp(<<'END');
port = 7443
cert = /etc/ctrl-exec-agent/agent.crt
key  = /etc/ctrl-exec-agent/agent.key
ca   = /etc/ctrl-exec-agent/ca.crt
END
    my $c = Exec::Agent::Config::load_config($path);
    ok !defined $c->{tags} || ref($c->{tags}) eq 'HASH',
        'tags absent or empty hashref when section not present';
};

subtest 'load_config: tags do not interfere with top-level keys' => sub {
    my $path = write_temp(<<'END');
port = 7443
cert = /etc/ctrl-exec-agent/agent.crt
key  = /etc/ctrl-exec-agent/agent.key
ca   = /etc/ctrl-exec-agent/ca.crt

[tags]
env = staging
END
    my $c = Exec::Agent::Config::load_config($path);
    is $c->{port}, '7443',     'port unaffected by tags section';
    is $c->{tags}{env}, 'staging', 'tag parsed correctly';
    ok !exists $c->{env}, 'tag key not promoted to top-level config';
};

subtest 'load_config: unknown section keys are silently ignored' => sub {
    my $path = write_temp(<<'END');
port = 7443
cert = /etc/ctrl-exec-agent/agent.crt
key  = /etc/ctrl-exec-agent/agent.key
ca   = /etc/ctrl-exec-agent/ca.crt

[unknown]
foo = bar
END
    my $c = eval { Exec::Agent::Config::load_config($path) };
    ok !$@,               'no error for unknown section';
    ok !exists $c->{foo}, 'unknown section key not in config';
};

subtest 'load_config: empty [tags] section returns empty hashref' => sub {
    my $path = write_temp(<<'END');
port = 7443
cert = /etc/ctrl-exec-agent/agent.crt
key  = /etc/ctrl-exec-agent/agent.key
ca   = /etc/ctrl-exec-agent/ca.crt

[tags]
END
    my $c = eval { Exec::Agent::Config::load_config($path) };
    ok !$@, 'no error for empty tags section';
};

# --- script_dirs ---

subtest 'load_config: script_dirs parsed into arrayref' => sub {
    my $path = write_temp(<<'END');
port = 7443
cert = /etc/ctrl-exec-agent/agent.crt
key  = /etc/ctrl-exec-agent/agent.key
ca   = /etc/ctrl-exec-agent/ca.crt
script_dirs = /opt/scripts:/usr/local/lib/ctrl-exec-scripts
END
    my $c = Exec::Agent::Config::load_config($path);
    is ref($c->{script_dirs}), 'ARRAY', 'script_dirs is arrayref';
    is scalar @{ $c->{script_dirs} }, 2, 'two dirs parsed';
    is $c->{script_dirs}[0], '/opt/scripts', 'first dir';
    is $c->{script_dirs}[1], '/usr/local/lib/ctrl-exec-scripts', 'second dir';
};

subtest 'load_config: absent script_dirs leaves key undefined' => sub {
    my $path = write_temp(<<'END');
port = 7443
cert = /etc/ctrl-exec-agent/agent.crt
key  = /etc/ctrl-exec-agent/agent.key
ca   = /etc/ctrl-exec-agent/ca.crt
END
    my $c = Exec::Agent::Config::load_config($path);
    ok !exists $c->{script_dirs}, 'script_dirs absent when not configured';
};

subtest 'load_allowlist: rejects path outside script_dirs' => sub {
    my $path = write_temp(<<'END');
backup = /opt/scripts/backup.sh
bad    = /tmp/evil.sh
END
    my $warn = '';
    local $SIG{__WARN__} = sub { $warn .= $_[0] };
    my $al = Exec::Agent::Config::load_allowlist(
        $path, ['/opt/scripts']
    );
    ok  exists $al->{backup}, 'path in approved dir accepted';
    ok !exists $al->{bad},    'path outside approved dir rejected';
    like $warn, qr/not in approved script_dirs/, 'warning issued for rejected path';
};

subtest 'load_allowlist: accepts path in any approved dir' => sub {
    my $path = write_temp(<<'END');
script-a = /opt/scripts/a.sh
script-b = /usr/local/lib/ctrl-exec-scripts/b.sh
END
    my $al = Exec::Agent::Config::load_allowlist(
        $path, ['/opt/scripts', '/usr/local/lib/ctrl-exec-scripts']
    );
    ok exists $al->{'script-a'}, 'path in first approved dir accepted';
    ok exists $al->{'script-b'}, 'path in second approved dir accepted';
};

subtest 'load_allowlist: no script_dirs means no restriction' => sub {
    my $path = write_temp("anywhere = /anywhere/script.sh\n");
    my $al   = Exec::Agent::Config::load_allowlist($path, undef);
    ok exists $al->{anywhere}, 'path accepted when script_dirs not set';
};

subtest 'validate_script: rejects path outside script_dirs at execution time' => sub {
    my $al = { 'safe' => '/opt/scripts/safe.sh', 'unsafe' => '/tmp/evil.sh' };
    my $dirs = ['/opt/scripts'];

    my $warn = '';
    local $SIG{__WARN__} = sub { $warn .= $_[0] };

    my $good = Exec::Agent::Config::validate_script('safe',   $al, $dirs);
    my $bad  = Exec::Agent::Config::validate_script('unsafe', $al, $dirs);

    is   $good, '/opt/scripts/safe.sh', 'approved path returned';
    ok  !defined $bad,                  'unapproved path returns undef';
    like $warn, qr/not in script_dirs/, 'warning issued at execution time';
};

subtest '_path_in_dirs: resolves symlinks and .. for existing paths' => sub {
    my $base     = tempdir(CLEANUP => 1);
    my $approved = "$base/approved";
    my $outside  = "$base/outside";
    mkdir $approved or die $!;
    mkdir $outside  or die $!;

    open my $fh, '>', "$approved/ok.sh" or die $!;
    print $fh "#!/bin/sh\n"; close $fh;
    ok Exec::Agent::Config::_path_in_dirs("$approved/ok.sh", [$approved]),
        'real script under approved dir is accepted';

    open $fh, '>', "$outside/evil.sh" or die $!;
    print $fh "#!/bin/sh\n"; close $fh;

  SKIP: {
        symlink("$outside/evil.sh", "$approved/link.sh")
            or skip 'symlinks not supported here', 1;
        ok !Exec::Agent::Config::_path_in_dirs("$approved/link.sh", [$approved]),
            'symlink escaping the approved dir is rejected (resolved by abs_path)';
    }

    ok !Exec::Agent::Config::_path_in_dirs("$approved/../outside/evil.sh", [$approved]),
        '.. escaping the approved dir is rejected';
};

subtest 'validate_script: no script_dirs means no restriction at execution time' => sub {
    my $al = { 'any' => '/anywhere/script.sh' };
    my $r  = Exec::Agent::Config::validate_script('any', $al, undef);
    is $r, '/anywhere/script.sh', 'path returned when no script_dirs';
};

# --- auth_hook ---

subtest 'load_config: auth_hook accepted when executable' => sub {
    my ($fh, $hook_path) = tempfile(UNLINK => 1, SUFFIX => '.sh');
    print $fh "#!/bin/bash\nexit 0\n";
    close $fh;
    chmod 0755, $hook_path;

    my $path = write_temp(<<"END");
port = 7443
cert = /etc/ctrl-exec-agent/agent.crt
key  = /etc/ctrl-exec-agent/agent.key
ca   = /etc/ctrl-exec-agent/ca.crt
auth_hook = $hook_path
END
    my $c = eval { Exec::Agent::Config::load_config($path) };
    ok !$@,                              'no error for executable hook';
    is $c->{auth_hook}, $hook_path,      'auth_hook path stored';
};

subtest 'load_config: auth_hook absent leaves key undefined' => sub {
    my $path = write_temp(<<'END');
port = 7443
cert = /etc/ctrl-exec-agent/agent.crt
key  = /etc/ctrl-exec-agent/agent.key
ca   = /etc/ctrl-exec-agent/ca.crt
END
    my $c = Exec::Agent::Config::load_config($path);
    ok !exists $c->{auth_hook}, 'auth_hook absent when not configured';
};

subtest 'load_config: non-executable auth_hook dies' => sub {
    my ($fh, $hook_path) = tempfile(UNLINK => 1, SUFFIX => '.sh');
    print $fh "#!/bin/bash\nexit 0\n";
    close $fh;
    chmod 0644, $hook_path;   # not executable

    my $path = write_temp(<<"END");
port = 7443
cert = /etc/ctrl-exec-agent/agent.crt
key  = /etc/ctrl-exec-agent/agent.key
ca   = /etc/ctrl-exec-agent/ca.crt
auth_hook = $hook_path
END
    eval { Exec::Agent::Config::load_config($path) };
    like $@, qr/not executable/, 'dies for non-executable hook';
};

subtest 'load_config: missing auth_hook path dies' => sub {
    my $path = write_temp(<<'END');
port = 7443
cert = /etc/ctrl-exec-agent/agent.crt
key  = /etc/ctrl-exec-agent/agent.key
ca   = /etc/ctrl-exec-agent/ca.crt
auth_hook = /nonexistent/hook.sh
END
    eval { Exec::Agent::Config::load_config($path) };
    like $@, qr/not executable/, 'dies for missing hook file';
};

done_testing;
