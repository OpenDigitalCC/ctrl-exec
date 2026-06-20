#!/usr/bin/perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempfile);
use FindBin    qw($Bin);
use lib "$Bin/../lib";

use Exec::Agent::Config qw();

# Suppress syslog during tests - Log falls back to stderr; redirect to silence
open my $saved_stderr, '>&', \*STDERR;
open STDERR, '>', '/dev/null';

# Helper: write a minimal valid agent.conf with optional extra keys appended
sub write_conf {
    my ($extra) = @_;
    my ($fh, $path) = tempfile(UNLINK => 1, SUFFIX => '.conf');
    print $fh "port = 7443\n";
    print $fh "cert = /etc/ctrl-exec-agent/agent.crt\n";
    print $fh "key  = /etc/ctrl-exec-agent/agent.key\n";
    print $fh "ca   = /etc/ctrl-exec-agent/ca.crt\n";
    print $fh $extra if defined $extra;
    close $fh;
    return $path;
}

# ---------------------------------------------------------------------------
# load_config: allowed_ips parsing
# ---------------------------------------------------------------------------

subtest 'load_config: allowed_ips parsed as arrayref' => sub {
    my $path = write_conf("allowed_ips = 192.168.1.10\n");
    my $c = Exec::Agent::Config::load_config($path);
    is ref($c->{allowed_ips}), 'ARRAY', 'allowed_ips is arrayref';
    is scalar @{ $c->{allowed_ips} }, 1, 'one entry';
    is $c->{allowed_ips}[0], '192.168.1.10', 'entry value correct';
};

subtest 'load_config: multiple allowed_ips entries parsed' => sub {
    my $path = write_conf("allowed_ips = 192.168.1.10, 10.0.0.0/8\n");
    my $c = Exec::Agent::Config::load_config($path);
    is scalar @{ $c->{allowed_ips} }, 2, 'two entries parsed';
    is $c->{allowed_ips}[0], '192.168.1.10', 'first entry';
    is $c->{allowed_ips}[1], '10.0.0.0/8',   'second entry';
};

subtest 'load_config: whitespace trimmed from each entry' => sub {
    my $path = write_conf("allowed_ips =  192.168.1.10 ,  10.0.0.0/8 \n");
    my $c = Exec::Agent::Config::load_config($path);
    is $c->{allowed_ips}[0], '192.168.1.10', 'leading/trailing space stripped from first';
    is $c->{allowed_ips}[1], '10.0.0.0/8',   'leading/trailing space stripped from second';
};

subtest 'load_config: allowed_ips absent leaves key undefined' => sub {
    my $path = write_conf();
    my $c = Exec::Agent::Config::load_config($path);
    ok !exists $c->{allowed_ips}, 'allowed_ips key absent when not configured';
};

subtest 'load_config: empty allowed_ips leaves key undefined' => sub {
    my $path = write_conf("allowed_ips = \n");
    my $c = Exec::Agent::Config::load_config($path);
    ok !exists $c->{allowed_ips}, 'allowed_ips key absent for empty value';
};

subtest 'load_config: whitespace-only allowed_ips leaves key undefined' => sub {
    my $path = write_conf("allowed_ips =    ,   ,  \n");
    my $c = Exec::Agent::Config::load_config($path);
    ok !exists $c->{allowed_ips}, 'allowed_ips key absent when all entries are blank';
};

subtest 'load_config: unsupported prefix length filtered and logs config-warn' => sub {
    my @warned;
    {
        no warnings 'redefine';
        local *Exec::Log::log_action = sub {
            my ($level, $fields) = @_;
            push @warned, $fields if ($fields->{ACTION} // '') eq 'config-warn';
        };
        my $path = write_conf("allowed_ips = 10.0.0.0/7, 192.168.1.10\n");
        my $c = Exec::Agent::Config::load_config($path);
        is scalar @{ $c->{allowed_ips} }, 1, 'invalid entry filtered out';
        is $c->{allowed_ips}[0], '192.168.1.10', 'valid entry retained';
    }
    is scalar @warned, 1, 'config-warn logged once for bad entry';
    is $warned[0]{ENTRY}, '10.0.0.0/7', 'ENTRY field identifies bad entry';
    like $warned[0]{MSG}, qr/unsupported prefix length/i, 'MSG describes problem';
};

subtest 'load_config: all entries invalid deletes allowed_ips key' => sub {
    {
        no warnings 'redefine';
        local *Exec::Log::log_action = sub {};
        my $path = write_conf("allowed_ips = 10.0.0.0/7, 10.0.0.0/32\n");
        my $c = Exec::Agent::Config::load_config($path);
        ok !exists $c->{allowed_ips}, 'allowed_ips absent when all entries invalid';
    }
};

subtest 'load_config: valid prefix lengths /8 /16 /24 all accepted' => sub {
    my $path = write_conf("allowed_ips = 10.0.0.0/8, 192.168.1.0/16, 172.16.0.0/24\n");
    my $c = Exec::Agent::Config::load_config($path);
    is scalar @{ $c->{allowed_ips} }, 3, 'all three CIDR entries accepted';
};

# ---------------------------------------------------------------------------
# ip_allowed: exact IP matching
# ---------------------------------------------------------------------------

subtest 'ip_allowed: exact IP match returns 1' => sub {
    is Exec::Agent::Config::ip_allowed('192.168.1.10', ['192.168.1.10']),
       1, 'exact match returns 1';
};

subtest 'ip_allowed: exact IP non-match returns 0' => sub {
    is Exec::Agent::Config::ip_allowed('192.168.1.11', ['192.168.1.10']),
       0, 'non-matching exact IP returns 0';
};

subtest 'ip_allowed: empty list returns 0' => sub {
    is Exec::Agent::Config::ip_allowed('192.168.1.10', []),
       0, 'empty allowed list returns 0';
};

subtest 'ip_allowed: multiple entries - first matches' => sub {
    is Exec::Agent::Config::ip_allowed(
        '10.0.0.1', ['10.0.0.1', '192.168.1.10']),
       1, 'returns 1 when first of multiple entries matches';
};

subtest 'ip_allowed: multiple entries - last matches' => sub {
    is Exec::Agent::Config::ip_allowed(
        '192.168.1.10', ['10.0.0.1', '192.168.1.10']),
       1, 'returns 1 when last of multiple entries matches';
};

subtest 'ip_allowed: multiple entries - none match' => sub {
    is Exec::Agent::Config::ip_allowed(
        '1.2.3.4', ['10.0.0.1', '192.168.1.10']),
       0, 'returns 0 when no entry matches';
};

# ---------------------------------------------------------------------------
# ip_allowed: CIDR /8
# ---------------------------------------------------------------------------

subtest 'ip_allowed: /8 - IP within prefix returns 1' => sub {
    is Exec::Agent::Config::ip_allowed('10.99.1.1', ['10.0.0.0/8']),
       1, '/8 match on first octet returns 1';
};

subtest 'ip_allowed: /8 - IP outside prefix returns 0' => sub {
    is Exec::Agent::Config::ip_allowed('11.0.0.1', ['10.0.0.0/8']),
       0, '/8 non-match on first octet returns 0';
};

subtest 'ip_allowed: /8 - boundary: last address in range matches' => sub {
    is Exec::Agent::Config::ip_allowed('10.255.255.255', ['10.0.0.0/8']),
       1, '/8 last address in range matches';
};

# ---------------------------------------------------------------------------
# ip_allowed: CIDR /16
# ---------------------------------------------------------------------------

subtest 'ip_allowed: /16 - IP within prefix returns 1' => sub {
    is Exec::Agent::Config::ip_allowed('192.168.5.1', ['192.168.0.0/16']),
       1, '/16 match on first two octets returns 1';
};

subtest 'ip_allowed: /16 - IP outside prefix returns 0' => sub {
    is Exec::Agent::Config::ip_allowed('192.169.0.1', ['192.168.0.0/16']),
       0, '/16 non-match on second octet returns 0';
};

subtest 'ip_allowed: /16 - different first octet returns 0' => sub {
    is Exec::Agent::Config::ip_allowed('193.168.0.1', ['192.168.0.0/16']),
       0, '/16 non-match on first octet returns 0';
};

# ---------------------------------------------------------------------------
# ip_allowed: CIDR /24
# ---------------------------------------------------------------------------

subtest 'ip_allowed: /24 - IP within prefix returns 1' => sub {
    is Exec::Agent::Config::ip_allowed('172.16.0.50', ['172.16.0.0/24']),
       1, '/24 match on first three octets returns 1';
};

subtest 'ip_allowed: /24 - IP outside prefix returns 0' => sub {
    is Exec::Agent::Config::ip_allowed('172.16.1.1', ['172.16.0.0/24']),
       0, '/24 non-match on third octet returns 0';
};

subtest 'ip_allowed: /24 - boundary: .255 in range matches' => sub {
    is Exec::Agent::Config::ip_allowed('172.16.0.255', ['172.16.0.0/24']),
       1, '/24 last host address matches';
};

# ---------------------------------------------------------------------------
# ip_allowed: IPv6 and edge cases
# ---------------------------------------------------------------------------

subtest 'ip_allowed: IPv6 address returns 0 without warning' => sub {
    my $warned = 0;
    {
        no warnings 'redefine';
        local *Exec::Log::log_action = sub { $warned++ };
        my $r = Exec::Agent::Config::ip_allowed(
            '2001:db8::1', ['192.168.1.10', '10.0.0.0/8']);
        is $r, 0, 'IPv6 address returns 0';
    }
    is $warned, 0, 'no log_action call for IPv6';
};

subtest 'ip_allowed: unknown peer returns 0' => sub {
    is Exec::Agent::Config::ip_allowed('unknown', ['192.168.1.10']),
       0, "'unknown' peer does not match any entry";
};

# ---------------------------------------------------------------------------
# Octet validation + canonicalisation at load (CG-004): a zero-padded or
# malformed dotted-quad must not silently fail open by never matching.
# ---------------------------------------------------------------------------

subtest 'load_config: zero-padded octets are canonicalised, so they match' => sub {
    my $path = write_conf("allowed_ips = 10.00.0.0/16\n");
    my $c = Exec::Agent::Config::load_config($path);
    is $c->{allowed_ips}[0], '10.0.0.0/16',
        'leading zeros stripped to canonical form';
    is Exec::Agent::Config::ip_allowed('10.0.5.5', $c->{allowed_ips}), 1,
        'canonicalised entry matches a real peer (was a silent no-match)';
};

subtest 'load_config: zero-padded exact IP canonicalised and matches' => sub {
    my $path = write_conf("allowed_ips = 192.168.001.010\n");
    my $c = Exec::Agent::Config::load_config($path);
    is $c->{allowed_ips}[0], '192.168.1.10', 'exact IP canonicalised';
    is Exec::Agent::Config::ip_allowed('192.168.1.10', $c->{allowed_ips}), 1,
        'canonical entry matches the canonical peer';
};

subtest 'load_config: malformed octets are warned-and-dropped' => sub {
    # 999 is out of range; "10.0/16" has too few octets; "a.b.c.d" non-numeric.
    my $path = write_conf("allowed_ips = 999.1.1.1, 10.0/16, a.b.c.d, 192.168.1.10\n");
    my $c = Exec::Agent::Config::load_config($path);
    is_deeply $c->{allowed_ips}, ['192.168.1.10'],
        'only the one well-formed entry survives; malformed ones dropped';
};

subtest 'load_config: all-malformed allowed_ips leaves the key undefined' => sub {
    my $path = write_conf("allowed_ips = 999.999.999.999, nonsense\n");
    my $c = Exec::Agent::Config::load_config($path);
    ok !exists $c->{allowed_ips},
        'no surviving entries -> key removed (fail closed, not open)';
};

# Restore stderr
open STDERR, '>&', $saved_stderr;

done_testing;
