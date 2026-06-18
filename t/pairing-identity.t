#!/usr/bin/perl
use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/../lib";

use Exec::Pairing qw();

# --- _reverse_lookup: graceful on bad/absent input (no DNS dependency) ---

is Exec::Pairing::_reverse_lookup(undef),       undef, 'reverse: undef IP -> undef';
is Exec::Pairing::_reverse_lookup(''),          undef, 'reverse: empty IP -> undef';
is Exec::Pairing::_reverse_lookup('unknown'),   undef, "reverse: 'unknown' -> undef";

# --- _identity_recommendation: keyed on the reverse-DNS signal ---

subtest 'confirmed reverse differs from reported name -> suggest rename' => sub {
    my $req = {
        hostname          => 'ai-dev',
        source_ip         => '10.0.0.6',
        reverse_dns       => 'ai-dev.home.example',
        reverse_confirmed => 1,
    };
    my $rec = Exec::Pairing::_identity_recommendation($req);
    like $rec, qr/forward-confirmed/,            'mentions forward-confirmed';
    like $rec, qr/edit-agent ai-dev --rename ai-dev\.home\.example/,
        'suggests rename to the resolvable FQDN';
    unlike $rec, qr/--lookup-by ip/, 'does not push IP when a name resolves';
};

subtest 'confirmed reverse equals reported name -> hostname is fine' => sub {
    my $req = {
        hostname          => 'web-01.lan.example',
        source_ip         => '10.0.0.7',
        reverse_dns       => 'web-01.lan.example',
        reverse_confirmed => 1,
    };
    my $rec = Exec::Pairing::_identity_recommendation($req);
    like $rec, qr/forward-confirmed/,        'notes confirmation';
    like $rec, qr/lookup_by=hostname/,       'says hostname resolution is fine';
    unlike $rec, qr/edit-agent/,             'no fix needed, no edit suggested';
};

subtest 'no confirmed reverse -> suggest lookup-by ip with source' => sub {
    my $req = {
        hostname          => 'ai-dev',
        source_ip         => '10.0.0.6',
        reverse_dns       => '',
        reverse_confirmed => 0,
    };
    my $rec = Exec::Pairing::_identity_recommendation($req);
    like $rec, qr/could not forward-confirm/i,                'explains the gap';
    like $rec, qr/edit-agent ai-dev --lookup-by ip --ip 10\.0\.0\.6/,
        'suggests dispatch by source IP';
};

subtest 'unconfirmed reverse is treated as no name' => sub {
    # A PTR that does not forward-confirm must not be recommended as a rename
    # target - it could be a host claiming a name it does not own.
    my $req = {
        hostname          => 'ai-dev',
        source_ip         => '10.0.0.6',
        reverse_dns       => 'evil.example',
        reverse_confirmed => 0,
    };
    my $rec = Exec::Pairing::_identity_recommendation($req);
    unlike $rec, qr/--rename/,        'unconfirmed PTR is never a rename target';
    like   $rec, qr/--lookup-by ip/,  'falls back to IP';
};

# --- _identity_lines: surfaces all signals ---

subtest 'identity lines show name, source IP, reverse DNS' => sub {
    my @lines = Exec::Pairing::_identity_lines({
        hostname          => 'ai-dev',
        ip                => '10.0.0.6',
        source_ip         => '10.0.0.6',
        reverse_dns       => 'ai-dev.home.example',
        reverse_confirmed => 1,
    });
    my $text = join "\n", @lines;
    like $text, qr/Reported name:\s+ai-dev/,                 'reported name';
    like $text, qr/Source IP:\s+10\.0\.0\.6/,                'source IP';
    like $text, qr/Reverse DNS:\s+ai-dev\.home\.example.*forward-confirmed/,
        'reverse DNS with confirmation';
};

subtest 'identity lines flag a reported IP that differs (NAT)' => sub {
    my @lines = Exec::Pairing::_identity_lines({
        hostname  => 'ai-dev',
        ip        => '192.168.1.5',   # agent self-reported (private)
        source_ip => '203.0.113.9',   # what the dispatcher saw (NAT gateway)
    });
    my $text = join "\n", @lines;
    like $text, qr/Reported IP:\s+192\.168\.1\.5.*NAT/, 'flags differing reported IP';
};

subtest 'identity lines note when no reverse DNS resolves' => sub {
    my @lines = Exec::Pairing::_identity_lines({
        hostname => 'ai-dev', ip => '10.0.0.6', source_ip => '10.0.0.6',
    });
    like join("\n", @lines), qr/Reverse DNS:\s+\(none/, 'notes absent reverse DNS';
};

done_testing;
