#!/usr/bin/perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir tempfile);
use FindBin    qw($Bin);
use lib "$Bin/../lib";

use Exec::Agent::AgentPairing qw();

# Skip all if openssl not available
unless (system('openssl version >/dev/null 2>&1') == 0) {
    plan skip_all => 'openssl not available';
}

# --- generate_csr_only ---

subtest 'generate_csr_only: requires hostname' => sub {
    my $dir = tempdir(CLEANUP => 1);
    eval {
        Exec::Agent::AgentPairing::generate_csr_only(
            key_path => "$dir/agent.key",
        );
    };
    like $@, qr/hostname required/, 'dies without hostname';
};

subtest 'generate_csr_only: requires key_path' => sub {
    eval {
        Exec::Agent::AgentPairing::generate_csr_only(
            hostname => 'test-host',
        );
    };
    like $@, qr/key_path required/, 'dies without key_path';
};

subtest 'generate_csr_only: dies if key file missing' => sub {
    eval {
        Exec::Agent::AgentPairing::generate_csr_only(
            hostname => 'test-host',
            key_path => '/nonexistent/agent.key',
        );
    };
    like $@, qr/Key file not found/, 'dies with clear message for missing key';
};

subtest 'generate_csr_only: produces valid CSR from existing key' => sub {
    my $dir = tempdir(CLEANUP => 1);

    # Generate a key first
    system('openssl', 'genrsa', '-out', "$dir/agent.key", '2048') == 0
        or plan skip_all => 'openssl genrsa failed';

    my $result = eval {
        Exec::Agent::AgentPairing::generate_csr_only(
            hostname => 'renewal-test-host',
            key_path => "$dir/agent.key",
        );
    };
    ok !$@, "no error: $@";
    like $result->{csr_pem}, qr/-----BEGIN CERTIFICATE REQUEST-----/,
        'returns PEM CSR';
};

subtest 'generate_csr_only: CSR contains hostname as CN' => sub {
    my $dir = tempdir(CLEANUP => 1);

    system('openssl', 'genrsa', '-out', "$dir/agent.key", '2048') == 0
        or plan skip_all => 'openssl genrsa failed';

    my $result = Exec::Agent::AgentPairing::generate_csr_only(
        hostname => 'myhost.example.com',
        key_path => "$dir/agent.key",
    );

    my $text = `echo '$result->{csr_pem}' | openssl req -noout -subject 2>/dev/null`;
    like $text, qr/myhost\.example\.com/, 'hostname appears in CSR CN';
};

subtest 'generate_csr_only: does not create a new key file' => sub {
    my $dir = tempdir(CLEANUP => 1);

    system('openssl', 'genrsa', '-out', "$dir/agent.key", '2048') == 0
        or plan skip_all => 'openssl genrsa failed';

    my $key_mtime_before = (stat "$dir/agent.key")[9];

    Exec::Agent::AgentPairing::generate_csr_only(
        hostname => 'test-host',
        key_path => "$dir/agent.key",
    );

    my $key_mtime_after = (stat "$dir/agent.key")[9];
    is $key_mtime_after, $key_mtime_before, 'existing key file not modified';

    my @other = glob("$dir/*.key");
    is scalar(@other), 1, 'no additional key files created';
};

# --- _renewal_due (via Exec::Engine) ---
# Test through the public interface indirectly by checking the logic
# with known expiry strings.

subtest '_renewal_due: cert well within validity is not due' => sub {
    # Expiry 400 days from now, cert_days=365: half-life=182.5 days
    # remaining=400 days > 182.5 days -> not due
    require Exec::Engine;
    my $future = time() + (400 * 86400);
    my $expiry = _epoch_to_openssl($future);
    my $due = Exec::Engine::_renewal_due($expiry, 365);
    ok !$due, 'cert with 400 days remaining not due (cert_days=365)';
};

subtest '_renewal_due: cert past half-life is due' => sub {
    require Exec::Engine;
    # Expiry 100 days from now, cert_days=365: half-life=182.5 days
    # remaining=100 days < 182.5 days -> due
    my $future = time() + (100 * 86400);
    my $expiry = _epoch_to_openssl($future);
    my $due = Exec::Engine::_renewal_due($expiry, 365);
    ok $due, 'cert with 100 days remaining is due (cert_days=365)';
};

subtest '_renewal_due: expired cert is due' => sub {
    require Exec::Engine;
    my $past = time() - (10 * 86400);
    my $expiry = _epoch_to_openssl($past);
    my $due = Exec::Engine::_renewal_due($expiry, 365);
    ok $due, 'already-expired cert is due';
};

subtest '_renewal_due: unparseable expiry returns not due (safe default)' => sub {
    require Exec::Engine;
    my $due = Exec::Engine::_renewal_due('not a date', 365);
    ok !$due, 'unparseable expiry treated as not due';
};

subtest '_renewal_due: respects cert_days configuration' => sub {
    require Exec::Engine;
    # 200 days remaining
    # cert_days=365: half-life=182.5 days -> not due (200 > 182.5)
    # cert_days=730: half-life=365.0 days -> due     (200 < 365)
    my $future = time() + (200 * 86400);
    my $expiry = _epoch_to_openssl($future);
    ok !Exec::Engine::_renewal_due($expiry, 365), 'not due with cert_days=365';
    ok  Exec::Engine::_renewal_due($expiry, 730), 'due with cert_days=730';
};

# --- ping_all renew gating ---
# The de-rooted API server cannot sign (no CA key), so it pings with renew => 0.
# Stub the fan-out to yield one agent with a past-half-life cert, and _renew_one
# to record whether renewal was attempted.
subtest 'ping_all: renew => 0 skips renewal even for a due cert' => sub {
    require Exec::Engine;
    my $due = _epoch_to_openssl(time() + 100 * 86400);   # < half-life at cert_days=365
    no warnings 'redefine';
    local *Exec::Engine::_fan_out = sub {
        return [ { name => 'h1', target => 'h1:7443',
                   result => { status => 'ok', expiry => $due, staged => 0 } } ];
    };
    my $attempts = 0;
    local *Exec::Engine::_renew_one = sub { $attempts++; return { status => 'ok' } };

    $attempts = 0;
    Exec::Engine::ping_all(hosts => ['h1'], config => { cert_days => 365 }, renew => 1);
    ok $attempts, 'renew => 1 renews a due cert (CLI/maintenance path)';

    $attempts = 0;
    Exec::Engine::ping_all(hosts => ['h1'], config => { cert_days => 365 }, renew => 0);
    is $attempts, 0, 'renew => 0 does not renew, even when due (API path)';
};

# Format an epoch as an OpenSSL notAfter string: "Jun  7 16:28:00 2028 GMT"
sub _epoch_to_openssl {
    my ($epoch) = @_;
    my @t = gmtime($epoch);
    return sprintf '%s %2d %02d:%02d:%02d %04d GMT',
        (qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec))[$t[4]],
        $t[3], $t[2], $t[1], $t[0], $t[5] + 1900;
}

done_testing;
