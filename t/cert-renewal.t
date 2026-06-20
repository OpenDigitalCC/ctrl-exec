#!/usr/bin/perl
# Agent-owned cert renewal: validate -> stage (unprivileged) -> promote (root, at
# start). Exercises the validation gate (CA-signed + key continuity), atomic
# staging in the agent's writable space, and promotion into the live cert path.
# All runs as the test user against temp files - no executor, no root needed,
# which is exactly the point of the chosen boundary.
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use FindBin    qw($Bin);
use lib "$Bin/../lib";

use Exec::CA                  qw();
use Exec::Agent::AgentPairing qw();

my $ossl = `command -v openssl 2>/dev/null`; chomp $ossl;
plan skip_all => 'openssl not available' unless $ossl && -x $ossl;

my $TMP = tempdir(CLEANUP => 1);
sub slurp { open my $fh, '<', $_[0] or die "open $_[0]: $!"; local $/; <$fh> }
sub spit  { open my $fh, '>', $_[0] or die "open $_[0]: $!"; print $fh $_[1]; close $fh }

# CA + the agent's identity. Live cert/key/ca in a "config dir"; staging in a
# separate "state dir".
my $CONF  = "$TMP/conf";  mkdir $CONF;
my $STATE = "$TMP/state"; mkdir $STATE;
Exec::CA::generate_ca(ca_dir => $CONF, days => 30, bits => 2048);

my $a = Exec::Agent::AgentPairing::generate_key_and_csr(hostname => 'agent-host', bits => 2048);
spit("$CONF/agent.key", $a->{key_pem});
spit("$CONF/agent.crt", Exec::CA::sign_csr(csr_pem => $a->{csr_pem}, ca_dir => $CONF, days => 30));

my %paths = (
    ca_path     => "$CONF/ca.crt",
    key_path    => "$CONF/agent.key",
    cert_path   => "$CONF/agent.crt",
    staged_path => "$STATE/agent.crt.staged",
);

# A legitimately renewed cert: same key, freshly signed by the same CA.
my $renew_csr = Exec::Agent::AgentPairing::generate_csr_only(
    hostname => 'agent-host', key_path => "$CONF/agent.key");
my $renewed = Exec::CA::sign_csr(csr_pem => $renew_csr->{csr_pem}, ca_dir => $CONF, days => 60);

subtest 'validate_cert: accepts a same-key cert from the same CA' => sub {
    my ($ok, $reason) = Exec::Agent::AgentPairing::validate_cert(
        cert_pem => $renewed, ca_path => $paths{ca_path}, key_path => $paths{key_path});
    ok $ok, 'valid renewed cert accepted' or diag($reason);
};

subtest 'validate_cert: rejects a different key' => sub {
    my $other = Exec::Agent::AgentPairing::generate_key_and_csr(hostname => 'agent-host', bits => 2048);
    my $wrong = Exec::CA::sign_csr(csr_pem => $other->{csr_pem}, ca_dir => $CONF, days => 30);
    my ($ok, $reason) = Exec::Agent::AgentPairing::validate_cert(
        cert_pem => $wrong, ca_path => $paths{ca_path}, key_path => $paths{key_path});
    ok !$ok, 'cert for a different key rejected';
    like $reason, qr/public key/, 'reason names the key mismatch';
};

subtest 'validate_cert: rejects a cert from a different CA' => sub {
    my $TMP2 = tempdir(CLEANUP => 1);
    Exec::CA::generate_ca(ca_dir => $TMP2, days => 30, bits => 2048);
    my $foreign = Exec::CA::sign_csr(csr_pem => $renew_csr->{csr_pem}, ca_dir => $TMP2, days => 30);
    my ($ok, $reason) = Exec::Agent::AgentPairing::validate_cert(
        cert_pem => $foreign, ca_path => $paths{ca_path}, key_path => $paths{key_path});
    ok !$ok, 'cert from a foreign CA rejected';
    like $reason, qr/verify|CA/i, 'reason names the CA failure';
};

subtest 'stage then promote: end-to-end adoption' => sub {
    my $orig = slurp($paths{cert_path});

    my $s = Exec::Agent::AgentPairing::stage_renewed_cert(cert_pem => $renewed, %paths);
    ok $s->{ok}, 'valid cert staged' or diag($s->{error});
    ok -f $paths{staged_path}, 'staged file written';
    is slurp($paths{cert_path}), $orig, 'live cert untouched by staging';

    my $p = Exec::Agent::AgentPairing::promote_staged_cert(%paths);
    ok $p->{ok} && $p->{promoted}, 'staged cert promoted';
    is slurp($paths{cert_path}), $renewed, 'live cert replaced with the renewed cert';
    ok !-f $paths{staged_path}, 'staged file consumed';
};

subtest 'promote is a no-op when nothing is staged' => sub {
    my $orig = slurp($paths{cert_path});
    my $p = Exec::Agent::AgentPairing::promote_staged_cert(%paths);
    ok $p->{ok} && !$p->{promoted}, 'nothing promoted';
    is slurp($paths{cert_path}), $orig, 'live cert unchanged';
};

subtest 'mode_promote_cert never dies, even when the install fails' => sub {
    # Load the agent as a modulino (its `main() unless caller` guard keeps the
    # server from starting) so mode_promote_cert can be driven directly. It runs
    # in ExecStartPre, where a die would block the agent from starting, so its
    # contract is "always return". Point the live cert at a missing directory so
    # promotion of a valid staged cert fails at the write.
    local $SIG{__WARN__} = sub {};
    my $loaded = do "$Bin/../bin/ctrl-exec-agent";
    ok($loaded, 'agent modulino loaded') or return;

    require Exec::Log;
    Exec::Log::init('cert-renewal-test');

    my $conf = "$TMP/promote-test.conf";
    spit($conf,
        "port = 7443\ncert = $TMP/nodir/agent.crt\nkey = $CONF/agent.key\n"
      . "ca = $CONF/ca.crt\ncert_staging_path = $TMP/promote-fail.staged\n");
    spit("$TMP/promote-fail.staged", $renewed);   # a valid staged cert

    no warnings 'once';
    local $main::CONFIG_PATH = $conf;
    my $ok = eval { main::mode_promote_cert({}); 1 };
    ok($ok, 'mode_promote_cert returned without dying on an install failure')
        or diag($@);
    ok(! -e "$TMP/nodir/agent.crt", 'live cert not created in a missing dir');
    # The staged cert validated but failed to install: it must be kept (not
    # dropped) so the next start retries - proving the promote actually ran.
    ok(-f "$TMP/promote-fail.staged", 'valid-but-uninstallable staged cert kept for retry');
};

subtest 'a bad staged cert is dropped and never promoted' => sub {
    my $orig = slurp($paths{cert_path});
    # Stage a foreign-CA cert by writing it directly (bypassing the stage gate),
    # to prove promote re-validates and refuses it.
    my $TMP2 = tempdir(CLEANUP => 1);
    Exec::CA::generate_ca(ca_dir => $TMP2, days => 30, bits => 2048);
    spit($paths{staged_path},
        Exec::CA::sign_csr(csr_pem => $renew_csr->{csr_pem}, ca_dir => $TMP2, days => 30));

    my $p = Exec::Agent::AgentPairing::promote_staged_cert(%paths);
    ok !$p->{ok}, 'invalid staged cert refused at promote';
    is slurp($paths{cert_path}), $orig, 'live cert left intact';
    ok !-f $paths{staged_path}, 'bad staged cert dropped so it cannot wedge startup';
};

done_testing;
