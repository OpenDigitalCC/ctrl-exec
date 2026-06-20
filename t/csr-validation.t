use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use FindBin qw($Bin);
use lib "$Bin/../lib";

use Exec::CA;

# sign_csr must validate the CSR before signing - it is otherwise a signing
# oracle that would mint a cert for any subject with any key/algorithm (S2).
# This exercises the key-size floor, weak-signature rejection, and the optional
# expected_cn identity binding.

my $dir = tempdir(CLEANUP => 1);
Exec::CA::generate_ca(ca_dir => $dir, days => 30, bits => 2048);

# Build a CSR with a given key size, digest and CN. Returns the PEM, or undef
# if openssl could not produce it (e.g. a build that refuses 1024-bit keys).
sub make_csr {
    my (%o) = @_;
    my $bits = $o{bits} // 2048;
    my $md   = $o{md}   // 'sha256';
    my $cn   = $o{cn}   // 'agent-test';
    my $key  = "$dir/k.$bits.$md.$cn.key";
    my $csr  = "$dir/k.$bits.$md.$cn.csr";

    return undef if system('openssl', 'genrsa', '-out', $key, $bits) != 0;
    return undef if system('openssl', 'req', '-new', '-key', $key,
                           '-out', $csr, "-$md", '-subj', "/CN=$cn") != 0;

    open my $fh, '<', $csr or return undef;
    local $/;
    return scalar <$fh>;
}

# Good CSR: 2048-bit, sha256 - signs cleanly.
{
    my $csr = make_csr(bits => 2048, md => 'sha256', cn => 'agent-good');
    ok($csr, 'generated a good 2048-bit sha256 CSR') or BAIL_OUT('openssl unusable');
    my $cert = eval { Exec::CA::sign_csr(csr_pem => $csr, ca_dir => $dir, days => 30) };
    is($@, '', 'sign_csr accepts a 2048-bit sha256 CSR');
    like($cert // '', qr/BEGIN CERTIFICATE/, 'returns a signed certificate');
}

# Weak key: 1024-bit - rejected.
SKIP: {
    my $csr = make_csr(bits => 1024, md => 'sha256', cn => 'agent-weakkey');
    skip 'openssl would not produce a 1024-bit key', 1 unless $csr;
    my $cert = eval { Exec::CA::sign_csr(csr_pem => $csr, ca_dir => $dir, days => 30) };
    ok($@, 'sign_csr rejects a 1024-bit key');
}

# Weak signature: sha1 - rejected.
SKIP: {
    my $csr = make_csr(bits => 2048, md => 'sha1', cn => 'agent-sha1');
    skip 'openssl would not produce a sha1 CSR', 1 unless $csr;
    my $cert = eval { Exec::CA::sign_csr(csr_pem => $csr, ca_dir => $dir, days => 30) };
    ok($@, 'sign_csr rejects a sha1 self-signature');
}

# expected_cn binding: a matching CN signs, a mismatched CN is refused.
{
    my $csr = make_csr(bits => 2048, md => 'sha256', cn => 'agent-bound');
    ok($csr, 'generated a CSR for the CN-binding case');

    my $ok = eval {
        Exec::CA::sign_csr(csr_pem => $csr, ca_dir => $dir, days => 30,
                           expected_cn => 'agent-bound');
    };
    is($@, '', 'sign_csr accepts when expected_cn matches the subject');
    like($ok // '', qr/BEGIN CERTIFICATE/, 'matching expected_cn yields a cert');

    eval {
        Exec::CA::sign_csr(csr_pem => $csr, ca_dir => $dir, days => 30,
                           expected_cn => 'some-other-agent');
    };
    like($@, qr/does not match/, 'sign_csr refuses a CN that is not the expected identity');
}

done_testing;
