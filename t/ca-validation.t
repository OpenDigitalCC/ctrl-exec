#!/usr/bin/perl
# t/ca-validation.t
#
# Unit tests for the CA.pm hardening changes:
#
#   Finding 1 - CN injection guard in generate_ca
#   Finding 2 - CSR size and format guards in sign_csr
#   Finding 4 - stderr captured in _run_or_die croak message
#   Finding 5 - temp files written to ca_dir, not /tmp
#   Finding 6 - days validated as positive integer in all three public functions
#
# Tests for findings 1, 2, and 6 (rejection cases) croak before any
# file I/O and require no real CA on disk.
#
# Tests for findings 4 and 5, and the days=1 acceptance cases for
# generate_ca and generate_dispatcher_cert, require openssl to be
# available and generate real keys. These are grouped under a SKIP block
# that checks for openssl first.

use strict;
use warnings;
use Test::More;
use File::Temp  qw(tempdir tempfile);
use File::Copy  qw();
use File::Glob  qw(bsd_glob);
use FindBin     qw($Bin);
use lib "$Bin/../lib";

use Exec::CA  qw();
use Exec::Log qw();

Exec::Log::init('test');

# Scratch dir used by tests that need a directory path but no real CA
my $scratch = tempdir(CLEANUP => 1);

# Plant placeholder CA files so sign_csr's CA existence checks pass,
# allowing the size/format guards beyond them to be reached.
{ open my $fh, '>', "$scratch/ca.key" or die "cannot write ca.key: $!"; print $fh "placeholder\n" }
{ open my $fh, '>', "$scratch/ca.crt" or die "cannot write ca.crt: $!"; print $fh "placeholder\n" }

# ---------------------------------------------------------------------------
# Finding 6 – days validation (croaks before any file I/O)
# All three functions, all invalid values
# ---------------------------------------------------------------------------

for my $fn (qw(generate_ca generate_dispatcher_cert sign_csr)) {
    for my $bad (0, -1, 'abc', '') {
        my $label = defined $bad && length $bad ? $bad : '(empty)';
        subtest "days validation: $fn rejects days => $label" => sub {
            my %base = (ca_dir => $scratch, days => $bad);
            $base{cn}      = 'Test CA'   if $fn eq 'generate_ca';
            $base{csr_pem} = "-----BEGIN CERTIFICATE REQUEST-----\nYQ==\n-----END CERTIFICATE REQUEST-----\n"
                             if $fn eq 'sign_csr';
            eval { Exec::CA->can($fn)->(%base) };
            like $@, qr/days must be a positive integer/,
                "$fn: days=$label croaks with correct message";
        };
    }
}

subtest 'days validation: sign_csr accepts days => 1 (fires before openssl with bad CA)' => sub {
    # days=1 passes the guard; croak comes from missing CA key, not days check.
    # Use a fresh empty dir so the CA existence check fires as intended.
    my $empty = tempdir(CLEANUP => 1);
    eval {
        Exec::CA::sign_csr(
            csr_pem => "-----BEGIN CERTIFICATE REQUEST-----\nYQ==\n-----END CERTIFICATE REQUEST-----\n",
            ca_dir  => $empty,
            days    => 1,
        );
    };
    unlike $@, qr/days must be a positive integer/,
        'days=1 passes the days guard in sign_csr';
    like $@, qr/CA key not found/,
        'croak comes from missing CA, not days validation';
};

# ---------------------------------------------------------------------------
# Finding 1 – CN injection guard in generate_ca
# ---------------------------------------------------------------------------

subtest 'CN validation: slash rejected' => sub {
    eval { Exec::CA::generate_ca(cn => 'ctrl-exec CA/O=Evil', ca_dir => $scratch) };
    like $@, qr/Invalid CN/, 'slash in CN croaks';
};

subtest 'CN validation: null byte rejected' => sub {
    eval { Exec::CA::generate_ca(cn => "ctrl-exec\0CA", ca_dir => $scratch) };
    like $@, qr/Invalid CN/, 'null byte in CN croaks';
};

subtest 'CN validation: equals sign rejected' => sub {
    eval { Exec::CA::generate_ca(cn => 'CN=Bad', ca_dir => $scratch) };
    like $@, qr/Invalid CN/, 'equals sign in CN croaks';
};

subtest 'CN validation: valid characters accepted (word, space, hyphen, dot)' => sub {
    # Verify the guard passes - croak should come from existing CA or openssl,
    # not from the CN check.
    my $d = tempdir(CLEANUP => 1);
    eval { Exec::CA::generate_ca(cn => 'My CA-01.example', ca_dir => $d, days => 1) };
    unlike $@, qr/Invalid CN/, 'valid CN does not trigger CN guard';
};

# ---------------------------------------------------------------------------
# Finding 2 – CSR size and format guards in sign_csr
# These fire before CA key check, so no real CA needed.
# ---------------------------------------------------------------------------

subtest 'CSR format: oversized CSR rejected' => sub {
    eval {
        Exec::CA::sign_csr(
            csr_pem => 'A' x 10_241,
            ca_dir  => $scratch,
            days    => 1,
        );
    };
    like $@, qr/CSR exceeds maximum size/, 'oversized CSR croaks';
};

subtest 'CSR format: oversized CSR - no temp file written' => sub {
    my $d = tempdir(CLEANUP => 1);
    eval {
        Exec::CA::sign_csr(
            csr_pem => 'A' x 10_241,
            ca_dir  => $d,
            days    => 1,
        );
    };
    my @files = bsd_glob("$d/*");
    is scalar @files, 0, 'no temp file written to ca_dir before format check';
};

subtest 'CSR format: non-PEM content rejected' => sub {
    for my $bad ('{}', '<xml/>', 'not a csr', '') {
        eval {
            Exec::CA::sign_csr(
                csr_pem => $bad,
                ca_dir  => $scratch,
                days    => 1,
            );
        };
        # Empty string hits the 'csr_pem required' croak, not the format guard.
        # Others hit the format guard.
        like $@, qr/Invalid CSR format|csr_pem required/,
            "non-PEM input '$bad' rejected before reaching openssl";
    }
};

subtest 'CSR format: valid PEM header passes guard' => sub {
    # Passes the format guard; croak comes from missing CA key, not format check.
    # Use a fresh empty dir so the CA existence check fires as intended.
    my $empty = tempdir(CLEANUP => 1);
    eval {
        Exec::CA::sign_csr(
            csr_pem => "-----BEGIN CERTIFICATE REQUEST-----\nYQ==\n-----END CERTIFICATE REQUEST-----\n",
            ca_dir  => $empty,
            days    => 1,
        );
    };
    unlike $@, qr/Invalid CSR format/, 'valid PEM header passes the format guard';
    like   $@, qr/CA key not found/,   'croak is from missing CA, not format check';
};

subtest 'CSR format: exactly 10240 bytes accepted by size guard' => sub {
    # 10240 bytes of PEM-looking content passes the size guard
    my $pem = "-----BEGIN CERTIFICATE REQUEST-----\n" . ('A' x (10_240 - 37 - 34)) . "\n-----END CERTIFICATE REQUEST-----\n";
    $pem = substr($pem, 0, 10_240);
    # Inject the PEM header so the format guard passes
    substr($pem, 0, 36) = "-----BEGIN CERTIFICATE REQUEST-----\n";
    eval {
        Exec::CA::sign_csr(csr_pem => $pem, ca_dir => $scratch, days => 1);
    };
    unlike $@, qr/CSR exceeds maximum size/, '10240-byte CSR passes size guard';
};

# ---------------------------------------------------------------------------
# Tests requiring openssl - skipped if not available
# ---------------------------------------------------------------------------

my $has_openssl = (system('openssl version >/dev/null 2>&1') == 0);

SKIP: {
    skip 'openssl not available', 15 unless $has_openssl;

    # Generate a real test CA once for all openssl-dependent tests
    my $ca_dir = tempdir(CLEANUP => 1);
    my $ca_ok = eval {
        Exec::CA::generate_ca(
            cn     => 'Test CA',
            ca_dir => $ca_dir,
            days   => 1,
            bits   => 2048,   # 2048 for test speed; 4096 in production
        );
        1;
    };

    skip "Test CA generation failed: $@", 15 unless $ca_ok;

    # --- Finding 6: generate_ca days=1 accepted ---

    subtest 'days validation: generate_ca accepts days => 1' => sub {
        my $d = tempdir(CLEANUP => 1);
        eval { Exec::CA::generate_ca(cn => 'Test CA', ca_dir => $d, days => 1, bits => 2048) };
        is $@, '', 'generate_ca: days=1 does not croak';
        ok -f "$d/ca.crt", 'generate_ca: ca.crt created with days=1';
    };

    # --- Finding 6: generate_dispatcher_cert days validation ---

    subtest 'days validation: generate_dispatcher_cert rejects days => 0' => sub {
        eval {
            Exec::CA::generate_dispatcher_cert(ca_dir => $ca_dir, days => 0);
        };
        like $@, qr/days must be a positive integer/,
            'generate_dispatcher_cert: days=0 croaks';
    };

    subtest 'days validation: generate_dispatcher_cert accepts days => 1' => sub {
        my $d = tempdir(CLEANUP => 1);
        # Copy CA files to fresh dir so we get a clean ctrl-exec cert
        for my $f (qw(ca.key ca.crt ca.serial)) {
            File::Copy::copy("$ca_dir/$f", "$d/$f")
                if -f "$ca_dir/$f";
        }
        eval {
            Exec::CA::generate_dispatcher_cert(
                ca_dir => $d, days => 1, bits => 2048
            );
        };
        is $@, '', 'generate_dispatcher_cert: days=1 does not croak';
        ok -f "$d/dispatcher.crt", 'generate_dispatcher_cert: dispatcher.crt created';
    };

    # --- Finding 4: stderr captured in croak message ---

    subtest '_run_or_die: croak message includes openssl stderr output' => sub {
        # A structurally valid PEM header but with garbage base64 content.
        # Passes the format guard, reaches openssl, openssl writes to stderr.
        # _run_or_die captures fd 2 via POSIX::dup2 so the child process
        # stderr is redirected into the temp file and included in the croak.
        my $bad_csr = "-----BEGIN CERTIFICATE REQUEST-----\nYQ==\n-----END CERTIFICATE REQUEST-----\n";
        eval {
            Exec::CA::sign_csr(
                csr_pem => $bad_csr,
                ca_dir  => $ca_dir,
                days    => 1,
            );
        };
        my $err = $@;
        isnt $err, '', 'sign_csr with bad CSR content croaks';
        # The croak message should contain more than just the bare exit code line
        unlike $err, qr/\ACommand failed.*exit \d+\s*\z/s,
            'croak message is not a bare exit-code-only string';
        # Should contain something from openssl stderr
        like $err, qr/(?:unable|error|invalid|bad|problem|ASN|DER)/i,
            'croak message contains openssl diagnostic output';
    };

    # --- Finding 5: temp files in ca_dir, not /tmp ---

    subtest 'sign_csr: no .csr or .crt temp files appear in /tmp' => sub {
        my @before = (bsd_glob('/tmp/*.csr'), bsd_glob('/tmp/*.crt'));

        my $bad_csr = "-----BEGIN CERTIFICATE REQUEST-----\nYQ==\n-----END CERTIFICATE REQUEST-----\n";
        eval { Exec::CA::sign_csr(csr_pem => $bad_csr, ca_dir => $ca_dir, days => 1) };

        my @after = (bsd_glob('/tmp/*.csr'), bsd_glob('/tmp/*.crt'));
        is scalar @after, scalar @before,
            'no .csr or .crt temp files appeared in /tmp';
    };

    subtest 'sign_csr: temp files cleaned up from ca_dir after call' => sub {
        my @before = (bsd_glob("$ca_dir/*.csr"), bsd_glob("$ca_dir/*.crt"));

        my $bad_csr = "-----BEGIN CERTIFICATE REQUEST-----\nYQ==\n-----END CERTIFICATE REQUEST-----\n";
        eval { Exec::CA::sign_csr(csr_pem => $bad_csr, ca_dir => $ca_dir, days => 1) };

        my @after = (bsd_glob("$ca_dir/*.csr"), bsd_glob("$ca_dir/*.crt"));
        is scalar @after, scalar @before,
            'File::Temp object destructor cleaned up temp files from ca_dir after failed call';
    };

    # --- Finding 2: oversized CSR does not create temp file ---
    # (Confirmed with real CA dir present)

    subtest 'CSR format: oversized CSR - no temp file in ca_dir' => sub {
        my @before = bsd_glob("$ca_dir/*");
        eval {
            Exec::CA::sign_csr(
                csr_pem => 'A' x 10_241,
                ca_dir  => $ca_dir,
                days    => 1,
            );
        };
        my @after = bsd_glob("$ca_dir/*");
        is scalar @after, scalar @before,
            'oversized CSR: file count in ca_dir unchanged (no temp file written)';
    };

    # --- Finding 1: valid CN generates real CA ---

    subtest 'CN validation: generate_ca with valid CN produces ca.crt' => sub {
        my $d = tempdir(CLEANUP => 1);
        eval {
            Exec::CA::generate_ca(
                cn     => 'ctrl-exec CA-01',
                ca_dir => $d,
                days   => 1,
                bits   => 2048,
            );
        };
        is $@, '',      'no croak for valid CN';
        ok -f "$d/ca.crt", 'ca.crt created for valid CN';
    };
}

done_testing;
