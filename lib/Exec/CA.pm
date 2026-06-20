package Exec::CA;

use strict;
use warnings;
use File::Temp  qw(tempfile tempdir);
use File::Path  qw(make_path);
use Carp        qw(croak);


my $CA_DIR   = '/etc/ctrl-exec';
my $CA_KEY   = "$CA_DIR/ca.key";
my $CA_CERT  = "$CA_DIR/ca.crt";
my $SERIAL   = "$CA_DIR/ca.serial";

# One-time CA setup - generates ca.key and ca.crt
# Dies if CA already exists unless force => 1
sub generate_ca {
    my (%opts) = @_;
    my $days  = $opts{days}  // 3650;
    my $bits  = $opts{bits}  // 4096;
    my $cn    = $opts{cn}    // 'ctrl-exec CA';
    my $force = $opts{force} // 0;
    my $ca_dir = $opts{ca_dir} // $CA_DIR;

    croak "days must be a positive integer"
        unless defined $days && $days =~ /^\d+$/ && $days > 0;

    croak "Invalid CN: must contain only word characters, spaces, hyphens, and dots"
        unless $cn =~ /^[\w\s\-\.]+$/;

    my $ca_key  = "$ca_dir/ca.key";
    my $ca_cert = "$ca_dir/ca.crt";

    if (-f $ca_key && !$force) {
        croak "CA already exists at '$ca_key'. Use force => 1 to overwrite.";
    }

    make_path($ca_dir) unless -d $ca_dir;

    _genrsa($ca_key, $bits);

    _run_or_die(
        'openssl', 'req', '-new', '-x509',
        '-key',     $ca_key,
        '-out',     $ca_cert,
        '-days',    $days,
        '-subj',    "/CN=$cn",
    );

    _write_serial("$ca_dir/ca.serial", '01');

    return { ca_key => $ca_key, ca_cert => $ca_cert };
}

# Generate the ctrl-exec's own key and cert, signed by the CA.
# Safe to call after setup-ca. Dies if dispatcher cert already exists
# unless force => 1.
sub generate_dispatcher_cert {
    my (%opts) = @_;
    my $days   = $opts{days}   // 825;
    my $bits   = $opts{bits}   // 4096;
    my $ca_dir = $opts{ca_dir} // $CA_DIR;
    my $force  = $opts{force}  // 0;

    croak "days must be a positive integer"
        unless defined $days && $days =~ /^\d+$/ && $days > 0;

    # The dispatcher cert/key paths are the caller's to specify - they are the
    # single source of truth (ctrl-exec.conf 'cert'/'key'), the same files the
    # dispatcher serves with and that approve/rotate read the serial from. There
    # is deliberately no default name here: a hardcoded 'dispatcher.crt' is what
    # let setup/rotate target a different file than the one served, producing a
    # permanent "serial mismatch".
    my $disp_crt = $opts{cert} or croak "cert path required";
    my $disp_key = $opts{key}  or croak "key path required";

    my $ca_key   = "$ca_dir/ca.key";
    my $ca_cert  = "$ca_dir/ca.crt";
    my $serial   = "$ca_dir/ca.serial";

    croak "CA key not found at '$ca_key' - run setup-ca first" unless -f $ca_key;

    if (-f $disp_crt && !$force) {
        croak "dispatcher cert already exists at '$disp_crt'. Use force => 1 to overwrite.";
    }

    # The CSR is a throwaway intermediate; a temp file leaves nothing behind.
    my (undef, $disp_csr) = tempfile('disp-XXXXXX', SUFFIX => '.csr', TMPDIR => 1, UNLINK => 1);

    _genrsa($disp_key, $bits);

    _run_or_die(
        'openssl', 'req', '-new',
        '-key',  $disp_key,
        '-out',  $disp_csr,
        '-subj', '/CN=ctrl-exec-dispatcher',
    );

    _run_or_die(
        'openssl', 'x509', '-req',
        '-in',           $disp_csr,
        '-CA',           $ca_cert,
        '-CAkey',        $ca_key,
        '-CAserial',     $serial,
        '-CAcreateserial',
        '-out',          $disp_crt,
        '-days',         $days,
    );

    unlink $disp_csr;

    return { key => $disp_key, cert => $disp_crt };
}


# Writes cert to $out_path if provided, else returns PEM string only
sub sign_csr {
    my (%opts) = @_;
    my $csr_pem  = $opts{csr_pem}  or croak "csr_pem required";
    my $days     = $opts{days}     // 825;
    my $ca_dir   = $opts{ca_dir}   // $CA_DIR;
    my $out_path = $opts{out_path};
    # Optional: bind the CSR subject CN to a known identity. Callers that know
    # which agent they are signing for (cert renewal) pass this so a holder of
    # one signed cert cannot mint a cert naming a different identity. Undef at
    # pairing time, where the operator visually confirms the identity instead.
    my $expected_cn = $opts{expected_cn};

    croak "days must be a positive integer"
        unless defined $days && $days =~ /^\d+$/ && $days > 0;

    my $ca_key   = "$ca_dir/ca.key";
    my $ca_cert  = "$ca_dir/ca.crt";
    my $serial   = "$ca_dir/ca.serial";

    croak "CA key not found at '$ca_key'"   unless -f $ca_key;
    croak "CA cert not found at '$ca_cert'" unless -f $ca_cert;

    croak "CSR exceeds maximum size"
        unless length($csr_pem) <= 10_240;

    croak "Invalid CSR format"
        unless $csr_pem =~ /\A-----BEGIN CERTIFICATE REQUEST-----/;

    # Write CSR to temp file.
    # File::Temp->new returns an object; the file is unlinked when the object
    # goes out of scope (success or croak), unlike list-form tempfile() which
    # only unlinks at END.
    my $csr_tmp = File::Temp->new(SUFFIX => '.csr', DIR => $ca_dir, UNLINK => 1);
    my $csr_path = $csr_tmp->filename;
    print $csr_tmp $csr_pem;
    close $csr_tmp;

    # Validate before signing. Without this, sign_csr is a signing oracle: it
    # would sign any subject with any key/algorithm. Reject weak keys and weak
    # self-signatures, confirm the CSR is self-consistent, and - when the caller
    # supplies expected_cn - bind the subject CN to that identity.
    _validate_csr($csr_path, $expected_cn);

    my $cert_tmp  = File::Temp->new(SUFFIX => '.crt', DIR => $ca_dir, UNLINK => 1);
    my $cert_path = $cert_tmp->filename;
    close $cert_tmp;

    _run_or_die(
        'openssl', 'x509', '-req',
        '-in',        $csr_path,
        '-CA',        $ca_cert,
        '-CAkey',     $ca_key,
        '-CAserial',  $serial,
        '-CAcreateserial',
        '-out',       $cert_path,
        '-days',      $days,
    );

    my $cert_pem = _slurp($cert_path);

    if ($out_path) {
        _write_file($out_path, $cert_pem, 0644);
    }

    return $cert_pem;
}

# Read CA cert PEM - for distribution to agents during pairing
sub read_ca_cert {
    my (%opts) = @_;
    my $ca_dir = $opts{ca_dir} // $CA_DIR;
    return _slurp("$ca_dir/ca.crt");
}

# --- private helpers ---

# Generate an RSA private key at $path under a tight umask, so the key is never
# momentarily group/world-readable in the (shared, 0750) CA directory between
# openssl creating the -out file and the chmod. openssl honours the process
# umask when it creates the output file; 0077 forces 0600 at creation time.
sub _genrsa {
    my ($path, $bits) = @_;
    my $old_umask = umask 0077;
    my $ok = eval { _run_or_die('openssl', 'genrsa', '-out', $path, $bits); 1 };
    umask $old_umask;
    die $@ unless $ok;
    chmod 0600, $path;   # belt-and-braces in case a prior umask was looser
}

# Validate a CSR (at $csr_path) before signing. Dies (croaks) on any failure,
# which the caller surfaces as a signing refusal.
sub _validate_csr {
    my ($csr_path, $expected_cn) = @_;

    # Self-consistency: the CSR signature must verify against its own public
    # key, proving the requester holds the corresponding private key. A bad
    # signature makes openssl exit non-zero, which _run_or_die turns into a die.
    _run_or_die('openssl', 'req', '-verify', '-noout', '-in', $csr_path);

    my $text = _run_or_capture('openssl', 'req', '-in', $csr_path, '-noout', '-text');

    my ($bits) = $text =~ /Public-Key:\s*\((\d+)\s*bit\)/;
    croak "CSR public key too small (need >= 2048 bits)"
        unless defined $bits && $bits >= 2048;

    # Reject weak digests. Algorithm strings run the digest into the rest of the
    # name (e.g. "sha1WithRSAEncryption", "ecdsa-with-SHA1"), so match the digest
    # token without requiring a trailing word boundary; the (?![0-9]) guard keeps
    # "sha1" from matching the strong "sha256"/"sha512" family.
    my ($sigalg) = $text =~ /Signature Algorithm:\s*(\S+)/;
    croak "CSR uses a weak or unrecognised signature algorithm"
            . (defined $sigalg ? " ($sigalg)" : '')
        if !defined $sigalg || $sigalg =~ /(?:md[245]|sha-?1)(?![0-9])/i;

    if (defined $expected_cn) {
        my ($cn) = $text =~ /Subject:[^\n]*?\bCN\s*=\s*([^,\n]+)/;
        $cn =~ s/\s+$// if defined $cn;
        croak "CSR subject CN does not match the expected identity"
            unless defined $cn && $cn eq $expected_cn;
    }
}

# Like _run_or_die, but captures and returns the command's stdout. stderr is
# left on the inherited fd 2. Used to inspect a CSR with `openssl req -text`.
sub _run_or_capture {
    my @cmd = @_;

    my ($out_fh, $out_path) = tempfile(UNLINK => 1);
    my $out_fileno = fileno($out_fh);

    require POSIX;
    my $saved_fd1 = POSIX::dup(1)
        or croak "Cannot dup stdout: $!";
    POSIX::dup2($out_fileno, 1)
        or do { POSIX::close($saved_fd1); croak "Cannot redirect stdout: $!" };
    close $out_fh;

    my $rc = system(@cmd);

    POSIX::dup2($saved_fd1, 1);
    POSIX::close($saved_fd1);

    croak "Command failed (@cmd): exit $?" if $rc != 0;
    return _slurp($out_path);
}

sub _run_or_die {
    my @cmd = @_;

    # Capture openssl stderr by redirecting fd 2 at the OS level.
    # open(local *STDERR, ...) only redirects Perl's STDERR glob; system()
    # inherits the original fd 2 from the OS regardless of that redirect.
    # POSIX::dup2 operates on raw file descriptors so the child sees the
    # redirect.
    my ($err_fh, $err_path) = tempfile(UNLINK => 1);
    my $err_fileno = fileno($err_fh);

    require POSIX;
    my $saved_fd2 = POSIX::dup(2)
        or croak "Cannot dup stderr: $!";
    POSIX::dup2($err_fileno, 2)
        or do { POSIX::close($saved_fd2); croak "Cannot redirect stderr: $!" };
    close $err_fh;

    my $rc = system(@cmd);

    # Restore fd 2 before any further output
    POSIX::dup2($saved_fd2, 2);
    POSIX::close($saved_fd2);

    if ($rc != 0) {
        my $stderr = _slurp($err_path);
        $stderr =~ s/\s+$//;
        croak "Command failed (@cmd): exit $?\n$stderr";
    }
}

sub _slurp {
    my ($path) = @_;
    open my $fh, '<', $path or croak "Cannot read '$path': $!";
    local $/;
    return scalar <$fh>;
}

sub _write_file {
    my ($path, $content, $mode) = @_;
    open my $fh, '>', $path or croak "Cannot write '$path': $!";
    print $fh $content;
    close $fh;
    chmod $mode, $path;
}

sub _write_serial {
    my ($path, $value) = @_;
    _write_file($path, $value, 0600);
}

1;
