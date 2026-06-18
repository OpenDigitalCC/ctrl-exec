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

    _run_or_die('openssl', 'genrsa', '-out', $ca_key, $bits);
    chmod 0600, $ca_key;

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

    _run_or_die('openssl', 'genrsa', '-out', $disp_key, $bits);
    chmod 0600, $disp_key;

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
