package Exec::Cmd;

# Run an external command (list form, no shell) and die with its captured stderr
# on a non-zero exit. The stderr capture redirects fd 2 at the OS level
# (POSIX::dup2) so the child's actual error - e.g. openssl's message - reaches the
# die text; a plain `system()==0 or die` discards it. Consolidated from CA (which
# had this) and AgentPairing (which had a bare system()==0 that lost the error).

use strict;
use warnings;
use Carp       qw(croak);
use File::Temp qw(tempfile);
use Exporter   qw(import);

use Exec::FileUtil qw(slurp);

our @EXPORT_OK = qw(run_or_die);

sub run_or_die {
    my @cmd = @_;

    my ($err_fh, $err_path) = tempfile(UNLINK => 1);
    my $err_fileno = fileno($err_fh);

    require POSIX;
    my $saved_fd2 = POSIX::dup(2)
        or croak "Cannot dup stderr: $!";
    POSIX::dup2($err_fileno, 2)
        or do { POSIX::close($saved_fd2); croak "Cannot redirect stderr: $!" };
    close $err_fh;

    my $rc = system(@cmd);

    POSIX::dup2($saved_fd2, 2);
    POSIX::close($saved_fd2);

    if ($rc != 0) {
        my $stderr = slurp($err_path);
        $stderr =~ s/\s+$//;
        croak "Command failed (@cmd): exit $?\n$stderr";
    }
}

1;
