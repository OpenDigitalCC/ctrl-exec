#!/usr/bin/perl
# t/exec-fd-root.t  (T-051)
#
# The action inherits only stdin, stdout and stderr, as root with run_as and
# with and without `writable` (the read-only mount namespace), for each input=
# mode. Each script lists the fds it holds and then writes a forged result
# frame (exit 42, stdout FORGED) to every fd above 2: before T-051 the
# executor's connection socket was among them and the agent took the forged
# frame as the run's result. The executor is started holding an extra fd its
# launcher left open (not close-on-exec); that must not reach the action
# either. Driven through the agent front end (Exec::Agent::Server with
# executor_socket), as t/exec-input-root.t is. Skips unless root (run it in
# tools/wedge-rig, or a root container).
#
# CE_EXECUTOR_SRC=<file> builds another executor source instead (to show the
# failure on the executor before T-051).

use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use FindBin    qw($Bin);
use lib "$Bin/../lib";
use Fcntl qw(F_GETFD F_SETFD FD_CLOEXEC);
use IO::Socket::UNIX qw();
use JSON::PP ();
use POSIX qw();

plan skip_all => 'must run as root (run_as and the mount namespace need it)' unless $> == 0;
my $cc = `command -v gcc 2>/dev/null`; chomp $cc;
plan skip_all => 'gcc not available' unless $cc && -x $cc;
plan skip_all => '/proc/self/fd not available' unless -d '/proc/self/fd';
my @nobody = getpwnam('nobody');
plan skip_all => 'no "nobody" user to drop to' unless @nobody;
my $RUN_UID = $nobody[2];

require Exec::Agent::Config;
require Exec::Agent::Server;
require Exec::Log;
{
    no warnings qw(redefine once);
    *Exec::Log::log_action = sub { };
}
my $JSON = JSON::PP->new->canonical;

# /run, not /tmp: a `writable` profile mounts a private tmpfs on /tmp. The
# executor's input directory is <socket dir>/input, so the socket dir must be
# traversable by the run_as user (0755) and owned by root.
umask 022;
my $TMP = tempdir(DIR => '/run', CLEANUP => 1);
chmod 0755, $TMP;
my $SRC = $ENV{CE_EXECUTOR_SRC} // "$Bin/../src/ctrl-exec-executor.c";
my $BIN = "$TMP/ctrl-exec-executor";
system($cc, '-O2', '-o', $BIN, $SRC, '-lcap') == 0
    or plan skip_all => "could not compile $SRC";
my $W = "$TMP/w";               # records from the actions; the writable carve-out
mkdir $W; chmod 0777, $W;
mkdir "$TMP/s";

sub write_file { my ($p, $c, $m) = @_; open my $fh, '>', $p or die "$p: $!"; print $fh $c; close $fh; chmod $m, $p if $m }
sub slurp { my ($p) = @_; open my $fh, '<', $p or return undef; local $/; my $c = <$fh>; return $c }

# The action: record "<fd> <target>" for every fd it holds (its own directory
# handle on /proc/self/fd excluded), its uid and, for input=fields, its file
# read by path; then write a forged result frame to every fd above 2, then exit
# 0 with "genuine" on stdout.
sub fd_script {
    my ($out) = @_;
    return <<"PL";
#!/usr/bin/perl
use strict; use warnings;
my \@fds;
opendir my \$d, '/proc/self/fd' or die "opendir: \$!";
my \$me = "/proc/\$\$/fd";
for my \$fd (sort { \$a <=> \$b } grep { /^\\d+\\z/ } readdir \$d) {
    my \$t = readlink("/proc/self/fd/\$fd") // '?';
    next if \$t eq \$me;
    push \@fds, "\$fd \$t";
}
closedir \$d;
my \$file = '';
if (defined \$ENV{CTRL_EXEC_INPUT}) {
    my \$fh;
    if (open \$fh, '<', "\$ENV{CTRL_EXEC_INPUT}/key") { local \$/; \$file = <\$fh> // '' }
}
open my \$o, '>', '$out' or die "\$!";
print \$o "\$_\\n" for \@fds;
print \$o "FILE=\$file\\n";
print \$o "UID=\$<\\n";
close \$o;
my \$forged = pack('N N a* N', 42, 7, "FORGED\\n", 0);
for (\@fds) {
    my (\$fd) = /^(\\d+)/;
    next if \$fd <= 2;
    if (open my \$w, '>&=', \$fd) { syswrite \$w, \$forged }
}
print "genuine\\n";
exit 0;
PL
}

my %mode = (ctx => 'context', raw => 'raw:key', flds => 'fields');
my $sc = '';
for my $prof (qw(plain conf)) {
    for my $m (sort keys %mode) {
        my $name = "fd-$m-$prof";
        write_file("$TMP/s/$name.pl", fd_script("$W/fds.$name"), 0755);
        $sc .= "$name = $TMP/s/$name.pl profile=$prof input=$mode{$m}\n";
    }
}

my $agent_conf = "$TMP/agent.conf";
write_file($agent_conf, "port = 7443\ncert = /x\nkey = /y\nca = /z\nscript_dirs = $TMP/s\n"
                      . "[profile default]\nrun_as = nobody\n"
                      . "[profile plain]\nrun_as = nobody\n"
                      . "[profile conf]\nrun_as = nobody\nwritable = $W\n");
my $scripts_conf = "$TMP/scripts.conf";
write_file($scripts_conf, $sc);
my ($allowlist, $skipped);
{
    local $SIG{__WARN__} = sub {};
    ($allowlist, $skipped) = Exec::Agent::Config::load_allowlist_full($scripts_conf, ["$TMP/s"]);
}
is scalar(keys %$allowlist), 6, 'all test scripts allowlisted' or diag explain $skipped;

my $sock     = "$TMP/exec.sock";
my $exec_log = "$TMP/exec.log";
my $LEAK_FD  = 9;
my $epid = fork // die "fork: $!";
if (!$epid) {
    open STDERR, '>>', $exec_log or POSIX::_exit(127);
    # An fd the launcher left open across exec (fd 9, close-on-exec off).
    open my $leak, '>', "$TMP/launcher-leak" or POSIX::_exit(127);
    POSIX::dup2(fileno $leak, $LEAK_FD) // POSIX::_exit(127);
    open my $l9, '>&=', $LEAK_FD or POSIX::_exit(127);
    fcntl($l9, F_SETFD, fcntl($l9, F_GETFD, 0) & ~FD_CLOEXEC) or POSIX::_exit(127);
    exec($BIN, 'serve', $sock, $agent_conf, $scripts_conf, 'root') or POSIX::_exit(127);
}
my $up = 0;
for (1 .. 100) { if (-S $sock) { $up = 1; last } select undef, undef, undef, 0.05 }
ok $up, 'executor created its socket' or do { done_testing; exit };
ok -e "/proc/$epid/fd/$LEAK_FD", "the executor holds the launcher's fd $LEAK_FD";

sub post {
    my ($payload) = @_;
    my $body = $JSON->encode($payload);
    my ($client, $server) = IO::Socket::UNIX->socketpair(
        IO::Socket::AF_UNIX(), IO::Socket::SOCK_STREAM(), 0) or die "socketpair: $!";
    print $client "POST /run HTTP/1.0\r\nContent-Length: " . length($body) . "\r\n\r\n$body";
    $client->shutdown(1);
    Exec::Agent::Server::handle_connection(
        $server, '10.0.0.5', $allowlist, { script_dirs => ["$TMP/s"], executor_socket => $sock },
        {}, { deadbeef => 'disp-1' }, 'deadbeef', {}, '9.9.9', $skipped,
    );
    $server->close;
    local $/;
    my $resp = <$client> // '';
    $client->close;
    $resp =~ s/\A.*?\r\n\r\n//s;
    return JSON::PP::decode_json($resp);
}

my $VALUE = 'fd-root-test-value';
for my $prof (qw(plain conf)) {
    for my $m (sort keys %mode) {
        my $name = "fd-$m-$prof";
        subtest "input=$mode{$m}, profile $prof (run_as nobody): only fds 0, 1, 2" => sub {
            unlink "$W/fds.$name";
            my $r = post({ script => $name, args => [], reqid => $name, username => 'u',
                           token => 't', input => { key => $VALUE } });
            my $seen = slurp("$W/fds.$name") // '';
            my @fds = map { (split / /)[0] } grep { /^\d+ / } split /\n/, $seen;
            is "@fds", '0 1 2', 'fds held: 0 1 2' or diag $seen, explain $r;
            like $seen, qr/^$_ pipe:\[\d+\]$/m, "fd $_ is the executor's pipe" for 0 .. 2;
            like $seen, qr/^UID=\Q$RUN_UID\E$/m, 'ran as run_as';
            is $seen =~ /^FILE=(.*)$/m ? $1 : undef, ($m eq 'flds' ? $VALUE : ''),
                $m eq 'flds' ? 'reads its input file by path' : 'no input directory';
            is $r->{exit}, 0, 'the result is the genuine exit status' or diag explain $r;
            is $r->{stdout}, "genuine\n", 'and the genuine stdout (no forged frame)';
        };
    }
}

kill 'TERM', $epid; waitpid $epid, 0;
done_testing;
