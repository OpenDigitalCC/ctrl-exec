#!/usr/bin/perl
# t/exec-fd.t  (T-051)
#
# The action inherits only stdin, stdout and stderr. Before T-051 the
# executor's per-connection socket (from accept() without SOCK_CLOEXEC) stayed
# open across execve, so an action could write its own result frame to the
# agent: any exit code and output it liked. Each script here lists the fds it
# holds and then tries exactly that forgery on every fd above 2.
#
# Unprivileged test build (CTRL_EXEC_EXEC_ALLOW_UNPRIV, profiles without
# run_as), driven through the agent front end (Exec::Agent::Server) for each
# input= mode, and for direct mode (no executor) as a guard. The executor is
# started holding an extra fd its launcher left open (not close-on-exec), to
# show that what the executor inherits does not reach the action either. The
# run_as and `writable` cases are in t/exec-fd-root.t.
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

use Exec::Agent::Config qw();
use Exec::Agent::Server qw();
use Exec::Log           qw();

my $cc = `command -v gcc 2>/dev/null`; chomp $cc;
plan skip_all => 'gcc not available' unless $cc && -x $cc;
plan skip_all => '/proc/self/fd not available' unless -d '/proc/self/fd';

{
    no warnings 'redefine';
    *Exec::Log::log_action = sub { };
}
my $JSON = JSON::PP->new->canonical;

umask 022;   # nothing group-writable: the executor refuses it (T-045)
my $dir = tempdir(CLEANUP => 1);
my $SRC = $ENV{CE_EXECUTOR_SRC} // "$Bin/../src/ctrl-exec-executor.c";
my $BIN = "$dir/ctrl-exec-executor";
system($cc, '-O2', '-DCE_TEST_SEAM', '-o', $BIN, $SRC, '-lcap') == 0
    or plan skip_all => "could not compile $SRC";
@Exec::Agent::Config::TRUSTED_OWNERS = (0, $>);
$Exec::Agent::Config::TRUSTED_TOP    = $dir;
mkdir "$dir/s" or die;
mkdir "$dir/out" or die;
sub write_file { my ($p, $c, $m) = @_; open my $fh, '>', $p or die "$p: $!"; print $fh $c; close $fh; chmod $m, $p if $m }
sub slurp { my ($p) = @_; open my $fh, '<', $p or return undef; local $/; my $c = <$fh>; return $c }

# The action: record "<fd> <target>" for every fd it holds (its own directory
# handle on /proc/self/fd excluded), then write a forged result frame (exit 42,
# stdout FORGED) to every fd above 2, then exit 0 with "genuine" on stdout.
# For input=fields it also reads its file by path, as a real action does.
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
for my $m (sort keys %mode) {
    write_file("$dir/s/fd-$m.pl", fd_script("$dir/out/fds.$m"), 0755);
    $sc .= "fd-$m = $dir/s/fd-$m.pl input=$mode{$m}\n";
}
write_file("$dir/s/fd-direct.pl", fd_script("$dir/out/fds.direct"), 0755);
$sc .= "fd-direct = $dir/s/fd-direct.pl\n";

my $agent_conf = "$dir/agent.conf";
write_file($agent_conf, "port = 7443\ncert = /x\nkey = /y\nca = /z\nscript_dirs = $dir/s\n[profile default]\n");
my $scripts_conf = "$dir/scripts.conf";
write_file($scripts_conf, $sc);
my ($allowlist, $skipped);
{
    local $SIG{__WARN__} = sub {};
    ($allowlist, $skipped) = Exec::Agent::Config::load_allowlist_full($scripts_conf, ["$dir/s"]);
}
is scalar(keys %$allowlist), 4, 'test scripts allowlisted' or diag explain $skipped;

my $sock     = "$dir/exec.sock";
my $exec_log = "$dir/out/executor.log";
my $LEAK_FD  = 9;
my $epid;
sub start_executor {
    $epid = fork // die "fork: $!";
    if (!$epid) {
        open STDERR, '>>', $exec_log or POSIX::_exit(127);
        # An fd the launcher left open across exec (fd 9, close-on-exec off).
        open my $leak, '>', "$dir/out/launcher-leak" or POSIX::_exit(127);
        POSIX::dup2(fileno $leak, $LEAK_FD) // POSIX::_exit(127);
        open my $l9, '>&=', $LEAK_FD or POSIX::_exit(127);
        fcntl($l9, F_SETFD, fcntl($l9, F_GETFD, 0) & ~FD_CLOEXEC) or POSIX::_exit(127);
        $ENV{CTRL_EXEC_EXEC_ALLOW_UNPRIV} = 1;
        $ENV{CE_TEST_TRUSTED_UID} = $>;
        $ENV{CE_TEST_TRUSTED_TOP} = $dir;
        exec($BIN, 'serve', $sock, $agent_conf, $scripts_conf, scalar getpwuid($>))
            or POSIX::_exit(127);
    }
    for (1 .. 100) { return 1 if -S $sock; select undef, undef, undef, 0.05 }
    return 0;
}
ok start_executor(), 'executor created its socket' or do { done_testing; exit };
ok -e "/proc/$epid/fd/$LEAK_FD", "the executor holds the launcher's fd $LEAK_FD";

sub post {
    my ($payload, %cfg) = @_;
    my $body = $JSON->encode($payload);
    my ($client, $server) = IO::Socket::UNIX->socketpair(
        IO::Socket::AF_UNIX(), IO::Socket::SOCK_STREAM(), 0) or die "socketpair: $!";
    print $client "POST /run HTTP/1.0\r\nContent-Length: " . length($body) . "\r\n\r\n$body";
    $client->shutdown(1);
    Exec::Agent::Server::handle_connection(
        $server, '10.0.0.5', $allowlist, { script_dirs => ["$dir/s"], %cfg },
        {}, { deadbeef => 'disp-1' }, 'deadbeef', {}, '9.9.9', $skipped,
    );
    $server->close;
    local $/;
    my $resp = <$client> // '';
    $client->close;
    $resp =~ s/\A.*?\r\n\r\n//s;
    return JSON::PP::decode_json($resp);
}

my $VALUE = 'fd-test-value';
for my $m ((sort keys %mode), 'direct') {
    my $label = $m eq 'direct' ? 'direct mode (no executor)' : "executor, input=$mode{$m}";
    subtest "$label: the action holds only fds 0, 1, 2" => sub {
        unlink "$dir/out/fds.$m";
        my $r = post({ script => "fd-$m", args => [], reqid => "fd-$m", username => 'u',
                       token => 't', input => { key => $VALUE } },
                     $m eq 'direct' ? () : (executor_socket => $sock));
        my $seen = slurp("$dir/out/fds.$m") // '';
        my @fds = map { (split / /)[0] } grep { /^\d+ / } split /\n/, $seen;
        is "@fds", '0 1 2', 'fds held: 0 1 2' or diag $seen, explain $r;
        if ($m ne 'direct') {
            like $seen, qr/^1 pipe:\[\d+\]$/m, 'stdout is the executor pipe';
            like $seen, qr/^2 pipe:\[\d+\]$/m, 'stderr is the executor pipe';
            like $seen, qr/^0 pipe:\[\d+\]$/m, 'stdin is the executor pipe';
        }
        is $seen =~ /^FILE=(.*)$/m ? $1 : undef, ($m eq 'flds' ? $VALUE : ''),
            $m eq 'flds' ? 'reads its input file by path' : 'no input directory';
        is $r->{exit}, 0, 'the result is the genuine exit status' or diag explain $r;
        is $r->{stdout}, "genuine\n", 'and the genuine stdout (no forged frame)';
    };
}

kill 'TERM', $epid; waitpid $epid, 0;
done_testing;
