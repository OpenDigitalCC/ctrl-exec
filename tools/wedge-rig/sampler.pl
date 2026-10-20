#!/usr/bin/perl
# Wedge rig sampler. Runs inside the container as root. Once a second appends a
# CSV row to the file named in $ARGV[0] (default /out/samples.csv).
# For each of api, agent, exec (master pids from /run/rig/*.pid):
#   pid, nfds (/proc/<pid>/fd), kids (direct children of the master),
#   desc (all descendants), zomb (zombie descendants)
# Plus: container-wide process and zombie counts, the master's nofile soft
# limit, TCP sockets by state (ss -tan), and unix connections on the executor
# socket (ss -xan, local address == socket path, state not LISTEN).
use strict;
use warnings;
use Time::HiRes qw(time sleep);
use POSIX qw(strftime);

my $out  = shift // '/out/samples.csv';
my $sock = '/run/ctrl-exec-agent/exec.sock';
my @roles = qw(api agent exec);

sub procs {
    my %p;
    opendir(my $d, '/proc') or return \%p;
    for my $e (readdir $d) {
        next unless $e =~ /^\d+$/;
        open(my $f, '<', "/proc/$e/stat") or next;
        my $s = <$f>;
        close $f;
        next unless defined $s and $s =~ /^\d+ \((.*)\) (\S) (\d+)/s;
        $p{$e} = { comm => $1, state => $2, ppid => $3 };
    }
    closedir $d;
    return \%p;
}

sub nfds {
    my $pid = shift;
    opendir(my $d, "/proc/$pid/fd") or return -1;
    my $n = grep { $_ ne '.' && $_ ne '..' } readdir $d;
    closedir $d;
    return $n;
}

sub softlimit {
    my $pid = shift;
    open(my $f, '<', "/proc/$pid/limits") or return -1;
    while (<$f>) { return $1 if /^Max open files\s+(\d+)/ }
    return -1;
}

my $new = !-s $out;
open(my $o, '>>', $out) or die "$out: $!";
select((select($o), $| = 1)[0]);
if ($new) {
    my @h = ('epoch', 'time');
    for my $r (@roles) { push @h, map {"${r}_$_"} qw(pid fds kids desc zomb nofile) }
    push @h, qw(all_procs all_zomb ESTAB TIME_WAIT CLOSE_WAIT FIN_WAIT SYN other_tcp exec_unix_conns);
    print $o join(',', @h), "\n";
}

my $next = int(time) + 1;
while (1) {
    my $now = time;
    sleep($next - $now) if $next > $now;
    $next++;
    my $t = time;
    my $P = procs();
    my %kids;
    for my $pid (keys %$P) { push @{ $kids{ $P->{$pid}{ppid} } }, $pid }
    my @row = (sprintf('%.3f', $t), strftime('%H:%M:%S', gmtime($t)));
    for my $r (@roles) {
        my $pid = -1;
        if (open(my $pf, '<', "/run/rig/$r.pid")) { $pid = <$pf>; chomp $pid; close $pf }
        if ($pid < 0 || !$P->{$pid}) { push @row, ($pid, -1, -1, -1, -1, -1); next }
        my $direct = scalar @{ $kids{$pid} // [] };
        my ($desc, $zomb) = (0, 0);
        my @q = @{ $kids{$pid} // [] };
        while (my $c = shift @q) {
            $desc++;
            $zomb++ if $P->{$c}{state} eq 'Z';
            push @q, @{ $kids{$c} // [] };
        }
        push @row, ($pid, nfds($pid), $direct, $desc, $zomb, softlimit($pid));
    }
    my $allz = grep { $P->{$_}{state} eq 'Z' } keys %$P;
    push @row, (scalar(keys %$P), $allz);

    my %st;
    if (open(my $ss, '-|', 'ss', '-tan')) {
        <$ss>;
        while (<$ss>) { my ($s) = split; $st{$s}++ }
        close $ss;
    }
    my $fw = ($st{'FIN-WAIT-1'} // 0) + ($st{'FIN-WAIT-2'} // 0);
    my $syn = ($st{'SYN-SENT'} // 0) + ($st{'SYN-RECV'} // 0);
    my $other = 0;
    for my $k (keys %st) {
        $other += $st{$k} unless $k =~ /^(ESTAB|TIME-WAIT|CLOSE-WAIT|FIN-WAIT-[12]|SYN-SENT|SYN-RECV)$/;
    }
    push @row, ($st{ESTAB} // 0, $st{'TIME-WAIT'} // 0, $st{'CLOSE-WAIT'} // 0, $fw, $syn, $other);

    my $u = 0;
    if (open(my $ss, '-|', 'ss', '-xan')) {
        <$ss>;
        while (<$ss>) {
            my @f = split;
            # Netid State Recv-Q Send-Q Local Peer
            next unless @f >= 5;
            $u++ if $f[4] eq $sock && $f[1] ne 'LISTEN';
        }
        close $ss;
    }
    push @row, $u;
    print $o join(',', @row), "\n";
}
