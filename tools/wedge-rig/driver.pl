#!/usr/bin/perl
# Wedge rig driver: sends runs to the ctrl-exec API (POST /run) as a caller does.
#   driver.pl --total N [--conc C] [--delay SECONDS] [--url URL] [--out FILE]
#             [--script NAME] [--host NAME]
# conc 1 = fully serialised (next run starts after the previous returns, then
# the delay). With conc>1, C workers each run their share back to back.
# Writes one CSV row per run: seq,epoch,time,dur_ms,http,exit,error,stdout
# and prints a summary to stdout.
use strict;
use warnings;
use HTTP::Tiny;
use JSON::PP;
use Time::HiRes qw(time sleep);
use POSIX qw(strftime);
use Getopt::Long;

my %o = (total => 10, conc => 1, delay => 0, url => 'http://127.0.0.1:17445',
         out => 'runs.csv', script => 'rig-hello', host => 'rig', timeout => 120);
GetOptions(\%o, 'total=i', 'conc=i', 'delay=f', 'url=s', 'out=s', 'script=s', 'host=s', 'timeout=i') or die "bad options\n";
die "total must be 1..500\n" unless $o{total} >= 1 && $o{total} <= 500;
die "conc must be 1..16\n" unless $o{conc} >= 1 && $o{conc} <= 16;

sub csv { join ',', map { my $v = $_ // ''; $v =~ s/[\r\n]+/ /g; $v =~ s/"/""/g; $v =~ /[,"]/ ? "\"$v\"" : $v } @_ }

sub one_run {
    my ($seq) = @_;
    my $http = HTTP::Tiny->new(timeout => $o{timeout});
    my $body = encode_json({ hosts => [$o{host}], script => $o{script}, args => [],
                             username => 'rig', token => 'rig' });
    my $t0 = time;
    my $r = $http->post("$o{url}/run", { headers => { 'Content-Type' => 'application/json' }, content => $body });
    my $dur = int((time - $t0) * 1000);
    my ($exit, $err, $out) = ('', '', '');
    my $status = $r->{status};
    my $d = eval { decode_json($r->{content}) };
    if ($d) {
        my $res = $d->{results};
        my $x = ref $res eq 'ARRAY' ? $res->[0] : (ref $res eq 'HASH' ? (values %$res)[0] : undef);
        if (ref $x eq 'HASH') {
            $exit = $x->{exit} // '';
            $err  = $x->{error} // '';
            $out  = $x->{stdout} // '';
            $out =~ s/\s+$//;
        } else {
            $err = 'no result: ' . ($d->{error} // substr($r->{content}, 0, 120));
        }
    } else {
        $err = 'transport: ' . ($r->{content} // '') ;
        $err = substr($err, 0, 160);
    }
    return csv($seq, sprintf('%.3f', $t0), strftime('%H:%M:%S', gmtime($t0)), $dur, $status, $exit, $err, $out);
}

open(my $fh, '>', $o{out}) or die "$o{out}: $!";
select((select($fh), $| = 1)[0]);
print $fh "seq,epoch,time,dur_ms,http,exit,error,stdout\n";

my $start = time;
my @pids;
for my $w (0 .. $o{conc} - 1) {
    my $pid = fork() // die "fork: $!";
    if ($pid == 0) {
        # worker w takes seq numbers w+1, w+1+conc, ...
        open(my $wf, '>>', $o{out}) or die;
        select((select($wf), $| = 1)[0]);
        for (my $seq = $w + 1; $seq <= $o{total}; $seq += $o{conc}) {
            print $wf one_run($seq), "\n";
            sleep($o{delay}) if $o{delay} > 0;
        }
        exit 0;
    }
    push @pids, $pid;
}
waitpid($_, 0) for @pids;
my $elapsed = time - $start;
close $fh;

# summary (rows are in completion order; sort by start time for "first failure")
open(my $in, '<', $o{out}) or die;
<$in>;
my @rows;
while (<$in>) {
    chomp;
    my @f = /("(?:[^"]|"")*"|[^,]*)(?:,|$)/g;
    pop @f if @f > 8;
    push @rows, \@f;
}
close $in;
@rows = sort { $a->[1] <=> $b->[1] } @rows;
my ($ok, $bad, $first, %errs) = (0, 0, undef);
for my $r (@rows) {
    my ($seq, $ep, $time, $dur, $http, $exit, $err) = @$r;
    $err =~ s/^"|"$//g;
    if ($http eq '200' && $exit eq '0' && $err eq '') { $ok++ }
    else { $bad++; $first //= "seq=$seq at $time (http $http exit $exit)"; $errs{"http=$http exit=$exit err=$err"}++ }
}
printf "total=%d conc=%d delay=%s elapsed=%.1fs ok=%d failed=%d\n", $o{total}, $o{conc}, $o{delay}, $elapsed, $ok, $bad;
print "first failure (by start time): ", ($first // 'none'), "\n";
print "  $errs{$_} x $_\n" for sort keys %errs;
