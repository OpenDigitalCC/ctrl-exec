#!/usr/bin/perl
# t/exec-client-frame.t  (T-013 piece 3)
#
# The bytes Exec::Agent::ExecClient sends the executor. A run with nothing new
# to say keeps the v1 frame (so it works with an executor of either age); a run
# with input, or a context for CTRL_EXEC_CONTEXT, sends v2: the magic where v1
# has the reqid length, then the v1 fields, the context, the args, and the input
# fields sorted by name as UTF-8 bytes. Captured by a stub executor and decoded
# here field by field.

use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use FindBin    qw($Bin);
use lib "$Bin/../lib", "$Bin/lib";
use ChildGuard ();
use IO::Socket::UNIX qw();
use POSIX qw();

use Exec::Agent::ExecClient qw();

my $dir  = ChildGuard::dir(tempdir(CLEANUP => 1));
my $sock = "$dir/stub.sock";
my $cap  = "$dir/frame";

# Stub executor: store the request frame, answer exit 0.
my $srv = IO::Socket::UNIX->new(Local => $sock, Type => IO::Socket::UNIX::SOCK_STREAM(), Listen => 5)
    or die "listen: $!";
my $spid = ChildGuard::guarded_fork() // die "fork: $!";
if (!$spid) {
    while (my $c = $srv->accept) {
        my $hdr = ''; $c->sysread($hdr, 4);
        my $n = unpack 'N', $hdr; my $got = '';
        while (length $got < $n) { $c->sysread(my $b, $n - length $got) or last; $got .= $b }
        open my $fh, '>', $cap or POSIX::_exit(1); binmode $fh; print $fh $hdr . $got; close $fh;
        $c->syswrite(pack('l>', 0) . pack('N', 0) . pack('N', 0));
        close $c;
    }
    POSIX::_exit(0);
}

sub frame { open my $fh, '<', $cap or return ''; binmode $fh; local $/; return <$fh> }
sub fields {   # decode n length-prefixed fields from $buf at $$off
    my ($buf, $off, $n) = @_;
    my @f;
    for (1 .. $n) { my $l = unpack 'N', substr($buf, $$off, 4); push @f, substr($buf, $$off + 4, $l); $$off += 4 + $l }
    return @f;
}

subtest 'no input, no context: the v1 frame' => sub {
    my $r = Exec::Agent::ExecClient::run(socket => $sock, reqid => 'q1', dispatcher_id => 'd',
        script => 's', args => ['a1', 'a2'], stdin => '{"x":1}');
    is $r->{exit}, 0, 'ran';
    my $b = frame();
    is unpack('N', $b), length($b) - 4, 'total length';
    my $off = 4;
    is_deeply [fields($b, \$off, 4)], ['q1', 'd', 's', '{"x":1}'], 'reqid, disp, script, stdin';
    is unpack('N', substr($b, $off, 4)), 2, 'argc'; $off += 4;
    is_deeply [fields($b, \$off, 2)], ['a1', 'a2'], 'args';
    is $off, length $b, 'nothing else';
};

subtest 'input: the v2 frame, fields sorted, values as UTF-8 bytes' => sub {
    my $r = Exec::Agent::ExecClient::run(socket => $sock, reqid => 'q2', dispatcher_id => 'd',
        script => 's', args => ['a1'], stdin => '{"input":{}}', context => '{"script":"s"}',
        input => { zeta => "z\0z", alpha => "caf\x{e9} \x{263a}", 'b.pem' => '' });
    is $r->{exit}, 0, 'ran';
    my $b = frame();
    is unpack('N', $b), length($b) - 4, 'total length';
    is unpack('N', substr($b, 4, 4)), 0xCE0E0002, 'magic where v1 has the reqid length';
    ok 0xCE0E0002 > 16 * 1024 * 1024, 'the magic exceeds any frame, so an old executor rejects it';
    my $off = 8;
    is_deeply [fields($b, \$off, 5)], ['q2', 'd', 's', '{"input":{}}', '{"script":"s"}'],
        'reqid, disp, script, stdin, context';
    is unpack('N', substr($b, $off, 4)), 1, 'argc'; $off += 4;
    is_deeply [fields($b, \$off, 1)], ['a1'], 'args';
    is unpack('N', substr($b, $off, 4)), 3, 'field count'; $off += 4;
    is_deeply [fields($b, \$off, 6)],
        ['alpha', "caf\xc3\xa9 \xe2\x98\xba", 'b.pem', '', 'zeta', "z\0z"],
        'name/value pairs sorted by name, values UTF-8 encoded';
    is $off, length $b, 'nothing after the last field';
};

subtest 'a context alone (fields script, no input) is v2 with no fields' => sub {
    Exec::Agent::ExecClient::run(socket => $sock, script => 's', context => '{}');
    my $b = frame();
    is unpack('N', substr($b, 4, 4)), 0xCE0E0002, 'v2';
    is unpack('N', substr($b, -4)), 0, 'zero fields';
};

subtest 'a frame over the executor cap is refused here, not sent' => sub {
    unlink $cap;
    my $r = Exec::Agent::ExecClient::run(socket => $sock, script => 's', context => '{}',
        input => { a => 'x' x (16 * 1024 * 1024) });
    is $r->{exit}, -1, 'refused';
    like $r->{error}, qr/request too large for the executor \(\d+ bytes; the limit is 16777216\)/, 'says why';
    ok !-e $cap, 'nothing sent';
};

kill 'TERM', $spid;
waitpid $spid, 0;
done_testing;
