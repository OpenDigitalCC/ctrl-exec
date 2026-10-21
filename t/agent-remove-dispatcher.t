#!/usr/bin/perl
# t/agent-remove-dispatcher.t
#
# T-064, on a real agent: 'ctrl-exec-agent remove-dispatcher <id>' withdraws one
# dispatcher. Its map entries go, its CA goes from the bundle unless another
# dispatcher is under it, the running agent is reloaded (so its connections are
# refused while the other dispatcher still runs), and the last dispatcher can go
# (the agent then serves no one and says so). 'list-dispatchers' shows who is
# trusted. An unknown id changes nothing and names the known ids.

use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/../lib", "$Bin/lib";

require AgentRig;
plan skip_all => 'openssl not available' unless AgentRig::available();

sub slurp {
    my ($path) = @_;
    open my $fh, '<', $path or die "read $path: $!";
    local $/;
    return scalar <$fh>;
}

sub spew {
    my ($path, $text) = @_;
    open my $fh, '>', $path or die "write $path: $!";
    print $fh $text;
    close $fh;
}

# Run ctrl-exec-agent <args> against the rig's files; returns (output with
# stderr merged, exit status). The rig agent's pid goes in a pid file so the
# command reloads it.
sub cea {
    my ($rig, @args) = @_;
    my $pf = "$rig->{dir}/agent.pid";
    spew($pf, ($rig->{pid} // 0) . "\n");
    my @cmd = ($^X, "-I$Bin/../lib", "-I$Bin/lib", '-MNoSyslog', "$Bin/../bin/ctrl-exec-agent",
               '--config', $rig->{conf}, '--allowlist', $rig->{allow}, '--pidfile', $pf, @args);
    open my $p, '-|', "@cmd 2>&1" or die "run: $!";
    local $/;
    my $out = <$p>;
    close $p;
    return ($out, $? >> 8);
}

sub ncerts { my $t = slurp($_[0]); return scalar(() = $t =~ /-----BEGIN CERTIFICATE-----/g) }

sub reloaded {
    my ($rig, $from) = @_;
    return $rig->wait_log(qr/ACTION=allowlist-reload/, 5, $from);
}

subtest 'removing one of two dispatchers, each with its own CA' => sub {
    my $rig = AgentRig->new(second_ca => 1);
    my $d   = $rig->{dir};
    my ($f1, $f2) = (AgentRig::fingerprint("$d/ca.crt"), AgentRig::fingerprint("$d/ca2.crt"));
    $rig->start or BAIL_OUT('rig agent did not start: ' . $rig->log_text);
    is $rig->request(as => 'trusted'), 200, 'dispatcher 1 runs';
    is $rig->request(as => 'd2'),      200, 'dispatcher 2 runs';

    my ($out, $rc) = cea($rig, 'list-dispatchers');
    is $rc, 0, 'list-dispatchers succeeds';
    is $out, "d2 $f2 7d2\ntest-dispatcher $f1 3ea issuer-of-agent-cert\n",
        'one line per id and CA: <id> <ca-fpr> <serials>, the agent certificate\'s issuer marked';

    my $from = $rig->log_len;
    ($out, $rc) = cea($rig, 'remove-dispatcher', 'd2');
    is $rc, 0, 'remove-dispatcher succeeds' or diag $out;
    like $out, qr/Removed dispatcher 'd2': 1 trusted-map entry/, 'says what went';
    like $out, qr/CA removed from \S+: \Q$f2\E/, 'names the CA removed from the bundle';
    like $out, qr/Reloaded the running agent \(SIGHUP to pid $rig->{pid}\)/, 'reloaded the agent';
    like $out, qr/restart/i, 'and says the listener needs a restart for the CA';
    like $out, qr/ACTION=remove-dispatcher CA=\Q$f2\E ENTRIES=1 ID=d2 RESULT=ok/, 'logged with the id and CA'
        or diag $out;

    unlike slurp("$d/dispatchers"), qr/ d2$/m, 'map entry gone';
    like   slurp("$d/dispatchers"), qr/^\Q$f1\E 3ea test-dispatcher$/m, 'the other entry stays';
    is ncerts($rig->{ca_file}), 1, 'bundle holds one CA';
    is AgentRig::fingerprint($rig->{ca_file}), $f1, 'and it is the other dispatcher\'s';

    ok reloaded($rig, $from), 'the agent reloaded';
    isnt $rig->request(as => 'd2') // 0, 200, 'dispatcher 2 is refused at once, on reload';
    is $rig->request(as => 'trusted'), 200, 'dispatcher 1 still runs';

    # After a restart the CA is gone from the listener too: no handshake.
    $rig->stop;
    $rig->start or BAIL_OUT('rig agent did not restart: ' . $rig->log_text);
    is $rig->request(as => 'd2'), undef, 'after a restart dispatcher 2 cannot even connect';
    is $rig->request(as => 'trusted'), 200, 'dispatcher 1 runs';
    $rig->stop;
};

subtest 'a CA used by two dispatchers stays until the last goes' => sub {
    my $rig = AgentRig->new(second_ca => 1);
    my $d   = $rig->{dir};
    my ($f1, $f2) = (AgentRig::fingerprint("$d/ca.crt"), AgentRig::fingerprint("$d/ca2.crt"));
    spew("$d/dispatchers", "$f1 3ea d1\n$f1 bbb d1b\n$f2 7d2 d2\n");

    my ($out, $rc) = cea($rig, 'remove-dispatcher', 'd1b');
    is $rc, 0, 'd1b removed' or diag $out;
    like $out, qr/CA kept in \S+ \(another dispatcher still uses it\): \Q$f1\E/, 'CA kept, said so';
    like $out, qr/No running agent found/, 'no agent running: told how to reload';
    is ncerts($rig->{ca_file}), 2, 'bundle unchanged';

    # The agent's own certificate is from the first CA, so that CA stays (below);
    # make d2's CA shared too and remove it last.
    ($out, $rc) = cea($rig, 'remove-dispatcher', 'd2');
    is $rc, 0, 'd2 removed' or diag $out;
    like $out, qr/CA removed from \S+: \Q$f2\E/, 'its CA, used by nobody else, goes';
    is ncerts($rig->{ca_file}), 1, 'bundle holds one CA';
    is AgentRig::fingerprint($rig->{ca_file}), $f1, 'the one still in use';
    like slurp("$d/dispatchers"), qr/^\Q$f1\E 3ea d1$/m, 'd1 still trusted';
};

subtest 'removing the last dispatcher' => sub {
    my $rig = AgentRig->new();      # one CA, a pre-0.14 map
    my $d   = $rig->{dir};
    my $f1  = AgentRig::fingerprint("$d/ca.crt");
    my $ca_before = slurp("$d/ca.crt");
    $rig->start or BAIL_OUT('rig agent did not start: ' . $rig->log_text);
    is $rig->request(as => 'trusted'), 200, 'it runs';

    my $from = $rig->log_len;
    my ($out, $rc) = cea($rig, 'remove-dispatcher', 'test-dispatcher');
    is $rc, 0, 'removed' or diag $out;
    like $out, qr/CA kept in \S+ \(it issued this agent's certificate\)/, 'its CA stays (it issued the agent certificate)';
    like $out, qr/No trusted dispatchers remain: the agent will start and answer, but refuse every caller/,
        'says the agent now serves no one';
    is slurp("$d/ca.crt"), $ca_before, 'ca.crt unchanged';
    ok reloaded($rig, $from), 'reloaded';
    isnt $rig->request(as => 'trusted') // 0, 200, 'its connection is refused';

    ($out, $rc) = cea($rig, 'list-dispatchers');
    is $out, '', 'list-dispatchers prints nothing';
    ($out, $rc) = cea($rig, 'self-check');
    like $out, qr/Dispatchers: NONE trusted - the agent starts but refuses every caller/,
        'self-check says so';

    $rig->stop;
    ok $rig->start, 'the agent starts with no trusted dispatcher' or diag $rig->log_text;
    isnt $rig->request(as => 'trusted') // 0, 200, 'and refuses the caller';
    ok $rig->alive, 'and stays up';
    $rig->stop;
};

subtest 'the last CA is kept when no agent certificate pins it' => sub {
    my $rig = AgentRig->new();
    my $d   = $rig->{dir};
    unlink "$d/agent.crt";
    my $before = slurp("$d/ca.crt");
    my ($out, $rc) = cea($rig, 'remove-dispatcher', 'test-dispatcher');
    is $rc, 0, 'removed' or diag $out;
    like $out, qr/CA kept in \S+ \(the last CA: the file is never left empty\)/, 'the last CA stays';
    is slurp("$d/ca.crt"), $before, 'ca.crt unchanged';
};

subtest 'an unknown id' => sub {
    my $rig = AgentRig->new(second_ca => 1);
    my $d   = $rig->{dir};
    my $map = slurp("$d/dispatchers");
    my $ca  = slurp($rig->{ca_file});
    my ($out, $rc) = cea($rig, 'remove-dispatcher', 'nope');
    isnt $rc, 0, 'exit is non-zero';
    like $out, qr/unknown dispatcher 'nope' \(known: d2, test-dispatcher\)/, 'names the known ids';
    is slurp("$d/dispatchers"), $map, 'map untouched';
    is slurp($rig->{ca_file}), $ca, 'bundle untouched';
    ($out, $rc) = cea($rig, 'remove-dispatcher');
    is $rc, 2, 'no id: usage, exit 2';
};

subtest 'the dispatcher that issued the agent certificate' => sub {
    my $rig = AgentRig->new(second_ca => 1);
    my $d   = $rig->{dir};
    my ($f1, $f2) = (AgentRig::fingerprint("$d/ca.crt"), AgentRig::fingerprint("$d/ca2.crt"));
    my $expiry = `openssl x509 -noout -enddate -in $d/agent.crt`;
    $rig->start or BAIL_OUT('rig agent did not start: ' . $rig->log_text);

    my ($out, $rc) = cea($rig, 'self-check');
    like $out, qr/Agent certificate issued by: test-dispatcher/, 'self-check names the issuer';

    my $from = $rig->log_len;
    ($out, $rc) = cea($rig, 'remove-dispatcher', 'test-dispatcher');
    is $rc, 0, 'removed' or diag $out;
    like $out, qr/CA kept in \S+ \(it issued this agent's certificate\): \Q$f1\E/, 'its CA is kept';
    like $out, qr/WARNING: This agent's certificate was issued by 'test-dispatcher', which can no longer renew it; it expires on \w{3} .*GMT.*request-pairing --dispatcher <host>/,
        'warns about renewal and expiry, and how to re-pair';
    like $out, qr/ACTION=remove-dispatcher .*REASON=agent-cert-issuer/s, 'and logs it';
    unlike $out, qr/CA removed from/, 'no CA left the bundle';
    is ncerts($rig->{ca_file}), 2, 'bundle unchanged';
    is system("openssl verify -CAfile $rig->{ca_file} $d/agent.crt >/dev/null 2>&1"), 0,
        'ca.crt still verifies the agent certificate';

    ok reloaded($rig, $from), 'reloaded';
    isnt $rig->request(as => 'trusted') // 0, 200, 'the removed dispatcher is refused';
    is $rig->request(as => 'd2'), 200, 'the other still runs';
    ($out, $rc) = cea($rig, 'self-ping');
    is $rc, 0, 'self-ping still works' or diag $out;
    ($out, $rc) = cea($rig, 'list-dispatchers');
    is $out, "d2 $f2 7d2\n", 'list-dispatchers: only d2, not marked';
    $rig->stop;
};

done_testing;
