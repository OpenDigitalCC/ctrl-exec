#!/usr/bin/perl
# t/agent-doctor.t
#
# T-055: 'ctrl-exec-agent doctor'. Each check on a throwaway agent's files
# (AgentRig: its own CAs, certificates, map and agent.conf; no agent started):
# what it reports, at which severity, with which fix; the clean case reports
# nothing; --fix makes only its two changes (the old map upgraded in place, an
# unused CA removed from the bundle) and a second --fix changes nothing; the
# CLI's exit status, --json and log lines; unprivileged, it reports what it
# could not read instead of failing.

use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/../lib", "$Bin/lib";
use JSON qw(decode_json);

require AgentRig;
plan skip_all => 'openssl not available' unless AgentRig::available();

use Exec::Doctor              qw();
use Exec::Agent::Doctor       qw();
use Exec::Agent::Config       qw();
use Exec::Log                 qw();
use Exec::CertInfo            qw();

{
    no warnings 'redefine';
    *Exec::Log::log_action = sub { 1 };
}

sub slurp { open my $fh, '<', $_[0] or die "$_[0]: $!"; local $/; scalar <$fh> }
sub spew  { open my $fh, '>', $_[0] or die "$_[0]: $!"; print $fh $_[1]; close $fh }

sub script {
    my ($path) = @_;
    spew($path, "#!/bin/sh\necho ok\n");
    chmod 0755, $path;
    return $path;
}

# A rig whose directory stands in for root-owned directories (the ownership
# rule's test seam), with one executable script 'ok'.
sub rig {
    my (%o) = @_;
    my $rig = AgentRig->new(%o);
    @Exec::Agent::Config::TRUSTED_OWNERS = (0, $<);
    $Exec::Agent::Config::TRUSTED_TOP    = $rig->{dir};
    script("$rig->{dir}/ok.sh");
    spew($rig->{allow}, "ok = $rig->{dir}/ok.sh\n" . ($o{allowlist} // ''));
    return $rig;
}

sub run_checks {
    my ($rig) = @_;
    return Exec::Agent::Doctor::checks(config => $rig->{conf}, allowlist => $rig->{allow},
                                        listening => sub { 1 });
}

sub by_check {
    my ($findings, $check) = @_;
    return grep { $_->{check} eq $check } @$findings;
}

subtest 'a clean agent: nothing to report' => sub {
    my $rig = rig(second_ca => 1);
    my $f = run_checks($rig);
    is_deeply [ map { $_->{check} } @$f ], [], 'no findings' or diag explain $f;
    is Exec::Doctor::exit_status($f), 0, 'exit 0';
};

subtest 'scripts.conf: skipped, missing, not executable, unknown option and dispatcher, profiles' => sub {
    my $rig = rig(second_ca => 1, allowlist => join '',
        "rel = relative.sh\n",
        "gone = /nonexistent/gone.sh\n",
        "noexec = __DIR__/noexec.sh\n",
        "opt = __DIR__/ok.sh timeout=5\n",
        "lim = __DIR__/ok.sh dispatchers=nobody-here\n",
        "prof = __DIR__/ok.sh profile=special\n");
    my $d = $rig->{dir};
    spew($rig->{allow}, slurp($rig->{allow}) =~ s/__DIR__/$d/gr);
    spew("$d/noexec.sh", "#!/bin/sh\n");
    chmod 0644, "$d/noexec.sh";
    $rig->set_conf('', "[profile default]\n[profile special]\nrun_as = nobody\n");
    my $f = run_checks($rig);

    my ($s) = by_check($f, 'script-skipped');
    is $s->{severity}, 'problem', 'skipped entry: a problem';
    like $s->{what}, qr/'rel' is skipped and does not run: 'relative\.sh' is not an absolute path/,
        'names the entry and the reason';
    like $s->{fix}, qr/^correct the 'rel' line: sudoedit \S+scripts\.conf$/, 'fix: edit the line';

    my ($m) = by_check($f, 'script-missing');
    ok $m && $m->{severity} eq 'problem', 'missing script: a problem';
    like $m->{what}, qr{/nonexistent/gone\.sh does not exist}, 'names the path';

    my ($x) = by_check($f, 'script-not-executable');
    ok $x && $x->{severity} eq 'problem', 'not executable: a problem';
    is $x->{fix}, "sudo chmod +x $d/noexec.sh", 'fix: chmod +x';

    my ($o) = by_check($f, 'script-unknown-option');
    ok $o && $o->{severity} eq 'note', 'unknown option: a note';
    like $o->{what}, qr/'opt' has an unknown option 'timeout='/, 'names it';

    my ($u) = by_check($f, 'script-unknown-dispatcher');
    ok $u && $u->{severity} eq 'note', 'dispatchers= id not in the map: a note';
    like $u->{what}, qr/'lim' names dispatcher 'nobody-here'/, 'names the id';
    like $u->{fix}, qr/paired: d2, test-dispatcher/, 'lists the paired ids';

    my ($p) = by_check($f, 'profiles-not-applied');
    ok $p && $p->{severity} eq 'problem', 'a profile without the executor: a problem';
    like $p->{what}, qr/: prof\.$/, 'names the script';
    like $p->{fix}, qr/executor_socket = .*systemctl enable --now ctrl-exec-executor/, 'fix: the executor';
};

subtest 'the ownership rule: a note per reason under warn, a problem under strict' => sub {
    my $rig = rig(second_ca => 1);
    my $d = $rig->{dir};
    mkdir "$d/srv-scripts";
    script("$d/srv-scripts/$_.sh") for qw(a b);
    chmod 02775, "$d/srv-scripts";
    spew($rig->{allow}, "a = $d/srv-scripts/a.sh\nb = $d/srv-scripts/b.sh\n");
    my $f = run_checks($rig);
    my @n = by_check($f, 'script-ownership');
    is scalar @n, 1, 'one note for the shared reason';
    is $n[0]{severity}, 'note', 'a note, not a problem: the scripts run';
    like $n[0]{what}, qr/'\Q$d\E\/srv-scripts' is group-writable: 2 scripts run \(a, b\) with a warning/,
        'names the directory and both scripts';
    like $n[0]{what}, qr/script_ownership = strict would refuse them/, 'says what strict would do';
    like $n[0]{fix}, qr/^sudo chmod g-w \Q$d\E\/srv-scripts, once nobody needs to write there/,
        'fix: chmod g-w, not applied by doctor';
    ok !$n[0]{autofix}, 'not an automatic fix';
    is Exec::Doctor::exit_status($f), 0, 'notes only: exit 0';

    $rig->set_conf("script_ownership = strict\n");
    $f = run_checks($rig);
    my @s = by_check($f, 'script-skipped');
    is scalar @s, 2, 'strict: both skipped';
    is $s[0]{severity}, 'problem', 'a problem';
    like $s[0]{fix}, qr/^sudo chmod g-w \S+ \(or set script_ownership = warn/, 'fix: chmod, or warn';
};

subtest 'the executor socket set but nothing there' => sub {
    my $rig = rig(second_ca => 1);
    $rig->set_conf("executor_socket = $rig->{dir}/exec.sock\n");
    my ($e) = by_check(run_checks($rig), 'executor');
    ok $e && $e->{severity} eq 'problem', 'a problem';
    like $e->{what}, qr/the socket does not exist: \S+exec\.sock\): executor_socket is set, so every run fails/,
        'says why and what it means';
};

subtest 'agent.conf: unloadable, and not paired' => sub {
    my $rig = rig(second_ca => 1);
    spew($rig->{conf}, "port = x\n");
    my $f = run_checks($rig);
    is scalar @$f, 1, 'one finding: nothing else can be checked';
    is $f->[0]{check}, 'agent-conf', 'agent-conf';
    is $f->[0]{severity}, 'problem', 'a problem';

    $rig = rig(second_ca => 1);
    unlink "$rig->{dir}/agent.crt";
    $f = run_checks($rig);
    is_deeply [ map { $_->{check} } @$f ], ['not-paired'], 'not paired: a note, and no trust checks';
    like $f->[0]{fix}, qr/request-pairing --dispatcher/, 'fix: pair';
};

subtest 'an expired agent certificate' => sub {
    my $rig = rig(second_ca => 1);
    no warnings 'redefine';
    local *Exec::CertInfo::expiry_from_path = sub { 'Jan  1 00:00:00 2020 GMT' };
    my ($e) = by_check(run_checks($rig), 'agent-cert-expired');
    ok $e && $e->{severity} eq 'problem', 'a problem';
    like $e->{fix}, qr/request-pairing --dispatcher \S+ --rekey/, 'fix: re-key';
};

subtest 'an old-format map: upgraded by --fix, once' => sub {
    my $rig = rig();    # a one-CA rig with the pre-0.14 map line "3ea test-dispatcher"
    my $map = "$rig->{dir}/dispatchers";
    my $f = run_checks($rig);
    my ($o) = by_check($f, 'trust-map-old-format');
    ok $o && $o->{severity} eq 'note', 'reported as a note';
    like $o->{what}, qr/1 trusted-map line\(s\) in \S+ are in the pre-0\.14 form/, 'says what';
    ok $o->{autofix}, 'automatic with --fix';
    ok !by_check($f, 'trust-ca-unused'), 'no CA judged unused while old lines remain';

    Exec::Doctor::apply_fixes($f);
    ok $o->{fixed}, 'fixed';
    my $fpr = AgentRig::fingerprint("$rig->{dir}/ca.crt");
    like slurp($map), qr/^\Q$fpr\E 3ea test-dispatcher$/m, 'the line now carries its CA';
    my $after = slurp($map);
    my $f2 = run_checks($rig);
    is_deeply [ map { $_->{check} } @$f2 ], [], 'nothing left to report' or diag explain $f2;
    Exec::Doctor::apply_fixes($f2);
    is slurp($map), $after, 'a second --fix changes nothing';
};

subtest 'trust: a map CA missing from the bundle, an unused CA, none trusted' => sub {
    my $rig = rig(second_ca => 1);
    my $d   = $rig->{dir};
    my ($f1, $f2, $fr) = map { AgentRig::fingerprint("$d/$_.crt") } qw(ca ca2 rogue-ca);

    spew("$d/dispatchers", "$f1 3ea test-dispatcher\n$f2 7d2 d2\n$fr 99 gone\n");
    my ($m) = by_check(run_checks($rig), 'trust-ca-missing');
    ok $m && $m->{severity} eq 'problem', 'a map CA not in the bundle: a problem';
    like $m->{what}, qr/'gone' are trusted under CA SHA256:\Q$fr\E, which is not in/, 'names it';
    like $m->{fix}, qr/remove-dispatcher gone/, 'fix: re-pair or remove';

    spew("$d/dispatchers", "$f1 3ea test-dispatcher\n");
    my $f = run_checks($rig);
    my @u = by_check($f, 'trust-ca-unused');
    is scalar @u, 1, 'the CA no entry uses: one note';
    like $u[0]{what}, qr/CA SHA256:\Q$f2\E/, 'names ca2';
    is $u[0]{severity}, 'note', 'a note';
    Exec::Doctor::apply_fixes($f);
    ok $u[0]{fixed}, 'fixed by --fix';
    my $bundle = slurp($rig->{ca_file});
    is scalar(() = $bundle =~ /BEGIN CERTIFICATE/g), 1, 'ca2 is gone from the bundle';
    is AgentRig::fingerprint($rig->{ca_file}), $f1, 'ca (which issued the agent certificate) stays';
    my $f3 = run_checks($rig);
    is_deeply [ map { $_->{check} } @$f3 ], [], 'nothing left to report';
    Exec::Doctor::apply_fixes($f3);
    is slurp($rig->{ca_file}), $bundle, 'a second --fix changes nothing';

    spew("$d/dispatchers", "# empty\n");
    $f = run_checks($rig);
    ok by_check($f, 'trust-none'), 'no dispatcher: trust-none';
    ok !by_check($f, 'trust-ca-unused'), 'the last CA is never reported for removal';
};

subtest 'the agent certificate issued by a dispatcher no longer trusted' => sub {
    my $rig = rig(second_ca => 1);
    my $d   = $rig->{dir};
    my $f2  = AgentRig::fingerprint("$d/ca2.crt");
    spew("$d/dispatchers", "$f2 7d2 d2\n");    # test-dispatcher (ca) removed
    my $f = run_checks($rig);
    my ($i) = by_check($f, 'agent-cert-issuer-untrusted');
    ok $i, 'reported';
    is $i->{severity}, 'problem', 'expires within 30 days (the rig certificate lives 2 days): a problem';
    like $i->{what}, qr/expires on .*\(\d+ days\)/, 'says when';
    like $i->{fix}, qr/request-pairing --dispatcher \S+ --rekey/, 'fix: re-key';
    ok !by_check($f, 'trust-ca-unused'), 'its CA is not offered for removal';

    # The same with a certificate that has a year to run: a note.
    system("openssl x509 -req -in $d/agent.csr -CA $d/ca.crt -CAkey $d/ca.key -set_serial 1005"
         . " -out $d/agent.crt -days 400 -extfile $d/agent.ext 2>/dev/null") == 0 or die;
    ($i) = by_check(run_checks($rig), 'agent-cert-issuer-untrusted');
    is $i->{severity}, 'note', 'more than 30 days left: a note';
};

subtest 'revocations under every CA, with several CAs' => sub {
    my $rig = rig(second_ca => 1);
    spew("$rig->{dir}/revoked", "3EA\n");
    my ($r) = by_check(run_checks($rig), 'revoked-any-ca');
    ok $r && $r->{severity} eq 'note', 'a note';
    like $r->{what}, qr/1 line\(s\) in \S+ revoke a serial under every CA \(3ea;/, 'names the serial';

    my $one = rig();
    spew("$one->{dir}/revoked", "3EA\n");
    ok !by_check(run_checks($one), 'revoked-any-ca'), 'one CA: nothing to say';
};

# The CLI: ctrl-exec-agent doctor against the rig's files. stderr carries the
# log (NoSyslog), stdout the report.
sub cea {
    my ($rig, @args) = @_;
    my $err = "$rig->{dir}/stderr";
    my @cmd = ($^X, "-I$Bin/../lib", "-I$Bin/lib", '-MNoSyslog', "$Bin/../bin/ctrl-exec-agent",
               '--config', $rig->{conf}, '--allowlist', $rig->{allow}, @args);
    open my $p, '-|', "@cmd 2>$err" or die "run: $!";
    local $/;
    my $out = <$p> // '';
    close $p;
    return ($out, $? >> 8, slurp($err));
}

subtest 'CLI: exit status, report, log' => sub {
    my $rig = rig(second_ca => 1);
    my ($out, $rc, $log) = cea($rig, 'doctor');
    is $rc, 0, 'no problem: exit 0' or diag $out;
    like $out, qr/^ctrl-exec-agent doctor: no problems/m, 'summary line';

    spew($rig->{allow}, "gone = /nonexistent/x.sh\n");
    ($out, $rc, $log) = cea($rig, 'doctor');
    is $rc, 1, 'a problem: exit 1';
    like $out, qr/^PROBLEM  Script 'gone': \/nonexistent\/x\.sh does not exist.* Fix: /m, 'one line with its fix';
    like $log, qr/ACTION=doctor-finding CHECK=script-missing .*PROGRAM=ctrl-exec-agent SEVERITY=problem/,
        'logged';

    ($out, $rc) = cea($rig, 'doctor', 'extra');
    is $rc, 2, 'usage: exit 2';

    ($out, $rc) = cea($rig, 'doctor', '--json');
    is $rc, 1, '--json: same exit status';
    my $j = eval { decode_json($out) };
    ok $j, 'stdout is one JSON object' or diag $out;
    is $j->{problems}, 1, 'problems counted';
    is $j->{findings}[0]{check}, 'script-missing', 'the finding';

    ($out, $rc) = cea($rig, 'doctor', '--brief');
    unlike $out, qr/^note/m, '--brief: no notes listed';
};

subtest 'CLI: --fix, then again' => sub {
    my $rig = rig();    # old-format map
    my $map = "$rig->{dir}/dispatchers";
    my ($out, $rc) = cea($rig, 'doctor');
    like $out, qr/^note     1 trusted-map line/m, 'reported';
    like $out, qr/some can be fixed with: ctrl-exec-agent doctor --fix/, 'points at --fix';
    is slurp($map), "3ea test-dispatcher\n", 'report only: the map is untouched';

    ($out, $rc) = cea($rig, 'doctor', '--fix');
    like $out, qr/^fixed    1 trusted-map line/m, '--fix: listed as fixed';
    my $after = slurp($map);
    isnt $after, "3ea test-dispatcher\n", 'the map was upgraded';
    ($out, $rc) = cea($rig, 'doctor', '--fix');
    unlike $out, qr/^fixed/m, 'a second --fix fixes nothing';
    is slurp($map), $after, 'and changes nothing';
};

SKIP: {
    skip 'root reads every file', 1 unless $>;
    subtest 'unprivileged: what it cannot read is a note' => sub {
        my $rig = rig(second_ca => 1);
        chmod 0, $rig->{conf};
        my ($out, $rc) = cea($rig, 'doctor');
        is $rc, 0, 'exit 0: nothing found to be wrong';
        like $out, qr/^note     Could not read \S+agent\.conf \(permission denied\), so nothing else was checked\. Fix: sudo ctrl-exec-agent doctor$/m,
            'says what it could not check and how to';
        chmod 0600, $rig->{conf};
        chmod 0, $rig->{allow};
        my $f = run_checks($rig);
        my ($a) = by_check($f, 'access');
        like $a->{what}, qr/scripts\.conf.*scripts were not checked/, 'scripts.conf unreadable: a note';
        ok !grep({ $_->{severity} eq 'problem' } @$f), 'and no problem invented';
        chmod 0600, $rig->{allow};
    };
}

done_testing;
