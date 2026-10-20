#!/usr/bin/perl
# Shared conformance test: the C executor (ctrl-exec-executor) and the Perl front-end
# (Exec::Agent::Config) must derive the IDENTICAL security decision for the same
# agent.conf/scripts.conf - same allow/deny, same resolved profile fields. If
# they ever diverge, the executor would apply a different privilege than the
# front-end authorised. Both parsers are exercised here against the same fixtures.
#
# Not compared, by design: front-end-only validation the executor has no use for
# (required keys port/cert/key/ca, numeric port, allowed_ips, rate_limit_*,
# auth_hook). The corpus below is the parity gate: a change to either parser that
# alters any listed case makes this test fail.
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use FindBin    qw($Bin);
use lib "$Bin/../lib";

use Exec::Agent::Config qw();

my $cc = `command -v gcc 2>/dev/null`; chomp $cc;
plan skip_all => 'gcc not available' unless $cc && -x $cc;

my $TMP = tempdir(CLEANUP => 1);
my $BIN = "$TMP/ctrl-exec-executor";
system($cc, '-O2', '-o', $BIN, "$Bin/../src/ctrl-exec-executor.c", '-lcap') == 0
    or plan skip_all => 'could not compile src/ctrl-exec-executor.c';

my $REQUIRED = "port = 7443\ncert = /x\nkey = /y\nca = /z\n";
my $n = 0;
sub wf { my ($body) = @_; my $p = "$TMP/f." . (++$n);
    open my $f, '>', $p or die $!; print $f $body; close $f; return $p }

# The C decision: stdout line, or CONFIG-ERROR on exit 2.
sub c_resolve {
    my ($a, $s, $name) = @_;
    my $out = `\Q$BIN\E resolve \Q$a\E \Q$s\E \Q$name\E 2>/dev/null`;
    return 'CONFIG-ERROR' if ($? >> 8) == 2;
    chomp $out;
    return $out;
}

# The Perl decision, formatted into the same canonical line as the C resolve.
sub perl_resolve {
    my ($a, $s, $name) = @_;
    local $SIG{__WARN__} = sub {};
    my $config = eval { Exec::Agent::Config::load_config($a) };
    return 'CONFIG-ERROR' if $@;
    # No script_dirs here so out-of-dir entries are still present; validate_script
    # applies the dir check below, mirroring the C (find then dir-check).
    my $al = Exec::Agent::Config::load_allowlist($s);
    return "DENY not-allowlisted" unless exists $al->{$name};
    my $path = Exec::Agent::Config::validate_script($name, $al, $config->{script_dirs});
    return "DENY not-in-script-dirs" unless defined $path;
    my $prof = Exec::Agent::Config::script_profile($name, $al);
    # Every profile - including 'default' - must be defined; no built-in fallback.
    return "DENY undefined-profile" unless exists $config->{profiles}{$prof};
    my $p = $config->{profiles}{$prof};
    my $runas = $p->{run_as} // '';
    my $nnp   = $p->{no_new_privileges} // 1;
    my $caps  = join(',', @{ $p->{caps}     // [] });
    my $writ  = join(':', @{ $p->{writable} // [] });
    return "OK path=$path|profile=$prof|run_as=$runas|nnp=$nnp|caps=$caps|writable=$writ";
}

# --- fixtures: each names the scripts to resolve against one config pair -------

my @fixtures = (
    {
        label   => 'default + defined profile + order-independent profile=',
        agent   => $REQUIRED . "script_dirs = /opt/s\n"
                 . "[profile cert-deploy]\nrun_as = root\ncaps = CAP_CHOWN, CAP_KILL\n"
                 . "writable = /etc/ssl:/srv/certificates\n",
        scripts => "status      = /opt/s/status.sh\n"
                 . "deploy-cert = /opt/s/deploy.sh profile=cert-deploy\n"
                 . "before      = profile=cert-deploy /opt/s/b.sh\n"
                 . "outside     = /elsewhere/x.sh\n"
                 . "ghost       = /opt/s/g.sh profile=nope\n"
                 . "relative    = opt/s/rel.sh\n",
        names   => [qw(status deploy-cert before outside ghost relative missing)],
    },
    {
        label   => 'no script_dirs => no dir restriction',
        agent   => $REQUIRED . "[profile p]\nrun_as = www-data\n",
        scripts => "anywhere = /var/tmp/a.sh profile=p\n",
        names   => [qw(anywhere)],
    },
    {
        label   => 'explicit [profile default] override + nnp off',
        agent   => $REQUIRED . "[profile default]\nrun_as = nobody\nno_new_privileges = no\n",
        scripts => "x = /opt/x.sh\n",
        names   => [qw(x)],
    },
    {
        label   => 'two paths on a line => skipped (not-allowlisted)',
        agent   => $REQUIRED,
        scripts => "bad = /opt/a.sh /opt/b.sh\ngood = /opt/g.sh\n",
        names   => [qw(bad good)],
    },
    {
        label   => 'config error: invalid capability (both must reject)',
        agent   => $REQUIRED . "[profile x]\ncaps = NOTCAP\n",
        scripts => "s = /opt/s.sh profile=x\n",
        names   => [qw(s)],
    },
    {
        label   => 'config error: out-of-range numeric run_as (both must reject)',
        agent   => $REQUIRED . "[profile big]\nrun_as = 99999999999999999999\n",
        scripts => "s = /opt/s.sh profile=big\n",
        names   => [qw(s)],
    },
    {
        label   => 'whole-line comments + mixed comma/space cap separators agree',
        agent   => $REQUIRED . "script_dirs = /opt/s\n"
                 . "# a comment line in agent.conf\n"
                 . "[profile mixed]\n"
                 . "run_as = www-data\n"
                 . "caps = CAP_CHOWN,CAP_KILL CAP_SETUID\n"
                 . "no_new_privileges = yes\n",
        scripts => "# a comment line in scripts.conf\n"
                 . "s = /opt/s/s.sh profile=mixed\n",
        names   => [qw(s)],
    },
);

# --- T-031 corpus: every edge the two parsers must agree on -------------------
# Grouped by the surface they exercise. Each fixture compares the C `resolve`
# line with the Perl one for every listed script name.
my $LONG = '/opt/' . ('d' x 5000) . '/x.sh';

push @fixtures, (
    # -- scripts.conf: comments, blanks, whitespace -----------------------------
    {
        label   => 'scripts: inline # after a path makes extra tokens => skipped',
        expect  => { a => 'DENY not-allowlisted', c => 'OK', d => 'DENY not-allowlisted' },
        agent   => $REQUIRED . "[profile default]\nrun_as = nobody\n",
        scripts => "a = /opt/a.sh # note\nb = /opt/b.sh profile=default # note\n"
                 . "c = /opt/c.sh#note\nd = /opt/d.sh #\n",
        names   => [qw(a b c d)],
    },
    {
        label   => 'scripts: blank lines, indented comment, tabs, no space round =',
        agent   => $REQUIRED . "[profile default]\nrun_as = nobody\n",
        scripts => "\n   \n\t# indented comment\n  t1\t=\t/opt/t1.sh\t\n"
                 . "t2=/opt/t2.sh\n   t3   =   /opt/t3.sh   profile=default   \n",
        names   => [qw(t1 t2 t3)],
    },
    {
        label   => 'scripts: CRLF line endings',
        expect  => { w => 'OK path=/opt/w.sh', v => 'OK path=/opt/v.sh|profile=default' },
        agent   => $REQUIRED . "[profile default]\nrun_as = nobody\n",
        scripts => "w = /opt/w.sh\r\nv = /opt/v.sh profile=default\r\n",
        names   => [qw(w v)],
    },
    {
        label   => 'scripts: no path, empty value, no = , annotation-only',
        agent   => $REQUIRED,
        scripts => "nopath = profile=default\nempty =\nnoeq /opt/n.sh\n"
                 . "ok = /opt/ok.sh\n",
        names   => [qw(nopath empty noeq ok)],
    },
    # -- scripts.conf: path rules ----------------------------------------------
    {
        label   => 'scripts: relative paths skipped (bare, ./, ../, after annotation)',
        agent   => $REQUIRED,
        scripts => "r1 = rel.sh\nr2 = ./rel.sh\nr3 = ../rel.sh\n"
                 . "r4 = profile=default rel.sh\nr5 = ~/x.sh\n",
        names   => [qw(r1 r2 r3 r4 r5)],
    },
    {
        label   => 'scripts: two paths skipped wherever the annotation sits',
        agent   => $REQUIRED,
        scripts => "p1 = /a.sh /b.sh profile=default\np2 = profile=default /a.sh /b.sh\n"
                 . "p3 = /a.sh profile=default /b.sh\np4 = /a.sh rel.sh\np5 = rel.sh /a.sh\n",
        names   => [qw(p1 p2 p3 p4 p5)],
    },
    {
        label   => 'scripts: profile= placement, repeats, empty, odd annotations',
        expect  => { l => 'OK path=/opt/l.sh|profile=a', r => 'OK path=/opt/r.sh|profile=a', rep => 'OK path=/opt/rep.sh|profile=b', emp => 'DENY undefined-profile', unk => 'OK path=/opt/unk.sh|profile=a', upper => 'DENY not-allowlisted' },
        agent   => $REQUIRED . "[profile a]\nrun_as = nobody\n[profile b]\nrun_as = root\n",
        scripts => "l = profile=a /opt/l.sh\nr = /opt/r.sh profile=a\n"
                 . "rep = /opt/rep.sh profile=a profile=b\nrep2 = profile=b /opt/rep2.sh profile=a\n"
                 . "emp = /opt/emp.sh profile=\nunk = /opt/unk.sh timeout=5 schema=x profile=a\n"
                 . "upper = /opt/up.sh Profile=a\nnum = /opt/num.sh profile1=a\n"
                 . "eqpath = /opt/a=b.sh profile=a\neqlead = =x /opt/q.sh\n"
                 . "keyonly = /opt/k.sh profile\n",
        names   => [qw(l r rep rep2 emp unk upper num eqpath eqlead keyonly)],
    },
    {
        label   => 'scripts: script_dirs boundary (prefix, trailing slash, dots)',
        expect  => { in => 'OK', sib => 'DENY not-in-script-dirs', second => 'OK', out => 'DENY not-in-script-dirs' },
        agent   => $REQUIRED . "script_dirs = /opt/s/:/srv/x\n[profile default]\nrun_as = nobody\n",
        scripts => "in = /opt/s/a.sh\nsib = /opt/sx/a.sh\nexact = /opt/s\n"
                 . "second = /srv/x/y/z.sh\ndots = /opt/s/../evil.sh\nout = /etc/passwd\n",
        names   => [qw(in sib exact second dots out)],
    },
    {
        label   => 'script_dirs: only separators => no restriction',
        expect  => { a => 'DENY not-in-script-dirs' },
        agent   => $REQUIRED . "script_dirs = :::\n[profile default]\nrun_as = nobody\n",
        scripts => "a = /anywhere/a.sh\n",
        names   => [qw(a)],
    },
    {
        label   => 'script_dirs: empty fields between real dirs',
        agent   => $REQUIRED . "script_dirs = :/opt/s::/srv/x:\n[profile default]\nrun_as = nobody\n",
        scripts => "a = /opt/s/a.sh\nb = /srv/x/b.sh\nc = /tmp/c.sh\n",
        names   => [qw(a b c)],
    },
    {
        label   => 'scripts: very long path line (5000 chars)',
        expect  => { long => 'DENY not-allowlisted', after => 'OK' },
        agent   => $REQUIRED . "[profile default]\nrun_as = nobody\n",
        scripts => "long = $LONG\nafter = /opt/after.sh\n",
        names   => [qw(long after)],
    },
    {
        label   => 'scripts: name lookups case, hyphen, underscore, dot',
        expect  => { 'My-Script_2' => 'OK', 'my-script_2' => 'DENY not-allowlisted', 'my.dot' => 'DENY not-allowlisted' },
        agent   => $REQUIRED . "[profile default]\nrun_as = nobody\n",
        scripts => "My-Script_2 = /opt/m.sh\nmy.dot = /opt/dot.sh\n",
        names   => ['My-Script_2', 'my-script_2', 'my.dot'],
    },
    # -- scripts.conf: duplicate names -----------------------------------------
    {
        label   => 'scripts: duplicate names, both valid',
        expect  => { dup => 'OK path=/opt/second.sh|profile=b' },
        agent   => $REQUIRED . "[profile default]\nrun_as = nobody\n[profile b]\nrun_as = root\n",
        scripts => "dup = /opt/first.sh\ndup = /opt/second.sh profile=b\n",
        names   => [qw(dup)],
    },
    {
        label   => 'scripts: duplicate names, first skipped (two paths), second valid',
        expect  => { dup => 'OK path=/opt/second.sh' },
        agent   => $REQUIRED . "[profile default]\nrun_as = nobody\n",
        scripts => "dup = /opt/a.sh /opt/b.sh\ndup = /opt/second.sh\n",
        names   => [qw(dup)],
    },
    {
        label   => 'scripts: duplicate names, first valid, second skipped (relative)',
        expect  => { dup => 'OK path=/opt/first.sh' },
        agent   => $REQUIRED . "[profile default]\nrun_as = nobody\n",
        scripts => "dup = /opt/first.sh\ndup = rel.sh\n",
        names   => [qw(dup)],
    },
    # -- agent.conf: comments, whitespace, sections ----------------------------
    {
        label   => 'agent: inline # becomes part of the value (run_as invalid)',
        expect  => { s => 'CONFIG-ERROR' },
        agent   => $REQUIRED . "[profile p]\nrun_as = root # because\n",
        scripts => "s = /opt/s.sh profile=p\n",
        names   => [qw(s)],
    },
    {
        label   => 'agent: inline # in caps is an invalid capability',
        agent   => $REQUIRED . "[profile p]\ncaps = CAP_CHOWN # why\n",
        scripts => "s = /opt/s.sh profile=p\n",
        names   => [qw(s)],
    },
    {
        label   => 'agent: inline # in writable stays in the path',
        expect  => { s => 'OK path=/opt/s.sh|profile=p|run_as=|nnp=1|caps=|writable=/var/lib/x # data' },
        agent   => $REQUIRED . "[profile p]\nwritable = /var/lib/x # data\n",
        scripts => "s = /opt/s.sh profile=p\n",
        names   => [qw(s)],
    },
    {
        label   => 'agent: inline # in no_new_privileges is not a true value',
        expect  => { s => 'OK path=/opt/s.sh|profile=p|run_as=|nnp=0' },
        agent   => $REQUIRED . "[profile p]\nno_new_privileges = yes # ok\n",
        scripts => "s = /opt/s.sh profile=p\n",
        names   => [qw(s)],
    },
    {
        label   => 'agent: inline # in script_dirs is part of the dir',
        expect  => { a => 'DENY not-in-script-dirs' },
        agent   => $REQUIRED . "script_dirs = /opt/s # dirs\n[profile default]\nrun_as = nobody\n",
        scripts => "a = /opt/s/a.sh\n",
        names   => [qw(a)],
    },
    {
        label   => 'agent: blank lines, tabs and spacing round = and in headers',
        expect  => { s => 'OK path=/opt/s.sh|profile=sp|run_as=www-data|nnp=1|caps=CAP_KILL|writable=/a:/b' },
        agent   => $REQUIRED . "\n\n   \n\t[ profile   sp ]\t\n\trun_as\t=\t  www-data  \n"
                 . "  caps=CAP_KILL\n   writable   =   /a:/b   \n",
        scripts => "s = /opt/s.sh profile=sp\n",
        names   => [qw(s)],
    },
    {
        label   => 'agent: CRLF line endings',
        expect  => { s => 'OK path=/opt/s.sh|profile=p|run_as=www-data|nnp=0|caps=CAP_KILL' },
        agent   => "port = 7443\r\ncert = /x\r\nkey = /y\r\nca = /z\r\n"
                 . "[profile p]\r\nrun_as = www-data\r\ncaps = CAP_KILL\r\n"
                 . "no_new_privileges = no\r\n",
        scripts => "s = /opt/s.sh profile=p\n",
        names   => [qw(s)],
    },
    {
        label   => 'agent: unknown keys (top level, profile, other sections) ignored',
        expect  => { s => 'OK path=/opt/s.sh|profile=p|run_as=nobody' },
        agent   => $REQUIRED . "colour = blue\n[tags]\nrole = web\nscript_dirs = /nowhere\n"
                 . "[other]\nrun_as = root\n[profile p]\nfuture_key = 1\nrun_as = nobody\n",
        scripts => "s = /opt/s.sh profile=p\n",
        names   => [qw(s)],
    },
    {
        label   => 'agent: profile keys after a switch to [tags] go to tags only',
        agent   => $REQUIRED . "[profile p]\nrun_as = nobody\n[tags]\ncaps = CAP_KILL\n",
        scripts => "s = /opt/s.sh profile=p\n",
        names   => [qw(s)],
    },
    {
        label   => 'agent: profile blocks repeated merge, later keys win',
        expect  => { s => 'OK path=/opt/s.sh|profile=p|run_as=www-data|nnp=1|caps=CAP_KILL|writable=/b' },
        agent   => $REQUIRED . "[profile p]\nrun_as = root\ncaps = CAP_KILL\nwritable = /a\n"
                 . "[profile q]\nrun_as = nobody\n"
                 . "[profile p]\nrun_as = www-data\nwritable = /b\n",
        scripts => "s = /opt/s.sh profile=p\n",
        names   => [qw(s)],
    },
    {
        label   => 'agent: repeated key inside a profile, last wins',
        agent   => $REQUIRED . "[profile p]\nrun_as = root\nrun_as = nobody\ncaps = CAP_KILL\ncaps = CAP_CHOWN\n",
        scripts => "s = /opt/s.sh profile=p\n",
        names   => [qw(s)],
    },
    {
        label   => 'agent: profile names (hyphen, dot, underscore, case-sensitive)',
        agent   => $REQUIRED . "[profile a-b]\nrun_as = nobody\n[profile a.b]\nrun_as = root\n"
                 . "[profile A_B]\nrun_as = www-data\n",
        scripts => "h = /opt/h.sh profile=a-b\nd = /opt/d.sh profile=a.b\n"
                 . "u = /opt/u.sh profile=A_B\nl = /opt/l.sh profile=a_b\n",
        names   => [qw(h d u l)],
    },
    {
        label   => 'agent: section keyword case ([PROFILE x])',
        expect  => { s => 'OK path=/opt/s.sh|profile=x|run_as=nobody' },
        agent   => $REQUIRED . "[PROFILE x]\nrun_as = nobody\n",
        scripts => "s = /opt/s.sh profile=x\n",
        names   => [qw(s)],
    },
    {
        label   => 'agent: empty profile block gets all defaults',
        agent   => $REQUIRED . "[profile empty]\n",
        scripts => "s = /opt/s.sh profile=empty\n",
        names   => [qw(s)],
    },
    {
        label   => 'agent: profile header without a name (both must reject)',
        agent   => $REQUIRED . "[profile]\nrun_as = root\n",
        scripts => "s = /opt/s.sh\n",
        names   => [qw(s)],
    },
    {
        label   => 'agent: undefined profile and default profile',
        agent   => $REQUIRED . "[profile only]\nrun_as = nobody\n",
        scripts => "d = /opt/d.sh\nu = /opt/u.sh profile=default\nx = /opt/x.sh profile=only\n"
                 . "n = /opt/n.sh profile=Only\n",
        names   => [qw(d u x n)],
    },
    {
        label   => 'agent: default profile defined => unannotated scripts use it',
        agent   => $REQUIRED . "[profile default]\nrun_as = 65534\ncaps = CAP_NET_BIND_SERVICE\nwritable = /var/lib/d/\n",
        scripts => "d = /opt/d.sh\n",
        names   => [qw(d)],
    },
    # -- run_as -----------------------------------------------------------------
    (map { my ($lbl, $v) = @$_; +{
        label   => "run_as: $lbl",
        agent   => $REQUIRED . "[profile p]\nrun_as = $v\n",
        scripts => "s = /opt/s.sh profile=p\n",
        names   => [qw(s)],
    } } (
        ['name', 'www-data'], ['leading underscore name', '_apt'], ['digits-in-name', 'user1'],
        ['numeric 0', '0'], ['numeric 1000', '1000'], ['leading zeros', '0000000000000000000000042'],
        ['uid_t max 4294967295', '4294967295'], ['uid_t max + 1 4294967296', '4294967296'],
        ['2^63', '9223372036854775808'], ['2^64', '18446744073709551616'],
        ['2^64 - 1', '18446744073709551615'], ['65 digits', '9' x 65],
        ['name starting with digit', '1abc'], ['name with dot', 'a.b'], ['negative', '-1'],
        ['plus sign', '+5'], ['hex', '0x10'], ['name with space', 'a b'],
        ['name with colon', 'a:b'], ['hyphen first', '-abc'], ['trailing hyphen', 'abc-'],
        ['uppercase name', 'Root'], ['dollar', 'a$'], ['very long name (200)', 'a' x 200],
    )),
    {
        label   => 'run_as: second profile with empty value',
        agent   => $REQUIRED . "[profile p]\nrun_as = root\n[profile q]\nrun_as =\n",
        scripts => "s = /opt/s.sh profile=q\n",
        names   => [qw(s)],
    },
    # -- caps -------------------------------------------------------------------
    (map { my ($lbl, $v) = @$_; +{
        label   => "caps: $lbl",
        agent   => $REQUIRED . "[profile p]\ncaps = $v\n",
        scripts => "s = /opt/s.sh profile=p\n",
        names   => [qw(s)],
    } } (
        ['single', 'CAP_CHOWN'], ['commas no space', 'CAP_CHOWN,CAP_KILL'],
        ['spaces only', 'CAP_CHOWN CAP_KILL'], ['tabs', "CAP_CHOWN\tCAP_KILL"],
        ['comma+space', 'CAP_CHOWN, CAP_KILL'], ['leading/trailing commas', ',CAP_CHOWN,'],
        ['double commas', 'CAP_CHOWN,,CAP_KILL'], ['only separators', ', ,'],
        ['unknown but well-formed CAP_NOPE', 'CAP_NOPE'], ['digits CAP_X86', 'CAP_X86_64'],
        ['lowercase', 'cap_chown'], ['mixed case', 'CAP_Chown'], ['bare CAP_', 'CAP_'],
        ['no prefix', 'CHOWN'], ['semicolon separator', 'CAP_CHOWN;CAP_KILL'],
        ['colon separator', 'CAP_CHOWN:CAP_KILL'], ['duplicates', 'CAP_KILL CAP_KILL'],
        ['hyphen in name', 'CAP_A-B'], ['31 caps', join(' ', map {"CAP_C$_"} 1..31)],
        ['32 caps', join(' ', map {"CAP_C$_"} 1..32)], ['33 caps', join(' ', map {"CAP_C$_"} 1..33)],
        ['long cap name (200)', 'CAP_' . ('A' x 196)],
    )),
    # -- writable ---------------------------------------------------------------
    (map { my ($lbl, $v) = @$_; +{
        label   => "writable: $lbl",
        agent   => $REQUIRED . "[profile p]\nwritable = $v\n",
        scripts => "s = /opt/s.sh profile=p\n",
        names   => [qw(s)],
    } } (
        ['single', '/var/lib/x'], ['trailing slash', '/var/lib/x/'], ['root', '/'],
        ['several', '/a:/b/:/c'], ['empty fields', '/a::/b:'], ['leading colon', ':/a'],
        ['only colons', ':::'], ['relative', 'var/lib/x'], ['relative second', '/a:b'],
        ['dot-relative', './x'], ['dotdot', '/a/../b'], ['comma is not a separator', '/a,/b'],
        ['space inside', '/a b'], ['32 paths', join(':', map {"/p$_"} 1..32)],
        ['33 paths', join(':', map {"/p$_"} 1..33)], ['long path (5000)', '/' . ('w' x 5000)],
    )),
    # -- no_new_privileges ------------------------------------------------------
    (map { my ($lbl, $v) = @$_; +{
        label   => "no_new_privileges: $lbl",
        agent   => $REQUIRED . "[profile p]\nno_new_privileges = $v\n",
        scripts => "s = /opt/s.sh profile=p\n",
        names   => [qw(s)],
    } } (
        (map { [$_, $_] } qw(1 0 y n yes no true false on off YES Yes TRUE On Y maybe 2 enabled 10)),
    )),
    {
        label   => 'no_new_privileges: absent => on',
        agent   => $REQUIRED . "[profile p]\nrun_as = nobody\n",
        scripts => "s = /opt/s.sh profile=p\n",
        names   => [qw(s)],
    },
);

# --- malformed lines and unusual bytes ----------------------------------------
# Perl croaks on a line that is neither a header, a comment nor key = value; the
# C parser must reject the same lines (else the executor would load a file the
# front end refused).
push @fixtures, (
    (map { my ($lbl, $body) = @$_; +{
        label   => "agent malformed: $lbl",
        agent   => $REQUIRED . $body,
        scripts => "s = /opt/s.sh profile=p\n",
        names   => [qw(s)],
    } } (
        ['line without =',                    "[profile p]\nrun_as nobody\n"],
        ['top-level line without =',          "orphan\n[profile p]\nrun_as = nobody\n"],
        ['key with a dot',                    "[profile p]\nrun.as = nobody\n"],
        ['key starting with hyphen',          "[profile p]\n-x = 1\n"],
        ['key with hyphen inside',            "[profile p]\nfuture-key = 1\nrun_as = nobody\n"],
        ['empty value, no trailing space',    "[profile p]\ncaps =\n"],
        ['empty value, trailing space',       "[profile p]\ncaps = \n"],
        ['blank-valued no_new_privileges',    "[profile p]\nno_new_privileges = \n"],
        ['empty script_dirs value',           "script_dirs =\n[profile p]\nrun_as = nobody\n"],
        ['unterminated header',               "[profile p\nrun_as = nobody\n"],
        ['header with extra word',            "[profile a b]\nrun_as = nobody\n"],
        ['header with junk after ]',          "[profile p] junk\nrun_as = nobody\n"],
        ['header with double ]',              "[profile p]]\nrun_as = nobody\n"],
        ['empty header',                      "[]\n[profile p]\nrun_as = nobody\n"],
        ['blank header',                      "[ ]\n[profile p]\nrun_as = nobody\n"],
        ['header name with hyphen',           "[a-b]\n[profile p]\nrun_as = nobody\n"],
        ['header three words',                "[a b c]\n[profile p]\nrun_as = nobody\n"],
        ['profile name with odd char',        "[profile p\@q]\nrun_as = nobody\n"],
        ['profile name with slash',           "[profile a/b]\nrun_as = nobody\n"],
        ['padded header',                     "  [ profile\tp ]  \nrun_as = nobody\n"],
        ['section named tags with sub name',  "[tags x]\nrole = web\n[profile p]\nrun_as = nobody\n"],
        ['= inside a value',                  "[profile p]\nwritable = /a=b\nrun_as = nobody\n"],
        ['leading = (no key)',                "[profile p]\n= nobody\n"],
        ['NUL byte inside a value',           "[profile p]\nrun_as = no\0body\n"],
        ['vertical tab between caps',         "[profile p]\ncaps = CAP_CHOWN\x0bCAP_KILL\n"],
        ['form feed between caps',            "[profile p]\ncaps = CAP_CHOWN\x0cCAP_KILL\n"],
        ['carriage return between caps',      "[profile p]\ncaps = CAP_CHOWN\rCAP_KILL\n"],
        ['UTF-8 in run_as',                   "[profile p]\nrun_as = caf\xc3\xa9\n"],
        ['UTF-8 in profile name',             "[profile caf\xc3\xa9]\nrun_as = nobody\n"],
        ['UTF-8 in writable path',            "[profile p]\nwritable = /srv/caf\xc3\xa9\n"],
        ['UTF-8 in key',                      "[profile p]\ncaf\xc3\xa9 = 1\nrun_as = nobody\n"],
        ['256-char profile name',             "[profile " . ('p' x 256) . "]\nrun_as = nobody\n"],
        ['128-char profile name',             "[profile " . ('p' x 128) . "]\nrun_as = nobody\n"],
        ['127-char profile name',             "[profile " . ('p' x 127) . "]\nrun_as = nobody\n"],
        ['65 profiles',                       join('', map {"[profile q$_]\nrun_as = nobody\n"} 1..65) . "[profile p]\nrun_as = nobody\n"],
        ['64 profiles',                       join('', map {"[profile q$_]\nrun_as = nobody\n"} 1..63) . "[profile p]\nrun_as = nobody\n"],
        ['33 script_dirs',                    "script_dirs = " . join(':', map {"/d$_"} 1..33) . "\n[profile p]\nrun_as = nobody\n"],
        ['32 script_dirs',                    "script_dirs = " . join(':', map {"/d$_"} 1..32) . "\n[profile p]\nrun_as = nobody\n"],
        ['script_dirs entry 5000 chars',      "script_dirs = /" . ('x' x 5000) . "\n[profile p]\nrun_as = nobody\n"],
        ['very long ignored value line',      "colour = " . ('z' x 100000) . "\n[profile p]\nrun_as = nobody\n"],
        ['top-level key named profiles',      "profiles = x\n[profile p]\nrun_as = nobody\n"],
        ['top-level key named tags',          "tags = x\n[tags]\nrole = web\n[profile p]\nrun_as = nobody\n"],
        ['very long unknown profile value',   "[profile p]\nrun_as = nobody\nfuture = " . ('z' x 100000) . "\n"],
    )),
    (map { my ($lbl, $body) = @$_; +{
        label   => "scripts malformed: $lbl",
        agent   => $REQUIRED . "[profile default]\nrun_as = nobody\n[profile p]\nrun_as = root\n",
        scripts => $body,
        names   => [qw(s)],
    } } (
        ['vertical tab between path and annotation', "s = /opt/s.sh\x0bprofile=p\n"],
        ['form feed between two paths',              "s = /opt/a.sh\x0c/opt/b.sh\n"],
        ['NUL inside path',                          "s = /opt/a\0b.sh\n"],
        ['UTF-8 in path',                            "s = /opt/caf\xc3\xa9.sh\n"],
        ['UTF-8 in profile annotation',              "s = /opt/s.sh profile=caf\xc3\xa9\n"],
        ['path 4095 chars',                          "s = /" . ('a' x 4094) . "\n"],
        ['path 4096 chars',                          "s = /" . ('a' x 4095) . "\n"],
        ['path 4097 chars',                          "s = /" . ('a' x 4096) . "\n"],
        ['profile annotation 127 chars',             "s = /opt/s.sh profile=" . ('p' x 127) . "\n"],
        ['profile annotation 128 chars',             "s = /opt/s.sh profile=" . ('p' x 128) . "\n"],
        ['profile annotation 5000 chars',            "s = /opt/s.sh profile=" . ('p' x 5000) . "\n"],
        ['name 5000 chars',                          ('n' x 5000) . " = /opt/s.sh\n"],
        ['line 100000 chars of trailing space',      "s = /opt/s.sh" . (' ' x 100000) . "\n"],
        ['last line without newline',                "s = /opt/s.sh"],
        ['comment last line without newline',        "s = /opt/s.sh\n# trailing"],
        ['equals only',                              "=\ns = /opt/s.sh\n"],
        ['value is only =',                          "s = =\n"],
        ['annotation key with digit',                "s = /opt/s.sh profile2=p\n"],
        ['two = in one token path',                  "s = /opt/x=y=z.sh profile=p\n"],
        ['dir path with spaces split => two paths',  "s = /opt/my dir/s.sh\n"],
    )),
);

for my $fx (@fixtures) {
    my $a = wf($fx->{agent});
    my $s = wf($fx->{scripts});
    subtest $fx->{label} => sub {
        for my $name (@{ $fx->{names} }) {
            my $perl = perl_resolve($a, $s, $name);
            my $c    = c_resolve($a, $s, $name);
            is $c, $perl, "'$name': C and Perl agree (" . substr($perl, 0, 120) . ")";
            # Pin the outcome where the label states one, so two parsers that
            # both fail for the wrong reason cannot pass vacuously.
            if (my $want = ($fx->{expect} // {})->{$name}) {
                like $perl, qr/^\Q$want\E/, "'$name': outcome is $want";
            }
        }
    };
}

done_testing;
