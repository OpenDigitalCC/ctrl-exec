#!/usr/bin/perl
# t/install-no-gcc.t
#
# T-028: a tarball install on a host that cannot build the executor (no gcc, or
# no libcap headers) must not leave a NEW agent.conf pointing at an executor
# that does not exist, must say plainly what is missing and how to fix it, and
# must leave an EXISTING agent.conf alone. install.sh is sourced and its helpers
# (build_executor, settle_executor_conf, print_executor_notice) are run on a
# temp tree with a PATH that has no gcc.
use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use File::Temp qw(tempdir);
use File::Path qw(make_path);

my $install_sh = "$Bin/../install.sh";
sub slurp { open(my $fh, '<', $_[0]) or return ''; local $/; <$fh> }
sub spew  { open(my $fh, '>', $_[0]) or die "$_[0]: $!"; print $fh $_[1]; close $fh }

# A PATH holding only the tools install.sh's helpers need - and no gcc.
sub host {
    my ($gcc_stub) = @_;
    my $r = tempdir(CLEANUP => 1);
    make_path("$r/etc", "$r/sbin", "$r/systemd", "$r/pathbin");
    for my $t (qw(bash sh sed grep cat mkdir chmod chown dirname basename tr head
                  id rm cp mv ln install env echo printf readlink)) {
        for my $d (qw(/usr/bin /bin)) {
            if (-x "$d/$t") { symlink "$d/$t", "$r/pathbin/$t"; last }
        }
    }
    if (defined $gcc_stub) { spew("$r/pathbin/gcc", $gcc_stub); chmod 0755, "$r/pathbin/gcc" }
    return $r;
}

sub run {
    my ($r, $body) = @_;
    $body =~ s/'/'\\''/g;
    my $script = <<"END";
set -euo pipefail
source "$install_sh"
SBIN_DIR="$r/sbin"
SYSTEMD_DIR="$r/systemd"
AGENT_CONF_DIR="$r/etc"
HAS_SYSTEMD=false
PKG_MGR=apt
SUDO_CMD=sudo
$body
END
    local $ENV{PATH} = "$r/pathbin";
    my $out = `$r/pathbin/bash -c '$script' 2>&1`;
    return ($? >> 8, $out);
}

my $example = slurp("$Bin/../etc/agent.conf.example");
like $example, qr/^executor_socket\s*=/m, 'precondition: the example enables executor_socket';

# --- no gcc, new agent.conf -> executor_socket commented out, loud notice ---
{
    my $r = host();
    ok !-e "$r/pathbin/gcc", 'no gcc on the test PATH';
    spew("$r/etc/agent.conf", $example);
    my ($rc, $out) = run($r, 'build_executor; settle_executor_conf "$AGENT_CONF_DIR/agent.conf" new; print_executor_notice');
    is $rc, 0, 'no gcc: helpers succeed (install carries on)' or diag $out;
    ok !-e "$r/sbin/ctrl-exec-executor", 'no gcc: no executor installed';
    my $conf = slurp("$r/etc/agent.conf");
    unlike $conf, qr/^executor_socket\s*=/m, 'no gcc: executor_socket is not active in the new agent.conf';
    like $conf, qr/^# executor_socket\s*=\s*\/run\/ctrl-exec-agent\/exec\.sock/m, 'no gcc: the line is kept, commented, ready to re-enable';
    like $conf, qr/DISABLED by install\.sh/, 'no gcc: agent.conf says why';
    like $out, qr/ctrl-exec-executor was NOT built/, 'no gcc: notice headline';
    like $out, qr/Missing: gcc .*libcap development headers/, 'no gcc: notice names what is missing';
    like $out, qr/Per-script profiles are NOT applied/, 'no gcc: notice says profiles are not applied';
    like $out, qr/sudo apt-get install gcc libcap-dev/, 'no gcc: notice gives the install command';
    like $out, qr/sudo \.\/install\.sh --agent/, 'no gcc: notice says to re-run';
    # the edited file still parses as the agent expects (profiles block intact)
    like $conf, qr/^\[profile default\]/m, 'no gcc: rest of agent.conf untouched';
}

# --- no gcc, existing agent.conf -> never edited, notice says runs will fail ---
{
    my $r = host();
    spew("$r/etc/agent.conf", $example);
    my ($rc, $out) = run($r, 'build_executor; settle_executor_conf "$AGENT_CONF_DIR/agent.conf" existing; print_executor_notice');
    is $rc, 0, 'existing conf: helpers succeed';
    is slurp("$r/etc/agent.conf"), $example, 'existing conf: agent.conf byte-for-byte unchanged';
    like $out, qr/still sets\s+executor_socket\s+and\s+was not changed/, 'existing conf: notice says it was left alone';
    like $out, qr/every run fails\s+with an error naming the executor/, 'existing conf: notice says what runs do';
}

# --- gcc present but libcap headers missing (compile fails) ---
{
    my $r = host("#!/bin/sh\n[ \"\$1\" = -E ] && exit 1\necho 'fatal error: sys/capability.h: No such file' >&2\nexit 1\n");
    spew("$r/etc/agent.conf", $example);
    my ($rc, $out) = run($r, 'build_executor; settle_executor_conf "$AGENT_CONF_DIR/agent.conf" new; print_executor_notice');
    is $rc, 0, 'no libcap: helpers succeed';
    like $out, qr/Missing: the libcap development headers/, 'no libcap: notice names the headers';
    unlike slurp("$r/etc/agent.conf"), qr/^executor_socket\s*=/m, 'no libcap: executor_socket commented out';
}

# --- gcc works -> nothing disabled, no notice ---
{
    my $r = host("#!/bin/sh\nout=\n[ \"\$1\" = -E ] && exit 0\nwhile [ \$# -gt 0 ]; do [ \"\$1\" = -o ] && out=\$2; shift; done\n: > \"\$out\"\nexit 0\n");
    spew("$r/etc/agent.conf", $example);
    my ($rc, $out) = run($r, 'build_executor; settle_executor_conf "$AGENT_CONF_DIR/agent.conf" new; print_executor_notice');
    is $rc, 0, 'gcc ok: succeeds' or diag $out;
    ok -x "$r/sbin/ctrl-exec-executor", 'gcc ok: executor installed';
    is slurp("$r/etc/agent.conf"), $example, 'gcc ok: agent.conf untouched';
    unlike $out, qr/NOT built/, 'gcc ok: no warning notice';
}

# --- no gcc but an executor from an earlier install -> kept, nothing disabled ---
{
    my $r = host();
    spew("$r/sbin/ctrl-exec-executor", "bin\n"); chmod 0755, "$r/sbin/ctrl-exec-executor";
    spew("$r/etc/agent.conf", $example);
    my ($rc, $out) = run($r, 'build_executor; settle_executor_conf "$AGENT_CONF_DIR/agent.conf" new; print_executor_notice');
    is slurp("$r/etc/agent.conf"), $example, 'earlier executor: agent.conf untouched';
    unlike $out, qr/NOT built/, 'earlier executor: no warning notice';
}

done_testing;
