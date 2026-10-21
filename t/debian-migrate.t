#!/usr/bin/perl
# t/debian-migrate.t
#
# The .deb maintainer scripts migrate a pre-0.13 install (T-008, T-065: the
# move itself is Exec::DispatcherConfig::migrate_legacy_dir, which the postinst
# runs with this checkout's lib on PERL5LIB here). They cannot be
# run as dpkg would, so the migration blocks are cut out of the scripts and run
# against a temp tree (the absolute /etc/ and /run/ and /usr/sbin/ paths are
# re-rooted by text substitution). Checks the dispatcher postinst's config-dir
# move, and that the agent preinst/postinst name the new unit and old unit
# consistently.

use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use File::Temp qw(tempdir);
use File::Path qw(make_path);

sub slurp { open(my $fh, '<', $_[0]) or die "$_[0]: $!"; local $/; <$fh> }
sub spew  { open(my $fh, '>', $_[0]) or die "$_[0]: $!"; print $fh $_[1]; close $fh }

my $disp = slurp("$Bin/../debian/ctrl-exec-dispatcher.postinst");
my ($block) = $disp =~ /(        if \[ -d \/etc\/ctrl-exec \].*?\n        fi\n)\n        # Config directory\./s;
ok($block, 'dispatcher postinst has the config-dir migration block') or BAIL_OUT('block not found');

sub migrate {
    my ($root) = @_;
    (my $b = $block) =~ s{/etc/}{$root/etc/}g;
    spew("$root/block.sh", "set -e\n$b");
    local $ENV{PERL5LIB} = "$Bin/../lib";
    my $out = `sh $root/block.sh 2>&1`;
    return ($? >> 8, $out);
}

{   # old only
    my $r = tempdir(CLEANUP => 1);
    make_path("$r/etc/ctrl-exec");
    spew("$r/etc/ctrl-exec/ctrl-exec.conf", "cert = $r/etc/ctrl-exec/dispatcher.crt\nauth_hook = $r/etc/ctrl-exec/auth-hook\nca = /x/ca.crt\n");
    spew("$r/etc/ctrl-exec/ca.key", "K\n");
    # the block's sed pattern is anchored on the re-rooted old path
    my ($rc, $out) = migrate($r);
    is $rc, 0, 'old only: block runs' or diag($out);
    ok -d "$r/etc/ctrl-exec-dispatcher" && -f "$r/etc/ctrl-exec-dispatcher/ca.key", 'old only: moved';
    ok -l "$r/etc/ctrl-exec", 'old only: symlink left at the old name';
    my $c = slurp("$r/etc/ctrl-exec-dispatcher/ctrl-exec.conf");
    like $c, qr{^cert = \Q$r\E/etc/ctrl-exec-dispatcher/dispatcher\.crt$}m, 'old only: cert path rewritten';
    like $c, qr{^auth_hook = \Q$r\E/etc/ctrl-exec-dispatcher/auth-hook$}m, 'old only: auth_hook path rewritten';
    like $c, qr{^ca = /x/ca\.crt$}m, 'old only: unrelated path untouched';
    ok -f "$r/etc/ctrl-exec-dispatcher/ctrl-exec.conf.pre-0.13", 'old only: previous config kept';
    my ($rc2, $out2) = migrate($r);
    is $rc2, 0, 'second run (symlink in place) is a no-op';
    unlike $out2, qr/moved/, 'second run does not move again';
}
{   # old real, new seeded (no CA): moved, the seeded dir kept aside
    my $r = tempdir(CLEANUP => 1);
    make_path("$r/etc/ctrl-exec", "$r/etc/ctrl-exec-dispatcher");
    spew("$r/etc/ctrl-exec/ctrl-exec.conf", "cert = $r/etc/ctrl-exec/dispatcher.crt\n");
    spew("$r/etc/ctrl-exec/ca.key", "OLD\n");
    spew("$r/etc/ctrl-exec-dispatcher/ctrl-exec.conf", "# seeded\n");
    my ($rc, $out) = migrate($r);
    is $rc, 0, 'seeded new: block runs' or diag($out);
    is slurp("$r/etc/ctrl-exec-dispatcher/ca.key"), "OLD\n", 'seeded new: real config moved in';
    ok -l "$r/etc/ctrl-exec", 'seeded new: symlink left';
    is slurp("$r/etc/ctrl-exec-dispatcher.seeded/ctrl-exec.conf"), "# seeded\n", 'seeded new: seeded dir kept aside';
}
{   # both hold a CA: left alone
    my $r = tempdir(CLEANUP => 1);
    make_path("$r/etc/ctrl-exec", "$r/etc/ctrl-exec-dispatcher");
    for my $d ("$r/etc/ctrl-exec", "$r/etc/ctrl-exec-dispatcher") {
        spew("$d/ctrl-exec.conf", "cert = $d/dispatcher.crt\n");
        spew("$d/ca.key", "K $d\n");
    }
    my ($rc, $out) = migrate($r);
    is $rc, 0, 'both: block runs';
    like $out, qr/leaving \S+ alone/, 'both: says so';
    like $out, qr/Both .* hold .* CA/, 'both: names the reason';
    ok !-l "$r/etc/ctrl-exec" && -f "$r/etc/ctrl-exec/ca.key", 'both: old left alone';
}
{   # fresh
    my $r = tempdir(CLEANUP => 1);
    make_path("$r/etc");
    my ($rc) = migrate($r);
    is $rc, 0, 'fresh: block runs';
    ok !-e "$r/etc/ctrl-exec" && !-e "$r/etc/ctrl-exec-dispatcher", 'fresh: nothing created by the migration';
}

# Agent scripts: the preinst stops/disables the old unit, the postinst enables
# and starts the new one, and neither refers to the old name for anything else.
my $pre  = slurp("$Bin/../debian/ctrl-exec-agent.preinst");
my $post = slurp("$Bin/../debian/ctrl-exec-agent.postinst");
ok(-x "$Bin/../debian/ctrl-exec-agent.preinst", 'agent preinst is executable');
like $pre,  qr/systemctl stop ctrl-exec-exec\.service/,    'preinst stops the old unit';
like $pre,  qr/systemctl disable ctrl-exec-exec\.service/, 'preinst disables the old unit';
like $post, qr/systemctl enable ctrl-exec-executor\.service/, 'postinst enables the new unit';
like $post, qr/deb-systemd-invoke start ctrl-exec-executor\.service/, 'postinst starts the new unit';
like $post, qr/for svc in ctrl-exec-executor ctrl-exec-agent/, 'upgrade restart loop names the new unit';
is(system('sh', '-n', "$Bin/../debian/ctrl-exec-agent.preinst"), 0, 'preinst parses');
is(system('sh', '-n', "$Bin/../debian/ctrl-exec-agent.postinst"), 0, 'agent postinst parses');
is(system('sh', '-n', "$Bin/../debian/ctrl-exec-dispatcher.postinst"), 0, 'dispatcher postinst parses');

done_testing;
