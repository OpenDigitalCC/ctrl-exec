#!/usr/bin/perl
# trusted-dispatchers.t
#
# Unit tests for the agent-side trusted-dispatcher map: the serial -> identity
# store that lets one agent serve more than one dispatcher natively. Covers
# valid_dispatcher_id, load_trusted_dispatchers, add_trusted_dispatcher (the
# append-enrolment primitive), and dispatcher_trusted (the gate/resolver).

use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use FindBin    qw($Bin);
use lib "$Bin/../lib";

use Exec::Agent::AgentPairing qw();

# Silence the warn() on an unreadable file path; not exercised here.
open my $saved_stderr, '>&', \*STDERR;

my $tmpdir = tempdir(CLEANUP => 1);

sub slurp {
    my ($path) = @_;
    open my $fh, '<', $path or die "read $path: $!";
    local $/;
    return scalar <$fh>;
}

# ---------------------------------------------------------------------------
# valid_dispatcher_id
# ---------------------------------------------------------------------------

subtest 'valid_dispatcher_id accepts well-formed labels' => sub {
    for my $id ('automation', 'human-orchestrator', 'ctrl.host_1', 'A', 'x9',
                ('a' x 64)) {
        ok( Exec::Agent::AgentPairing::valid_dispatcher_id($id), "accepts '$id'" );
    }
};

subtest 'valid_dispatcher_id rejects malformed labels' => sub {
    for my $id ('', '-leading', '.leading', '_leading', 'has space',
                'has/slash', 'tab\there', ('a' x 65)) {
        ok( !Exec::Agent::AgentPairing::valid_dispatcher_id($id),
            "rejects '$id'" );
    }
    ok( !Exec::Agent::AgentPairing::valid_dispatcher_id(undef), 'rejects undef' );
};

# ---------------------------------------------------------------------------
# load_trusted_dispatchers
# ---------------------------------------------------------------------------

subtest 'absent file yields an empty map' => sub {
    my $map = Exec::Agent::AgentPairing::load_trusted_dispatchers(
        path => "$tmpdir/does-not-exist",
    );
    is_deeply( $map, {}, 'empty hashref when file is absent' );
};

subtest 'parses entries, comments, blanks, and normalises serials' => sub {
    my $path = "$tmpdir/map-parse";
    open my $fh, '>', $path or die $!;
    print $fh <<'EOF';
# a comment
deadbeef01 automation

ff human            # decimal 255 would also normalise to ff
DE:AD:BE:EF colon-form
EOF
    close $fh;

    my $map = Exec::Agent::AgentPairing::load_trusted_dispatchers(path => $path);
    is( $map->{deadbeef01}, 'automation', 'hex serial entry parsed' );
    is( $map->{ff},         'human',      'short hex serial parsed' );
    is( $map->{deadbeef},   'colon-form', 'colon-form serial normalised to hex' );
    is( scalar keys %$map, 3, 'comment and blank lines ignored' );
};

subtest 'skips entries with a missing or invalid identity' => sub {
    my $path = "$tmpdir/map-bad-id";
    open my $fh, '>', $path or die $!;
    print $fh "aaaa1111\n";                 # serial only, no id
    print $fh "bbbb2222 has space rest\n";  # id captures the whole remainder -> has spaces -> invalid
    print $fh "cccc3333 .bad\n";            # invalid id (leading dot)
    print $fh "dddd4444 good\n";            # valid
    close $fh;

    my $map = Exec::Agent::AgentPairing::load_trusted_dispatchers(path => $path);
    ok( !exists $map->{aaaa1111}, 'serial-only line skipped' );
    ok( !exists $map->{bbbb2222}, 'id-with-spaces line skipped' );
    ok( !exists $map->{cccc3333}, 'invalid-id line skipped' );
    is( $map->{dddd4444}, 'good', 'valid line kept' );
    is( scalar keys %$map, 1, 'only the well-formed entry survives' );
};

# ---------------------------------------------------------------------------
# add_trusted_dispatcher (append enrolment)
# ---------------------------------------------------------------------------

subtest 'creates the map file with one entry' => sub {
    my $path = "$tmpdir/map-create";
    Exec::Agent::AgentPairing::add_trusted_dispatcher(
        path => $path, serial => 'abc123', id => 'first',
    );
    my $map = Exec::Agent::AgentPairing::load_trusted_dispatchers(path => $path);
    is_deeply( $map, { abc123 => 'first' }, 'single entry stored' );
    like( slurp($path), qr/^#/, 'file carries a managed-by header comment' );
};

subtest 'appending a second dispatcher preserves the first' => sub {
    my $path = "$tmpdir/map-append";
    Exec::Agent::AgentPairing::add_trusted_dispatcher(
        path => $path, serial => '1111aaaa', id => 'automation',
    );
    Exec::Agent::AgentPairing::add_trusted_dispatcher(
        path => $path, serial => '2222bbbb', id => 'human',
    );
    my $map = Exec::Agent::AgentPairing::load_trusted_dispatchers(path => $path);
    is_deeply(
        $map,
        { '1111aaaa' => 'automation', '2222bbbb' => 'human' },
        'both dispatchers trusted after append',
    );
};

subtest 'updating an existing serial replaces only its identity' => sub {
    my $path = "$tmpdir/map-update";
    Exec::Agent::AgentPairing::add_trusted_dispatcher(
        path => $path, serial => 'cccc1111', id => 'oldname',
    );
    Exec::Agent::AgentPairing::add_trusted_dispatcher(
        path => $path, serial => 'dddd2222', id => 'other',
    );
    Exec::Agent::AgentPairing::add_trusted_dispatcher(
        path => $path, serial => 'cccc1111', id => 'newname',
    );
    my $map = Exec::Agent::AgentPairing::load_trusted_dispatchers(path => $path);
    is( $map->{cccc1111}, 'newname', 'identity updated for existing serial' );
    is( $map->{dddd2222}, 'other',   'other entry untouched' );
    is( scalar keys %$map, 2, 'no duplicate entry created' );
};

subtest 'normalises serial form on add (decimal in, hex stored)' => sub {
    my $path = "$tmpdir/map-norm";
    Exec::Agent::AgentPairing::add_trusted_dispatcher(
        path => $path, serial => '255', id => 'dec',
    );
    my $map = Exec::Agent::AgentPairing::load_trusted_dispatchers(path => $path);
    is( $map->{ff}, 'dec', 'decimal serial stored as hex key' );
};

subtest 'rejects an invalid id or unusable serial' => sub {
    my $path = "$tmpdir/map-reject";
    eval { Exec::Agent::AgentPairing::add_trusted_dispatcher(
        path => $path, serial => 'abcd', id => 'bad id') };
    like( $@, qr/invalid dispatcher id/, 'croaks on invalid id' );

    eval { Exec::Agent::AgentPairing::add_trusted_dispatcher(
        path => $path, serial => '', id => 'good') };
    like( $@, qr/invalid dispatcher serial/, 'croaks on empty serial' );
};

# ---------------------------------------------------------------------------
# remove_trusted_dispatcher (the "remove" half of add-then-remove rotation)
# ---------------------------------------------------------------------------

subtest 'removes one entry and preserves the rest' => sub {
    my $path = "$tmpdir/map-rm";
    Exec::Agent::AgentPairing::add_trusted_dispatcher(
        path => $path, serial => '1111aaaa', id => 'automation');
    Exec::Agent::AgentPairing::add_trusted_dispatcher(
        path => $path, serial => '2222bbbb', id => 'human');

    my $removed = Exec::Agent::AgentPairing::remove_trusted_dispatcher(
        path => $path, serial => '1111aaaa');
    is( $removed, 1, 'returns 1 when an entry is removed' );

    my $map = Exec::Agent::AgentPairing::load_trusted_dispatchers(path => $path);
    is_deeply( $map, { '2222bbbb' => 'human' }, 'only the target serial removed' );
};

subtest 'remove normalises the serial form (decimal removes hex entry)' => sub {
    my $path = "$tmpdir/map-rm-norm";
    Exec::Agent::AgentPairing::add_trusted_dispatcher(
        path => $path, serial => 'ff', id => 'dec');
    my $removed = Exec::Agent::AgentPairing::remove_trusted_dispatcher(
        path => $path, serial => '255');     # decimal 255 == hex ff
    is( $removed, 1, 'decimal serial removes the matching hex entry' );
    is_deeply( Exec::Agent::AgentPairing::load_trusted_dispatchers(path => $path),
        {}, 'map now empty' );
};

subtest 'remove is a no-op for an absent serial or file' => sub {
    is( Exec::Agent::AgentPairing::remove_trusted_dispatcher(
            path => "$tmpdir/map-rm-nope", serial => 'deadbeef'),
        0, 'absent file -> 0' );

    my $path = "$tmpdir/map-rm-absent";
    Exec::Agent::AgentPairing::add_trusted_dispatcher(
        path => $path, serial => 'aaaa1111', id => 'x');
    is( Exec::Agent::AgentPairing::remove_trusted_dispatcher(
            path => $path, serial => 'ffff9999'),
        0, 'absent serial -> 0 (other entries untouched)' );
    is_deeply( Exec::Agent::AgentPairing::load_trusted_dispatchers(path => $path),
        { 'aaaa1111' => 'x' }, 'existing entry preserved' );

    eval { Exec::Agent::AgentPairing::remove_trusted_dispatcher(
        path => $path, serial => '') };
    like( $@, qr/invalid dispatcher serial/, 'croaks on empty serial' );
};

# ---------------------------------------------------------------------------
# dispatcher_trusted (gate / resolver)
# ---------------------------------------------------------------------------

subtest 'resolves a trusted serial to its identity' => sub {
    my $map = { deadbeef => 'automation', ff => 'human' };
    is( Exec::Agent::AgentPairing::dispatcher_trusted('deadbeef', $map),
        'automation', 'hex peer serial resolves' );
    # IO::Socket::SSL hands serials as decimal; 255 must match hex 'ff'.
    is( Exec::Agent::AgentPairing::dispatcher_trusted('255', $map),
        'human', 'decimal peer serial matches hex map entry' );
};

subtest 'an unknown or empty serial is untrusted' => sub {
    my $map = { deadbeef => 'automation' };
    is( Exec::Agent::AgentPairing::dispatcher_trusted('cafef00d', $map),
        undef, 'unknown serial -> undef' );
    is( Exec::Agent::AgentPairing::dispatcher_trusted('', $map),
        undef, 'empty serial -> undef' );
    is( Exec::Agent::AgentPairing::dispatcher_trusted('deadbeef', {}),
        undef, 'empty map -> undef' );
};

done_testing;
