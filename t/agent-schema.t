#!/usr/bin/perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use FindBin    qw($Bin);
use lib "$Bin/../lib";

use Exec::Agent::Schema qw();

# Suppress syslog output during tests.
{
    no warnings 'redefine';
    *Exec::Log::log_action = sub {};
}

# Write a script + optional sidecar in $dir; return its absolute path.
sub make_script {
    my ($dir, $name, $sidecar_content) = @_;
    my $path = "$dir/$name";
    open my $fh, '>', $path or die "write $path: $!";
    print {$fh} "#!/bin/sh\nexit 0\n";
    close $fh;
    chmod 0755, $path;
    if (defined $sidecar_content) {
        open my $sh, '>', "$path.schema.json" or die "write sidecar: $!";
        print {$sh} $sidecar_content;
        close $sh;
    }
    return $path;
}

# --- explicit version is used verbatim; body carried through ---
{
    my $dir = tempdir(CLEANUP => 1);
    my $p = make_script($dir, 'check-disk.sh', <<'JSON');
{ "version": "2", "description": "Check disk",
  "read_only": true, "destructive": false,
  "arguments": { "type": "object", "properties": { "threshold": { "type": "integer" } } },
  "argv": [ { "arg": "threshold" } ] }
JSON
    my $s = Exec::Agent::Schema::load_for_allowlist({ 'check-disk' => $p });
    ok   exists $s->{'check-disk'},                   'sidecar loaded';
    is   $s->{'check-disk'}{schema_version}, '2',     'explicit version used verbatim';
    is   $s->{'check-disk'}{schema}{description}, 'Check disk', 'body carried through';
    is   $s->{'check-disk'}{schema}{arguments}{type}, 'object',  'arguments preserved';
    ok   $s->{'check-disk'}{schema}{read_only},       'flags preserved';
}

# --- no explicit version -> sha256: derived, stable across reformatting ---
{
    my $dir = tempdir(CLEANUP => 1);
    my $p1 = make_script($dir, 'a.sh', '{"description":"x","arguments":{"type":"object"}}');
    # Same data, different whitespace/key order -> must yield the same version.
    my $p2 = make_script($dir, 'b.sh', "{\n  \"arguments\" : { \"type\": \"object\" },\n  \"description\":\"x\"\n}\n");

    my $s = Exec::Agent::Schema::load_for_allowlist({ a => $p1, b => $p2 });
    like $s->{a}{schema_version}, qr/^sha256:[0-9a-f]{12}$/, 'derived version is sha256:<12 hex>';
    is   $s->{a}{schema_version}, $s->{b}{schema_version},
        'canonical hash is stable across reformatting and key order';
}

# --- different body -> different derived version ---
{
    my $dir = tempdir(CLEANUP => 1);
    my $p1 = make_script($dir, 'a.sh', '{"description":"one"}');
    my $p2 = make_script($dir, 'b.sh', '{"description":"two"}');
    my $s = Exec::Agent::Schema::load_for_allowlist({ a => $p1, b => $p2 });
    isnt $s->{a}{schema_version}, $s->{b}{schema_version},
        'distinct bodies derive distinct versions';
}

# --- reserved/invalid explicit version falls back to derived ---
{
    my $dir = tempdir(CLEANUP => 1);
    my $reserved = make_script($dir, 'r.sh', '{"version":"sha256:deadbeef","description":"x"}');
    my $bad      = make_script($dir, 'g.sh', '{"version":"has spaces!","description":"x"}');
    my $s = Exec::Agent::Schema::load_for_allowlist({ r => $reserved, g => $bad });
    like $s->{r}{schema_version}, qr/^sha256:[0-9a-f]{12}$/,
        'reserved sha256: prefix is rejected and a hash is derived';
    like $s->{g}{schema_version}, qr/^sha256:[0-9a-f]{12}$/,
        'malformed version falls back to a derived hash';
}

# --- a numeric explicit version is accepted ---
{
    my $dir = tempdir(CLEANUP => 1);
    my $p = make_script($dir, 'n.sh', '{"version":3,"description":"x"}');
    my $s = Exec::Agent::Schema::load_for_allowlist({ n => $p });
    is $s->{n}{schema_version}, '3', 'numeric version normalised to string';
}

# --- metadata-only sidecar (no arguments) is still carried ---
{
    my $dir = tempdir(CLEANUP => 1);
    my $p = make_script($dir, 'm.sh', '{"description":"meta only","destructive":true}');
    my $s = Exec::Agent::Schema::load_for_allowlist({ m => $p });
    ok exists $s->{m},                          'metadata-only sidecar loaded';
    ok !exists $s->{m}{schema}{arguments},      'no arguments key present';
    is $s->{m}{schema}{description}, 'meta only','description carried';
}

# --- no sidecar, invalid JSON, non-object, and oversize are all skipped ---
{
    my $dir = tempdir(CLEANUP => 1);
    my $none    = make_script($dir, 'none.sh');                          # no sidecar
    my $broken  = make_script($dir, 'broken.sh', '{ not valid json ');
    my $array   = make_script($dir, 'arr.sh', '[1,2,3]');               # JSON, not object
    my $big     = make_script($dir, 'big.sh', '{"x":"' . ('a' x 70000) . '"}');

    my $s = Exec::Agent::Schema::load_for_allowlist({
        none => $none, broken => $broken, arr => $array, big => $big,
    });
    ok !exists $s->{none},   'script with no sidecar is absent';
    ok !exists $s->{broken}, 'invalid JSON sidecar skipped';
    ok !exists $s->{arr},    'non-object JSON sidecar skipped';
    ok !exists $s->{big},    'oversize sidecar skipped';
}

# --- only allowlisted scripts are consulted (no directory scan) ---
{
    my $dir = tempdir(CLEANUP => 1);
    my $listed   = make_script($dir, 'listed.sh',   '{"description":"in"}');
    my $unlisted = make_script($dir, 'unlisted.sh', '{"description":"out"}');
    # 'unlisted' has a sidecar on disk but is NOT in the allowlist passed in.
    my $s = Exec::Agent::Schema::load_for_allowlist({ listed => $listed });
    ok  exists $s->{listed},   'allowlisted script with sidecar loaded';
    ok !exists $s->{unlisted}, 'sidecar for a non-allowlisted script is never read';
    is  scalar(keys %$s), 1,   'only the allowlist drives sidecar reads';
}

done_testing;
