#!/usr/bin/perl
use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/../lib";

use Exec::API qw();

# A minimal OpenAPI spec with the structure _build_live_spec touches: a /run
# body referencing RunRequest (hosts + script), and a /ping body with hosts.
sub base_spec {
    return {
        info  => { version => '0.9.0' },
        paths => {
            '/run' => { post => { requestBody => { content => { 'application/json' => {
                schema => { '$ref' => '#/components/schemas/RunRequest' } } } } } },
            '/ping' => { post => { requestBody => { content => { 'application/json' => {
                schema => { '$ref' => '#/components/schemas/PingRequest' } } } } } },
        },
        components => { schemas => {
            RunRequest  => { properties => {
                hosts  => { type => 'array', items => { type => 'string' } },
                script => { type => 'string' },
            } },
            PingRequest => { properties => {
                hosts => { type => 'array', items => { type => 'string' } },
            } },
        } },
    };
}

# Find the variant in an x-ctrl-exec-scripts entry matching a schema_version.
sub variant_for {
    my ($entry, $version) = @_;
    for my $v (@$entry) {
        return $v if defined $v->{schema_version} && $v->{schema_version} eq $version;
    }
    return undef;
}

# --- enum injection + schema surfacing, with a drifted fleet ---
{
    my $results = [
        { host => 'web-01', status => 'ok', scripts => [
            { name => 'check-disk', schema_version => '2',
              schema => { description => 'disk', arguments => { type => 'object' } } },
            { name => 'env-dump' },                       # no schema advertised
        ] },
        { host => 'web-02', status => 'ok', scripts => [
            { name => 'check-disk', schema_version => '2',
              schema => { description => 'disk', arguments => { type => 'object' } } },
        ] },
        { host => 'web-03', status => 'ok', scripts => [
            { name => 'check-disk', schema_version => 'sha256:abc123def456',
              schema => { description => 'disk (old)' } },
        ] },
        { host => 'down-01', status => 'error', error => 'unreachable' },  # ignored
    ];

    my $spec = base_spec();
    Exec::API::_build_live_spec($spec, ['web-01', 'web-02', 'web-03'], $results);

    my $rr = $spec->{components}{schemas}{RunRequest}{properties};
    is_deeply $rr->{hosts}{items}{enum}, ['web-01', 'web-02', 'web-03'],
        'host enum injected into RunRequest';
    is_deeply $spec->{components}{schemas}{PingRequest}{properties}{hosts}{items}{enum},
        ['web-01', 'web-02', 'web-03'], 'host enum injected into PingRequest too';
    is_deeply $rr->{script}{enum}, ['check-disk', 'env-dump'],
        'script enum is the sorted, de-duplicated set of discovered scripts';

    my $ext = $spec->{'x-ctrl-exec-scripts'};
    ok $ext, 'x-ctrl-exec-scripts extension present';

    my $cd = $ext->{'check-disk'};
    is scalar @$cd, 2, 'check-disk surfaced as two version variants (fleet drift visible)';

    my $v2 = variant_for($cd, '2');
    ok $v2, 'version "2" variant present';
    is_deeply $v2->{hosts}, ['web-01', 'web-02'], 'v2 hosts grouped and sorted';
    is $v2->{schema}{description}, 'disk', 'v2 schema surfaced verbatim';

    my $vold = variant_for($cd, 'sha256:abc123def456');
    ok $vold, 'derived-version variant present';
    is_deeply $vold->{hosts}, ['web-03'], 'old-version host isolated to its own variant';

    my $ed = $ext->{'env-dump'};
    is scalar @$ed, 1, 'env-dump has a single variant';
    ok !exists $ed->[0]{schema_version}, 'no schema_version for an unschemad script';
    ok !exists $ed->[0]{schema},          'no schema body for an unschemad script';
    is_deeply $ed->[0]{hosts}, ['web-01'], 'env-dump host recorded';

    # The /run args contract is untouched - core does not fold argv into it.
    ok !exists $rr->{args}, 'RunRequest args contract left as-is (positional, not typed here)';
}

# --- empty fleet: no enums, no extension ---
{
    my $spec = base_spec();
    Exec::API::_build_live_spec($spec, [], []);
    my $rr = $spec->{components}{schemas}{RunRequest}{properties};
    ok !defined $rr->{hosts}{items}{enum}, 'no host enum when no hosts';
    ok !exists $rr->{script}{enum},         'no script enum when nothing discovered';
    ok !exists $spec->{'x-ctrl-exec-scripts'}, 'no extension when nothing discovered';
}

done_testing;
