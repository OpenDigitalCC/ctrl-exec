#!/usr/bin/perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use FindBin qw($Bin);
use lib "$Bin/../lib";

use Exec::Registry qw();

# resolve_dispatch is the single addressing path used by ping, run, discovery,
# and the API: registry-only, with an explicit "unknown" list instead of a
# silent DNS fallback. These tests exercise it against a temp registry.

my $dir = tempdir(CLEANUP => 1);
sub agent {
    my ($name, %f) = @_;
    open my $fh, '>', "$dir/$name.json" or die $!;
    print $fh JSON_encode({ hostname => $name, %f });
    close $fh;
}
# Tiny JSON writer to avoid a hard JSON dep in the test.
sub JSON_encode {
    my ($h) = @_;
    my @p;
    for my $k (sort keys %$h) {
        my $v = $h->{$k};
        push @p, qq{"$k":} . ($v =~ /^\d+$/ ? $v : qq{"$v"});
    }
    return '{' . join(',', @p) . '}';
}

agent('ip-agent',   lookup_by => 'ip',       ip => '10.0.0.5', port => 7443);
agent('host-agent', lookup_by => 'hostname', ip => '10.0.0.6', port => 7443);
agent('alt-port',   lookup_by => 'ip',       ip => '10.0.0.7', port => 7450);

subtest 'lookup_by=ip resolves to the stored internal IP' => sub {
    my $r = Exec::Registry::resolve_dispatch(['ip-agent'], registry_dir => $dir);
    ok $r->{ok}, 'ok';
    is_deeply $r->{hosts}, [ { name => 'ip-agent', target => '10.0.0.5' } ],
        'target is the internal IP, not the hostname';
};

subtest 'lookup_by=hostname resolves to the hostname (DNS at dispatch)' => sub {
    my $r = Exec::Registry::resolve_dispatch(['host-agent'], registry_dir => $dir);
    is_deeply $r->{hosts}, [ { name => 'host-agent', target => 'host-agent' } ],
        'target is the hostname';
};

subtest 'stored non-default port is appended' => sub {
    my $r = Exec::Registry::resolve_dispatch(['alt-port'], registry_dir => $dir);
    is $r->{hosts}[0]{target}, '10.0.0.7:7450', 'ip:port';
};

subtest ':port suffix overrides the stored port for a known agent' => sub {
    my $r = Exec::Registry::resolve_dispatch(['ip-agent:7460'], registry_dir => $dir);
    is $r->{hosts}[0]{target}, '10.0.0.5:7460', 'override applied';
    is $r->{hosts}[0]{name},   'ip-agent',      'keyed by the registry name';
};

subtest 'unknown agent is reported, never DNS-resolved' => sub {
    my $r = Exec::Registry::resolve_dispatch(['nope'], registry_dir => $dir);
    ok !$r->{ok}, 'not ok';
    is_deeply $r->{unknown}, ['nope'], 'listed as unknown';
    ok !exists $r->{hosts}, 'no hosts returned';
};

subtest 'a single unknown fails the whole batch' => sub {
    my $r = Exec::Registry::resolve_dispatch(['ip-agent', 'ghost'], registry_dir => $dir);
    ok !$r->{ok}, 'not ok';
    is_deeply $r->{unknown}, ['ghost'], 'only the unknown is listed';
};

# The CLI resolver turns an unknown agent into a hard error (no silent
# fallback). With no registry in the test environment, any name is unknown.
subtest 'CLI _resolve_dispatch_hosts dies on an unknown agent' => sub {
    {
        no warnings 'redefine';
        local *main::main = sub {};
        do "$Bin/../bin/ctrl-exec-dispatcher";
        die "load: $@" if $@;
    }
    eval { main::_resolve_dispatch_hosts(['definitely-not-a-registered-agent-xyz']) };
    like $@, qr/unknown agent/, 'dies with an unknown-agent error';
};

done_testing;
