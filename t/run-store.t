#!/usr/bin/perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use FindBin    qw($Bin);
use lib "$Bin/../lib";

use Exec::RunStore qw();

# Suppress syslog output during tests.
{
    no warnings 'redefine';
    *Exec::Log::log_action = sub {};
}

# Canned result_all responses, set per-test, keyed by host. aggregate() calls
# Exec::Engine::result_all; we intercept it so no networking happens.
our %FETCH;
{
    no warnings 'redefine';
    *Exec::Engine::result_all = sub {
        my (%opts) = @_;
        my @out;
        for my $entry (@{ $opts{hosts} }) {
            my $name = ref $entry eq 'HASH' ? $entry->{name} : $entry;
            push @out, { host => $name, %{ $FETCH{$name} // { status => 'error', error => 'no canned' } } };
        }
        return \@out;
    };
}

# A resolver that is never expected to matter (result_all is mocked); identity.
my $resolver = sub { $_[0] };

# --- record_sync + load: shape preserved, marked complete ---
{
    my $dir = tempdir(CLEANUP => 1);
    Exec::RunStore::record_sync(
        reqid    => 'aabbccdd00010001',
        script   => 'backup',
        hosts    => ['h1', 'h2'],
        results  => [ { host => 'h1', exit => 0 }, { host => 'h2', exit => 0 } ],
        runs_dir => $dir,
    );
    my $rec = Exec::RunStore::load('aabbccdd00010001', $dir);
    is   $rec->{mode},   'sync',   'sync record mode';
    is   $rec->{script}, 'backup', 'sync record script';
    ok   $rec->{complete},          'sync record is complete';
    is   scalar @{ $rec->{results} }, 2, 'sync results preserved';
}

# --- record_async captures per-host acceptance state ---
{
    my $dir = tempdir(CLEANUP => 1);
    Exec::RunStore::record_async(
        reqid  => 'aabbccdd00020001',
        script => 'slow',
        dispatch_results => [
            { host => 'h1', status => 'accepted' },
            { host => 'h2', status => 'busy', error => 'script already running' },
            { host => 'h3', status => 'error', error => 'forbidden: serial mismatch' },
        ],
        runs_dir => $dir,
    );
    my $rec = Exec::RunStore::load('aabbccdd00020001', $dir);
    is $rec->{mode}, 'async',          'async record mode';
    is $rec->{hosts}{h1}{status}, 'accepted', 'accepted host recorded';
    is $rec->{hosts}{h2}{status}, 'busy',     'busy host recorded';
    is $rec->{hosts}{h3}{status}, 'error',    'error host recorded';
    ok !$rec->{complete},            'not complete while a host is accepted';
    is_deeply $rec->{pending}, ['h1'], 'only the accepted host is pending';
}

# --- aggregate: accepted -> done ---
{
    my $dir = tempdir(CLEANUP => 1);
    Exec::RunStore::record_async(
        reqid => 'aabbccdd00030001', script => 'backup',
        dispatch_results => [ { host => 'h1', status => 'accepted' } ],
        runs_dir => $dir,
    );
    local %FETCH = ( h1 => { status => 'done', exit => 0, stdout => "ok\n", stderr => '' } );
    my $rec = Exec::RunStore::aggregate(
        reqid => 'aabbccdd00030001', config => {}, runs_dir => $dir, resolver => $resolver,
    );
    is $rec->{hosts}{h1}{status}, 'done', 'host transitions to done';
    is $rec->{hosts}{h1}{exit},   0,      'exit captured on aggregate';
    is $rec->{hosts}{h1}{stdout}, "ok\n", 'stdout captured on aggregate';
    ok $rec->{complete},                   'run complete once the only host is done';

    # The transition is persisted: a fresh load reflects done.
    my $reloaded = Exec::RunStore::load('aabbccdd00030001', $dir);
    is $reloaded->{hosts}{h1}{status}, 'done', 'done state persisted';
}

# --- aggregate: still running stays pending ---
{
    my $dir = tempdir(CLEANUP => 1);
    Exec::RunStore::record_async(
        reqid => 'aabbccdd00040001', script => 'slow',
        dispatch_results => [ { host => 'h1', status => 'accepted' } ],
        runs_dir => $dir,
    );
    local %FETCH = ( h1 => { status => 'running' } );
    my $rec = Exec::RunStore::aggregate(
        reqid => 'aabbccdd00040001', config => {}, runs_dir => $dir, resolver => $resolver,
    );
    is $rec->{hosts}{h1}{status}, 'running', 'host shown running';
    ok !$rec->{complete},                     'run still incomplete';
    is_deeply $rec->{pending}, ['h1'],        'running host remains pending';
}

# --- aggregate: agent has no record -> expired ---
{
    my $dir = tempdir(CLEANUP => 1);
    Exec::RunStore::record_async(
        reqid => 'aabbccdd00050001', script => 'backup',
        dispatch_results => [ { host => 'h1', status => 'accepted' } ],
        runs_dir => $dir,
    );
    local %FETCH = ( h1 => { status => 'unknown' } );
    my $rec = Exec::RunStore::aggregate(
        reqid => 'aabbccdd00050001', config => {}, runs_dir => $dir, resolver => $resolver,
    );
    is $rec->{hosts}{h1}{status}, 'expired', 'purged agent result maps to expired';
    ok $rec->{complete},                      'expired is terminal';
}

# --- aggregate: transient fetch error keeps the host pending and retries ---
{
    my $dir = tempdir(CLEANUP => 1);
    Exec::RunStore::record_async(
        reqid => 'aabbccdd00060001', script => 'backup',
        dispatch_results => [ { host => 'h1', status => 'accepted' } ],
        runs_dir => $dir,
    );

    local %FETCH = ( h1 => { status => 'error', error => 'connection refused' } );
    my $rec = Exec::RunStore::aggregate(
        reqid => 'aabbccdd00060001', config => {}, runs_dir => $dir, resolver => $resolver,
    );
    is   $rec->{hosts}{h1}{status},      'accepted',           'status kept on fetch error';
    like $rec->{hosts}{h1}{fetch_error}, qr/connection refused/, 'fetch error annotated';
    ok   !$rec->{complete},               'still pending after a transient error';

    # Next poll succeeds: the host is retried (still pending) and completes.
    local %FETCH = ( h1 => { status => 'done', exit => 3, stdout => '', stderr => '' } );
    my $rec2 = Exec::RunStore::aggregate(
        reqid => 'aabbccdd00060001', config => {}, runs_dir => $dir, resolver => $resolver,
    );
    is $rec2->{hosts}{h1}{status}, 'done', 'retried host completes';
    is $rec2->{hosts}{h1}{exit},   3,      'exit captured on retry';
    ok !exists $rec2->{hosts}{h1}{fetch_error}, 'fetch error cleared on success';
    ok $rec2->{complete},                       'complete after retry';
}

# --- aggregate: multi-host, mixed terminal/pending ---
{
    my $dir = tempdir(CLEANUP => 1);
    Exec::RunStore::record_async(
        reqid => 'aabbccdd00070001', script => 'backup',
        dispatch_results => [
            { host => 'h1', status => 'accepted' },
            { host => 'h2', status => 'accepted' },
            { host => 'h3', status => 'busy', error => 'busy' },
        ],
        runs_dir => $dir,
    );
    local %FETCH = (
        h1 => { status => 'done', exit => 0, stdout => '', stderr => '' },
        h2 => { status => 'running' },
    );
    my $rec = Exec::RunStore::aggregate(
        reqid => 'aabbccdd00070001', config => {}, runs_dir => $dir, resolver => $resolver,
    );
    is $rec->{hosts}{h1}{status}, 'done',    'h1 done';
    is $rec->{hosts}{h2}{status}, 'running', 'h2 still running';
    is $rec->{hosts}{h3}{status}, 'busy',    'h3 untouched (terminal, never fetched)';
    ok !$rec->{complete},                     'incomplete while h2 runs';
    is_deeply $rec->{pending}, ['h2'],        'only h2 pending';
}

# --- aggregate: sync record is returned unchanged (no fetch) ---
{
    my $dir = tempdir(CLEANUP => 1);
    Exec::RunStore::record_sync(
        reqid => 'aabbccdd00080001', script => 'backup',
        hosts => ['h1'], results => [ { host => 'h1', exit => 0 } ], runs_dir => $dir,
    );
    # If aggregate tried to fetch, the mock would inject something; assert it does not.
    local %FETCH = ( h1 => { status => 'running' } );
    my $rec = Exec::RunStore::aggregate(
        reqid => 'aabbccdd00080001', config => {}, runs_dir => $dir, resolver => $resolver,
    );
    is $rec->{mode}, 'sync', 'sync record unchanged by aggregate';
    ok $rec->{complete},     'sync record stays complete';
}

# --- load unknown, purge, and reqid validation ---
{
    my $dir = tempdir(CLEANUP => 1);
    is Exec::RunStore::load('deadbeef', $dir), undef, 'unknown reqid loads undef';

    Exec::RunStore::record_async(
        reqid => 'aabbccdd00090001', script => 'x',
        dispatch_results => [ { host => 'h1', status => 'accepted' } ],
        runs_dir => $dir,
    );
    is Exec::RunStore::purge($dir, 86400), 0, 'fresh record not purged';
    ok -f "$dir/aabbccdd00090001.json", 'record still present';

    my $old = time() - 100_000;
    utime $old, $old, "$dir/aabbccdd00090001.json";
    is Exec::RunStore::purge($dir, 86400), 1, 'aged record purged';
    ok !-f "$dir/aabbccdd00090001.json", 'record removed';

    eval { Exec::RunStore::record_async(dispatch_results => []) };
    like $@, qr/reqid required/, 'record_async requires reqid';

    eval { Exec::RunStore::record_async(reqid => '../evil', dispatch_results => []) };
    like $@, qr/invalid reqid/, 'record_async rejects path characters in reqid';
}

done_testing;
