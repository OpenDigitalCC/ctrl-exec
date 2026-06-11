#!/usr/bin/perl
use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);

# Load the dispatcher CLI's subs without running main().
{
    no warnings 'redefine';
    local *main::main = sub {};
    do "$Bin/../bin/ctrl-exec-dispatcher";
    die "Could not load ctrl-exec-dispatcher: $@" if $@;
}

sub capture_stdout {
    my ($code) = @_;
    open my $old, '>&', \*STDOUT or die;
    close STDOUT;
    open STDOUT, '>', \my $buf or die;
    $code->();
    close STDOUT;
    open STDOUT, '>&', $old or die;
    return $buf;
}

# --- _format_async_submit ---

{
    my $out = capture_stdout(sub {
        main::_format_async_submit('abc123def4567890', [
            { host => 'h1', status => 'accepted', rtt => '12ms' },
            { host => 'h2', status => 'busy',  error => 'script already running' },
            { host => 'h3', status => 'error', error => 'forbidden: serial mismatch' },
        ]);
    });
    like $out, qr/req:abc123def4567890/,  'async submit: reqid shown';
    like $out, qr/h1\s+\[accepted/,        'async submit: accepted host';
    like $out, qr/h2\s+\[BUSY: script already running/, 'async submit: busy host with reason';
    like $out, qr/h3\s+\[ERROR: forbidden/, 'async submit: error host with reason';
    like $out, qr/status abc123def4567890/, 'async submit: prints the follow-up command';
}

# --- _format_status: async record, mixed states ---

{
    my $record = {
        reqid    => 'abc123def4567890',
        script   => 'backup',
        mode     => 'async',
        complete => 0,
        hosts    => {
            h1 => { status => 'done', exit => 0, stdout => "all good\n", stderr => '' },
            h2 => { status => 'running' },
            h3 => { status => 'expired' },
            h4 => { status => 'busy', error => 'script already running' },
        },
    };
    my $out = capture_stdout(sub { main::_format_status($record) });

    like $out, qr/Request abc123def4567890/,       'status: reqid in header';
    like $out, qr/script: backup/,                  'status: script in header';
    like $out, qr/\[PENDING\]/,                     'status: PENDING while a host runs';
    like $out, qr/h1\s+\[done\s+exit:0\]/,          'status: done host with exit';
    like $out, qr/all good/,                        'status: done host stdout shown';
    like $out, qr/h2\s+\[running\]/,                'status: running host';
    like $out, qr/h3\s+\[EXPIRED\]/,                'status: expired host';
    like $out, qr/h4\s+\[BUSY\]/,                   'status: busy host';
    like $out, qr/script already running/,          'status: busy host reason shown';
}

{
    my $record = {
        reqid    => 'feedface00000001',
        script   => 'backup',
        mode     => 'async',
        complete => 1,
        hosts    => { h1 => { status => 'done', exit => 0, stdout => '', stderr => '' } },
    };
    my $out = capture_stdout(sub { main::_format_status($record) });
    like $out, qr/\[COMPLETE\]/, 'status: COMPLETE when no host is pending';
}

# A still-pending host carrying a transient fetch error is annotated.
{
    my $record = {
        reqid => 'r', script => 's', mode => 'async', complete => 0,
        hosts => { h1 => { status => 'accepted', fetch_error => 'connection refused' } },
    };
    my $out = capture_stdout(sub { main::_format_status($record) });
    like $out, qr/h1\s+\[accepted\]/,         'status: accepted host shown';
    like $out, qr/fetch pending: connection refused/, 'status: transient fetch error annotated';
}

# --- _format_status: sync record delegates to the normal run renderer ---

{
    my $record = {
        reqid   => 'r', script => 'backup', mode => 'sync', complete => 1,
        results => [ { host => 'h1', exit => 0, stdout => "synced\n", stderr => '', rtt => '5ms' } ],
    };
    my $out = capture_stdout(sub { main::_format_status($record) });
    like $out, qr/==> h1\s+\[OK\s+exit:0/, 'status: sync record rendered as a run result';
    like $out, qr/synced/,                  'status: sync stdout shown';
}

# --- _host_failed ---

{
    ok !main::_host_failed({ status => 'done', exit => 0 }), 'host_failed: done exit 0 is success';
    ok  main::_host_failed({ status => 'done', exit => 2 }), 'host_failed: done non-zero is failure';
    ok  main::_host_failed({ status => 'busy' }),            'host_failed: busy is failure';
    ok  main::_host_failed({ status => 'error' }),           'host_failed: error is failure';
    ok  main::_host_failed({ status => 'expired' }),         'host_failed: expired is failure';
    ok !main::_host_failed({ status => 'running' }),         'host_failed: running is not (yet) a failure';
}

done_testing;
