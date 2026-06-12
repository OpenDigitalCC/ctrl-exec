#!/usr/bin/perl
use strict;
use warnings;
use Test::More tests => 28;
use FindBin qw($Bin);

# Load just the parsing and formatting functions from bin/ctrl-exec-dispatcher
# by requiring it into a package that won't execute main()
{
    no warnings 'redefine';
    local *main::main = sub {};   # suppress main() execution
    do "$Bin/../bin/ctrl-exec-dispatcher";
    die "Could not load ctrl-exec: $@" if $@;
}

# --- _parse_run_args ---

{
    my ($hosts, $script, $args) = main::_parse_run_args('host-a', 'backup');
    is_deeply $hosts,  ['host-a'], 'parse_run_args: single host';
    is        $script, 'backup',   'parse_run_args: script name';
    is_deeply $args,   [],         'parse_run_args: no script args';
}

{
    my ($hosts, $script, $args) = main::_parse_run_args(
        'host-a', 'host-b', 'backup');
    is_deeply $hosts,  ['host-a', 'host-b'], 'parse_run_args: multiple hosts';
    is        $script, 'backup',              'parse_run_args: script with multiple hosts';
    is_deeply $args,   [],                    'parse_run_args: no args with multiple hosts';
}

{
    my ($hosts, $script, $args) = main::_parse_run_args(
        'host-a', 'logger', '--', '-t', 'my-tag', 'my message');
    is_deeply $hosts,  ['host-a'],                       'parse_run_args: host with script args';
    is        $script, 'logger',                          'parse_run_args: script before --';
    is_deeply $args,   ['-t', 'my-tag', 'my message'],   'parse_run_args: args after --';
}

{
    my ($hosts, $script, $args) = main::_parse_run_args(
        'host-a', 'host-b', 'deploy', '--', '--env', 'prod');
    is_deeply $hosts,  ['host-a', 'host-b'],    'parse_run_args: multi-host with script args';
    is        $script, 'deploy',                 'parse_run_args: script multi-host with args';
    is_deeply $args,   ['--env', 'prod'],        'parse_run_args: script args multi-host';
}

{
    # -- with no args after it
    my ($hosts, $script, $args) = main::_parse_run_args('host-a', 'check', '--');
    is_deeply $args, [], 'parse_run_args: -- with no following args';
}

{
    eval { main::_parse_run_args('host-a') };
    like $@, qr/at least one host and a script/, 'parse_run_args: dies with only one arg';
}

{
    eval { main::_parse_run_args() };
    like $@, qr/at least one host and a script/, 'parse_run_args: dies with no args';
}

# --- _format_run_results (output capture) ---

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

{
    my $out = capture_stdout(sub {
        main::_format_run_results([{
            host   => 'host-a',
            exit   => 0,
            stdout => "hello\n",
            stderr => '',
            rtt    => '42ms',
        }]);
    });
    like $out, qr/==> host-a/,   'format_run_results: host in output';
    like $out, qr/OK/,            'format_run_results: OK for exit 0';
    like $out, qr/exit:0/,        'format_run_results: exit code shown';
    like $out, qr/42ms/,          'format_run_results: rtt shown';
    like $out, qr/hello/,         'format_run_results: stdout shown';
}

{
    my $out = capture_stdout(sub {
        main::_format_run_results([{
            host   => 'host-b',
            exit   => 1,
            stdout => '',
            stderr => 'something failed',
            rtt    => '10ms',
            error  => undef,
        }]);
    });
    like $out, qr/FAIL/,             'format_run_results: FAIL for non-zero exit';
    like $out, qr/something failed/, 'format_run_results: stderr shown';
}

{
    my $out = capture_stdout(sub {
        main::_format_run_results([{
            host  => 'host-c',
            exit  => -1,
            error => 'connection refused',
            rtt   => '5ms',
        }]);
    });
    like $out, qr/FAIL/,               'format_run_results: FAIL for error';
    like $out, qr/connection refused/,  'format_run_results: error message shown';
}

# --- _format_ping_results ---

{
    my $out = capture_stdout(sub {
        main::_format_ping_results([{
            host    => 'host-a',
            status  => 'ok',
            rtt     => '55ms',
            expiry  => 'Jun  7 2028',
            version => '0.1',
        }]);
    });
    like $out, qr/host-a/,    'format_ping_results: host shown';
    like $out, qr/ok/,        'format_ping_results: status shown';
    like $out, qr/55ms/,      'format_ping_results: rtt shown';
    like $out, qr/Jun.*2028/, 'format_ping_results: expiry shown';
}

done_testing;
