#!/usr/bin/perl
# t/agent-serve-symbols.t
#
# Regression guard for the class of bug that broke 0.12.2: a sub that lives in
# Exec::Agent::Server was called UNQUALIFIED from bin/ctrl-exec-agent's accept
# loop (`_peer_serial($conn)` instead of `Exec::Agent::Server::peer_serial`).
# `use strict` does not catch this - an undefined-subroutine call is a RUNTIME
# error, raised only when a connection is actually accepted - so it sailed past
# `perl -c`, past agent-modulino.t (which only loads the bin), and past the
# handler unit tests (which call the subs directly, already qualified). It
# crashed the agent's main process on the first real connection.
#
# This test reads both source files and asserts the bin makes NO unqualified
# call to any sub defined in Exec::Agent::Server (excluding any same-named sub
# the bin defines itself). The Server sub list is derived from the source, so the
# guard stays correct as handlers are added or renamed - no hand-kept list.

use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);

my $bin_path    = "$Bin/../bin/ctrl-exec-agent";
my $server_path = "$Bin/../lib/Exec/Agent/Server.pm";

ok(-e $bin_path,    'agent bin present');
ok(-e $server_path, 'Server.pm present');

sub slurp_lines {
    my ($path) = @_;
    open my $fh, '<', $path or die "cannot read $path: $!";
    my @lines = <$fh>;
    close $fh;
    return @lines;
}

sub sub_names {
    my (@lines) = @_;
    my %names;
    for my $line (@lines) {
        $names{$1} = 1 if $line =~ /^\s*sub\s+(\w+)\b/;
    }
    return %names;
}

my @server_lines = slurp_lines($server_path);
my @bin_lines    = slurp_lines($bin_path);

my %server_subs = sub_names(@server_lines);
my %bin_subs    = sub_names(@bin_lines);

# Subs that belong to Server and are NOT also defined locally in the bin. Only
# these must always be reached through the Exec::Agent::Server:: qualifier.
my @guarded = sort grep { !$bin_subs{$_} } keys %server_subs;
ok(scalar @guarded, 'found Server subs to guard');

# A call is "unqualified" when the sub name is followed by '(' and is NOT
# preceded by ':' (which would make it Exec::Agent::Server::name(...)) or by a
# word char. Trailing comments are stripped so a name mentioned in prose does
# not trip the guard.
for my $name (@guarded) {
    my @offending;
    my $lineno = 0;
    for my $raw (@bin_lines) {
        $lineno++;
        my $code = $raw;
        $code =~ s/#.*//;                 # drop trailing comment
        next unless $code =~ /(?<![:\w])\Q$name\E\s*\(/;
        push @offending, "$lineno: " . ($raw =~ s/\s+$//r);
    }
    is_deeply(\@offending, [],
        "bin calls Exec::Agent::Server::$name only through the package qualifier")
        or diag("unqualified call(s) to $name (would die at runtime):\n  "
                . join("\n  ", @offending));
}

# Positive assertion: the accept loop reads the peer serial through the
# qualified public name (the fixed call site).
my $bin_src = join '', @bin_lines;
like($bin_src, qr/Exec::Agent::Server::peer_serial\s*\(/,
    'accept loop reads the peer serial via Exec::Agent::Server::peer_serial');

done_testing;
