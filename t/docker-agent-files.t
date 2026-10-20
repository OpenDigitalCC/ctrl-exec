#!/usr/bin/perl
# t/docker-agent-files.t
#
# docs/DOCKER.md shows the agent image's Dockerfile and entrypoint in full, and
# tools/agent-container/ holds the same two files, which the container test
# (tools/agent-container/test.sh) builds and runs. Keep them identical, so the
# files an operator copies from the guide are the ones that were tested (T-048).

use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);

my $root = "$Bin/..";

sub slurp {
    my ($path) = @_;
    open my $fh, '<', $path or die "read $path: $!";
    local $/;
    return scalar <$fh>;
}

my $doc = slurp("$root/docs/DOCKER.md");

# The first fenced block of the given language after the line that names the file.
sub block_after {
    my ($marker, $lang) = @_;
    my $at = index $doc, $marker;
    return undef if $at < 0;
    my $rest = substr $doc, $at;
    return $rest =~ /^```\Q$lang\E\n(.*?)^```$/ms ? $1 : undef;
}

my %files = (
    'tools/agent-container/Dockerfile'    => ['`agent/Dockerfile`',    'dockerfile'],
    'tools/agent-container/entrypoint.sh' => ['`agent/entrypoint.sh`', 'bash'],
);

for my $file (sort keys %files) {
    my ($marker, $lang) = @{ $files{$file} };
    my $shown = block_after($marker, $lang);
    ok defined $shown, "DOCKER.md shows $marker" or next;
    is $shown, slurp("$root/$file"), "DOCKER.md's $marker is $file, byte for byte";
}

ok -x "$root/tools/agent-container/entrypoint.sh", 'the entrypoint is executable';

# The agent services in the sample compose carry the executor's settings.
my $compose = block_after('## compose.yml', 'yaml');
ok defined $compose, 'DOCKER.md shows compose.yml' or done_testing, exit;
like $compose, qr/^  cap_add: \[.*\bSETPCAP\b.*\bSYS_ADMIN\b.*\]$/m,
    'x-hardened-agent adds SETPCAP and SYS_ADMIN';
like $compose, qr/^  security_opt: \[.*apparmor=unconfined.*\]$/m,
    'x-hardened-agent sets apparmor=unconfined';
like $compose, qr/^  agent:\n    <<: \*hardened-agent$/m, 'the agent service uses it';

done_testing;
