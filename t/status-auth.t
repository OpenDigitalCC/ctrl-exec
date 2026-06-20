use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use FindBin    qw($Bin);
use lib "$Bin/../lib";

use Exec::Auth     qw();
use Exec::RunStore qw();

# GET /status/{reqid} must be owner-gateable: the run store records who submitted
# a run, and a 'status' auth check exposes the reqid + submitter to the hook so it
# can return a run's output only to an authorised caller (closing the disclosure
# where any caller holding a reqid could read any run's output).

my $dir = tempdir(CLEANUP => 1);

# 1. The submitter is recorded with the run.
Exec::RunStore::record_sync(
    reqid => 'deadbeef', script => 'x', hosts => ['h'], results => [],
    runs_dir => $dir, submitter => { username => 'alice', source_ip => '10.0.0.1' },
);
my $rec = Exec::RunStore::load('deadbeef', $dir);
is $rec->{submitter}{username},  'alice',    'submitter username recorded';
is $rec->{submitter}{source_ip}, '10.0.0.1', 'submitter source_ip recorded';

# 2. A 'status' check hands the hook the reqid + submitter, so it can owner-gate.
#    This hook allows only when the bearer token equals the recorded submitter.
my $hook = "$dir/owner-gate";
open my $fh, '>', $hook or die "cannot write hook: $!";
print $fh <<'SH';
#!/bin/sh
[ -n "$ENVEXEC_REQID" ] || exit 1                     # reqid must reach the hook
[ "$ENVEXEC_TOKEN" = "$ENVEXEC_SUBMITTER" ] && exit 0  # owner check
exit 1
SH
close $fh;
chmod 0755, $hook;

my $owner = Exec::Auth::check(
    action    => 'status',
    reqid     => 'deadbeef',
    submitter => { username => 'alice' },
    token     => 'alice',
    config    => { auth_hook => $hook },
);
ok $owner->{ok}, 'the owner (matching token) may read the result';

my $other = Exec::Auth::check(
    action    => 'status',
    reqid     => 'deadbeef',
    submitter => { username => 'alice' },
    token     => 'bob',
    config    => { auth_hook => $hook },
);
ok !$other->{ok}, 'a non-owner (mismatched token) is denied';

done_testing;
