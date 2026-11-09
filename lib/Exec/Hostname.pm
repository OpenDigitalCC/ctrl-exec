package Exec::Hostname;

use strict;
use warnings;
use feature      qw(signatures);
no warnings      qw(experimental::signatures);

# The one rule for a DNS hostname an agent registers under (T-081, T-084), used
# by the agent (request-pairing --name, the default name) and by the dispatcher
# for a new pairing request. Not Exec::Registry::valid_agent_name, which is
# wider so that records already on disk keep loading.

# One or more dot-separated labels, each 1-63 of letters, digits and hyphens,
# not starting or ending with a hyphen, 253 characters at most.
sub valid ($name) {
    return 0 unless defined $name && length $name <= 253;
    return $name =~ /\A[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\z/ ? 1 : 0;
}

1;
