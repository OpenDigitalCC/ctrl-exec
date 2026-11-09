package Exec::Hostname;

use strict;
use warnings;
use feature      qw(signatures);
no warnings      qw(experimental::signatures);

# Hostname rules for an agent's name. valid() is the strict rule for
# request-pairing --name (T-081); has_empty_label() is what the default name and
# a new pairing request are checked for (T-084). Exec::Registry::valid_agent_name
# stays the wider rule so that records already on disk keep loading.

# One or more dot-separated labels, each 1-63 of letters, digits and hyphens,
# not starting or ending with a hyphen, 253 characters at most.
sub valid ($name) {
    return 0 unless defined $name && length $name <= 253;
    return $name =~ /\A[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\z/ ? 1 : 0;
}

# True when $name has an empty label: a leading or trailing dot, or two dots
# together ('host..', 'host.'). The one thing a default name and a new pairing
# request are refused for (R-029); other characters, such as '_', stay
# allowed as before, so hosts that paired before still pair.
sub has_empty_label ($name) {
    return defined $name && $name =~ /(?:\A\.|\.\.|\.\z)/ ? 1 : 0;
}

1;
