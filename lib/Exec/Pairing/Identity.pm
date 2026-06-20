package Exec::Pairing::Identity;

# Source-IP identity diagnostics for pairing: forward-confirmed reverse DNS and
# the operator-facing lines/recommendation derived from it. Split out of
# Exec::Pairing - a self-contained leaf (no pairing-protocol state) used by the
# interactive approval UI and recorded at queue time.

use strict;
use warnings;
use Socket qw(getaddrinfo getnameinfo
              AI_NUMERICHOST NI_NAMEREQD NI_NUMERICHOST NIx_NOSERV);

# Forward-confirmed reverse DNS of an IP. Returns { ptr => $name, confirmed => 0|1 }
# or undef when there is no usable PTR (or the lookup times out). 'confirmed' is
# true only when the PTR name forward-resolves back to the same IP, which guards
# against a host claiming a name it does not actually own. Bounded by $timeout
# (default 2s) so a missing or slow resolver cannot hang an interactive prompt.
sub reverse_lookup {
    my ($ip, $timeout) = @_;
    $timeout //= 2;
    return undef unless defined $ip && length $ip && $ip ne 'unknown';

    my $out = eval {
        local $SIG{ALRM} = sub { die "timeout\n" };
        alarm $timeout;

        # Build a sockaddr for the numeric IP (AI_NUMERICHOST = no DNS here).
        my ($aerr, @ai) = getaddrinfo($ip, '', { flags => AI_NUMERICHOST });
        die "addr\n" if $aerr || !@ai;

        # PTR. NI_NAMEREQD makes a missing PTR an error rather than echoing the
        # numeric IP back as the "name".
        my ($nerr, $name) = getnameinfo($ai[0]{addr}, NI_NAMEREQD, NIx_NOSERV);
        die "ptr\n" if $nerr || !defined $name || !length $name;

        # Forward-confirm: the PTR name must resolve back to the same IP.
        my ($ferr, @fa) = getaddrinfo($name, '');
        my $confirmed = 0;
        unless ($ferr) {
            for my $a (@fa) {
                my ($gerr, $host) = getnameinfo($a->{addr}, NI_NUMERICHOST, NIx_NOSERV);
                next if $gerr;
                if (defined $host && $host eq $ip) { $confirmed = 1; last }
            }
        }
        { ptr => $name, confirmed => $confirmed };
    };
    alarm 0;
    return $out;   # undef on timeout or any failure
}

# Operator-facing identity lines for a queued request: the reported name (which
# becomes the registry key), the source IP as this dispatcher saw it, the
# agent's self-reported IP when it differs (a sign of NAT in between), and the
# forward-confirmed reverse-DNS name. Reverse-DNS fields are read from the
# request record (resolved once at queue time), not looked up again here.
sub identity_lines {
    my ($req) = @_;
    my @lines;
    push @lines, sprintf("  Reported name: %s   (becomes the registry key)",
        $req->{hostname} // '?');
    push @lines, sprintf("  Source IP:     %s   (as this dispatcher saw the connection)",
        $req->{source_ip} // '?');
    if (defined $req->{ip} && length $req->{ip}
        && defined $req->{source_ip} && $req->{ip} ne $req->{source_ip}) {
        push @lines, sprintf("  Reported IP:   %s   (agent self-reported; differs - NAT?)",
            $req->{ip});
    }
    if (length($req->{reverse_dns} // '')) {
        push @lines, sprintf("  Reverse DNS:   %s   (%s)",
            $req->{reverse_dns},
            $req->{reverse_confirmed} ? 'forward-confirmed' : 'unconfirmed');
    }
    else {
        push @lines, "  Reverse DNS:   (none resolvable from this dispatcher)";
    }
    return @lines;
}

# A one-or-two-line recommendation for how to register the agent so this
# dispatcher can actually reach it, keyed on the reverse-DNS signal. Returns a
# (possibly multi-line) string, or '' when nothing useful can be said.
sub identity_recommendation {
    my ($req) = @_;
    my $name = $req->{hostname}  // '';
    my $src  = $req->{source_ip} // '';
    my $rev  = $req->{reverse_dns} // '';
    my $conf = $req->{reverse_confirmed} ? 1 : 0;

    if ($conf && length $rev && lc $rev ne lc $name) {
        return "Recommendation: this dispatcher resolves the agent's IP to '$rev'"
             . " (forward-confirmed), which differs from the reported name '$name'.\n"
             . "  If '$name' does not resolve here, register the resolvable name:\n"
             . "    ctrl-exec-dispatcher edit-agent $name --rename $rev";
    }
    if ($conf && length $rev) {
        return "Recommendation: reported name '$name' is forward-confirmed by"
             . " reverse DNS; lookup_by=hostname should resolve from here.";
    }
    return "Recommendation: could not forward-confirm a name for the agent's"
         . " source IP from this dispatcher.\n"
         . "  If '$name' does not resolve here, dispatch by IP instead:\n"
         . "    ctrl-exec-dispatcher edit-agent $name --lookup-by ip"
         . (length $src ? " --ip $src" : '');
}

1;
