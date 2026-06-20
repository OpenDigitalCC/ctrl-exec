package Exec::RateLimit;

use strict;
use warnings;
use feature      qw(signatures);
no warnings      qw(experimental::signatures);
use Exec::Log qw();

# Parse a "limit/window/block" rate spec (e.g. "10/60/300") into a validated
# [limit, window, block] arrayref of integers, or undef if malformed. Shared by
# the dispatcher pairing config and the agent config, which each built the same
# split-and-validate-three-ints inline.
sub parse_limit_spec ($raw) {
    return undef unless defined $raw;
    my ($limit, $window, $block) = split m{/}, $raw, 3;
    return undef unless defined $limit  && $limit  =~ /^\d+$/
                     && defined $window && $window =~ /^\d+$/
                     && defined $block  && $block  =~ /^\d+$/;
    return [ int($limit), int($window), int($block) ];
}

# Volume threshold: connections within the short window
use constant VOLUME_WINDOW   => 60;
use constant VOLUME_LIMIT    => 10;
use constant VOLUME_BLOCK    => 300;   # 5 minutes

# Probe threshold: handshake failures within the long window
use constant PROBE_WINDOW    => 600;
use constant PROBE_LIMIT     => 3;
use constant PROBE_BLOCK     => 3600;  # 1 hour

# Pruning window: the longer of the two windows
use constant PRUNE_WINDOW    => 600;

# Maximum number of distinct IP entries before eviction
use constant MAX_ENTRIES     => 1000;


# check($peer_ip, $rate_state_ref, $rate_config) -> 1 (blocked) or 0 (allow)
#
# Called in the parent accept loop before fork(). Checks both volume and probe
# thresholds. Applies a block and logs on first trigger. Returns 1 silently
# for IPs already under an active block.
#
# $rate_config is an optional hashref from $config->{rate_limit}. When absent,
# module constants are used. Keys: disabled, volume_limit, volume_window,
# volume_block, probe_limit, probe_window, probe_block.
sub check ($peer, $state_ref, $rate_config = undef) {
    $rate_config //= {};

    # Disabled: rate limiting turned off entirely
    return 0 if $rate_config->{disabled};

    my $volume_limit  = $rate_config->{volume_limit}  // VOLUME_LIMIT;
    my $volume_window = $rate_config->{volume_window} // VOLUME_WINDOW;
    my $volume_block  = $rate_config->{volume_block}  // VOLUME_BLOCK;
    my $probe_limit   = $rate_config->{probe_limit}   // PROBE_LIMIT;
    my $probe_window  = $rate_config->{probe_window}  // PROBE_WINDOW;
    my $probe_block   = $rate_config->{probe_block}   // PROBE_BLOCK;
    my $prune_window  = ($volume_window > $probe_window)
                      ? $volume_window : $probe_window;

    my $now = time();

    # Step 1: Already blocked?
    if (exists $state_ref->{$peer} &&
        exists $state_ref->{$peer}{blocked_until} &&
        $state_ref->{$peer}{blocked_until} > $now) {
        return 1;
    }

    # Step 2: Block expired - clear entire entry and allow
    if (exists $state_ref->{$peer} &&
        exists $state_ref->{$peer}{blocked_until}) {
        delete $state_ref->{$peer};
        return 0;
    }

    # Step 3: Reclaim space if at capacity. This runs in the single-threaded
    # parent accept loop, so it must not be expensive: a full O(n log n) sort of
    # the table on every connection (the old approach) lets a flood from many
    # distinct source IPs pin the table and turns the limiter into a CPU
    # amplifier for the very DoS it guards. Instead do ONE O(n) pass that drops
    # every entry whose block has already expired (bulk reclaim - the common
    # case under a probe/volume flood, where blocks expire in waves) and tracks
    # the earliest-expiring entry as a fallback victim if the pass frees nothing.
    if (scalar keys %$state_ref >= MAX_ENTRIES) {
        my ($victim, $victim_until);
        for my $k (keys %$state_ref) {
            my $bu = $state_ref->{$k}{blocked_until};
            if (defined $bu && $bu <= $now) {
                delete $state_ref->{$k};   # block expired - reclaim
                next;
            }
            my $until = $bu // 0;
            if (!defined $victim || $until < $victim_until) {
                ($victim, $victim_until) = ($k, $until);
            }
        }
        # If nothing expired (e.g. a flood of distinct never-blocked IPs), evict
        # the single earliest-expiring entry found in the same pass.
        if (defined $victim && scalar keys %$state_ref >= MAX_ENTRIES) {
            delete $state_ref->{$victim};
        }
        Exec::Log::log_action('WARNING', {
            ACTION => 'rate-evict',
            COUNT  => MAX_ENTRIES,
        });
    }

    # Ensure entry exists before pruning
    $state_ref->{$peer} //= { connections => [], failures => [] };
    my $entry = $state_ref->{$peer};

    # Step 4: Prune timestamps older than the longer of the two windows
    $entry->{connections} = [ grep { $now - $_ < $prune_window } @{ $entry->{connections} } ];
    $entry->{failures}    = [ grep { $now - $_ < $prune_window } @{ $entry->{failures}    } ];

    # Step 5: Volume check - count connections within the short window only
    my $recent_conns = grep { $now - $_ < $volume_window } @{ $entry->{connections} };
    if ($volume_limit > 0 && $recent_conns >= $volume_limit) {
        $entry->{blocked_until} = $now + $volume_block;
        Exec::Log::log_action('WARNING', {
            ACTION => 'rate-block',
            PEER   => $peer,
            REASON => 'volume',
        });
        return 1;
    }

    # Step 6: Probe check - count failures within the probe window
    my $recent_fails = grep { $now - $_ < $probe_window } @{ $entry->{failures} };
    if ($probe_limit > 0 && $recent_fails >= $probe_limit) {
        $entry->{blocked_until} = $now + $probe_block;
        Exec::Log::log_action('WARNING', {
            ACTION => 'rate-block',
            PEER   => $peer,
            REASON => 'probe',
        });
        return 1;
    }

    return 0;
}


# record_connection($peer_ip, $rate_state_ref) -> void
#
# Called after check() returns 0, before fork(). Records a post-handshake
# connection timestamp for volume tracking.
sub record_connection ($peer, $state_ref) {
    $state_ref->{$peer} //= { connections => [], failures => [] };
    push @{ $state_ref->{$peer}{connections} }, time();
}


# record_failure($peer_ip, $rate_state_ref) -> void
#
# Called when a TLS handshake failure is detected (item 3 call site). Records
# a failure timestamp for probe tracking.
sub record_failure ($peer, $state_ref) {
    $state_ref->{$peer} //= { connections => [], failures => [] };
    push @{ $state_ref->{$peer}{failures} }, time();
}

1;
