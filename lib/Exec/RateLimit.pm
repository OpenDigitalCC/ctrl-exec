package Exec::RateLimit;

use strict;
use warnings;
use Exec::Log qw();

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
sub check {
    my ($peer, $state_ref, $rate_config) = @_;
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

    # Step 3: Evict one entry if at capacity
    if (scalar keys %$state_ref >= MAX_ENTRIES) {
        my @sorted = sort {
            ($state_ref->{$a}{blocked_until} // 0)
            <=>
            ($state_ref->{$b}{blocked_until} // 0)
        } keys %$state_ref;
        delete $state_ref->{ $sorted[0] };
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


# record_connection($peer_ip, $rate_state_ref, $rate_config) -> void
#
# Called after check() returns 0, before fork(). Records a post-handshake
# connection timestamp for volume tracking. $rate_config is accepted for
# call-site consistency but not used here.
sub record_connection {
    my ($peer, $state_ref, $rate_config) = @_;

    $state_ref->{$peer} //= { connections => [], failures => [] };
    push @{ $state_ref->{$peer}{connections} }, time();
}


# record_failure($peer_ip, $rate_state_ref, $rate_config) -> void
#
# Called when a TLS handshake failure is detected (item 3 call site). Records
# a failure timestamp for probe tracking. $rate_config is accepted for
# call-site consistency but not used here.
sub record_failure {
    my ($peer, $state_ref, $rate_config) = @_;

    $state_ref->{$peer} //= { connections => [], failures => [] };
    push @{ $state_ref->{$peer}{failures} }, time();
}

1;
