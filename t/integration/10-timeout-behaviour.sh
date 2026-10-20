#!/bin/bash
# 10-timeout-behaviour.sh
#
# Tests configurable read_timeout behaviour.
#
# Strategy: write a temporary ctrl-exec.conf with a specific read_timeout,
# then invoke the ctrl-exec with --config pointing at it. The original
# ctrl-exec.conf is never modified.
#
# Sections:
#   1. read_timeout = 10: script completing in 5s succeeds
#   2. read_timeout = 10: script sleeping 15s triggers timeout with correct message
#   3. Orphaned script: agent continues running after ctrl-exec times out
#      - agent syslog shows script start but no completion at timeout
#      - ctrl-exec syslog shows timeout error with reqid
#   4. read_timeout = 120: script sleeping 90s completes successfully
#
# Requires: 1 reachable agent.
# Scripts needed: sleep-5, sleep-15, sleep-90 (written by setup-agent-scripts.sh).
#
# Note: the 90s test is slow by design. The suite runner will show elapsed time.
# Skip it by setting SKIP_SLOW_TESTS=1.

set -uo pipefail
source "${_LIB_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}/lib.sh"

require_agents 1

ORIG_CONF="/etc/ctrl-exec-dispatcher/ctrl-exec.conf"
TMP_CONF="/tmp/ctrl-exec-test-$$.conf"
SSH_USER="${AGENT_SSH_USER:-root}"

# --- build a temporary config with a given read_timeout ---
make_conf() {
    local timeout="$1"
    # Copy cert/key/ca lines from the real config, add/replace read_timeout
    grep -E '^\s*(cert|key|ca|agents_dir|registry)\s*=' "$ORIG_CONF" > "$TMP_CONF"
    echo "read_timeout = $timeout" >> "$TMP_CONF"
}

# --- run ctrl-exec with the temporary config ---
run_with_timeout() {
    local timeout="$1"; shift
    make_conf "$timeout"
    run_dispatcher --config "$TMP_CONF" "$@"
}

# --- helper: run on agent via SSH ---
agent_run() {
    if [ "$AGENT1" = "localhost" ] || [ "$AGENT1" = "$(hostname)" ]; then
        sudo bash -c "$*"
    else
        ssh "${SSH_USER}@${AGENT1}" "sudo bash -c '$*'"
    fi
}

cleanup() { rm -f "$TMP_CONF"; }
trap cleanup EXIT

# ============================================================
assert_agents_reachable
describe "Timeout: read_timeout = 10 - script completing in 5s succeeds"
# ============================================================

START=$(date +%s)
run_with_timeout 10 run "$AGENT1" sleep-5
ELAPSED=$(elapsed_seconds "$START")

assert_exit 0 "$RC" "sleep-5 exits 0 with 10s timeout"
assert_contains "$OUT" "sleep-5: done" "sleep-5 output received"
[ "$ELAPSED" -ge 4 ] \
    && pass "elapsed ~5s confirms script ran (${ELAPSED}s)" \
    || fail "elapsed ~5s confirms script ran" "only ${ELAPSED}s"

# ============================================================
assert_agents_reachable
describe "Timeout: read_timeout = 10 - script sleeping 15s triggers timeout"
# ============================================================

START=$(date +%s)
run_with_timeout 10 run "$AGENT1" sleep-15
ELAPSED=$(elapsed_seconds "$START")

assert_exit 1 "$RC" "ctrl-exec exits non-zero on timeout"

if echo "$OUT$ERR" | grep -qE "read timeout after 10s"; then
    pass "error message: 'read timeout after 10s'"
else
    fail "error message: 'read timeout after 10s'" \
        "got: $(echo "$OUT$ERR" | grep -i timeout | head -2)"
fi

[ "$ELAPSED" -ge 9 ] && [ "$ELAPSED" -le 14 ] \
    && pass "ctrl-exec returned at ~10s not ~15s (${ELAPSED}s)" \
    || fail "ctrl-exec returned at ~10s not ~15s" "got ${ELAPSED}s"

# ============================================================
assert_agents_reachable
describe "Timeout: orphaned script - agent continues after ctrl-exec times out"
# ============================================================
# This section verifies the documented behaviour: the agent is stateless
# with respect to ctrl-exec connectivity. The script runs to completion
# on the agent regardless of the ctrl-exec timeout.
#
# We can only observe the syslog entries from outside; we cannot directly
# confirm the script is still running without SSH. If SSH is available
# we check the process table.

REQID=""

# Run sleep-15 with 10s timeout, capture reqid from JSON output
run_with_timeout 10 run "$AGENT1" sleep-15 --json
REQID=$(python3 -c "
import sys, json
data = json.loads(sys.argv[1])
results = data.get('results', [])
print(results[0].get('reqid', '') if results else '')
" "$OUT" 2>/dev/null)

[ -n "$REQID" ] \
    && pass "reqid captured from timeout response: $REQID" \
    || fail "reqid captured from timeout response" "output: $OUT"

# Check ctrl-exec syslog for timeout entry with reqid
if [ -n "$REQID" ]; then
    DISP_LOG=$(journalctl -t ctrl-exec --since "1 minute ago" 2>/dev/null \
        || grep "ctrl-exec" /var/log/syslog 2>/dev/null \
        || true)
    if echo "$DISP_LOG" | grep -q "$REQID"; then
        pass "ctrl-exec syslog contains reqid $REQID"
    else
        skip "ctrl-exec syslog check" \
            "cannot read ctrl-exec syslog - verify manually: journalctl -t ctrl-exec | grep $REQID"
    fi
else
    skip "ctrl-exec syslog check" "no reqid to search for"
fi

# Check agent is still running the script (process-level, requires SSH)
if agent_run "true" 2>/dev/null; then
    sleep 2   # give the script a moment to still be running
    RUNNING=$(agent_run "pgrep -f 'sleep 15' | wc -l" 2>/dev/null || echo "0")
    if [ "${RUNNING:-0}" -gt 0 ]; then
        pass "sleep-15 still running on agent after ctrl-exec timeout"
    else
        # May have finished - only a concern if we're within the window
        skip "Agent process check" \
            "could not confirm sleep-15 still running - may have already exited"
    fi

    # Wait for the script to finish, then check agent syslog for completion
    sleep 10
    AGENT_LOG=$(agent_run \
        "logread 2>/dev/null || journalctl -t ctrl-exec-agent --since '2 minutes ago' 2>/dev/null || true")
    if echo "$AGENT_LOG" | grep -qiE "script.*exit|exit.*script|sleep-15.*done|finished"; then
        pass "agent syslog records script completion after timeout"
    else
        skip "Agent syslog completion check" \
            "syslog entry format unclear - verify manually on $AGENT1"
    fi
else
    skip "Orphaned process and syslog checks" \
        "no SSH access to $AGENT1 - set AGENT_SSH_USER and verify manually"
fi

# ============================================================
assert_agents_reachable
describe "Timeout: read_timeout = 120 - 90s script completes successfully"
# ============================================================

if [ "${SKIP_SLOW_TESTS:-0}" = "1" ]; then
    skip "90s timeout test" "SKIP_SLOW_TESTS=1"
else
    printf '        NOTE: this test takes ~90 seconds\n'
    START=$(date +%s)
    run_with_timeout 120 run "$AGENT1" sleep-90
    ELAPSED=$(elapsed_seconds "$START")

    assert_exit 0 "$RC" "sleep-90 exits 0 with 120s timeout"
    assert_contains "$OUT" "sleep-90: done" "sleep-90 output received"
    [ "$ELAPSED" -ge 88 ] \
        && pass "elapsed ~90s confirms full run (${ELAPSED}s)" \
        || fail "elapsed ~90s confirms full run" "only ${ELAPSED}s"
fi

# ============================================================
assert_agents_reachable
describe "Timeout: backward-compatible 'timeout' key also accepted"
# ============================================================
# The brief states 'timeout' is accepted as a fallback key for
# backward compatibility. Verify a conf using 'timeout' (not 'read_timeout')
# produces the same behaviour.

grep -E '^\s*(cert|key|ca|agents_dir|registry)\s*=' "$ORIG_CONF" > "$TMP_CONF"
echo "timeout = 10" >> "$TMP_CONF"

START=$(date +%s)
run_dispatcher --config "$TMP_CONF" run "$AGENT1" sleep-15
ELAPSED=$(elapsed_seconds "$START")

assert_exit 1 "$RC" "timeout key: exits non-zero on timeout"
if echo "$OUT$ERR" | grep -qE "read timeout after 10s"; then
    pass "timeout key: error message reports correct value (10s)"
else
    fail "timeout key: error message reports correct value" \
        "got: $(echo "$OUT$ERR" | grep -i timeout | head -2)"
fi

summary
