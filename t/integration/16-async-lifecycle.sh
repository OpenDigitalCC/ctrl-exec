#!/bin/bash
# 16-async-lifecycle.sh
#
# Exercises the asynchronous (long-running) execution lifecycle end to end
# through the dispatcher CLI:
#
#   - run --async submits detached and returns a reqid immediately
#   - status <reqid> reports per-host progress
#   - wait <reqid> blocks until complete and returns the job output
#   - agent-side concurrency refuses a second async run of the same script
#   - status for an unknown reqid exits non-zero
#   - wait honours --timeout, exiting 2 while a job is still pending
#
# Requires: 1 reachable agent minimum.
# Scripts needed: sleep-5 (~5s), lock-test (sleeps a configurable duration),
#   sleep-test (~30s). All installed by setup-agent-scripts.sh.

set -uo pipefail
source "${_LIB_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}/lib.sh"

require_agents 1

# Extract a top-level JSON string field's value into stdout (grep/sed, no jq).
json_value() {
    local json="$1" field="$2"
    echo "$json" | grep -o "\"${field}\":[^,}]*" | head -1 \
        | sed 's/^"[^"]*":[[:space:]]*//' \
        | sed 's/^"\(.*\)"$/\1/' \
        | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
}

# ============================================================
assert_agents_reachable
describe "Async: run --async returns a reqid and accepts the job"
# ============================================================

run_dispatcher run "$AGENT1" sleep-5 --async --json
assert_exit 0 "$RC" "async submit succeeds"
assert_json_valid "$OUT" "async submit output is valid JSON"
assert_contains "$OUT" '"status":"accepted"' "host accepted the job"

REQID=$(json_value "$OUT" reqid)
[ -n "$REQID" ] \
    && pass "reqid returned: $REQID" \
    || fail "reqid returned" "no reqid in: $OUT"

# ============================================================
assert_agents_reachable
describe "Async: wait blocks until the job completes and returns output"
# ============================================================

if [ -n "$REQID" ]; then
    run_dispatcher wait "$REQID" --timeout 30
    assert_exit 0 "$RC" "wait returns 0 when the job completes successfully"
    assert_contains "$OUT" "COMPLETE" "run reported complete"
    assert_contains "$OUT" "sleep-5: done" "job stdout retrieved via wait"
    assert_contains "$OUT" "done  exit:0" "host finished with exit 0"
else
    skip "wait lifecycle" "no reqid from async submit"
fi

# ============================================================
assert_agents_reachable
describe "Async: status of a completed run is stable and shows the result"
# ============================================================

if [ -n "$REQID" ]; then
    run_dispatcher status "$REQID"
    assert_exit 0 "$RC" "status of a known reqid exits 0"
    assert_contains "$OUT" "COMPLETE" "status still reports complete"
    assert_contains "$OUT" "sleep-5: done" "status shows the stored output"
else
    skip "status of completed run" "no reqid from async submit"
fi

# ============================================================
assert_agents_reachable
describe "Async: a second async run of the same script is refused (busy)"
# ============================================================

# Start a longer job so the second submit lands while it is still running.
run_dispatcher run "$AGENT1" lock-test --async --json -- 10
assert_exit 0 "$RC" "first lock-test async submit accepted"
BUSY_REQID=$(json_value "$OUT" reqid)
assert_contains "$OUT" '"status":"accepted"' "first submit accepted"

# Immediately submit the same script again - the agent should refuse it.
run_dispatcher run "$AGENT1" lock-test --async --json -- 10
assert_contains "$OUT" '"status":"busy"' "concurrent same-script run refused as busy"

# Let the first job finish so it does not leak into later tests.
if [ -n "$BUSY_REQID" ]; then
    run_dispatcher wait "$BUSY_REQID" --timeout 20 >/dev/null 2>&1 || true
fi

# ============================================================
assert_agents_reachable
describe "Async: status of an unknown reqid exits non-zero"
# ============================================================

run_dispatcher status deadbeefdeadbeef
assert_exit 1 "$RC" "unknown reqid exits 1"
assert_contains "$ERR" "No such request" "unknown reqid reports clearly"

# ============================================================
assert_agents_reachable
describe "Async: wait --timeout exits 2 while the job is still pending"
# ============================================================

# sleep-test sleeps ~30s; a 2s wait must time out with the job still running.
run_dispatcher run "$AGENT1" sleep-test --async --json
TIMEOUT_REQID=$(json_value "$OUT" reqid)

if [ -n "$TIMEOUT_REQID" ]; then
    run_dispatcher wait "$TIMEOUT_REQID" --timeout 2
    assert_exit 2 "$RC" "wait times out with exit 2 while pending"
    assert_contains "$OUT" "PENDING" "timed-out wait shows the run still pending"
else
    skip "wait timeout" "no reqid from sleep-test async submit"
fi

summary
