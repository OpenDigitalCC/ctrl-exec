#!/bin/bash
# 15-agent-auth-context.sh
#
# Verifies that the agent-side auth hook receives the correct context fields
# for every run request: action, script, username, token, and source_ip.
#
# Design:
#   The auth-context-check hook (installed by setup-agent-scripts.sh
#   --install-auth-test) writes all received DISPATCHER_* env vars to a
#   status file on the agent at /tmp/ctrl-exec-auth-test-status on every
#   call. The allowlisted script auth-status-dump retrieves that file via a
#   subsequent dispatch, without requiring SSH access to the agent.
#
#   A passing dispatch with known values populates the status file. The
#   source IP is read back from it, so no hardcoding is needed.
#
#   Denial tests send a wrong or missing field. The hook writes the status
#   file before applying policy, so the test can confirm what was received
#   even for denied requests.
#
# Requires:
#   setup-agent-scripts.sh --install-auth-test run on at least one registered
#   agent before this test. The test scans all reachable agents for one with
#   auth-status-dump in its allowlist and runs against that agent. Skips
#   cleanly if no qualifying agent is found.
#
# Cleanup:
#   This test does not modify agent state. The hook and agent.conf changes
#   are installed and removed by setup-agent-scripts.sh --install-auth-test
#   and --remove-auth-test respectively.

set -uo pipefail
source "${_LIB_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}/lib.sh"

require_agents 1

# --- find an agent with auth-status-dump configured ---
#
# Attempt to dispatch auth-status-dump against each reachable agent.
# The script exits 1 if the status file does not yet exist (no prior call),
# so we accept both exit 0 and exit 1 as evidence the script is present and
# reachable. Exit 1 from a missing status file produces "STATUS_FILE_NOT_FOUND"
# on stdout; a true "not permitted" denial produces no stdout and a ctrl-exec
# error on stderr. We distinguish these by checking stdout content.

AUTH_AGENT=""
for _candidate in "${AGENTS[@]}"; do
    _probe_out=$(sudo "$DISPATCHER" run "$_candidate" auth-status-dump \
        --username "test-user" --token "test-token-value" 2>/dev/null || true)
    # Accept if script ran: output is either status vars or STATUS_FILE_NOT_FOUND
    if echo "$_probe_out" | grep -qE "^DISPATCHER_|STATUS_FILE_NOT_FOUND"; then
        AUTH_AGENT="$_candidate"
        break
    fi
done

if [ -z "$AUTH_AGENT" ]; then
    skip "Agent auth context tests" \
        "auth-status-dump not available on any agent — run: sudo bash setup-agent-scripts.sh --install-auth-test"
    summary
    exit 0
fi

# --- helper: read status file from agent via dispatch ---

read_status_file() {
    run_dispatcher run "$AUTH_AGENT" auth-status-dump \
        --username "test-user" --token "test-token-value"
    echo "$OUT"
}

parse_field() {
    # parse_field <status_output> <field_name>
    echo "$1" | grep "^${2}=" | cut -d= -f2-
}

# ============================================================
assert_agents_reachable
describe "Auth context: passing request with known values"
# ============================================================

run_dispatcher run "$AUTH_AGENT" args-echo \
    --username "test-user" --token "test-token-value" -- first second

assert_exit 0 "$RC" "dispatch with correct values succeeds"
assert_contains "$OUT" "[1] first" "script executed (args present)"

# ============================================================
describe "Auth context: status file populated after passing request"
# ============================================================

STATUS=$(read_status_file)

assert_exit 0 "$RC" "auth-status-dump retrieved status file"

if echo "$STATUS" | grep -q "^ENVEXEC_ACTION="; then
    pass "ENVEXEC_ACTION present in status file"
else
    fail "ENVEXEC_ACTION present in status file" "status: $STATUS"
fi

# ============================================================
describe "Auth context: ENVEXEC_ACTION is 'run'"
# ============================================================

ACTION=$(parse_field "$STATUS" "ENVEXEC_ACTION")
[ "$ACTION" = "run" ] \
    && pass "ENVEXEC_ACTION = run" \
    || fail "ENVEXEC_ACTION = run" "got: '$ACTION'"

# ============================================================
describe "Auth context: ENVEXEC_SCRIPT matches requested script"
# ============================================================

# The status file was written during the args-echo call above.
SCRIPT=$(parse_field "$STATUS" "ENVEXEC_SCRIPT")
[ "$SCRIPT" = "args-echo" ] \
    && pass "ENVEXEC_SCRIPT = args-echo" \
    || fail "ENVEXEC_SCRIPT = args-echo" "got: '$SCRIPT'"

# ============================================================
describe "Auth context: ENVEXEC_USERNAME forwarded correctly"
# ============================================================

USERNAME=$(parse_field "$STATUS" "ENVEXEC_USERNAME")
[ "$USERNAME" = "test-user" ] \
    && pass "ENVEXEC_USERNAME = test-user" \
    || fail "ENVEXEC_USERNAME = test-user" "got: '$USERNAME'"

# ============================================================
describe "Auth context: ENVEXEC_TOKEN forwarded correctly"
# ============================================================

TOKEN=$(parse_field "$STATUS" "ENVEXEC_TOKEN")
[ "$TOKEN" = "test-token-value" ] \
    && pass "ENVEXEC_TOKEN = test-token-value" \
    || fail "ENVEXEC_TOKEN = test-token-value" "got: '$TOKEN'"

# ============================================================
describe "Auth context: ENVEXEC_SOURCE_IP is non-empty"
# ============================================================

SOURCE_IP=$(parse_field "$STATUS" "ENVEXEC_SOURCE_IP")
if [ -n "$SOURCE_IP" ]; then
    pass "ENVEXEC_SOURCE_IP is non-empty: $SOURCE_IP"
else
    fail "ENVEXEC_SOURCE_IP is non-empty" "was empty or missing"
fi

# ============================================================
describe "Auth context: ENVEXEC_DISPATCHER carries the calling dispatcher's identity"
# ============================================================

# The agent resolves the connecting cert serial to a trusted dispatcher identity
# and passes it to the hook. It is non-empty whenever the caller is a trusted
# dispatcher (which it must be to have reached the hook at all).
DISPATCHER_ID=$(parse_field "$STATUS" "ENVEXEC_DISPATCHER")
if [ -n "$DISPATCHER_ID" ]; then
    pass "ENVEXEC_DISPATCHER is non-empty: $DISPATCHER_ID"
else
    fail "ENVEXEC_DISPATCHER is non-empty" "was empty or missing"
fi

# Record the observed ctrl-exec IP for the remainder of the test.
DISPATCHER_IP="$SOURCE_IP"

# ============================================================
assert_agents_reachable
describe "Auth context: wrong username is denied"
# ============================================================

run_dispatcher run "$AUTH_AGENT" args-echo \
    --username "wrong-user" --token "test-token-value" -- probe

assert_exit 1 "$RC" "wrong username: ctrl-exec exits non-zero"
assert_not_contains "$OUT" "[1] probe" "wrong username: script did not execute"

STATUS=$(read_status_file)
RECORDED_USER=$(parse_field "$STATUS" "ENVEXEC_USERNAME")
[ "$RECORDED_USER" = "wrong-user" ] \
    && pass "wrong username: hook received the incorrect value before denying" \
    || fail "wrong username: hook received the incorrect value before denying" \
            "got: '$RECORDED_USER'"

# ============================================================
assert_agents_reachable
describe "Auth context: wrong token is denied"
# ============================================================

run_dispatcher run "$AUTH_AGENT" args-echo \
    --username "test-user" --token "wrong-token" -- probe

assert_exit 1 "$RC" "wrong token: ctrl-exec exits non-zero"
assert_not_contains "$OUT" "[1] probe" "wrong token: script did not execute"

STATUS=$(read_status_file)
RECORDED_TOKEN=$(parse_field "$STATUS" "ENVEXEC_TOKEN")
[ "$RECORDED_TOKEN" = "wrong-token" ] \
    && pass "wrong token: hook received the incorrect value before denying" \
    || fail "wrong token: hook received the incorrect value before denying" \
            "got: '$RECORDED_TOKEN'"

# ============================================================
assert_agents_reachable
describe "Auth context: missing token is denied"
# ============================================================

run_dispatcher run "$AUTH_AGENT" args-echo \
    --username "test-user" -- probe

assert_exit 1 "$RC" "missing token: ctrl-exec exits non-zero"
assert_not_contains "$OUT" "[1] probe" "missing token: script did not execute"

STATUS=$(read_status_file)
RECORDED_TOKEN=$(parse_field "$STATUS" "ENVEXEC_TOKEN")
[ -z "$RECORDED_TOKEN" ] \
    && pass "missing token: hook received empty token before denying" \
    || fail "missing token: hook received empty token before denying" \
            "got: '$RECORDED_TOKEN'"

# ============================================================
assert_agents_reachable
describe "Auth context: missing username is denied"
# ============================================================

# When --username is omitted, the ctrl-exec substitutes the invoking user
# (typically root when run via sudo). The hook receives a non-empty username
# that does not match the approved value and correctly denies.

run_dispatcher run "$AUTH_AGENT" args-echo \
    --token "test-token-value" -- probe

assert_exit 1 "$RC" "missing username: ctrl-exec exits non-zero"
assert_not_contains "$OUT" "[1] probe" "missing username: script did not execute"

STATUS=$(read_status_file)
RECORDED_USER=$(parse_field "$STATUS" "ENVEXEC_USERNAME")
[ "$RECORDED_USER" != "test-user" ] \
    && pass "missing username: hook received non-approved username before denying ($RECORDED_USER)" \
    || fail "missing username: hook received non-approved username before denying" \
            "got approved value 'test-user' — username was not substituted"

# ============================================================
assert_agents_reachable
describe "Auth context: source IP is consistent across requests"
# ============================================================

# Run a second passing request and confirm source IP matches the first.
run_dispatcher run "$AUTH_AGENT" args-echo \
    --username "test-user" --token "test-token-value" -- verify

assert_exit 0 "$RC" "second passing request succeeds"

STATUS=$(read_status_file)
SOURCE_IP2=$(parse_field "$STATUS" "ENVEXEC_SOURCE_IP")

[ "$SOURCE_IP2" = "$DISPATCHER_IP" ] \
    && pass "ENVEXEC_SOURCE_IP consistent: $DISPATCHER_IP" \
    || fail "ENVEXEC_SOURCE_IP consistent" \
            "first=$DISPATCHER_IP second=$SOURCE_IP2"

summary
