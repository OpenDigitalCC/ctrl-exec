#!/bin/bash
# 12-serial-check.sh
#
# Verifies that /run and /ping enforce the trusted-dispatcher map check.
#
# The agent loads its trusted-dispatcher map from
# /etc/ctrl-exec-agent/ctrl-exec-dispatchers (or the path configured by
# trusted_dispatchers_path). Each line maps a dispatcher cert serial to that
# dispatcher's identity, recorded at pairing time. A connecting cert is accepted
# only if its serial is a key in the map.
#
# Three behaviours to confirm:
#   1. Normal operation: ping and run succeed when the peer serial is in the map
#   2. Map absent: ping and run return 403 when the map file is removed
#   3. /renew exemption: an absent map does not break cert renewal
#      (covered by manual validation only - no /renew command in the CLI)
#
# These tests require SSH access to AGENT1 to move and restore the map
# file and send SIGHUP. Set AGENT_SSH_USER if the agent is not reachable
# as root via SSH (defaults to root).
#
# Requires: 1 reachable agent.
# Scripts needed: env-dump (for /run tests).

set -uo pipefail
source "${_LIB_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}/lib.sh"

require_agents 1

SSH_USER="${AGENT_SSH_USER:-root}"
# The trusted-dispatcher map; removing it empties the agent's trust set so every
# /run, /ping, /result and /capabilities is rejected (serial not in the map).
SERIAL_FILE="/etc/ctrl-exec-agent/ctrl-exec-dispatchers"
SERIAL_BAK="/etc/ctrl-exec-agent/ctrl-exec-dispatchers.bak"

# --- helpers ---

agent_run() {
    if [ "$AGENT1" = "localhost" ] || [ "$AGENT1" = "$(hostname 2>/dev/null || uname -n)" ]; then
        sudo bash -c "$*"
    else
        ssh "${SSH_USER}@${AGENT1}" "sudo bash -c '$*'"
    fi
}

agent_ssh_available() {
    if [ "$AGENT1" = "localhost" ] || [ "$AGENT1" = "$(hostname 2>/dev/null || uname -n)" ]; then
        return 0
    fi
    ssh -o BatchMode=yes -o ConnectTimeout=5 "${SSH_USER}@${AGENT1}" true 2>/dev/null
}

agent_reload() {
    agent_run 'systemctl reload ctrl-exec-agent 2>/dev/null || \
        ([ -f /etc/init.d/ctrl-exec-agent ] && /etc/init.d/ctrl-exec-agent reload 2>/dev/null) || \
        kill -HUP $(cat /var/run/ctrl-exec-agent.pid 2>/dev/null || \
                    cat /run/ctrl-exec-agent.pid 2>/dev/null) 2>/dev/null || \
        pkill -HUP -x ctrl-exec-agent 2>/dev/null || true'
    sleep 1
}

json_field() {
    python3 -c "
import sys, json
try:
    data = json.loads(sys.argv[1])
    # check top-level first, then results[0]
    if sys.argv[2] in data:
        print(data[sys.argv[2]])
    else:
        results = data.get('results', [])
        if results:
            print(results[0].get(sys.argv[2], '__MISSING__'))
        else:
            print('__MISSING__')
except Exception:
    print('__MISSING__')
" "$1" "$2" 2>/dev/null
}

# Restore serial file and reload agent on exit (even on set -e failure)
_SERIAL_MOVED=0
cleanup() {
    if [ "$_SERIAL_MOVED" -eq 1 ]; then
        agent_run "[ -f '$SERIAL_BAK' ] && mv '$SERIAL_BAK' '$SERIAL_FILE' || true" 2>/dev/null
        agent_reload 2>/dev/null
        _SERIAL_MOVED=0
    fi
}
trap cleanup EXIT

# ============================================================
assert_agents_reachable
describe "Trusted-dispatcher map: ping and run succeed when the peer serial is in the map"
# ============================================================

run_dispatcher ping "$AGENT1" --json
assert_exit 0 "$RC" "ping exits 0 with matching serial"
assert_json_valid "$OUT" "ping returns valid JSON"

STATUS=$(json_field "$OUT" "status")
[ "$STATUS" = "ok" ] \
    && pass "ping status is ok" \
    || fail "ping status is ok" "got: $STATUS"

run_dispatcher run "$AGENT1" env-dump --json
assert_exit 0 "$RC" "run exits 0 with matching serial"
assert_json_valid "$OUT" "run returns valid JSON"

EXIT=$(json_field "$OUT" "exit")
[ "$EXIT" = "0" ] \
    && pass "run exit code is 0" \
    || fail "run exit code is 0" "got: $EXIT"

# ============================================================
assert_agents_reachable
describe "Trusted-dispatcher map: ping and run return 403 when the map file is absent"
# ============================================================

if ! agent_ssh_available; then
    skip "Serial absent tests" \
         "no SSH access to $AGENT1 - set AGENT_SSH_USER and verify manually"
    skip "Serial absent tests (run)" \
         "no SSH access to $AGENT1 - set AGENT_SSH_USER and verify manually"
else
    # Confirm serial file exists before proceeding
    if ! agent_run "[ -f '$SERIAL_FILE' ]"; then
        skip "Map absent: ping returns 403" \
             "ctrl-exec-dispatchers not present on $AGENT1 - re-pair before testing"
        skip "Map absent: run returns 403" \
             "ctrl-exec-dispatchers not present on $AGENT1 - re-pair before testing"
    else
        # Move the serial file away and reload
        agent_run "mv '$SERIAL_FILE' '$SERIAL_BAK'"
        _SERIAL_MOVED=1
        agent_reload

        run_dispatcher ping "$AGENT1" --json
        assert_exit 1 "$RC" "ping exits non-zero with no serial file"
        assert_json_valid "$OUT" "ping returns valid JSON on 403"

        ERROR=$(json_field "$OUT" "error")
        echo "$ERROR" | grep -qi "serial\|forbidden\|mismatch" \
            && pass "ping error field mentions serial or forbidden" \
            || fail "ping error field mentions serial or forbidden" "got: $ERROR"

        run_dispatcher run "$AGENT1" env-dump --json
        assert_exit 1 "$RC" "run exits non-zero with no serial file"
        assert_json_valid "$OUT" "run returns valid JSON on 403"

        ERROR=$(json_field "$OUT" "error")
        echo "$ERROR" | grep -qi "serial\|forbidden\|mismatch" \
            && pass "run error field mentions serial or forbidden" \
            || fail "run error field mentions serial or forbidden" "got: $ERROR"

        # Restore and confirm normal operation resumes
        agent_run "mv '$SERIAL_BAK' '$SERIAL_FILE'"
        _SERIAL_MOVED=0
        agent_reload

        run_dispatcher ping "$AGENT1" --json
        assert_exit 0 "$RC" "ping succeeds after serial file restored"

        run_dispatcher run "$AGENT1" env-dump --json
        assert_exit 0 "$RC" "run succeeds after serial file restored"
    fi
fi

# ============================================================
assert_agents_reachable
describe "Serial check: syslog confirms serial-reject logged on 403"
# ============================================================

if ! agent_ssh_available; then
    skip "Syslog serial-reject verification" \
         "no SSH access to $AGENT1 - set AGENT_SSH_USER and verify manually"
else
    skip "Syslog serial-reject verification" \
         "requires live 403 trigger with syslog read - verify manually:
        journalctl -t ctrl-exec-agent | grep serial-reject"
fi

summary
