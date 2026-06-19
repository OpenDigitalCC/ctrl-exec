#!/bin/bash
# setup-agent-scripts.sh
#
# Install test scripts on a ctrl-exec agent and enable them in scripts.conf.
# Run this on each agent host before running the integration tests.
#
# Usage:
#   sudo bash setup-agent-scripts.sh                      # install standard test scripts
#   sudo bash setup-agent-scripts.sh --install-auth-test  # also install auth context test hook
#   sudo bash setup-agent-scripts.sh --remove-auth-test   # remove auth context test hook and restore agent.conf
#
# Default (no args):
#   - Writes test scripts to /opt/ctrl-exec-scripts/
#   - Appends entries to /etc/ctrl-exec-agent/scripts.conf (if not present)
#   - Sends SIGHUP to reload the allowlist
#
# --install-auth-test additionally:
#   - Writes the auth-context-check hook to /etc/ctrl-exec-agent/auth-context-check.sh
#   - Writes auth-status-dump script to /opt/ctrl-exec-scripts/
#   - Appends auth-status-dump to scripts.conf
#   - Backs up agent.conf and appends auth_hook line
#   - Sends SIGHUP to reload
#
# --remove-auth-test:
#   - Removes the auth-context-check hook file
#   - Removes auth-status-dump script and its allowlist entry from scripts.conf
#   - Restores agent.conf from backup, or strips the auth_hook line if no backup exists
#   - Sends SIGHUP to reload
#
# Safe to run multiple times - checks before appending.

set -euo pipefail

# Prevent BASH_ENV from auto-sourcing lib.sh if set from a prior test session.
unset BASH_ENV ENV

SCRIPT_DIR="/opt/ctrl-exec-scripts"
CONF="/etc/ctrl-exec-agent/scripts.conf"

mkdir -p "$SCRIPT_DIR"

# --- write test scripts ---

cat > "$SCRIPT_DIR/env-dump.sh" << 'EOF'
#!/bin/sh
exec 0</dev/null
env | sort
EOF

cat > "$SCRIPT_DIR/big-output.sh" << 'EOF'
#!/bin/sh
exec 0</dev/null
# Default 500 lines; pass a count as $1 to override.
count="${1:-500}"
i=1
while [ "$i" -le "$count" ]; do
    echo "line $i of output from $(hostname 2>/dev/null || uname -n)"
    i=$((i + 1))
done
EOF

cat > "$SCRIPT_DIR/sleep-test.sh" << 'EOF'
#!/bin/sh
exec 0</dev/null
echo "sleeping on $(hostname 2>/dev/null || uname -n)"
sleep 30
echo "done"
EOF

cat > "$SCRIPT_DIR/args-echo.sh" << 'EOF'
#!/bin/sh
exec 0</dev/null
echo "argc: $#"
i=1
for arg in "$@"; do
    echo "[$i] $arg"
    i=$((i + 1))
done
EOF

cat > "$SCRIPT_DIR/exit-code.sh" << 'EOF'
#!/bin/sh
# Returns the exit code passed as $1, or 0 if none given.
exec 0</dev/null
code="${1:-0}"
echo "exiting with code $code"
exit "$code"
EOF

cat > "$SCRIPT_DIR/context-dump.sh" << 'EOF'
#!/bin/sh
# Reads JSON context from stdin and echoes it to stdout unchanged.
# Used to verify username, token, reqid forwarding.
cat
EOF

cat > "$SCRIPT_DIR/lock-test.sh" << 'EOF'
#!/bin/sh
# Sleeps for the number of seconds given as $1 (default 10).
# Used to hold a lock while a concurrent dispatch is attempted.
exec 0</dev/null
secs="${1:-10}"
echo "lock-test holding for ${secs}s on $(hostname 2>/dev/null || uname -n)"
sleep "$secs"
echo "lock-test done"
EOF

cat > "$SCRIPT_DIR/allowlist-reload-check.sh" << 'EOF'
#!/bin/sh
# Simple script added after initial setup to verify SIGHUP reload works.
exec 0</dev/null
echo "allowlist-reload-check: ok on $(hostname 2>/dev/null || uname -n)"
EOF

cat > "$SCRIPT_DIR/sleep-5.sh" << 'EOF'
#!/bin/sh
# Sleeps 5 seconds. Used for timeout testing (should complete within 10s timeout).
exec 0</dev/null
echo "sleep-5: starting on $(hostname 2>/dev/null || uname -n)"
sleep 5
echo "sleep-5: done"
EOF

cat > "$SCRIPT_DIR/sleep-15.sh" << 'EOF'
#!/bin/sh
# Sleeps 15 seconds. Used to trigger the 10s read timeout.
# Will continue running on the agent after the ctrl-exec times out.
exec 0</dev/null
echo "sleep-15: starting on $(hostname 2>/dev/null || uname -n)"
sleep 15
echo "sleep-15: done"
EOF

cat > "$SCRIPT_DIR/sleep-90.sh" << 'EOF'
#!/bin/sh
# Sleeps 90 seconds. Used to verify read_timeout = 120 allows long runs.
exec 0</dev/null
echo "sleep-90: starting on $(hostname 2>/dev/null || uname -n)"
sleep 90
echo "sleep-90: done"
EOF

cat > "$SCRIPT_DIR/daemonise-test.sh" << 'EOF'
#!/bin/sh
# Immediately daemonises and returns a job reference via stdout.
# The background job writes its completion to a temp file.
# Demonstrates the async pattern for callers that cannot block.
REQID="job-$$-$(date +%s)"
OUTFILE="/tmp/ctrl-exec-job-${REQID}.out"

# Fork into background, redirect all output to file
(
    echo "daemonise-test: background job $REQID starting"
    sleep 10
    echo "daemonise-test: background job $REQID complete"
) > "$OUTFILE" 2>&1 &

# Return immediately with job reference
echo "{\"job_id\":\"$REQID\",\"output_file\":\"$OUTFILE\"}"
EOF

chmod 0755 \
    "$SCRIPT_DIR/env-dump.sh" \
    "$SCRIPT_DIR/big-output.sh" \
    "$SCRIPT_DIR/sleep-test.sh" \
    "$SCRIPT_DIR/args-echo.sh" \
    "$SCRIPT_DIR/exit-code.sh" \
    "$SCRIPT_DIR/context-dump.sh" \
    "$SCRIPT_DIR/lock-test.sh" \
    "$SCRIPT_DIR/allowlist-reload-check.sh" \
    "$SCRIPT_DIR/sleep-5.sh" \
    "$SCRIPT_DIR/sleep-15.sh" \
    "$SCRIPT_DIR/sleep-90.sh" \
    "$SCRIPT_DIR/daemonise-test.sh"

echo "Scripts written to $SCRIPT_DIR"

# --- append allowlist entries if missing ---

append_if_missing() {
    local name="$1" path="$2"
    if grep -qE "^${name}\s*=" "$CONF" 2>/dev/null; then
        echo "  $name already in $CONF"
    else
        echo "$name = $path" >> "$CONF"
        echo "  Added: $name = $path"
    fi
}

echo "Updating $CONF ..."
append_if_missing "env-dump"                  "$SCRIPT_DIR/env-dump.sh"
append_if_missing "big-output"               "$SCRIPT_DIR/big-output.sh"
append_if_missing "sleep-test"               "$SCRIPT_DIR/sleep-test.sh"
append_if_missing "args-echo"                "$SCRIPT_DIR/args-echo.sh"
append_if_missing "exit-code"                "$SCRIPT_DIR/exit-code.sh"
append_if_missing "context-dump"             "$SCRIPT_DIR/context-dump.sh"
append_if_missing "lock-test"                "$SCRIPT_DIR/lock-test.sh"
append_if_missing "sleep-5"                  "$SCRIPT_DIR/sleep-5.sh"
append_if_missing "sleep-15"                 "$SCRIPT_DIR/sleep-15.sh"
append_if_missing "sleep-90"                 "$SCRIPT_DIR/sleep-90.sh"
append_if_missing "daemonise-test"           "$SCRIPT_DIR/daemonise-test.sh"
append_if_missing "ctrl-exec-demonstrator"  "$SCRIPT_DIR/ctrl-exec-demonstrator.sh"
# allowlist-reload-check is intentionally NOT added here.
# Test 09 adds it manually after setup to verify SIGHUP reload works.

# --- reload allowlist ---

reload_agent() {
    # systemd (Debian)
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active ctrl-exec-agent >/dev/null 2>&1; then
        systemctl reload ctrl-exec-agent 2>/dev/null \
            || systemctl kill --signal=HUP ctrl-exec-agent
        echo "Sent HUP to ctrl-exec-agent via systemctl - allowlist reloaded"
        return 0
    fi

    # procd (OpenWrt)
    if [ -f /etc/init.d/ctrl-exec-agent ]; then
        /etc/init.d/ctrl-exec-agent reload 2>/dev/null \
            || /etc/init.d/ctrl-exec-agent restart
        echo "Sent reload to ctrl-exec-agent via procd - allowlist reloaded"
        return 0
    fi

    # Portable fallback: find PID via ps, no pkill/pgrep required
    local pid
    pid=$(ps 2>/dev/null \
        | awk '/ctrl-exec-agent/ && !/awk/ && !/setup-agent/ {print $1; exit}')
    if [ -n "$pid" ]; then
        kill -HUP "$pid"
        echo "Sent SIGHUP to ctrl-exec-agent (pid $pid) - allowlist reloaded"
        return 0
    fi

    echo "WARNING: ctrl-exec-agent not running - start it before testing"
}

reload_agent

# --- auth context test hook (optional) ---

AGENT_CONF="/etc/ctrl-exec-agent/agent.conf"
AGENT_CONF_BACKUP="/etc/ctrl-exec-agent/agent.conf.before-auth-test"
HOOK_PATH="/etc/ctrl-exec-agent/auth-context-check.sh"
STATUS_FILE="/tmp/ctrl-exec-auth-test-status"
AUTH_STATUS_DUMP="$SCRIPT_DIR/auth-status-dump.sh"

install_auth_test() {
    echo ""
    echo "Installing auth context test hook ..."

    # Write hook: records all context env vars to status file, then applies policy.
    # auth-status-dump is allowed through without touching the status file, so
    # the test can read back results from the preceding call undisturbed.
    cat > "$HOOK_PATH" << 'EOF'
#!/bin/sh
# auth-context-check.sh
# Installed by: setup-agent-scripts.sh --install-auth-test
# Removed by:   setup-agent-scripts.sh --remove-auth-test
#
# Records received context to STATUS_FILE then applies known-value policy.
# auth-status-dump is always allowed through without touching the status file,
# so the test can retrieve results from the preceding call.
# Exit codes for policy failures use distinct values to identify the failing field.

STATUS_FILE="/tmp/ctrl-exec-auth-test-status"

# Allow auth-status-dump through without recording - preserves the status
# file written by the preceding call so the test can read it back.
if [ "$ENVEXEC_SCRIPT" = "auth-status-dump" ]; then
    exit 0
fi

# Record what was received for all other scripts
cat > "$STATUS_FILE" << VARS
ENVEXEC_ACTION=$ENVEXEC_ACTION
ENVEXEC_SCRIPT=$ENVEXEC_SCRIPT
ENVEXEC_USERNAME=$ENVEXEC_USERNAME
ENVEXEC_TOKEN=$ENVEXEC_TOKEN
ENVEXEC_SOURCE_IP=$ENVEXEC_SOURCE_IP
ENVEXEC_DISPATCHER=$ENVEXEC_DISPATCHER
ENVEXEC_DISPATCHER_SERIAL=$ENVEXEC_DISPATCHER_SERIAL
ENVEXEC_ARGS_JSON=$ENVEXEC_ARGS_JSON
VARS

# Apply known-value policy
[ "$ENVEXEC_ACTION"   = "run"              ] || exit 11
[ "$ENVEXEC_USERNAME" = "test-user"        ] || exit 13
[ "$ENVEXEC_TOKEN"    = "test-token-value" ] || exit 14
[ -n "$ENVEXEC_SOURCE_IP"                  ] || exit 15
exit 0
EOF
    chmod 0755 "$HOOK_PATH"
    echo "  Hook written: $HOOK_PATH"

    # Write auth-status-dump script
    cat > "$AUTH_STATUS_DUMP" << 'EOF'
#!/bin/sh
# Outputs the auth context status file written by auth-context-check.sh.
# Used by integration test 15 to read hook-received values without SSH.
exec 0</dev/null
STATUS_FILE="/tmp/ctrl-exec-auth-test-status"
if [ -f "$STATUS_FILE" ]; then
    cat "$STATUS_FILE"
else
    echo "STATUS_FILE_NOT_FOUND"
    exit 1
fi
EOF
    chmod 0755 "$AUTH_STATUS_DUMP"
    echo "  Script written: $AUTH_STATUS_DUMP"

    # Add to allowlist
    append_if_missing "auth-status-dump" "$AUTH_STATUS_DUMP"

    # Patch agent.conf
    if grep -qE "^auth_hook\s*=" "$AGENT_CONF" 2>/dev/null; then
        echo "  auth_hook already set in $AGENT_CONF — not overwriting"
        echo "  WARNING: ensure it points to $HOOK_PATH for test 15 to work"
    else
        cp "$AGENT_CONF" "$AGENT_CONF_BACKUP"
        echo "  Backed up agent.conf to $AGENT_CONF_BACKUP"
        echo "auth_hook = $HOOK_PATH" >> "$AGENT_CONF"
        echo "  Appended: auth_hook = $HOOK_PATH"
    fi

    reload_agent
    echo "Auth context test hook installed."
    echo "Run integration test 15-agent-auth-context.sh to verify."
}

remove_auth_test() {
    echo ""
    echo "Removing auth context test hook ..."

    # Remove hook file
    if [ -f "$HOOK_PATH" ]; then
        rm -f "$HOOK_PATH"
        echo "  Removed: $HOOK_PATH"
    else
        echo "  Hook not found, skipping: $HOOK_PATH"
    fi

    # Remove auth-status-dump script
    if [ -f "$AUTH_STATUS_DUMP" ]; then
        rm -f "$AUTH_STATUS_DUMP"
        echo "  Removed: $AUTH_STATUS_DUMP"
    else
        echo "  auth-status-dump not found, skipping"
    fi

    # Remove auth-status-dump from allowlist
    if grep -qE "^auth-status-dump\s*=" "$CONF" 2>/dev/null; then
        sed -i "/^auth-status-dump\s*=/d" "$CONF"
        echo "  Removed auth-status-dump from $CONF"
    else
        echo "  auth-status-dump not in $CONF, skipping"
    fi

    # Restore agent.conf
    if [ -f "$AGENT_CONF_BACKUP" ]; then
        cp "$AGENT_CONF_BACKUP" "$AGENT_CONF"
        chown root:ctrl-exec-agent "$AGENT_CONF"
        chmod 640 "$AGENT_CONF"
        rm -f "$AGENT_CONF_BACKUP"
        echo "  Restored agent.conf from backup"
    else
        # No backup — just strip the auth_hook line if it points to our hook
        if grep -qE "^auth_hook\s*=\s*${HOOK_PATH}" "$AGENT_CONF" 2>/dev/null; then
            sed -i "/^auth_hook\s*=\s*${HOOK_PATH}/d" "$AGENT_CONF"
            echo "  Removed auth_hook line from agent.conf (no backup found)"
        else
            echo "  auth_hook not set to test hook in agent.conf, not modified"
        fi
    fi

    # Remove status file
    rm -f "$STATUS_FILE"

    reload_agent
    echo "Auth context test hook removed."
}

# --- mode dispatch ---

MODE="${1:-}"
case "$MODE" in
    --install-auth-test) install_auth_test ;;
    --remove-auth-test)  remove_auth_test ;;
    "")                  : ;;  # default install already complete above
    *)
        echo "Unknown argument: $MODE"
        echo "Usage: $0 [--install-auth-test|--remove-auth-test]"
        exit 1
        ;;
esac

echo "Done. Verify with: sudo ctrl-exec-agent self-check"
