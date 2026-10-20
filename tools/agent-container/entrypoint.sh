#!/bin/bash
# Runs as root: pairs on first start (the certificates are written into a
# root-owned directory), starts the privileged executor as root, and runs the
# agent as the unprivileged ctrl-exec-agent user. It then stays as a small
# supervisor: a HUP is passed to the agent as a reload, a stop reaches both,
# and if either daemon exits the container exits.
set -eu

CONF_DIR=/etc/ctrl-exec-agent
CONF="$CONF_DIR/agent.conf"
RUN_DIR=/run/ctrl-exec-agent
SOCK="$RUN_DIR/exec.sock"
AGENT_USER=ctrl-exec-agent

log() { echo "[entrypoint] $*"; }

# DISPATCHER_HOST must be set in the container environment or compose file.
if [ -z "${DISPATCHER_HOST:-}" ]; then
    log "ERROR: DISPATCHER_HOST environment variable not set." >&2
    exit 1
fi

# First start: no cert means we have not paired yet. request-pairing blocks
# until the operator approves on the dispatcher (30 seconds by default), stores
# the certificates, and returns; a denial or timeout exits non-zero, and the
# restart policy then sends a fresh request.
if [ ! -f "$CONF_DIR/agent.crt" ]; then
    log "No cert found - requesting pairing with $DISPATCHER_HOST..."
    ctrl-exec-agent request-pairing --dispatcher "$DISPATCHER_HOST"
    log "Paired."
fi

# Optional: forward the agent's syslog to a remote TLS collector.
if [ -n "${SYSLOG_HOST:-}" ]; then
    SYSLOG_PORT="${SYSLOG_PORT:-6514}"
    log "forwarding daemon.* to $SYSLOG_HOST:$SYSLOG_PORT"
    cat > /run/rsyslog.conf << EOC
global(
    defaultNetstreamDriver="gtls"
    defaultNetstreamDriverCAFile="/etc/ssl/certs/ca-certificates.crt"
)
module(load="imuxsock")
daemon.* action(
    type="omfwd"
    target="$SYSLOG_HOST"
    port="$SYSLOG_PORT"
    protocol="tcp"
    StreamDriver="gtls"
    StreamDriverMode="1"
    StreamDriverAuthMode="x509/name"
    StreamDriverPermittedPeers="$SYSLOG_HOST"
    template="RSYSLOG_SyslogProtocol23Format"
)
EOC
    rsyslogd -f /run/rsyslog.conf -i /run/rsyslogd.pid
fi

# The privileged executor, as root, with the arguments of the package's
# ctrl-exec-executor.service. It makes the socket, owned by the agent user and
# mode 0600; the agent hands it every run.
mkdir -p "$RUN_DIR"
chmod 755 "$RUN_DIR"
log "Starting ctrl-exec-executor as root"
ctrl-exec-executor serve "$SOCK" "$CONF" "$CONF_DIR/scripts.conf" "$AGENT_USER" &
executor_pid=$!
for _ in $(seq 1 50); do
    [ -S "$SOCK" ] && break
    sleep 0.1
done
if [ ! -S "$SOCK" ]; then
    log "ERROR: ctrl-exec-executor did not create $SOCK." >&2
    exit 1
fi

# Adopt a renewed certificate staged while the agent was running (the deb's
# unit does this as ExecStartPre), then serve as the unprivileged user.
ctrl-exec-agent promote-cert || true
log "Starting ctrl-exec-agent serve as $AGENT_USER"
setpriv --reuid="$AGENT_USER" --regid="$AGENT_USER" --init-groups \
        ctrl-exec-agent serve &
agent_pid=$!

# Signal the agent as its own user. Root here holds no CAP_KILL, and without it
# may not signal a process of another user; a process of the same user may.
signal_agent() {
    setpriv --reuid="$AGENT_USER" --regid="$AGENT_USER" --clear-groups \
            sh -c 'kill -s "$1" "$2"' sh "$1" "$agent_pid" || true
}
stopping=
trap 'log "HUP: reloading the agent"; signal_agent HUP' HUP
trap 'stopping=1; signal_agent TERM; kill -TERM "$executor_pid" 2>/dev/null || true' TERM INT

# Wait for either daemon to exit. A trapped signal interrupts the wait; carry
# on while both are still running.
set +e
while :; do
    wait -n "$executor_pid" "$agent_pid"
    rc=$?
    [ -d "/proc/$agent_pid" ] && [ -d "/proc/$executor_pid" ] && continue
    break
done
if [ -z "$stopping" ]; then
    if [ -d "/proc/$agent_pid" ]; then
        log "ctrl-exec-executor exited ($rc); stopping the agent" >&2
        signal_agent TERM
    else
        log "ctrl-exec-agent exited ($rc); stopping the executor" >&2
        kill -TERM "$executor_pid" 2>/dev/null
    fi
fi
wait
[ -n "$stopping" ] && exit 0
exit "$rc"
