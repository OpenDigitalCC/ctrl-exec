#!/bin/bash
# Wedge rig entrypoint (PID 1 under `docker run --init`, so orphans are reaped
# as init would). Replaces OpenRC with direct daemon starts; the daemons
# inherit the container's --ulimit nofile, which is the point.
#   1. CA + dispatcher cert + config
#   2. start syslog, executor (root), agent (ctrl-exec-agent), api (ctrl-exec)
#      -- the agent needs a cert first, so pairing happens before the agent
#   3. pair the agent with the dispatcher on this same host, rename it "rig"
# Extra agent.conf lines may be passed in RIG_AGENT_EXTRA (newline separated).
set -euo pipefail

PIDS=/run/rig
mkdir -p "$PIDS"
mkdir -p /run/ctrl-exec-agent
chmod 755 /run/ctrl-exec-agent

echo "[rig] nofile limits (soft/hard): $(ulimit -Sn)/$(ulimit -Hn)"

cat > /etc/ctrl-exec-dispatcher/ctrl-exec.conf <<EOC
cert = /etc/ctrl-exec-dispatcher/dispatcher.crt
key  = /etc/ctrl-exec-dispatcher/dispatcher.key
ca   = /etc/ctrl-exec-dispatcher/ca.crt
auth_hook = /etc/ctrl-exec-dispatcher/auth-hook
api_bind = 0.0.0.0
api_port = 7445
api_auth_default = deny
EOC
chown root:ctrl-exec /etc/ctrl-exec-dispatcher/ctrl-exec.conf
chmod 640 /etc/ctrl-exec-dispatcher/ctrl-exec.conf

cp /opt/rig/agent.conf /etc/ctrl-exec-agent/agent.conf
if [ -n "${RIG_AGENT_EXTRA:-}" ]; then
    printf '%s\n' "$RIG_AGENT_EXTRA" | cat - /etc/ctrl-exec-agent/agent.conf > /tmp/agent.conf.new
    cp /tmp/agent.conf.new /etc/ctrl-exec-agent/agent.conf
fi
cp /opt/rig/scripts.conf /etc/ctrl-exec-agent/scripts.conf
chown root:ctrl-exec-agent /etc/ctrl-exec-agent/agent.conf /etc/ctrl-exec-agent/scripts.conf
chmod 640 /etc/ctrl-exec-agent/agent.conf /etc/ctrl-exec-agent/scripts.conf

ctrl-exec-dispatcher setup-ca
ctrl-exec-dispatcher setup-ctrl-exec

# syslog, as on the affected host (the daemons log through /dev/log)
syslogd -n -O /var/log/rig-syslog &
echo $! > "$PIDS/syslog.pid"
sleep 1

# executor first: root, same arguments as etc/systemd/ctrl-exec-executor.service
/usr/local/sbin/ctrl-exec-executor serve /run/ctrl-exec-agent/exec.sock \
    /etc/ctrl-exec-agent/agent.conf /etc/ctrl-exec-agent/scripts.conf ctrl-exec-agent \
    >> /var/log/rig-exec.log 2>&1 &
echo $! > "$PIDS/exec.pid"

# api as the unprivileged service user, as in etc/systemd/ctrl-exec-api.service
su-exec ctrl-exec \
    /usr/local/bin/ctrl-exec-api >> /var/log/rig-api.log 2>&1 &
echo $! > "$PIDS/api.pid"

# pairing: the agent requests, the dispatcher approves
ctrl-exec-dispatcher pairing-mode start --timeout 300 || true
# verified pairing (T-041): the agent checks the listener chains to this CA
ctrl-exec-agent request-pairing --dispatcher "$(hostname)" --background --timeout 120 \
    --dispatcher-fingerprint "$(ctrl-exec-dispatcher ca-fingerprint)" > /dev/null
for _ in $(seq 1 60); do
    ids=$(ctrl-exec-dispatcher list-requests 2>/dev/null | awk '/^[0-9a-f]{8,}/ {print $1}' || true)
    for id in $ids; do
        ctrl-exec-dispatcher approve "$id" || true
    done
    [ -f /etc/ctrl-exec-agent/agent.crt ] && break
    sleep 2
done
ctrl-exec-dispatcher pairing-mode stop || true
[ -f /etc/ctrl-exec-agent/agent.crt ] || { echo "[rig] pairing failed" >&2; exit 1; }

registered=$(ctrl-exec-dispatcher list-agents | awk 'NR>0 && $1 != "" && $1 !~ /^(HOST|-)/ {print $1; exit}')
echo "[rig] agent registered as: $registered"
if [ "$registered" != "rig" ]; then
    ctrl-exec-dispatcher edit-agent "$registered" --rename rig
fi
# the agent is on this same host: reach it by the container's own address
ctrl-exec-dispatcher edit-agent rig --lookup-by ip --ip "$(hostname -i | awk '{print $1}')"

su-exec ctrl-exec-agent \
    /usr/local/bin/ctrl-exec-agent serve >> /var/log/rig-agent.log 2>&1 &
echo $! > "$PIDS/agent.pid"

sleep 2
for r in exec api agent; do
    kill -0 "$(cat $PIDS/$r.pid)" 2>/dev/null || { echo "[rig] $r died at start" >&2; tail -5 /var/log/rig-$r.log >&2; exit 1; }
done
echo "[rig] ready: exec=$(cat $PIDS/exec.pid) api=$(cat $PIDS/api.pid) agent=$(cat $PIDS/agent.pid)"
touch "$PIDS/ready"
wait
