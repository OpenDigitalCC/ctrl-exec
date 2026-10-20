#!/bin/bash
# Container test for the agent image in docs/DOCKER.md (T-048): the executor
# runs as root inside the agent container, profiles are enforced, a profile the
# container cannot enforce fails the run with a clear error, and a HUP reloads
# the agent without restarting the container.
#
# Builds the .debs from the checkout's COMMITTED HEAD (git archive, then
# dpkg-buildpackage; commit your changes first), builds the agent image from
# the Dockerfile and entrypoint.sh beside this script (the ones DOCKER.md
# shows; t/docker-agent-files.t keeps them identical), and a throwaway
# dispatcher container that only pairs and runs `ced run`. Constrained
# containers on a private network; everything is removed at the end. Needs
# docker and dpkg-buildpackage on the host; no root.
#
#   tools/agent-container/test.sh            # prints ok/not ok lines; exit 0 = all passed
#   KEEP=1 tools/agent-container/test.sh     # leave the containers up to inspect
set -euo pipefail

HERE=$(readlink -f "$(dirname "$0")")
WT=$(readlink -f "$HERE/../..")
BUILD="$HERE/.build"
P=claude-t048
NET="$P-net"
AGENT="$P-agent"
DISP="$P-dispatcher"
AGENT_IMG="$P-agent:test"
DISP_IMG="$P-dispatcher:test"
LIMITS=(--cpus 0.5 --memory 256m --pids-limit 200)
# The agent container's flags, as in DOCKER.md's compose.yml.
HARDENED=(--init --read-only --tmpfs /tmp --tmpfs /run --cap-drop ALL
          --cap-add CHOWN --cap-add FOWNER --cap-add DAC_OVERRIDE
          --cap-add SETUID --cap-add SETGID)
EXECUTOR_CAPS=(--cap-add SETPCAP --cap-add SYS_ADMIN
               --security-opt apparmor=unconfined)
NNP=(--security-opt no-new-privileges:true)

FAILED=0
ok()  { echo "ok - $*"; }
nok() { echo "not ok - $*"; FAILED=1; }
check() {   # check <description> <haystack> <regex>
    if grep -Eq -- "$3" <<< "$2"; then ok "$1"; else nok "$1"; echo "$2" | sed 's/^/#   /'; fi
}

cleanup() {
    [ -n "${KEEP:-}" ] && { echo "# KEEP set: containers left running"; return; }
    docker rm -f "$AGENT" "$DISP" > /dev/null 2>&1 || true
    docker volume rm "$P-agent-data" "$P-agent-state" "$P-agent-scripts" > /dev/null 2>&1 || true
    docker network rm "$NET" > /dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

# --- build -------------------------------------------------------------------
rm -rf "$BUILD"
mkdir -p "$BUILD/src" "$BUILD/agent" "$BUILD/dispatcher"
git -C "$WT" archive --format=tar HEAD | tar -x -C "$BUILD/src"
echo "# building the debs from HEAD $(git -C "$WT" rev-parse --short HEAD)"
(cd "$BUILD/src" && nice -n 19 dpkg-buildpackage -us -uc -b > "$BUILD/deb-build.log" 2>&1)
cp "$BUILD"/ctrl-exec-common_*.deb "$BUILD"/ctrl-exec-agent_*.deb "$BUILD/agent/"
cp "$BUILD"/ctrl-exec-common_*.deb "$BUILD"/ctrl-exec-dispatcher_*.deb "$BUILD/dispatcher/"
cp "$HERE/Dockerfile" "$HERE/entrypoint.sh" "$BUILD/agent/"
cat > "$BUILD/dispatcher/Dockerfile" << 'EOF'
FROM debian:trixie-slim
COPY ctrl-exec-common_*.deb ctrl-exec-dispatcher_*.deb /tmp/
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        /tmp/ctrl-exec-common_*.deb /tmp/ctrl-exec-dispatcher_*.deb \
 && rm -rf /var/lib/apt/lists/* /tmp/*.deb
RUN ced setup-ca && ced setup-ctrl-exec
ENTRYPOINT ["sleep", "infinity"]
EOF
nice -n 19 docker build -q -t "$AGENT_IMG" "$BUILD/agent" > /dev/null
nice -n 19 docker build -q -t "$DISP_IMG" "$BUILD/dispatcher" > /dev/null

# --- start and pair ----------------------------------------------------------
docker network create "$NET" > /dev/null
docker run -d --name "$DISP" --hostname dispatcher --network "$NET" \
    --network-alias dispatcher "${LIMITS[@]}" "$DISP_IMG" > /dev/null
docker exec "$DISP" ced pairing-mode start --timeout 120 > /dev/null

start_agent() {   # start_agent <extra docker run flags...>
    docker rm -f "$AGENT" > /dev/null 2>&1 || true
    docker run -d --name "$AGENT" --hostname agent --network "$NET" \
        --network-alias agent "${LIMITS[@]}" "${HARDENED[@]}" "$@" \
        -e DISPATCHER_HOST=dispatcher \
        -v "$P-agent-data:/etc/ctrl-exec-agent" \
        -v "$P-agent-state:/var/lib/ctrl-exec-agent" \
        -v "$P-agent-scripts:/opt/ctrl-exec-scripts" \
        "$AGENT_IMG" > /dev/null
}
wait_serving() {
    for _ in $(seq 1 60); do
        docker logs "$AGENT" 2>&1 | grep -q 'Starting ctrl-exec-agent serve' && { sleep 2; return 0; }
        sleep 1
    done
    docker logs "$AGENT" 2>&1 | tail -20 | sed 's/^/#   /'
    return 1
}

start_agent "${EXECUTOR_CAPS[@]}" "${NNP[@]}"
paired=
for _ in $(seq 1 40); do
    for id in $(docker exec "$DISP" ced list-requests 2>/dev/null | awk '/^[0-9a-f]{8,}/ {print $1}'); do
        docker exec "$DISP" ced approve "$id" > /dev/null 2>&1 || true
    done
    if docker exec "$AGENT" test -f /etc/ctrl-exec-agent/agent.crt 2>/dev/null; then paired=1; break; fi
    sleep 1
done
docker exec "$DISP" ced pairing-mode stop > /dev/null 2>&1 || true
[ -n "$paired" ] && ok "agent paired" || { nok "agent paired"; exit 1; }
wait_serving && ok "agent serving" || { nok "agent serving"; exit 1; }
NAME=$(docker exec "$DISP" ced list-agents | awk 'NR > 1 && $1 ~ /^agent/ {print $1; exit}')
[ -n "$NAME" ] || { nok "agent registered"; exit 1; }
# The registered name carries the host's search domain; reach it by the
# network alias instead.
if [ "$NAME" != agent ]; then
    docker exec "$DISP" ced edit-agent "$NAME" --rename agent > /dev/null
    NAME=agent
fi

# --- provision scripts and profiles ------------------------------------------
docker exec -i "$AGENT" sh -c 'cat > /opt/ctrl-exec-scripts/probe.sh
    chown root:root /opt/ctrl-exec-scripts/probe.sh
    chmod 755 /opt/ctrl-exec-scripts/probe.sh /opt/ctrl-exec-scripts' << 'EOF'
#!/bin/sh
echo "user=$(id -un) uid=$(id -u)"
grep -E '^(CapEff|CapBnd|NoNewPrivs):' /proc/self/status | tr -d '\t'
if touch /etc/ctrl-exec-agent/probe-w 2>/dev/null; then echo control=rw; else echo control=ro; fi
EOF
docker exec -i "$AGENT" sh -c 'cat >> /etc/ctrl-exec-agent/agent.conf' << 'EOF'

[profile web]
run_as = www-data

[profile rootnnp0]
run_as = root
no_new_privileges = no

[profile netadmin]
run_as = www-data
caps = CAP_NET_ADMIN
EOF
docker exec -i "$AGENT" sh -c 'cat >> /etc/ctrl-exec-agent/scripts.conf' << 'EOF'
probe-web = /opt/ctrl-exec-scripts/probe.sh profile=web
probe-root = /opt/ctrl-exec-scripts/probe.sh profile=rootnnp0
probe-netadmin = /opt/ctrl-exec-scripts/probe.sh profile=netadmin
EOF
# Restart once so phases 1 and 2 start from this config; phase 3 tests reload.
docker restart "$AGENT" > /dev/null
wait_serving || { nok "agent serving after restart"; exit 1; }

run() { docker exec "$DISP" ced run "$NAME" "$1" 2>&1 || true; }

# --- 1. run_as through the executor ------------------------------------------
out=$(run probe-web)
check "run_as=www-data: the script runs as www-data" "$out" 'user=www-data uid=33'
check "run_as=www-data: no capabilities, bounding set empty" "$out" 'CapBnd:0000000000000000'
check "run_as=www-data: control dir read-only to the action" "$out" 'control=ro'
out=$(run probe-root)
check "root profile with no_new_privileges=no: no capabilities left" "$out" 'CapEff:0000000000000000'

# --- 2. a profile the container cannot enforce fails clearly -----------------
out=$(run probe-netadmin)
check "caps=CAP_NET_ADMIN (not in the container's set): run fails" "$out" 'keeps CAP_NET_ADMIN, which the executor does not hold'
if grep -q 'user=' <<< "$out"; then nok "caps=CAP_NET_ADMIN: script output absent"; else ok "caps=CAP_NET_ADMIN: script output absent"; fi

# --- 3. reload without a restart ---------------------------------------------
started=$(docker inspect -f '{{.State.StartedAt}}' "$AGENT")
docker exec "$AGENT" sh -c 'echo "probe-new = /opt/ctrl-exec-scripts/probe.sh profile=web" >> /etc/ctrl-exec-agent/scripts.conf'
out=$(run probe-new)
check "before reload: the new script is not yet allowed" "$out" 'not (in the allowlist|permitted|allowed)|unknown script|not found'
docker kill -s HUP "$AGENT" > /dev/null
sleep 2
out=$(run probe-new)
check "after docker kill -s HUP: the new script runs" "$out" 'user=www-data'
docker exec "$AGENT" sh -c 'echo "probe-new2 = /opt/ctrl-exec-scripts/probe.sh profile=web" >> /etc/ctrl-exec-agent/scripts.conf'
docker exec "$AGENT" sh -c 'kill -HUP 1'
sleep 2
out=$(run probe-new2)
check "after docker exec sh -c 'kill -HUP 1': the next new script runs" "$out" 'user=www-data'
state=$(docker inspect -f '{{.State.Running}} {{.State.StartedAt}} {{.RestartCount}}' "$AGENT")
check "the container was not restarted by either reload" "$state" "^true $started 0\$"

# --- 4. a container without the executor's capabilities fails closed ---------
# Without no-new-privileges on the container, so that a root action which
# execs with no_new_privileges=no would regain whatever the executor could not
# drop from the bounding set: the run must fail rather than do that.
start_agent --cap-add SYS_ADMIN --security-opt apparmor=unconfined
wait_serving || nok "agent serving without SETPCAP"
out=$(run probe-root)
check "without CAP_SETPCAP: the run fails, naming the bounding set" "$out" 'cannot drop CAP_[A-Z_]+ from the capability bounding set'
if grep -q 'user=' <<< "$out"; then nok "without CAP_SETPCAP: script did not run"; else ok "without CAP_SETPCAP: script did not run"; fi

start_agent --cap-add SETPCAP "${NNP[@]}"
wait_serving || nok "agent serving without SYS_ADMIN"
out=$(run probe-web)
check "without CAP_SYS_ADMIN: the run fails, naming the mount namespace" "$out" "cannot create the action's mount namespace"

start_agent --cap-add SETPCAP --cap-add SYS_ADMIN "${NNP[@]}"
wait_serving || nok "agent serving under the default AppArmor profile"
out=$(run probe-web)
check "under AppArmor docker-default: the run fails, naming mount" "$out" "cannot set up the action's mount namespace|cannot create the action's mount namespace"

# --- 5. the supervisor stops cleanly -----------------------------------------
start_agent "${EXECUTOR_CAPS[@]}" "${NNP[@]}"
wait_serving || nok "agent serving again"
docker stop -t 10 "$AGENT" > /dev/null
code=$(docker inspect -f '{{.State.ExitCode}}' "$AGENT")
check "docker stop: the entrypoint exits 0" "$code" '^0$'

[ "$FAILED" = 0 ] && echo "# PASS" || echo "# FAIL"
exit "$FAILED"
