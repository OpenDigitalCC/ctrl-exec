#!/bin/bash
# Shared helpers for the upgrade-rig scenarios. Sourced by run.sh and by each
# scenarios/*.sh (which run.sh starts with RIG_* set in the environment).
#
# Every container, network and volume the rig makes carries the label
# ce-upgrade-rig=1 and the name prefix ce-uprig-, so rig_cleanup removes all of
# it, whatever a scenario left after a failure.
#
# shellcheck disable=SC2016  # shell text for `docker exec bash -c` is single-quoted on purpose: it expands in the container
# shellcheck disable=SC2034  # FAILED and the RIG_* settings are read by the sourcing scripts

RIG_LABEL=ce-upgrade-rig=1
RIG_PREFIX=ce-uprig
RIG_IMG=${RIG_IMG:-ce-upgrade-rig:systemd}

# Per-container limits: small, and well inside the shared host's capacity.
RIG_LIMITS=(--cpus 0.5 --memory 384m --memory-swap 384m --pids-limit 256)
# systemd as PID 1 in a private cgroup namespace (the image's rig-init remounts
# the container's own cgroup subtree writable). SYS_ADMIN and AppArmor
# unconfined are what the executor needs anyway (per-run mount namespace); they
# are container-scoped. No --privileged, no host cgroup mount.
RIG_SYSD=(--cgroupns=private --tmpfs /run --tmpfs /run/lock --tmpfs /tmp
          --cap-add SYS_ADMIN --security-opt apparmor=unconfined)

FAILED=0
ok()  { echo "ok - $*"; }
nok() { echo "not ok - $*"; FAILED=1; }
note() { echo "# $*"; }
# check <description> <haystack> <regex>: pass when the regex matches
check() {
    if grep -Eq -- "$3" <<< "$2"; then ok "$1"; else nok "$1"; tail -15 <<< "$2" | sed 's/^/#   /'; fi
}
# check_not <description> <haystack> <regex>: pass when the regex does not match
check_not() {
    if grep -Eq -- "$3" <<< "$2"; then nok "$1"; grep -E -- "$3" <<< "$2" | sed 's/^/#   /' | head -10; else ok "$1"; fi
}
# Fatal setup failure: the scenario cannot reach its assertions.
die_setup() { echo "not ok - setup: $*"; echo "RESULT: ERROR"; exit 2; }

rig_cleanup() {
    local ids
    ids=$(docker ps -aq --filter "label=$RIG_LABEL")
    if [ -n "$ids" ]; then
        # shellcheck disable=SC2086  # one id per word
        docker rm -f $ids > /dev/null 2>&1 || true
    fi
    # images a scenario built (scenario 3's compose images)
    ids=$(docker images -q --filter "reference=$RIG_PREFIX-*")
    if [ -n "$ids" ] && [ -z "${RIG_KEEP_IMAGES:-}" ]; then
        # shellcheck disable=SC2086
        docker rmi -f $ids > /dev/null 2>&1 || true
    fi
    ids=$(docker volume ls -q --filter "label=$RIG_LABEL")
    if [ -n "$ids" ]; then
        # shellcheck disable=SC2086
        docker volume rm $ids > /dev/null 2>&1 || true
    fi
    ids=$(docker network ls -q --filter "label=$RIG_LABEL")
    if [ -n "$ids" ]; then
        # shellcheck disable=SC2086
        docker network rm $ids > /dev/null 2>&1 || true
    fi
}

net_create() {   # net_create <name>
    docker network create --label "$RIG_LABEL" "$1" > /dev/null
}

# host_start <container> <alias> <network> [docker run args...]: a fresh
# systemd host from the rig image, the FROM and TO debs mounted read-only at
# /debs/from and /debs/to. Waits until systemd has finished booting.
host_start() {
    local name=$1 alias=$2 net=$3 state
    shift 3
    docker run -d --name "$name" --hostname "$alias" --label "$RIG_LABEL" \
        --network "$net" --network-alias "$alias" \
        "${RIG_LIMITS[@]}" "${RIG_SYSD[@]}" \
        -v "$RIG_DEBS_FROM:/debs/from:ro" -v "$RIG_DEBS_TO:/debs/to:ro" \
        -v "$RIG_CLI_DIR:/rig-cli:ro" \
        "$@" "$RIG_IMG" > /dev/null
    for _ in $(seq 1 60); do
        state=$(docker exec "$name" systemctl is-system-running 2>/dev/null || true)
        case "$state" in running|degraded) return 0 ;; esac
        sleep 1
    done
    die_setup "$name: systemd did not finish booting (state '$state')"
}

# x <container> <shell text>: run shell text as root in the container
x() { docker exec -i "$1" bash -c "$2"; }

# install_debs <container> <from|to> <package...>: dpkg -i the named packages of
# one deb set together (common must come with agent or dispatcher: they depend
# on it at the exact version). Output is the maintainer scripts' own.
install_debs() {
    local name=$1 set=$2 p list=""
    shift 2
    for p in "$@"; do list="$list /debs/$set/ctrl-exec-${p}_*.deb"; done
    x "$name" "DEBIAN_FRONTEND=noninteractive dpkg -i $list"
}

pkg_version() {   # pkg_version <container> <package>
    docker exec "$1" dpkg-query -W -f '${Version}' "ctrl-exec-$2" 2>/dev/null || true
}

# The token the rig's dispatcher auth hook accepts.
RIG_TOKEN=rig-token-0123456789

# A realistic hook (the 0.12 example's token pattern): allow a known token,
# deny the rest with exit 2.
AUTH_HOOK='#!/bin/bash
# upgrade-rig auth hook: token check, as in auth-hook.example example 3
if [ "${ENVEXEC_TOKEN:-}" != "'"$RIG_TOKEN"'" ]; then
    logger -t ctrl-exec-auth "denied: bad token for $ENVEXEC_ACTION from $ENVEXEC_SOURCE_IP"
    exit 2
fi
exit 0
'

# dispatcher_install <container> [from|to]: a dispatcher on the FROM debs (or
# the named set) as the 0.12 install guide leaves it: package config directory
# (wherever the postinst puts it), CA and dispatcher cert, the API on all
# interfaces behind a token auth hook, ctrl-exec-api enabled and started under
# systemd. Prints the config directory used.
dispatcher_install() {
    local name=$1 set=${2:-from}
    install_debs "$name" "$set" common dispatcher >> "${RIG_EVIDENCE:-/dev/null}" 2>&1 \
        || die_setup "$name: dpkg -i of the $set dispatcher debs failed"
    x "$name" 'set -e
        if [ -d /etc/ctrl-exec-dispatcher ]; then d=/etc/ctrl-exec-dispatcher; else d=/etc/ctrl-exec; fi
        conf=$d/ctrl-exec.conf
        cat > "$d/auth-hook"
        chmod 755 "$d/auth-hook"
        sed -i "/^[[:space:]]*auth_hook[[:space:]]*=/d; /^[[:space:]]*api_bind[[:space:]]*=/d" "$conf"
        printf "auth_hook = %s/auth-hook\napi_bind = 0.0.0.0\n" "$d" >> "$conf"
        ctrl-exec-dispatcher setup-ca > /dev/null
        ctrl-exec-dispatcher setup-ctrl-exec > /dev/null
        systemctl enable --now ctrl-exec-api.service 2> /dev/null
        echo "$d"' <<< "$AUTH_HOOK" || die_setup "$name: dispatcher setup failed"
}

# agent_install <container> [from|to]: the FROM agent debs, or the named set
# (config left as the package seeds it: executor on, [profile default] run_as
# nobody).
agent_install() {
    local set=${2:-from}
    install_debs "$1" "$set" common agent >> "${RIG_EVIDENCE:-/dev/null}" 2>&1 \
        || die_setup "$1: dpkg -i of the $set agent debs failed"
}

# pair <dispatcher container> <agent container> <agent alias>: pair the agent
# (CLI pairing, approved on the dispatcher), register it under its network
# alias, then enable and start the executor and the agent under systemd, as
# the install guide has the operator do after pairing. The executor unit's
# name is whatever the FROM package ships.
pair() {
    local disp=$1 agent=$2 alias=$3 paired="" id name
    x "$disp" 'ctrl-exec-dispatcher pairing-mode start --timeout 120 > /dev/null 2>&1' \
        || die_setup "pairing-mode start failed on $disp"
    x "$agent" "ctrl-exec-agent request-pairing --dispatcher $(docker inspect -f '{{.Config.Hostname}}' "$disp") --background --timeout 120 > /dev/null 2>&1" \
        || die_setup "request-pairing failed on $agent"
    for _ in $(seq 1 40); do
        for id in $(x "$disp" 'ctrl-exec-dispatcher list-requests 2>/dev/null' | awk '/^[0-9a-f]{8,}/ {print $1}'); do
            x "$disp" "ctrl-exec-dispatcher approve $id" > /dev/null 2>&1 || true
        done
        if x "$agent" 'test -f /etc/ctrl-exec-agent/agent.crt' 2> /dev/null; then paired=1; break; fi
        sleep 1
    done
    x "$disp" 'ctrl-exec-dispatcher pairing-mode stop' > /dev/null 2>&1 || true
    [ -n "$paired" ] || die_setup "$agent did not pair with $disp"
    sleep 1
    name=$(x "$disp" 'ctrl-exec-dispatcher list-agents' | awk -v a="$alias" 'NR > 1 && ($1 == a || index($1, a ".") == 1) {print $1; exit}')
    [ -n "$name" ] || die_setup "$agent is not in the dispatcher's registry"
    if [ "$name" != "$alias" ]; then
        x "$disp" "ctrl-exec-dispatcher edit-agent '$name' --rename '$alias'" > /dev/null \
            || die_setup "rename of $name to $alias failed"
    fi
    x "$agent" 'set -e
        if [ -f /lib/systemd/system/ctrl-exec-executor.service ] || [ -f /usr/lib/systemd/system/ctrl-exec-executor.service ]; then
            u=ctrl-exec-executor
        else
            u=ctrl-exec-exec
        fi
        systemctl enable --now "$u.service" 2> /dev/null
        systemctl enable --now ctrl-exec-agent.service 2> /dev/null' \
        || die_setup "$agent: starting the executor and agent failed"
    wait_agent "$agent" || die_setup "$agent: agent not listening after start"
}

# wait_agent <container>: until something listens on 7443 (max 30 s)
wait_agent() {
    for _ in $(seq 1 30); do
        x "$1" 'ss -Hltn "sport = :7443" | grep -q LISTEN' 2> /dev/null && return 0
        sleep 1
    done
    return 1
}

# wait_api <container>: until the API answers HTTP on 7445 (max 30 s). Any
# HTTP status counts: 0.12's /health goes through the auth hook.
wait_api() {
    for _ in $(seq 1 30); do
        x "$1" 'perl -MHTTP::Tiny -e "exit(HTTP::Tiny->new(timeout => 3)->get(q{http://127.0.0.1:7445/health})->{status} == 599 ? 1 : 0)"' 2> /dev/null && return 0
        sleep 1
    done
    return 1
}

# cli <container> <cli set: from|to> <args...>: ctrl-exec-cli from the chosen
# plugins commit, with the rig token, against the API on the container's own
# loopback unless the args name another --url. stdout and stderr together,
# then a last line "cli-exit=N"; always returns 0.
cli() {
    local name=$1 set=$2 a q=""
    shift 2
    for a in "$@"; do q="$q $(printf '%q' "$a")"; done
    x "$name" "CTRL_EXEC_TOKEN=$RIG_TOKEN CTRL_EXEC_USERNAME=rig CTRL_EXEC_API_URL=\${CTRL_EXEC_API_URL:-http://127.0.0.1:7445} perl /rig-cli/ctrl-exec-cli-$set $q 2>&1; echo cli-exit=\$?" || true
}

# unit_states <container> <unit...>: "unit=state" for each
unit_states() {
    local name=$1 u out=""
    shift
    for u in "$@"; do
        out="$out $u=$(docker exec "$name" systemctl is-active "$u" 2>/dev/null || true)"
    done
    echo "${out# }"
}

# journal <container> <lines>: the last lines of the container's journal, for
# the evidence directory
journal() {
    docker exec "$1" journalctl --no-pager -n "${2:-200}" 2>/dev/null || true
}

# plain_layout <container>: the stock estate - one root-owned script in the
# package's /opt/ctrl-exec-scripts, default profile. The control case: it
# passes every ownership rule, so a failure with it is not about the layout.
# 0.12 packages made the directory 750 root:ctrl-exec-agent, which the default
# profile's run_as nobody cannot enter; a 0.12 operator opened it to 755.
plain_layout() {
    x "$1" 'set -e
        chmod 755 /opt/ctrl-exec-scripts
        printf "#!/bin/sh\necho \"rig-hello user=\$(id -un) args=\$*\"\n" > /opt/ctrl-exec-scripts/rig-hello.sh
        chown root:root /opt/ctrl-exec-scripts/rig-hello.sh
        chmod 755 /opt/ctrl-exec-scripts/rig-hello.sh
        echo "rig-hello = /opt/ctrl-exec-scripts/rig-hello.sh" > /etc/ctrl-exec-agent/scripts.conf' \
        || die_setup "$1: plain layout failed"
}
