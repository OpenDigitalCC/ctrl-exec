#!/bin/bash
# Build and start the wedge rig: one Alpine container holding ctrl-exec-api,
# ctrl-exec-agent and ctrl-exec-executor, constrained to 1 CPU / 512 MB, with the
# affected host's default open-files limit (1024 soft / 4096 hard) on all three
# daemons. The API is published on 127.0.0.1:17445 only.
#
# Env: RIG_NOFILE (default 1024:4096), RIG_AGENT_EXTRA (extra agent.conf lines,
#      e.g. "rate_limit_disable = 1"), RIG_NAME (default ce-wedge-rig)
set -euo pipefail

HERE=$(readlink -f "$(dirname "$0")")
WT=$(readlink -f "$HERE/../..")
NAME="${RIG_NAME:-ce-wedge-rig}"
NOFILE="${RIG_NOFILE:-1024:4096}"
EXTRA="${RIG_AGENT_EXTRA:-}"

BUILD="$HERE/.build"
mkdir -p "$BUILD"
git -C "$WT" archive --format=tar.gz --prefix=ctrl-exec-src/ -o "$BUILD/src.tar.gz" HEAD
cp "$HERE/Dockerfile" "$HERE/agent.conf" "$HERE/scripts.conf" "$HERE/rig-hello.sh" \
   "$HERE/sampler.pl" "$HERE/entrypoint.sh" "$BUILD/"

docker build -t "$NAME" "$BUILD"

docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" --hostname rig-host --init \
    --cpus=1 --memory=512m --memory-swap=512m --pids-limit=2048 \
    --ulimit "nofile=$NOFILE" \
    --cap-add SYS_ADMIN --security-opt apparmor=unconfined \
    -e "RIG_AGENT_EXTRA=$EXTRA" \
    -p 127.0.0.1:17445:7445 \
    "$NAME"

for _ in $(seq 1 90); do
    if docker exec "$NAME" test -f /run/rig/ready; then
        echo "rig ready: API on http://127.0.0.1:17445 (container $NAME)"
        docker exec "$NAME" sh -c 'for r in api agent exec; do p=$(cat /run/rig/$r.pid); echo "$r pid $p: $(grep "Max open files" /proc/$p/limits)"; done'
        exit 0
    fi
    sleep 2
done
echo "rig did not become ready; container log follows" >&2
docker logs --tail 40 "$NAME" >&2
exit 1
