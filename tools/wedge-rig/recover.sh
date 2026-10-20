#!/bin/bash
# Idle recovery: after a wedge, send one run every INTERVAL seconds (default 10)
# until one succeeds, report seconds waited, then stay idle for SETTLE seconds
# (default 65) so the next burst starts with an empty rate window.
#   ./recover.sh LABEL [INTERVAL] [SETTLE]
# Writes out/LABEL/recovery.txt. Polls are single runs, so they are visible to
# the sampler only if it is running (run.sh stops it; use sampler-start.sh).
set -euo pipefail
HERE=$(readlink -f "$(dirname "$0")")
LABEL="${1:?label}"
INTERVAL="${2:-10}"
SETTLE="${3:-65}"
DEST="$HERE/out/$LABEL"
mkdir -p "$DEST"
: > "$DEST/recovery.txt"
t0=$(date +%s)
echo "recovery poll start $(date -u +%H:%M:%S)" | tee -a "$DEST/recovery.txt"
while :; do
    sleep "$INTERVAL"
    set +e
    "$HERE/driver.pl" --total 1 --out "$DEST/recover-poll.csv" > "$DEST/recover-poll.out"
    set -e
    now=$(date +%s)
    if grep -q 'ok=1 ' "$DEST/recover-poll.out"; then
        echo "recovered: first success $(date -u +%H:%M:%S), $((now - t0))s after polling began" | tee -a "$DEST/recovery.txt"
        break
    fi
    if [ $((now - t0)) -gt 900 ]; then
        echo "no recovery within 900s" | tee -a "$DEST/recovery.txt"
        break
    fi
done
sleep "$SETTLE"
