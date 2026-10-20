#!/bin/bash
# One measured burst against the running rig.
#   ./run.sh LABEL TOTAL CONC DELAY
# Starts the in-container sampler, runs the driver, stops the sampler, then
# collects into out/LABEL/: runs.csv, samples.csv, summary.txt, logs/.
set -euo pipefail

HERE=$(readlink -f "$(dirname "$0")")
NAME="${RIG_NAME:-ce-wedge-rig}"
LABEL="${1:?label}"
TOTAL="${2:?total}"
CONC="${3:-1}"
DELAY="${4:-0}"
DEST="$HERE/out/$LABEL"
mkdir -p "$DEST/logs"

docker exec "$NAME" rm -f /tmp/samples.csv /var/log/rig-syslog
docker exec "$NAME" sh -c ': > /var/log/rig-syslog'
docker exec -d "$NAME" /opt/rig/sampler.pl /tmp/samples.csv
sleep 3

set +e
"$HERE/driver.pl" --total "$TOTAL" --conc "$CONC" --delay "$DELAY" --out "$DEST/runs.csv" | tee "$DEST/summary.txt"
set -e

sleep 3
docker exec "$NAME" pkill -f /opt/rig/sampler.pl || true
sleep 1
docker cp "$NAME:/tmp/samples.csv" "$DEST/samples.csv"
docker cp "$NAME:/var/log/rig-syslog" "$DEST/logs/syslog"
for f in api agent exec; do
    docker cp "$NAME:/var/log/rig-$f.log" "$DEST/logs/$f.log" || true
done
echo "evidence in $DEST"
