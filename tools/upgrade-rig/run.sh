#!/bin/bash
# Upgrade rig: install the FROM release's debs on realistic estates, upgrade to
# the TO debs with no step between, and check the estate still lists and runs
# its scripts. See README.md.
#
#   tools/upgrade-rig/run.sh [options] [scenario...]
#
#   --from X       deb set installed first. A release version (0.12.4: the debs
#                  committed in dist/ at tag v0.12.4) or any core commit-ish
#                  (built from that commit). Default 0.12.4.
#   --to X         deb set upgraded to. Same forms. Default HEAD (the commit of
#                  the checkout this script is in).
#   --cli-from R   plugins commit-ish for the ctrl-exec-cli of the 0.12-era
#                  caller (scenario 3's run-jobs image). Default v0.3.10.
#   --cli-to R     plugins commit-ish for the ctrl-exec-cli used everywhere
#                  else. Default main.
#   --label L      evidence directory name under out/ (default: from the refs)
#   --keep         leave the last scenario's containers up (a later run or
#                  --cleanup removes them)
#   --cleanup      remove every rig container, network, volume and image
#                  (the host image too), then exit
#
#   scenarios: s1 s1b s2 s3 s4 s5 s6 (default: all, in that order)
#
# Exit 0 when every scenario passed. Evidence: out/<label>/.
set -euo pipefail

HERE=$(readlink -f "$(dirname "$0")")
WT=$(readlink -f "$HERE/../..")
CORE=$(dirname "$(readlink -f "$(git -C "$WT" rev-parse --git-common-dir)")")
PLUGINS=${PLUGINS_REPO:-$(readlink -f "$CORE/../plugins")}
BUILD="$HERE/.build"

FROM=0.12.4
TO=HEAD
CLI_FROM=v0.3.10
CLI_TO=main
LABEL=""
KEEP=""
CLEANUP=""
SCENARIOS=()

usage() { sed -n '2,26p' "$0" | sed 's/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
    case "$1" in
        --from)     FROM=$2; shift 2 ;;
        --to)       TO=$2; shift 2 ;;
        --cli-from) CLI_FROM=$2; shift 2 ;;
        --cli-to)   CLI_TO=$2; shift 2 ;;
        --label)    LABEL=$2; shift 2 ;;
        --keep)     KEEP=1; shift ;;
        --cleanup)  CLEANUP=1; shift ;;
        -h|--help)  usage; exit 0 ;;
        s1|s1b|s2|s3|s4|s5|s6) SCENARIOS+=("$1"); shift ;;
        *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done
[ ${#SCENARIOS[@]} -gt 0 ] || SCENARIOS=(s1 s1b s2 s3 s4 s5 s6)

# shellcheck source=lib.sh
source "$HERE/lib.sh"

if [ -n "$CLEANUP" ]; then
    rig_cleanup
    docker rmi "$RIG_IMG" > /dev/null 2>&1 || true
    echo "rig removed (deb cache kept in $BUILD/debs)"
    exit 0
fi

# --- deb sets -------------------------------------------------------------------
# debs_for <spec> -> prints the directory holding that set's three debs.
# A release version reads the debs committed at its tag (the released bytes);
# anything else is a commit, built once with dpkg-buildpackage and cached under
# .build/debs/<sha>.
debs_for() {
    local spec=$1 dir sha p
    if [[ $spec =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] \
       && git -C "$CORE" rev-parse -q --verify "refs/tags/v$spec" > /dev/null; then
        dir="$BUILD/debs/release-$spec"
        if [ ! -f "$dir/.done" ]; then
            mkdir -p "$dir"
            for p in "common_${spec}_all" "dispatcher_${spec}_all" "agent_${spec}_amd64"; do
                git -C "$CORE" show "v$spec:dist/ctrl-exec-$p.deb" > "$dir/ctrl-exec-$p.deb" \
                    || { echo "no dist/ctrl-exec-$p.deb at tag v$spec" >&2; return 1; }
            done
            touch "$dir/.done"
        fi
        echo "$dir"
        return 0
    fi
    sha=$(git -C "$WT" rev-parse --verify "$spec^{commit}") \
        || { echo "not a release version or core commit: $spec" >&2; return 1; }
    dir="$BUILD/debs/$sha"
    if [ ! -f "$dir/.done" ]; then
        rm -rf "$dir"
        mkdir -p "$dir/src"
        git -C "$WT" archive --format=tar "$sha" | tar -x -C "$dir/src"
        echo "# building debs from $(git -C "$WT" log -1 --format='%h %s' "$sha")" >&2
        if ! (cd "$dir/src" && nice -n 19 dpkg-buildpackage -us -uc -b > "$dir/build.log" 2>&1); then
            echo "deb build failed for $spec; see $dir/build.log" >&2
            return 1
        fi
        rm -rf "$dir/src"
        touch "$dir/.done"
    fi
    echo "$dir"
}

# cli_for <commit-ish> <dest>: the plugins repo's ctrl-exec-cli at that commit
cli_for() {
    git -C "$PLUGINS" show "$1:ce-api-plugins/ctrl-exec-cli/ctrl-exec-cli" > "$2" \
        || { echo "no ctrl-exec-cli at plugins $1" >&2; return 1; }
    chmod 755 "$2"
}

describe() {   # describe <spec> <repo>
    if [[ $1 =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then echo "release $1"; return; fi
    git -C "$2" log -1 --format="%h (%s)" "$1^{commit}"
}

START=$(date +%s)
RIG_DEBS_FROM=$(debs_for "$FROM")
RIG_DEBS_TO=$(debs_for "$TO")
RIG_CLI_DIR="$BUILD/cli"
mkdir -p "$RIG_CLI_DIR"
cli_for "$CLI_FROM" "$RIG_CLI_DIR/ctrl-exec-cli-from"
cli_for "$CLI_TO" "$RIG_CLI_DIR/ctrl-exec-cli-to"
export RIG_DEBS_FROM RIG_DEBS_TO RIG_CLI_DIR

[ -n "$LABEL" ] || LABEL="from-$(echo "$FROM" | tr '/' '_')-to-$(echo "$TO" | tr '/' '_')-$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$HERE/out/$LABEL"
mkdir -p "$OUT"

{
    echo "FROM     $(describe "$FROM" "$WT")  $RIG_DEBS_FROM"
    echo "TO       $(describe "$TO" "$WT")  $RIG_DEBS_TO"
    echo "CLI_FROM plugins $(describe "$CLI_FROM" "$PLUGINS")"
    echo "CLI_TO   plugins $(describe "$CLI_TO" "$PLUGINS")"
} | tee "$OUT/refs.txt"

# --- host image -------------------------------------------------------------------
# Rebuilt only when image/Dockerfile changes (its hash is a label on the image).
hash=$(sha256sum "$HERE/image/Dockerfile" | cut -c1-16)
have=$(docker image inspect "$RIG_IMG" --format '{{index .Config.Labels "ce-upgrade-rig.dockerfile"}}' 2>/dev/null || true)
if [ "$have" != "$hash" ]; then
    echo "# building $RIG_IMG"
    nice -n 19 docker build -q --label "ce-upgrade-rig.dockerfile=$hash" \
        -t "$RIG_IMG" "$HERE/image" > /dev/null
fi

if [ -z "$KEEP" ]; then trap rig_cleanup EXIT; fi

declare -A RESULT TIME
for s in "${SCENARIOS[@]}"; do
    rig_cleanup
    case "$s" in
        s1)  cmd=("$HERE/scenarios/s1-agent-srv-scripts.sh") ;;
        s1b) cmd=("$HERE/scenarios/s1-agent-srv-scripts.sh" srv-group-writable) ;;
        s2)  cmd=("$HERE/scenarios/s2-dispatcher-etc-dir.sh") ;;
        s3)  cmd=("$HERE/scenarios/s3-cloudient-compose.sh") ;;
        s4)  cmd=("$HERE/scenarios/s4-cli-input-plain-http.sh") ;;
        s5)  cmd=("$HERE/scenarios/s5-input-mode-after-fields-run.sh") ;;
        s6)  cmd=("$HERE/scenarios/s6-second-dispatcher-own-ca.sh") ;;
    esac
    echo
    echo "=== $s"
    t0=$(date +%s)
    set +e
    RIG_EVIDENCE="$OUT/$s.evidence.txt" timeout 600 "${cmd[@]}" < /dev/null 2>&1 | tee "$OUT/$s.log"
    set -e
    TIME[$s]=$(( $(date +%s) - t0 ))
    RESULT[$s]=$(sed -n 's/^RESULT: //p' "$OUT/$s.log" | tail -1)
    [ -n "${RESULT[$s]}" ] || RESULT[$s]="ERROR (no result line)"
done

{
    echo
    echo "=== summary ($(head -2 "$OUT/refs.txt" | awk '{print $1 ": " $2 " " $3}' | paste -sd ' ' -))"
    printf '%-4s %-6s %s\n' SCEN SECS RESULT
    for s in "${SCENARIOS[@]}"; do
        printf '%-4s %-6s %s\n' "$s" "${TIME[$s]}" "${RESULT[$s]}"
        grep '^not ok' "$OUT/$s.log" | sed 's/^/       /' || true
    done
    echo "total $(( $(date +%s) - START )) s; evidence in $OUT"
} | tee "$OUT/summary.txt"

rc=0
for s in "${SCENARIOS[@]}"; do
    case "${RESULT[$s]}" in PASS*) ;; *) rc=1 ;; esac
done
exit "$rc"
