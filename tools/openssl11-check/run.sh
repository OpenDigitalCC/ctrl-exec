#!/bin/bash
# OpenSSL 1.1 check (T-067): run the TLS, trust and pairing tests of a
# committed tree against a distribution release whose system OpenSSL is the
# 1.1.1 line (Debian 11 by default, Ubuntu 20.04 with --distro focal), then
# remove everything and print a verdict. A release check the owner runs by
# hand; not part of the default suite (prove t/ never calls it). See README.md.
#
#   tools/openssl11-check/run.sh [options] [t/<file>.t ...]
#
#   --ref R        commit-ish to test (default HEAD of this checkout). Only
#                  committed content is copied (git archive); uncommitted edits
#                  are never tested.
#   --distro D     bullseye (debian:bullseye-slim, OpenSSL 1.1.1w; default)
#                  or focal (ubuntu:20.04, OpenSSL 1.1.1f)
#   --keep-image   keep the built image (and the base image) for a later run
#
#   Test files default to the trust/pairing/TLS list below.
#
# Exit 0 and "VERDICT: PASS" when every test file passed; 1 and
# "VERDICT: FAIL" otherwise; 2 on a usage or setup error.
#
# Network: building the image pulls the base image and installs packages with
# apt. That is the only network use; the tests themselves run in a container
# with no network (loopback only).
set -euo pipefail

HERE=$(readlink -f "$(dirname "$0")")
WT=$(readlink -f "$HERE/../..")

REF=HEAD
DISTRO=bullseye
KEEP_IMAGE=""
TESTS=()

# Every test that makes a TLS connection, builds or verifies a certificate,
# or reads the agent's CA bundle or trusted-dispatcher map.
DEFAULT_TESTS=(
    t/agent-ca-bundle.t t/agent-trust-issuer.t t/pairing-verified.t
    t/pairing-keep-cert.t t/agent-remove-dispatcher.t t/ca-cert-roles.t
    t/ca-subject-aki.t t/trusted-dispatchers.t t/rotate-serial.t
    t/cert-renewal.t t/agent-script-dispatchers.t
    t/agent-429.t t/agent-reload.t t/agent-scripts-autoreload.t
    t/agent-serve-unpaired.t t/agent-probe.t t/api-transport.t
    t/ca-random-serials.t t/ca-validation.t t/csr-validation.t
    t/pairing-csr.t t/pairing-timeout.t t/pairing-queue-limit.t
    t/pairing-code-binding.t t/pairing-serial-source.t t/renewal.t
    t/rotation.t t/serial-normalisation.t
    t/engine-old-cert-hint.t t/agent-doctor.t t/dispatcher-doctor.t
)

usage() { sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
    case "$1" in
        --ref)        REF=$2; shift 2 ;;
        --distro)     DISTRO=$2; shift 2 ;;
        --keep-image) KEEP_IMAGE=1; shift ;;
        -h|--help)    usage; exit 0 ;;
        -*)           echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
        *)            TESTS+=("$1"); shift ;;
    esac
done
[ ${#TESTS[@]} -gt 0 ] || TESTS=("${DEFAULT_TESTS[@]}")

case "$DISTRO" in
    bullseye) BASE=debian:bullseye-slim ;;
    focal)    BASE=ubuntu:20.04 ;;
    *) echo "unknown distro: $DISTRO (bullseye or focal)" >&2; exit 2 ;;
esac

SHA=$(git -C "$WT" rev-parse --verify "$REF^{commit}") || {
    echo "not a commit: $REF" >&2
    exit 2
}
IMG="ce-openssl11-check:$DISTRO"
CTR="ce-openssl11-check-$DISTRO-$$"

# Remove what this run made: the container always; the image, and the base
# image when this run pulled it, unless --keep-image.
HAD_BASE=""
if docker image inspect "$BASE" > /dev/null 2>&1; then
    HAD_BASE=1
fi
# shellcheck disable=SC2317  # invoked by the trap
cleanup() {
    docker rm -f "$CTR" > /dev/null 2>&1 || true
    if [ -z "$KEEP_IMAGE" ]; then
        docker rmi "$IMG" > /dev/null 2>&1 || true
        if [ -z "$HAD_BASE" ]; then
            docker rmi "$BASE" > /dev/null 2>&1 || true
        fi
    fi
}
trap cleanup EXIT INT TERM

echo "== ref $REF ($SHA), $BASE"
docker build -q --build-arg "BASE=$BASE" -t "$IMG" "$HERE" > /dev/null

# One CPU, 1 GB, no network: the tests use loopback only.
docker create --name "$CTR" --cpus 1 --memory 1g --pids-limit 512 \
    --network none "$IMG" "${TESTS[@]}" > /dev/null
git -C "$WT" archive --format=tar --prefix=src/ "$SHA" | docker cp - "$CTR:/"

set +e
docker start -a "$CTR"
rc=$?
set -e

echo
if [ "$rc" -eq 0 ]; then
    echo "VERDICT: PASS ($BASE, $SHA)"
    exit 0
fi
echo "VERDICT: FAIL ($BASE, $SHA, prove exit $rc)"
exit 1
