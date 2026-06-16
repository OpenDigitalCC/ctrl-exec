#!/bin/bash
# make-release.sh - Create a versioned release tarball and CycloneDX SBOM,
# or repackage a ctrl-exec release under a licensed brand name.
#
# Usage:
#   ./make-release.sh [--auto] [--no-deb]
#       Build ctrl-exec-<version>.tar.gz from the current source tree.
#       Bumps VERSION, creates git tag, generates sbom.json. Also builds the
#       versioned .deb packages (ctrl-exec-common, ctrl-exec-agent, ctrl-exec)
#       from debian/ into dist/, keeping debian/changelog in step with the
#       release version. --no-deb skips the .deb build; it is also skipped
#       gracefully when debian/ or dpkg-buildpackage is absent.
#
#   ./make-release.sh --brand <name> [--from ctrl-exec-<version>.tar.gz]
#       Repackage an existing ctrl-exec tarball as <name>-exec-<version>.tar.gz.
#       Does not touch git, does not bump VERSION, does not retag.
#       If --from is omitted, the most recent ctrl-exec-*.tar.gz is used.
#
# Brand substitution applies ctrl -> BRAND to all customer-facing identifiers:
# binary names, service unit names, config paths, syslog tags, package metadata.
# The Perl namespace (Exec::) and ENVEXEC_ variables are never substituted.

set -euo pipefail

# Outputs go to dist/. Release tarballs are gitignored and committed via
# git add -f; the .deb packages are tracked normally (latest release only -
# stale-version debs are pruned on each build).

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
die()   { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

# Build the versioned .deb packages from debian/ and place them alongside the
# release tarball in $1=dist dir, for release version $2. Keeps the Debian
# changelog version in step with the release. Skips gracefully (warn, no fail)
# when debian/ or dpkg-buildpackage is absent so the tarball release still
# succeeds on non-Debian hosts.
build_debs() {
    local dist="$1" version="$2"
    local parent
    parent=$(dirname "$PWD")

    if [[ ! -d debian ]]; then
        warn "No debian/ directory - skipping .deb build."
        return 0
    fi
    if ! command -v dpkg-buildpackage &>/dev/null; then
        warn "dpkg-buildpackage not found - skipping .deb build (tarball still produced)."
        return 0
    fi

    # Keep the Debian changelog version in step with the release version, so
    # the produced .debs are versioned to match. Only add an entry when it
    # differs (the first release at the current changelog version is a no-op).
    local cl_version
    cl_version=$(dpkg-parsechangelog -l debian/changelog -S Version 2>/dev/null || echo "")
    if [[ "$cl_version" != "$version" ]]; then
        info "Adding debian/changelog entry for $version (was ${cl_version:-none})..."
        DEBEMAIL="${DEBEMAIL:-sjm@opendigital.cc}" \
        DEBFULLNAME="${DEBFULLNAME:-OpenDigital CC}" \
        dch --changelog debian/changelog --newversion "$version" \
            --distribution unstable "Release $version" \
            || die "dch failed to set debian/changelog to $version"
    fi

    info "Building .deb packages (version $version)..."
    # -d: pure-Perl Architecture: all packages compile nothing, so the
    # build-essential implied build-dependency is not required.
    dpkg-buildpackage -us -uc -b -d || die ".deb build failed."

    mkdir -p "$dist"
    local moved=0 f
    for f in "$parent"/ctrl-exec*_"${version}"_*.deb \
             "$parent"/ctrl-exec_"${version}"_*.buildinfo \
             "$parent"/ctrl-exec_"${version}"_*.changes; do
        [[ -e "$f" ]] || continue
        mv -f "$f" "$dist/"
        moved=$((moved + 1))
    done
    info "Placed $moved .deb artifact(s) in $dist/"

    # Prune stale-version artefacts so dist/ carries only the current release
    # (the .deb is committed; keeping every past version would bloat the repo).
    # Mirrors the tarball cleanup further down. Untracks any that were committed.
    local removed=0 old
    for old in "$dist"/ctrl-exec*_all.deb \
               "$dist"/ctrl-exec_*.buildinfo \
               "$dist"/ctrl-exec_*.changes; do
        [[ -e "$old" ]] || continue
        case "$old" in
            *_"${version}"_*) continue ;;
        esac
        rm -f "$old"
        git rm --cached --quiet --ignore-unmatch "$old" 2>/dev/null || true
        removed=$((removed + 1))
    done
    [[ "$removed" -gt 0 ]] && info "Pruned $removed stale .deb artefact(s) from $dist/"

    # Remove build byproducts from the working tree.
    fakeroot debian/rules clean >/dev/null 2>&1 || true
}


# --- output directory ---

DIST_DIR="dist"

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

AUTO=0
BRAND=""
FROM=""
BUILD_DEBS=1

while [[ $# -gt 0 ]]; do
    case "$1" in
        --auto|--force)
            AUTO=1; shift ;;
        --brand)
            [[ -n "${2:-}" ]] || die "--brand requires a value (e.g. --brand acme)"
            BRAND="$2"; shift 2 ;;
        --from)
            [[ -n "${2:-}" ]] || die "--from requires a tarball path"
            FROM="$2"; shift 2 ;;
        --no-deb)
            BUILD_DEBS=0; shift ;;
        *)
            die "Unknown argument: $1" ;;
    esac
done

# ---------------------------------------------------------------------------
# Brand mode: repackage ctrl-exec tarball as BRAND-exec
# ---------------------------------------------------------------------------

if [[ -n "$BRAND" ]]; then

    # Locate source tarball
    if [[ -z "$FROM" ]]; then
        FROM=$(find "$DIST_DIR" -maxdepth 1 -name 'ctrl-exec-*.tar.gz' 2>/dev/null | sort -V | tail -1)
        [[ -n "$FROM" ]] || die "No ctrl-exec-*.tar.gz found. Use --from <tarball>."
        info "Using: $FROM"
    fi
    [[ -f "$FROM" ]] || die "Source tarball not found: $FROM"

    # Extract version from tarball name
    TARBALL_BASE=$(basename "$FROM")
    VERSION=$(echo "$TARBALL_BASE" | sed 's/ctrl-exec-//; s/\.tar\.gz//')
    [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] \
        || die "Could not extract semver from tarball name: $TARBALL_BASE"

    mkdir -p "$DIST_DIR"
    BRAND_TARBALL="${DIST_DIR}/${BRAND}-exec-${VERSION}.tar.gz"
    BRAND_NAME="${BRAND}-exec-${VERSION}"

    info "Building $BRAND_TARBALL from $FROM (version $VERSION)"

    STAGE_DIR=$(mktemp -d)
    trap 'rm -rf "$STAGE_DIR"' EXIT

    # Unpack ctrl-exec tarball
    tar -xzf "$FROM" -C "$STAGE_DIR"

    # Detect the actual top-level directory name inside the tarball
    # (may be ctrl-exec-<version> or dispatcher-<version> from a pre-rename
    # build). Read it from the just-extracted tree rather than piping
    # `tar -tzf | head`, which raises SIGPIPE under `set -o pipefail`.
    UNPACKED_DIR=$(find "$STAGE_DIR" -maxdepth 1 -mindepth 1 -type d -printf '%f\n')
    [[ -n "$UNPACKED_DIR" && -d "$STAGE_DIR/$UNPACKED_DIR" ]] \
        || die "Expected unpacked directory not found under $STAGE_DIR"

    # Rename top-level directory to brand name
    mv "$STAGE_DIR/$UNPACKED_DIR" "$STAGE_DIR/$BRAND_NAME"
    STAGE="$STAGE_DIR/$BRAND_NAME"

    # -----------------------------------------------------------------------
    # Brand substitution: ctrl -> BRAND in all text files.
    # Compound forms are replaced before the bare word to avoid
    # double-substitution (ctrl-exec-agent must not become BRAND-BRAND-exec-agent).
    # -----------------------------------------------------------------------

    info "Applying brand substitution: ctrl -> $BRAND ..."

    find "$STAGE" -type f \
        ! -name '*.png' ! -name '*.jpg' ! -name '*.gif' \
        ! -name '*.tar.gz' ! -name '*.zip' \
    | while IFS= read -r f; do
        grep -q "ctrl" "$f" 2>/dev/null || continue
        sed -i \
            -e "s/ctrl-exec-dispatcher/${BRAND}-exec-dispatcher/g" \
            -e "s/ctrl-exec-agent/${BRAND}-exec-agent/g" \
            -e "s/ctrl-exec-api/${BRAND}-exec-api/g" \
            -e "s/ctrl-exec-plugins/${BRAND}-exec-plugins/g" \
            -e "s/ctrl-exec-demonstrator/${BRAND}-exec-demonstrator/g" \
            -e "s/ctrl-exec-serial/${BRAND}-exec-serial/g" \
            -e "s/update-ctrl-exec/update-${BRAND}-exec/g" \
            -e "s|/etc/ctrl-exec-agent|/etc/${BRAND}-exec-agent|g" \
            -e "s|/etc/ctrl-exec|/etc/${BRAND}-exec|g" \
            -e "s|/var/lib/ctrl-exec|/var/lib/${BRAND}-exec|g" \
            -e "s|/usr/local/lib/ctrl-exec|/usr/local/lib/${BRAND}-exec|g" \
            -e "s|/opt/ctrl-exec-scripts|/opt/${BRAND}-exec-scripts|g" \
            -e "s/ctrl-exec/${BRAND}-exec/g" \
            "$f"
    done

    # Rename files
    declare -A FMAP=(
        ["bin/ctrl-exec-dispatcher"]="bin/${BRAND}-exec-dispatcher"
        ["bin/ctrl-exec-agent"]="bin/${BRAND}-exec-agent"
        ["bin/ctrl-exec-api"]="bin/${BRAND}-exec-api"
        ["bin/update-ctrl-exec-serial"]="bin/update-${BRAND}-exec-serial"
        ["etc/ctrl-exec-agent.service"]="etc/${BRAND}-exec-agent.service"
        ["etc/ctrl-exec-api.service"]="etc/${BRAND}-exec-api.service"
        ["etc/ctrl-exec-agent.init"]="etc/${BRAND}-exec-agent.init"
        ["etc/ctrl-exec.conf.example"]="etc/${BRAND}-exec.conf.example"
        ["etc/ctrl-exec_conf.example"]="etc/${BRAND}-exec_conf.example"
        ["etc/ctrl-exec-agent_conf.example"]="etc/${BRAND}-exec-agent_conf.example"
        ["etc/ctrl-exec-demonstrator.sh"]="etc/${BRAND}-exec-demonstrator.sh"
    )
    for old in "${!FMAP[@]}"; do
        new="${FMAP[$old]}"
        [[ -f "$STAGE/$old" ]] && mv "$STAGE/$old" "$STAGE/$new"
    done

    # -----------------------------------------------------------------------
    # Verify the rebrand produced valid Perl. Substituting ctrl -> BRAND turns
    # an unquoted hyphenated bareword (e.g. a hash key $opts{ctrl-exec}) into
    # BRAND-exec, which 'use strict' rejects. A compile check of every staged
    # bin and module catches that class of breakage - which had to be fixed by
    # hand during the original dispatcher -> ctrl-exec rename - and any other
    # damage the substitution might do.
    # -----------------------------------------------------------------------
    info "Verifying rebranded Perl compiles..."
    rebrand_err=0
    while IFS= read -r pf; do
        # Only check Perl: library modules and scripts with a perl shebang.
        # bin/ also holds shell helpers (e.g. update-*-serial) that perl -c
        # must skip.
        if [[ "$pf" != *.pm ]]; then
            read -r shebang < "$pf" || true
            [[ "$shebang" == *perl* ]] || continue
        fi
        if ! perl -c -I"$STAGE/lib" "$pf" >/dev/null 2>&1; then
            warn "Rebranded Perl fails to compile: ${pf#"$STAGE"/}"
            perl -c -I"$STAGE/lib" "$pf" 2>&1 | sed 's/^/    /' >&2
            rebrand_err=1
        fi
    done < <(find "$STAGE/bin" "$STAGE/lib" -type f \
                  \( -name '*.pm' -o -path "$STAGE/bin/*" \) 2>/dev/null)
    [[ "$rebrand_err" -eq 0 ]] \
        || die "Rebrand introduced invalid Perl (see above). Quote any hyphenated hash keys in the source (e.g. \$opts{'ctrl-exec'}) and retry."

    # -----------------------------------------------------------------------
    # Brand SBOM (separate from ctrl-exec sbom.json)
    # -----------------------------------------------------------------------

    info "Generating CycloneDX SBOM for ${BRAND}-exec ..."

    TIMESTAMP=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
    BSERIAL="urn:uuid:$(python3 -c "import uuid; print(uuid.uuid4())")"
    BRAND_SBOM="${BRAND}-exec-${VERSION}-sbom.json"

    python3 - "$STAGE" "$VERSION" "$BRAND" "$BSERIAL" "$TIMESTAMP" "$BRAND_SBOM" <<'PYEOF'
import json, sys, os, hashlib

stage, version, brand, serial, timestamp, outfile = sys.argv[1:7]
components = []

def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as fh:
        for chunk in iter(lambda: fh.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()

for dirpath, name_key, ctype in [
    (os.path.join(stage, 'bin'), None, 'file'),
]:
    if os.path.isdir(dirpath):
        for name in sorted(os.listdir(dirpath)):
            path = os.path.join(dirpath, name)
            if os.path.isfile(path):
                components.append({
                    'type': 'file', 'name': name, 'version': version,
                    'hashes': [{'alg': 'SHA-256', 'content': sha256(path)}],
                    'licenses': [{'license': {'id': 'proprietary'}}],
                    'purl': f'pkg:generic/{brand}/{name}@{version}'
                })

lib_dir = os.path.join(stage, 'lib')
if os.path.isdir(lib_dir):
    for root, dirs, files in os.walk(lib_dir):
        dirs.sort()
        for fname in sorted(files):
            path = os.path.join(root, fname)
            if fname.endswith('.pm'):
                rel = os.path.relpath(path, lib_dir)
                name = rel.replace(os.sep, '::').removesuffix('.pm')
                ctype = 'library'
            else:
                name = fname
                ctype = 'file'
            components.append({
                'type': ctype, 'name': name, 'version': version,
                'hashes': [{'alg': 'SHA-256', 'content': sha256(path)}],
                'licenses': [{'license': {'id': 'proprietary'}}],
                'purl': f'pkg:generic/{brand}/{name}@{version}'
            })

deps = [
    {'type': 'library', 'name': 'IO::Socket::SSL', 'version': 'unknown',
     'description': 'TLS sockets. Debian: libio-socket-ssl-perl'},
    {'type': 'library', 'name': 'JSON', 'version': 'unknown',
     'description': 'JSON encode/decode. Debian: libjson-perl'},
    {'type': 'library', 'name': 'LWP::UserAgent', 'version': 'unknown',
     'description': 'HTTP client. Debian: libwww-perl'},
    {'type': 'library', 'name': 'perl', 'version': 'unknown',
     'description': 'Perl runtime. Debian: perl'},
    {'type': 'library', 'name': 'openssl', 'version': 'unknown',
     'description': 'Key and certificate operations. Debian: openssl'},
]

sbom = {
    'bomFormat': 'CycloneDX', 'specVersion': '1.6',
    'serialNumber': serial, 'version': 1,
    'metadata': {
        'timestamp': timestamp,
        'tools': [{'name': 'make-release.sh'}],
        'component': {
            'type': 'application',
            'name': f'{brand}-exec',
            'version': version,
            'description': 'Perl mTLS remote script execution system',
            'licenses': [{'license': {'id': 'proprietary'}}],
        }
    },
    'components': components + deps
}

with open(outfile, 'w') as fh:
    json.dump(sbom, fh, indent=2)
print(f'Written: {outfile}')
PYEOF

    cp "$BRAND_SBOM" "$STAGE/$BRAND_SBOM"

    # Remove the ctrl-exec sbom from the brand package
    rm -f "$STAGE/sbom.json"

    # Repack
    tar -czf "$BRAND_TARBALL" -C "$STAGE_DIR" "$BRAND_NAME"
    BRAND_HASH=$(sha256sum "$BRAND_TARBALL" | awk '{print $1}')
    echo "$BRAND_HASH  $BRAND_TARBALL" > "${BRAND_TARBALL%.tar.gz}.tar.gz.sha256"

    echo ""
    echo "================================================================"
    echo " Brand package complete"
    echo "================================================================"
    echo ""
    echo "  Source:    $FROM"
    echo "  Brand:     ${BRAND}-exec"
    echo "  Version:   $VERSION"
    echo "  Tarball:   $BRAND_TARBALL"
    echo "  Checksum:  ${BRAND_TARBALL%.tar.gz}.tar.gz.sha256"
    echo "  SBOM:      $BRAND_SBOM"
    echo ""
    echo "  Deliver $BRAND_TARBALL and $BRAND_SBOM to the licensed distributor."
    echo "  Do not distribute the ctrl-exec source tarball."
    echo ""
    echo "================================================================"
    exit 0
fi

# ---------------------------------------------------------------------------
# Standard ctrl-exec release
# ---------------------------------------------------------------------------

# Read version to release from NEXT_VERSION if present, otherwise VERSION
if [[ -f "NEXT_VERSION" ]]; then
    VERSION=$(cat "NEXT_VERSION" | tr -d '[:space:]')
    info "Release version: $VERSION (from NEXT_VERSION)"
elif [[ -f "VERSION" ]]; then
    VERSION=$(cat "VERSION" | tr -d '[:space:]')
    info "Release version: $VERSION (from VERSION)"
else
    die "Neither NEXT_VERSION nor VERSION file found."
fi
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] \
    || die "VERSION must be semver n.n.n, got: $VERSION"

if ! git rev-parse --git-dir &>/dev/null; then
    die "Not a git repository."
fi

if ! git diff --quiet || ! git diff --cached --quiet; then
    die "Working tree has uncommitted changes. Commit or stash before releasing."
fi

COMMIT=$(git rev-parse HEAD)
info "Git commit: $COMMIT"

RELEASE_NAME="ctrl-exec-${VERSION}"
mkdir -p "$DIST_DIR"
TARBALL="${DIST_DIR}/${RELEASE_NAME}.tar.gz"
STAGE_DIR=$(mktemp -d)
STAGE="${STAGE_DIR}/${RELEASE_NAME}"
trap 'rm -rf "$STAGE_DIR"' EXIT

SHIP_FILES=(
    bin/ctrl-exec-dispatcher
    bin/ctrl-exec-agent
    bin/ctrl-exec-api
    bin/update-ctrl-exec-serial
    install.sh
    VERSION
    LICENCE
    COMMERCIAL_LICENCE.md
    README.md
    docs/API.md
    docs/BACKGROUND.md
    docs/DEVELOPER.md
    docs/DOCKER.md
    docs/INSTALL.md
    docs/MANUAL-CHECKS.md
    docs/REFERENCE.md
    docs/SECURITY.md
)

SHIP_DIRS=(lib etc t)

info "Staging files..."
mkdir -p "$STAGE"

for f in "${SHIP_FILES[@]}"; do
    [[ -f "$f" ]] || die "Expected file not found: $f"
    mkdir -p "$STAGE/$(dirname "$f")"
    cp "$f" "$STAGE/$f"
done

for d in "${SHIP_DIRS[@]}"; do
    [[ -d "$d" ]] || die "Expected directory not found: $d"
    cp -r "$d" "$STAGE/"
done

info "Stamping version $VERSION in binaries..."
chmod 755 "$STAGE/install.sh"
for bin in ctrl-exec-dispatcher ctrl-exec-agent ctrl-exec-api; do
    [[ -f "$STAGE/bin/$bin" ]] || continue
    sed -i "s/our \$VERSION = .*/our \$VERSION = '$VERSION';/" \
        "$STAGE/bin/$bin"
done

info "Generating CycloneDX SBOM..."

# The full-project SBOM travels in the tarball (and is committed at the repo
# root). Per-package SBOMs are generated for each .deb by debian/rules during the
# package build; both use tools/generate-sbom.py, so the two never drift. Read
# from the staged, version-stamped tree so component hashes match the tarball.
python3 tools/generate-sbom.py \
    --scope full --version "$VERSION" \
    --bin-dir "$STAGE/bin" --lib-dir "$STAGE/lib" \
    --out sbom.json

info "sbom.json written ($(wc -l < sbom.json) lines)"
cp sbom.json "$STAGE/sbom.json"

info "Creating tarball: $TARBALL"

while IFS= read -r old; do
    old_base="${old}"
    [[ "$old_base" == "$TARBALL" ]] && continue
    old_sha="${old_base%.tar.gz}.tar.gz.sha256"
    rm -f "$old_base" "$old_sha"
    git rm --cached --quiet --ignore-unmatch "$old_base" "$old_sha" 2>/dev/null || true
    info "Removed previous tarball: $old_base"
done < <(find "$DIST_DIR" -maxdepth 1 -name 'ctrl-exec-*.tar.gz' | sort)

tar -czf "$TARBALL" -C "$STAGE_DIR" "$RELEASE_NAME"

TARBALL_HASH=$(sha256sum "$TARBALL" | awk '{print $1}')
info "SHA-256: $TARBALL_HASH"
echo "$TARBALL_HASH  $TARBALL" > "${TARBALL}.sha256"

if [[ "$BUILD_DEBS" -eq 1 ]]; then
    build_debs "$DIST_DIR" "$VERSION"
else
    info "Skipping .deb build (--no-deb)."
fi

TAG="v${VERSION}"
if git rev-parse "$TAG" &>/dev/null 2>&1; then
    warn "Tag $TAG already exists - skipping tag creation."
else
    git tag -a "$TAG" -m "Release $VERSION"
    info "Tagged: $TAG"
fi

MAJOR=$(echo "$VERSION" | cut -d. -f1)
MINOR=$(echo "$VERSION" | cut -d. -f2)
PATCH=$(echo "$VERSION" | cut -d. -f3)
NEXT_VERSION="${MAJOR}.${MINOR}.$((PATCH + 1))"
echo "$VERSION" > VERSION          # VERSION = current release, for dist/ link
echo "$NEXT_VERSION" > NEXT_VERSION  # NEXT_VERSION = what the next run will build
info "VERSION set to $VERSION (current release). NEXT_VERSION set to $NEXT_VERSION."

echo ""
echo "================================================================"
echo " Release $VERSION complete"
echo "================================================================"
echo ""
echo "  Tarball:   $TARBALL"
echo "  Checksum:  ${TARBALL}.sha256"
echo "  SBOM:      sbom.json"
if [[ "$BUILD_DEBS" -eq 1 ]] && compgen -G "$DIST_DIR/ctrl-exec*_${VERSION}_all.deb" >/dev/null; then
    echo "  Packages:  $DIST_DIR/ctrl-exec-common_${VERSION}_all.deb"
    echo "             $DIST_DIR/ctrl-exec-agent_${VERSION}_all.deb"
    echo "             $DIST_DIR/ctrl-exec-dispatcher_${VERSION}_all.deb"
fi
echo "  Tag:       $TAG  ($COMMIT)"
echo "  Next ver:  $NEXT_VERSION  (written to NEXT_VERSION)"
echo ""
echo "  To build a branded package from this release:"
echo "    ./make-release.sh --brand <name> --from $TARBALL"
echo ""

if [[ "$AUTO" -eq 1 ]]; then
    info "Auto mode: committing and pushing..."
    git add -u                             # stages tarball/deb deletions from git rm above
    git add sbom.json VERSION NEXT_VERSION debian/changelog
    git add -f "$TARBALL" "${TARBALL}.sha256"
    [[ "$BUILD_DEBS" -eq 1 ]] && git add "$DIST_DIR"/ctrl-exec*_"${VERSION}"_all.deb 2>/dev/null
    git commit -m "release: $VERSION"
    git push
    git push origin "$TAG"
    info "Released and pushed."
else
    echo "Next steps:"
    echo ""
    echo "  1. Review sbom.json and commit everything for the release:"
    echo "       git add -u"
    echo "       git add sbom.json VERSION NEXT_VERSION debian/changelog"
    echo "       git add -f $TARBALL ${TARBALL}.sha256"
    if [[ "$BUILD_DEBS" -eq 1 ]]; then
        echo "       git add $DIST_DIR/ctrl-exec*_${VERSION}_all.deb"
    fi
    echo "       git commit -m 'release: $VERSION'"
    echo ""
    echo "  2. Push commits and tag:"
    echo "       git push && git push origin $TAG"
    echo ""
    if [[ "$BUILD_DEBS" -eq 1 ]]; then
        echo "  The .deb packages in $DIST_DIR/ are tracked in git (latest"
        echo "  release only; stale versions are pruned automatically). Copy"
        echo "  to /srv/projects/packages/ or your apt repo as needed."
        echo ""
    fi
fi

echo "================================================================"
