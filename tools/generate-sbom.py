#!/usr/bin/env python3
"""Generate a CycloneDX SBOM for ctrl-exec, scoped to a package or the whole
project.

Components are the shipped source files (binaries and scripts as 'file', Perl
modules as 'library'); external dependencies are detected by scanning those
files' contents, so a package's SBOM lists only the externals its own code
references. Scopes:

    full        every binary + the whole Exec:: library (the tarball SBOM)
    common      the Exec:: library only          (ctrl-exec-common)
    agent       ctrl-exec-agent + update-ctrl-exec-serial   (ctrl-exec-agent)
    dispatcher  ctrl-exec-dispatcher + ctrl-exec-api         (ctrl-exec-dispatcher)

Used by both make-release.sh (full SBOM -> tarball) and debian/rules (per-package
SBOMs -> each .deb) so the two can never drift. Component hashes are taken from
whatever tree --bin-dir/--lib-dir point at, so callers pass the staged,
version-stamped tree to get hashes that match the shipped files.
"""
import argparse
import datetime
import hashlib
import json
import os
import re
import sys
import uuid

LICENSE = {'license': {'id': 'AGPL-3.0-only'}}

# External (non-core) runtime dependencies. Each is included in a scope's SBOM
# only when its signature is found in that scope's file contents. perl is the
# runtime itself and is added for any scope that ships executable code.
DEPS = [
    {
        'name': 'IO::Socket::SSL',
        'sig': re.compile(r'IO::Socket::SSL'),
        'description': 'TLS sockets. Debian: libio-socket-ssl-perl, Alpine: perl-io-socket-ssl',
        'refs': [
            'https://packages.debian.org/trixie/libio-socket-ssl-perl',
            'https://pkgs.alpinelinux.org/package/edge/main/x86_64/perl-io-socket-ssl',
        ],
    },
    {
        'name': 'JSON',
        'sig': re.compile(r'(?:use|require)\s+JSON\b'),
        'description': 'JSON encode/decode. Debian: libjson-perl, Alpine: perl-json',
        'refs': [
            'https://packages.debian.org/trixie/libjson-perl',
            'https://pkgs.alpinelinux.org/package/edge/main/x86_64/perl-json',
        ],
    },
    {
        'name': 'LWP::UserAgent',
        'sig': re.compile(r'LWP::UserAgent'),
        'description': 'HTTP client. Debian: libwww-perl, Alpine: perl-libwww',
        'refs': [
            'https://packages.debian.org/trixie/libwww-perl',
            'https://pkgs.alpinelinux.org/package/edge/main/x86_64/perl-libwww',
        ],
    },
    {
        'name': 'openssl',
        'sig': re.compile(r'\bopenssl\b'),
        'description': 'Key, CSR, and certificate operations. Debian: openssl, Alpine: openssl',
        'refs': [
            'https://packages.debian.org/trixie/openssl',
            'https://pkgs.alpinelinux.org/package/edge/main/x86_64/openssl',
        ],
    },
]

PERL_DEP = {
    'name': 'perl',
    'description': 'Perl runtime and core modules. Debian: perl, Alpine: perl',
    'refs': [
        'https://packages.debian.org/trixie/perl',
        'https://pkgs.alpinelinux.org/package/edge/main/x86_64/perl',
    ],
}

# Scope -> which binaries it ships (None = every binary), whether it ships the
# Exec:: library, and the application component name for the SBOM metadata.
SCOPES = {
    'full':       {'bins': None, 'libs': True,  'app': 'ctrl-exec'},
    'common':     {'bins': [],   'libs': True,  'app': 'ctrl-exec-common'},
    'agent':      {'bins': ['ctrl-exec-agent', 'update-ctrl-exec-serial'],
                   'libs': False, 'app': 'ctrl-exec-agent'},
    'dispatcher': {'bins': ['ctrl-exec-dispatcher', 'ctrl-exec-api'],
                   'libs': False, 'app': 'ctrl-exec-dispatcher'},
}


def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as fh:
        for chunk in iter(lambda: fh.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


def component(name, ctype, path, version):
    return {
        'type': ctype,
        'name': name,
        'version': version,
        'hashes': [{'alg': 'SHA-256', 'content': sha256(path)}],
        'licenses': [LICENSE],
        'purl': 'pkg:generic/opendigital/{}@{}'.format(name, version),
    }


def collect(scope, bin_dir, lib_dir, version):
    """Return (components, scanned_paths) for the scope."""
    spec = SCOPES[scope]
    components = []
    scanned = []

    # Binaries / scripts -> 'file' components.
    if spec['bins'] is None:
        names = sorted(os.listdir(bin_dir)) if os.path.isdir(bin_dir) else []
    else:
        names = spec['bins']
    for name in names:
        path = os.path.join(bin_dir, name)
        if os.path.isfile(path):
            components.append(component(name, 'file', path, version))
            scanned.append(path)

    # Exec:: library -> 'library' for .pm, 'file' for anything else (openapi.json).
    if spec['libs'] and os.path.isdir(lib_dir):
        for root, dirs, files in os.walk(lib_dir):
            dirs.sort()
            for fname in sorted(files):
                path = os.path.join(root, fname)
                if fname.endswith('.pm'):
                    rel = os.path.relpath(path, lib_dir)
                    name = rel.replace(os.sep, '::')[:-3]
                    components.append(component(name, 'library', path, version))
                else:
                    components.append(component(fname, 'file', path, version))
                scanned.append(path)

    return components, scanned


def detect_deps(paths):
    """Externals whose signature appears in any of the scanned files, plus perl
    whenever the scope ships executable code."""
    blob = []
    for path in paths:
        try:
            with open(path, 'r', errors='ignore') as fh:
                blob.append(fh.read())
        except OSError:
            pass
    text = '\n'.join(blob)

    deps = []
    for dep in DEPS:
        if dep['sig'].search(text):
            deps.append(dep)
    found = [
        {
            'type': 'library',
            'name': d['name'],
            'version': 'unknown',
            'description': d['description'],
            'externalReferences': [
                {'type': 'distribution', 'url': u} for u in d['refs']
            ],
        }
        for d in deps
    ]
    if paths:
        found.append({
            'type': 'library',
            'name': PERL_DEP['name'],
            'version': 'unknown',
            'description': PERL_DEP['description'],
            'externalReferences': [
                {'type': 'distribution', 'url': u} for u in PERL_DEP['refs']
            ],
        })
    return found


def build(scope, bin_dir, lib_dir, version, timestamp, serial):
    components, scanned = collect(scope, bin_dir, lib_dir, version)
    deps = detect_deps(scanned)
    return {
        'bomFormat': 'CycloneDX',
        'specVersion': '1.6',
        'serialNumber': serial,
        'version': 1,
        'metadata': {
            'timestamp': timestamp,
            'tools': [{'name': 'generate-sbom.py', 'version': version}],
            'component': {
                'type': 'application',
                'name': SCOPES[scope]['app'],
                'version': version,
                'description': 'Perl mTLS remote script execution system',
                'licenses': [LICENSE],
                'externalReferences': [
                    {'type': 'vcs', 'url': 'https://github.com/OpenDigitalCC/ctrl-exec'},
                ],
            },
        },
        'components': components + deps,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--scope', required=True, choices=sorted(SCOPES))
    ap.add_argument('--version', required=True)
    ap.add_argument('--bin-dir', default='bin')
    ap.add_argument('--lib-dir', default='lib')
    ap.add_argument('--out', required=True)
    ap.add_argument('--timestamp', default=None)
    ap.add_argument('--serial', default=None)
    args = ap.parse_args()

    timestamp = args.timestamp or datetime.datetime.now(
        datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    serial = args.serial or 'urn:uuid:{}'.format(uuid.uuid4())

    sbom = build(args.scope, args.bin_dir, args.lib_dir, args.version,
                 timestamp, serial)
    with open(args.out, 'w') as fh:
        json.dump(sbom, fh, indent=2)
        fh.write('\n')


if __name__ == '__main__':
    main()
