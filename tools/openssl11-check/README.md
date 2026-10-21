# openssl11-check: the TLS and trust tests on OpenSSL 1.1 (T-067)

The development hosts run OpenSSL 3. Debian 11 and Ubuntu 20.04, which
existing estates still run, ship the OpenSSL 1.1.1 line with Net::SSLeay
1.88, and both differ in ways the default suite never sees (T-066: Net::SSLeay
before 1.92 returns nothing from `X509_STORE_CTX_init`; T-067: `openssl x509
-req` adds no key identifiers on 1.1). This check runs the tests that touch
TLS, certificates, the agent's CA bundle and the trusted-dispatcher map inside
a Debian 11 (or Ubuntu 20.04) container, against that release's own OpenSSL
and Perl modules.

It is not part of the default suite (`prove t/` never calls it). Run it by
hand before a release cut, and after any change to agent trust, pairing,
certificate issue or the TLS listener.

## Commands

    tools/openssl11-check/run.sh                       # HEAD on Debian 11, default test list
    tools/openssl11-check/run.sh --distro focal        # HEAD on Ubuntu 20.04
    tools/openssl11-check/run.sh --ref v0.13.2 t/agent-reload.t t/renewal.t
    tools/openssl11-check/run.sh --keep-image          # keep the image for a quicker next run

`--ref R`
: the commit-ish to test (default `HEAD`). The committed tree at that commit is
  copied in with `git archive`; uncommitted edits are never tested, so commit
  first.

`--distro D`
: `bullseye` (`debian:bullseye-slim`, OpenSSL 1.1.1w; the default) or
  `focal` (`ubuntu:20.04`, OpenSSL 1.1.1f).

`--keep-image`
: keep the built image, and the base image if this run pulled it. By default
  both are removed at the end.

Test files given as arguments replace the default list (in `run.sh`). The
output is prove's, then one line: `VERDICT: PASS (...)` with exit 0, or
`VERDICT: FAIL (...)` with exit 1. Exit 2 is a usage or setup error.

## What it does

1. Builds `ce-openssl11-check:<distro>` from the `Dockerfile` here: the base
   image plus `perl`, `openssl`, `libnet-ssleay-perl`,
   `libio-socket-ssl-perl`, `libjson-perl`, `libwww-perl` from the release's
   own packages. Debian 11 is archived, so its apt sources are pointed at
   `archive.debian.org`.
2. Creates one container limited to one CPU, 1 GB of memory and 512
   processes, with **no network** (the tests use loopback only), and copies the
   committed tree into it.
3. Runs `prove -Ilib` on the test list as an unprivileged user, as on a
   development host. Tests that need root, gcc or a running system skip, as
   they do there.
4. Removes the container, and the image unless `--keep-image`, on every exit.

## Network use

Building the image pulls the base image from Docker Hub and installs packages
with apt (from `archive.debian.org` for Debian 11). That is the only network
use, and it is why this is a check the owner runs by hand rather than a test:
the default suite and the other wrappers make no network access. The tests
themselves run with the container's network disabled.

Needs docker; no root.
