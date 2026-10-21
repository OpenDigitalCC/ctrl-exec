# OpenSSL 1.1 check image (T-067): a distribution release whose system OpenSSL
# is the 1.1.1 line, with the Perl modules ctrl-exec uses from its own
# packages, so the tests run against that release's OpenSSL and Net::SSLeay.
# BASE is debian:bullseye-slim (OpenSSL 1.1.1w, Net::SSLeay 1.88) or
# ubuntu:20.04 (OpenSSL 1.1.1f, Net::SSLeay 1.88). Debian 11 is archived, so
# its apt sources point at archive.debian.org.
ARG BASE=debian:bullseye-slim
FROM ${BASE}

ARG BASE
ENV DEBIAN_FRONTEND=noninteractive
RUN case "$BASE" in \
      debian:bullseye*) \
        printf '%s\n' \
          'deb http://archive.debian.org/debian bullseye main' \
          'deb http://archive.debian.org/debian-security bullseye-security main' \
          > /etc/apt/sources.list ;; \
    esac \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
        perl openssl libnet-ssleay-perl libio-socket-ssl-perl libjson-perl \
        libwww-perl liblwp-protocol-https-perl ca-certificates procps \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -m tester

COPY inside.sh /usr/local/bin/openssl11-inside
ENTRYPOINT ["/usr/local/bin/openssl11-inside"]
