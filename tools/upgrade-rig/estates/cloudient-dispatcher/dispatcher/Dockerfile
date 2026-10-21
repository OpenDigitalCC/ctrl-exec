# ctrl-exec dispatcher - built from the release debs (the estate's Dockerfile,
# unchanged between 0.12 and 0.13). Build context: this file, entrypoint.sh and
# the two .deb files.

FROM debian:trixie-slim

# Fixed UID/GID so bind-mount ownership is the same numeric value on every
# host. The package postinst skips user creation when the account exists.
ARG CE_UID=10001
RUN groupadd --system --gid ${CE_UID} ctrl-exec \
 && useradd  --system --uid ${CE_UID} --gid ctrl-exec \
             --no-create-home --shell /usr/sbin/nologin ctrl-exec

COPY ctrl-exec-common_*.deb ctrl-exec-dispatcher_*.deb /tmp/
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        /tmp/ctrl-exec-common_*.deb /tmp/ctrl-exec-dispatcher_*.deb \
 && rm -rf /var/lib/apt/lists/* /tmp/*.deb

COPY entrypoint.sh /dispatcher-entrypoint.sh
RUN chmod 755 /dispatcher-entrypoint.sh

EXPOSE 7444 7445
ENTRYPOINT ["/dispatcher-entrypoint.sh"]
