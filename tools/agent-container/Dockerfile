FROM debian:trixie-slim

# The agent package is architecture-specific (it carries the C executor), so
# use the .deb that matches the image platform.
COPY ctrl-exec-common_*.deb ctrl-exec-agent_*.deb /tmp/
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        /tmp/ctrl-exec-common_*.deb /tmp/ctrl-exec-agent_*.deb \
        rsyslog rsyslog-gnutls ca-certificates \
 && rm -rf /var/lib/apt/lists/* /tmp/*.deb

COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh

EXPOSE 7443
ENTRYPOINT ["/entrypoint.sh"]
