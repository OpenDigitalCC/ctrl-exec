# run-jobs - the estate's scheduler image, as deployed with 0.12: the CLI is a
# single script on core Perl modules, jobs parse its --json output with jq.
# The scheduler loop is not under test (the rig runs one job by hand, as the
# estate's own docs do), so the container only idles.
FROM debian:trixie-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        perl \
        bsdutils \
        ca-certificates \
        jq \
 && rm -rf /var/lib/apt/lists/*

COPY ctrl-exec-cli /usr/local/bin/ctrl-exec-cli
RUN chmod 755 /usr/local/bin/ctrl-exec-cli

ENTRYPOINT ["sleep", "infinity"]
