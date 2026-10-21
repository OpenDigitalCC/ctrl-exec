# Wedge rig image: Alpine, ctrl-exec built from the worktree source tree.
# Build context is staged by up.sh: src.tar.gz is `git archive HEAD` of the
# worktree, so the image always holds exactly the committed source.
FROM alpine:3.21

RUN apk add --no-cache bash openssl perl perl-libwww perl-io-socket-ssl \
        perl-json perl-lwp-protocol-https ca-certificates coreutils \
        iproute2 su-exec curl gcc musl-dev libcap-dev libcap

WORKDIR /opt/ctrl-exec
COPY src.tar.gz /tmp/src.tar.gz
RUN tar xzf /tmp/src.tar.gz --strip-components=1 \
    && ./install.sh --agent \
    && ./install.sh --dispatcher \
    && ./install.sh --api \
    && rm /tmp/src.tar.gz

COPY agent.conf scripts.conf /opt/rig/
COPY rig-hello.sh /opt/ctrl-exec-scripts/rig-hello.sh
COPY sampler.pl /opt/rig/sampler.pl
COPY entrypoint.sh /entrypoint.sh
RUN chown root:root /opt/ctrl-exec-scripts/rig-hello.sh \
    && chmod 755 /opt/ctrl-exec-scripts/rig-hello.sh \
    && chmod 755 /entrypoint.sh /opt/rig/sampler.pl

EXPOSE 7445
ENTRYPOINT ["/entrypoint.sh"]
