#!/bin/sh
# The estate's 0.12-era dispatcher entrypoint. Runs as root: fixes bind-mount
# ownership, seeds config and CA on first start, runs the cert-maintenance
# loop (the deb's systemd timer), then drops to the ctrl-exec user for the
# API. Root retains the CA key; the network-facing API never has it.
set -eu

CONF_DIR=/etc/ctrl-exec
CONF=$CONF_DIR/ctrl-exec.conf
STATE_DIR=/var/lib/ctrl-exec
MAINT_INTERVAL=${MAINT_INTERVAL:-14400}   # 4h, matches the deb timer

log() { echo "[entrypoint] $*"; }

fix_perms() {
    chown root:ctrl-exec "$CONF_DIR" && chmod 750 "$CONF_DIR"
    for d in pairing agents locks runs; do
        mkdir -p "$STATE_DIR/$d"
        chown root:ctrl-exec "$STATE_DIR/$d" && chmod 2770 "$STATE_DIR/$d"
    done
}

write_config() {
    [ -f "$CONF" ] && return 0
    log "seeding $CONF from environment"
    cat > "$CONF" << EOC
# Seeded by entrypoint on first start. Edit on the host; restart to apply.
cert = $CONF_DIR/dispatcher.crt
key  = $CONF_DIR/dispatcher.key
ca   = $CONF_DIR/ca.crt

dispatcher_id    = ${DISPATCHER_ID:-dispatcher}
api_bind         = ${API_BIND:-0.0.0.0}
api_port         = ${API_PORT:-7445}
api_auth_default = ${API_AUTH_DEFAULT:-deny}
EOC
    [ -f "$CONF_DIR/auth-hook" ] && echo "auth_hook = $CONF_DIR/auth-hook" >> "$CONF"
    chown root:ctrl-exec "$CONF" && chmod 640 "$CONF"
}

init_ca() {
    [ -f "$CONF_DIR/ca.crt" ] && return 0
    log "first start: creating CA and dispatcher cert"
    ced setup-ca
    ced setup-ctrl-exec
}

maintenance_loop() {
    sleep 300
    while :; do
        ced maintain || log "maintain failed (exit $?)"
        sleep "$MAINT_INTERVAL"
    done
}

main() {
    fix_perms
    write_config
    init_ca
    maintenance_loop &
    log "starting ctrl-exec-api as ctrl-exec"
    exec setpriv --reuid=ctrl-exec --regid=ctrl-exec --init-groups \
                 /usr/bin/ctrl-exec-api
}

main "$@"
