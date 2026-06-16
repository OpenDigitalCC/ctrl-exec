---
title: cea — CLI Reference
subtitle: Complete command reference for ctrl-exec-agent.
updated: 2026-06-10
github_url: https://github.com/OpenDigitalCC/ctrl-exec/blob/main/docs/CLI-AGENT.md
current_page: /cli-agent
---

`cea` is the shortcut for `ctrl-exec-agent`. All commands below work with either name.

# serve

```
ctrl-exec-agent serve [--config <path>]
```

Starts the agent daemon. Listens on the configured port (default: 7443) for incoming mTLS connections from the dispatcher. Runs in the foreground — use systemd or procd for service management in production.

```bash
ctrl-exec-agent serve
ctrl-exec-agent serve --config /etc/ctrl-exec-agent/agent.conf
```

The agent reloads its configuration and allowlist on SIGHUP without restarting:

```bash
sudo systemctl kill --signal=HUP ctrl-exec-agent
```

# request-pairing

```
ctrl-exec-agent request-pairing --dispatcher <hostname> [--port <n>] [--lookup-by ip|hostname] [--background] [--timeout <s>]
```

Generates a key pair and CSR, connects to the dispatcher pairing port, and waits for approval. On approval, stores the signed certificate and CA certificate, and records the approving dispatcher — its serial and stable id — in the agent's trusted-dispatcher map. The entry is appended: re-pairing against a further dispatcher leaves existing dispatchers trusted. The agent's configured operational port is reported in the request so dispatch can reach it without a per-command port.

`--dispatcher <hostname>`
: Hostname or IP of the dispatcher instance. Required.

`--port <n>`
: Pairing port on the dispatcher host. Default: 7444.

`--lookup-by ip|hostname`
: Suggests how the dispatcher host should resolve this agent for dispatch (default: hostname). The operator's `ced approve --lookup-by` overrides it.

`--background`
: Prints the request ID and pairing code to stdout, then waits without requiring an interactive terminal. Suitable for automated or orchestrated pairing.

`--timeout <s>`
: Seconds to wait for approval before timing out. Default: 600 (10 minutes).

```bash
sudo ctrl-exec-agent request-pairing --dispatcher ctrl-exec.example.com
sudo ctrl-exec-agent request-pairing --dispatcher ctrl-exec.example.com --background
sudo ctrl-exec-agent request-pairing --dispatcher ctrl-exec.example.com --background --timeout 300
```

Both terminals display a 6-digit verification code derived from the CSR content. Verify the codes match before approving on the dispatcher side. A mismatch indicates the CSR was substituted or the request was misrouted.

# self-ping

```
ctrl-exec-agent self-ping
```

Connects to `127.0.0.1:7443` using the agent's own certificate. Confirms the port is listening and mTLS is functional.

The expected response is `403 serial mismatch`. The agent's own certificate is not a dispatcher certificate, and the agent correctly rejects it. This is the success case — it confirms the serial check is active. Any other result indicates a configuration problem.

# self-check

```
ctrl-exec-agent self-check
```

Validates the agent configuration without making any network connections. Checks certificate files exist and are readable, configuration keys are valid, and allowlist entries point to existing paths.

Run before reloading to verify a configuration change will not break the running agent:

```bash
ctrl-exec-agent self-check && \
    sudo systemctl kill --signal=HUP ctrl-exec-agent
```

# pairing-status

```
ctrl-exec-agent pairing-status
```

Shows the agent's current certificate, expiry date, and its trusted-dispatcher map — the serial and stable id of each dispatcher the agent trusts.

```
Certificate:  /etc/ctrl-exec-agent/agent.crt
Serial:       0A:1B:2C:3D
Expiry:       Mar 16 12:00:00 2027 GMT
Trusted dispatchers:
  4E:5F:6A:7B  ced-prod
  8C:9D:0E:1F  ced-ops
```

Use after re-pairing to confirm the approving dispatcher was recorded in the map.

# Exit Codes

| Code | Meaning |
| --- | --- |
| `0` | Success |
| `1` | Configuration or runtime error |
| `2` | Pairing failed or timed out |
