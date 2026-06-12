---
title: Pairing
subtitle: How a new agent is introduced to the fleet and what the protocol guarantees.
updated: 2026-06-10
github_url: https://github.com/OpenDigitalCC/ctrl-exec/blob/main/docs/PAIRING.md
current_page: /pairing
---

# Overview

Pairing is the ceremony by which a new agent joins the fleet. It establishes mutual trust between an agent and a dispatcher instance: the agent receives a CA-signed certificate, and the dispatcher records the agent in the registry.

Pairing runs on a separate port (7444 by default) using server-TLS only. The agent does not yet have a certificate to present, so only the dispatcher's identity is verified during the pairing exchange itself.

# The Protocol

1. The operator starts `ced pairing-mode` on the dispatcher host. This opens a listener on the pairing port and waits for incoming CSR submissions.

2. On the agent host, the operator runs `ctrl-exec-agent request-pairing --dispatcher <hostname>`. The agent generates a new RSA key pair, constructs a CSR, and connects to the pairing port.

3. Both sides independently compute a 6-digit verification code derived from the CSR content. The code is displayed on both terminals.

4. The operator compares the codes. If they match, the operator approves the request. If they do not match, the request should be denied — a mismatch indicates the CSR was substituted or the request was routed to a different agent.

5. On approval, the dispatcher signs the CSR with the CA and returns to the agent:
   - The signed agent certificate
   - The CA certificate
   - The current dispatcher certificate serial number

6. The agent stores all three files. It is now ready to serve requests.

7. The dispatcher writes a registry entry for the agent: hostname, IP, pairing timestamp, certificate expiry, and serial tracking state.

# Security Properties

Verification code
: The 6-digit code is derived from the CSR content on both sides independently. An attacker who intercepts the connection and substitutes a different CSR would produce a different code. The operator's comparison step catches this. The code is not transmitted over the network — it is computed locally from what each side received or generated.

Serial pinning
: After pairing, the agent stores the dispatcher's certificate serial number. Every subsequent connection from the dispatcher is checked against this value. A valid CA-signed certificate with a different serial is rejected. This means that cert rotation is a first-class operation — a new dispatcher cert requires all agents to receive the updated serial.

One-time ceremony
: Pairing mode must be explicitly started and runs until stopped. It does not run continuously. The pairing queue has a maximum size (`pairing_max_queue`, default 10) — requests beyond this are refused until the queue drains.

# Running Pairing Mode

```bash
sudo ced pairing-mode
```

Pairing mode is interactive when run in a terminal. As requests arrive they are displayed with a prompt:

```
New request from agent-host.example.com (192.168.1.42)
Pairing code: 482 917
Approve? [a/d]:
```

Commands:

`a`
: Approve the current request.

`d`
: Deny the current request.

`a1` / `d2`
: Approve or deny by queue position when multiple requests are pending.

`list`
: Redisplay all pending requests with their codes and source IPs.

`quit`
: Exit pairing mode. Any pending requests are left in the queue and expire after 10 minutes.

To run on a non-default port:

```bash
sudo ced pairing-mode --port 7444
```

# Approving from a Separate Terminal

Pending requests can be approved or denied non-interactively while `pairing-mode` is running in another terminal:

```bash
ced list-requests
ced approve <reqid>
ced deny <reqid>
```

This is the workflow for scripted or orchestrated pairing approval.

At approval the operator can set how dispatch reaches the agent:

```bash
ced approve <reqid> --lookup-by ip        # dispatch by IP, not hostname
ced approve <reqid> --ip 192.168.1.10     # set the agent's address explicitly
ced approve <reqid> --agent-port 7450     # agent serves on a non-default port
```

The agent self-reports its source address at pairing, and that is the IP recorded by default. `--ip` overrides it — needed when a NAT in front of the dispatcher or the agent hides the real address (see [Networking and NAT](#networking-and-nat)). `--lookup-by ip` dispatches by the stored IP rather than the hostname; `--agent-port` records a non-default operational port. All three can also be changed later without re-pairing via `ced edit-agent`.

# Networking and NAT

ctrl-exec connects in two directions: the **agent** dials the dispatcher's pairing port (7444) once, at pairing; the **dispatcher** dials each **agent's** operational port (7443) for every run, ping, and renewal. Every agent must therefore be inbound-reachable on its operational port from the dispatcher.

The address recorded for an agent is, in priority order: an explicit `approve --ip`, then the agent's self-reported source address, then the pairing connection's source IP — the last of which is unreliable behind a NAT, which rewrites it to the gateway address.

**Dispatcher behind NAT** (for example in Docker), agents directly reachable: publish the dispatcher's pairing port (`-p 7444:7444`). The agent self-reports its real address, so it registers correctly, and dispatch works over the dispatcher's routed egress. No override is needed in the common case.

**Agent behind NAT**, dispatcher reachable: the agent self-reports a private address the dispatcher cannot reach. Forward the operational port on the agent's router and approve with the public address — `ced approve <reqid> --ip <public-ip>` (add `--agent-port` if the external port differs) — or point a public DNS name at the agent's NAT and use `--lookup-by hostname`.

**Both behind NAT:** forward the dispatcher's pairing port and each agent's operational port, and register each agent's public address (`--ip`) or hostname. Where inbound forwarding to an agent is impossible (for example carrier-grade NAT), put the hosts on a routable overlay — a WireGuard or VPN mesh, or an SSH reverse tunnel — and pair and dispatch over the overlay addresses, where NAT no longer applies.

# Automated Pairing

For orchestrated environments where interactive approval is not practical, the agent supports a background mode:

```bash
sudo ctrl-exec-agent request-pairing --dispatcher ctrl-exec.example.com --background
```

The agent prints the request ID and pairing code to stdout, then waits without requiring a terminal. The approval step remains explicit — an operator or automation system must call `ced approve <reqid>`.

To set an approval timeout (default 600 seconds):

```bash
sudo ctrl-exec-agent request-pairing \
    --dispatcher ctrl-exec.example.com \
    --background \
    --timeout 300
```

# HA Considerations

In a high-availability deployment, run pairing mode on one node at a time. The pairing queue is not designed for concurrent write access from multiple dispatcher instances. See [High Availability](/ha) for deployment guidance.

# After Pairing

Start the agent service:

```bash
sudo systemctl enable ctrl-exec-agent
sudo systemctl start ctrl-exec-agent
```

Confirm the agent is reachable:

```bash
ced ping <hostname>
```

List all paired agents:

```bash
ced list-agents
```
