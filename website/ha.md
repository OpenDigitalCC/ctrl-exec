---
title: High Availability
subtitle: Running multiple dispatcher instances sharing state for redundancy.
updated: 2026-03-16
github_url: https://github.com/OpenDigitalCC/ctrl-exec/blob/main/docs/HA.md
current_page: /ha
---

ctrl-exec is designed so that all persistent state lives on disk in known paths and the dispatcher process holds no runtime state. Any number of dispatcher instances sharing the same state files can serve requests interchangeably.

::: widebox
All persistent state is files on disk. The dispatcher holds no runtime state. Multiple instances sharing the same state files serve requests interchangeably.
:::

# What State Exists and Where

## Must be shared or replicated

`/etc/ctrl-exec/`
: CA key and certificate, dispatcher TLS key and certificate. The CA key is the root of trust — access to it allows issuing arbitrary agent certificates. Transfer only over encrypted, host-authenticated channels.

`/etc/ctrl-exec/ca.serial`
: Serial counter for certificate issuance. Must be consistent across all instances — concurrent signing against different copies produces duplicate serials.

`/var/lib/ctrl-exec/agents/`
: Agent registry. One JSON file per paired agent.

`/var/lib/ctrl-exec/rotation.json`
: Cert rotation state.

## Instance-local — do not share

`/var/lib/ctrl-exec/locks/`
: Concurrency lock files. Per-instance. Must not be on a shared filesystem.

`/var/lib/ctrl-exec/runs/`
: Run results. Required on a shared path only if `GET /status/{reqid}` must work regardless of which instance handled the original request.

# Replication Approaches

## Shared filesystem

Mount `/etc/ctrl-exec` and `/var/lib/ctrl-exec` on all dispatcher hosts via NFS or DRBD. All instances read and write the same files. For concurrent pairing operations, use DRBD with OCFS2 or GFS2 for cluster-safe locking on `ca.serial`.

## Active/passive with rsync

Rsync state from primary to standby after pairing or rotation events:

```bash
rsync -az --delete /etc/ctrl-exec/ standby:/etc/ctrl-exec/
rsync -az --delete /var/lib/ctrl-exec/agents/ standby:/var/lib/ctrl-exec/agents/
rsync -az --delete /var/lib/ctrl-exec/rotation.json standby:/var/lib/ctrl-exec/rotation.json
```

Transfer the CA key only over an encrypted, host-authenticated channel (`scp` with `known_hosts` verification, or equivalent).

## Object storage for the registry

The agent registry is a directory of small JSON files suitable for S3, GCS, or Azure Blob storage in cloud environments. The CA material must not go in object storage — it belongs in a secrets manager or encrypted block volume.

# Load Balancing

Each connection to port 7443 is self-contained — no session state must be pinned to a specific instance. Any TCP/L4 load balancer works.

HAProxy
: L4 TCP proxy with a backend pool of dispatcher hosts and health checks on port 7443. mTLS passthrough requires no certificate configuration on the load balancer.

keepalived
: Virtual IP failover via VRRP. Agents connect to the VIP and are unaware of failover. Suitable for two-node active/passive.

DNS round-robin
: Multiple A records for the dispatcher hostname. No dedicated load balancer. Not suitable where sub-minute failover is required.

# Active/Passive Failover

Promotion procedure:

1. Confirm the primary is unreachable before promoting. Do not promote while the primary may still be serving.
2. Ensure the standby has a current copy of state directories.
3. Start dispatcher services on the standby:
   ```bash
   sudo systemctl start ctrl-exec-api
   ```
4. Move the virtual IP or update DNS to point at the standby.

Agents reconnect transparently on their next request. No re-pairing is required. The standby presents the same dispatcher certificate (same serial) as the primary.

# Active/Active Considerations

Multiple instances serving port 7443 simultaneously is supported for `run` and `ping`. Key constraints:

Concurrency locking
: Lock files are per-instance. Two instances can dispatch the same script to the same agent simultaneously. If cross-instance concurrency control matters, use a shared filesystem with cluster-safe locking, or route requests for a given agent through the same instance.

Pairing mode
: Run on one node at a time. The pairing queue is not designed for concurrent write access from multiple instances.

Cert rotation
: Run on one designated node. Running `ced rotate-cert` simultaneously from two nodes produces a race on `rotation.json` and `ca.serial`.

# Cert Rotation in an HA Setup

All instances must present the new certificate before any agent processes its serial update. Procedure:

1. Run `ced rotate-cert` on one designated node.
2. Sync updated `/etc/ctrl-exec/` to all other instances immediately.
3. Restart all instances:
   ```bash
   sudo systemctl restart ctrl-exec-api
   ```

The overlap window (`cert_overlap_days`) applies to agents that were offline during the broadcast — it is not a grace period for dispatcher instances themselves.

# What HA Does Not Solve

CA key compromise
: An attacker with the CA key can issue valid agent certificates regardless of how many dispatcher instances exist. HA increases availability; it does not limit blast radius.

Pairing queue coordination
: Pending requests in `/var/lib/ctrl-exec/pairing/` are not replicated in a standard rsync setup. A request submitted to one node's pairing mode cannot be approved on another.

Agent cert revocation propagation
: The revocation list lives on each agent individually. A dispatcher failover does not affect which certificates agents will accept or reject.

Split-brain
: Two instances both running `ced rotate-cert` simultaneously produces undefined results. Use VRRP, distributed locking, or operational discipline to prevent this.
