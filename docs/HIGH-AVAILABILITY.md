---
title: ctrl-exec - High Availability
subtitle: Running redundant dispatcher instances with shared state
brand: odcc
---

# ctrl-exec - High Availability

ctrl-exec is designed so that all persistent state lives on disk in known
paths, and the dispatcher process itself holds no runtime state that cannot
be reconstructed from those files. This property makes horizontal redundancy
straightforward: any number of dispatcher instances sharing the same state
files can serve requests interchangeably.

This document covers what state exists and where, approaches to replicating
or sharing it, load balancing and failover patterns, and what HA does not
protect against.

For installation and configuration reference, see REFERENCE.md. For CA
and cert security guidance, see SECURITY.md and SECURITY-OPERATIONS.md.


## What State Exists and Where

All ctrl-exec state is on the filesystem of the dispatcher host. There is
no embedded database, no in-memory cluster state, and no daemon with
persistent connections that must be preserved across restarts.

`/etc/ctrl-exec/ca.key`
: The CA private key. Root of trust for the entire deployment. This is the
  most sensitive file in the system — access to it allows issuing arbitrary
  agent certificates. Mode 0600, owned by root.

`/etc/ctrl-exec/ca.crt`
: The CA certificate. Distributed to agents at pairing time and used by
  both the dispatcher and all agents to verify peer certificates.

`/etc/ctrl-exec/ca.serial`
: The serial counter for cert issuance. Incremented on every signing
  operation (`sign_csr` in `CA.pm`). Must be consistent across all
  dispatcher instances — concurrent signing operations against different
  copies would produce duplicate serials.

`/etc/ctrl-exec/dispatcher.key`
: The dispatcher's own private key.

`/etc/ctrl-exec/dispatcher.crt`
: The dispatcher's TLS certificate, signed by the CA. Its serial number is
  the value agents store as a key in their trusted-dispatcher map and check
  on every `/run`, `/ping`, `/result`, and `/capabilities` request. All
  instances of the same dispatcher must present the same cert. (As of 0.9.0
  an agent's map may hold the serials of several distinct dispatchers — see
  Native Multi-Dispatcher below. Within one dispatcher's HA set, every
  instance still presents that dispatcher's single shared cert.)

`/var/lib/ctrl-exec/agents/`
: The agent registry. One JSON file per paired agent (e.g.
  `web-01.json`). Contains hostname, IP, pairing timestamp, cert expiry,
  and serial tracking state. Read and written by pairing, renewal, rotation,
  and registry commands. Written atomically via rename.

`/var/lib/ctrl-exec/locks/`
: Concurrency lock files. One file per `host--script` pair, held via
  `flock(2)` for the duration of a dispatch. These are process-local to the
  dispatcher instance running the dispatch. They do not need to be shared
  across instances and should not be — see Active/active below.

`/var/lib/ctrl-exec/runs/`
: Stored run results, written by `ctrl-exec-api`. Keyed by reqid, retained
  for 24 hours. Required only if `GET /status/{reqid}` is used. If result
  retrieval is not used, this directory does not affect correctness.

`/var/lib/ctrl-exec/pairing/`
: Pending pairing requests. Written when an agent submits a CSR and deleted
  on approval, denial, or stale expiry (10-minute timeout). Only required
  on whichever node is running pairing mode. Pairing mode should run on one
  node at a time.

`/var/lib/ctrl-exec/rotation.json`
: Cert rotation state: current serial, previous serial, rotation timestamp,
  overlap expiry, and per-agent serial tracking status. Written by
  `rotate-cert` and the internal check loop.

The paths that must be shared or replicated for active/passive or
active/active operation are:

- `/etc/ctrl-exec/` — all CA and cert material
- `/var/lib/ctrl-exec/agents/` — agent registry
- `/var/lib/ctrl-exec/rotation.json` — rotation state

Lock files and run results are instance-local concerns.


## Replication Approaches

### Shared filesystem

The simplest approach for bare-metal or VM deployments is a shared
filesystem mounted at `/etc/ctrl-exec` and `/var/lib/ctrl-exec` on all
dispatcher hosts. Both NFS and DRBD (in primary/secondary or dual-primary
mode) work. All instances read and write the same files.

Considerations:

- Serial counter consistency: `ca.serial` is read and written on every cert
  signing. Under NFS, open-file locking is advisory and may not be
  respected across clients. Use DRBD with OCFS2 or GFS2 for cluster-safe
  locking if pairing operations run concurrently across nodes.
- Registry writes are atomic (rename), which is safe over NFS on the same
  subnet but not guaranteed over high-latency links.
- Lock files in `/var/lib/ctrl-exec/locks/` should not be on the shared
  filesystem. Mount only the CA and registry paths; keep locks on local
  storage per instance.

### Active/passive with rsync

For a cold-standby arrangement, rsync the state directories from the primary
to the standby on a schedule or after each significant write:

```bash
# Run on primary after pairing or rotation events
rsync -az --delete /etc/ctrl-exec/ standby:/etc/ctrl-exec/
rsync -az --delete /var/lib/ctrl-exec/agents/ standby:/var/lib/ctrl-exec/agents/
rsync -az --delete /var/lib/ctrl-exec/rotation.json standby:/var/lib/ctrl-exec/rotation.json
```

RPO is the rsync interval. For low-frequency pairing environments (agents
paired once and seldom changed), a 5-minute cron is sufficient. For fleets
where pairing and rotation happen regularly, trigger rsync post-operation
rather than on a schedule.

Transfer the CA key over an encrypted, host-authenticated channel only:
`scp` with `known_hosts` verification, not `StrictHostKeyChecking=no`.

### Object storage for the registry

The agent registry (`/var/lib/ctrl-exec/agents/`) is a directory of small
JSON files. In cloud environments, it can be stored in object storage (S3,
GCS, Azure Blob) and synced to local disk on each instance at startup and
after write operations. This is suitable when the fleet is managed from
ephemeral dispatcher instances (e.g. autoscaling groups) and a shared NFS
mount is inconvenient.

The CA material (`/etc/ctrl-exec/`) should not be in object storage — the
CA key must remain in a secrets manager or encrypted block volume with
audited access controls, not in a general-purpose object bucket.


## Load Balancing

Port 7443 carries mTLS connections for `/run`, `/ping`, `/result`, and
`/capabilities`. Each connection is self-contained: the agent authenticates
the connecting cert against the CA, checks the connecting serial is a key in
its trusted-dispatcher map, processes the request, and closes the connection.
There is no session state that must be pinned to a specific dispatcher
instance.

Any TCP/L4 load balancer works for port 7443:

HAProxy
: L4 or L7 TCP proxy. Configure a backend pool of dispatcher hosts with
  health checks on port 7443. mTLS passthrough (L4 mode) requires no cert
  configuration on the load balancer.

keepalived
: Virtual IP failover using VRRP. The active dispatcher holds the VIP;
  on failure the VIP moves to the standby. Agents connect to the VIP address
  and are unaware of the failover. Suitable for two-node active/passive.

DNS round-robin
: Multiple A records for the dispatcher hostname. Agents resolve the name
  on each request. No dedicated load balancer required. Failover depends
  on DNS TTL and client retry behaviour; not suitable where sub-minute
  failover is required.

Port 7444 (pairing) and port 7445 (API) do not need to be load-balanced
in normal operation. Pairing mode runs on one node at a time. The API can
be load-balanced but result storage in `/var/lib/ctrl-exec/runs/` must
be on a shared path if `GET /status/{reqid}` is expected to work regardless
of which node handled the original request. (On the agent side, async results
are partitioned by owning dispatcher under
`/var/lib/ctrl-exec-agent/runs/<dispatcher-id>/<reqid>.json`, and
`GET /result/<reqid>` is owner-gated — see DEVELOPER.md. That is a per-agent
concern and is unaffected by dispatcher-side load balancing.)


## Active/Passive Failover

In an active/passive setup, one dispatcher instance handles all traffic;
the standby holds a replicated copy of all state and takes over when the
primary fails.

Promotion procedure:

1. Confirm the primary is unreachable (avoid split-brain — do not promote
   the standby while the primary may still be serving).
2. Ensure the standby has a current copy of the state directories. If using
   rsync replication, trigger a final sync if the primary is still
   accessible, or accept the lag from the last scheduled sync.
3. On the standby, start the dispatcher services:

   ```bash
   systemctl start ctrl-exec-api
   ```

4. Move the virtual IP or update DNS to point at the standby.

Agents reconnect transparently on their next request. There is no
re-pairing required. The standby presents the same dispatcher cert (same
serial, same `dispatcher_id`) as the primary — agents see no difference, and
the serial already in their trusted-dispatcher map continues to match.

If the standby was behind in registry state (new agents paired on the
primary after the last sync), those agents will be unknown to the newly
promoted node. They will still connect successfully on port 7443 (mTLS
trust is CA-based, not registry-based) but will not appear in
`list-agents` until the registry entry is recovered or the agent is
re-paired.


## Active/Active

Multiple dispatcher instances serving port 7443 simultaneously is
supported for `run` and `ping` operations. All instances present the same
cert (same serial), share the same registry, and agents accept connections
from any of them.

This active/active model is several instances of **one** dispatcher sharing a
single identity (one cert, one serial, one `dispatcher_id`) for redundancy.
It is distinct from native multi-dispatcher (0.9.0), where **several distinct**
dispatchers — each with its own identity, cert, and `dispatcher_id` — appear
as separate keys in an agent's trusted-dispatcher map. The two compose: a
single dispatcher in such a map may itself be run active/active. See Native
Multi-Dispatcher below.

Concurrency locking
: Lock files in `/var/lib/ctrl-exec/locks/` are per-instance. An
  active/active setup does not provide cross-instance concurrency locks —
  two instances can dispatch the same script to the same agent at the same
  time. If concurrency control matters, either keep lock files on a shared
  filesystem with cluster-safe locking, or route all requests for a given
  agent through the same instance (consistent hashing at the load balancer).

Pairing mode
: Pairing mode should only run on one node at a time. The pairing queue
  in `/var/lib/ctrl-exec/pairing/` is not designed for concurrent write
  access from multiple instances. Run pairing interactively on a designated
  node, or use `approve` and `deny` commands on the same node that accepted
  the request.

Cert rotation
: `rotate-cert` should be run on one node. It writes `rotation.json`,
  broadcasts the new serial to all agents, and updates per-agent status in
  the registry. Running it simultaneously from two nodes would produce a
  race on `rotation.json` and `ca.serial`. Schedule rotation as a
  maintenance operation on a designated node.

Registry writes
: Agent registry files are written atomically via rename. Concurrent writes
  from multiple instances to different agent files are safe. Concurrent
  writes to the same agent file (e.g. two renewals for the same agent)
  are last-write-wins — operationally harmless since the content converges.


## Native Multi-Dispatcher

Native multi-dispatcher (0.9.0) lets a single agent serve more than one
distinct dispatcher. Each dispatcher presents its own cert, chaining to a
shared CA root, and each appears as its own line in the agent's
trusted-dispatcher map at `/var/lib/ctrl-exec-agent/ctrl-exec-dispatchers` — one
line per dispatcher, `<hex-serial> <dispatcher-id>`. The map lives in the
agent-writable state directory (not under `/etc/ctrl-exec-agent`, which holds
only secrets), so the agent can rewrite it in place during rotation. It
replaces the old single `ctrl-exec-serial` file and is reloaded on SIGHUP.

`/run`, `/ping`, `/result`, and `/capabilities` are accepted only if the
connecting cert's serial is a key in the map. The matched dispatcher's
identity (its `dispatcher_id`) then drives permission and attribution: agent
logs carry `DISPATCHER=<id>`, auth hooks receive `ENVEXEC_DISPATCHER` and
`ENVEXEC_DISPATCHER_SERIAL`, and the async result store is partitioned by
owner under `/var/lib/ctrl-exec-agent/runs/<dispatcher-id>/<reqid>.json` so a
run is returned only to the dispatcher that submitted it (others get 404).

Each dispatcher has a stable `dispatcher_id`, set via `dispatcher_id` in
`ctrl-exec.conf` and defaulting to the dispatcher's hostname. It is delivered
to the agent at pairing time. Pairing **appends** to the map rather than
replacing it, so pairing a second dispatcher to an agent leaves the first in
place.

This is the supported mechanism for running multiple operators of differing
trust classes against one host. Running separate agent instances per operator
remains possible as optional defence-in-depth, but is no longer the way to
achieve multi-operator separation. Independent per-dispatcher CAs with SNI
are out of scope; all dispatchers in an agent's map chain to one shared CA
root.

Relation to the HA models above
: Active/passive and active/active concern redundant instances of **one**
  dispatcher sharing a single identity. Native multi-dispatcher concerns
  **several distinct** dispatcher identities trusted by one agent. They are
  orthogonal and may be combined: any dispatcher listed in an agent's map can
  itself be deployed active/active behind a load balancer or VIP.


## Cert Rotation in an HA Setup

dispatcher cert rotation changes the serial agents must trust. In an HA setup
all instances present the same cert, so they rotate together — they share one
cert, one serial, and one `dispatcher_id`. As of 0.9.0 rotation propagates to
each reachable agent automatically over the run channel, with no re-pairing,
via add-then-remove against the trusted-dispatcher map (see below).

Seamless rotation (0.9.0)
: Rotation updates each agent's trusted-dispatcher map at
  `/var/lib/ctrl-exec-agent/ctrl-exec-dispatchers` automatically. The serial
  broadcast (`broadcast_serial` → built-in `/rotate-serial`) **adds** the new
  serial to the map against the dispatcher's stable `dispatcher_id`, while the
  **old** serial stays trusted through the overlap window — so the live cert
  (the old one before the instances restart, the new one after) is accepted
  throughout. After the overlap window the dispatcher broadcasts removal of the
  old serial (`retire_previous_serial`, logged as `serial-retire`), so the
  retired cert stops being trusted. Because `dispatcher_id` is stable across
  rotation, trust and attribution carry over, and the agent can rewrite its own
  map because it lives in the agent-writable state directory. Only an agent that
  was **offline** during the broadcast misses the new serial and, once the
  overlap window expires, is marked `serial-stale` and needs re-pairing.

Rotation procedure for HA:

1. Run `ced rotate-cert` on one designated node. This generates the
   new cert, writes it to `/etc/ctrl-exec/dispatcher.crt` and
   `/etc/ctrl-exec/dispatcher.key`, and broadcasts the new serial to all
   agents via their built-in `/rotate-serial` operation.
2. Sync the updated `/etc/ctrl-exec/` to all other dispatcher instances. The
   old serial stays trusted through the overlap window, so an instance still
   presenting the old cert continues to be accepted while the sync and restarts
   roll through — there is no narrow window in which an unsynced instance is
   rejected. Complete the sync well before the overlap window expires.
3. Reload or restart all dispatcher instances:

   ```bash
   systemctl restart ctrl-exec-api
   ```

   `ctrl-exec-api` reads its cert at startup. There is no live cert
   reload — a restart is required.

Each agent's built-in `/rotate-serial` handler adds the new serial to the
trusted-dispatcher map and sends SIGHUP to the agent process; the agent reloads
its map on SIGHUP and immediately trusts the rotated cert, with no re-pairing.
The overlap window (`cert_overlap_days`, default 30 days) is the time the old
serial remains trusted: it lets the dispatcher instances roll from the old cert
to the new at their own pace, and it is also the window in which agents that
were unreachable during the broadcast can reconnect and receive the update. An
agent still offline when the window expires is marked `serial-stale` and needs
re-pairing.


## What HA Does Not Solve

CA key compromise
: An attacker with the CA key can issue valid agent certificates regardless
  of how many dispatcher instances exist. The CA is the single root of trust
  for the deployment. HA increases availability; it does not limit the blast
  radius of a CA key compromise. All instances share the same CA, so a
  compromise affects all of them equally. See SECURITY-OPERATIONS.md for
  the CA compromise recovery procedure.

Cert serial consistency
: All instances must converge on the new dispatcher cert during a rotation.
  The overlap window keeps the old serial trusted while instances roll over, so
  an instance briefly presenting the old cert is still accepted — divergence is
  not immediately fatal. But an instance left on the old cert past the overlap
  window, after the old serial has been retired, is rejected by every agent.
  The replication and reload procedure must complete well within the window.

Pairing queue coordination
: Pending pairing requests in `/var/lib/ctrl-exec/pairing/` are not
  replicated in a standard rsync setup. A request submitted to one node's
  pairing mode cannot be approved on another. Run pairing on a single
  designated node.

Agent cert revocation propagation
: The revocation list on each agent (`/etc/ctrl-exec-agent/revoked-serials`)
  must be updated via a `ced run` to each agent individually. HA on
  the dispatcher side does not change this — revocation state lives on the
  agents, not on the dispatcher. A dispatcher failover does not affect which
  certs agents will accept or reject.

Split-brain
: If two dispatcher instances both believe they are primary and both run
  `rotate-cert` simultaneously, the results are undefined. Use VRRP,
  distributed locking, or operational discipline to ensure rotation runs
  on exactly one node at a time.
