---
title: ctrl-exec - Script schema sidecar contract
subtitle: The self-describing-scripts seam between core and the MCP bridge
brand: odcc
---

# Script schema sidecar contract

This is the contract between **core** (`ctrl-exec-agent`, `ctrl-exec-api`) and any
**consumer** of script metadata - principally the MCP bridge plugin, but also
`/openapi-live.json` arg typing, a web-form UI, or an auth hook. It defines an
optional per-script *schema sidecar*, how the agent advertises it, and the exact
wire shape downstream tools can rely on.

Ratify this document before building either half: it is the single integration
surface, and once core ships it the bridge can be built against it independently.


## Layering: core transports, the consumer interprets

The governing invariant is that **core never interprets the schema body.** It
treats the sidecar as opaque JSON it carries from the agent to the consumer; it
derives one identity string from it; it never executes it and never uses it to
alter how a script runs.

| Concern | Owner |
| --- | --- |
| Read the sidecar, size/parse-check it, derive `schema_version` | **core (agent)** |
| Emit `schema` + `schema_version` on `/capabilities`; pass through `/discovery` | **core** |
| Interpret `arguments` (→ tool input schema), `argv` (→ `/run` args), metadata flags | **consumer** |
| Validate caller arguments against `arguments` | **consumer** |
| Detect cross-host version collisions | **consumer** |

So two layers are specified below: the **wire contract** (what core guarantees)
and the **sidecar body format** (the agreed structure of the opaque blob, which
script authors write and consumers read). Core enforces only the wire contract.


## The sidecar file

For an allowlist entry `name = /path/to/script`, the agent looks for a sidecar
at the script path with `.schema.json` appended:

```
/opt/ctrl-exec-scripts/check-disk.sh
/opt/ctrl-exec-scripts/check-disk.sh.schema.json    ← sidecar (optional)
```

Appending (rather than replacing the extension) is unambiguous for any script
name and matches the existing house convention (`*.tar.gz.sha256`).

Rules enforced by the agent:

- Read **only for allowlisted scripts**, and **only** at `<script-path>.schema.json`.
  The agent never scans directories and never reads a sidecar for a script that
  is not in the allowlist.
- Maximum size **64 KiB**. Larger → treated as absent (see *Fallbacks*).
- Must parse as a JSON **object**. Otherwise → treated as absent.
- Read as data only. The agent does **not** act on any field; it forwards the
  body and moves on.
- Re-read on `SIGHUP` alongside the allowlist.


## Sidecar body format

All fields are optional. A bare `{}` is valid (it just carries no information).
Fields are grouped by who interprets them.

### Metadata (consumer-interpreted)

```json
{
  "description": "Check disk usage against a threshold",
  "version": "2",
  "read_only": true,
  "destructive": false,
  "idempotent": true
}
```

- `description` *(string)* - human/LLM-facing summary of what the script does.
- `version` *(string)* - explicit schema version identity. See *Version identity*.
- `read_only` *(boolean, default `false`)* - the script makes no changes.
- `destructive` *(boolean, default `true`)* - the script may make destructive
  changes. **Defaults to `true`**: an undescribed script is assumed destructive,
  the safe posture for a remote-exec surface. `read_only: true` implies
  `destructive: false`.
- `idempotent` *(boolean, default `false`)* - repeating the call is safe.

The MCP bridge maps these to tool annotations: `read_only` → `readOnlyHint`,
`destructive` → `destructiveHint`, `idempotent` → `idempotentHint`.
`openWorldHint` is not author-controlled in v1 (defaults to `true`).

### `arguments` (consumer-interpreted)

A JSON Schema (draft 2020-12) describing the script's named inputs, as an object
schema. The MCP bridge exposes this near-verbatim as the tool `inputSchema`; a UI
renders a form from it; an auth hook can validate against it.

```json
"arguments": {
  "type": "object",
  "properties": {
    "threshold": { "type": "integer", "minimum": 1, "maximum": 100, "default": 90 }
  },
  "required": []
}
```

Core does **not** validate that this is a well-formed JSON Schema - it only
guarantees the bytes are valid JSON. Schema validity is the consumer's concern.

### `argv` (consumer-interpreted)

ctrl-exec scripts take **positional** arguments, but a good tool input is a
**named** object. `argv` defines how the named inputs render into the positional
`args` array sent to `POST /run`. Each element is one of:

- a **string literal** → emitted verbatim (e.g. a fixed subcommand).
- `{ "arg": "<name>" }` → the value of input `<name>` as a string token. If
  absent and the property declares a `default`, the default is used; if absent
  and not `required`, the token is omitted.
- `{ "arg": "<name>", "flag": "--foo" }` → for a boolean input, emit `--foo` when
  true and nothing when false; for a non-boolean, emit `--foo` then its value.
- `{ "arg": "<name>", "repeat": true }` → for an array input, emit one token per
  element.

If `argv` is omitted, the consumer falls back to emitting each
`arguments.properties` value in declaration order, and **should** warn that the
ordering is implicit. Authors are encouraged to always supply `argv` for
deterministic mapping. Core ignores `argv` entirely.


## Version identity (core-derived)

The agent computes one `schema_version` string per sidecar and hoists it to the
script entry so consumers can group without re-deriving:

1. If the body has a top-level string `version` matching `^[A-Za-z0-9._-]{1,64}$`
   and **not** beginning with `sha256:`, then `schema_version` = that string.
2. Otherwise `schema_version` = `"sha256:"` + the first 12 hex chars of the
   SHA-256 of the **canonical JSON** of the body (object keys sorted, insignificant
   whitespace removed). Computed with the same `openssl dgst -sha256` method the
   agent already uses for pairing codes, to avoid a new module dependency.

Consequences, by design:

- **Derived (`sha256:`) versions are collision-free**: identical bodies share a
  version; different bodies never do. Cosmetic reformatting does not churn the
  version (canonical form is hashed).
- The `sha256:` prefix is reserved; an explicit `version` may not use it (such a
  value is ignored and the version is derived instead, with a warning).
- A malformed `version` field does **not** invalidate the sidecar - the agent
  derives a hash version and carries the rest.


## `/capabilities` wire shape (core guarantee)

Each script entry gains two **optional** fields. Scripts with no usable sidecar
carry neither (exactly today's shape), so the change is backward-compatible.

```json
{
  "status": "ok",
  "host": "web-01",
  "version": "0.9.0",
  "scripts": [
    {
      "name": "check-disk",
      "path": "/opt/ctrl-exec-scripts/check-disk.sh",
      "executable": true,
      "schema_version": "2",
      "schema": {
        "description": "Check disk usage against a threshold",
        "version": "2",
        "read_only": true,
        "destructive": false,
        "idempotent": true,
        "arguments": {
          "type": "object",
          "properties": { "threshold": { "type": "integer", "minimum": 1, "maximum": 100, "default": 90 } },
          "required": []
        },
        "argv": [ { "arg": "threshold" } ]
      }
    },
    { "name": "legacy-tool", "path": "/opt/ctrl-exec-scripts/legacy", "executable": true }
  ],
  "tags": { "role": "web" }
}
```

- `schema` is the sidecar body **verbatim** (core does not rewrite it).
- `schema_version` is the core-derived identity (mirrors an explicit `version`,
  or `sha256:...`).
- A script with no/invalid sidecar omits both fields.

`/discovery` aggregates `/capabilities` across hosts and passes both fields
through **unchanged** inside each host's script entries; it performs no merging.


## Cross-host version collisions (consumer)

Because core sees one host at a time, collision detection belongs to the
consumer that aggregates across hosts (the bridge). When two hosts report the
same `name` and the same **explicit** `schema_version` but different `schema`
bodies, that is a declared-version collision - an operator error. The consumer
**must not** silently merge them; it surfaces both distinctly (e.g. a stable
body-hash disambiguator) and warns. Derived (`sha256:`) versions cannot collide
by construction, so collisions only arise from misused explicit versions.


## Fallbacks and error handling (core)

Core never fails a `/capabilities` response over a bad sidecar; it degrades:

| Situation | Agent behaviour | Consumer behaviour |
| --- | --- | --- |
| No sidecar | omit `schema`/`schema_version` | expose a generic tool (`hosts` + `args: string[]`) |
| Over 64 KiB, or not valid JSON object | omit both, log `schema-skip` + reason | generic tool |
| Valid JSON, no `arguments` | carry `schema` (metadata/flags) + version | description/flags usable; generic args |
| Bad `version` field | derive a `sha256:` version, carry the rest, warn | normal |

Every allowlisted script therefore remains callable; a missing or broken sidecar
only costs argument typing, never availability.


## Security properties

- The sidecar **cannot widen the callable surface.** It only describes scripts
  already in the allowlist; a sidecar beside a non-allowlisted script is never
  read. The allowlist remains the sole gate on *what* can run.
- The schema is **advertised data, never executed.** The agent does not interpret
  `argv`/`arguments`; only downstream consumers do, and only to shape inputs.
- Reads are bounded (allowlisted path only, size-capped, parse-failure-safe), so
  a hostile or corrupt sidecar cannot stall or crash capability discovery.
- The end-to-end property the bridge relies on: an LLM can only select an
  operator-approved script and fill operator-defined argument fields - it cannot
  invent operations or arguments outside the schema.


## Worked example

Sidecar `check-disk.sh.schema.json` (above) flows through unchanged:

```
agent /capabilities → schema_version "2" + schema body
        │
ctrl-exec-api /discovery → same fields, aggregated per host
        │
MCP bridge → tool "check-disk" (or "check-disk@2" if the fleet is split),
             inputSchema = arguments, annotations from the flags,
             hosts enum = hosts reporting version "2"
        │
tools/call check-disk { hosts:["web-01"], threshold: 85 }
        │  validate against arguments; render argv → ["85"]
        ▼
POST /run { hosts:["web-01"], script:"check-disk", args:["85"], async:true }
```
