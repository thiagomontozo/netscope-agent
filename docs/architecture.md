# Architecture

## System boundary

NetScope Agent is an outbound-only execution worker. The Control Plane owns policy,
scope creation, scheduling, and correlation. The Agent retains an independent local
trust boundary: a job must pass transport, signature, expiry, identity, protocol,
risk, capability, module-schema, target, and authorization checks.

```text
Control Plane                         Monitored network
┌──────────────────┐       HTTPS      ┌─────────────────────────┐
│ enrollment       │ <─────────────── │ identity + enrollment   │
│ heartbeat/jobs   │ <─────────────── │ client + backoff        │
│ results/evidence │ <─────────────── │ verifier → executor     │
│ audit log        │ <─────────────── │ modules → bounded tools │
└──────────────────┘   Agent starts   └─────────────────────────┘
                      every connection
```

No component listens for arbitrary execution requests. The static registry maps a
signed `moduleId` to compiled code. Go-native modules use `net`, `net/http`, and
`crypto/tls`. External adapters invoke a located binary directly with
`exec.CommandContext(binary, validatedArgs...)`; no shell parses those arguments.

## Runtime flow

Startup creates protected data directories, loads or enrolls identity, builds a
validated TLS client, pins the Control Plane Ed25519 job key, discovers capabilities,
and constructs the static registry. Polling stops on SIGINT/SIGTERM. Accepted work
gets a global slot, module slot, deadline, cancellation context, bounded buffers,
and optional verified temporary PCAP. Results are normalized and delivered or put
in the bounded spool. Shutdown stops polling, waits for running work under its
existing policy, attempts a final heartbeat/audit event, cleans per-job temporary
files, closes idle connections, and exits.

## Data directory

```text
data/
├── identity/  # Ed25519 identity, credential, pinned server key
├── spool/     # small pending result/event JSON documents
├── temp/      # verified short-lived artifacts and isolated tool output
└── state/     # reserved local state
```

These paths are runtime state and are excluded from version control.
