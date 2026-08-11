# Security model

## Invariants

- NetScope Agent is not a remote shell and has no generic command primitive.
- Every network connection is Agent-initiated; no arbitrary inbound execution port exists.
- HTTPS server validation is required. mTLS may add client authentication.
- Every executable job is bound to an agent, organization, scope, target, parameters,
  risk class, issue/expiry time, nonce, protocol version, and Ed25519 signature.
- Active work requires an authorization reference. Controlled-active modules may
  additionally require a module-specific controlled-endpoint assertion.
- External processes receive only adapter-generated arguments and a minimal environment.
- Output, result, artifact, time, concurrency, spool size, and spool age are bounded.
- Runtime plugins, script upload, auto-escalation, and unsigned updates do not exist.

## Threat model

TLS protects transport confidentiality, peer authentication, and integrity. A signed
job envelope separately protects queued/stored job integrity and prevents a database,
broker, proxy, or application bug from changing target or arguments without detection.
Nonces support replay detection at the Control Plane; expiry sharply bounds replay
value at the Agent. Agent-ID binding prevents cross-agent delivery.

The Agent assumes the OS account and its private state remain protected. A fully
compromised host can observe work performed there. The Agent reduces blast radius by
running unprivileged, not exposing a listener, minimizing dependencies/environment,
and isolating temporary data. It does not claim to sandbox a malicious scanner binary.

## Security review checklist

- `os/exec`: restricted to capability/version discovery and compiled adapters.
- Shells: no `sh -c`, `cmd /c`, or `powershell -Command` execution path.
- Arguments: fixed flags plus schema-validated host, port, duration, and internal path.
- Path traversal: temporary artifact paths must remain beneath `data/temp`.
- Temp files: unpredictable names, restrictive permissions, scoped cleanup.
- Artifacts: HTTPS, expiry, declared size, maximum size, exact SHA-256 verification.
- TLS: system/custom CA validation, TLS 1.2 minimum, optional mTLS; insecure mode is
  explicit, development-only, and produces a critical log.
- Identity: atomic `0600` storage; private keys are neither logged nor transmitted.
- Enrollment: token is short-lived/single-use and is not persisted by the Agent.
- Jobs: signature, protocol, recipient, required fields, issue/expiry, scope, target,
  risk, capability, module schema, and authorization are checked.
- Processes: context deadline/cancellation, no stdin, minimal environment, bounded output.
- Spool: only result/event JSON, bounded bytes and age; never a local job queue.
- Logs: no tokens, keys, Authorization values, signed URLs, PCAPs, evidence, or bodies.

## Privilege guidance

Run the base Agent as a dedicated unprivileged identity. Do not run everything as
root because one module might need a network capability. On Linux, grant a narrow
capability such as `CAP_NET_RAW` only to the precise deployment that enables an ICMP
implementation requiring it. Containers should not use `--privileged` by default.
