# NetScope Agent

Secure cross-platform network sensor and execution agent for NetScope, written in Go.

> Current status: **Experimental**. Agent version `0.2.0-experimental`; NetScope Agent Protocol `1.0`.

## Overview

NetScope Agent is the outbound-only sensor/worker for the NetScope Control Plane. It enrolls with a short-lived token, obtains an agent-specific mTLS certificate, reports a versioned capability manifest, polls for authorized jobs, executes only compiled adapters with validated parameters, and returns bounded technical results and evidence metadata.

The Control Plane remains responsible for Authorized Scope, ScanGuard, organization isolation, correlation, contextual risk, findings and incidents. The Agent does not infer business impact or compromise.

## Security boundary

**NetScope Agent is not a remote shell.** It provides no terminal, command endpoint, script upload, SSH proxy, PowerShell interface, runtime plugin loader, executable downloader or remote auto-update. External processes are selected from a compiled allowlist and started directly with `exec.CommandContext(binary, validatedArgs...)`; no shell interprets arguments.

Every Agent connection is outbound. The Agent opens no administrative listener.

## Protocol compatibility

The wire types in `internal/protocol` match the current Control Plane contracts under `netscope/contracts/agent/v1`:

- `POST /agent/v1/enroll`
- `POST /agent/v1/heartbeat`
- `POST /agent/v1/capabilities`
- `GET /agent/v1/jobs/next`
- `POST /agent/v1/jobs/:id/start`
- `POST /agent/v1/jobs/:id/result`
- `POST /agent/v1/jobs/:id/fail`
- `GET /agent/v1/jobs/:id/cancellation`
- `POST /agent/v1/evidence`

Different protocol major versions are rejected. Protocol `1.0` rejects unknown fields in security-sensitive responses and validates required identities, timestamps, target, nonce, risk class, timeout, module version and parameters before execution.

## Secure enrollment and cryptographic identity

On first start the Agent creates an ECDSA P-256 private key and PKCS#10 CSR locally. The private key never leaves the host. Enrollment sends the token inside the exact JSON request body, not as a permanent Authorization credential. The Control Plane consumes the token and returns its public CA material and a 90-day client certificate.

Identity files are staged and installed together under `data/identity` with restrictive permissions. Subsequent requests authenticate using that client certificate. HTTPS server certificate validation always remains enabled; a private server CA may be configured with `NETSCOPE_SERVER_CA_CERT`. `InsecureSkipVerify` is not exposed.

## Job signing status

The Control Plane currently reserves Ed25519 envelope fields but does not activate signing or publish a signing key. The Agent therefore accepts only unsigned v1 envelopes. A partially populated or unexpectedly signed envelope is rejected with `SIGNATURE_INVALID`; this avoids pretending that an undefined canonicalization is secure. Signed-job support remains planned until both repositories define and activate the same canonical representation.

## Capability reporting

Capability discovery reports the exact v1 manifest: platform, compiled module IDs, capability IDs, implementation type, module versions, risk classes and fixed external tools. Lists are sorted before JSON encoding, producing a deterministic SHA-256 `capabilitiesHash`. Missing tools remain unavailable and are never installed automatically.

The following protocol-aligned adapters are compiled:

| Module | Version | Risk | Execution |
|---|---:|---|---|
| `network.ping` | `0.1.0` | SAFE_ACTIVE | fixed OS adapter |
| `network.route` | `0.1.0` | SAFE_ACTIVE | fixed traceroute/tracert adapter |
| `network.dns` | `0.1.0` | SAFE_ACTIVE | Go resolver |
| `network.tcp` | `0.1.0` | SAFE_ACTIVE | `net.Dialer` |
| `network.http` | `0.1.0` | SAFE_ACTIVE | bounded `net/http` |
| `network.tls` | `0.1.0` | SAFE_ACTIVE | `crypto/tls` metadata |
| `nmap.discovery` | `0.1.0` | CONTROLLED_ACTIVE | fixed discovery profile |
| `nmap.services` | `0.1.0` | CONTROLLED_ACTIVE | fixed service profiles |
| `traffic.tshark` | `0.1.0` | PASSIVE | compiled, not advertised pending artifact delivery |
| `traffic.zeek` | `0.1.0` | PASSIVE | compiled, not advertised pending artifact delivery |
| `security.suricata` | `0.1.0` | PASSIVE | compiled, not advertised pending artifact delivery |
| `performance.iperf3` | `0.1.0` | CONTROLLED_ACTIVE | compiled, not advertised pending endpoint details |

Greenbone is not implemented in this Agent and its capability is not reported.

## Validated execution lifecycle

The central Executor performs recipient and organization binding, protocol and expiry checks, in-memory nonce replay protection, target validation, exact module-version/risk matching, capability checks, strict parameter decoding, global/per-module slot reservation, server `start` acknowledgement, bounded timeout, cancellation polling, execution, result normalization and delivery.

The target is used exactly as delivered in `JobEnvelope.target`. Modules cannot replace it from environment variables or output. HTTP follows only the configured redirect count and rejects cross-host redirects. The Agent never accepts arbitrary flags.

## Results and evidence

Successful execution is normalized into the exact `JobResult` contract with `status: "SUCCEEDED"`, stable `resultIdentity`, observations, allowed monitor metrics, warnings, evidence manifest and explicit truncation. The Control Plane determines findings, priority, contextual risk and incident association.

Each structured evidence item receives a UUID, SHA-256 checksum, byte size, `application/json` content type, source module and an allowed artifact kind. Evidence integrity metadata helps detect unintended changes; it is not a formal forensic chain of custody.

Protocol v1 provides evidence metadata registration but no authorized artifact-content upload or download endpoint. The Agent does not invent a parallel transport. PCAP adapters remain unavailable until that contract exists.

## Result spool and retries

An ambiguous result delivery stores the exact already-normalized payload. Retrying preserves `jobId`, `resultIdentity`, `resultVersion`, evidence IDs and JSON fields, matching Control Plane idempotency. Failure and evidence payloads have their own spool kinds. The spool is age-limited, size-limited, mode-restricted and never stores jobs or PCAP content.

Polling uses exponential backoff with jitter. Heartbeats use configurable 30-second intervals with jitter, compatible with the Control Plane degraded/offline grace policy. Revoked identities and protocol incompatibility stop job polling.

## Resource and privilege controls

- conservative default of two concurrent jobs;
- per-module concurrency limits;
- Control Plane timeout capped by `NETSCOPE_MAX_JOB_TIMEOUT`;
- bounded stdout, stderr, result, artifact metadata and spool;
- context cancellation terminates Go operations and known external processes;
- temporary/runtime state excluded from Git;
- structured `slog` output without tokens, keys, certificates, raw PCAP or full evidence.

Run as a dedicated unprivileged account. Do not use Docker `--privileged`. Grant a narrow OS capability only to a deployment that explicitly needs it.

## Configuration

Copy `.env.example` into an approved secret/configuration mechanism. Required first-start values are:

```text
NETSCOPE_CONTROL_PLANE_URL=https://netscope.example.invalid
NETSCOPE_AGENT_NAME=branch-office-01
NETSCOPE_ENROLLMENT_TOKEN=<short-lived single-use token>
NETSCOPE_SERVER_CA_CERT=/protected/path/server-ca.pem
```

Remove the enrollment token after a successful first start. The Agent also calls `os.Unsetenv` after saving its identity, but it cannot edit an external service manager's configuration.

## Platforms and deployment

- Linux amd64/arm64: supported foundation; systemd example included.
- Windows amd64: supported foundation; run under a dedicated non-administrator service identity.
- macOS amd64/arm64: experimental; Go-native modules are preferred.

See `docs/deployment-linux.md` and `docs/deployment-windows.md`.

## Documentation

- [Architecture](docs/architecture.md)
- [Enrollment](docs/enrollment.md)
- [Security](docs/security.md)
- [Protocol v1](docs/protocol-v1.md)
- [Modules](docs/modules.md)
- [Capabilities](docs/capabilities.md)
- [Job lifecycle](docs/job-lifecycle.md)
- [Evidence](docs/evidence.md)
- [Troubleshooting](docs/troubleshooting.md)

## Limitations

- Job signing is planned but not active in the Control Plane.
- Certificate rotation has no Control Plane Agent API endpoint yet; re-enrollment requires explicit administrative recovery.
- Protocol v1 has evidence metadata registration but no artifact-content transfer contract, so PCAP adapters are not advertised.
- The controlled iperf endpoint ID is not resolved into endpoint details by the current envelope, so iperf is not advertised.
- Nonce replay state is memory-bounded and resets on process restart; server job state remains authoritative.
- Runtime and interoperability validation remains pending in an authorized laboratory.

## License

MIT License. Copyright 2026 Thiago Montozo.
