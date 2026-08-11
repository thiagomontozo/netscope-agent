# NetScope Agent

Secure cross-platform network sensor and execution agent for NetScope, written in Go.

**Current status: Experimental.** The v0.1 protocol and module schemas may change.

## Overview

NetScope Agent is a small sensor/worker installed in an authorized monitored
network. It enrolls with the NetScope Control Plane, reports narrowly scoped
capabilities, polls for signed jobs, runs compiled-in modules, and returns bounded
structured results and requested evidence.

## Role in NetScope

This repository is independent of the Control Plane. The Control Plane owns
organizations, authorized scopes, policies, scheduling, correlation, and global
risk context. The Agent enforces local validation and executes only supported jobs.
Labels such as `site=rio` and the administrator-configured zone (`INTERNAL`, `DMZ`,
`EXTERNAL_SENSOR`, or `LAB`) assist scheduling; labels alone never authorize work.

## Architecture

The process is composed of configuration, cryptographic identity, enrollment,
HTTPS client, capability discovery, signed-job validator, static module registry,
bounded executor, evidence manager, and small disk spool. See
[`docs/architecture.md`](docs/architecture.md).

## Security Principles

**NetScope Agent is not a remote shell.** The agent does not execute arbitrary
commands received from the server. Active assessments require authorization by
the NetScope Control Plane. External tools run through predefined adapters with
validated arguments. The agent should run with the minimum privileges required by
enabled modules.

There is no shell endpoint, terminal, SSH proxy, script upload, command-string
execution, runtime plugin loading, privilege escalation, or remote auto-update.

## Outbound-Only Communication

Every connection starts at the Agent: HTTPS enrollment, heartbeat, job polling,
cancellation checks, event/result reporting, and signed artifact download. The
Agent does not listen for arbitrary inbound execution traffic, which supports NAT,
firewalls, branch networks, and cloud deployments.

## Enrollment

An administrator creates a short-lived, single-use token. On first start the Agent
generates its Ed25519 identity and calls `POST /agent/v1/enroll`. The Control Plane
returns a permanent agent ID and credential; only public identity material leaves
the host. Remove `NETSCOPE_ENROLLMENT_TOKEN` from persistent configuration after
success. See [`docs/enrollment.md`](docs/enrollment.md).

## Agent Identity

The Ed25519 private key and permanent credential are stored in
`data/identity/identity.json` with restrictive permissions. Private key material is
never transmitted or passed to scanner processes. Production deployments should
add OS keystore protection where available.

## mTLS

HTTPS and normal server-certificate validation are mandatory. A custom CA and
client certificate/key can be configured for mTLS. The development-only insecure
TLS switch is explicit and emits a critical log; it must never be used in production.

## Signed Jobs

Job envelopes are verified with a pinned Control Plane Ed25519 public key after
transport validation. Signature coverage includes target, parameters, scope,
authorization reference, risk class, timestamps, nonce, and protocol version.
Expired, misaddressed, unsigned, incompatible, or unauthorized envelopes are
rejected. See [`docs/job-protocol.md`](docs/job-protocol.md).

## Job Lifecycle

The Agent polls `/agent/v1/jobs/next`, validates the envelope, checks module and
capability compatibility, reserves global and per-module slots, applies the shorter
of the configured timeout and job expiry, checks cancellation, executes, normalizes,
reports, and releases resources. Already authorized safe work may finish during a
temporary outage; no new local queued jobs are started.

## Capabilities

Startup discovery reports OS, architecture, Go-native networking capabilities and
availability/version summaries for fixed external tools. Tools are never installed
automatically. Missing tools make the capability unavailable. See
[`docs/capabilities.md`](docs/capabilities.md).

## Module Registry

The v0.1 registry is compiled into the binary. Each descriptor declares ID,
version, risk class, required tool/capability, platform support, and module-level
concurrency. Arbitrary `.so` files or server-supplied modules are not loaded.

## Built-in Modules

### Ping

`network.ping` runs the platform ping adapter with fixed count/timeout arguments.
Raw ICMP privilege is never elevated automatically.

### Traceroute

`network.route` selects `traceroute` or `tracert` and supplies only validated,
adapter-owned flags. Its bounded output is prepared for normalized hop processing.

### DNS

`network.dns` uses Go's resolver and an allowlist of A, AAAA, CNAME, MX, NS, and
TXT record types.

### TCP

`network.tcp` uses `net.Dialer` with a validated host, port, and bounded timeout.

### HTTP

`network.http` offers only HEAD and GET profiles, limits body reads and redirects,
rejects cross-host redirects, sends no user-controlled sensitive headers, and does
not execute JavaScript.

### TLS

`network.tls` uses `crypto/tls`, validates the hostname, and reports certificate,
issuer, validity, SAN, protocol, and cipher metadata—never private keys.

### Nmap Adapter

`nmap.discovery` and `nmap.services` use fixed profiles and XML output. There are no
free-form arguments, arbitrary NSE scripts, spoofing, evasion, or user-selected
stealth flags. Service discovery requires a controlled endpoint authorization.

### TShark Adapter

`traffic.tshark` processes only an authorized downloaded PCAP with one of three
compiled profiles: summary, protocol distribution, or selected fields. It does not
start live capture or accept arbitrary display filters.

### Zeek Adapter

`traffic.zeek` performs offline PCAP analysis in an isolated temporary directory,
enumerates expected logs, and removes temporary output after execution.

### Suricata Adapter

`security.suricata` performs offline PCAP analysis and counts normalized EVE alert
events. It does not enable IPS or alter traffic.

### iperf3 Adapter

`performance.iperf3` requires a signed controlled-endpoint target, explicit
authorization reference, fixed bandwidth profile, validated port, and duration of
at most 30 seconds.

## PCAP Processing

PCAP references must be HTTPS, unexpired, size-bounded, and accompanied by an exact
SHA-256 checksum and size. Files use unpredictable names under `data/temp`, mode
`0600`, and are deleted after the offline adapter finishes. Signed URL credentials
are not logged or retained.

## Evidence

Results distinguish structured observations, metrics, warnings, evidence metadata,
and artifacts. Checksums accompany artifacts where appropriate. The Agent uploads
only explicitly requested evidence and never silently expands collection scope.

## Resource Limits

Timeout, stdout, stderr, result, artifact, spool bytes, and spool age are bounded.
External output uses bounded writers, so a tool cannot grow an in-memory buffer
without limit. Truncation is explicit in `truncated` and warnings.

## Concurrency

`NETSCOPE_MAX_CONCURRENT_JOBS` defaults to two. The registry also applies per-module
limits: lightweight Go modules allow more parallelism, while PCAP and active tool
adapters default to one.

## Spooling

Small result and audit-event payloads may be queued locally when the Control Plane
is unavailable. The spool is size- and age-limited and does not retain large PCAPs.
It never acts as a local job queue.

## Logging

Structured JSON logging uses `slog` and correlates `agentId`, `jobId`, and
`moduleId` where applicable. Tokens, authorization headers, private keys, signed
artifact URLs, full PCAPs, full evidence, and sensitive HTTP bodies must not be logged.

## Linux Deployment

Run as the dedicated unprivileged `netscope` user with configuration under
`/etc/netscope-agent` and state under `/var/lib/netscope-agent`. The supplied systemd
unit starts with no ambient capabilities. Grant a narrowly scoped capability such
as `CAP_NET_RAW` only if an enabled adapter truly requires it. See
[`docs/deployment-linux.md`](docs/deployment-linux.md).

## Windows Deployment

Use a dedicated non-administrator service identity and `%ProgramData%\NetScope Agent`
for protected state. See [`docs/deployment-windows.md`](docs/deployment-windows.md).

## macOS Notes

macOS amd64 and arm64 support is experimental. Go-native DNS/TCP/HTTP/TLS modules
are preferred; external tools and their flags depend on local installation. No tool
is installed or privilege granted automatically.

## Configuration

| Variable | Default | Purpose |
|---|---:|---|
| `NETSCOPE_CONTROL_PLANE_URL` | required | HTTPS Control Plane base URL |
| `NETSCOPE_AGENT_NAME` | `netscope-agent` | Human-readable agent name |
| `NETSCOPE_ENROLLMENT_TOKEN` | first start only | Short-lived enrollment credential |
| `NETSCOPE_DATA_DIR` | `./data` | Identity, state, temp, and spool root |
| `NETSCOPE_LOG_LEVEL` | `info` | debug, info, warn, or error |
| `NETSCOPE_JOB_POLL_INTERVAL` | `5s` | Normal outbound polling interval |
| `NETSCOPE_MAX_CONCURRENT_JOBS` | `2` | Global execution slots |
| `NETSCOPE_DEFAULT_TIMEOUT` | `60s` | Default per-job deadline |

Additional hardening variables cover CA/mTLS files, pinned job-signing key, network
zone, request timeout, output/artifact/spool limits and age. See `.env.example` for
the minimal first-enrollment configuration. Never commit a real token.

## Security Hardening

Pin the Control Plane signing key, use mTLS where required, protect identity and CA
files with OS ACLs, remove the enrollment token, run unprivileged, enable only
needed tools, restrict egress to the Control Plane/artifact hosts, and monitor audit
events. Container deployments should add only module-specific capabilities; do not
use `--privileged` as the default.

## Limitations

v0.1 is experimental, has no automatic update, live packet capture, live Zeek or
Suricata mode, dynamic plugins, advanced process sandbox, or tests. External tool
normalization is intentionally conservative and availability varies by OS.

## Roadmap

v0.2: automated tests, CI, improved OS adapters, live Zeek sensor support,
Suricata live events, S3 artifact streaming, and stronger resource isolation.

v0.3: NATS JetStream transport, signed remote upgrades with checksum/rollback and
approval, agent groups, central policy distribution, and advanced sandboxing.

## Contributing

Keep the outbound-only trust boundary, add no general command execution, define
schemas and risk class before adapters, bound every resource, and document security
consequences in an ADR. Security reports should avoid public disclosure of secrets.

## License

MIT License. Copyright 2026 Thiago Montozo. See [`LICENSE`](LICENSE).
