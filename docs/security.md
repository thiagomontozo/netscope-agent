# Security

Trust is layered: HTTPS, mTLS identity, server-side revocation, Ed25519
named-key verification, expiry/nonce replay checks, compiled modules, validated
targets, bounded execution/output and scoped artifact integrity. Signed-job
policy has no insecure fallback; rotation uses private staged fsync and atomic
rename.

## Invariants

- No remote shell, administrative listener, arbitrary command, script upload, SSH proxy, dynamic plugin or remote updater exists.
- HTTPS verification is mandatory; `InsecureSkipVerify` is not configurable.
- Post-enrollment API calls require the locally stored client certificate and private key.
- The private key and enrollment token are never logged or sent to modules.
- Jobs are bound to protocol, agent, organization, scope, module, target, parameters, risk, timestamps, timeout and nonce.
- Module and global concurrency, time, output, response and spool are bounded.
- External processes use `exec.CommandContext` with a fixed executable allowlist and adapter-built arguments. No `sh -c`, `bash -c`, `cmd /c` or PowerShell command string is used.

## Signed jobs

The Control Plane has an interface and optional fields for Ed25519 signing, but its runtime does not sign envelopes or distribute a signing key. The Agent does not claim otherwise. Unsigned v1 jobs are accepted after mTLS and local validation; partially signed or unexpectedly signed jobs are rejected as `SIGNATURE_INVALID`. Canonicalization and activation must be implemented in both repositories before this changes.

## Target and parameter protection

The Agent uses `target.type` and `target.value` exactly as received. It validates hostname, IP, CIDR or absolute HTTP(S) URL syntax. Parameters are decoded into adapter-specific structs with unknown fields rejected. Target values never become executable names or flags.

The Agent cannot independently reconstruct the Authorized Scope value because the envelope carries only `scopeId`, environment, authorization reference and normalized target. ScanGuard and database ownership validation are therefore Control Plane responsibilities; the Agent enforces immutability and recipient binding.

## Static review focus

Review `internal/process`, `internal/security`, `internal/identity`, `internal/client`, `internal/executor`, `internal/spool` and every module whenever the contract changes. Secrets, certificates, artifact URLs, PCAP contents and full evidence must not enter logs.
