# Troubleshooting

## Enrollment rejected

Confirm the token is current, single-use and at least 32 characters; the URL is HTTPS; the platform is supported; the server certificate chains to the system or configured server CA; and no legacy/partial identity files are present. Never paste tokens into logs.

## mTLS identity rejected

Check certificate expiry and the local metadata fingerprint. `AGENT_REVOKED` means the Control Plane no longer accepts the certificate fingerprint. Rotation is not currently exposed; use an approved administrative recovery process.

## Protocol incompatible

Both sides must use major version `1`. The current exact version is `1.0`. The Agent stops polling on `PROTOCOL_INCOMPATIBLE`.

## Capability hash mismatch

The Agent sorts the manifest before hashing. A mismatch means the wire representation or server contract changed; do not continue dispatch until both implementations are reviewed.

## Module unavailable

Missing fixed tools produce unavailable capabilities. PCAP and iperf adapters are intentionally unavailable under the current envelope/artifact contracts. The Agent never installs tools.

## Spool full

Restore Control Plane connectivity, verify mTLS, inspect only metadata such as item count/bytes, and preserve file permissions. Do not edit queued JSON; altered results will fail Control Plane idempotency checks.
