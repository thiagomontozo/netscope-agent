# Enrollment

The authenticated response may carry named Ed25519 public trust metadata. The
Agent validates its fingerprint before atomically persisting it beside the mTLS
identity; no Control Plane signing private key is transmitted.

Protocol v1 enrollment uses `POST /agent/v1/enroll` with a direct JSON body containing `protocolVersion`, `enrollmentToken`, `agentName`, hostname, OS, architecture, agent version, a PKCS#10 CSR, initial capability IDs and optional network zone.

The Agent creates an ECDSA P-256 key locally and sends only the CSR. The Control Plane atomically consumes the short-lived token, issues a 90-day client-auth certificate and returns:

- agent and organization UUIDs;
- protocol and agent status;
- public Control Plane CA material;
- client certificate and expiry;
- server time;
- an optional job-signing public key, currently absent because signing is inactive.

The private key, certificate, CA and metadata are written to a staging directory and installed together. Existing or partial identity material is never overwritten silently. After success the process unsets `NETSCOPE_ENROLLMENT_TOKEN`; operators must also remove it from the service configuration.

All later `/agent/v1` calls present the client certificate. The Control Plane hashes its DER bytes and matches the fingerprint to an ONLINE, DEGRADED or OFFLINE non-expired agent. REVOKED and unknown identities are rejected.

Certificate rotation is not exposed by the current Agent API. Recovery or re-enrollment must be an explicit administrative procedure.
