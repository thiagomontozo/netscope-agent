# Enrollment

1. An administrator creates a short-lived, single-use token in the Control Plane.
2. On first start, the Agent generates an Ed25519 key pair locally.
3. It sends `POST /agent/v1/enroll` over validated HTTPS with its name, version,
   platform, and public key. The token is carried only in the enrollment request.
4. The Control Plane validates and consumes the token, registers the public identity,
   and returns an agent ID and permanent credential. It may also return the pinned
   Ed25519 public key used to verify job envelopes.
5. The Agent atomically stores identity material with mode `0600` and subsequently
   uses the permanent credential. The administrator removes the token from the
   persistent service environment.

The private key never leaves the host. Failed enrollment does not write a partial
identity. Re-enrollment requires an explicit administrative recovery procedure; the
Agent does not silently overwrite an existing identity.

Production deployments should combine restrictive filesystem ACLs with an OS
keystore or hardware-backed key design when their risk model requires it. Token and
permanent credentials must never appear in logs, process arguments, or scanner
environments.
