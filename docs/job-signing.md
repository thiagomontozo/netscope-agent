# Signed jobs

The Agent defaults to `NETSCOPE_REQUIRE_SIGNED_JOBS=true`. Enrollment stores a
TEST-independent trust record containing the Control Plane Ed25519 key ID,
public key, fingerprint, algorithm and issue time. Before module lookup or
execution, the Agent validates protocol, identities, target, risk, time, nonce
and the signature made over NetScope Canonical JSON v1. It never tries every
key. Modification, unknown key, invalid base64, unsigned-required work and
replay fail with `SIGNATURE_INVALID` or the more specific validation code.

The Control Plane contracts and vectors are canonical. The vendored Agent
snapshot exists only for offline CI and records shared canonical bytes and
TEST ONLY key material; there is no runtime cross-repository dependency.
