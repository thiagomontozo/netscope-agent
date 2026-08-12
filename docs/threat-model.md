# Agent trust threat model

The Control Plane threat model is mirrored at the Agent boundary. Enrollment
token theft is limited by TTL/single use; MITM by HTTPS/mTLS; job manipulation
and downgrade by explicit compatibility and Ed25519 policy; replay by expiry,
job/Agent binding and a bounded nonce cache; artifact tampering/path traversal
by streaming SHA-256, size limits, opaque temporary names and regular-file
checks; stale or stolen identities by local permissions, atomic rotation and
server-side revocation. A compromised Agent host can still use its active keys
and falsify its observations until revoked. HSM, OCSP, automatic binary update,
multipart resume and production load validation are not implemented.
