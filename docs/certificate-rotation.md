# Certificate rotation

The authenticated Agent creates a fresh P-256 private key and CSR locally,
requests a new certificate, verifies key pairing/expiry/fingerprint, writes and
fsyncs a private staging identity, then atomically renames the active directory
while retaining one rollback directory. Only after local activation does it
create a fresh mTLS client with certificate B and confirm the certificate ID to
the Control Plane using B. Pending B can authenticate only confirmation. No private key crosses the
wire. A partial or invalid staged identity never replaces the active identity.

The client implements rotate and confirm protocol operations; production
operators must schedule rotation before the configured warning window and
remove a rollback after successful confirmation according to policy. If local
validation, client creation or confirmation fails, the Agent restores A,
requests server-side revocation of pending B using A and removes staged files.
