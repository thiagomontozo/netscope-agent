# Safe integration testing

CI uses Go unit tests, `httptest` loopback servers, temporary directories,
synthetic bytes, TEST ONLY Ed25519 vectors and context-aware mock modules. Tests
cover canonicalization, signing/tamper, wrong Agent, expiry, replay, protocol
major mismatch, unsigned policy, token scoping/expiry, streaming checksum,
checksum mismatch, cancellation and timeout terminal states.

v0.2.1 adds the Control Plane JCS snapshot, integer/decimal/nested/Unicode
vectors, Ed25519 verification, decimal mutation, ephemeral certificate rotation
success/rollback, streaming upload, oversize rejection, malicious artifact ID
containment and partial transfer cleanup.

No test invokes ping, traceroute, Nmap, TShark, Zeek, Suricata, iperf3, DNS/HTTP
Internet probes, packet capture or discovery. External adapters compile but are
not executed.
