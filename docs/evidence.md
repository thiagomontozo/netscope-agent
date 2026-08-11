# Evidence

The Agent produces the exact `EvidenceManifest` fields: UUID, source, content type, summary, structured object, SHA-256, byte size and allowed artifact kind. Evidence is generated after bounded module execution and before result delivery.

Structured evidence uses `application/json`. The checksum covers the exact structured bytes stored in the manifest. Result spooling preserves the evidence ID and payload, which is required for idempotent retry.

The Control Plane endpoint `/agent/v1/evidence` registers metadata only. It does not upload artifact bytes and there is no pre-signed artifact download endpoint in Protocol v1. Consequently, this Agent does not send files, invent URLs or retain PCAP content in its spool. PCAP adapters remain unavailable.

Integrity metadata helps detect unintended changes. It is not a claim of forensic certification, admissibility or tamper-proof storage.
