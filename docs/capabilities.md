# Capabilities

`CapabilityManifest` exactly matches Protocol v1:

- `protocolVersion`, `agentId`, `platform`;
- sorted module entries with module/capability ID, availability, `builtin` or `external-tool`, version and risk class;
- sorted external tool entries;
- sorted network capability IDs;
- artifact capability IDs.

Tool presence/version detection uses fixed help/version arguments, a two-second context, a minimal environment and at most 256 output bytes. Nothing is installed.

The manifest is deterministically sorted and JSON encoded before SHA-256 hashing. The Agent compares its hash with the hash returned by `POST /agent/v1/capabilities`; a mismatch stops startup. Heartbeats reuse that hash.

PCAP modules are compiled but `available=false` because Protocol v1 does not deliver artifact content. iperf is likewise unavailable because the envelope provides a controlled endpoint ID without resolved destination details. This fail-closed behavior prevents accidental dispatch.
