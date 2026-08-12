# Vendored NetScope Agent Protocol 1.0 validation snapshot

The Control Plane repository is canonical. This directory contains only the
fixtures and cryptographic vectors required to validate the Agent without a
runtime or CI dependency on GitHub. `contract-manifest.sha256` records the
canonical snapshot checksum. Updates must be exported from the Control Plane in
one coordinated change; they must not be edited independently here.

The v0.2.1 snapshot identifies Control Plane source revision `main` at the
coordinated release commit. `contract-manifest.sha256` pins every vendored test
vector; `go test ./internal/canonicaljson` validates canonical bytes, SHA-256
and Ed25519 without a runtime GitHub dependency.
