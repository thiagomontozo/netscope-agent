# Signed protocol canonicalization

The Agent mirrors the Control Plane RFC 8785 implementation in the small
`internal/canonicaljson` package. It accepts exactly one valid I-JSON value,
rejects duplicate names and invalid or non-finite numbers, and emits UTF-8 JCS
bytes independent of map order, whitespace, locale and operating system.

Finite IEEE-754 decimals remain numbers and use deterministic ECMAScript
serialization. The Agent does not decode trusted parameters into an
uncontrolled `float64` map before signing: raw JSON is checked with
`json.Decoder.UseNumber`, canonicalized, and embedded as canonical raw JSON in
the protected JobEnvelope payload. Bare integers beyond `±(2^53-1)` fail
closed rather than being silently rounded.

The vendored Control Plane vectors are checksum-pinned. CI verifies canonical
bytes, SHA-256 and Ed25519 for all vectors on Linux, Windows and macOS.
