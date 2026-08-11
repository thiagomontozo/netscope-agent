# Job protocol

This compatibility page is retained for existing links. The normative Agent-side
documentation is [protocol-v1.md](protocol-v1.md), and the lifecycle and retry
semantics are in [job-lifecycle.md](job-lifecycle.md).

The wire source of truth is the Control Plane `contracts/agent/v1` directory.
NetScope Protocol `1.0` sends a typed `JobEnvelope`; it never sends a shell command,
raw command line, or arbitrary argument list. Job signing fields are reserved but
the current Control Plane does not sign envelopes. The Agent fails closed if signing
fields unexpectedly appear rather than claiming an unimplemented verifier.
