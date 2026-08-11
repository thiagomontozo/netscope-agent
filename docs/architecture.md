# Architecture

NetScope Agent is an outbound-only Go worker. The Control Plane owns authorization and context; the Agent maintains an independent validation and resource boundary.

```text
Control Plane /agent/v1
        ^ HTTPS + client mTLS
        |
Client -> Protocol types -> Job verifier -> Executor -> Compiled registry
                              |              |          |
                         nonce/target    limits/cancel  Go or fixed adapter
                                             |
                                 Result normalization -> bounded spool
```

Startup loads configuration, builds the compiled registry, discovers fixed capabilities, loads or enrolls the certificate identity, creates the mTLS client, publishes the capability manifest and sends an initial heartbeat. The Agent then alternates heartbeat and job polling. It never starts a local listener or accepts an inbound command.

`internal/protocol` is the single wire-model package. Module results are internal and cannot be sent until the central Executor normalizes them into Protocol v1. External tools pass through the bounded process runner; the runner accepts only a compiled executable allowlist and never invokes a shell.

Runtime state:

```text
data/
  identity/  # private key, client certificate, public CA, metadata
  spool/     # exact pending result/failure/evidence JSON
  temp/      # reserved bounded temporary content
  state/     # reserved operational state
```

The Control Plane artifact API currently registers metadata only. No component fabricates an artifact-content transport.
