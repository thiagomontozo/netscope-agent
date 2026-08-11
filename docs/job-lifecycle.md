# Job lifecycle

```text
heartbeat -> poll -> validate -> reserve slot -> start acknowledgement
          -> cancellation check -> bounded execution -> result or failure
          -> exact-payload spool on ambiguous delivery
```

Validation covers protocol major, UUIDs, recipient agent and organization, scope reference, target type/value, authorization reference, risk class, issue/expiry time, timeout, nonce replay, known module, exact module version, platform/capability, strict parameters and module target rules.

The server assigns a polled job. The Agent must successfully call `/start` before executing. The execution deadline is the shortest of envelope timeout, envelope expiry and local maximum. Cancellation is checked before execution and every five seconds thereafter. Context cancellation stops Go calls and known external processes.

Successful results are normalized centrally. Failures never go to the success endpoint. A Control Plane cancellation already makes the server state terminal, so the Agent stops without trying to overwrite it.

No job is queued locally. When disconnected, polling backs off and no new work starts.
