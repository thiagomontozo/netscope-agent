# Job protocol

Protocol version `1.0` uses a JSON `JobEnvelope`. The Agent accepts only an envelope
returned by authenticated `GET /agent/v1/jobs/next`; it has no client-facing job
submission endpoint.

```json
{
  "protocolVersion": "1.0",
  "jobId": "job_123",
  "agentId": "agent_123",
  "organizationId": "org_123",
  "moduleId": "network.tcp",
  "moduleVersion": "1.0.0",
  "scope": {
    "scopeEnvironment": "INTERNAL",
    "scopeId": "scope_123",
    "authorizationReference": "approval_123"
  },
  "target": {"host": "service.example.internal", "port": 443},
  "parameters": {"timeoutMillis": 3000},
  "riskClass": "SAFE_ACTIVE",
  "issuedAt": "2026-08-11T12:00:00Z",
  "expiresAt": "2026-08-11T12:05:00Z",
  "nonce": "single-use-random-value",
  "signature": "base64url-ed25519-signature"
}
```

The signature is calculated over the JSON encoding of the typed envelope with the
`signature` field empty. Producers must use the identical field model and encoding
contract. A future protocol should adopt an explicit canonical JSON standard before
supporting independent producer implementations.

The Agent rejects a missing field/target, different agent, expired or future-issued
job, incompatible major protocol, unknown module, risk mismatch, missing capability,
invalid module parameters, missing active-assessment authorization, and invalid or
absent signature. The Control Plane must enforce nonce uniqueness.

Minor versions may add optional fields that older Agents safely ignore only when the
signed canonicalization contract explicitly permits them. Major-version differences
are rejected. `agentVersion`, `protocolVersion`, and supported module versions allow
the Control Plane to reject incompatible scheduling before delivery.

Normalized results contain job/module IDs, status, start/end time, summary,
observations, metrics, evidence metadata, warnings, truncation, optional tool version,
and a stable error code. Global vulnerability priority remains a Control Plane task.
