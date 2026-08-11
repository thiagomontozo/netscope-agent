# NetScope Agent Protocol v1

Protocol version: `1.0`. Agent version: `0.2.0-experimental`.

The normative source is the Control Plane directory `contracts/agent/v1`.
Requests are direct JSON objects. Successful JSON responses are wrapped as
`{"data": ...}`. Errors use `{"error":{"code","message","requestId"}}`.
Security-sensitive responses reject unknown fields and multiple JSON values.

## Transport and authentication

Enrollment uses server-authenticated HTTPS and a short-lived token in the request
body. Every later operation uses HTTPS with the enrolled client certificate. The
Control Plane authenticates its SHA-256 fingerprint; no bearer credential or
permanent enrollment token is sent. A regular browser does not use this API.

| Operation | Method and path | Agent type |
|---|---|---|
| Enrollment | `POST /agent/v1/enroll` | `EnrollmentRequest/Response` |
| Heartbeat | `POST /agent/v1/heartbeat` | `Heartbeat` |
| Capabilities | `POST /agent/v1/capabilities` | `CapabilityManifest` |
| Poll | `GET /agent/v1/jobs/next` | `JobEnvelope` or JSON `null` data |
| Start | `POST /agent/v1/jobs/:id/start` | no request body |
| Result | `POST /agent/v1/jobs/:id/result` | `JobResult` |
| Failure | `POST /agent/v1/jobs/:id/fail` | `JobFailure` |
| Cancellation | `GET /agent/v1/jobs/:id/cancellation` | `JobCancellation` |
| Evidence | `POST /agent/v1/evidence` | `EvidenceRequest` |

## Enrollment

`EnrollmentRequest` contains `protocolVersion`, `enrollmentToken`, `agentName`,
`hostname`, `os`, `architecture`, `agentVersion`, `publicIdentity.csrPem`, sorted
`capabilitiesSummary`, and optional `labels` and `networkZone`.

`EnrollmentResponse` contains `protocolVersion`, `agentId`, `organizationId`,
`status`, `serverTime`, `controlPlaneIdentity.caCertificatePem`, optional
`controlPlaneIdentity.jobSigningPublicKey`, and
`agentCredential.certificatePem/expiresAt`. It never returns the enrollment token.

## Heartbeat and capabilities

`Heartbeat` contains `protocolVersion`, `agentId`, `agentVersion`, `timestamp`,
`hostname`, `os`, `architecture`, `status`, `runningJobs`, `availableSlots`,
`capabilitiesHash`, `healthSummary`, and optional `lastJobResult` with `jobId`,
`status`, and `completedAt`. The response contains the server status, protocol,
compatibility status, and server time.

`CapabilityManifest` contains `protocolVersion`, `agentId`, `platform`, `modules`,
`externalTools`, `networkCapabilities`, and `artifactCapabilities`. Every module has
`moduleId`, `capabilityId`, `available`, `implementation`, `moduleVersion`, and
`riskClasses`. Tool records have `name`, `version`, and `available`. Lists are
sorted before hashing and reporting.

## Job envelope and start

`JobEnvelope` contains:

- protocol, job, organization, and recipient agent IDs;
- module ID and exact `moduleVersionRequirement`;
- scope ID and `scopeEnvironment`;
- optional asset, service, diagnostic-run, and vantage-point IDs;
- immutable `target.type/value` and typed `validatedParameters`;
- risk class and `authorizationReference`;
- issue, expiry, timeout, and nonce controls;
- optional `signatureAlgorithm` and `signature` fields.

It never contains a command, shell string, executable, arbitrary argument list, or
script. The Agent acknowledges the assigned job through `/start` without a request
body and executes only after that succeeds.

## Result and failure

`JobResult` contains `protocolVersion`, stable `resultIdentity`, `resultVersion`,
job/agent/module IDs, `status: SUCCEEDED`, timestamps, technical summary,
observations, metrics, warnings, evidence manifest, optional tool version, and
`truncated`. Observations use the shared status and confidence enums. The Agent does
not assign global priority, business impact, contextual risk, or incident linkage.

Failures use the separate `JobFailure` body: protocol/job/agent IDs, stable `code`,
safe `summary`, `occurredAt`, and `retryable`. Codes are:

- `MODULE_UNAVAILABLE`, `TOOL_NOT_FOUND`, `CAPABILITY_MISSING`;
- `INVALID_JOB`, `JOB_EXPIRED`, `TARGET_REJECTED`;
- `TIMEOUT`, `PROCESS_FAILED`, `OUTPUT_LIMIT_EXCEEDED`, `ARTIFACT_ERROR`;
- `CANCELLED`, `PROTOCOL_INCOMPATIBLE`, `SIGNATURE_INVALID`, `INTERNAL_ERROR`.

No stack trace is sent.

## Cancellation and evidence

`JobCancellation` contains protocol/job IDs, `cancellationRequested`, optional
`requestedAt`, and current `jobStatus`. The Agent polls it and cancels the module
context; there is no Agent-originated state override.

`EvidenceRequest` contains protocol/job/agent IDs and one `EvidenceManifest`.
The manifest contains evidence ID, source module, content type, summary, structured
data, SHA-256, byte size, and artifact kind. The current endpoint registers metadata;
it does not transfer artifact content.

## Compatibility, retries, and signing

Different major versions are incompatible. Same-major evolution can be compatible,
but v1 required fields and enums remain mandatory. Module versions are independently
exact. A protocol or authentication terminal error stops job polling.

Result retries reuse the exact identity, version, evidence IDs, and payload so the
Control Plane checksum receipt treats delivery idempotently. Failure retry after an
ambiguous response treats `JOB_STATE_INVALID` as already terminal because the failure
endpoint is state-machine guarded rather than receipt based.

Ed25519 fields are reserved but inactive: the Control Plane does not sign envelopes
or return a signing key. The Agent rejects unexpected signing fields. Certificate
rotation, artifact-content transfer, and controlled endpoint resolution are not
implemented by the current Control Plane API.
