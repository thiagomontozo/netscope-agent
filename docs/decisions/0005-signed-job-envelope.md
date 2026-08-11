# 0005 — Signed job envelope

## Status

Accepted

## Context

TLS does not protect a job while stored in an application database or queue.

## Decision

Require Ed25519 signatures over the typed job envelope, including target, parameters,
scope, authorization, risk, timestamps, nonce, and recipient.

## Consequences

Queue tampering is detected at execution time. Key rotation and canonical encoding
must be coordinated by protocol version.
