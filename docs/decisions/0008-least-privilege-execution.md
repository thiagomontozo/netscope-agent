# 0008 — Least-privilege execution

## Status

Accepted

## Context

Some network operations may require special OS capabilities, while most do not.

## Decision

Run the base Agent unprivileged and grant only module-specific capabilities where
deployment policy permits. Never auto-escalate.

## Consequences

Some capabilities will be unavailable until explicitly configured. A single optional
module does not justify running the whole Agent as root or Administrator.
