# 0010 — Local result spool

## Status

Accepted

## Context

Temporary Control Plane outages should not discard completed safe work.

## Decision

Persist a small, permission-restricted, byte- and age-bounded queue of pending result
and audit-event JSON payloads. Do not queue jobs or retain large PCAPs.

## Consequences

Results can be retried after connectivity returns. Full spools reject additional
items explicitly and require operational attention.
