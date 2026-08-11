# 0003 — Short-lived enrollment token

## Status

Accepted

## Context

A bootstrap secret is necessary but should not become a permanent Agent credential.

## Decision

Use a short-lived, single-use token only for the first enrollment and issue separate
permanent Agent credentials afterward.

## Consequences

Administrators must remove the token from service configuration after enrollment.
Token leakage has a smaller time and reuse window.
