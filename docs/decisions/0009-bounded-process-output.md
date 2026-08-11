# 0009 — Bounded process output

## Status

Accepted

## Context

External tools can emit unbounded stdout/stderr and exhaust Agent memory or disk.

## Decision

Use bounded writers for stdout/stderr, context deadlines, result/artifact limits,
and explicit truncation metadata.

## Consequences

Some raw detail may be omitted. Consumers can distinguish truncation and use a
separately authorized bounded artifact workflow when appropriate.
