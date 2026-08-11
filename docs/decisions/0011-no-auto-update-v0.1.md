# 0011 — No automatic update in v0.1

## Status

Accepted

## Context

Remote binary replacement is a sensitive execution surface that needs a mature trust
and recovery design.

## Decision

Do not implement Agent auto-update in v0.1.

## Consequences

Operators deploy upgrades through existing managed channels. A future design must
require signed releases, checksums, explicit approval, atomic installation, and rollback.
