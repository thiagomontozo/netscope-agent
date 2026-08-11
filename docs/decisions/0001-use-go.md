# 0001 — Use Go

## Status

Accepted

## Context

The Agent must be small, cross-platform, statically deployable, and suitable for
network and cryptographic work with few dependencies.

## Decision

Use stable Go, the standard library, `context.Context`, and avoid CGO where possible.

## Consequences

Linux, Windows, and macOS builds share most code. OS-specific behavior remains in
narrow adapters, and unsupported tools must be reported rather than assumed.
