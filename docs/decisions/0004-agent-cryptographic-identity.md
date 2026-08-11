# 0004 — Agent cryptographic identity

## Status

Accepted

## Context

The Control Plane must identify Agents without receiving their private key material.

## Decision

Generate an Ed25519 key pair locally and store identity atomically with restrictive
permissions. Send only the public key during enrollment.

## Consequences

Identity backup and recovery need an explicit operational policy. OS keystore or
hardware backing can strengthen future releases.
