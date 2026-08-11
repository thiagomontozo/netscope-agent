# 0002 — Outbound-only Agent

## Status

Accepted

## Context

Agents run behind NAT and firewalls. An inbound execution listener would increase
exposure and operational complexity.

## Decision

The Agent initiates enrollment, heartbeat, polling, status, result, and artifact
HTTPS requests. It exposes no remote execution listener.

## Consequences

Deployments need only controlled egress. Cancellation and dispatch are polling-based,
with bounded latency determined by configured intervals.
