# 0007 — Compiled module registry

## Status

Accepted

## Context

Runtime plugins delivered by a server introduce code-signing, compatibility, and
arbitrary-code-execution risks.

## Decision

Compile the v0.1 module set into the Agent and register descriptors statically.

## Consequences

Adding a module requires a reviewed Agent release. Signed module packages may be
researched later but are outside v0.1.
