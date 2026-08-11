# 0006 — No arbitrary shell

## Status

Accepted

## Context

A generic command or script channel would turn a network sensor into a remote shell.

## Decision

Never accept command strings, scripts, shell flags, or terminal sessions. External
tools are invoked directly by compiled adapters with validated arguments.

## Consequences

Every operation requires a module and schema change. This deliberately reduces
flexibility in exchange for a smaller, auditable attack surface.
