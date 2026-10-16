# ADR 0003: Registry-Generated Actions

- Status: Accepted
- Date: 2026-08-02

## Context

Handwritten forms and command-specific UI handlers drift from CLI validation
and safety policy. Netrune already has a central command registry.

## Decision

The command registry is the only action catalog. Every entry exposes argument
schema, help, defaults, capability, output view, safety class, risk level,
effects, run support, and confirmation policy. The console generates forms and
previews from that metadata. The service revalidates all submitted data.

## Consequences

- Adding a complete registry entry makes an action discoverable without a new
  form implementation.
- Registry completeness is tested across every discovered action; no count is
  duplicated in this decision record.
- Terminal-only and preview-only classifications remain explicit.
- UI validation is convenience; core/service validation remains authoritative.
