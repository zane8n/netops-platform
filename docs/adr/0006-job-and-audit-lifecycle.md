# ADR 0006: One Job and Audit Lifecycle

- Status: Accepted
- Date: 2026-08-02

## Context

Long diagnostics and workflows need live progress, cancellation, final
structured results, operator attribution, and chronological evidence without
mixing progress into result tables.

## Decision

Runnable non-terminal console actions execute as core jobs. Jobs persist
request, actor context, status, timing, exit code, summary, and result JSON.
Ordered events persist stream, phase, progress, payload, and ISO 8601 UTC time.
Workflows emit per-step events and one final summary; each step declares stop or
continue behavior. Safety-significant actions also write audit events.

## Consequences

- The Activity pane can stream readable progress while the workbench remains
  structured.
- `partial` is a terminal state distinct from success and failure.
- Cancellation is a request and does not erase completed evidence.
- Retention and archival remain deployment responsibilities until a later ADR.
