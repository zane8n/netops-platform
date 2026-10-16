# ADR 0006: One Job and Audit Lifecycle

> **Job half superseded 2026-08-25.** The job/Activity-pane machinery this ADR
> describes (`create_job`, background threads, live progress streaming,
> cancellation) was written for the TUI/API console ADR 0001 superseded, and
> nothing in the CLI-only architecture ever called it -- `jobs list/show/cancel`
> read a `jobs` table nothing wrote to. It has been removed along with the
> `jobs` domain. The audit half is unaffected and remains the live mechanism:
> `record_audit_event` and the `audit_events` table, as used throughout the
> guarded configuration lifecycle (ADR 0005).

- Status: Partially superseded 2026-08-25 (job half only; audit half remains current)
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
