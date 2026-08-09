# ADR 0002: Versioned Result Contract

- Status: Accepted
- Date: 2026-08-02

## Context

Commands return tables, JSON, prose, and helper-specific structures. Rendering
each shape independently makes filtering, export, findings, provenance, and
future clients inconsistent.

## Decision

All application-layer views and completed job results use
`ResultEnvelopeV1`. Tables are named `DatasetV1` values with typed
`ColumnSpec` metadata. Findings and provenance are first-class, and the raw
payload is retained as evidence. Schema changes are additive within v1;
breaking semantics require a new version.

## Consequences

- One workbench can render inventory, topology, diagnostics, jobs, and audit.
- CSV exports preserve the filtered and sorted visible result.
- Helper output may need adapters before it is considered a mature v8 result.
- New clients depend on a stable contract rather than terminal formatting.
