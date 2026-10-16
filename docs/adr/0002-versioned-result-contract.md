# ADR 0002: Versioned Result Contract

> **Superseded 2026-08-25.** `ResultEnvelopeV1`, `DatasetV1`, `ColumnSpec`, and
> the other envelope types this ADR describes were written for the "one
> workbench" (TUI/API) client ADR 0001 superseded; the CLI's `self.emit()`
> renders raw dicts directly and never adopted them. They had zero callers
> outside `contracts.py` itself and were removed. `contracts.py` keeps the
> versioned types that are actually consumed: `ObservationV1`,
> `IngestChannelV1`, `IngestRunV1`, `PluginDescriptorV1`,
> `CapabilityEvidenceV1`, and the `PathRequestV1`/`PathHopV1`/
> `PathFindingV1`/`PathResultV1` family -- the additive-schema, new-version-for
> -breaking-changes discipline below still applies to those.

- Status: Superseded 2026-08-25
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
