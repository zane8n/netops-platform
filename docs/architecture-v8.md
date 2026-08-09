# NetOps 8.5 Architecture

## Purpose

NetOps 8.5 is a local-first, profile-scoped network operations application. A
single policy core remains responsible for inventory, chronological state,
transport policy, diagnostics, command construction, and guarded execution.
The platform package gives the CLI, terminal console, jobs, ingest channels,
plugins, path inspection, exports, and future clients versioned contracts.

## Runtime layers

```text
Operator
  |
  +-- Textual console -----------+
  +-- noun-first CLI ------------+---- netops_platform.core.App
  +-- localhost API / WebUI -----+        |
                                          +-- SQLite canonical state
netops_platform                              +-- job and audit lifecycle
  +-- contracts.py                          +-- policy and command registry
  +-- profiles.py                           +-- profile-scoped XDG paths
  +-- ingest.py                             +-- observations and provenance
  +-- plugins.py                            +-- trusted entry-point lifecycle
  +-- path_inspector.py                     +-- bounded L2/L3 evidence graph
  +-- privacy.py / release.py               +-- publication and artifacts
  +-- service.py                            +-- helper process supervision
  +-- preferences.py                        +-- shell/vendor adapters
  +-- tui/
```

### Core

The canonical core implementation is `netops_platform/core.py`; temporary
flat modules such as `netops_core.py` alias their canonical package modules to
preserve imports and helper entry points through the v8 release line. The core
owns target resolution, schema migration, the command
registry, command construction, process groups, jobs, audit records, SSH trust,
configuration gates, and compatibility dispatch. Shell helpers remain adapter
implementations, not public policy boundaries.

### Contracts

`netops_platform/contracts.py` defines schema version 1 for:

- `ResultEnvelopeV1`: status, summary, metrics, datasets, findings,
  provenance, raw evidence, and timing.
- `DatasetV1` and `ColumnSpec`: table identity, stable columns, row keys,
  sorting metadata, and row actions.
- `Finding`: severity, stable code, message, target, remediation, and evidence.
- `ActionPreviewV1`: normalized arguments, exact command, effects, targets,
  missing fields, policy state, preview hash, and confirmation phrase.
- `OperatorContext`: actor, UID, session, reason, and ticket.
- `JobEventV1`: ordered event ID, UTC timestamp, stream, phase, progress, and
  structured payload.
- `ObservationV1`, `IngestChannelV1`, and `IngestRunV1`: idempotent source
  observations, channel configuration, provenance, and run outcomes.
- `PluginDescriptorV1` and `DeviceDriverV1`: trusted extension identity,
  compatibility, source, support level, and capability declarations.
- `CapabilityEvidenceV1`: timestamped semantic evidence independent of vendor
  command syntax.
- `PathRequestV1`, `PathHopV1`, `PathFindingV1`, and `PathResultV1`: bounded
  Ghoster requests, hop evidence, confidence, age, findings, and outcomes.

Consumers must tolerate additive fields. Breaking field removal or semantic
changes require a new schema version and an adapter period.

## Profile and configuration boundary

Each profile owns configuration, SQLite state, caches, known hosts, aliases,
ingest channels, drivers, named secrets, and backup policy under XDG roots.
Precedence is `CLI > environment > selected profile > global config > neutral
defaults`. `--profile` never changes the active-profile selector.

Profiles contain data, not executable hooks. Site-specific address expansion,
name-prefix rewrites, WLC filters, and aliases are opt-in profile settings. A
fresh profile has none of those behaviors.

## Ingest and provenance flow

```text
channel manifest -> bounded reader -> raw record -> ObservationV1 validation
                 -> duplicate check -> append-only observation/field evidence
                 -> redacted reject or non-destructive current-state materialization
```

Partial and stale observations remain historical evidence but cannot erase or
replace newer trusted values. HTTP credentials are references, not literals;
pagination remains on the configured origin. NetBox is the stable reference
adapter. Controller APIs and live SNMPv3 providers remain explicitly gated.

Accepted current-state deliveries trigger canonical reconciliation. Identity
matching first indexes strong and corroborating evidence, then evaluates only
candidate blocks; it never performs an unbounded all-pairs inventory scan.
Derived-state refresh computes one canonical snapshot and reuses it for
identity history, health, and relationships. Ingest writes are committed in
bounded batches to avoid one SQLite transaction per observation.

Schema 13 adds `inventory_merges` for explicit device lifecycle succession.
The source snapshot becomes historical-only, the target remains active, and a
managed relationship plus audit/history events preserve provenance. Active
merge policy suppresses stale source materialization after later imports. A
revocation restores the source only after checking IP ownership.

## Plugin and driver boundary

Python plugins use standard entry points and are not imported while disabled.
Explicit enablement validates API version, source, collisions, load behavior,
and prohibited capabilities. Plugins are trusted local code, not a sandbox.
Shell and network-write capabilities are rejected.

An enabled ingest provider implements
`read_records(channel, reader, secrets)` and returns mapping objects. NetOps
resolves only manifest-declared secret references, passes values in memory,
redacts provider exceptions, and records distribution provenance. Parser and
exporter entry points implement `parse()` and `export()` respectively; they are
registered as internal extension APIs in 8.5. A device-driver entry point
returns one `DeviceDriver` or exposes `netops_device_drivers()`.

Declarative device drivers add read command templates and parser identifiers.
They cannot define configuration, save, reload, erase, or VLAN-write actions.
Built-in writes additionally require deterministic family/model/firmware
selection and profile enablement.

## Ghoster flow

Ghoster resolves endpoint evidence, selects a source and edge switch, performs
a bounded graph search over cached topology, and then optionally validates each
hop through read-only semantic capabilities. The hard limits are depth 16 and
256 nodes. ACL/policy references remain unknown unless a supported parser can
prove their semantics. Runs, hops, and findings are append-only chronological
records.

### Application service

`netops_platform/service.py` is the headless boundary used by the TUI. It:

- converts canonical state into view envelopes;
- enriches registry entries into generated-form metadata;
- validates previews and confirmation evidence;
- submits jobs with an authenticated local operator context;
- adapts job output back into datasets and findings;
- exports only the currently materialized rows.

The TUI must not construct helper commands, write SQLite directly, or weaken a
core policy. A future GUI should consume this service or an equivalent API
adapter rather than duplicate command logic.

## Query flow

1. A view requests a `QuerySpec` from `NetOpsService`.
2. The service reads bounded canonical state from the core.
3. Rows become one or more `DatasetV1` objects with stable IDs.
4. The service derives metrics, findings, and provenance.
5. The console renders the envelope without transport access.
6. Filtering and sorting occur against the loaded dataset; refresh is explicit.

Opening the console is local-read-only. A mount or navigation event must never
start SNMP, SSH, ping, speed-test traffic, discovery, or configuration.

## Action flow

1. The operator selects an action from the registry or row context.
2. `ActionForm` is generated from `arg_schema`; no per-command form is required.
3. `service.preview()` normalizes arguments and asks the core for the exact
   bounded command and effects.
4. Read-only actions may run when required arguments are present.
5. Active actions require an operator reason.
6. Config actions additionally require a ticket, matching preview hash, and the
   exact typed phrase.
7. `service.submit()` re-previews the action and rejects stale or altered
   confirmation evidence.
8. The core creates a job and records operator context in job and audit data.

Interactive SSH is terminal-only. The console suspends itself and delegates to
the managed `device ssh` path rather than trying to emulate a terminal session.

## Job flow

Jobs use one lifecycle:

```text
queued -> running -> completed | partial | failed | cancelled | stale
                    running -> cancelling -> cancelled | completed
```

Events have monotonic database IDs and explicit stream/phase fields. Live
stderr progress is shown in the Activity pane while the final structured result
remains a clean workbench dataset. Cancellation is explicit. Exiting with jobs
active requires the operator to stay, open Jobs, or cancel them.

## Configuration transaction boundary

The enabled v8 configuration action is typed VLAN assignment. Its lifecycle is:

```text
validated preview -> confirmation binding -> preflight -> backup -> apply
                  -> read-back verification -> audit result
```

A preflight or backup failure blocks apply. A verification failure produces a
partial result with captured rollback evidence; NetOps does not claim an
automatic transactional rollback. Arbitrary `device config` remains preview
only in generated/background interfaces.

Access and trunk requests of up to eight VLAN IDs verify every requested VLAN.
Larger trunk sets sample deterministic boundaries and return partial with
`verification_complete=false`; sampled evidence is never reported as full
success.

Direct `netops-control config` and `netops-control vlan` execution is denied
unless the core supplies the internal audited-confirmation marker. This marker
is an implementation capability and is not a supported operator override.

## SSH trust boundary

All shell SSH adapters use the private managed known-hosts file. Normal modes:

- `accept-new`: trust first contact, reject changed keys.
- `strict`: require prior enrollment.

`device trust-scan` retrieves fingerprints without trusting them.
`device trust-enroll` requires an exact SHA-256 fingerprint verified through an
independent channel. Store writes are atomic, mode `0600`, and audited.
Break-glass host-key bypass requires both an explicit mode and an explicit
environment acknowledgement and emits a warning; it is not a persistent
configuration option.

## Extending v8

For a new action:

1. Add or update the core `CommandSpec` with bounded builders and argument
   validators.
2. Assign safety class, risk level, effects, capability, output view,
   confirmation policy, and help for every field.
3. Decide whether the action is job-safe, terminal-only, or preview-only.
4. Return structured JSON with stable status and evidence whenever practical.
5. Add a service adapter only when generic row/finding adaptation is
   insufficient.
6. Add service policy tests, parser/adapter tests, TUI interaction tests where
   behavior changes, and shell lifecycle tests for helper changes.
7. Update documentation and migration notes.

Do not add a TUI button that bypasses the registry, a second source of command
templates, or an unversioned result shape.
