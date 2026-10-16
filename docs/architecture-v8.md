# Netrune 8.5 Architecture

## Purpose

Netrune 8.5 is a local-first, profile-scoped network operations application. A
single policy core remains responsible for inventory, chronological state,
transport policy, diagnostics, command construction, and guarded execution.
The platform package gives the CLI, jobs, ingest channels, plugins, path
inspection, and exports versioned contracts. The full-screen Textual console
and its headless `service.py` boundary were removed (see
[ADR 0001](adr/0001-local-first-operator-console.md), "Superseded"); every
operator interface is the CLI.

## Runtime layers

```text
Operator
  |
  +-- noun-first CLI ------------+---- netrune.core.App
  +-- traffic collector ---------+        |
                                          +-- SQLite canonical state
netrune                              +-- job and audit lifecycle
  +-- contracts.py                          +-- policy and command registry
  +-- profiles.py                           +-- profile-scoped XDG paths
  +-- ingest.py                             +-- observations and provenance
  +-- plugins.py                            +-- trusted entry-point lifecycle
  +-- path_inspector.py                     +-- bounded L2/L3 evidence graph
  +-- privacy.py / release.py               +-- publication and artifacts
  +-- traffic*.py                           +-- watchlist poller, exposition,
                                                stack provisioning
```

### Core

The canonical core implementation is `netops_platform/core.py`; the top-level
flat modules (`netops_core.py` and siblings) and the `netrune` package alias
it to preserve imports and helper entry points through the v8 compatibility
window (see [migration-netrune.md](migration-netrune.md)). The core owns
target resolution, schema migration, the command registry, command
construction, process groups, jobs, audit records, SSH trust, configuration
gates, and compatibility dispatch. Shell helpers remain adapter
implementations, not public policy boundaries.

### Contracts

`netops_platform/contracts.py` defines schema version 1 for the types actually
consumed elsewhere in the tree:

- `ObservationV1`, `IngestChannelV1`, and `IngestRunV1`: idempotent source
  observations, channel configuration, provenance, and run outcomes.
- `PluginDescriptorV1`: trusted extension identity, compatibility, source,
  and capability declarations.
- `CapabilityEvidenceV1`: timestamped semantic evidence independent of vendor
  command syntax.
- `PathRequestV1`, `PathHopV1`, `PathFindingV1`, and `PathResultV1`: bounded
  Ghoster requests, hop evidence, confidence, age, findings, and outcomes.

Consumers must tolerate additive fields. Breaking field removal or semantic
changes require a new schema version and an adapter period. A wider set of
result/dataset/job-event/action-preview envelope types existed here for the
removed TUI/service layer; they were dropped rather than kept as unused
surface once nothing referenced them.

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
`read_records(channel, reader, secrets)` and returns mapping objects. Netrune
resolves only manifest-declared secret references, passes values in memory,
redacts provider exceptions, and records distribution provenance. Parser and
exporter entry points implement `parse()` and `export()` respectively; they are
registered as internal extension APIs in 8.5. A device-driver entry point
returns one `DeviceDriver` or exposes `netrune_device_drivers()`.

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

## Audit trail

Every command runs synchronously in its own process; there is no background
job queue or progress stream (see ADR 0006, "job half superseded" -- that
machinery was written for the removed TUI/API console and nothing in the
CLI-only architecture ever called it). Safety-significant actions still write
an audit event as they run: actor, target, result, and a JSON detail blob,
never pruned (see "Configuration transaction boundary" below). `netrune db
status` reports table counts; there is nothing else to poll.

## Configuration transaction boundary

The enabled v8 configuration action is typed VLAN assignment. Its lifecycle is:

```text
validated preview -> confirmation binding -> preflight -> backup -> apply
                  -> read-back verification -> audit result
```

A preflight or backup failure blocks apply. A verification failure produces a
partial result with captured rollback evidence; Netrune does not claim an
automatic transactional rollback.

Access and trunk requests of up to eight VLAN IDs verify every requested VLAN.
Larger trunk sets sample deterministic boundaries and return partial with
`verification_complete=false`; sampled evidence is never reported as full
success.

Direct `netrune-control config` and `netrune-control vlan` execution is denied
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
3. Decide whether the action is job-safe or preview-only.
4. Return structured JSON with stable status and evidence whenever practical.
5. Add unit and shell-lifecycle tests for the new or changed behavior.
6. Update documentation and migration notes.

Do not add a second source of command templates or an unversioned result
shape.
