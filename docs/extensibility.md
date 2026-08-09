# Profiles, Ingest, Plugins, and Drivers

NetOps customization is profile-scoped and data-driven. Most operators should
not need to fork the project.

## Ingest Contract

An `IngestChannelV1` manifest selects a reader and maps source fields into
`ObservationV1`. Every accepted observation records source identity, observed
and received times, completeness, status, confidence, provenance, raw-evidence
hash, and deterministic idempotency key.

Place channel TOML files in the active profile's `channels` directory:

```bash
netops profile paths
netops ingest validate
netops ingest channels
netops ingest run csv-devices
netops ingest history
netops ingest rejects
```

CSV, JSON, JSONL, HTTPS JSON, NetBox, stdin NDJSON, and fixture-gated SNMPv3
are supported. Catalyst Center, Aruba Central, and SmartZone API readers are
experimental and require explicit fixture or environment gates.

Invalid records are quarantined with redacted evidence. Duplicate delivery
does not create duplicate history. Sparse observations can refresh status and
poll time but cannot erase trusted non-empty fields. Field-level provenance is
stored independently from the materialized inventory view.

The built-in SSH scan, Cisco WLC, SmartZone, AP scan, and LLDP/CDP adapters use
the same run and observation tables under stable `built-in-*` channel names.
They receive the same idempotency, chronology, and provenance behavior as
manifest channels instead of maintaining a second history model.

## Secret References

Manifests accept only `vault:`, `env:`, or permission-validated `file:` secret
references. Literal secrets are rejected. Prefer named secrets:

```bash
netops secrets set ingest/netbox/token
netops secrets status ingest/netbox/token
netops secrets list
```

Secret values are prompted through the terminal and never returned by list,
status, config export, support bundle, or logs.

## Trusted Python Plugins

Plugins use standard Python entry points:

```toml
[project.entry-points."netops.parsers"]
example = "example_package.parser:plugin"
```

Groups are `netops.ingest`, `netops.device_drivers`, `netops.parsers`, and
`netops.exporters`. Discovery records package source and version without
importing disabled code. Enable only reviewed packages:

```bash
netops plugin list
netops plugin groups
netops plugin enable netops.parsers:example
netops plugin check netops.parsers
netops plugin disable netops.parsers:example
```

API-incompatible, colliding, or failed plugins are isolated and reported.
Shell hooks and write capabilities are rejected. Plugins are trusted local
Python code and are not a security sandbox.

### Plugin Runtime Protocol

Every plugin object must expose `NETOPS_PLUGIN_API_VERSION = "1"`. Optional
`NETOPS_PLUGIN_CAPABILITIES` values are normalized and checked; any write,
shell, subprocess, process, exec, execute, or system claim is rejected.

The group-specific interfaces are:

| Group | Required object interface | Runtime use in 8.5 |
|---|---|---|
| `netops.ingest` | `read_records(channel, reader, secrets)` returning an iterable of mappings | Selected by a `plugin` channel's `reader.provider` |
| `netops.device_drivers` | One `DeviceDriver`, or `netops_device_drivers()` returning drivers | Revalidated and loaded into only the selected profile's registry clone |
| `netops.parsers` | Callable `parse()` method | Loaded into the internal parser extension registry |
| `netops.exporters` | Callable `export()` method | Loaded into the internal exporter extension registry |

An ingest provider is configured with a normal channel manifest:

```toml
schema_version = 1

[channel]
name = "example-provider"
kind = "plugin"
enabled = true
entity_kind = "device"
source_id_field = "id"
observed_at_field = "observed_at"

[secrets]
token = "vault:ingest/example/token"

[reader]
provider = "example"
completeness = "partial"
confidence = 85
```

Only references declared under `[secrets]` are resolved. Values are
passed in memory, are not added to arguments or configuration, and are removed
from provider exception text. The observation records the providing
distribution as provenance. Provider records still cross the normal mapping,
validation, duplicate, quarantine, stale-field, and materialization boundary.

Device-driver plugins receive a second validation after generic plugin load.
Detection patterns and parser IDs must be bounded, read commands must pass the
same declarative allowlist, firmware write profiles are discarded, and
configuration/VLAN-write capabilities are forced unsupported. A collision
rejects the driver set atomically.

Parser and exporter entry points are intentionally internal extension APIs in
8.5; there is no generic CLI that executes arbitrary plugin methods. A public
consumer must first define a versioned input/output contract and bounded core
action rather than exposing plugin call-through.

## Declarative Device Drivers

Read-only TOML drivers belong in the profile's `drivers` directory. They can
add semantic read commands, parser-template identifiers, and bounded regular
expressions under `[match]` for deterministic family selection. Every profile
gets its own registry copy. Newline-bearing commands, shell metacharacters,
unknown command prefixes, configuration operations, save/reload/erase
operations, and claimed write support are rejected.

Built-in writes remain separately gated by a certified firmware profile,
explicit profile enablement, exact preview, backup, confirmation, read-back,
and audit evidence. Declarative and third-party drivers cannot write in 8.5.

## Developing a New Integration

1. Define source ownership, stable IDs, completeness, trust, and deletion
   semantics.
2. Capture sanitized success, empty, malformed, rejected-command, timeout, and
   wrapped-output fixtures.
3. Map raw fields to `ObservationV1` or semantic capability evidence.
4. Prove duplicate delivery, sparse update, stale record, and failure behavior.
5. Package a versioned entry point and document compatibility.
6. Keep it disabled until fixture and authorized-lab evidence passes.
