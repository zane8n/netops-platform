# Netrune Platform Maturity Roadmap

## Objective

Develop Netrune as a neutral, evidence-led network operations platform without
turning incomplete vendor compatibility into broad support claims. Correctness,
provenance, privacy, and rollback remain prerequisites for convenience or new
writes.

## Release Train

### 8.2 Public Foundation

Status: implemented for the 8.5 beta branch; release gates remain in progress.

- Estate behavior exported to an ignored `legacy-local` profile.
- Neutral defaults, RFC 5737 examples, synthetic locally administered MACs,
  Apache-2.0, security/contribution/support policies, and third-party notices.
- `netrune init`, XDG profile paths, Linux/WSL2 installation, migration, and
  isolated-wheel smoke tooling.
- One command registry generates CLI help source, Markdown, JSON, `netrune(1)`,
  and Bash/Zsh/Fish completions; drift is a CI failure.
- Privacy scanner, private denylist support, clean public-export utility, and
  tracked-source/archive/history checks.
- Local third-party UI guide and operator-run logs excluded from publication.

The clean-export pipeline has produced and independently scanned a neutral
one-commit rehearsal with no remote and all tracked WebUI assets retained. Open
gate: create the durable public repository from the reviewed tracked-only set.
The private repository remains intact.

### 8.3 Profiles, Secrets, Ingest, and Plugins

Status: implemented for the 8.5 beta branch; authorized integration evidence
remains a release gate.

- Isolated profiles own config, state, cache, data, aliases, known hosts,
  channels, drivers, and named secrets.
- Precedence is CLI, environment, selected profile, global config, neutral
  defaults. One-shot `--profile` selection does not change the active profile.
- Idempotent legacy migration records a manifest, imports non-secret state, and
  leaves original files untouched.
- Sudo/PAM-gated encrypted named secrets support `vault:`, `env:`, and private
  `file:` manifest references. SSH compatibility commands map to
  `ssh/default/password`.
- `ObservationV1` ingest preserves field provenance, rejects duplicate history,
  quarantines invalid records, and prevents sparse observations from erasing
  trusted values.
- Declarative CSV, JSON, JSONL, HTTPS JSON, stdin NDJSON, fixture-gated SNMPv3,
  and read-only NetBox channels are implemented.
- Catalyst Center, Aruba Central, and SmartZone adapters remain experimental and
  fixture/credential gated.
- Standard Python entry-point plugins are disabled until explicitly enabled,
  version checked, source recorded, failure isolated, and prohibited from
  shell or write capabilities.
- Built-in SSH, controller, AP, and neighbor adapters record through the same
  idempotent ingest-run, observation, and provenance contract.
- Enabled ingest providers receive only declared secrets; Python device
  drivers are revalidated into a profile-local registry and forced read-only.

Automated pagination, same-origin TLS, rate-limit, quarantine, duplicate,
sparse/stale update, provider failure/redaction, collision, and profile
isolation fixtures pass. Open gate: authorized NetBox/provider contract
evidence and named-secret migration/rollback rehearsal on clean Linux and WSL2.

### 8.4 Ghoster and Device Compatibility

Status: bounded path engine and semantic capabilities implemented; real-lab
path evidence remains required.

- `netrune path inspect` and `netrune ghoster` resolve endpoint identity and plan
  from cached topology before optional bounded live validation.
- Defaults are depth 8 and 64 nodes; hard limits are 16 and 256.
- Results are `COMPLETE`, `BLOCKED`, `PARTIAL`, or `UNKNOWN`, with hop evidence,
  confidence, age, findings, and RFC 3339 times retained chronologically.
- Semantic driver capabilities cover FDB, VLAN membership, STP, LAG, SVI, VRF,
  routes, ARP/ND, interface policy, and neighbors.
- Cisco NX-OS is distinct from IOS/IOS-XE. Cisco, Aruba AOS-S, Aruba AOS-CX,
  and RUCKUS FastIron support is model/firmware/capability specific.
- Declarative drivers can add read commands and parser identifiers. Writes are
  prohibited. Built-in writes require a certified firmware profile and all
  existing preview, enablement, backup, confirmation, verification, and audit
  gates.

Open gate: accepted fixtures for every advertised semantic capability and one
authorized real multi-hop path covering Layer 2, Layer 3, stale evidence, and a
known blocker.

### 8.5 Beta and Stable

Status: `8.5.0b3` publication candidate. The owner-approved beta refinement
adds reversible manual device lifecycle merges and removes quadratic identity
read behavior; other feature scope remains frozen.

- Command-first, light/monochrome-friendly TUI with profiles, integrations, and
  path views hidden until invoked.
- Redacted support bundles, checksums, CycloneDX SBOM, provenance metadata,
  detached-signature support, rollback guide, and wheel smoke testing.
- Wheel and source distributions include the reproducible WebUI production
  assets; isolated install tests verify console entry points, profiles, static
  asset placement, and the localhost server path.
- Distribution name `netrune`; console commands `netrune` and `netrune`.
- Localhost API/WebUI remains experimental, loopback-only, and single-user.

Stable promotion requires:

1. Clean Linux and WSL2 wheel installs and rollback rehearsal.
2. No unresolved critical/high security or privacy finding.
3. Accepted read fixtures for every advertised family and capability.
4. One authorized Ghoster lab path with reviewed redacted evidence.
5. Profile, XDG, and secret migration/rollback/idempotency rehearsal.
6. Light and monochrome TUI snapshots and WebUI build tests.
7. Registry drift, unit/integration/property/audit tests, dependency review,
   checksums, SBOM, provenance, archive scans, and clean-history scans passing.
8. Executed or fixture-verified documentation examples.

## Post-8.5 Backlog

### 8.6 Telemetry and Event Ingest

- Syslog and SNMP trap channels with backpressure, deduplication, clock-skew
  handling, retention, and source health.
- gNMI capability negotiation, subscriptions, reconnect lifecycle, and schema
  versioning as a dedicated provider family.
- Endpoint agents or approved probes for device-to-core and device-to-Internet
  throughput evidence.
- Scheduled evidence freshness and drift alerts.

### 8.7 Compliance and Simulation

- Declarative configuration compliance without automatic remediation.
- Candidate/pre-state topology simulation for VLAN, STP, LAG, and routing
  effects, clearly separated from observed evidence.
- Backup restore sampling, parser confidence budgets, and approved immutable
  audit export.
- MAC aging, rapid movement, duplicate identity, locally administered address,
  and vendor-block anomaly analysis.

### 9.0 Shared Service

- Authenticated multi-user API identity, authorization, tenant/profile
  boundaries, request limits, secrets broker, and remote-safe deployment.
- Signed/reviewed plugin distribution and process isolation.
- High-availability state and worker design only after single-node event and
  migration semantics are proven.

## Capability Promotion Rules

A read capability moves from experimental or unsupported only when primary
documentation, sanitized firmware fixtures, malformed/empty/rejected/timeout
cases, deterministic profile selection, authorized lab evidence, and explicit
provenance all agree.

A write capability additionally requires typed bounded intent, exact firmware
applicability, preflight, recoverable backup, deterministic commands, rejection
detection, exact post-checks, rollback, immutable actor/reason/ticket evidence,
and out-of-band recovery acceptance.

## Immediate Next Work

The next phase after the 8.5 beta code freeze is verification, not new feature
scope: complete the sanitized firmware fixture corpus, Linux/WSL2 migration and
rollback matrix, Ghoster lab acceptance, dependency/signature review, and clean
public repository rehearsal. Isolated wheel and atomic installer smokes are
implemented and passing locally. After stable promotion, begin 8.6 with the
event-ingest provider lifecycle and endpoint probe contract.
