# Changelog

## 8.5.0b2 - 2026-08-09

### Added

- Guarded `inventory merge`, `inventory merges`, and `inventory unmerge`
  workflows for audited device lifecycle succession. Retired source records
  remain chronological memory, stale rematerialization is suppressed, and
  revocation refuses to overwrite a newly assigned source IP.
- Schema 13 `inventory_merges` state and managed manual-identity relationships.

### Changed

- Public-facing metadata now identifies this release as a public beta, uses the
  publication repository URLs, and recommends isolated `pipx` installation.
- Clean exports use the approved public-source commit subject and disclosure
  body, and public CI scans the complete independent history.
- Privacy checks now inspect filenames/archive paths and reject RFC 1918 IPv4
  literals in addition to scanning text for private identifiers and secrets.
- GitHub Actions now use the current Node 24 action generations for checkout,
  Python/Node setup, and release-artifact upload.
- Identity reconciliation uses indexed evidence candidates instead of
  all-pairs AP/switch comparisons. Derived refreshes reuse one canonical
  snapshot, historical device resolution uses indexed evidence, count queries
  share one SQLite connection, and ingest observations commit in bounded
  batches.
- Successful materializing ingest commands now synchronize canonical identity,
  health, and relationship state before reporting completion.
- Bulk inventory activity uses one canonical snapshot and a bounded worker pool
  for independent reachability probes.

### Performance

- On the migration acceptance dataset, `inventory show --limit 1` improved from
  9.83 seconds to 0.28 seconds, and local device-support resolution improved
  from 2.71 seconds to 0.44 seconds. Representative AP, health, memory, and
  database reads complete below 0.5 seconds on the same host.

### Fixed

- The WebUI lockfile now resolves patched PostCSS and Nano ID releases, and CI
  rejects future high or critical npm advisory findings.
- Release CI explicitly retains the hidden checksum, SBOM, and provenance
  directory in its downloadable artifact.
- Device SSH now requires and validates a profile SSH username before opening
  the vault, passes login and host as separate OpenSSH arguments, and preserves
  `ssh_user` through profile migration and shell configuration writes.
- `diagnose speed --profile` remains a speed-test option instead of being
  consumed as a one-shot NetOps state-profile selector; diagnostic `--source`
  aliases now reach core-ping and throughput handlers.
- All supported registry actions now reach concrete command mappings. Vault
  status, IEEE MAC registry/online lookup, device support, and device identity
  no longer degrade to an unknown registry action.
- Unknown plugin enable/disable requests return validation errors instead of
  internal failures, and plugin changes honor dry-run previews.
- Every advertised `netops-control` mode now has working command-specific help,
  including backup history, diff, and MAC lookup.
- Driver command-stream separators are consumed explicitly so shell control,
  backup, and MAC lookup workflows behave consistently on Python 3.11 through
  3.14.
- CI provisions the Expect runtime used by prompt-aware SSH tests, and the real
  GPG round-trip verifies the current named `ssh/default/password` store rather
  than the retired legacy vault path.

## 8.5.0b1 - 2026-08-08

Public-beta foundation and feature-scope freeze. Later beta builds may fix
defects and evidence gaps but do not add new 8.5 scope.

### Added

- Neutral XDG profiles with one-shot selection, active-profile management,
  configuration precedence, isolated state, and idempotent legacy migration.
- Sudo/PAM-gated named encrypted secrets and `vault:`, `env:`, and private
  `file:` references; SSH vault commands map to `ssh/default/password`.
- Versioned observation, ingest-run, plugin, device-driver, capability-evidence,
  and path-inspection contracts plus schema 12 chronological tables.
- Declarative CSV, JSON, JSONL, HTTPS JSON, stdin NDJSON, fixture-gated SNMPv3,
  and stable read-only NetBox ingest channels with field provenance,
  deduplication, sparse-update safety, and redacted quarantine.
- Disabled-by-default trusted Python entry-point plugins with API/version/source
  validation, failure isolation, collision checks, and write rejection.
- `netops path inspect` and `netops ghoster` bounded hybrid L2/L3 endpoint path
  inspection with persisted hops, findings, confidence, age, and timestamps.
- Semantic FDB, VLAN, STP, LAG, SVI, VRF, route, ARP/ND, policy, and neighbor
  capabilities; Cisco NX-OS is separate from IOS/IOS-XE.
- Redacted support bundles, privacy/history/archive scans, clean public-export
  tooling, SHA-256 checksums, CycloneDX SBOM, provenance, and detached signing.
- Registry-generated Markdown and JSON references, `netops(1)`, and Bash, Zsh,
  and Fish completions with CI drift checks.
- Clean Linux/WSL2 installation, isolated-wheel smoke tests, profile/channel/
  driver examples, Apache-2.0, and publication governance documents.

### Changed

- Defaults are profile-driven and contain no site aliases, address shorthand,
  organization prefix removal, WLC filters, plaintext credentials, or cloud
  synchronization settings.
- Device writes require explicit profile enablement and a certified built-in
  firmware profile in addition to preview, backup, confirmation, verification,
  and audit gates. External/declarative drivers are read-only.
- The TUI remains command-first and uncluttered; profiles, channels, plugins,
  evidence, and path results appear only when invoked.
- Public examples use RFC 5737 addresses, `.example` domains, generic device
  names, and locally administered synthetic MACs.

### Fixed

- Legacy profile migration now recovers from a schema-only destination created
  during startup. It validates source and destination databases, backs up the
  empty destination, performs an atomic SQLite copy, and still refuses to
  overwrite any profile containing operator or history rows.

### Security and Privacy

- Removed the bundled third-party UI guide and local AI operator-run history
  from the distributable tree.
- Added literal-secret, private-key, token, personal-path, denied-identifier,
  archive, and clean-history publication gates.
- Plugins cannot declare shell or write capabilities; HTTP ingest requires TLS
  except for loopback fixtures, and TLS verification cannot be disabled.
- Support bundles exclude inventory, raw evidence, aliases, known hosts,
  secrets, and backups and still require operator review before sharing.

### Verification Status

- The complete automated suite, generated-reference check, source/archive
  privacy scans, WebUI production build, wheel/sdist metadata checks, isolated
  wheel HTTP smoke, and atomic install/rollback/uninstall smoke pass locally.
- The project dependency graph has no known vulnerabilities in the release
  audit, and generated SHA-256, CycloneDX, and provenance files pass privacy
  inspection.
- A neutral one-commit public-export rehearsal passes full-history scanning,
  has no remote, and retains tracked compiled WebUI assets. The durable public
  repository must still be produced from the reviewed tracked source set.
- Stable promotion remains blocked on accepted firmware read fixtures, one
  authorized real Ghoster path, Linux/WSL2 migration rollback rehearsal, and
  publication approval.

### Next

- Complete external beta evidence and produce the durable one-commit public
  repository from reviewed tracked files. No new features enter the 8.5 line
  before stable promotion.

## 8.1.0 - 2026-08-08

Device compatibility, identity, and inventory-ingest release.

### Added

- Extensible device-family registry with explicit Cisco IOS, Aruba AOS-S,
  Aruba AOS-CX, RUCKUS FastIron, SmartZone/AP, and fail-closed unknown drivers.
- Public `device support` capability reports and `device identity` evidence
  reports for hostname-change review.
- Direct `lookup mac online` and registry lifecycle commands backed by the
  official IEEE MA-L, MA-M, and MA-S public listings, with a private validated
  cache, longest-prefix matching, stale fallback, and provenance.
- Multi-root, multi-VLAN locate and propagation matrices with repeated
  `--target`/`--vlan` input, ranges, bounded per-cell traversal, and live
  progress that remains separate from final output.
- Vendor-neutral ARP, forwarding-table, interface, LLDP, ping, interface-health,
  and cable command plans, plus AOS-CX and FastIron parser coverage.
- Three-day SSH-password lifecycle estimates, ISO 8601 expiry windows, and
  replacement guidance derived from a successful `connect -p` vault write.
- Device support and extension guide plus an ordered operations-maturity
  roadmap with evidence-based support promotion gates.

### Changed

- Discovery now passes observations through one normalized ingest boundary;
  current status and poll time update without sparse ICMP/SNMP results erasing
  trusted hostname, platform, model, serial, or MAC data.
- Corroborated hostname changes update the canonical display name while
  preserving old names as chronological aliases. Candidate name thresholds are
  85 percent for APs and 75 percent for switches, but names alone never merge
  conflicting physical identities.
- Core lookup selects semantic commands from the detected device family rather
  than assuming Cisco syntax.
- Legacy SSH compatibility filters server-advertised KEX, host-key, cipher, and
  MAC algorithms and applies the same bounded options to generic and
  prompt-aware transports. SSH protocol 1 remains unsupported.

### Security

- Aruba and RUCKUS configuration and VLAN writes fail before transport until
  model/firmware fixtures, exact verification, rollback, and authorized lab
  acceptance satisfy the write promotion gate.
- IEEE registry downloads enforce HTTPS, response-size and schema checks,
  SHA-256 metadata, private permissions, and atomic replacement.
- Placeholder identity fields and conflicting valid MAC/serial/asset evidence
  cannot silently collapse separate devices.

### Verification

- 167 automated tests pass; one real-GPG round-trip test is skipped only when
  the restricted runner cannot create the GPG Agent socket.
- An 8.1.0 wheel builds and installs in an isolated virtual environment; its
  public CLI and packaged shell-to-Python driver/ingest resolution smoke tests
  pass outside the source tree.
- Synthetic Cisco, Aruba, and RUCKUS parser fixtures cover family detection,
  ARP/MAC/interface parsing, command selection, unsupported writes, ingest
  retention, identity aliases, and legacy SSH option propagation.
- Real firmware acceptance and production writes remain controlled lab tasks;
  the support report labels this boundary explicitly.

### Next

- Build the sanitized model/firmware fixture corpus and select capability
  profiles from evidence, beginning with representative IOS-XE, AOS-S, AOS-CX,
  FastIron 08.0.95, 09.0.10, and 10.0.20 devices.

## 8.0.0 - 2026-08-02

Major operator-console and application-platform release. Existing noun-first
CLI commands remain available; an interactive no-argument invocation now opens
the local terminal console.

### Added

- Responsive Textual console with Overview, Inventory, Topology/VLAN,
  Diagnostics, Operations, History/Audit, and Settings views.
- Command-first Action Hub startup with a four-column searchable catalog,
  on-demand Functions chooser, collapsible result details, and a closed-by-
  default Inspector/Activity drawer.
- Shared `ResultEnvelopeV1`, dataset/column, finding, provenance, action
  preview, operator context, query, and job event contracts.
- One sortable/filterable/exportable result workbench with topology, findings,
  evidence, raw payload, inspector, and live Activity views.
- Registry-generated forms across 95 actions, command palette discovery,
  contextual device actions, private preferences, dark/light/monochrome states,
  and deterministic wide/compact/narrow layouts.
- Structured job results, actor/reason/ticket context, phase/progress events,
  partial terminal state, rerun review, and active-job exit handling.
- Managed SSH host-key status, scan, SHA-256-bound enrollment, forget, strict
  and accept-new policies, private atomic known-hosts storage, and audit events.
- Guarded VLAN job lifecycle with exact preview binding, typed confirmation,
  preflight, required backup, apply, read-back verification, audit, and manual
  rollback evidence.
- Exact post-change checks for access and up-to-eight-VLAN trunk requests;
  larger trunk sets are boundary-sampled and can only finish partial/attention.
- v8 architecture, operator-console, UI design-system, migration, and accepted
  decision documentation.
- PEP 517 packaging, `uv` lockfile, installed `netops` entry point, and packaged
  TCSS assets.
- Installed `netop` alias for the explicit `netop tui` launch form.
- Public `netops vault status|set|migrate|unlock` lifecycle with chronological,
  non-prompting status and a one-time legacy-vault migration.

### Changed

- Root `netops` opens the TUI only for capable interactive terminals;
  `--no-tui`, `--plain`, explicit CLI commands, and non-TTY use remain
  headless.
- Workflows use typed manifests with per-step stop/continue policy, live events,
  child structured output, and one final success/partial/failure matrix.
- Local view loading and job polling use bounded async UI workers, avoiding
  default-executor shutdown defects observed under Python 3.14.
- Human-facing history, results, jobs, and audit surfaces consistently expose
  ISO 8601 UTC recording times and freshness.
- TUI theme defaults to grayscale automatic light/dark detection with a light
  fallback; `NO_COLOR` forces neutral mode and colored themes are opt-in.
- SQLite schema advances from 10 to 11 for structured job and audit metadata.
- New SSH-password vault writes default to terminal sudo-gated GPG. Existing
  legacy vaults remain readable through terminal-only loopback until migrated.

### Fixed

- Source-linked `netops tui` and `netop tui` now hand off automatically from a
  system Python without Textual to the synchronized sibling `.venv`; TUI package
  imports are lazy and non-interactive requests fail before SQLite startup.
- Vault migration accepts inherited terminal input when the interactive helper
  runs in a detached process session, without exposing entered secrets.
- Root-key validation supports namespaced privileged UID mappings such as
  `65534` while still requiring a matching protected-directory owner, a private
  `0700` key directory, and a regular `0400` or `0600` key file.
- Root-key metadata parsing normalizes carriage returns emitted by sudo's
  pseudo-terminal policy, preventing valid WSL keys from being rejected as an
  unknown file type.
- Vault status and unlock prompts identify Windows Hello when
  `pam_wsl_hello.so` is configured in sudo's PAM stack.
- Vault actions retain the foreground controlling terminal so tty-scoped
  Windows Hello/sudo authorization remains valid for subsequent root-key reads;
  other isolated interactive workflows keep their existing process handling.
- Interactive SSH now uses the same foreground terminal path as vault actions,
  and vault decryption validates and reads the root key within one authenticated
  sudo broker process. This prevents tty-scoped PAM authorization from being
  lost between authentication, metadata validation, and key access.

### Security

- Direct `netops-control config` and `vlan` execution fail unless invoked through
  the core's process-local audited-confirmation capability.
- Generic and prompt-aware SSH paths share managed host-key policy; changed
  keys fail closed.
- Break-glass SSH requires an explicit one-process acknowledgement and warns.
- Action submission re-previews normalized intent and rejects changed hashes,
  missing reasons/tickets, and mismatched typed confirmation.
- Sudo-gated vaults use a root-only random per-user key, never store or pass the
  sudo password, force GPG loopback mode, and preserve the previous vault when
  encryption fails.

### Verification

- 141 automated unit, parser, workflow, subprocess lifecycle, v8 service, and
  Textual interaction tests pass.
- Headless contract tests cover registry completeness, private preferences, SSH
  trust, guarded VLAN phases, workflow summaries, job result adaptation, and
  side-effect-free TUI help.
- Textual tests mount without transport I/O at 160x48, 120x36, and 80x24 and
  exercise generated guarded forms and persisted theme preferences.
- Shell lifecycle fixtures cover managed known-host options, break-glass gating,
  denied direct helper writes, cached sudo authentication, terminal-only legacy
  migration, versioned vault framing, and atomic encryption failure handling.
- Production switch writes, real firmware matrices, live Internet transfer, and
  controlled endpoint/core throughput remain authorized lab acceptance tasks.

### Next

- Run a controlled field pilot against representative Cisco and Aruba firmware,
  establish strict host-key enrollment coverage, and retain sanitized fixtures.
- Add complete or explicitly partial verification semantics for large trunk
  VLAN lists, complete-scan topology removal gates, and authenticated API
  identity before any non-loopback deployment.

## 7.3.0 - 2026-07-31

Stability and diagnostic-efficiency release for the backend, core CLI/TUI, and
shell adapters. The WebUI is intentionally outside this release scope.

### Changed

- Internet speed profiles now reuse one verified, server-pinned client session
  for sequential upload and download. This removes duplicate setup work while
  retaining separate loaded-latency sampling for each direction.
- Speed-server discovery is cached by routed path and can be reused across
  profiles when the cached candidate set is sufficient. Transfer traffic is
  always fresh; `NETOPS_SPEED_CACHE_TTL_SECONDS=0` disables discovery caching.
- `quick` remains the one-server, medium-confidence operator profile;
  `balanced` compares two servers by default; `thorough` uses three.
- Root help and `--version` return before SQLite/runtime initialization. Public
  and compatibility launchers read the central `VERSION` file.
- Direct control input now validates read-only commands, interfaces, VLAN IDs
  and ranges, option cardinality, and MAC syntax before transport access.
- Remote SSH-vault synchronization is disabled. Credentials remain in the
  local GPG vault unless a separately reviewed secret-manager adapter is added.

### Fixed

- Process-group and descendant cleanup across core subprocesses, latency,
  speed, connect, control, jobs, discovery, and prompt-aware SSH paths.
- Interrupted latency no longer offers the post-run SSH handoff.
- Duplicate speed helper setup, missing loaded-latency coverage metadata, and
  silent JSON-render failures.
- Core-origin ping parsing for Cisco reply marks and usable reports returned by
  wrappers with nonzero aggregate status.
- VLAN cascades accepting usable per-switch reports, excluding endpoint
  neighbors, suppressing cycles, and traversing all discovered switch links
  within the requested depth/node budget.
- Port-health baseline handling, counter-delta timing, interface identity,
  counter wrap, and full-duplex utilization reporting.
- Cable TDR prechecks, accepted/rejected start classification, unsupported
  status, and parsed-result handling.
- `iperf3` results can no longer report success when the process failed.
- Exact inventory lookup, SNMPv3/SSH argument arrays, target validation,
  discovery bounds/atomic updates, and private runtime cleanup.
- Backup metadata honors path overrides; backup files use safe names, private
  staged writes, atomic replacement, and stable unchanged-history paths.
- Vault writes preserve the previous encrypted file when encryption fails.

### Verification

- 113 automated unit, parser, workflow, and subprocess lifecycle tests pass.
- Python sources compile and Bash entry points pass syntax validation.
- Fixture tests cover direct-PID cancellation and prove descendant processes
  and private runtime directories are removed.
- A live Internet transfer and production-device read/write test are not part
  of automated release verification and require an authorized environment.

### Next

- Add representative recorded-output fixtures for every supported switch
  firmware family, then run authorized lab validation for core ping, VLAN
  cascade, cable status/TDR, controlled `iperf3`, and quick Internet speed.
- Add managed SSH host-key enrollment and authenticated operator identity
  before expanding remote or write-capable deployment.
