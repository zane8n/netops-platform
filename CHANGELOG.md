# Changelog

## Unreleased

### Added

- Real terminal output. `rich` has been a declared dependency since the
  Textual console (ADR 0001, superseded 2026-08-15) but nothing has
  imported it since -- every table was hand-rolled fixed-width text. Tables
  (`render_table`, used at ~85 call sites across every domain), key/value
  payloads, path findings, usage errors, and `netrune help` now render with
  bold section headers and semantic color: a status word
  (`ONLINE`/`PASS`/`SUCCESS`, `OFFLINE`/`FAIL`/`ERROR`/`BLOCKED`,
  `WARN`/`PARTIAL`/`ATTENTION`, ...) is colored consistently wherever it
  appears in a cell, not just in a column literally named `status`. No box
  borders -- a header rule and clean column alignment, matching the
  plain-text table's own look rather than a heavier boxed style. A value
  longer than its column truncates with `...` the same way the plain
  fallback always has, rather than growing the row; every column is sized
  to its own content up front (capped, same as plain) rather than letting
  rich's own fit-to-terminal squeeze negotiate column widths, which turned
  out to starve short columns (`IP`, `STATUS`) toward nothing whenever one
  long column (`NAME`, a diagnose doctor `DETAIL`) was also on the row.
- `netrune device ssh <query>` picks interactively when the query is
  ambiguous. Previously an ambiguous target just got passed straight
  through to the SSH helper as typed text, which the helper then had to
  fail on its own. In a real terminal it now lists the matching devices and
  reads arrow keys (`↑`/`↓` to move, Enter to connect, `q`/Esc/Ctrl+C to
  cancel) directly off the tty in cbreak mode, with no new dependency.
  Non-interactive runs (piped, `--json`, `--plain`, no tty) are completely
  unaffected -- same pass-through-as-typed behavior as before.
- This only ever fires for an interactive, color-capable terminal.
  Everything piped, redirected, or run under `--json` takes the exact
  hand-rolled plain-text path this file always had -- unchanged byte for
  byte, which is also why the full test suite needed zero changes (pytest's
  captured stdout is never a tty). `--plain` now actually does something:
  it previously parsed into `opts.plain` and went nowhere, so it was
  indistinguishable from the default. It now suppresses color the same way
  `--no-color` already did, making both flags real, working escape hatches
  rather than one silently inert one. Color decisions check `stdout` and
  `stderr` independently, so redirecting one while the other stays a
  terminal (`command 2>error.log`) can't leak ANSI codes into the log.
- `netrune ai --ollama-select` now actually lets the model select. The
  Modelfile moves from `qwen2.5-coder:7b` (a code fine-tune) to `qwen3:8b`;
  its hybrid "thinking" phase is always disabled for this tool's tasks
  (tool routing, grounded summarization), measured ~20x faster with no
  accuracy loss (64.5s -> 2.9s on a trivial prompt; correct, grounded
  answers confirmed on both tool selection and `--model-summary`
  rewording). Separately, and regardless of model: `choose_workflow()`
  always returns a workflow name -- it has to, the zero-model fast path has
  no fallback -- so narrowing the model to exactly that one tool schema on
  every `--ollama-select` call meant the deterministic router had already
  decided before the model ever saw the question. Only the three workflows
  that read a live device directly (`get_down_interfaces`,
  `get_interface_summary`, `get_vlan_summary`) still get pre-decided, since
  that's a safety-relevant distinction model judgment shouldn't own;
  everything else -- AP/health/topology/memory/relationship lookups and the
  broad Ask center -- now reaches the model as real choices among the full
  approved tool set. Verified live against Ollama end to end, not just
  unit-tested: a broad question now correctly picks the specific matching
  tool (e.g. `get_aps_on_switch`) instead of always landing on the generic
  `answer_from_netrune_state` catch-all. The default timeout moves from 60s
  to 180s (a single full-schema round measured 55-80s on non-GPU-accelerated
  hardware; 60s had no headroom at all) and the default `keep_alive` from
  `0` to `5m`, so one multi-round `--model-summary` conversation -- and a
  back-to-back session of separate questions -- doesn't re-pay a ~20s model
  load on every round.

### Removed

- The `jobs` domain, end to end: `netrune jobs list/show/cancel`, their
  registry entries, help topics, and completions, and the background-thread
  job runner (`create_job`/`run_job`/`cancel_job`/`shutdown_jobs`) and
  `ui_options` behind them. This was live infrastructure for the removed
  WebUI/API console -- jobs created via an HTTP request, checked via a later
  request to the same long-running server. Nothing in the CLI-only
  architecture ever created one: `create_job` had no caller outside tests, so
  the `jobs` table was permanently empty on every real install and
  `jobs list/show/cancel` were permanent dead ends. `commands run` (the
  synchronous public path) and audit events are unaffected; ADR 0006 and ADR
  0002 are annotated with what changed and why. Five more zero-caller
  payload/UI-form methods from the same era went with it
  (`inventory_detail_payload`, `memory_query_payload`,
  `topology_graph_payload`, `automation_payload`, `local_readiness_payload`).
- `inventory show`, `topology neighbors`, and `jobs logs` were pure aliases of
  `inventory list`, `topology show`, and `jobs show` -- same handler, same
  output, a second registry entry, help topic, and completion for zero added
  capability. Beta compatibility does not extend to a spelling that never did
  anything the canonical one didn't.

### Fixed

- `netrune device config --confirm` now goes through the same guarded
  lifecycle `vlan set` already had: a changed-only backup before the push, a
  second one after to prove the running configuration actually changed rather
  than assuming it from a clean exit code, and an audit event either way.
  Arbitrary config commands were the more dangerous of the two and had the
  thinner guardrail.
- `secrets delete` now previews the named secret and records an audit event
  on completion, matching `inventory forget`'s shape. It previously required
  `--confirm` but showed nothing first and audited nothing after.
- A confirmed non-loopback VictoriaMetrics bind (`--accept-push`) generated a
  systemd unit, compose service, and "run it by hand" snippet with no
  authentication at all -- not just on the push path, on the full
  query/import/admin API. A kept-across-regeneration token now gates it via
  `-httpAuth.username`/`-httpAuth.password`, surfaced as a ready-to-paste
  authenticated push URL; `traffic push` sends it as a Basic Auth header
  rather than relying on urllib to do something with `user:pass@host` on its
  own, which it does not.
- `netrune jobs cancel`'s help text described cancelling jobs "running inside
  the current serve process" -- `serve` has been gone since the WebUI/TUI
  removal. The job-creation and background-thread machinery it refers to is
  not reachable from any current CLI path either; `jobs list/show/cancel`
  read a `jobs` table nothing in this release ever writes to outside tests.
- `RETENTION_DEFAULTS` covered 8 tables; the other dozen or so operational and
  diagnostic tables (`command_history`, `backup_history`, `speed_tests`,
  `scan_runs`, and friends) had no entry at all and grew without bound on a
  long-running install. `netrune db prune` now covers them, at windows suited
  to what each one is for. `observations`, `observation_fields`,
  `inventory_merges`, and `relationships_current` stay unpruned on purpose --
  they're provenance and current state, not diagnostic noise, the same
  reasoning that already kept `audit_events` off this list.
- Support bundles accumulated one file per `netrune support bundle`
  invocation forever. The default directory now keeps the newest 10; an
  explicit custom output path is never touched.

### Changed

- `diagnose port-health`, `lookup mac-profile`, and switch neighbor discovery
  (LLDP/CDP) authenticated once per show command against the same device --
  two to six SSH logins for what is conceptually one read. They now use the
  same one-login-per-device `show-batch` mechanism already used elsewhere in
  the file. Neighbor discovery runs once per switch in a topology scan, so
  this is the difference between one login per switch and one per switch per
  protocol.
- `core.py`'s `App` class held roughly 7,200 of the file's ~10,090 lines
  across all ~23 command domains in one place. The device, inventory, vlan,
  topology, lookup, and diagnose domains now live in their own modules
  (`device_cli.py`, `inventory_cli.py`, `vlan_cli.py`, `topology_cli.py`,
  `lookup_cli.py`, `diagnose_cli.py`) as mixin classes `App` composes
  together, chosen over free functions because several of these domains are
  called into from other parts of the class (`command_for_action` calling
  `vlan_change_request` directly, for one) rather than through a single
  entry point -- `self.foo(...)` resolves the same via MRO regardless of
  which file defines it, so no call site needed to change. Helpers shared
  across two or more of these domains, or with code outside them entirely,
  stay in `core.py`. No behavior changes; `core.py` is down to 6,458 lines.
- The `ask`, `setup`, and `path` domains move out of `core.py` too
  (`ask_cli.py`, `setup_cli.py`, `path_cli.py`), as free functions rather
  than mixins since none of the three are called into from elsewhere in the
  class. `ask_payload`, `execute_ask_plan`, and `write_snmp_community` keep
  public names with matching 2-line delegate methods on `App`, since tests
  call them directly as `self.app.ask_payload(...)` and friends; everything
  else with no such external caller becomes a private module-level
  function. `State`, the SQLite persistence layer sitting next to `App`,
  was investigated as a further decomposition candidate and rejected: one
  shared schema script for every table, one shared connection lifecycle,
  and an atomic cross-table reconciliation pass (`sync_derived_state`) mean
  there's no seam to split it along without either breaking that atomicity
  or just relocating today's coupling into new files. No behavior changes;
  `core.py` is down to 6,016 lines.

### Fixed

- An abbreviated address is an address again. The shell resolver has always
  completed `7.71` against the profile's prefix; Python did not, and treated the
  same text as a digit fragment that could match any address containing it --
  including a *former* address of a different device. Two resolvers disagreeing
  about what an operator typed is how a command lands on hardware nobody chose.
  Fragments like `4.7` matched twenty devices and now match none.
- `device ssh` says so when it connects to an address other than the one typed.
  A switch that moved is still the right switch, but silent substitution is
  indistinguishable from reaching the wrong box.

### Added

- `netrune inventory forget <target>` drops a device's inventory and derived
  state so the next scan adopts it from what it reports now. A name recorded
  wrong is inherited by every later sighting, and there was no way out short of
  editing the database. Every address the device has answered on is forgotten
  together, so the halves cannot merge back. Backups, audit events, and traffic
  history are untouched; `--with-names` also drops the naming history, which is
  right when the name was the mistake and wrong when the device merely moved.
- A Netrune / Overview dashboard: five state tiles -- last reading, links down,
  busiest link, unreachable targets, interfaces being collected -- over two
  charts bounded with `topk`. An overview drawing every watched interface is
  more lines than a chart can keep apart, so it draws the five that matter.
- `netrune traffic stack up|down|restart|status|install` drive the generated
  units. Copying unit files and remembering the systemctl incantation is the
  part people skip, and a stack that is never started is one that was never
  generated. `status` reports units that differ from the generated copy.
- Grafana runs natively when its binary is on the machine, and in a container
  only when it is not. A container runtime on a laptop is a thing that gets
  closed, and when it stops the dashboards stop while the rest of the stack
  keeps running.

### Changed

- Traffic history is kept for 180 days rather than 30, and the window is
  configurable with `traffic_retention_days`. A link that saturates at month-end
  needs more than a month of history to show it, and a sample is a few hundred
  bytes.
- Switching graphers retires the previous one's unit instead of leaving it on
  disk for something to start later.

- A workflow step that reports findings is no longer counted as a failure.
  `health attention` exits PARTIAL exactly when it has something to show, which
  is the reason to run it, so "Build attention queue" appeared as FAILED on every
  healthy morning. Steps now report SUCCESS, ATTENTION, or FAILED, `on_failure`
  reacts only to real failures, and the summary counts them separately.

### Changed

- `workflow morning-check` refreshes LLDP/CDP topology before reviewing changes.
  It reviewed recorded changes without ever scanning, so the morning read
  yesterday's picture. The scan runs after the reachability check so it has a
  fresh status to skip offline devices by.

- Any job spanning more than one device now skips devices the last sweep
  recorded offline, and names them. Each one costs a full SSH timeout -- about
  five seconds -- so a sweep paid that for every unreachable device before doing
  any work. Backup already did this; every other mode now does too, through one
  implementation rather than a second copy of the rule.
- `--online-only` does what its name says. It was accepted and ignored.
- `--include-offline` attempts everything, for a sweep meant to find what has
  recovered. A device named on its own is still always attempted, and a device
  absent from the inventory is treated as unknown rather than unreachable.

### Added

- Remote pollers. `scripts/poller-install.sh` turns a Debian-family box into a
  collector on the monitored network, reachable over Tailscale; `netrune traffic
  pull` merges its readings into this machine's store, and `netrune traffic
  remote` runs any traffic command on it over SSH. Nothing new listens: control
  rides SSH, and the poller's exposition is the one it already had.
- `netrune traffic export` prints a collector's stored readings as JSONL. Rows
  rather than scraped metrics, because scraping returns rates already computed
  and the counters behind them were never retained.
- Watches carry the collector that polls them. A pulled interface is never
  polled locally, never republished by the local exposition, and is named with
  its collector wherever it appears next to a local one.
- Readings are keyed by collector, watch, metric, and second, so a pull retried
  over an overlapping window after a dropped connection absorbs the overlap
  rather than storing it twice.
- `stack init` refuses a non-loopback bind without `--confirm`, and carries that
  consent into the generated unit. A service cannot answer a prompt at start
  time, and deriving consent from the address would have let `--bind 0.0.0.0`
  publish the exposition with nobody having agreed to it.

### Added (earlier in this cycle)

- The grapher is now pluggable. Dashboards are defined once as a neutral model
  of panels, queries, semantic units, and variables, and adapters render that
  into Grafana JSON, Perses resources, or nothing at all. `--grapher` selects
  one; `netrune traffic stack graphers` lists them. Grafana is the default.
  `scrape.yml`, `alerts.yml`, and every non-grapher unit are byte-identical
  whichever is chosen, which is what makes the choice reversible.
- A third dashboard, Collector, showing whether collection is actually
  happening. A stopped collector leaves flat lines rather than empty ones,
  because the exposition keeps serving its last reading.
- `netrune traffic verify` walks the pipeline link by link -- watchlist,
  collector, exposition, storage, scraping, rate derivation, grapher -- in the
  order data flows, so the first failure is the cause rather than a symptom.
- Adapters declare the storage URL from their own vantage point. Grafana
  proxies queries from its own process, so its datasource resolves
  `host.docker.internal` inside the container; Perses has the browser fetch
  directly, so it keeps the host address. Getting this backwards produces a
  dashboard that loads and shows nothing.

### Added (earlier in this cycle)

- A metrics pipeline built on raw counters. `netrune traffic exporter` publishes
  every collected reading as Prometheus exposition on loopback; VictoriaMetrics
  scrapes it and owns retention and querying; vmalert owns alerting; Perses owns
  dashboards. Netrune publishes `ifHCInOctets`, `ifHCOutOctets`, errors,
  discards, link speed, and operational and administrative status raw and
  monotonic, and never a rate: MetricsQL derives rates at query time, which also
  makes counter resets handle themselves.
- `netrune traffic stack init` generates the whole stack from the watchlist —
  scrape config, vmalert rules, Perses project, datasource, and two dashboards
  scoped to throughput, utilisation, errors, and interface status, plus a compose
  file. The scrape interval is derived from the shortest watch interval so
  scraping cannot outrun collection.
- `netrune traffic backfill` imports history collected before the stack existed.
  Stored rates are published as `netrune_history_*` gauges rather than
  reconstructed into counters, because integrating a rate would fabricate
  readings nobody took.
- `netrune traffic pause`, `resume`, `interval`, and `status`. Each accepts a
  watch id, a device, or an interface name and acts on everything that matches,
  so pausing a switch pauses its ports and pausing `Gi1/1/1` reaches that port on
  every switch. The collector re-reads the watchlist every tick, so changes take
  effect without restarting it.
- `netrune traffic watch` accepts a comma-separated list of interfaces and
  resolves the batch in one SNMP walk.
- Interface errors, discards, and administrative status are now collected.
  Operational and administrative status are separate metrics: down while
  administratively up is a fault, and both down is somebody's decision.

### Removed

- The full-screen Textual console, the headless application service that existed
  to feed it, the preference store, the Textual dependency, and the launcher's
  managed-runtime handoff. Every operator interface is now the CLI.

### Changed

- The per-device SNMP read is one batched request for every OID rather than one
  request per OID: ten OIDs per interface became one round trip per device.

### Added (earlier in this cycle)

- `netrune traffic`: a watchlist-driven monitoring domain. `traffic watch`
  records interface throughput over SNMP IF-MIB, `traffic ping` records
  round-trip time and loss from this host, and only named targets are ever
  polled. `traffic poll` collects one round, `traffic daemon` collects
  continuously with each target on its own interval, `traffic show` renders
  terminal sparklines, and `traffic report` writes a self-contained HTML page
  with charts and no external assets or scripts.
- Traffic samples and counter baselines are stamped with the collector that
  took them, so a remote poller and a laptop can write to the same history
  without corrupting each other's rate arithmetic.
- `App.icmp_probe` measures reachability from the collector host, and the SNMP
  helper now reports `ifName` alongside each counter read so a reassigned
  ifIndex is re-resolved rather than silently graphed as the same port.

### Changed

- The loopback HTTP server, JSON API, server-sent event job stream, and Vue
  browser console were removed, along with their compiled assets and the
  `netrune serve` command. Every interface is now a local process: the CLI
  and the traffic collector. `--json` remains the supported machine-readable
  surface.
- SNMP helper modes no longer open the SSH vault, so an unattended collector
  never prompts for Windows Hello or sudo. A recent SNMPv2c success on a host
  now suppresses a blocked SNMPv3 attempt for 24 hours instead of paying its
  timeout on every round.
- `--since` accepts a duration such as `15m`, `6h`, or `2d` as well as a plain
  number of seconds.

## 8.5.0b3 - 2026-08-09

### Added

- Canonical `netrune` distribution, console, Python API, `NETRUNE_*`
  environment prefix, `netrune.*` plugin groups, helper launchers, generated
  references, installation paths, and product identity.
- One-time non-destructive XDG state migration from the former application
  roots. SQLite state is copied with the backup API, including committed WAL
  data, validated, renamed to `netrune.sqlite3`, and recorded in a migration
  manifest while source files remain unchanged.
- Targeted vendor-driver forwarding-table and LLDP/CDP walk for device-to-core
  MAC paths, plus conservative core SVI parsing for Cisco, Aruba, and RUCKUS
  output.

### Changed

- Path hops are displayed from the endpoint-facing switch toward the core,
  with ingress/egress interfaces aligned to packet direction.
- `path history` accepts `--vlan` and prints reusable compact run references.
  `path show` accepts a full ID, unique prefix, endpoint plus VLAN, `last`, and
  the `hshow` compatibility alias.
- `netops`, `netop`, `NETOPS_*`, `netops_platform`, and `netops.*` plugins
  remain supported through the v8 compatibility window; canonical Netrune
  settings take precedence.

### Fixed

- Fresh live forwarding evidence now supersedes stale cached endpoint
  attachment evidence, preventing a core trunk MAC entry from being reported
  as the endpoint edge port.
- Cisco IOS MAC inspection uses an address query before its case-sensitive
  output-filter fallback. Known attachment evidence from another VLAN is
  rejected rather than presented as a path on the requested VLAN.
- Incomplete live forwarding walks retain every verified switch hop instead of
  collapsing to a shorter stale cache path, and a failed transport is not
  retried immediately for the same hop's VLAN inspection.
- Trunk VLAN validation now checks both sides of every discovered switch link,
  and an unparsed Layer 3 state is reported as unknown instead of inferred.
- SVI parsing accepts transport-prefixed output and no longer mistakes
  interface text such as `Keepalive not supported` for an unsupported command.

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
  consumed as a one-shot Netrune state-profile selector; diagnostic `--source`
  aliases now reach core-ping and throughput handlers.
- All supported registry actions now reach concrete command mappings. Vault
  status, IEEE MAC registry/online lookup, device support, and device identity
  no longer degrade to an unknown registry action.
- Unknown plugin enable/disable requests return validation errors instead of
  internal failures, and plugin changes honor dry-run previews.
- Every advertised `netrune-control` mode now has working command-specific help,
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
- `netrune path inspect` and `netrune ghoster` bounded hybrid L2/L3 endpoint path
  inspection with persisted hops, findings, confidence, age, and timestamps.
- Semantic FDB, VLAN, STP, LAG, SVI, VRF, route, ARP/ND, policy, and neighbor
  capabilities; Cisco NX-OS is separate from IOS/IOS-XE.
- Redacted support bundles, privacy/history/archive scans, clean public-export
  tooling, SHA-256 checksums, CycloneDX SBOM, provenance, and detached signing.
- Registry-generated Markdown and JSON references, `netrune(1)`, and Bash, Zsh,
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
- PEP 517 packaging, `uv` lockfile, installed `netrune` entry point, and packaged
  TCSS assets.
- Installed `netrune` alias for the explicit `netrune tui` launch form.
- Public `netrune vault status|set|migrate|unlock` lifecycle with chronological,
  non-prompting status and a one-time legacy-vault migration.

### Changed

- Root `netrune` opens the TUI only for capable interactive terminals;
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

- Source-linked `netrune tui` and `netrune tui open` now hand off automatically from a
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

- Direct `netrune-control config` and `vlan` execution fail unless invoked through
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
  always fresh; `NETRUNE_SPEED_CACHE_TTL_SECONDS=0` disables discovery caching.
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
