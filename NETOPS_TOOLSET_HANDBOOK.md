# NetOps Toolset Operator and Maintainer Handbook

**Zero-to-expert guide for NetOps Platform v8.5.0b2**

**Audit date:** 2026-08-08
**Last revised:** 2026-08-08
**Audited source:** `$HOME/src/netops-platform`
**SQLite schema:** version 12
**Audience:** new operators, senior network engineers, system administrators, maintainers, reviewers, and future contributors

This handbook explains the toolset that is actually present in the audited source tree. It does not assume prior knowledge of NetOps. It covers setup, architecture, data ownership, every supported command domain and action, the terminal operator console, WebUI and API, operational playbooks, safety boundaries, troubleshooting, tests, implementation details, known defects, and a concrete improvement framework.

In an interactive terminal, running `netops` with no arguments opens the v8
operator console. The stable automation and expert interface remains the
noun-first command:

```text
netops <domain> <action> [arguments] [global flags]
```

Examples:

```bash
netops inventory list ZONE10
netops health offline
netops memory switch ZONE10
netops diagnose latency 1.1.1.1 --count 10
```

The files named `netops-discovery`, `netops-control`, `netops-probe`, `netops-connect`, and `netops-legacy` are implementation helpers or compatibility layers. Their own help text still shows older commands such as `netops discover` and `netops control`. Do not treat those old examples as the preferred public interface. Use the v8 commands in this handbook unless you are debugging internals and understand the consequences.

---

## Contents

1. [Read This First: Safety Contract](#1-read-this-first-safety-contract)
2. [What NetOps Is](#2-what-netops-is)
3. [Architecture and Execution Flow](#3-architecture-and-execution-flow)
4. [Complete File Map](#4-complete-file-map)
5. [Requirements and Installation](#5-requirements-and-installation)
6. [Configuration and Credentials](#6-configuration-and-credentials)
7. [State, Files, and SQLite](#7-state-files-and-sqlite)
8. [Command Grammar, Targets, Flags, and Exit Codes](#8-command-grammar-targets-flags-and-exit-codes)
9. [Safe First Run](#9-safe-first-run)
10. [Inventory Commands](#10-inventory-commands)
11. [Access Point Commands](#11-access-point-commands)
12. [Topology Commands](#12-topology-commands)
13. [Relationship Memory Commands](#13-relationship-memory-commands)
14. [Health Commands](#14-health-commands)
15. [Backup Commands](#15-backup-commands)
16. [Device and VLAN Commands](#16-device-and-vlan-commands)
17. [Lookup and Diagnostic Commands](#17-lookup-and-diagnostic-commands)
18. [Workflows, Jobs, and Command Registry](#18-workflows-jobs-and-command-registry)
19. [Database Administration](#19-database-administration)
19A. [Profiles, Ingest, Plugins, and Extension Points](#19a-profiles-ingest-plugins-and-extension-points)
20. [Natural Ask](#20-natural-ask)
20A. [Terminal Operator Console](#20a-terminal-operator-console)
21. [WebUI](#21-webui)
22. [HTTP API](#22-http-api)
23. [Operational Playbooks](#23-operational-playbooks)
24. [Security Model](#24-security-model)
25. [Troubleshooting](#25-troubleshooting)
26. [Testing and Release Verification](#26-testing-and-release-verification)
27. [Maintainer Guide](#27-maintainer-guide)
28. [Known Limitations and Defects](#28-known-limitations-and-defects)
29. [Improvement Roadmap](#29-improvement-roadmap)
30. [Command Cheat Sheet](#30-command-cheat-sheet)
31. [Glossary](#31-glossary)

---

## 1. Read This First: Safety Contract

NetOps combines passive reads, local state changes, active network probing, SSH access, backups, and device configuration. Those are not equivalent risk classes.

### 1.1 The supported safety boundary

Use these rules every time:

1. Use `netops ...`, not `netops-control ...`, for normal operations.
2. Preview any device configuration before execution.
3. Review the exact target, interface, state effects, and generated command before confirming it.
4. Use an exact IP or hostname for writes. Avoid broad patterns, ranges, site names, and `--all` for configuration changes.
5. Keep the WebUI/API bound to `127.0.0.1` unless a separately reviewed authenticated reverse proxy and host firewall are deliberately designed. The TUI itself is local-only.
6. Treat SNMP communities, SNMPv3 secrets, SSH passwords, GitHub tokens, and controller communities as secrets.
7. Do not assume a successful command means the network is correct. Verify device state and, for configuration work, verify reachability and the saved configuration afterward.
8. Back up before changing production devices and require read-back verification after the change.
9. Verify SSH host-key fingerprints through an independent channel before strict enrollment.

### 1.2 Risk classes used by the command registry

| Class | Meaning | Examples |
|---|---|---|
| `read-only` | Reads local canonical state or remote device state | inventory list, memory queries, device show |
| `local-write` | Changes local canonical state or trust metadata | import, SSH trust enrollment |
| `network-read` | Reads the network and may refresh local cache/SQLite | inventory scan, health check, diagnostics, backup |
| `disruptive` | Starts a potentially disruptive but bounded network test | active cable TDR |
| `config-write` policy | Changes remote device configuration and requires the strongest preview evidence | device config, vlan set |

The legacy WebUI refuses to run registered configuration actions. The TUI can
run only the typed guarded VLAN workflow; arbitrary device configuration remains
preview-only. The synchronous CLI requires either `--dry-run` or `--confirm`
for `device config` and `vlan set`.

### 1.3 Internal helper boundary

The internal helper `netops-control` denies direct `config` and `vlan` execution.
Only the core can supply the process-local audited-confirmation marker after its
public policy gate. Direct `show` also enforces a bounded read-only/diagnostic
allowlist. This direct write attempt must fail:

```bash
./netops-control config switch1 "interface Gi1/0/7" "shutdown"
```

Use the guarded public form instead:

```bash
netops device config switch1 "interface Gi1/0/7" "shutdown" --dry-run
netops device config switch1 "interface Gi1/0/7" "shutdown" --confirm
```

### 1.4 What NetOps does not guarantee

NetOps is not a transactional network controller. It does not provide
multi-device rollback, candidate configuration, role-based authorization, or
guaranteed vendor-neutral syntax. Workflows declare stop/continue behavior per
step, but they do not replace an orchestration transaction. SSH host keys are
managed and changed keys fail closed; `accept-new` remains a compatibility mode
until an operator enrolls fingerprints and enables `strict`. Treat the toolset
as an operator automation platform, not as a substitute for change management.

---

## 2. What NetOps Is

NetOps is a local-first network operations toolkit for discovering devices and access points, keeping canonical inventory, recording relationship history, checking health, mapping topology, backing up configurations, running diagnostics, opening SSH sessions, and asking deterministic natural-language questions about stored state.

Its current design has six distinct layers:

1. **Public control plane:** `netops`, implemented by
   `netops_platform/core.py`; `netops_core.py` is the v8 compatibility alias.
2. **Network adapters:** Bash helpers for SNMP, ping, SSH, discovery, backup, VLAN, and diagnostics.
3. **Canonical state:** Profile-isolated SQLite schema version 12 plus derived history, ingest, diagnostics, path evidence, and relationship tables.
4. **Compatibility state:** pipe-delimited flat files used by the shell adapters.
5. **Application contracts and service:** versioned results, generated action metadata, previews, exports, jobs, audit context, and preferences in `netops_platform`.
6. **Operator interfaces:** full-screen Textual console, terminal/JSON output, Natural Ask, and a localhost Vue WebUI/API.

### 2.1 Core capabilities

- Discover switches and routers over ping/SNMP, with SSH enrichment.
- Discover Cisco WLC and Ruckus vSZ access points.
- Discover LLDP/CDP neighbors and render topology.
- Reconcile duplicate AP observations into canonical AP identities.
- Track identity, health, AP attachment, topology, and relationship changes over time.
- Trace VLAN presence and propagation recursively across bounded, LLDP/CDP-correlated switch layers.
- Locate IPs and MACs through the configured core and other switches, including direct Layer-2 MAC searches when no IP is known.
- Run local/core-origin latency, verified host-to-Internet speed, controlled `iperf3` throughput, sampled switch-port health, guarded cable TDR, DNS/TLS/filtering, and interface-utilization diagnostics.
- Save changed-only configuration backups with optional best-effort redaction.
- Execute safe multi-step workflows.
- Open a responsive local-first TUI with one dynamic result workbench, generated forms, guarded actions, live jobs, and audit history.
- Manage SSH host keys with scan, fingerprint-bound enrollment, status, forget, strict/accept-new modes, and private atomic storage.
- Run typed VLAN changes through preflight, backup, apply, read-back verification, and audit phases.
- Serve an experimental loopback-only WebUI/API and job stream.
- Answer 178 example patterns through deterministic retrieval and registry-backed command planning.

### 2.2 What Natural Ask is and is not

The core Natural Ask path is not a large language model. It normalizes wording, detects deterministic retrieval or operational intent, resolves local aliases and entity names, queries SQLite, and plans commands only from the structured registry. Its answers and plans remain explainable and bounded by current NetOps state and audited command builders.

The optional local `ai/` wrapper delegates broad questions and command requests back to this core engine. Its fast mode does not require a model. Ollama may select or reword approved tool output when a local model is installed, but it cannot generate raw shell or execute a command plan.

Natural Ask has no remote model credential requirement. Optional local-model
wrappers remain outside the deterministic command and authorization boundary.

---

## 3. Architecture and Execution Flow

### 3.1 High-level flow

```text
Operator
   |
   +--> netops or installed console entry point
           |
           +--> netops_platform (launcher, contracts, service, workbench)
                   |
                   +--> core.py (parser, policy, SQLite, registry, jobs, API)
                   |
                   +--> local SQLite queries
                   |
                   +--> helper subprocesses
                   |      +--> netops-discovery
                   |      +--> netops-control
                   |      +--> netops-probe
                   |      +--> netops-connect
                   |      +--> netops-legacy (selected diagnostics only)
                   |
                   +--> localhost HTTP server
                          +--> REST-like JSON API
                          +--> SSE job logs
                          +--> webui/dist static Vue application

Network helper state
   +--> devices.db
   +--> ap_devices.db
   +--> neighbor.db
          |
          +--> import-flat --> canonical SQLite --> derived memory/history
```

### 3.2 Launcher behavior

The source-tree `netops` launcher resolves its real path, selects a sibling
managed virtual environment when the TUI needs Textual, delegates the optional
AI wrapper, and executes the `netops_core.py` compatibility alias. That alias
installs the canonical `netops_platform.core` module object in `sys.modules`,
so imports and monkeypatches see one implementation. The wheel's `netops` and
`netop` console scripts enter `netops_platform.launcher` directly. A source
deployment still keeps sibling helpers together; a missing compatibility core
causes startup to exit with code 10.

### 3.3 Core startup behavior

For a stateful command, the core:

1. Resolves install, config, cache, SQLite, and backup paths.
2. Reads recognized key/value configuration without invoking the shell wizard.
3. Opens SQLite, creates/migrates schema version 12, and sanitizes invalid MAC identities.
4. Reconciles derived state while suppressing migration-only structural events.
5. Parses global flags regardless of where they appear in the argument list.
6. Dispatches a supported domain/action or a limited deprecated alias. The same
   registry generates CLI/TUI action metadata, Markdown reference, `netops(1)`,
   and shell completions; CI rejects drift.

Root help, version, and TUI help return before SQLite/runtime initialization.
The TUI and other stateful operations open and migrate the selected database.
Point tests at temporary paths when isolation matters.

### 3.4 Flat files versus SQLite

The shell adapters were built around flat files. The v8 core treats SQLite as canonical for list, history, memory, Natural Ask, jobs, API, and WebUI views. Scan helpers still write flat files; the v8 wrapper then imports them into SQLite and recomputes derived state.

The practical cycle is:

```text
network read -> helper flat files -> SQLite import -> identity reconciliation
             -> health/topology/relationship derivation -> operator queries
```

`inventory export-flat` runs the reverse bridge when legacy helpers need SQLite data reflected back into the flat files.

### 3.5 Current versus legacy servers

`netops_platform/core.py` contains the current v8 server. `netops-legacy` also
contains an older embedded server and scheduler implementation. The v8 launcher
does not use that old server. In particular, the current `/api/automation`
response is informational/planned; it does not activate the legacy scheduler.

---

## 4. Complete File Map

This audit classified every first-party file, generated artifact, and dependency boundary in the tree.

### 4.1 Top-level authored files

| File | Role | Normal users should execute it? |
|---|---|---|
| `netops` | Public Python launcher | Yes |
| `netops_core.py`, `netops_ask.py`, `netops_devices.py`, `netops_identity.py`, `netops_ingest.py`, `netops_mac_registry.py`, `netops_network.py`, `netops_speed.py` | Temporary flat-module aliases to canonical `netops_platform` modules; retained through v8.x for imports and helpers | No |
| `netops-lib.sh` | Shared Bash config, flat DB, SNMP, credential, SSH, and target helpers | No; it must be sourced |
| `netops-discovery` | Device/AP/neighbor discovery and flat-file management | Internal/diagnostic only |
| `netops-control` | SSH inventory, backups, bounded show/config, VLAN, core/MAC lookup | Internal; direct writes fail without the core capability marker |
| `netops-probe` | ICMP/TCP latency and multi-server speed testing | Internal/diagnostic only |
| `netops-connect` | Password vault, target resolution, interactive SSH | Internal; use `netops device ssh` |
| `netops_aruba_ssh.exp` | Prompt-aware Expect wrapper for complete Cisco/Aruba/RUCKUS read-only command capture | Internal |
| `netops-legacy` | Compatibility router, filtering and interface diagnostics, obsolete server | Internal |
| `pyproject.toml` / `uv.lock` | Python package, dependency, console-script, helper-script, and reproducible environment metadata | Used by packaging tools |
| `netops_platform/core.py` | Canonical CLI, policy, schema, state, registry, jobs, API, and static server | Indirectly |
| `netops_platform/devices.py` | Profile-clonable device-family registry, capability matrix, detection, and semantic command plans | No |
| `netops_platform/ingest.py` | Versioned channel readers, observation provenance, quarantine, idempotency, and materialization | No |
| `netops_platform/inventory_ingest.py` | Non-destructive compatibility-observation merge for shell/provider records | No |
| `netops_platform/identity.py`, `ask.py`, `network.py`, `mac_registry.py`, `speed.py` | Canonical identity, language, parser, IEEE-registry, and speed implementations | No |
| `netops_platform/contracts.py`, `profiles.py`, `plugins.py`, `path_inspector.py` | Versioned contracts, profile lifecycle, trusted extension policy, and Ghoster engine | No |
| `netops_platform/service.py`, `launcher.py`, `tui/` | Application boundary, installed console entry point, and Textual console | Indirectly |
| `netops_platform/support.py`, `privacy.py`, `release.py`, `docsgen.py` | Redacted support, publication scans, release metadata, and generated-reference tooling | Maintainers/release engineers |
| `docs/` | v8 architecture, operator console, design system, migration, and accepted decisions | Read before operation/maintenance |
| `.gitignore` | Excludes local environments, test/build output, bytecode, runtime databases, and generated agent logs | No |
| `examples/` | Neutral profile, channel, fixture, and declarative-driver examples | Copy into a test profile and adapt |
| `generate_reference.py` | Rebuilds command reference, man page, and shell completions from the command registry | Maintainers/packaging |
| `privacy_check.py` | Scans trees, archives, and clean public history for publication blockers | Maintainers/release engineers |

### 4.2 Tests

| File | Coverage |
|---|---|
| `tests/test_netops_core.py` | Device/AP identity and aliases, state behavior, command intent, extraction, previews, execution gates, process-group cleanup, startup isolation, registry/help coverage, vendor write denial, vault lifecycle, health predicates, and ISO chronology |
| `tests/test_netops_ai.py` | AI delegation, public-launcher-only argv, plan rendering, execution disclaimers, and ISO date rendering |
| `tests/test_netops_network.py` | Fixture-driven interface normalization, Cisco/Aruba/RUCKUS VLAN, LLDP/CDP, ARP/MAC, ping, OUI, interface health, cable TDR, and `iperf3` parsing |
| `tests/test_netops_devices.py` | Family detection, semantic command plans, declarative drivers, firmware profiles, capability reports, MAC formatting, and fail-closed writes |
| `tests/test_netops_ingest.py` | Compatibility observation parsing and merge paths, sparse-field retention, source union, and status/hostname refresh |
| `tests/test_netops_mac_registry.py` | Validated IEEE cache refresh, longest-prefix assignment, local/random handling, and stale-cache fallback |
| `tests/test_netops_active_workflows.py` | Bounded matrix traversal, dry-run isolation, schema repair, jobs/SSE, profile-local drivers, unified built-in ingest, Ghoster refresh, core ping/lookup, MAC evidence, diagnostics, TDR gating, and helper-result classification |
| `tests/test_netops_speed.py` | Explicit CA validation, retained TLS/hostname verification, server-list schema, paired client reuse, loaded latency sampling/cleanup, and transfer validation |
| `tests/test_netops_shell_lifecycle.py` | Shell parsing, cancellation/descendant cleanup, three-day sudo/legacy vault lifecycle, real-GPG round trip, filtered legacy SSH, installed helper resolution, normalized ingest, secure writes, discovery, prompt-aware SSH, write denial, speed caching, and dry-run safety |
| `tests/test_netops_v8.py` | Registry metadata, private preferences/migration, launcher handoff, installed-version fallback, SSH enrollment, guarded VLAN lifecycle, workflow summaries, result adaptation, and side-effect-free TUI help |
| `tests/test_netops_tui.py` | Textual interaction at wide/compact/narrow sizes, command-first local-only mount, on-demand surfaces, catalog filtering, guarded forms, and preferences |
| `tests/test_netops_platform_85.py` | Contracts/profile migration, installed WebUI resolution, channel security/idempotency/provenance/quarantine, plugin runtime policy, built-in ingest, Ghoster outcomes, privacy scanning, support bundles, and release reproducibility |

Do not rely on a count copied into documentation. The release gate runs the
entire discovered suite and records its result in release provenance. Parser
tests use sanitized synthetic Cisco/Aruba/RUCKUS fixtures and workflow tests
use mocked transports. SSE replay/completion is tested at the handler boundary,
but real firmware, browser, restore, and authorized write validation remain
separate lab gates.

### 4.3 WebUI source

| File | Role |
|---|---|
| `webui/package.json` | npm scripts and direct dependency ranges |
| `webui/package-lock.json` | lockfile v3 with 128 package entries and integrity hashes |
| `webui/index.html` | Vite HTML entry point |
| `webui/vite.config.ts` | Vue and Tailwind Vite plugins |
| `webui/tailwind.config.ts` | Tailwind content configuration |
| `webui/src/main.ts` | Creates and mounts the Vue app and imports CSS |
| `webui/src/App.vue` | Entire eight-view operator console and API client |
| `webui/src/styles.css` | Tabler import plus all custom layout, state, motion, and responsive styles |

The stylesheet contains multiple chronological design passes. CSS cascade order means the later "Final operator polish" and "Natural Ask cleanup" declarations override many earlier pastel/kinetic declarations. Removing apparently duplicated rules without visual regression testing can change the UI.

### 4.4 Generated WebUI files

| File | Role |
|---|---|
| `webui/dist/index.html` | Production page served by `netops serve` |
| `webui/dist/assets/index-DtXXxw82.css` | Minified bundled CSS, including Tabler |
| `webui/dist/assets/index-D3VX1lfP.js` | Minified bundled Vue application |

Production assets are reproducible from the locked WebUI manifest. Release CI
rebuilds them and rejects an unsuccessful test or build instead of relying on a
historical local build date.

### 4.5 Generated and third-party directories

- `__pycache__/` contains generated Python bytecode. It is not source.
- `webui/node_modules/` contains third-party packages installed from `package-lock.json`. The authored behavior was audited through source imports, manifests, lock metadata, and a clean production build, rather than treating thousands of dependency implementation files as NetOps-owned source.
- `.git/` is private development history and is never copied into a public
  export. Public releases start from a newly initialized, privacy-scanned tree.

### 4.6 Locked frontend versions

| Package | Resolved version |
|---|---:|
| Vue | 3.5.39 |
| Vite | 7.3.6 |
| `@vitejs/plugin-vue` | 6.0.7 |
| Tabler Core | 1.4.0 |
| Tabler Icons Vue | 3.44.0 |
| Tailwind CSS | 4.3.2 |
| TypeScript | 5.9.3 |

---

## 5. Requirements and Installation

The repository now has a PEP 517 package (`pyproject.toml`) and an `uv.lock`
environment. It still has no service unit or formal operating-system support
matrix; background deployment remains an explicit operations decision.

### 5.1 Base runtime

Required for the public core:

- Linux or a sufficiently GNU-compatible Unix environment.
- Python 3.11 or newer. The TUI package depends on Textual 8.2.8 and Rich 14-15;
  the core still avoids framework dependencies until the TUI is selected.
- Bash with associative arrays and `mapfile` support for helpers.
- SQLite 3 CLI for shell backup/history paths.
- Standard tools including `awk`, `sed`, `grep`, `sort`, `cut`, `date`, `stat`, `sha256sum`, `timeout`, `mktemp`, `find`, `getent`, and `ping`.

### 5.2 Capability dependencies

| Capability | Commands/tools required |
|---|---|
| SNMP discovery | `snmpget`, `snmpwalk`, MIB support where symbolic OIDs are used |
| SSH automation | OpenSSH `ssh`, `sshpass`, `gpg` |
| Aruba automated sessions | `expect` and executable `netops_aruba_ssh.exp` beside `netops-lib.sh`, or a wrapper selected with `NETOPS_ARUBA_SSH_WRAPPER` |
| CIDR/range discovery | `ipcalc` is used in one CIDR path; shell arithmetic handles other patterns |
| Latency | `ping`; TCP mode also uses Perl `IO::Socket::INET` |
| Tracing | `traceroute` |
| Filtering diagnostics | `curl`, `openssl`, optional `dig`, optional `nc`, DNS resolver tools |
| Internet speed | Python `speedtest-cli` module, `jq`, `ping`, `timeout`, `awk`, and `ip`; WSL enterprise trust import also needs Windows PowerShell |
| Controlled throughput | `iperf3` on the client and a deliberately operated `iperf3` server at the core/remote test point |
| Port and cable health | SSH/Expect; switch support for interface counters and, for active cable tests, vendor TDR commands; optional local `ethtool` is readiness metadata only under WSL |
| Wi-Fi signal metadata | optional `iw` |
| Interface monitor | `snmpget`, `snmpwalk`, `jq`, `awk`, `sed` |
| Frontend development | Node matching Vite's `^20.19.0 || >=22.12.0`, plus npm |

Package names vary by distribution. Verify commands rather than assuming a
package installed the expected binary. NetOps v8.5 beta imports the distro
`speedtest` Python module through `netops_platform/speed.py`; it does not depend
on parsing the external executable's text/JSON dialect.

### 5.3 Repository execution

For development, run from the source directory:

```bash
cd $HOME/src/netops-platform
uv sync --extra dev
uv run netops --help
uv run netop tui
```

The source launcher remains usable for noun-first commands. Opening the TUI from
source requires the synchronized Python environment. If its shebang selects a
system Python without Textual, a TUI request automatically re-executes through
the sibling `.venv`; noun-first CLI commands do not pay that dependency cost.
The launcher and executable helpers should have execute permission; imported
modules and the shell library need read permission.

Packaged installation is also supported:

```bash
pipx install $HOME/src/netops-platform
netops --version
```

The package installs both `netop` and `netops` console scripts, plus helper
scripts. It ships the TCSS theme and compiled WebUI assets; an installed
`netops serve` resolves those assets under the environment's
`share/netops-platform/webui/dist` directory.

### 5.4 Path deployment

A conservative deployment is to keep the files together in a versioned
directory and point `netops` and the singular `netop` alias at the launcher. Do
not copy only the launcher; it needs sibling Python and helper files.

Example layout:

```text
/opt/netops/8.5.0b2/
  netops
  netops_platform/
    core.py
    identity.py
    ask.py
    devices.py
    ingest.py
    tui/...
  netops_core.py                 v8 compatibility alias
  netops-lib.sh
  netops-discovery
  netops-control
  netops-probe
  netops-connect
  netops-legacy
  netops_aruba_ssh.exp
  webui/dist/...

/usr/local/bin/netops -> /opt/netops/8.5.0b2/netops
```

Prefer `install.sh` with a built wheel over manually assembling this layout.
The Aruba helper is resolved relative to the loaded shell library, so keeping
`netops_aruba_ssh.exp` beside `netops-lib.sh` is sufficient. Set
`NETOPS_ARUBA_SSH_WRAPPER` to an explicit executable path only when a deployment
intentionally stores the wrapper elsewhere. If no executable wrapper is
available, Aruba falls back to the generic SSH path.

### 5.5 Frontend installation and build

```bash
cd $HOME/src/netops-platform/webui
npm ci
npm run build
```

Development commands:

```bash
npm run dev
npm run preview
```

Both bind to `127.0.0.1` by package-script design. The Vite development server provides only the frontend; API calls still require an appropriate backend/proxy setup. The production command `netops serve` serves `webui/dist` and the API from one origin.

### 5.6 Root versus non-root operation

Do not alternate between root and non-root execution. NetOps follows the XDG
roots of the effective account, so each identity receives independent profiles,
state, cache, known hosts, and named secrets. Run the application as one normal
service account. Elevation is limited to the narrow vault-key broker through
`sudo`; running the whole application as root is not an installation method.

---

## 6. Configuration and Credentials

NetOps configuration is profile-scoped and data-only. The canonical file is
`profile.toml`; a profile-local `netsnmp.conf` remains as a temporary v8.x
compatibility layer for existing shell helpers. New secret values never belong
in TOML, key/value files, environment exports committed to disk, command
arguments, or aliases. Store them as named encrypted secrets and refer to them
with `vault:`, `env:`, or owner-only `file:` references where a channel contract
permits one.

Effective precedence is `CLI > environment > selected profile > global config
> neutral defaults`. `--profile NAME` selects one process without changing the
active profile; `netops profile use NAME` changes the default for later
processes.

### 6.1 First-time initialization

Initialize a neutral profile explicitly. Initialization creates private XDG
directories, a schema-versioned profile, compatibility files, SQLite state,
channel and driver directories, and a capability report. It does not discover a
network or prompt for credentials.

```bash
netops init --profile lab
netops profile use lab
netops profile paths
netops config set ssh_user operator
netops config show
netops config validate
```

Use `netops init --migrate-legacy` only when importing an existing pre-8.5
installation. Migration is copy-first, leaves source files untouched, and lists
legacy plaintext secret names as pending instead of copying their values.

### 6.2 Public configuration reference

| Key | Default | Meaning |
|---|---|---|
| `subnets` | empty | Space-separated/default network scopes for discovery |
| `ping_timeout` | `1` | Per-ping timeout in seconds |
| `snmp_timeout` | `3` | SNMP timeout in seconds |
| `scan_workers` | `30` | Parallel device-scan workers |
| `scan_host_timeout` | `20` | Overall timeout per scanned host |
| `ap_scan_workers` | `10` | Parallel AP/direct-model workers |
| `ap_switch_timeout` | `45` | Timeout for AP switch/controller operations |
| `enable_logging` | `true` | Enables helper log output where honored |
| `ssh_user` | empty | Non-secret SSH login name required by `device ssh` and SSH-backed helpers |
| `core_switch_ip` | empty | Core used by topology orientation and core ARP/MAC lookup |
| `cisco_wlc_ip` | empty | Cisco wireless controller address |
| `cisco_wlc_ap_ip_filter` | empty | Optional accepted AP management IP prefix from WLC discovery |
| `cisco_wlc_ap_name_contains` | empty | Optional AP-name substring filter |
| `cisco_wlc_ap_name_prefix` | empty | Optional AP-name prefix used by a deployment profile |
| `cisco_wlc_join_stats` | `true` | Enables optional SSH join-stat collection |
| `cisco_wlc_join_stats_cmd` | `show ap join stats summary all` | WLC command used for unjoined AP observations |
| `cisco_wlc_join_stats_timeout` | `45` | Join-stat command timeout |
| `ruckus_vsz_ip` | empty | Ruckus vSZ controller address |
| `ruckus_vsz_model_oids` | empty | Custom model OID mapping/input |
| `ruckus_ap_model_snmp` | `false` | Enables direct AP SNMP model enrichment |
| `default_backup_dir` | `~/network_backups` | Shell helper backup root |
| `ssh_host_key_mode` | `accept-new` | Managed SSH trust policy: compatibility `accept-new` or pre-enrolled production `strict` |
| `vault_password_ttl_hours` | `72` | Expected switch-password lifetime measured from the latest successful vault write |
| `vault_expiry_window_minutes` | `20` | Plus/minus uncertainty window around expected password expiry |
| `vault_expiry_warning_hours` | `12` | Advance warning period before the expiry window |
| `target_abbreviation_prefix` | empty | Optional one-to-three-octet IPv4 shorthand prefix; disabled in neutral profiles |
| `strip_prefixes` | empty | Optional comma-separated identity prefixes; neutral normalization remains active |
| `device_writes_enabled` | `false` | Profile gate for certified built-in firmware writes |
| `plugin_writes_enabled` | `false` | Reserved and forced ineffective in 8.5; plugin writes are prohibited |

Neutral defaults contain no target shorthand, naming rewrite, subnet, controller,
WLC filter, community, or credential. A fresh profile therefore cannot silently
reach or classify an operator's network before it is configured.

### 6.3 Named secret reference

Secret names use slash-separated lowercase paths such as
`ssh/default/password`, `snmp/site-a/auth`, and `ingest/netbox/token`. Values are
entered through a controlling terminal and are never printed by status/list,
configuration, support bundles, or generated references.

```bash
netops secrets status
netops secrets list
netops secrets set ingest/netbox/token
netops secrets delete ingest/netbox/token --confirm
netops secrets import-ssh
```

`vault:NAME` resolves through the encrypted named store. `env:NAME` is useful
for an external process supervisor but must not be persisted in profile files.
`file:PATH` is accepted only for a regular file owned by the current account
with mode `0600`. Literal authorization headers, URL userinfo, and sensitive URL
query parameters are rejected by ingest validation. Prefer SNMPv3 authPriv;
SNMPv2c values are bearer secrets transmitted without encryption.

### 6.4 Runtime environment overrides

The Python core and shell helpers reference these environment variables. The consumer column matters because path overrides are not applied consistently across the two generations of the toolset.

| Variable | Consumer | Effect |
|---|---|---|
| `NETOPS_CONFIG_DIR` | Python core | Overrides the Python config directory |
| `NETOPS_CACHE_DIR` | Python core | Overrides the Python cache directory |
| `NETOPS_STATE_DIR` | Python core | Overrides profile state during compatibility/testing |
| `NETOPS_DATA_DIR` | Python core | Overrides profile data during compatibility/testing |
| `NETOPS_PROFILE` | Python/shell launch path | Selects a profile for the current process |
| `NETOPS_SQLITE_DB` | Python core | Overrides the SQLite path |
| `NETOPS_BACKUP_DIR` | Python core | Overrides the Python-visible backup path |
| `NETOPS_JOB_CONCURRENCY` | Python server | Maximum concurrent server jobs; default `3` |
| `NETOPS_TUI` | Python launcher | Set `0`/`false` to retain no-argument CLI help instead of the interactive TUI |
| `NETOPS_TUI_CONFIG` | TUI | Overrides the private preferences JSON path |
| `NETOPS_TUI_THEME` | TUI | Selects `auto`, `light`, or `dark`; `auto` is neutral and defaults to light |
| `NETOPS_TERMINAL_THEME` | TUI | Supplies a `light` or `dark` terminal hint when `COLORFGBG` is unavailable |
| `NETOPS_EXPORT_DIR` | Application service | Overrides the private result-export directory |
| `NETOPS_PROGRESS` | Python/shell launch path | Set `0` to suppress terminal progress animation where honored |
| `NO_COLOR` | Python/shell output | Disables color where honored |
| `NETOPS_RESOLVE_MODE` | Shell target resolver | Selects interactive/default, `first`, or `all` ambiguity handling |
| `NETOPS_CHECK_TIMEOUT` | `netops-legacy` diagnostics | Connect timeout in seconds for port, DNS-adjacent, HTTP, HTTPS, and filtering probes; default `4`, and the legacy diagnostic parser can set/export it for that process |
| `NETOPS_SWITCH_NAME_MAX` | `netops-discovery` | Maximum accepted discovered switch hostname length; default `32` |
| `NETOPS_SSH_SHOW_ERRORS` | Generic shell SSH helper | Set `true` to stop suppressing helper SSH stderr during troubleshooting |
| `NETOPS_SSH_KNOWN_HOSTS_FILE` | Python/shell SSH paths | Overrides the private managed known-hosts file |
| `NETOPS_SSH_HOST_KEY_MODE` | Shell SSH path | One-process override of `strict` or `accept-new` |
| `NETOPS_SSH_BREAK_GLASS` | Shell SSH path | Must be explicitly `true` together with break-glass mode to disable verification for one process; emits a warning |
| `NETOPS_PASSWORD_FILE` | Python/shell vault paths | Overrides the encrypted SSH-password vault path; default `~/.ssh/sshpass_cache.gpg` |
| `NETOPS_MAC_REGISTRY_DIR` | Python core | Overrides the private IEEE MA-L/MA-M/MA-S cache directory |
| `NETOPS_VAULT_MODE` | Shell vault writer | Selects `sudo-gpg` (default) or the explicit `legacy-gpg` fallback when setting a password |
| `NETOPS_VAULT_NONINTERACTIVE` | Shell vault reader | When true, fails instead of requesting sudo authentication; useful for unattended jobs that must never block on a prompt |
| `NETOPS_SECRETS_FILE` | Named-secret store | Overrides the encrypted store for isolated tests or managed deployment |
| `NETOPS_PRIVACY_DENYLIST_FILE` | Release tooling | Adds deployment-specific publication blockers |

No environment variable or configuration key enables remote credential export.

Important: the shell helpers compute most config/cache paths directly from effective UID and `HOME`; they do not consistently honor all Python path overrides. Isolated Python tests therefore do not prove that a spawned shell helper will use the same paths. Run integration tests with a temporary `HOME` as well.

### 6.5 SSH password vault

`netops device ssh` maps its credential to the named key
`ssh/default/password`. Existing deployments can retain the compatibility vault
during migration; `netops secrets import-ssh` copies the decrypted value into
the profile's encrypted named store without printing it. The compatibility file
is:

```text
~/.ssh/sshpass_cache.gpg
```

The `-l`/`--legacy` SSH option sets the internal, process-local flag `CONFIG[legacy_ssh]=true`, enabling older key-exchange and host-key algorithms for that connection. `legacy_ssh` is not a recognized persistent `netsnmp.conf` key, so adding it to the file has no effect.

Inspect it without prompting:

```bash
netops vault status
netops vault status --json
```

The status includes the format, mode, file permissions, password-recorded time,
expected expiry, estimated expiry window, credential state, configured sudo/PAM
authenticator, sudo-cache state, and root-key state. Times use ISO 8601 UTC. It
uses `sudo -n` only and therefore never opens an authentication prompt.

The credential lifecycle is an operational estimate, not a query to the switch
or password authority. A successful `netops vault set` or `connect -p` updates
the vault file atomically; that recording time becomes the rotation baseline.
With the defaults, expected expiry is 72 hours later and the uncertainty window
is 20 minutes before through 20 minutes after that time:

| State | Meaning |
|---|---|
| `ACTIVE` | Earlier than the configured warning period |
| `DUE_SOON` | Inside the advance warning period but before the expiry window |
| `EXPIRY_WINDOW` | Inside the estimated plus/minus window |
| `EXPIRED` | Later than the end of the estimated window |
| `UNKNOWN` | No valid vault recording time is available |

NetOps warns during vault use when rotation is due, in-window, or likely
expired. An authentication rejection reports the recorded and expected times
and instructs the operator to run `connect -p`. It cannot prove that a password
expired: account lockout, AAA failure, username changes, and transport policy
can produce the same rejection. Vault migration preserves the original file
timestamp so migration does not reset the password age.

The default format is `sudo-gpg-v1`. It uses two separate controls:

1. `sudo` authenticates the operator through the host PAM policy. On this WSL
   workstation, `pam_wsl_hello.so` is sufficient, so fingerprint, face, or
   Windows Hello PIN approval satisfies the request. The normal Linux password
   remains PAM's fallback. Other systems use their configured sudo mechanism.
2. A random per-user encryption key at
   `/etc/netops/vault-keys/<numeric-uid>.key`, owned by root with mode `0600`,
   is validated and read by one narrowly scoped sudo broker process, then
   streamed to unprivileged GPG through a dedicated file descriptor. The
   broker checks the trusted owner, object types, directory and key modes, and
   non-empty key before it emits any key bytes.

On WSL, containers, and other user-namespaced filesystems, `stat` may display
the host-mapped privileged owner as UID `65534` rather than UID `0`. NetOps does
not weaken its file checks for that case: the key and protected key directory
must match the trusted `/etc` owner, the directory must be a `0700` directory,
and the key must be a regular `0400` or `0600` file.

The sudo/root password is never stored, passed to GPG, placed in an environment
variable, or used as the encryption key. GPG always runs with
`--pinentry-mode loopback`, so NetOps does not invoke the configured graphical
pinentry program. After the first successful terminal authentication, later
NetOps processes reuse sudo's normal credential timestamp until the operating
system's configured timeout expires. `--no-symkey-cache` prevents GPG Agent
from becoming a second, less-visible unlock cache. A private `flock` serializes
authentication, so parallel cascade workers cannot open competing sudo prompts;
the first authenticates and the rest reuse the resulting timestamp.

Windows Hello proves operator presence by signing a random PAM challenge; it
does not expose a reusable password or encryption secret to Linux. NetOps
therefore uses that successful sudo/PAM decision only to authorize reading the
root-owned random vault key. This preserves biometric unlock without trying to
derive encryption material from a fingerprint. Vault actions remain attached
to the foreground terminal, and interactive SSH uses that same runner, so sudo
policies that scope timestamps to a TTY see a coherent terminal session. The
privileged broker performs authentication, metadata validation, and key access
in one sudo invocation; detached read-only helpers therefore do not depend on
a second `sudo -n` call inheriting the first call's timestamp.

Set or replace the device SSH password through:

```bash
netops vault set
```

This first validates or creates the root-only random key, then asks twice for
the network-device SSH password. The password is symmetrically encrypted by
GPG into a mode-`0600` staged file and moved atomically over the local vault
only after successful encryption. A failed encryption leaves the previous
vault unchanged. The network-device password is decrypted into `SSHPASS` only
inside the requesting NetOps process for `sshpass`; it is not placed on a
command line.

#### One-time migration from the graphical legacy vault

An existing vault without the `NETOPS-SUDO-GPG-V1` format marker is reported as
`legacy-gpg`. Migrate it once:

```bash
netops vault status
netops vault migrate
netops vault status
```

Migration asks for sudo authentication in the terminal, then may ask once for
the old GPG vault passphrase in the same terminal. It decrypts the old vault in
memory, writes a complete staged `sudo-gpg-v1` vault, and replaces the original
only after encryption succeeds. No Windows or desktop pinentry window is used.
With WSL-Hello-sudo enabled, the first authentication is the Windows Hello
fingerprint/face/PIN dialog. The old GPG passphrase remains necessary once when
it is not cached because Windows Hello cannot decrypt the unrelated legacy GPG
ciphertext.

If the old passphrase is unavailable but the network-device SSH password is
known, use `netops vault set` to replace the old vault directly. To verify the
new vault and establish a sudo timestamp before a sequence of operations, run:

```bash
netops vault unlock
```

`unlock` verifies decryption and immediately removes the temporary password
from that helper process. It does not extend sudo beyond the host's configured
timeout. Set `NETOPS_VAULT_NONINTERACTIVE=true` for unattended execution that
must fail closed rather than request authentication.

The explicit fallback is:

```bash
netops vault set --legacy-vault
```

It asks for a separate GPG passphrase in the terminal and also forces loopback
mode, but each uncached process may require that passphrase. Prefer the
sudo-gated format on this workstation.

Back up both `~/.ssh/sshpass_cache.gpg` and the matching root-only key under
`/etc/netops/vault-keys/`. Store them with separate access controls. Losing the
root key makes a sudo-gated vault undecryptable; copying only the `.gpg` file is
not a complete backup. Protect the account, sudo policy, process environment,
root key, and encrypted vault.

Remote credential synchronization is not part of the platform. A future secret
manager requires a separately reviewed adapter, scoped identity, rotation,
revocation, and audit design.

### 6.6 Managed SSH host trust

Every generic and prompt-aware SSH adapter receives the same
`StrictHostKeyChecking` and private `UserKnownHostsFile` settings. `accept-new`
records first contact and rejects a changed key. `strict` requires a prior
record and is the recommended production state.

Use the public workflow:

```bash
netops device trust-scan SWITCH
netops device trust-enroll SWITCH --fingerprint SHA256:VERIFIED_VALUE --confirm
netops device trust-status SWITCH
```

The expected fingerprint must come from an independent trusted source. A
successful scan only reports what the current network path presented. Enroll
writes the matched key atomically to a mode `0600` store and records an audit
event. On approved device replacement, use `trust-forget`, verify the new key,
and enroll it again.

Break-glass mode disables verification only when both the mode and
`NETOPS_SSH_BREAK_GLASS=true` are supplied to that process. It writes no trust
record and prints a warning. Treat its use as an incident action.

### 6.7 Example profile configuration

```toml
schema_version = 1

[network]
subnets = "192.0.2.0/24 198.51.100.0/24"
core_switch_ip = "192.0.2.1"
core_iperf_server = "192.0.2.50"
target_abbreviation_prefix = ""

[access]
ssh_user = "operator"

[identity]
strip_prefixes = []
ap_similarity_threshold = 85
switch_similarity_threshold = 75

[discovery]
cisco_wlc_ip = "192.0.2.20"
cisco_wlc_ap_ip_filter = ""
cisco_wlc_ap_name_contains = ""
cisco_wlc_ap_name_prefix = ""
ruckus_vsz_ip = ""

[policy]
ssh_host_key_mode = "strict"
device_writes_enabled = false
plugin_writes_enabled = false
vault_password_ttl_hours = 72
vault_expiry_window_minutes = 20
vault_expiry_warning_hours = 12
```

Use `netops config set KEY VALUE` for a profile-local compatibility override,
`netops config unset KEY` to remove it, and `netops config paths` to see every
source. Secret-looking keys are rejected and must use `netops secrets set`.

Do not paste real credentials into issue reports, command history, screenshots, or this handbook.

---

## 7. State, Files, and SQLite

Understanding state ownership is the difference between merely running NetOps and diagnosing it correctly.

### 7.1 Non-root state layout

```text
~/.config/netops/
  active_profile
  config.toml                         optional global non-secret settings
  profiles/PROFILE/
    profile.toml                      canonical profile settings, mode 0600
    netsnmp.conf                      temporary shell compatibility settings
    known_hosts                       profile SSH trust store, mode 0600
    aliases.yaml                      profile aliases and naming rewrites
    channels/*.toml                   declarative ingest channels
    drivers/*.toml                    declarative read-only device drivers

~/.local/state/netops/profiles/PROFILE/
  netops.sqlite3                      canonical database
  netops.sqlite3-wal                  SQLite WAL when active
  netops.sqlite3-shm                  SQLite shared memory when active

~/.cache/netops/profiles/PROFILE/
  devices.db              legacy device observations
  ap_devices.db           legacy AP observations
  neighbor.db             legacy LLDP/CDP observations
  snmp_cache.db           community/probe cache
  mac-registry/           downloaded IEEE assignment cache

~/.local/share/netops/profiles/PROFILE/
  backups/                            default backup root
  exports/                            operator exports
  secrets.gpg                         encrypted named-secret store
```

`XDG_CONFIG_HOME`, `XDG_STATE_HOME`, `XDG_CACHE_HOME`, and `XDG_DATA_HOME`
relocate their corresponding roots. A profile owns all four roots as one
isolation boundary. Legacy `netsnmp` locations are read only by the explicit,
copy-first migration path.

### 7.2 Flat-file schemas

Device and AP observations use nine pipe-separated fields:

```text
IP|HOSTNAME_OR_AP_NAME|PLATFORM|MODEL|SERIAL|MAC|SOURCE|TIMESTAMP|STATUS
```

Neighbor observations use six fields:

```text
LOCAL_IP|LOCAL_NAME|LOCAL_PORT|REMOTE_NAME|REMOTE_PORT|REMOTE_IP
```

Status is normalized to uppercase values such as `ONLINE`, `OFFLINE`, or `UNKNOWN` in canonical paths. Timestamps are Unix epoch seconds.

Flat files are compatibility state, not relationally constrained data. A malformed line, duplicate AP, placeholder MAC, stale status, or source-specific naming variant can exist there. Import is where v8 normalizes and reconciles observations.

### 7.3 SQLite tables

Schema version 12 creates the following logical groups.

**Schema and settings**

| Table | Purpose |
|---|---|
| `schema_meta` | Current schema version and migration metadata |
| `settings` | Generic local key/value state |

**Current observed inventory**

| Table | Purpose |
|---|---|
| `devices` | Current switch/router/device observations keyed by IP |
| `aps` | Raw/current AP observations; multiple rows may represent one physical AP |
| `neighbors` | Current LLDP/CDP-style links |

**Identity and history**

| Table | Purpose |
|---|---|
| `inventory_identity_state` | Latest identity state indexed by IP, MAC, and name evidence |
| `inventory_history` | Append-style first-seen and field-change events |
| `inventory_merges` | Audited, reversible old-device to current-device lifecycle mappings |
| `ap_move_events` | AP switch or port movement events |

**Health and topology**

| Table | Purpose |
|---|---|
| `health_state` | Current entity health, outage start, last success/failure, flap count |
| `health_events` | First-seen and status-change events |
| `topology_snapshot` | Previous link set used for comparison |
| `topology_events` | Link-added and link-removed events |

**Relationship memory**

| Table | Purpose |
|---|---|
| `relationships_current` | Current IP/MAC/name/attachment/link/port relationships |
| `relationship_events` | Relationship appeared, changed, and disappeared history |
| `core_lookup_cache` | Raw observations from live core lookup commands |

**Operations**

| Table | Purpose |
|---|---|
| `jobs` | Server-created job lifecycle |
| `job_logs` | Per-job stdout, stderr, and system lines |
| `command_history` | Completed server job command and exit code |
| `backup_history` | Backup result, hash, path, size, and changed flag |
| `scan_runs` | Migration/reconciliation run records and completeness metadata |
| `audit_events` | Actor, action, target, reason, ticket, preview hash, and redacted result evidence |

**Ingest, plugins, and path evidence**

| Table | Purpose |
|---|---|
| `ingest_channels` | Materialized profile channel manifests and validation status |
| `ingest_runs` | Per-delivery received, accepted, duplicate, reject, and failure counts |
| `observations` | Append-only `ObservationV1` records and deterministic idempotency keys |
| `observation_fields` | Field-level value, source, confidence, and observed time |
| `observation_rejects` | Quarantined validation failures with redacted evidence |
| `plugin_state` | Profile enablement, package provenance, API version, and last load result |
| `capability_evidence` | Time-stamped semantic driver evidence used by path inspection |
| `path_runs` | Persisted `PathRequestV1`/`PathResultV1` and final outcome |
| `path_hops` | Ordered L2/L3 hop evidence and evidence age |
| `path_findings` | Blockers, warnings, unknown semantics, and confidence |

**Natural Ask**

| Table | Purpose |
|---|---|
| `ask_aliases` | Profile-specific deterministic phrase aliases |

**Diagnostic history**

| Table | Purpose |
|---|---|
| `probe_results` | Latency summaries |
| `speed_tests` | Speed and loaded-latency summaries |
| `interface_samples` | Interface rate/utilization samples |
| `filtering_checks` | DNS/TLS/filtering outcomes |
| `diagnostic_runs` | Unified, newest-first speed/throughput/port/cable/doctor records with source, target, status, summary, and raw JSON |

Core-origin ping, Internet speed, controlled throughput, port health, cable diagnostics, and readiness checks persist directly from their current-core workflows. Legacy latency/filtering/interface paths still have narrower persistence behavior; consult each command section rather than treating an empty table as a network result.

### 7.4 Device and AP identity reconciliation

AP sources commonly disagree about spelling, prefixes, addresses, and attachment detail. NetOps therefore exposes canonical AP rows rather than blindly counting raw rows.

The reconciliation process:

1. Rejects placeholder identity values and invalid IPs.
2. Normalizes a physical MAC to 12 lowercase hexadecimal digits.
3. Rejects all-zero, broadcast, multicast, and placeholder-OUI MACs.
4. Normalizes neutral location and role terms; optional deployment prefixes and
   rewrites come only from the selected profile.
5. Extracts an AP number and location signature where possible.
6. Builds indexed candidate buckets by valid MAC, serial, normalized signature,
   normalized name, valid IP, attachment, and role/model evidence.
7. Uses union-find grouping to merge linked observations without performing an
   all-pairs comparison across the inventory.
8. Refuses any merge that would combine two distinct valid physical MACs.
9. Chooses the best representative row by online status, valid IP, attachment detail, valid MAC, platform, and recency.
10. Aggregates aliases, addresses, MACs, and the latest seen time.

Canonical identity confidence is explicit:

| Evidence | Canonical ID | Confidence |
|---|---|---:|
| Valid physical MAC | `mac:<normalized-mac>` | 100 |
| AP number plus location signature | `ap:<signature>` | 92 |
| Best remaining row only | `row:<ip-or-name>` | 60 |

If any member is online, the canonical AP is online. It is offline only when every member is offline; otherwise status is unknown.

Do not infer a physical switch port from controller-only AP data. Natural Ask explicitly avoids claiming that a controller observation proves a cabled port.

Switch observations use the same evidence discipline. NetOps normalizes common
location/role forms and configured profile prefixes, retains all valid IPs, MACs, serials,
and hostnames, and chooses the most current meaningful row as the display row.
Name similarity creates candidates at 85 percent for APs and 75 percent for
switches. Automatic identity requires exact normalized naming or corroboration
from valid MAC, serial, IP, AP attachment, or same role/asset number plus model.
Conflicting physical MACs, meaningful serials, or different AP/switch asset
numbers block a merge. This prevents nearby `BUILDING-1` and `BUILDING-2` switches from being
merged merely because their names are similar.

When discovery records a new hostname for a corroborated device, the new name
becomes current and the old name remains in `inventory_identity_state`,
inventory history, and active `device_alias` relationships. Either name can
resolve the current device. Placeholder serials such as `N/A` are never used as
identity evidence.

Automatic reconciliation runs after successful inventory, AP, and topology
imports and after declarative ingest deliveries that materialize current device
state. Read commands use the same canonical rules but do not write history.
Candidate blocking keeps ordinary reads near-linear as inventories grow; it
does not reduce the physical-conflict checks required before an automatic
merge.

### 7.5 Derived relationship types

`memory refresh` derives these relationships:

| Type | Subject -> object | Typical confidence |
|---|---|---:|
| `identity_ip` | IP -> device/AP | 95 |
| `identity_mac` | MAC -> device | 95 |
| `identity_mac` | MAC -> AP | 99 |
| `identity_alias` | normalized alias -> canonical AP | AP identity confidence |
| `device_alias` | historical/current normalized hostname -> canonical switch/device | Device identity confidence |
| `ap_attachment` | canonical AP -> switch | 95 with switch IP, otherwise 84 |
| `port_occupancy` | switch port -> AP | 92 |
| `neighbor_link` | local switch/port -> neighbor | 88 |
| `port_occupancy` | switch port -> neighbor | 82 |
| `core_lookup` | queried IP/MAC -> lookup target | 70 |

Relationship events record appearance, change, and disappearance. Current relationships that are no longer derived are retained with disappeared status/history rather than silently erased.

Confidence is evidence strength, not a probability calibrated against ground truth. Use it to compare source quality, not to claim statistical certainty.

### 7.6 Health and attention semantics

Health state tracks first seen, last seen, last failed, outage start, and cumulative status transitions (`flap_count`). Each change between normalized statuses increments the flap count.

The attention view includes, among other items:

- entities currently offline;
- entities with at least three recorded flaps;
- entities whose last successful sighting is older than 24 hours;
- topology link changes;
- AP movement;
- backup failures or issues;
- diagnostic attention where data exists.

This is an operator review queue, not a deduplicated incident-management system. A stale inventory can create misleading attention until discovery is refreshed.

### 7.7 Migration behavior

`db migrate` creates or advances the schema and sanitizes invalid MAC-derived state. It recomputes derived identity, health, topology, and relationships. To avoid turning a structural migration into fake operational history, migration mode records and then deletes newly generated structural events from:

- `inventory_history`
- `health_events`
- `topology_events`
- `ap_move_events`
- `relationship_events`

A `scan_runs` record documents how many events were suppressed.

---

## 8. Command Grammar, Targets, Flags, and Exit Codes

### 8.1 Grammar

```text
netops                                      # interactive TUI when attached to a terminal
netop tui [--view VIEW] [--target TARGET]   # shortest explicit TUI form
netops tui [open] [--view VIEW] [--target TARGET]
netops <domain> <action> [positional arguments] [global flags]
netops help <domain> [action]
netops <domain> <action> --help
```

The parser recognizes global flags throughout the argument list except where a
command deliberately owns the same option name. In particular,
`diagnose speed --profile quick` selects a speed profile. To select NetOps state
for that command, put the global selector first:

```bash
netops --profile lab diagnose speed --profile quick
```

Other command-specific options are interpreted by the selected action or
forwarded to a helper.

Use the live help as the source of truth for the installed version:

```bash
netops --version
netops --help
netops help inventory scan
netops diagnose interface --help
netops help --json
```

`netops --version`, the public help banner, and `netops-legacy --version` read
the central `VERSION` file and currently report `NetOps 8.5.0b2`. Root help,
version, `netop tui --help`, and `netops tui --help` do not initialize SQLite
or other runtime state.

### 8.2 Target forms

Supported target forms vary by command. The shared resolver understands:

| Form | Example | Resolution |
|---|---|---|
| Full IPv4 | `198.51.100.71` | Used directly |
| Mine-site shorthand | `7.71` or `.7.71` | `198.51.100.71` |
| Three-octet shorthand | `134.7.71` | `198.51.100.71` |
| Shorthand range | `.7.71-75` | `198.51.100.71` through `.75` |
| Full range | `198.51.100.71-75` | Expanded inclusive range |
| Prefix | `198.51.100.` | Hosts 1 through 254 |
| File | `targets.txt` | Non-comment lines become targets |
| Inventory text | `ZONE34` | Fixed-string search in selected flat DBs |
| DNS hostname | `switch.example` | `getent hosts` fallback |

The shorthand parser runs before flat-file search so dots cannot act as wildcard-like text. Octets are range checked.

### 8.3 Ambiguity

If inventory text matches multiple rows, an interactive helper displays numbered candidates when a terminal is available. In non-interactive contexts it fails rather than guessing.

Control behavior with:

```bash
netops ... --first
netops ... --all
netops ... --interactive
```

The Python wrapper translates `--first` and `--all` into `NETOPS_RESOLVE_MODE` for shell helpers. Not every action allows multiple targets, and broad writes remain unsafe even when resolution technically succeeds.

### 8.4 Global flags

| Flag | Meaning |
|---|---|
| `--json` | Structured output where supported |
| `--profile NAME` | Select an isolated profile for this process without changing the active profile |
| `--plain` | Prefer plain terminal rendering |
| `--no-tui` | Keep no-argument CLI help in an interactive terminal |
| `--no-color` | Disable ANSI color in helpers that honor `NO_COLOR` |
| `--dry-run` | Preview subprocess/operation without launching risky work |
| `--confirm` | Permit a guarded configuration change |
| `--approve` | Alias for `--confirm` |
| `--yes` | Parsed compatibility confirmation used by selected helper paths |
| `--limit N` | Bound returned rows where supported |
| `--since WHEN` | Time filter where explicitly supported |
| `--status STATUS` | Usually `ONLINE` or `OFFLINE` |
| `--site SITE` | Site/location filter where supported |
| `--source SRC` | Source filter where supported |
| `--timeout N` | Wrapper subprocess timeout |
| `--workers N` | Worker hint where supported |
| `--first` | Resolve first ambiguous match |
| `--all` | Resolve all ambiguous matches |
| `--interactive` | Allow interactive selection |
| `--depth N` | Bound VLAN or path traversal; Ghoster accepts 1-16 |
| `--max-nodes N` | Bound graph work; Ghoster accepts 1-256 |
| `--refresh-neighbors` | Refresh bounded neighbor evidence where the action supports it |

Do not assume every parsed flag changes every command. For example, `--since`, `--site`, and `--source` only matter on paths that implement those filters.

### 8.5 Exit codes

| Code | Meaning | Operator interpretation |
|---:|---|---|
| 0 | Success | Requested action completed |
| 2 | Usage | Invalid domain/action/arguments or ambiguous non-interactive target |
| 3 | Partial | Useful result with a condition needing attention; for example offline findings |
| 4 | Unreachable | Required host/service/tool path could not be reached |
| 5 | Unsupported | Feature/vendor/path is not supported |
| 6 | Validation | Input or safety policy rejected the request |
| 7 | Confirmation required | Add `--dry-run` or deliberate `--confirm` |
| 8 | Authentication | Credentials or authentication failed |
| 9 | Timeout | Operation exceeded its time budget |
| 10 | Internal | Missing core, unexpected exception, or internal failure |

Automation should inspect exit status, not parse colors or prose. Code 3 is not equivalent to a crash; it often means the check ran and found an operational problem.

### 8.6 JSON discipline

Use `--json` for scripts, then validate both the process exit code and fields such as `ok`, `error`, `count`, or `rows`. Some shell-backed commands provide text only or have different JSON completeness. Never parse table column spacing in durable automation.

Example:

```bash
netops inventory list ZONE10 --json
netops db integrity --json
netops ask "How many APs are offline in ZONE10?" --json
```

---

## 9. Safe First Run

The following sequence teaches the platform without changing a network device.

### 9.1 Confirm the installation

```bash
netops --help
netops help --json
netops init --profile lab
netops --profile lab profile paths
netops --profile lab db path
```

Check that the reported install, config, cache, and database paths belong to the intended service account.

### 9.2 Initialize and inspect SQLite

```bash
netops db migrate --json
netops db status --json
netops db integrity --json
```

Expected core conditions:

- schema version is `12`;
- `quick_check` contains `ok`;
- `integrity_check` contains `ok`.

### 9.3 Inspect existing state

```bash
netops inventory list --limit 20
netops ap list --limit 20
netops health status --limit 20
netops topology neighbors --limit 20
netops health attention --limit 20
```

Empty output on a new installation is normal. It means no flat data has been imported or discovered.

### 9.4 Import existing helper data

```bash
netops inventory import-flat --dry-run
netops inventory import-flat --json
netops memory refresh --json
```

Import writes only local SQLite state, but use dry-run first to verify the selected deployment and paths.

### 9.5 Preview active discovery

```bash
netops inventory scan ZONE10 --dry-run
netops health check ZONE10 --dry-run
netops topology scan --dry-run
```

Then run only after confirming scope, credentials, timeout, worker count, and network authorization.

### 9.6 Preview a write guard

```bash
netops vlan set 198.51.100.71 Gi1/0/7 --access 120 --dry-run --json
```

The output must show a command preview and `dry_run: true`; it must not connect to the device.

### 9.7 Open the local console

```bash
netop tui
```

Opening the console reads only local canonical state and starts on the Action
Hub. Use Functions to request Status overview or Configuration when needed.
The complete console workflow is in `docs/operator-console.md`.

### 9.8 Validate extension surfaces

These commands inspect local configuration only and are safe on a fresh
profile:

```bash
netops --profile lab config validate
netops --profile lab ingest validate
netops --profile lab plugin groups
netops --profile lab plugin list
netops --profile lab device support
```

Do not enable a plugin merely because discovery found it. Confirm its package
source and version, review the code as trusted local Python, then enable the
exact `<group>:<name>` in a disposable profile first.

---

## 10. Inventory Commands

Inventory covers switches, routers, and the combined canonical search view.

### 10.1 `inventory scan`

```text
netops inventory scan [target|CIDR|range]
```

Examples:

```bash
netops inventory scan
netops inventory scan 203.0.113.0/24
netops inventory scan 198.51.100.20-60
netops inventory scan ZONE10 --dry-run
```

Behavior:

1. Delegates to device discovery.
2. Uses configured subnets when no target is given.
3. Generates candidate IPs for a single IP, shorthand, range, prefix, or CIDR.
4. Pings candidates and uses SNMP for system name, description, object identity, serial/model/MAC where available.
5. Classifies Cisco, Aruba, Ruckus, Juniper, and generic devices from returned evidence.
6. Preserves useful SSH enrichment when merging refreshed observations.
7. Updates `devices.db` and status/timestamps.
8. Imports the refreshed flat files into SQLite and recomputes derived state after successful v8 execution.

Operational cautions:

- A full prefix can generate 254 probes.
- High `scan_workers` can create a burst of ping/SNMP traffic.
- A missing or wrong SNMP community can make reachable devices appear under-enriched.
- A no-target scan inherits `subnets`; verify that value before execution.
- CIDR generation depends on platform tooling and deserves a dry-run in a new environment.

### 10.2 `inventory list`

```text
netops inventory list [pattern] [--status ONLINE|OFFLINE] [--site SITE]
```

Examples:

```bash
netops inventory list
netops inventory list ZONE10
netops inventory list --status OFFLINE
netops inventory list 192.0.2 --json --limit 100
```

This is a local canonical SQLite query. It searches device and reconciled AP fields, applies status/site filters where implemented, and does not contact the network.

Interpret raw versus canonical counts carefully: device rows are current observations; AP results are reconciled physical identities. `ap_observations` can exceed the canonical `aps` count.

### 10.3 `inventory show`

```text
netops inventory show [pattern]
```

This is an alias for the canonical list/search path. Use it for quick lookup, not SSH enrichment.

### 10.4 Manual device lifecycle merge

Use a manual merge when an old active record and its verified replacement are
one operational asset lifecycle but physical evidence correctly prevents an
automatic merge:

```bash
netops inventory merge SITE-A-OLD-SW01 SITE-A-ACCESS-01 \
  --reason "approved hardware replacement" --dry-run
netops inventory merge SITE-A-OLD-SW01 SITE-A-ACCESS-01 \
  --reason "approved hardware replacement" --confirm
netops inventory merges
```

The first argument is the historical source; the second is the current target.
Both must resolve to distinct active device rows. A reason is mandatory. Always
review the dry run, especially when valid MAC or serial evidence conflicts.

Applying a merge:

- removes the source from active `devices` and health state;
- retains its snapshots and identities in `inventory_history` and
  `inventory_identity_state` with an explicit historical state;
- adds an audited `manual_identity_merge` relationship;
- exposes the old name and address as historical aliases on the target;
- suppresses a matching stale source if a later flat-file or ingest refresh
  tries to materialize it again;
- records RFC 3339/ISO 8601 display timestamps and the suppression count.

This is a lifecycle decision, not a claim that two conflicting physical MACs
are the same hardware. The TUI/action hub exposes a preview only; application
requires the explicit CLI `--confirm` gate.

To inspect or reverse the decision:

```bash
netops inventory merges --all --json
netops inventory unmerge mrg-example \
  --reason "association was incorrect" --confirm
```

Unmerge restores the captured source only when its former IP is not now owned
by a different device. It never deletes the merge or its audit/history record.

### 10.5 `inventory details`

```text
netops inventory details <target>
```

Examples:

```bash
netops inventory details sq34
netops inventory details 198.51.100.92 --json
```

The output mode changes behavior:

- JSON uses canonical SQLite state and returns one device/AP record plus history, relationships, health, and backups.
- Plain output delegates to the legacy detailed view and may perform SSH enrichment/network reads.

Use `--json` when you need a guaranteed local-state inspection. Do not assume plain `details` is passive.

### 10.6 `inventory activity`

```text
netops inventory activity --file devices.txt
netops inventory activity <target...>
```

Input-file rules:

- one hostname or IP per line;
- blank lines ignored;
- lines beginning with `#` ignored.

The helper resolves one canonical inventory snapshot, performs independent ping
probes with a bounded worker pool, and prints offline records first and online
records second. It is useful for a controlled watch list that should not
trigger deep discovery.

### 10.7 `inventory import-flat`

```text
netops inventory import-flat
```

Imports `devices.db`, `ap_devices.db`, and `neighbor.db`, performs MAC cleanup and AP reconciliation, writes canonical tables, and synchronizes identity, health, topology, AP movement, and relationship state.

Run it after out-of-band helper changes or when moving an existing flat-file deployment into v8.

### 10.8 `inventory export-flat`

```text
netops inventory export-flat
```

Exports canonical current state to the three compatibility files. It is a local write and can affect subsequent helper resolution. Back up the existing flat files before using it during migration troubleshooting.

---

## 11. Access Point Commands

### 11.1 `ap scan`

```text
netops ap scan
```

The AP scan combines available sources:

- Cisco WLC SNMP inventory;
- optional Cisco WLC SSH join statistics;
- Ruckus vSZ SNMP inventory;
- optional direct AP model SNMP;
- LLDP/CDP AP observations from switches;
- prior AP observations used to preserve continuity and mark unmatched rows offline.

Controller filters are controlled by the WLC prefix/name settings. An AP excluded by those filters is absent, not necessarily offline.

The merge process updates `ap_devices.db`; v8 then imports and reconciles canonical APs. Source records can have controller attachment context without a physical port. Switch LLDP/CDP evidence is stronger for a physical port.

### 11.2 `ap list`

```text
netops ap list [pattern] [--status ONLINE|OFFLINE]
```

Examples:

```bash
netops ap list ZONE10
netops ap list Cisco --status OFFLINE
netops ap list --json --limit 200
```

Search includes AP names, aliases, addresses, platform, switch name, and port. Results are canonical identities, not raw controller rows.

### 11.3 `ap show`

```text
netops ap show [pattern]
```

This is a quick alias for `ap list`.

### 11.4 `ap unjoined`

```text
netops ap unjoined [pattern] [--limit N]
```

Shows Cisco WLC observations from join statistics that are not currently joined. It depends on:

- `cisco_wlc_join_stats=true`;
- a configured WLC;
- SSH credentials and `sshpass`;
- a WLC output format matched by the parser.

An empty result can mean no unjoined APs, disabled collection, failed SSH, filtered names, or parser drift. Check scan logs before declaring success.

### 11.5 `ap on-switch`

```text
netops ap on-switch <switch>
```

Examples:

```bash
netops ap on-switch ZONE10
netops ap on-switch SITEAZONE34SW01 --json
```

Combines canonical AP inventory and relationship memory to find APs associated with a switch name, IP, short name, or site token. Review `source`, `switch_ip`, `switch_port`, and confidence before treating the result as cabling proof.

### 11.6 `ap moves`

```text
netops ap moves [--limit N]
```

Lists recorded attachment changes. A move can be a real recable, controller/source correction, AP rename/reconciliation effect, or data disappearance/reappearance. Correlate it with topology, scan timestamps, and source.

### 11.7 `ap timeline`

```text
netops ap timeline [target]
```

Searches AP relationship and attachment history by AP name, IP, MAC, alias, or related text. Use canonical aliases when names changed.

---

## 12. Topology Commands

### 12.1 `topology scan`

```text
netops topology scan
```

Queries known switches for LLDP/CDP neighbors, parses local/remote port and identity fields, resolves remote IPs from inventory where possible, writes `neighbor.db`, imports it into SQLite, and compares the current link set with the previous snapshot.

Each tuple `(local_ip, local_port, remote_name, remote_port, remote_ip)` is treated as a link identity. A changed name or unresolved IP can therefore appear as remove-plus-add rather than an in-place edit.

### 12.2 `topology show`

```text
netops topology show [target]
```

- Without a target, reads cached topology links.
- With a target in plain mode, it may open the legacy topology view and orient a breadth-first diagram relative to `core_switch_ip`.
- JSON paths use canonical cached state.

The diagram's upstream/downstream interpretation depends on a correct configured core and complete neighbor data.

### 12.3 `topology neighbors`

```text
netops topology neighbors [target]
```

Lists cached raw neighbor rows, optionally filtered. This is the best first command when the graph seems wrong because it exposes the source link records before graph layout.

### 12.4 `topology changes`

```text
netops topology changes [--limit N]
```

Shows `link_added` and `link_removed` events. A scan that is partial, unauthenticated, or interrupted can produce apparent removals; validate scan completeness before escalating.

### 12.5 `topology timeline`

```text
netops topology timeline [target]
```

Reads neighbor relationship events, useful for reconstructing changes around one switch or site.

---

## 13. Relationship Memory Commands

Memory is the historical knowledge layer. It connects observations that inventory tables alone cannot answer, such as who used an IP before, where an AP was attached, or what occupied a port.

### 13.1 `memory refresh`

```text
netops memory refresh
```

Recomputes desired relationships from current devices, reconciled APs, neighbors, and core lookup observations. It updates current relationships and emits appeared/changed/disappeared events.

Run it after a manual SQLite import or repair. Normal v8 scans already refresh canonical state after helper completion.

### 13.2 `memory switch`

```text
netops memory switch <switch>
```

Returns:

- matching switch context;
- attached canonical APs;
- topology neighbors;
- current relationships;
- recent relationship timeline.

This is the most complete single-switch investigation command.

### 13.3 `memory device`

```text
netops memory device <name|ip>
```

Shows relationships in which the described device/AP appears as subject, object, or serialized attributes, plus matching history.

### 13.4 `memory ip`

```text
netops memory ip <ip>
```

Shows current IP ownership and historical events. An IP can legitimately have different owners over time; compare event timestamps and sources instead of assuming the latest text match is permanent.

### 13.5 `memory mac`

```text
netops memory mac <mac>
```

Accepts common colon, hyphen, dotted, and compact forms through normalization. It shows identity and movement history. Placeholder/multicast/broadcast MACs are intentionally excluded from canonical identity.

### 13.6 `memory port`

```text
netops memory port <switch> <port>
```

Examples:

```bash
netops memory port ZONE34 Gi1/0/7
netops memory port 198.51.100.92 7
```

Numeric ports are matched as an interface suffix in the API payload path; explicit interface names are safer when devices have multiple slot/module forms. Results include current occupancy and prior events.

### 13.7 `memory timeline`

```text
netops memory timeline [target]
```

Searches all relationship events. Use a narrow target and an explicit `--limit` on mature databases.

### 13.8 `memory explain`

```text
netops memory explain [target]
```

Summarizes relationship sources and average confidence. Use it to answer, "Why does NetOps believe this?" It does not independently verify the evidence.

### 13.9 `memory export`

```text
netops memory export --json
```

Exports current relationships. JSON is the appropriate format for analysis, graphing, and external audit.

### 13.10 `memory prune`

```text
netops memory prune
```

This action is reserved and disabled. Relationship history is retained indefinitely in the current implementation. Plan database growth and archival externally.

### 13.11 Time and chronology semantics

Memory and history preserve integer Unix epoch seconds in SQLite and JSON for compatibility. Human-facing CLI, TUI, and WebUI dates use ISO 8601 UTC:

```text
2026-01-15T12:34:56Z
```

Interpret the fields precisely:

- `first_seen` is when the current relationship was first entered into memory.
- `last_seen` is when the current canonical observation or relationship was most recently reconciled as present.
- `updated_at` is when the current-state row was last rewritten or changed.
- Event `created_at` is when NetOps recorded that transition; API event rows also expose `recorded_at_iso`.
- Current rows expose additive `first_seen_iso`, `last_seen_iso`, and `updated_at_iso` fields when those source values exist.
- Memory and event-history responses identify `chronology` as `newest_first`; `version 1` is the latest row.

`last_seen` is not guaranteed to be a fresh network poll. `memory refresh` can reconcile relationships from already-cached inventory, AP, and topology data. To prove current device state, run the relevant inventory/AP/topology/health operation first, confirm it completed, and then inspect memory. The existing `scan_runs` table does not yet provide complete per-target live-poll provenance.

---

## 14. Health Commands

### 14.1 `health check`

```text
netops health check [target]
```

Examples:

```bash
netops health check
netops health check ZONE10
netops health check 198.51.100.71 --json
```

This is a fast reachability refresh, not deep inventory discovery. It pings known or supplied devices/APs, updates flat status and timestamps, imports state, and updates health history.

Use it when you need a current online/offline view without waiting for SNMP, controller, and LLDP enrichment.

Limitations:

- ICMP blocking can produce false offline status.
- A successful ping does not prove SNMP, SSH, forwarding, controller join, or application health.
- A hostname can resolve differently from the address stored in inventory.

### 14.2 `health status`

```text
netops health status [--limit N]
```

Reads current `health_state`, ordered to surface offline/attention/failure statuses and high flap counts.

### 14.3 `health offline`

```text
netops health offline [--limit N]
```

Lists current offline devices and APs. The command can return exit code 3 when rows are found: the query succeeded, but its result indicates an operational problem.

### 14.4 `health attention`

```text
netops health attention [--limit N]
```

Aggregates health, topology, AP movement, backup, and diagnostic signals into a review list. Investigate source recency before treating every item as a live incident.

### 14.5 `health timeline`

```text
netops health timeline [--limit N]
```

Shows first-seen and status-change events. `flap_count` is cumulative for the current entity identity; it is not automatically reset after a quiet period.

---

## 15. Backup Commands

Backups are remote reads plus local writes. The supported v8 path skips known-offline targets, hashes normalized output, and avoids rewriting unchanged configuration.

### 15.1 `backup run`

```text
netops backup run <target> [--redact-secrets]
```

Examples:

```bash
netops backup run ZONE34
netops backup run 198.51.100.92 --redact-secrets
netops backup run ZONE10 --dry-run
```

The v8 wrapper always supplies internal `--online-only`, `--changed-only`, and `--summary` behavior.

Per target, the helper:

1. Resolves the target through inventory.
2. Skips rows currently marked offline.
3. Verifies enough platform context for Cisco or Aruba behavior.
4. Retrieves running configuration over SSH.
5. Removes terminal/control noise.
6. Optionally applies regex-based redaction.
7. Computes SHA-256 over the resulting content.
8. Compares it with the latest saved hash for that device IP.
9. Records an `unchanged` history row without creating another config file when hashes match.
10. Writes a timestamped file when changed.
11. Updates `<hostname>.latest.conf` as a symlink.
12. Records status, changed flag, hash, path, size, and message in SQLite.

The backup directory is organized into date-oriented paths by the helper. Verify the resolved path with a dry-run and `db path`, especially when Python overrides and shell `HOME` differ.

### 15.2 Secret redaction

`--redact-secrets` masks common tokens following terms such as password, secret, key-string, community-string, SNMP community, pre-shared key, WPA PSK, and RADIUS key.

It is best-effort regular-expression redaction. It can miss:

- vendor-specific syntax;
- multiline secrets;
- certificates and private keys;
- encoded credentials under unfamiliar labels;
- usernames, addresses, or other sensitive topology data.

Treat every backup as sensitive even when redaction is enabled.

### 15.3 `backup history`

```text
netops backup history <target>
```

Shows recent backup results for a resolved device. The underlying direct shell function chooses its SQLite path from root/non-root defaults and does not honor `NETOPS_SQLITE_DB`; see the known path-consistency defect.

### 15.4 `backup diff`

```text
netops backup diff <target>
```

Diffs the two latest successfully saved backups whose `changed` flag is 1. Unchanged history entries are skipped. A missing diff usually means fewer than two changed saved configurations, not necessarily a backup failure.

### 15.5 `backup verify`

```text
netops backup verify [--limit N]
```

Despite the verb, v8.5.0b2 primarily displays backup metadata recorded in SQLite. It does not perform full restore validation, parse every configuration, or reconnect to prove the file can be applied. Verify file existence and SHA-256 independently for audit-grade restoration.

### 15.6 Restore procedure

NetOps has no automated restore command. A controlled restore should be manual:

1. Identify the target by exact IP, serial, and hostname.
2. Use `backup history` and `backup diff` to choose a version.
3. Verify the file hash against `backup_history`.
4. Review and remove prompts, redactions, or unsupported lines.
5. Back up the current device configuration again.
6. Generate a staged configuration plan.
7. Preview through `netops device config ... --dry-run` where feasible.
8. Apply during an approved change window with console/out-of-band recovery.
9. Verify connectivity, intended state, and saved configuration.

Do not feed a redacted backup directly back to a device.

---

## 16. Device and VLAN Commands

### 16.1 `device ssh`

```text
netops device ssh [-l|--legacy] <target>
```

Examples:

```bash
netops device ssh ZONE34
netops device ssh 198.51.100.92
netops device ssh --legacy ZONE34
```

Flow:

1. `netops-connect` resolves exactly one target unless resolution mode says otherwise.
2. It validates that the active profile has a non-empty, whitespace-free `ssh_user`; missing configuration fails before vault authentication or transport access.
3. It decrypts the local SSH password vault into `SSHPASS`.
4. It opens `sshpass -e ssh -tt -l <user> <host>`, keeping username and host as separate OpenSSH arguments.
5. It applies `strict` or `accept-new` against the private NetOps known-hosts file; a changed key fails closed.
6. If negotiation reports old algorithms, it suggests retrying with `--legacy`.

Legacy mode asks the installed OpenSSH client which old Diffie-Hellman groups,
host-key algorithms, AES/3DES-CBC ciphers, and HMACs are still available, then
appends only that filtered set while retaining modern defaults. Negotiation
errors distinguish KEX, host key, cipher, MAC, generic negotiation, SSHv1,
authentication, and host-trust failures. SSHv1 is never enabled. Use legacy
mode only for devices that cannot be upgraded; those algorithms weaken
connection security.

For automated Aruba and RUCKUS command streams, the helper can use the Expect
wrapper. That wrapper detects `#` or `>` prompts, handles a "Press any key"
screen, removes ANSI/echo noise, sends commands, and logs out. The same filtered
legacy options are passed to the actual spawned SSH process. It filters
caller-supplied `exit` and confirmation-only `y` lines because it owns session
logout. It requires both `CREDS_ssh_user` and `SSHPASS` in its environment.

### 16.2 `device support` and `device identity`

```text
netops device support [target]
netops device identity <first-target> <second-target>
```

With no target, `support` lists every registered family, vendor, operating
system, device kind, and maturity level. With a target, it resolves current
inventory, shows detection evidence, and lists exact capability states. Use it
before assuming that a successful SSH login implies parser or write support.

`identity` compares two uniquely resolved switch/device records. It reports
normalized names, the 75 percent switch threshold, matching MAC/serial/IP/model
signals, conflicts, candidate state, same-device verdict, and confidence. It is
an explanation tool; it does not manually force two records together.

The normative support matrix and extension procedure are in
`docs/device-support.md`.

### 16.3 `device trust`

```text
netops device trust-status [target]
netops device trust-scan <target>
netops device trust-enroll <target> --fingerprint SHA256:VALUE --confirm
netops device trust-forget <target> --confirm
```

`trust-status` is local-only. `trust-scan` retrieves current keys without
enrolling them. `trust-enroll` accepts only scanned keys whose SHA-256
fingerprints exactly match independently verified values, writes the private
store atomically, and audits the enrollment. `trust-forget` removes all aliases
for the resolved host after confirmation and audits the removal. See section
6.6 for the production procedure.

### 16.4 `device show`

```text
netops device show <target> <show-command>
```

Examples:

```bash
netops device show ZONE34 show version
netops device show 198.51.100.92 "show interface status"
```

The v8 policy permits commands beginning with read-like verbs such as `show`, `sh`, `display`, or `get`, then blocks separators, shell escapes, configuration transitions, secret-bearing outputs, running configuration, tech-support bundles, and other risky patterns.

Examples of policy rejection:

```bash
netops device show ZONE34 "show running-config"
netops device show ZONE34 "show version ; reload"
```

The public block occurs before device access and returns validation code 6. Direct `netops-control show` independently rejects separators, configuration transitions, sensitive-output forms, missing/extra command arguments, and unsupported verbs with usage code 2; it is no longer a route around the read-only policy.

### 16.5 `device inventory`

```text
netops device inventory [target|--view]
```

- `--view` displays the shell inventory database.
- A target performs SSH inventory enrichment and merges platform/model/serial data.

This path is distinct from `inventory list`, which is canonical/local. Use it when SNMP could not supply sufficient identity and an SSH read is authorized.

### 16.6 `device config`

```text
netops device config <target> <commands...> --dry-run|--confirm
```

Example:

```bash
netops device config 198.51.100.92 \
  "interface Gi1/0/7" \
  "description AP-ZONE34-07" \
  --dry-run
```

Only after review:

```bash
netops device config 198.51.100.92 \
  "interface Gi1/0/7" \
  "description AP-ZONE34-07" \
  --confirm
```

Important behavior:

- Without either flag, it exits 7.
- `--dry-run` prints the exact helper command and makes no connection.
- `--confirm` invokes the shell command stream.
- The Cisco driver enters configuration mode and automatically saves the
  configuration.
- Direct helper write modes are blocked. Editor, pipe, and snippet parsing are
  implementation details reachable only after the core supplies its internal
  audited-confirmation capability.
- Aruba AOS-S, Aruba AOS-CX, RUCKUS FastIron, SmartZone, AP, and unknown drivers
  report configuration as unsupported and fail before transport when the
  inventory family is known.
- There is no rollback if command N fails after commands 1 through N-1 succeed.

Cisco configuration remains model/firmware sensitive. A successful preview
proves construction and policy only; validate syntax and recovery explicitly.

### 16.7 `vlan locate`

```text
netops vlan locate <target-list> <vlan-list> [--depth 0-10] [--max-nodes 1-256]
```

One target and one VLAN without `--depth` preserve the original one-switch
helper behavior. Multiple targets or VLANs use the structured cascade engine
even at depth 0.

```bash
netops vlan locate SW1 10,20-22
netops vlan locate SW1,SW2 10,20 --depth 3
netops vlan locate --target SW1 --target SW2 --vlan 10,20-22 --depth 3
```

The limits are 16 roots and 128 distinct VLANs. Comma-separated IDs and
ascending ranges are accepted. Repeated `--target`/`--device` and `--vlan`
options avoid ambiguity when names contain unusual punctuation. The final
matrix has one row per root/VLAN pair; JSON includes every independent run.

With `--depth`, it becomes a bounded recursive location workflow:

```bash
netops vlan locate site-a-core 131 --depth 5
netops vlan locate site-a-core 131 --depth 5 --max-nodes 40 --json
netops vlan locate site-a-core 131 --depth 5 --refresh-neighbors
netops vlan locate site-a-core 131 --depth 5 --dry-run
```

The root switch is layer 0. A depth of 5 means NetOps inspects the root and reachable switch neighbors through layer 5, a maximum of five switch-to-switch hops from the root. Switches at layer 5 are inspected, but their neighbors are not followed. The hard depth cap is 10.

The cascade resolves the root uniquely from canonical inventory/aliases, then performs breadth-first traversal. At each switch it:

1. Runs the existing VLAN inspection through `netops-control` over SSH.
2. Parses VLAN definition, access ports, trunks, and whether each reported trunk carries the VLAN.
3. Treats the established one-switch helper report as authoritative for VLAN and trunk state. A nonzero aggregate helper status does not invalidate a report that contains a parsed `DEFINED` or `NOT DEFINED` result and no inspection error.
4. Correlates reported trunk names against cached topology in both directions.
5. Runs live LLDP/CDP detail commands when topology is missing, when a reported trunk has no cached match, or whenever `--refresh-neighbors` is set.
6. Deduplicates equivalent LLDP/CDP observations by normalized local interface and remote device identity.
7. Follows only neighbors with credible switch evidence and a safely resolved device/IP. Phones, APs, and other endpoints are excluded from recursive targets and do not generate switch-resolution warnings.
8. Uses additional topology switch links only to continue traversal; it never invents a trunk or VLAN-propagation result from topology alone.
9. Suppresses already visited or already queued devices so physical loops do not create recursion loops.
10. Stops at `--depth` or `--max-nodes`; the node default is 64 and hard cap is 256.

`--refresh-neighbors` favors current link evidence but adds LLDP/CDP SSH
commands at every inspected switch. `--dry-run` resolves roots and prints the
intended bounds without opening device transport. `--limit` limits displayed
findings, not traversal. Command selection covers Cisco IOS, Aruba AOS-S,
Aruba AOS-CX, and RUCKUS FastIron; exact firmware compatibility remains tied to
accepted fixtures.

### 16.8 `vlan propagation`

```text
netops vlan propagation <target-list> <vlan-list> [--depth 0-10] [--max-nodes 1-256]
```

The one-switch form examines trunks/uplinks for VLAN propagation. The recursive form applies that inspection to every safely reachable switch layer:

```bash
netops vlan propagation site-a-core 131 --depth 5
netops vlan propagation site-a-core 131 --depth 5 --max-nodes 40 --json
netops vlan propagation site-a-core 131 --depth 5 --refresh-neighbors
netops vlan propagation site-a-core,plant-sw 10,20-22 --depth 5
```

The final report has two parts. **Switch path** records every inspected node with an explicit VLAN result. **Findings** contains only actionable VLAN gaps, inspection failures, unresolved switch targets, or traversal-budget warnings. A clean cascade says `No VLAN gaps or inspection failures found.` rather than printing endpoint noise.

| Result/code | Meaning |
|---|---|
| `PRESENT` | The VLAN is defined and no reported trunk is missing it |
| `ABSENT` | The one-switch helper reports that the VLAN is not defined |
| `TRUNK GAP` | The VLAN is defined, but at least one reported trunk does not carry it |
| `FAILED` / `INSPECTION_FAILED` | SSH/helper/parser inspection produced no usable VLAN result |
| `VLAN_NOT_DEFINED` | The VLAN is not defined on that switch |
| `VLAN_MISSING_ON_TRUNK` | A reported trunk does not carry the VLAN |
| `NEIGHBOR_DEVICE_UNRESOLVED` | Credible switch-neighbor evidence exists but is not a safe resolvable SSH target |
| `NODE_BUDGET_REACHED` | Traversal stopped at `--max-nodes` |

The plain table deliberately does not expose the older internal `state` label, which mixed execution quality with VLAN condition and could make an online switch with a valid parsed report look broken. It shows `VLAN` (`defined`, `not defined`, or `unknown`), access count for locate mode, reported trunk count, gap count, and `RESULT`. The legacy `state` field remains in JSON for compatibility; new integrations should use `result`, `defined`, `error`, and the explicit counters.

In JSON, evaluate the status dimensions separately:

- `ok` means switch inspections completed without parser/transport errors.
- `healthy` means no critical absent-VLAN or trunk-gap finding was observed.
- `complete` means there were no inspection errors, unresolved switch links, or node-budget truncation.
- `counts.present_nodes`, `counts.missing_nodes`, `counts.trunk_gaps`, and `counts.inspection_errors` are the primary aggregate measurements.
- `counts.switch_links` counts unique physical switch pairs; `counts.switch_link_observations` retains directional/interface observations for diagnosis.

A successful process exit means the inspection ran; it does not mean propagation is healthy. Automation must inspect `healthy`, `complete`, and `findings`. The workflow never adds a VLAN or changes a trunk.

Progress lines such as `[VLAN] 2/5 inspect SWITCH-NAME (192.0.2.2)` and `[VLAN] 2/5 SWITCH-NAME: VLAN 131 defined; trunks=2 gaps=0 next-switches=1` go to stderr and are flushed immediately. Locate mode also includes the access-port count. The CLI keeps the final report on stdout, while TUI jobs show progress in Activity and WebUI/API jobs expose it through SSE. This keeps concise progress visible without interleaving it into the final table or JSON document.

The underlying helper still uses VLAN 4 as one uplink-indicator heuristic. That is environment-specific and can misclassify networks where VLAN 4 is absent, local, or used differently. The recursive layer may use credible LLDP/CDP switch links to reach the next layer, but it does not count those links as trunks or assign them a propagation result unless the existing helper reports that evidence.

### 16.9 `vlan set`

```text
netops vlan set <target> <interface> [--access N|--trunk LIST] --dry-run|--confirm
```

Examples:

```bash
netops vlan set 198.51.100.92 Gi1/0/7 --access 120 --dry-run
netops vlan set 198.51.100.92 Gi1/0/48 --trunk 10,20,120 --dry-run
netops vlan set 198.51.100.92 Gi1/0/48 --trunk 10,20,120 --native 10 --dry-run
```

The public path validates interface syntax, access VLANs, trunk lists/ranges,
optional native VLAN, and `--replace`. Dry-run renders the exact intent and four
phases without network access. Confirmed execution uniquely resolves the device,
captures current interface evidence, requires a successful changed-only backup,
applies through the internally authorized helper, reads VLAN/interface evidence
back, and records an audit event. Preflight/backup failure blocks apply; apply or
verification failure returns partial/attention with retained manual-rollback
evidence.

Access changes and trunk requests containing at most eight VLAN IDs verify every
requested VLAN. Larger trunk ranges verify deterministic first/last boundary
samples and always return `ATTENTION` with `verification_complete: false`, even
when those samples pass. Complete the remaining verification manually; sampled
evidence never qualifies as full success.

The TUI additionally binds approval to reason, ticket, exact phrase, and preview
hash. VLAN writes are currently approved only for the Cisco driver. Known Aruba
and RUCKUS targets fail closed before preflight/backup/apply transport; their
read support does not imply write support.

---

## 17. Lookup and Diagnostic Commands

### 17.1 `lookup core`

```text
netops lookup core <ip|mac>
```

Examples:

```bash
netops lookup core 198.51.100.92
netops lookup core 0200.0000.0025
```

The structured workflow resolves `core_switch_ip`, detects its registered
driver, reads ARP, reads the forwarding table, and inspects the learned
interface description. Cisco IOS, Aruba AOS-S, Aruba AOS-CX, and RUCKUS
FastIron select their own command and MAC-format forms. An unknown core is
probed with `show version`; if it remains unknown, the workflow returns
unsupported instead of assuming Cisco syntax.

The result includes stage commands, exit codes, parsed ARP/FDB rows, driver,
port, VLAN, description, and an ISO 8601 UTC observation time. Evidence is
cached as a `core_lookup` observation and a forwarding hit updates MAC-location
history. This is evidence from a point in time, not continuous truth.

### 17.2 `lookup mac`

```text
netops lookup mac <inspect|locate|profile|history|vendor|online|registry> ...
```

Examples:

```bash
netops lookup mac inspect 0200.0000.0025
netops lookup mac locate 0200.0000.0025 ZONE34
netops lookup mac locate 0200.0000.0025 --site ZONE34 --limit 50
netops lookup mac profile 0200.0000.0025 ZONE34
netops lookup mac history 0200.0000.0025 --limit 100
netops lookup mac vendor 00:00:5e:00:53:01
netops lookup mac online 00:00:5e:00:53:01
netops lookup mac online 00:00:5e:00:53:01 --refresh
netops lookup mac registry status
netops lookup mac registry refresh
```

The MAC may use colon, hyphen, dotted, or plain hexadecimal notation. NetOps normalizes it to a canonical physical-unicast identity.

| Subcommand | Network access | What it does |
|---|---|---|
| `inspect` | None | Correlates cached inventory, AP, relationship, core-lookup, IP, OUI, and movement evidence |
| `locate` | SSH reads | Searches switch forwarding/CAM tables directly, even when the endpoint has no IP |
| `profile` | SSH reads | Runs `locate`, then profiles up to three likely edge ports using interface, LLDP/CDP, PoE, tracking/authentication, and core evidence |
| `history` | None | Shows newest-first `first_seen`, `moved`, and evidence-change records with ISO 8601 UTC timestamps |
| `vendor` | None | Looks up the locally installed OUI prefix; no Internet lookup is required |
| `online` | HTTPS when cache is missing/stale | Uses the longest matching official IEEE MA-L, MA-M, or MA-S assignment and reports provenance |
| `registry status` | None | Shows cache paths, rows, checksums, and recorded refresh time |
| `registry refresh` | HTTPS | Atomically refreshes all three official IEEE public CSV registries |

The IEEE cache directory is private (`0700`), data/manifest files are `0600`,
downloads are size bounded and CSV-schema validated, replacements are atomic,
and SHA-256 plus ISO 8601 UTC fetch times are recorded. The default freshness
period is seven days. `--offline` forbids refresh; `--refresh` forces one. A
failed refresh does not destroy an existing stale cache.

`locate` with no scope searches current non-offline inventory switches, bounded by `--limit` (default 100). A positional scope such as `ZONE34` must resolve to exactly one switch. `--site ZONE34` filters the all-switch target set. Use `--dry-run` to list the exact targets and helper commands without opening SSH.

Every forwarding-table hit records switch, interface, VLAN, entry type, source, confidence, and observation time as a `mac_location` relationship. A change to another switch/port creates a `moved` event. `history` and `inspect` are therefore chronological views, not just the latest answer. Plain tables render dates as `YYYY-MM-DDTHH:MM:SSZ`; JSON retains epoch fields and adds matching `_iso` fields.

NetOps classifies a hit on a topology-known inter-switch port as `switch-link`; other hits are `edge-candidate`. The likely physical endpoint is usually the furthest credible edge candidate, not every upstream CAM hit. `profile` gathers extra evidence only on the first three edge candidates to bound SSH load.

#### What a MAC can and cannot prove

A MAC table can locate a Layer-2 device without ARP, DHCP, or any known IP. Therefore a hit with no IP correlation is consistent with a device that is connected but has not obtained an address. It is not proof that the device is currently powered or functional: dynamic entries age out, may remain briefly after disconnect, and a silent endpoint may disappear from the table.

OUI/IEEE assignment data identifies the registered manufacturer/organization,
not an exact model. NetOps checks 36-bit MA-S and 28-bit MA-M assignments as
well as traditional 24-bit MA-L/OUI data. A more specific model hint is
possible only when LLDP/CDP, inventory, port description,
authentication/device-tracking, or another local observation supplies it.
Locally administered/randomized MACs have no authoritative IEEE manufacturer
assignment. NetOps reports these as evidence and hints, not certainties.

The older direct forms remain for compatibility:

```bash
netops lookup mac CORE01 0200.0000.0025
netops lookup mac all 0200.0000.0025 --limit 50
```

They query one switch or all current switches but provide less correlation than `locate`/`profile`. Prefer the explicit subcommands for new procedures.

### 17.3 `diagnose latency`

```text
netops diagnose latency <target> [--count N]
```

Examples:

```bash
netops diagnose latency 1.1.1.1
netops diagnose latency ZONE34 --count 10
netops diagnose latency 198.51.100.92 --count 5 --json
```

Default terminal mode is continuous until interrupted. Finite mode reports sent/received/loss, min/average/max latency, and average absolute consecutive latency difference as jitter. JSON mode is always finite and defaults to five samples when no count is provided.

The probe helper can also perform TCP-port timing internally, print timestamped bar output, force/auto-run traceroute, beep on loss, collect background metadata, and offer an interactive SSH handoff. Those are mostly legacy helper options rather than fully surfaced v8 action flags.

### 17.4 `diagnose core-ping`

```text
netops diagnose core-ping <target> [--core <switch>] [--count 1-20] [--packet-timeout 1-10]
```

Examples:

```bash
netops diagnose core-ping 192.0.2.50 --count 5
netops diagnose core-ping ZONE34 --core CORE01 --count 10
netops diagnose core-ping 192.0.2.50 --dry-run --json
```

This is the point-of-truth probe requested from the network core rather than from the NetOps host. The destination can be an IP or an inventory name that resolves to an IP. The source is `--core` when supplied, otherwise `core_switch_ip`/`core_switch` from configuration. A named core must resolve uniquely; a literal configured core IP can be used before it is imported into inventory.

NetOps selects read-only device syntax from the core platform: Cisco-style `ping ... repeat ... timeout ...` or Aruba-style `ping ... repetitions ...`. If the inventory platform is unknown, it first reads `show version` and makes a best-effort vendor selection. It parses transmitted/received packets, loss, and minimum/average/maximum latency.

Each completed measurement is stored in `probe_results` with mode `core-ping:<core-ip>`, the raw structured payload, and an ISO 8601 UTC observation companion. This makes the core vantage point distinguishable from a host-origin latency probe in diagnostic history.

Interpret it as a measurement from one routing point, not universal reachability. ICMP policy, VRFs, source-interface selection, control-plane policing, and vendor output differences can affect the result. The current action does not expose VRF or source-interface options. `--dry-run` resolves source/destination and bounds but does not contact the core.

### 17.5 `diagnose speed`

```text
netops diagnose speed [--profile quick|balanced|thorough] [--runs N] [--ca-file <PEM>]
```

Examples:

```bash
netops diagnose speed
netops diagnose speed --profile quick
netops diagnose speed --profile thorough --runs 5
netops diagnose speed --runs 5
netops diagnose speed --runs 3 --json
netops diagnose speed --profile balanced --dry-run
```

This measures the routed path from the machine running NetOps to Internet benchmark servers. It does **not** measure an arbitrary endpoint merely because that endpoint is connected to a named switch port.

Speed profiles trade runtime for confidence:

| Profile | Default runs | Purpose | Reliability meaning |
| --- | ---: | --- | --- |
| `quick` | 1 | Fast path check when you need a timely read | Fresh upload/download/loaded latency from one complete server; tries only a small candidate budget on failures; reliability is capped at medium because there is no cross-server agreement |
| `balanced` | 2 | Default operator mode | Two independent complete servers, shorter idle sampling than the old path, cross-server agreement still computed |
| `thorough` | 3 | Audit or disputed-result mode | Heavier sampling, old-style deeper candidate discovery, and optional `--runs 4`/`--runs 5` for stronger agreement |

`--runs` must be 1 through 5. Balanced and thorough require at least 2 runs; use `--profile quick` for a one-server check. The default command is now equivalent to `netops diagnose speed --profile balanced --runs 2`, which is materially faster than the older three-server default while still comparing independent servers.

The v8.5 beta path:

1. Determines route interface, source IP, gateway, active VPN-like interfaces, whether the tested route uses one, and optional Wi-Fi signal.
2. Uses `netops_platform/speed.py` and the Python `speedtest-cli` module,
   always with certificate-chain and hostname verification enabled.
3. Under WSL, builds a temporary trust bundle from Linux roots plus certificates trusted by Windows Local Machine Root/CA stores. `--ca-file` or `NETOPS_SPEED_CA_FILE` supplies an explicit PEM bundle. NetOps never silently falls back to `-k`/insecure TLS.
4. Reuses a short-lived server-discovery cache for the same routed path across profiles when it contains enough candidates, then still performs fresh upload/download traffic. Set `NETOPS_SPEED_CACHE_TTL_SECONDS=0` to force fresh discovery every time.
5. Discovers more candidate servers than requested so unauthorized/broken endpoints can be skipped.
6. Measures an idle ICMP baseline, pins one verified client to each selected server, and reuses that session for sequential upload then download. Separate concurrent ICMP streams measure loaded latency, jitter, loss, and sample coverage for each direction. Sequential transfer preserves directional accuracy while eliminating a second client/server setup round trip.
7. Requires the profile-specific number of complete servers, rejects large outliers for the sustained aggregate, computes observed range and coefficient of variation, and rates reliability high/medium/low.
8. Writes a 14-field internal record containing both loaded-jitter values and byte totals; the v8.1 field-index defect is fixed.
9. Stores the structured result in both `speed_tests` and `diagnostic_runs`, with `observed_at_iso`/`recorded_at_iso` chronology.

Interpret the result with the path metadata. A VPN, proxy, TLS inspection gateway, server congestion, traffic shaping, Wi-Fi, and endpoint CPU can all become the bottleneck. Multiple independent servers reduce server-specific error but cannot remove enterprise policy from the path.

An error such as `HTTP Error 401: Authorization Required` during discovery/upload means the benchmark endpoint is being rejected by an upstream gateway or requires authentication. It is not a zero-speed result. Confirm with:

```bash
netops diagnose doctor --online
netops diagnose filtering speedtest.net
```

Then use an organization-approved authenticated proxy/browser stack, allow the benchmark category, or use a controlled `iperf3` endpoint. Do not bypass enterprise filtering or report a partial transfer as a valid speed.

### 17.6 `diagnose throughput`

```text
netops diagnose throughput <iperf3-server> [--port 5201] [--seconds 10]
  [--parallel 1-16] [--direction both|upload|download] [--bind <source-ip>]
```

Examples:

```bash
netops diagnose throughput 203.0.113.20
netops diagnose throughput core --direction both --seconds 20 --parallel 2
netops diagnose throughput 203.0.113.20 --dry-run --json
```

This is the defensible endpoint-to-core capacity test. It requires an intentionally managed server:

```bash
# On a host at the core-side measurement point:
iperf3 -s -p 5201

# On the endpoint attached to the switch port, or its NetOps agent:
netops diagnose throughput <core-server-ip> --port 5201 --direction both
```

`upload` means NetOps client to server; `download` adds iperf3 reverse mode and means server to client. Each direction runs separately with a two-second omitted warm-up. NetOps parses JSON and reports receiver goodput, transferred bytes, elapsed time, streams, and TCP retransmits. Results are stored in `diagnostic_runs`.

`core` resolves `core_iperf_server`, then falls back to the configured core switch. A switch management plane is usually **not** an appropriate iperf3 server. Prefer a dedicated host connected at the desired core/distribution point, configure `core_iperf_server`, permit only the intended clients/port, and monitor the test host.

A switch cannot infer endpoint throughput from interface counters. To measure a particular device on a port, run the client on that device or deploy a controlled endpoint agent. Running against `127.0.0.1` only verifies the tool/parser and measures memory/loopback performance; it says nothing about the network.

### 17.7 `diagnose port-health`

```text
netops diagnose port-health <switch> on <interface>
  [--sample-seconds 0-60] [--expected-speed <Mbps>]
```

Examples:

```bash
netops diagnose port-health site-a-access on Gi1/0/12
netops diagnose port-health 203.0.113.96 on 9 --sample-seconds 10 --expected-speed 1000
netops diagnose port-health ZONE34 on Gi1/0/7 --dry-run --json
```

The command reads the interface twice and separates old cumulative totals from errors that increase during the observation window. Cisco IOS/IOS-XE parsing covers admin/oper/line state, link reason, negotiated speed/duplex/media, five-minute rates, CRC/frame/input/output errors, drops, collisions, and resets. Aruba AOS-Switch combines the detailed counter view with `show interfaces brief` to obtain mode and media.

Findings include admin/link down, half duplex, negotiated speed below `--expected-speed`, counter reset/wrap, and active increases in CRC, frame, input/output error, collision, runt, giant, or receive-error counters. Existing nonzero totals remain visible but do not become a current fault unless they increase during the sample. Exit 3 means the read succeeded and found `ATTENTION`, `DOWN`, or an incomplete result.

This command assesses the switch side. It does not prove cable pin continuity, application throughput, DHCP success, or endpoint health. Combine it with cable status/TDR and endpoint `iperf3` for a complete diagnosis.

### 17.8 `diagnose cable`

```text
netops diagnose cable <switch> on <interface>
netops diagnose cable <switch> on <interface> --test --dry-run
netops diagnose cable <switch> on <interface> --test --confirm [--wait 2-60]
```

The default is a read-only query of the **previously recorded** TDR/cable result. `NOT_RUN` means exactly that: the switch has no previous result. It does not mean the cable passed or failed.

Starting a new TDR is potentially disruptive. NetOps therefore returns exit 7 unless `--dry-run` or `--confirm` is present. The dry run prints the exact sequence without touching the switch. Supported active syntax is:

| Family | Start | Read result |
|---|---|---|
| Cisco IOS/IOS-XE | `test cable-diagnostics tdr interface <port>` | `show cable-diagnostics tdr interface <port>` |
| Aruba AOS-Switch | `test cable-diagnostics <port>` | `show cable-diagnostics <port>` |
| Aruba CX | `diag cable-diagnostic test/show <port>` | Status reads are supported where recognized; automated active confirmation is deliberately blocked |

Before an active Aruba AOS-Switch test, NetOps merges the brief media view and refuses optical media such as `1000LX`. Cisco media is similarly checked when exposed. Never initiate TDR on a production uplink merely to see what happens; schedule a maintenance window and verify the exact port.

TDR estimates copper-pair continuity/impedance and fault distance. It can detect patterns such as normal/good, open, short, crossed, or impedance mismatch where firmware reports them. It cannot validate fiber, guarantee all eight pins under motion/load, prove application throughput, or reliably catch every intermittent break. Remote equipment, Auto-MDIX, patch panels, and firmware limitations affect interpretation. Repeat a suspicious result and use a certified physical cable tester when pin map, wiremap, NEXT/return loss, or certification is required.

Each read/test is stored in `diagnostic_runs` with device, port, platform family, whether a new test was started, pair rows, limitations, and standard UTC date.

### 17.9 `diagnose doctor`

```text
netops diagnose doctor [--online]
```

The default performs local readiness checks only: required commands, Python speed backend, route to `1.1.1.1`, WSL detection, configured core, optional `core_iperf_server`, `iperf3`, `ethtool`, GPG/sudo availability, and SSH-vault format/readiness. Vault inspection uses only non-prompting sudo checks. `--online` additionally verifies Speedtest server discovery and TLS trust without running a full transfer.

Under WSL, a reported `ethN` speed from `ethtool` describes the virtual adapter presented to Linux, not the host's physical Ethernet cable. Use switch-side port health/TDR or Windows/physical test equipment for the actual cable. Doctor results are chronological `diagnostic_runs`, so readiness changes can be reviewed later.

### 17.10 `diagnose filtering`

```text
netops diagnose filtering [domain]
```

Example:

```bash
netops diagnose filtering google.com
```

This v8 command delegates to the selected filtering path in `netops-legacy`. Checks can include:

- system DNS resolution;
- comparison with `1.1.1.1` DNS where `dig` exists;
- TCP port 443;
- HTTPS response;
- TLS certificate issuer/inspection heuristics;
- DNS-over-TLS port 853;
- UDP 443/QUIC reachability heuristic;
- NXDOMAIN behavior;
- broad block-page indicators in text mode.

These are heuristics. A corporate CA, captive portal, split DNS, firewall policy, CDN behavior, or unavailable optional tool can alter results. The command does not prove absence of interception.

### 17.11 `diagnose interface`

```text
netops diagnose interface <device> on <interface> [--chart classic|histogram]
```

Examples:

```bash
netops diagnose interface ZONE34 on Gi1/0/7
netops diagnose interface 198.51.100.92 on Gi1/0/7 --chart histogram
```

The legacy interface monitor:

1. Resolves the device to an IP.
2. Requires an SNMPv2c community.
3. Resolves interface index from `IF-MIB::ifDescr` by exact or partial match.
4. Reads 64-bit octet counters where possible, with 32-bit fallback.
5. Samples twice over the configured interval.
6. Handles counter wrap and computes input/output bits per second.
7. Reads interface speed/admin/oper state and estimates utilization.
8. Renders a classic or histogram terminal chart.

The interface path does not use the shared SNMPv3 implementation. It is SNMPv2c-only in the audited code.

This remains the legacy continuous rate chart. API/WebUI registry jobs force `--once` so a background job terminates. Prefer `diagnose port-health` when link negotiation and active error deltas matter; use this legacy action when the SNMP rate chart itself is the goal.

### 17.12 `path inspect` and `ghoster`

```text
netops path inspect <endpoint> --vlan <1-4094>
  [--from <switch>] [--to <switch>] [--depth 1-16]
  [--max-nodes 1-256] [--cached|--live|--refresh] [--explain]

netops ghoster <endpoint> --vlan <1-4094> [same options]
```

`ghoster` is an alias for the path domain, not a second implementation.
Defaults are hybrid mode, depth 8, and 64 nodes. Hard limits are depth 16 and
256 nodes; limits prevent a malformed or cyclic topology from becoming an
unbounded SSH walk.

Examples:

```bash
netops path inspect 02:00:00:00:00:25 --vlan 120
netops path inspect 192.0.2.25 --vlan 120 --from SITE-A-CORE-01 --explain
netops ghoster 02:00:00:00:00:25 --vlan 120 --depth 5 --max-nodes 40
netops path inspect 02:00:00:00:00:25 --vlan 120 --cached --json
netops path history 02:00:00:00:00:25
netops path show path-EXAMPLE
```

The inspection algorithm is evidence-driven:

1. Normalize the endpoint as an IP, MAC, or inventory identity.
2. Resolve current endpoint attachment from MAC-location, AP attachment, and
   identity evidence. Multiple credible attachments are reported as ambiguous.
3. Resolve `--from`, or the profile's configured core, and optional `--to`.
4. Build an undirected cached LLDP/CDP graph and run bounded breadth-first
   search. Repeated nodes are not revisited, so ordinary loops terminate.
5. In hybrid/live mode, inspect each selected switch with the registered
   device driver and correlate the next neighbor with a parsed trunk.
6. Check VLAN definition and membership, inter-switch tagging/native context,
   forwarding-table direction, STP role, LAG state, and neighbor identity where
   evidence exists.
7. At L3 boundaries, consider SVI, VRF, route, ARP/ND, and attached policy
   references. Evidence must match the path interface, VLAN, or endpoint before
   it can establish a blocker.
8. Persist the request, result, ordered hops, findings, confidence, evidence
   observation times, and evidence ages.

Modes:

| Mode | Behavior | Appropriate use |
|---|---|---|
| hybrid/default | Plans from cache, then performs bounded read-only validation | Normal diagnosis |
| `--cached` | Uses current stored topology/evidence only | Preview, offline review, or change comparison |
| `--live` | Requires live read evidence for selected hops | Authorized focused validation |
| `--refresh` | Hybrid validation with requested neighbor refresh where supported | Stale/changed topology investigation |

Outcomes are deliberately strict:

| Outcome | Meaning |
|---|---|
| `COMPLETE` | A bounded hop path was validated and no evidence gap or confirmed blocker remains |
| `BLOCKED` | At least one path-relevant critical blocker was confirmed |
| `PARTIAL` | A path was built, but evidence is stale, ambiguous, missing, failed, unsupported, or cached-only |
| `UNKNOWN` | Source, endpoint attachment, or bounded topology path could not be established |

Confirmed blocker codes can include `VLAN_NOT_DEFINED`,
`VLAN_MISSING_ON_TRUNK`, `STP_BLOCKING`, `LAG_DOWN`, `SVI_DOWN`,
`VRF_MISMATCH`, `ROUTE_MISSING`, and `NEIGHBOR_RESOLUTION_MISSING`.
Warnings such as `STALE_TOPOLOGY`, `AMBIGUOUS_ENDPOINT_LOCATION`,
`TRUNK_EVIDENCE_UNKNOWN`, and `LIVE_INSPECTION_FAILED` force `PARTIAL` rather
than manufacturing certainty.

An attached ACL or policy name is not enough to prove a block. When the driver
cannot parse policy semantics, NetOps emits `POLICY_SEMANTICS_UNKNOWN`; the
operator must inspect the referenced policy. Similarly, the chosen path is the
best path represented by current topology evidence, not packet-level tracing.
ECMP, MLAG, tunneling, asymmetric routing, controller overlays, stale CAM
learning, and unsupported firmware can produce alternate real paths.

Plain output presents a concise hop table and findings. JSON includes RFC 3339
`requested_at_iso`, `started_at_iso`, `finished_at_iso`, hop evidence times, and
`evidence_age_seconds`. Use `path history` and `path show` to compare what was
known at different times instead of overwriting the prior diagnosis.

---

## 18. Workflows, Jobs, and Command Registry

### 18.1 Workflows

Workflows are typed manifests of existing v8 commands. Each step has a stable
ID, label, exact command, and `on_failure` policy (`continue` or `stop`). Steps
execute sequentially and return one structured final summary.

#### `workflow morning-check`

```bash
netops workflow morning-check --dry-run
netops workflow morning-check
```

Intended sequence: import/cache review, fast health, topology-change review, filtering diagnostic, and attention summary.

#### `workflow refresh-inventory`

```bash
netops workflow refresh-inventory
```

Runs fast health, AP scan, topology scan, memory refresh, and attention review. It is not the same as a full switch/router inventory scan.

#### `workflow backup-online`

```bash
netops workflow backup-online ZONE10
```

Runs changed-only backups for online matching devices.

#### `workflow site-health`

```bash
netops workflow site-health google.com
```

Combines latency and filtering checks for the target. A site token that does not resolve as a network/DNS target can fail one or both steps.

#### `workflow ap-audit`

```bash
netops workflow ap-audit
```

Refreshes AP state, recomputes memory, then reviews AP movement and attention.

### 18.2 Why workflow failure policy matters

Suppose AP discovery fails but a step's declared policy continues into `memory
refresh`. Memory can then be recomputed from stale AP data, and the final
attention command can still succeed. The workflow reports `PARTIAL`, preserves
each child's JSON/summary, and records whether it stopped. Always inspect every
step. Backup-online uses `stop` because later work must not proceed after its
required backup step fails.

### 18.3 Command registry

The registry is the shared catalog used by CLI registry commands, generated TUI
forms, WebUI forms, API previews/jobs, retry policy, and workflow metadata.

```bash
netops commands list
netops commands show backup-run --json
netops commands run backup-run ZONE34 --preview
netops commands run diagnose-latency --target 1.1.1.1 --count 10
```

Each command spec can define:

- stable command ID;
- label and description;
- domain;
- argument schema;
- rendered command template;
- read-only and local-write attributes;
- risk/safety class;
- output type;
- timeout;
- preview/run/cancel support;
- local/remote state effects;
- generated field help/defaults/grouping, capability, context kinds, output
  view, and confirmation policy through the application service.

The registry is the generated source of truth for all public action domains. v8.5 beta includes
Internet speed persistence, controlled throughput, sampled port health, cable
status/active-test preview, SSH trust management, guarded VLAN configuration,
and diagnostic readiness. Active cable testing, arbitrary configuration,
memory-prune, registry meta-runner, live-job cancellation, and server-start
actions remain preview-only where background execution would be unsafe or
meaningless. Interactive SSH is terminal-only. Guarded `vlan-set` is runnable
through the TUI service's stronger reason/ticket/hash/typed-confirmation gate;
legacy Ask/API/WebUI execution remains blocked for configuration.

`preview_for_action` is the single rendering policy used by Natural Ask and `/api/preview`. It reports missing arguments, validation failures, risk and safety classes, state effects, whether confirmation is required, and why an action is blocked. `/api/jobs` rejects unknown, preview-only, terminal, config, and danger actions before process creation.

`commands run` accepts both positional arguments and named option forms for registry fields. Prefer `commands show <id> --json` before automating a registry action.

### 18.4 Jobs

The core job system is used by the TUI and a running `netops serve` process.
Submitted jobs are queued in memory and SQLite, constrained by
`NETOPS_JOB_CONCURRENCY` (default 3), and execute commands in supervised process
groups.

Lifecycle:

```text
queued -> running -> completed | partial | failed | cancelled | stale
                    running -> cancelling -> cancelled | completed
```

On server startup, old `queued` or `running` database rows are marked `stale`, because their original process no longer exists.

The server captures:

- stdout lines;
- stderr lines;
- system start/refresh/finish messages and structured phase/progress metadata;
- actor, UID, session, reason, ticket, request, result JSON, exit code, duration,
  and ISO timestamps;
- command history and audit events for safety-significant attempts.

Recursive VLAN, active MAC, core-ping, speed, throughput, port-health, cable, and
workflow actions write concise progress to stderr. The TUI renders these events
in Activity; API/WebUI clients receive them through the event stream. The final
structured result remains separate and is adapted back into workbench datasets.

Job log records have monotonic IDs. The WebUI first loads persisted rows, then opens `/api/jobs/<id>/events?after=<last-id>` so already displayed lines are not replayed. Each event includes `created_at` plus `created_at_iso`; terminal jobs close the stream after their final log record and trigger a view refresh.

Direct noun-first CLI commands are synchronous and generally do not create job
rows. `netops jobs list` therefore primarily reflects TUI and WebUI/API jobs.

### 18.5 Job commands

```bash
netops jobs list [--limit N]
netops jobs show <id>
netops jobs logs <id>
netops jobs cancel <id>
```

Cancellation only works for a live process owned by the current core instance.
The CLI cannot resurrect an old in-memory process handle from a database row.
The owner sends `SIGTERM` to the process group, waits, and can escalate
internally while preserving prior events.

The TUI rerun action always reopens a populated generated form for review. The
WebUI only offers automatic retry when the registered command is read-only and
all required arguments can be reconstructed from defaults.

---

## 19. Database Administration

### 19.1 `db migrate`

```bash
netops db migrate --json
```

Creates/upgrades schema, cleans invalid MAC identity, recomputes derived state in migration mode, and reports suppressed structural events. v8.1 also repairs pre-v8 `jobs` tables that lack `created_at` or `writes_local`; existing rows are preserved and missing creation times are backfilled from start/finish chronology.

### 19.2 `db status`

```bash
netops db status --json
```

Reports:

- DB/cache paths;
- current and expected schema version;
- SQLite, WAL, and SHM byte sizes;
- device, AP observation/canonical, neighbor, relationship, backup, and job counts.

### 19.3 `db path`

```bash
netops db path
```

Use this before any direct `sqlite3` investigation. Never assume the non-root default when environment overrides or root execution are possible.

### 19.4 `db integrity`

```bash
netops db integrity --json
```

Runs SQLite `quick_check` and `integrity_check` without intended data changes. Both should return `ok`.

### 19.5 `db repair`

```bash
netops db repair
```

Runs migration, derived-state synchronization, WAL checkpoint, `ANALYZE`, optimizer maintenance, and integrity checks. It is not a universal corruption recovery tool and does not restore lost records.

Before repair:

1. Stop the WebUI/server and other writers.
2. Copy the DB plus any `-wal` and `-shm` files consistently, or use SQLite's backup mechanism.
3. Record `db status` and integrity output.
4. Confirm disk space and file ownership.

### 19.6 `db vacuum`

```bash
netops db vacuum
```

Checkpoints WAL and compacts SQLite. `VACUUM` needs temporary disk space and an exclusive-enough write window; run it during low activity after a backup.

### 19.7 Flat aliases

```bash
netops db import-flat
netops db export-flat
```

These are aliases of the inventory bridge commands.

### 19.8 Direct SQLite inspection

Read-only examples:

```bash
sqlite3 "$(netops db path)" '.tables'
sqlite3 "$(netops db path)" 'PRAGMA user_version;'
```

Do not manually edit derived tables unless you are repairing with a tested procedure. The next import/refresh may overwrite current state or emit misleading events.

---

## 19A. Profiles, Ingest, Plugins, and Extension Points

These domains turn NetOps from a fixed deployment script into a reusable local
platform. Profiles isolate operators and environments; channels ingest data;
plugins add reviewed Python implementations; declarative drivers add bounded
read commands without executable code.

### 19A.1 Profile lifecycle

```bash
netops profile list
netops profile create lab
netops profile show lab
netops profile use lab
netops profile paths
netops --profile production inventory list
```

`create` is idempotent: it creates missing private directories and neutral
files but does not overwrite an existing profile. `use` updates only the small
`active_profile` selector. `--profile` is preferable for automation because it
does not mutate that selector. A command must never read inventory, aliases,
known hosts, channels, secrets, or SQLite state from another profile.

Profile names contain 1-48 lowercase letters, digits, hyphens, or underscores.
Use separate profiles for production, lab, training, and migration rehearsal.
Do not use profiles as an authorization boundary between hostile local users;
Unix account permissions remain the security boundary.

### 19A.2 Legacy migration and rollback

```bash
netops profile migrate-legacy legacy-local --json
netops --profile legacy-local config validate
netops --profile legacy-local db integrity
```

Migration copies recognized public configuration, aliases, compatible cache
files, and SQLite through the SQLite backup API. It does not delete or modify
the source. Existing destination files win unless the destination is still the
generated neutral default. A legacy plaintext secret file is skipped; only its
non-empty key names are written to the migration report as pending work.

Re-running migration is supported. Existing matching destinations are reported
as skipped. Rollback means selecting the prior profile or prior application;
do not delete legacy sources until the new profile passes inventory counts,
integrity, secret access, SSH trust, and an authorized read-only lab operation.

### 19A.3 Configuration operations

```bash
netops config show
netops config get core_switch_ip
netops config set core_switch_ip 192.0.2.1
netops config unset core_switch_ip
netops config paths
netops config validate
```

`show` redacts secret-looking compatibility keys. `set` and `unset` update a
mode-`0600` profile compatibility file atomically; they reject secret names,
invalid key syntax, and multiline/control characters. Prefer editing
`profile.toml` for structured, reviewed configuration. Run `validate` after any
manual change. The validator also warns while a legacy plaintext secret file
still exists.

### 19A.4 Ingest channel anatomy

Each file under the profile's `channels/` directory is an
`IngestChannelV1` TOML manifest:

```toml
schema_version = 1

[channel]
name = "asset-export"
kind = "json"
enabled = true
entity_kind = "device"
source_id_field = "id"
observed_at_field = "observed_at"

[reader]
path = "/srv/netops-input/devices.json"
records_path = "devices"
completeness = "partial"
confidence = 90

[fields]
ip = "management.ip"
hostname = "name"
platform = "platform"
model = "model"
status = "status"

[provenance]
owner = "network-operations"
source_system = "asset-export"
```

Important fields:

| Field | Meaning |
|---|---|
| `channel.name` | Stable profile-unique channel ID |
| `channel.kind` | Reader implementation selected by contract |
| `source_id_field` | Stable source-side identity, not a display name |
| `observed_at_field` | When the source observed the entity |
| `reader.completeness` | Whether absent fields/records can carry full-snapshot meaning |
| `reader.confidence` | Source confidence from 0-100 |
| `fields` | Destination fact name to source dotted path |
| `provenance` | Human ownership and source-system context |
| `secrets` | Named references only; never literal values |

Relative file paths resolve from the manifest directory. The examples under
`examples/channels/` reference sibling `examples/data/`; when copying only a
manifest into a profile, copy its fixture data too or update the path.

### 19A.5 Supported readers

| Kind | Input | Stability and constraints |
|---|---|---|
| `csv` | UTF-8 delimited file with a header | Stable; local read |
| `json` | JSON document plus optional dotted `records_path` | Stable; local read |
| `jsonl` | One JSON object per non-empty line | Stable; local read |
| `stdin-ndjson` | NDJSON from standard input | Stable; requires piped stdin |
| `http-json` | HTTPS JSON with bounded pagination | Stable contract; TLS verification stays on |
| `netbox` | Token-authenticated NetBox REST records | Stable, read-only source-of-truth adapter |
| `snmpv3` | Fixture-gated contract in 8.5 | Experimental; no stable live claim |
| `catalyst-center` | API fixture/environment gate | Experimental |
| `aruba-central` | API fixture/environment gate | Experimental |
| `smartzone` | API fixture/environment gate | Experimental |

HTTP readers bound page count, timeout, and retry attempts. Pagination must
remain on the original origin. TLS verification cannot be disabled in a stable
channel. Rate-limit and server failures close the run as partial or failed;
they do not convert missing pages into deletions.

### 19A.6 Running and auditing ingest

```bash
netops ingest validate
netops ingest channels
netops ingest run asset-export
netops ingest history --limit 20
netops ingest observations asset-export --limit 20
netops ingest rejects --limit 20
```

Validation reads manifests but fetches no source records. `channels` syncs
valid manifests into SQLite while retaining an invalid row for each broken
file. One broken channel does not hide valid channels. Duplicate channel names
are invalid even when both files are individually parseable.

For every delivery, NetOps creates `IngestRunV1` and then:

1. reads records through the selected bounded reader;
2. maps source fields without evaluating code;
3. validates entity identity, timestamps, confidence, and fact shape;
4. hashes raw evidence and computes a deterministic idempotency key;
5. suppresses duplicate history for the same source observation;
6. appends accepted observations and field-level provenance;
7. quarantines invalid records with sensitive values redacted;
8. materializes current inventory only when the observation is not older than
   the trusted current field;
9. records received, accepted, duplicate, and rejected counts plus final status.

A sparse observation cannot erase a trusted non-empty value. A stale
observation is still useful chronological evidence but cannot roll current
hostname, platform, status, or last-seen time backward. `completed` means the
reader completed and no record failed; `partial` means useful records were
accepted before a bounded source/record failure; `failed` means no trustworthy
delivery completed.

Compatibility adapters do not bypass this evidence layer. SSH inventory,
Cisco WLC, SmartZone, AP scan, and LLDP/CDP refreshes register stable
`built-in-*` channels and append normal ingest runs and observations. Repeating
the same snapshot produces duplicate counts instead of duplicate history.
`netops ingest channels` shows these built-in channels alongside manifest
channels after they have produced evidence.

### 19A.7 Plugin lifecycle

Stable entry-point groups are:

- `netops.ingest`
- `netops.device_drivers`
- `netops.parsers`
- `netops.exporters`

```bash
netops plugin groups
netops plugin list
netops plugin enable netops.parsers:example
netops plugin check netops.parsers
netops plugin disable netops.parsers:example
```

Discovery reads package metadata but does not import disabled plugin code.
Enablement is profile-local and transactional: NetOps imports and validates the
exact entry point first, then records enablement; incompatible API versions,
name collisions, import failures, and write capability claims roll back. `check`
loads enabled entries one at a time and isolates failures so one package does
not prevent the rest from being reported.

Plugins are trusted Python code in the NetOps process, not a sandbox. Review
source, dependency tree, publisher, version, and hashes. Pin the package in the
deployment environment. Arbitrary shell hooks, third-party writes, and plugin
configuration actions are prohibited in 8.5.

Every plugin object declares `NETOPS_PLUGIN_API_VERSION = "1"`. An optional
`NETOPS_PLUGIN_CAPABILITIES` sequence is normalized and rejected when it claims
write, shell, subprocess, process, exec, execute, or system behavior. Each
entry-point group then has a required interface:

| Group | Required interface | 8.5 runtime boundary |
|---|---|---|
| `netops.ingest` | `read_records(channel, reader, secrets)` returning mapping records | A `kind="plugin"` channel selects it by `reader.provider` |
| `netops.device_drivers` | One `DeviceDriver` or `netops_device_drivers()` | Drivers are revalidated and added only to the selected profile's cloned registry |
| `netops.parsers` | `parse()` | Loaded into the internal parser extension registry |
| `netops.exporters` | `export()` | Loaded into the internal exporter extension registry |

Example plugin ingest channel:

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

NetOps resolves only the references declared in `[secrets]`, passes those
values in memory, removes them from provider exception messages, and records
the plugin distribution in observation provenance. Provider records still
pass through normal mapping, validation, idempotency, stale-field, quarantine,
and current-state rules. Python device drivers receive a second validation:
read command allowlists, bounded match patterns and parser IDs, collision
checks, discarded firmware-write profiles, and forced-unsupported
configuration/VLAN writes.

Parser and exporter plugins are internal extension APIs in 8.5. NetOps does
not expose a generic command that invokes arbitrary plugin methods; a public
consumer needs a versioned, bounded core action first.

### 19A.8 Declarative device drivers

Drivers under `profiles/PROFILE/drivers/*.toml` are data-only. A valid driver
declares:

- a unique lowercase `driver.family`;
- vendor, OS, and device kind labels;
- safe pager/logout commands;
- one or more bounded `[match]` regular expressions and confidence;
- semantic `[commands]` such as `inventory`, `fdb`, `neighbors`, or
  `vlan_membership`;
- capability states;
- stable lowercase parser-template IDs.

Every profile receives a copy of the built-in registry before its local drivers
load; a driver in one profile cannot contaminate another. Selection requires
all configured match fields to match. Profile drivers are checked before the
built-in signatures and cap confidence at 95.

Only approved read prefixes are accepted, including `show`, `display`, `get`,
`ping`, `traceroute`, and bounded pager/logout forms. Control characters, shell
metacharacters, unknown prefixes, configuration entry, save, reload, erase, and
write operations are rejected. Declarative drivers cannot override an existing
family. See `examples/drivers/example-switch.toml` and
`docs/device-support.md`.

### 19A.9 Redacted support bundle

```bash
netops support bundle
netops support bundle ./netops-support.tar.gz
```

The bundle contains version/platform/capability facts, redacted effective
configuration state, aggregate recent-run status, schema/integrity summaries,
and a manifest hash. It excludes inventory identities, targets, aliases,
addresses, MACs, secrets, raw evidence, backups, known hosts, channel URLs, and
plugin names. Inspect the archive before sharing it; redaction reduces risk but
cannot replace the operator's publication review.

---

## 20. Natural Ask

Ask is the natural-language command center for two deliberately separate modes:

1. **Retrieval:** answer from current inventory, health, topology, jobs, diagnostics, backups, and relationship history.
2. **Operation planning:** select one registered action, extract structured arguments, validate them, classify risk/state effects, and return an exact preview.

Asking for an operation does not execute it. Execution always crosses a second explicit boundary.

### 20.1 One-shot use

```bash
netops ask "How many APs are offline in ZONE10?"
netops ask "Where was SITE-SQ21-AP161 connected before?" --json
netops ask "Run a fast health check for ZONE34"
netops ask "Preview changing Gi1/0/7 on ZONE34 to access VLAN 120" --json
```

Retrieval returns an intent, answer, timestamped result rows, suggestions, and an evidence workflow. An operation returns `intent=command_plan` and a structured plan.

### 20.2 Command-plan contract

A command plan includes:

| Field | Meaning |
|---|---|
| `action` | Stable ID from `netops commands list` |
| `args` | Extracted structured values; never a generated shell fragment |
| `command` | Shell-escaped preview built by the core registry |
| `status` | `ready`, `needs_clarification`, `preview_only`, or `blocked` |
| `missing_args` | Required fields that the wording did not supply |
| `safety_class` | `read-only`, `network-read`, `network-read/local-write`, `local-write`, `interactive-read`, or `config-write` |
| `state_effects` | Expected local/device effects from registry metadata |
| `run_supported` | Whether API/WebUI/background execution is permitted |
| `requires_confirmation` | Whether CLI/UI must obtain an additional explicit confirmation |
| `execution_hint` | Exact guarded CLI form when execution is supported |

Examples:

```bash
# Local read: plan, then execute without active-operation confirmation.
netops ask "Prepare the database status command"
netops ask --execute "Prepare the database status command"

# Active network/local-state operation: --execute and --confirm are both required.
netops ask "Ping 198.51.100.92 five times"
netops ask --execute --confirm "Ping 198.51.100.92 five times"

# Configuration stays preview-only in Ask even if --confirm is supplied.
netops ask "Preview changing Gi1/0/7 on ZONE34 to access VLAN 120"
netops vlan set ZONE34 Gi1/0/7 --access 120 --dry-run
# Only after independent review:
netops vlan set ZONE34 Gi1/0/7 --access 120 --confirm
```

`--execute` on a retrieval answer fails because there is no command plan. `--execute` without `--confirm` fails for network reads, local writes, workflows, diagnostics, backups, scans, and other active operations. Unsafe `show` text, missing inputs, unknown actions, terminal sessions, and config/danger actions cannot be forced through this path.

### 20.3 Natural operation examples

| Wording | Planned action |
|---|---|
| `Run a fast health check for ZONE34` | `health-check` |
| `Refresh the AP and topology inventory` | `workflow-refresh-inventory` |
| `Ping 198.51.100.92 five times` | `diagnose-latency`, `count=5` |
| `Run a speed test three times` | `diagnose-speed`, `runs=3` |
| `Run iperf throughput to core in both directions` | `diagnose-throughput`; requires an iperf3 server target/configuration |
| `Check port health on ZONE34 Gi1/0/7 for ten seconds` | `diagnose-port-health`, sampled counter deltas |
| `Show the last cable diagnostic for ZONE34 Gi1/0/7` | read-only `diagnose-cable` |
| `Start a cable test on ZONE34 Gi1/0/7` | danger-class `diagnose-cable-test` preview; CLI confirmation required |
| `Run diagnostic doctor online` | `diagnose-doctor`, `online=true` |
| `Test filtering for example.com` | `diagnose-filtering` |
| `Run show version on SITEAZONE34SW01` | `device-show` after show-command policy validation |
| `Connect to admin-hill over SSH` | `device-ssh`, preview-only because it needs an interactive terminal |
| `Back up ZONE34` | `backup-run` |
| `Locate VLAN 120 on ZONE34` | `vlan-locate` |
| `Monitor Gi1/0/7 on ZONE34 once` | `diagnose-interface` with `once=true` |
| `Check SQLite integrity` | `db-integrity` |

When the user explicitly asks for a command/action/preview, Ask also scores registry IDs, labels, domains, descriptions, and examples. This makes less common public actions discoverable without adding a bespoke sentence rule for every phrasing.

### 20.4 Interactive chat

```bash
netops ask
```

The in-process session remembers recent result entities, selected targets, and the last command plan. Follow-ups can filter the previous result, ask for IP/model/location, revisit a plan, or change its target. A phrase such as "run it" only recalls the plan and its explicit execution hint; it does not silently run anything.

Session commands:

| Command | Effect |
|---|---|
| `/patterns` | Show supported families/examples |
| `/history` | Show current session question history |
| `/reset` | Clear follow-up context |
| `/alias phrase = target` | Add/update a local phrase alias |
| `/exit` | Leave chat |

Session context is not a durable conversation log. Alias rows are durable in SQLite.

### 20.5 Pattern and alias administration

```bash
netops ask patterns
netops ask patterns --json
netops ask aliases
netops ask alias set "engineering office" "engg ofc"
netops ask alias remove "engineering office"
```

Aliases are phrase substitutions, not new data. Choose specific phrases so an alias does not accidentally replace part of a switch qualifier or unrelated question.

### 20.6 Intent families

The catalog contains 178 example questions across 21 intent families:

| Intent | Questions it answers |
|---|---|
| `ap_on_switch` | Count/list canonical APs attached to a described switch |
| `ap_inventory` | Count/list/filter AP inventory by site, status, model, platform |
| `switch_inventory` | Count/list/filter switches/devices |
| `entity_details` | IP, MAC, model, names, aliases, status, last seen |
| `switch_summary` | One-switch AP, neighbor, health, and memory overview |
| `ap_location` | Current or previous AP switch/port |
| `port_memory` | Current/historical switch-port occupancy |
| `ip_memory` | Current/previous ownership of an IP |
| `mac_memory` | Identity, address, port, and movement for a MAC |
| `identity_history` | Prior names, IPs, MACs, models, attachments |
| `topology` | Current neighbors and switch relationships |
| `topology_changes` | New, removed, or changed links |
| `health` | Current outages, staleness, flapping, status counts |
| `attention` | Current operator review queue |
| `ap_moves` | Recent AP switch/port changes |
| `ap_aliases` | Canonical AP merges, aliases, addresses, duplicate observations |
| `unjoined_aps` | WLC APs observed as not joined |
| `backup_history` | Recent, failed, missing, or changed backups |
| `diagnostic_history` | Stored latency/speed/filtering/interface history |
| `job_status` | Queued/running/completed/failed/cancelled jobs |
| `command_plan` | Registry-backed operation selection, arguments, preview, clarification, and safety |

### 20.7 Resolution strategy

Natural Ask uses:

- case and punctuation normalization;
- common typo normalization;
- local phrase aliases;
- location/name variants;
- compact alphanumeric matching;
- token overlap and fuzzy ranking;
- canonical AP aliases/addresses;
- current result/target/plan context for follow-ups;
- operational verb and phrase rules;
- registry metadata scoring for explicit command requests;
- per-action extraction for IP, MAC, domain, interface, VLAN, job ID, count/runs, and safe show command;
- required-field, VLAN-range, and show-command validation.

It deliberately avoids free-form SQL, model-generated shell, arbitrary subprocesses, and direct helper selection.

### 20.8 Answer and plan quality rules

Before trusting an answer:

1. Check the returned intent matches the question.
2. Read the workflow/source explanation.
3. Check row timestamps and status.
4. Verify whether the answer uses canonical AP identities or raw observations.
5. Confirm controller-only AP data is not interpreted as a physical port.
6. Re-run the corresponding explicit command when the decision is operationally important.
7. For plans, inspect `action`, every argument, safety class, state effects, and exact preview.
8. Treat `needs_clarification`, `preview_only`, and `blocked` as hard states, not suggestions to bypass.

Examples:

```bash
# Natural question
netops ask "Which APs are down on ZONE34?"

# Explicit verification
netops ap on-switch ZONE34 --json
netops ap list ZONE34 --status OFFLINE --json
netops memory switch ZONE34 --json
```

### 20.9 API and WebUI sessions

`POST /api/ask` accepts a `session` object and returns its updated form. Send that object back for the next turn. The WebUI does this automatically, keeps the latest eight question/answer pairs, renders clickable suggestions, and provides separate preview/run controls. API clients must never interpret a returned plan as proof of execution.

### 20.10 Optional AI wrapper

The optional wrapper is included in the public source tree and source
distribution, but is not installed as part of the core wheel console in 8.5.
Use the source launcher for `netops ai`; wheel-only installations retain the
fully deterministic `netops ask` interface without undeclared model/runtime
dependencies.

`netops ai` fast mode routes broad retrieval and all command requests through `answer_from_netops_state`, which runs `netops --json ask <question>`. Only narrow live interface and VLAN-summary questions use dedicated show workflows. A command response preserves the action, status, safety class, exact preview, and execution hint, then states that the AI wrapper did not execute it.

```bash
netops ai "all APs that are down"
netops ai "Run a fast health check for ZONE34"
netops ai --ollama-select "Explain what changed around ZONE34"
```

Fast mode is deterministic and model-free. `--ollama-select` and `--model-summary` require a running local Ollama service and an installed model. If Ollama has no models, fast mode remains operational while model-assisted modes do not.

### 20.11 Failure modes

- **No intent matched:** Rephrase using `ask patterns` wording.
- **Wrong entity:** Use an exact hostname/IP/MAC or create a specific alias.
- **Stale answer:** Refresh inventory/health/memory first.
- **Duplicate-looking APs:** Inspect the `ap_aliases` intent and valid MAC evidence.
- **No diagnostic history:** The current v8 persistence gap may be responsible.
- **No prior location:** History starts only after NetOps observed and synchronized the relevant change.
- **Needs clarification:** Supply every field listed in `command_plan.missing_args`.
- **Blocked plan:** Read `reason`; do not move the request to a less guarded interface.
- **Wrong command match:** Rephrase with the public domain/action or ask for `commands list/show` metadata.
- **AI model unavailable:** Use default `netops ai` fast mode or install/create the configured Ollama model deliberately.

---

## 20A. Terminal Operator Console

The v8 Textual console is the primary interactive interface. It is launched by
`netops` in a capable interactive terminal, or explicitly:

```bash
netop tui
netops tui
netops tui open --view inventory --target ZONE34
```

The startup screen is the full-width Action Hub: search plus Action, Function,
Safety, and Purpose columns. Persistent dashboard metrics, topology, history,
evidence, inspector, and activity are intentionally absent. Press `F` to open
Inventory, Diagnostics, Topology/VLAN, Status overview, History/Audit, or
Configuration. Press `D` for advanced result metrics/tabs, `I` for Inspector,
and `L` for Activity. These capabilities remain available without occupying the
normal command-running surface.

Essential keys are `Ctrl+P` for the palette, `/` to filter, `A` for the Action
Hub, `F` for Functions, `J` for Jobs, `R` to refresh local state, `E` to export
visible rows, `?` for help, and `Q` to exit. Opening and navigating performs
bounded local SQLite reads only.

Forms are generated from all 91 registry entries. Active work requires a reason.
Typed configuration additionally requires a ticket, exact confirmation phrase,
and matching preview hash. Interactive SSH suspends the TUI and delegates to the
managed terminal path. Runnable non-terminal actions become jobs with live
events and structured final results.

Theme mode defaults to grayscale `auto`, follows available light/dark terminal
hints, and falls back to light. `NO_COLOR` forces neutral mode. Optional colored
light and dark themes remain available with `T` or `NETOPS_TUI_THEME`.

Preferences are private and atomic. CSV exports include only the filtered,
sorted visible result and are private by default. Complete operation,
responsive, security, and extension guidance is in:

- `docs/operator-console.md`
- `docs/ui-design-system.md`
- `docs/architecture-v8.md`
- `docs/migration-v8.md`

---

## 21. WebUI

The Vue WebUI is retained as a loopback browser interface. New operator-console
behavior is specified against the TUI/application service first.

### 21.1 Starting the browser console

```bash
netops serve
netops serve --port 8788
```

Default address:

```text
http://127.0.0.1:8787
```

The current server:

1. marks abandoned queued/running rows stale;
2. starts a threaded Python HTTP server;
3. serves `webui/dist`;
4. serves JSON APIs under `/api/`;
5. streams job lines over server-sent events (SSE).

The server has no authentication. Do not bind to `0.0.0.0` as a convenience.

### 21.2 Data loading behavior

On mount, the Vue app loads all light and heavy resources. Every nine seconds it refreshes these light resources:

- health;
- WebUI status;
- jobs;
- diagnostics;
- attention.

Heavier inventory, topology, command, backup, history, automation, option, and settings resources load initially and when the relevant view or full refresh is requested.

Errors are stored per resource. The banner can therefore show a partially loaded UI rather than failing the entire page. The footer shows the DB path and number of resources loaded.

### 21.3 Navigation and views

The UI has eight top-level views.

#### Overview

Shows device/AP/link/job counts, offline hints, attention signals, safe quick actions, recent jobs, and latest stored diagnostic summaries.

Quick actions:

- fast health;
- refresh inventory workflow;
- topology scan;
- open diagnostics.

#### Inventory

Provides device/AP segmented modes, text search, online/offline filters, a scrollable table, and a detail drawer. Selecting a row requests canonical details/history. Actions can launch a latency probe, open Memory, or prepare a backup target.

#### Memory

Supports switch, device, IP, MAC, port, timeline, and source/explain modes. Current relationships show first-seen and last-recorded dates, while timeline rows label the exact event-recording date. Both are sorted newest-first and rendered as ISO 8601 UTC. "Refresh memory" starts a server job.

#### Topology

Displays up to 36 graph nodes and 80 edges in a circular client-side layout, plus raw neighbor links and changes. This is a visualization of cached data, not a physical-coordinate topology engine.

#### Diagnostics

Starts host/core latency, Internet speed, controlled throughput, filtering, sampled port health, cable-status, readiness, and finite legacy-interface jobs. Active TDR is preview-only. The chronology is newest-first and displays standard UTC recording dates from `diagnostic_runs`; speed and port summaries also populate their specialized tables.

#### Operations

Shows workflows, backup launch/preview, planned Automation V2 information, and a registry-driven command palette. It renders argument controls from each command's `arg_schema`.

Commands with `run_supported=false` or danger/config risk are previewed rather than run.

#### Jobs

Filters all/active/completed/failed jobs, opens persisted and live logs, supports cancellation of current live processes, and offers safe retry/review based on command metadata.

#### Ask command center

Sends retrieval questions and operational requests to `/api/ask`. The view preserves session context, renders recent question/answer turns, chooses evidence columns dynamically, formats timestamps as ISO 8601 UTC, and shows the deterministic workflow. A command response adds the registered action, structured arguments, state effects, safety class, exact preview, missing inputs, and preview/run controls. `Ctrl+Enter` submits from the textarea.

The browser never executes a plan in the Ask request. **Run plan** is a separate click. Active plans show a browser confirmation before they are submitted to `/api/jobs`; preview-only/config/terminal plans cannot enter that queue.

### 21.4 Live job stream

When a job is selected or created, the browser:

1. fetches existing metadata/logs;
2. opens `EventSource('/api/jobs/<id>/events')`;
3. appends stdout/stderr/system lines;
4. ignores heartbeat lines;
5. closes and refreshes status when the stream errors/ends.

SSE is tied to the current server process for truly live queues. Historical log rows can still be replayed after restart.

### 21.5 Frontend limitations

- One large `App.vue` owns all views and state; there is no router or deep-link URL per view.
- It uses `Record<string, any>` extensively, so API contract drift is caught mainly at runtime.
- There are no frontend unit, accessibility, or browser end-to-end tests.
- The topology layout truncates large graphs.
- Several CSS design generations remain in one 2,061-line file.
- API JSON parsing assumes a JSON response body; a non-JSON proxy error can become a generic client error.
- Polling every nine seconds can add load with many open consoles.

### 21.6 Rebuilding and verifying distribution

```bash
cd webui
npm ci
npm run build
```

Verify that `dist/index.html` points to existing hashed assets and start `netops serve` for a same-origin smoke test. A source change has no production effect until `dist` is rebuilt and deployed.

---

## 22. HTTP API

The API is a local implementation interface, not a versioned public contract. Responses are JSON, carry `Cache-Control: no-store`, and recursively redact values whose keys look secret-sensitive. There is no authentication, authorization, TLS, formal OpenAPI schema, or body-size limit.

### 22.1 Conventions

```bash
curl -s http://127.0.0.1:8787/api/health
curl -s 'http://127.0.0.1:8787/api/aps?status=OFFLINE&limit=100'
```

List endpoints are inconsistent by design history: some return a JSON array directly; others return an object containing `rows`, `items`, `summary`, or other fields. Inspect actual shape before scripting.

Limits are sanitized and capped per endpoint, generally at 300, 500, 1,500, or 2,000.

Stored timestamp fields remain integer Unix epoch seconds. Memory and history payloads add ISO 8601 UTC companions such as `created_at_iso`, `recorded_at_iso`, `first_seen_iso`, and `last_seen_iso`; this is additive and does not replace the numeric source fields. Chronological memory/history collections are newest-first, with the numeric row ID used as the tie-breaker for events recorded in the same second.

### 22.2 GET endpoints

| Endpoint | Query | Response/purpose |
|---|---|---|
| `/api/health` | none | `ok`, version, paths, counts, public-safe config |
| `/api/webui/status` | none | build/state readiness and missing items |
| `/api/health/timeline` | `limit` | object with recent health-event `rows` |
| `/api/inventory/detail` | `kind=device|ap`, `target`, `limit` | record, health, history, relationships, backups |
| `/api/inventory/history` | `q`, `limit` | newest-first, versioned identity history with recorded-date fields |
| `/api/devices` | `q` | direct array of matching device rows |
| `/api/aps` | `q`, `status`, `limit` | direct array of reconciled APs |
| `/api/neighbors` | none | direct array of neighbors |
| `/api/topology` | `limit` | graph payload |
| `/api/topology/graph` | `limit` | same graph payload |
| `/api/topology/changes` | `limit` | direct array of topology events |
| `/api/history` | `limit` | direct newest-first array of versioned relationship events with recorded dates |
| `/api/memory/switch` | `target` or `q`, `limit` | switch memory, first/last recorded dates, chronology metadata; missing target is HTTP 400 |
| `/api/memory/timeline` | `q`, `limit` | newest-first versioned relationship timeline object |
| `/api/memory/query` | `mode`, `target`/`q`, `port`, `limit` | mode-dispatched memory payload with chronology metadata where applicable |
| `/api/attention` | `limit` | attention item object |
| `/api/backups` | `limit` | direct array of backup rows |
| `/api/workflows` | none | workflow catalog |
| `/api/diagnostics` | `limit` | timestamped summary plus probes, speed tests, filtering checks, interface samples, and unified diagnostic runs |
| `/api/automation` | none | planned/disabled schedule and attention-rule information |
| `/api/jobs` | none | recent jobs |
| `/api/jobs/<id>` | none | job plus persisted logs, or 404 |
| `/api/jobs/<id>/events` | none | SSE stream/replay |
| `/api/options` | none | UI target/domain/speed/quick-action options |
| `/api/commands` | none | command registry payload |
| `/api/settings` | none | public-safe recognized config |

### 22.3 `POST /api/ask`

Request:

```json
{
  "question": "How many APs are offline in ZONE10?",
  "limit": 100,
  "session": {}
}
```

`q` can substitute for `question`. A session object supplies follow-up context. The response includes the updated `session`, including recent history, last result/target, and last command plan where applicable; send it back on the next request. The endpoint plans but never executes operations. It returns HTTP 200 even when wording is unmatched; inspect `ok`, `error`, `command_plan.status`, and `missing_args`.

### 22.4 `POST /api/preview`

Request:

```json
{
  "action": "diagnose-latency",
  "args": {
    "target": "1.1.1.1",
    "count": "5"
  }
}
```

Response includes action, rendered command, normalized arguments, missing arguments, read/local-write flags, risk level, safety class, confirmation requirement, validation error, and `blocked`/reason. Configuration specs render an explicit `--dry-run` preview and remain blocked from WebUI execution.

Preview validates registry rendering; it does not prove the target will resolve, credentials work, vendor output parses, or remote command is semantically safe.

### 22.5 `POST /api/jobs`

Request:

```json
{
  "action": "health-check",
  "args": {
    "target": "ZONE10"
  }
}
```

Returns HTTP 201 and the queued job. Only actions implemented by `command_for_action` can be started. Unknown/missing arguments return HTTP 400.

After selected state-changing network-read jobs finish, the server imports flat files and logs `canonical state refreshed`, even if that import itself is suppressed by an exception handler. Review final state rather than relying solely on that line.

### 22.6 `POST /api/jobs/<id>/cancel`

Returns:

- HTTP 200 and `ok: true` when a current live process was signaled;
- HTTP 409 when the job is not running in this server.

### 22.7 SSE format

Each event is an unnamed SSE message:

```text
data: {"created_at":1784000000,"stream":"stdout","line":"..."}

```

The server emits a system heartbeat after 20 seconds without a line. A stream for a historical job replays DB logs and closes.

### 22.8 API deployment rules

If remote access is ever required, first add:

1. authentication and role authorization;
2. TLS termination;
3. host firewall restrictions;
4. request/body/rate limits;
5. audit identity for every job;
6. CSRF/origin controls for browser use;
7. a versioned API contract;
8. secret-redaction tests;
9. reverse-proxy timeout/SSE configuration;
10. an explicit rule preventing config actions from becoming remotely runnable.

Until then, keep it on loopback.

---

## 23. Operational Playbooks

### 23.1 New-site onboarding

1. Confirm written authorization and network scope.
2. Create service-account config and secret files.
3. Replace default SNMP communities; prefer SNMPv3.
4. Set site subnets and conservative worker/timeouts.
5. Configure controller and core addresses only after testing reachability manually.
6. Run `db migrate`, `db status`, and `db integrity`.
7. Dry-run inventory scope.
8. Scan a single known device.
9. Compare discovered hostname/model/serial/MAC to ground truth.
10. Expand to a small range, then the approved subnet.
11. Run AP scan and inspect raw versus canonical counts.
12. Run topology scan and verify raw neighbors before trusting the graph.
13. Refresh memory and inspect confidence/source.
14. Run a changed-only backup on one lab device.
15. Document parser exceptions and naming aliases.
16. Only then schedule broader routines.

Commands:

```bash
netops inventory scan 198.51.100.71 --dry-run
netops inventory scan 198.51.100.71
netops inventory details 198.51.100.71 --json
netops ap scan
netops topology scan
netops topology neighbors --json
netops memory refresh
netops health attention
netops backup run 198.51.100.71
```

### 23.2 Morning operations

```bash
netops workflow morning-check
netops health offline
netops health attention
netops topology changes --limit 50
netops ap moves --limit 50
netops jobs list --limit 30
```

Then classify each signal as current incident, stale-data artifact, expected change, or parser/source issue. Refresh only the affected domain before launching a broad deep scan.

### 23.3 Full observation refresh

For the broadest current picture:

```bash
netops inventory scan
netops ap scan
netops topology scan
netops memory refresh
netops health attention
```

`workflow refresh-inventory` does not include the full switch inventory scan, so add it explicitly when device identity needs refresh.

### 23.4 Device reported offline

```bash
netops health status --json
netops diagnose latency <exact-ip> --count 10
netops inventory details <exact-ip> --json
netops memory device <exact-ip> --json
netops topology neighbors <hostname> --json
netops health timeline --limit 100
```

Decision path:

1. If ICMP works, investigate stale health import or ICMP target mismatch.
2. If ICMP fails but neighbors remain, check VLAN/routing/power and upstream port.
3. If topology link disappeared at the same time, inspect upstream device and cabling.
4. If many peers fail, treat it as a site/uplink event rather than one-device failure.
5. Do not run configuration changes until management reachability and recovery path are understood.

### 23.5 AP missing or offline

```bash
netops ap list <name> --json
netops ask "Show alternate names for <name>"
netops ask "Where was <name> connected before?"
netops ap unjoined <name>
netops memory device <name> --json
netops ap timeline <name>
netops topology neighbors <switch> --json
```

Check whether the AP was filtered by WLC naming/IP rules, represented under an alias, unjoined, seen only by controller, or previously attached to another port.

### 23.6 Investigate an AP move

```bash
netops ap moves --limit 100
netops ap timeline <ap>
netops memory device <ap> --json
netops memory port <old-switch> <old-port>
netops memory port <new-switch> <new-port>
netops topology changes --limit 100
```

Validate both old/new source evidence and scan times. A naming merge can look like a move if source records changed concurrently.

### 23.7 Find an endpoint from IP or MAC

```bash
netops memory ip 198.51.100.92
netops lookup core 198.51.100.92
netops memory mac 0200.0000.0025
netops lookup mac CORE01 0200.0000.0025
```

Use memory first for historical/current cached evidence, then a live lookup for current switching state. Refresh memory afterward if you want the observation available to later questions.

### 23.8 VLAN investigation

```bash
netops vlan locate <switch> 120
netops vlan propagation <switch> 120
netops device show <switch> "show interfaces trunk"
netops topology neighbors <switch>
```

Before changing anything, verify vendor, target interface, intended access/trunk mode, existing native/allowed VLANs, spanning-tree implications, and out-of-band recovery.

### 23.9 Controlled VLAN change

```bash
netops backup run <exact-switch-ip>
netops vlan set <exact-switch-ip> Gi1/0/7 --access 120 --dry-run
netops device show <exact-switch-ip> "show interface Gi1/0/7 switchport"
netops vlan set <exact-switch-ip> Gi1/0/7 --access 120 --confirm
netops device show <exact-switch-ip> "show interface Gi1/0/7 switchport"
netops backup run <exact-switch-ip>
netops backup diff <exact-switch-ip>
```

The command helper saves configuration automatically. Still verify startup/saved state through an approved read command.

### 23.10 Backup audit

```bash
netops workflow backup-online ZONE10
netops backup verify --limit 200
netops health attention --limit 200
netops backup history <critical-device>
netops backup diff <critical-device>
```

Externally verify backup files, hashes, permissions, retention, off-host copy, and restore drills. NetOps metadata alone is not disaster recovery.

### 23.11 Filtering or interception investigation

```bash
netops diagnose filtering example.com
netops diagnose latency example.com --count 10
netops diagnose filtering cloudflare.com
```

Compare multiple known domains and a known-good network. Preserve raw resolver, certificate issuer, proxy, and firewall context before concluding that a path is filtered or intercepted.

### 23.12 Database incident

```bash
netops db status --json
netops db integrity --json
netops db path
```

Then stop writers, take a consistent backup, inspect disk/permissions, and use `db repair` only after preserving evidence. If integrity fails, prefer recovery from a known-good DB or SQLite recovery workflow over repeated mutation.

---

## 24. Security Model

### 24.1 Trust boundaries

NetOps crosses these boundaries:

- operator input into subprocess arguments;
- local config into SNMP/SSH commands;
- untrusted device output into parsers and SQLite;
- local browser into unauthenticated job API;
- secrets from disk into environment variables/processes;
- observed SSH host keys into the managed trust store;
- the local terminal operator into generated action/job context;
- the local encrypted credential vault and process environment;
- configuration output into backup files.

Each boundary needs explicit operational controls.

### 24.2 Positive controls present

- v8 configuration actions require preview or confirmation; TUI configuration
  also requires reason, ticket, exact phrase, and matching preview hash.
- WebUI and arbitrary generated config actions are preview-only.
- `device show` applies a read-only/sensitive-output policy.
- subprocess commands are represented as argument lists in the Python core rather than one shell string.
- API responses recursively redact secret-looking keys.
- `.env` is written mode 0600 by the wizard.
- GPG protects the local SSH password at rest.
- vault updates and configuration backups use private staged files followed by atomic replacement.
- legacy remote-vault sync is disabled and tested not to invoke a network client.
- invalid/placeholder MACs are rejected from physical identity.
- job processes use process groups, timeouts, and cancellation handling.
- jobs persist local actor/UID/session, reason, ticket, phases, structured result,
  and audit context.
- SSH adapters share a private managed known-hosts file; changed keys fail
  closed and strict enrollment is fingerprint-bound and audited.
- direct helper writes fail without the core's process-local capability marker.
- SQLite migrations suppress fake operational events.

### 24.3 Material risks

#### SSH host authenticity

Normal SSH uses either:

```text
StrictHostKeyChecking=accept-new
StrictHostKeyChecking=yes
UserKnownHostsFile=<private NetOps known_hosts>
```

`accept-new` protects against changed keys but does not independently authenticate
first contact. High-assurance deployments must verify fingerprints out of band,
enroll them, and use `strict`. Break-glass bypass remains a deliberate residual
risk and must be incident controlled.

#### Password automation

`sshpass` exposes the decrypted password to the child environment. Same-account or privileged process inspection and memory compromise remain relevant.

#### SNMPv2c

Default communities are insecure and sent in cleartext. Use isolated management networks, rotate values, minimize privilege, and prefer SNMPv3 authPriv.

#### Local API

Any process that can reach the bound address can start registered network-read/local-write jobs. Binding beyond loopback creates remote operational access without identity or authorization.

#### Internal helper capability

Direct `netops-control config` and `netops-control vlan` fail unless the core
provides its process-local audited-confirmation marker. Direct `show` enforces a
bounded read-only/diagnostic allowlist, argument-count validation, and
separator/secret blocking. File execution permissions are still useful defense
in depth, but the public `netops` launcher is the supported policy boundary.

#### Backup content

Running configuration contains credentials, addressing, topology, AAA, and security policy. Redaction is incomplete. Backups need encryption at rest, least privilege, retention, and access logging outside this codebase.

#### Legacy plaintext configuration

An imported pre-profile installation may still contain a plaintext secret file.
The migration skips its values and `config validate` warns until the operator
moves each value into named encrypted storage and securely retires the source.

#### Legacy algorithms

Legacy SSH mode re-enables weak KEX, host key, and cipher choices. Segment and upgrade devices rather than normalizing permanent use.

### 24.4 Recommended production controls

1. Dedicated non-login or tightly controlled service account.
2. Rootless operation with fixed `HOME`.
3. File permissions: XDG profile directories `0700`; profile, known-hosts,
   encrypted stores, and files containing evidence `0600`.
4. Management-network ACLs for SNMP/SSH.
5. SNMPv3 authPriv and least-privilege SSH accounts.
6. Independently verify/enroll critical device keys, then set host-key mode to `strict`.
7. Remove obsolete plaintext secret files after migration rehearsal and keep
   remote credential export disabled.
8. Loopback-only WebUI.
9. Export local job/audit records to central immutable collection and add an
   authenticated identity layer before any shared remote API use.
10. Encrypted, off-host backup replication and restore testing.
11. Preserve the core-only helper capability boundary and restrict helper file
   execution as defense in depth.
12. Change windows and out-of-band access for every remote write.

---

## 25. Troubleshooting

### 25.1 Start with five facts

For any issue, record:

```bash
netops --help
netops db path
netops db status --json
netops db integrity --json
netops health attention --json
```

Also record effective user, `HOME`, current command, target form, exit code, and whether output came from plain or JSON mode.

### 25.2 Unknown domain or old examples fail

Symptom:

```text
Unknown NetOps domain: probe
```

Cause: helper/legacy documentation uses the pre-v8 verb-first interface.

Use:

```bash
netops diagnose latency <target>
netops inventory scan <target>
netops device ssh <target>
netops backup run <target>
```

not `netops probe`, `netops discover`, `netops connect`, or `netops control`.

### 25.3 Verify the installed version

Use the central version command first:

```bash
netops --version
netops --help
netops help --json
```

If these disagree, the launcher and sibling `VERSION` file came from different deployments. Reinstall the complete versioned directory rather than copying individual helpers.

### 25.4 A legacy helper asks for setup

Cause: a compatibility helper was invoked outside the profile environment or
under the wrong account. Exit instead of entering production values. Confirm
`netops profile paths`, effective user, `HOME`, XDG variables, and the selected
profile, then run the public command. `netops init` is the supported setup path;
automation must never rely on a source-time interactive wizard.

### 25.5 Target not found

Checks:

1. Try exact IP.
2. Confirm target exists in the relevant flat file and canonical inventory.
3. Use `inventory list <text> --json`.
4. Check capitalization is not the problem; fixed search is case-insensitive in helper paths.
5. Test DNS with the operating system.
6. Confirm shorthand octets.

### 25.6 Ambiguous target without terminal

Use an exact IP/hostname. `--first` is acceptable for read-only automation only when deterministic ordering is documented. Avoid `--all` for writes.

### 25.7 Device shown offline but responds

Run a fast health check, then import and inspect timestamps:

```bash
netops health check <exact-ip>
netops inventory import-flat
netops inventory details <exact-ip> --json
```

Look for duplicate IP/name rows, stale flat files, ICMP behavior, or execution under a different account/cache.

### 25.8 SNMP discovery lacks detail

Check:

- version and credentials;
- ACL/source address;
- UDP 161 path;
- symbolic MIB availability;
- timeout;
- controller-specific community overrides;
- whether the device is supported by classification/parser rules.

Do not increase workers/timeouts blindly before testing one host with `snmpget`.

### 25.9 SSH says password file not found

Set it for the same operating-system account:

```bash
netops vault status
netops vault set
```

Verify `~/.ssh/sshpass_cache.gpg`, mode `0600`, `ssh_user`, `gpg`, `sudo`, and
`sshpass`. If status reports `legacy-gpg` and a graphical GPG dialog appears,
run `netops vault migrate`; the legacy passphrase is requested once in the
terminal. If a sudo-gated vault reports `root_key: missing`, restore
`/etc/netops/vault-keys/<uid>.key` from backup or use `netops vault set` to
replace the vault with a known device SSH password. Root access cannot recover
GPG ciphertext after its random key has been lost.

If an older v8 build reports `A controlling terminal is required for secret
input` even though the command is running in an interactive terminal, update to
the current build. The helper now accepts its inherited terminal descriptor
when process-session isolation makes `/dev/tty` unavailable.

If `device ssh` reports that the SSH username is not configured, set the
non-secret profile value and validate it before touching the password vault:

```bash
netops config set ssh_user operator
netops config validate
```

### 25.10 SSH output is empty

Generic helper stderr is hidden unless `NETOPS_SSH_SHOW_ERRORS=true`. Temporarily enable it for diagnosis, protect captured output, and check authentication, algorithms, prompt type, paging, command syntax, and Aruba wrapper resolution.

### 25.11 Aruba automation hangs or truncates

Check:

- `netops_aruba_ssh.exp` exists beside the loaded `netops-lib.sh` and is executable, or `NETOPS_ARUBA_SSH_WRAPPER` names the intended executable wrapper;
- `expect` and `sshpass` exist;
- prompt ends in `#`, `>`, or `$` as expected;
- device banner/paging behavior;
- command timeout and output volume;
- whether the platform field is exactly recognized as Aruba.

### 25.12 Show command blocked

The v8 policy intentionally blocks running config, secrets, separators, and unsafe verbs. Use a narrower operational show command. If sensitive output is genuinely required, handle it through an approved manual procedure rather than weakening the global policy casually.

### 25.13 Configuration exits 7

This is the confirmation gate:

```bash
netops device config ... --dry-run
```

Review, then use `--confirm` only under an approved change.

### 25.14 Backup says unchanged

The SHA-256 equals the latest saved backup. This is expected changed-only behavior. Check history rather than looking for a new file.

### 25.15 Backup history is empty but files exist

Possible causes:

- shell helper wrote to a different SQLite default than `NETOPS_SQLITE_DB`;
- operation ran as another user;
- old backups predate metadata;
- SQLite CLI was missing and record insertion was ignored;
- target resolved to another IP.

Compare `netops db path`, default cache path, backup file owner, and exact device IP.

### 25.16 AP count seems too low

Canonical AP reconciliation intentionally merges aliases. Compare:

```bash
netops db status --json
netops ask "Which AP records were merged?" --json
netops ap list --json
```

`ap_observations` versus canonical `aps` explains many count differences. Also check WLC filters and malformed observations.

### 25.17 AP count seems too high

Look for records without valid MAC/signature evidence, naming forms that do not normalize to the same location/AP number, conflicting valid MACs, and stale duplicate source rows. Conflicting physical MACs are intentionally kept separate.

### 25.18 Topology shows many removals

Do not assume a mass outage. Confirm the latest scan was complete and authenticated. Inspect `neighbor.db`, `topology neighbors`, scan logs, and source device reachability. A partial current set is compared against the full prior snapshot.

### 25.19 Memory has disappeared relationships

This means the latest derivation no longer found the relationship. It preserves historical evidence. Refresh source inventory/topology, inspect the relationship event's previous/current JSON, and evaluate source freshness.

### 25.20 Natural Ask gives no result

Use `netops ask patterns`, provide an exact entity, inspect aliases, or name the public domain/action explicitly. Retrieval remains bounded to deterministic state workflows; operations remain bounded to the 95 registered actions. If a plan reports `needs_clarification` or `blocked`, supply the listed fields or honor the policy reason rather than trying to bypass it.

### 25.21 WebUI is blank or reports missing state

Check:

```bash
netops db status --json
netops serve --port 8788
curl -s http://127.0.0.1:8788/api/health
curl -s http://127.0.0.1:8788/api/webui/status
```

Confirm `webui/dist/index.html` and referenced hashed assets exist beside the resolved deployment. Rebuild dist after source changes.

### 25.22 Job stays queued/running after restart

Starting a new job-owning core marks abandoned rows stale where applicable. A
dead TUI/server process cannot continue a job. Review logs and submit a fresh
safe job after understanding why the owner stopped.

### 25.23 Some diagnostics never gain structured history

`core-ping`, `speed`, `throughput`, `port-health`, `cable`, and `doctor` persist in their current-core workflows. Legacy continuous latency, filtering, and SNMP interface monitor paths can still finish with job logs but without the same unified record. Check `/api/diagnostics`, `diagnostic_runs`, the specialized table, and the job log. Do not convert “no row” into a network pass/fail conclusion.

### 25.24 Internet speed cannot discover or complete servers

Run:

```bash
netops diagnose doctor --online --json
netops diagnose filtering speedtest.net
netops diagnose speed --runs 2 --dry-run --json
```

Interpret common failures precisely:

| Symptom | Meaning/action |
|---|---|
| `CERTIFICATE_VERIFY_FAILED` | Required corporate/root CA is unavailable to the process; install it properly or use an approved `--ca-file` |
| `401 Authorization Required` | Proxy/filter/benchmark endpoint rejected the request; obtain approved authentication/policy or use controlled iperf3 |
| connection reset/read timeout | Retry once, check path/filtering, then stop treating the upstream service as reliable |
| fewer than two complete servers | Result is deliberately rejected; one server is insufficient for the reliable aggregate |
| high coefficient of variation/loss | Result is valid but low/medium confidence; investigate path load and retest |

Never add `-k`, disable hostname verification, or invent a speed from a partial download. Under WSL, NetOps imports trusted Windows roots securely, but it does not automatically inherit browser cookies or integrated gateway authentication.

### 25.25 Cable status says `NOT_RUN`

The read-only command found no previously stored TDR result. Preview a new test, verify that the exact port is copper and can tolerate interruption, then schedule/confirm it:

```bash
netops diagnose cable <switch> on <port> --test --dry-run
netops diagnose cable <switch> on <port> --test --confirm
```

For optical media, use optical diagnostics/DDM and link/error counters instead; NetOps refuses known fiber on the active AOS-Switch path. Use certified cable test equipment when a formal wiremap or category certification is required.

### 25.26 SQLite is locked

Stop extra server/helper processes, identify long-running transactions, inspect WAL/SHM ownership, and avoid deleting WAL files manually. Use checkpoint/repair only after a consistent backup.

---

## 26. Testing and Release Verification

### 26.1 Reproducible release checks

Release evidence comes from the current source and built artifacts, not a count
or live-network anecdote copied into this book.

| Gate | Required evidence |
|---|---|
| Python suite | Full discovered pytest suite passes on supported Python versions; environment-only GPG skips are identified |
| Shell syntax | Every shipped Bash helper and installer passes `bash -n`; ShellCheck findings are reviewed |
| Startup | `--version`, root help, and TUI help work without creating runtime state |
| SQLite | Empty and migrated profile reach schema 13; quick/integrity checks return `ok` |
| Profiles | Isolation, precedence, copy-first migration, rollback, and idempotency tests pass |
| Secrets | Named-secret conversion is atomic; values do not appear in argv, logs, config, support bundle, or output |
| Ingest | Schema, duplicate, sparse, stale, pagination, TLS, failure, and quarantine fixtures pass |
| Plugins | Disabled discovery, enablement, incompatibility, collision, provenance, import failure, and write rejection pass |
| Device drivers | Accepted fixtures cover success, empty, malformed, rejected-command, timeout, and wrapped output for every advertised family |
| Ghoster | Healthy, blocked, looped, stale, ambiguous, limited, unsupported, and partial-failure paths pass |
| TUI/WebUI | Light and monochrome TUI snapshots pass; WebUI tests and production build succeed |
| Generated docs | Registry-derived Markdown, man page, and Bash/Zsh/Fish completions have no drift |
| Packaging | Wheel/sdist build, metadata validation, isolated wheel smoke, checksums, SBOM, and provenance complete |
| Privacy | Source tree, clean public history, wheel, sdist, docs, completions, AI files, and WebUI assets pass the private denylist and secret scan |

### 26.2 Authorized-lab promotion gates

Synthetic fixtures prove parser behavior, not universal device support. Stable
promotion additionally requires clean Linux and WSL2 installation, accepted
read fixtures for Cisco IOS/IOS-XE, Cisco NX-OS, Aruba AOS-S, Aruba AOS-CX, and
RUCKUS FastIron, an authorized real Ghoster path, migration/rollback rehearsal,
and verified documentation examples. No automated test may contact an
unapproved network. Device writes, active cable tests, credential use, external
speed traffic, restore rehearsal, and controller APIs require explicit lab
authorization and scoped test identities.

### 26.3 Routine source checks

Run from the repository root:

```bash
env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. \
  .venv/bin/pytest -q -p no:cacheprovider
.venv/bin/python generate_reference.py --check
.venv/bin/python privacy_check.py --root .
.venv/bin/python -m pip_audit --strict .
bash -n install.sh scripts/*.sh netops-connect netops-probe \
  netops-discovery netops-lib.sh netops-control netops-legacy
cd webui && npm run build && git diff --exit-code -- dist
```

Add ShellCheck to CI even though it was not installed in the audited environment:

```bash
shellcheck netops-connect netops-probe netops-discovery netops-lib.sh netops-control netops-legacy
```

Expect needs at least parser/startup and mocked-session tests. Do not point automated tests at a real network by default.

### 26.4 Isolated CLI/database test pattern

Use an isolated environment:

```bash
export NETOPS_CONFIG_DIR=/tmp/netops-test/config
export NETOPS_CACHE_DIR=/tmp/netops-test/cache
export NETOPS_SQLITE_DB=/tmp/netops-test/cache/netops.sqlite3
export NETOPS_BACKUP_DIR=/tmp/netops-test/backups
export NETOPS_PROGRESS=0

./netops db migrate --json
./netops db status --json
./netops db integrity --json
./netops inventory list --json
./netops commands list --json
./netops ask patterns --json
```

For shell-backed tests, also set `HOME` to a fixture directory containing safe `~/.config/netsnmp/netsnmp.conf` and `.env`; Python overrides alone are not enough.

### 26.5 Frontend checks

```bash
cd webui
npm ci
npm run build
```

Recommended additions:

- `vue-tsc --noEmit` type checking;
- component tests for resource normalization and command controls;
- Playwright tests for all eight views;
- keyboard-only navigation;
- axe/WCAG checks;
- desktop/mobile screenshot regressions;
- SSE reconnect/cancel behavior;
- large inventory/topology fixtures;
- API error and partial-resource rendering.

### 26.6 Lab integration matrix

Before a release, test each supported adapter with recorded and live-lab output:

| Area | Cases |
|---|---|
| Cisco IOS/IOS-XE | inventory, show, config, backup, VLAN, ARP/MAC, CDP/LLDP |
| Aruba | prompt, paging, show, config, backup, LLDP, save behavior |
| Cisco WLC | AP inventory, filters, joined and unjoined output |
| Ruckus vSZ | AP inventory, model OIDs, direct model enrichment |
| SNMP | v2c, v3 authNoPriv, v3 authPriv, timeout/auth failure |
| SSH | normal key algorithms, legacy fallback, auth failure, banner/prompt variations |
| Targets | exact, shorthand, range, file, DNS, ambiguous, non-interactive |
| Partial scans | timeout, one bad device, interrupted run, stale rows |
| Backups | first save, unchanged, changed, redacted, SSH failure, hash/file verification |
| Diagnostics | no loss, loss, no DNS, TLS inspection, counter wrap, 32/64-bit counters |

### 26.7 Release gate

A credible release should require:

1. clean version-controlled baseline;
2. all unit/static/frontend tests passing;
3. schema migration from each supported previous version;
4. backup and restore of a realistic SQLite fixture;
5. parser fixtures for supported firmware families;
6. dry-run snapshots for every config action;
7. security review of API, SSH, secret handling, and command construction;
8. reproducible frontend dist;
9. updated live help and this handbook;
10. lab sign-off before production rollout.

---

## 27. Maintainer Guide

### 27.1 Core modules and ownership

**`netops_platform/core.py`** owns public behavior. The root
`netops_core.py` file is only its v8 compatibility alias:

- constants, version, exit codes;
- path and config loading;
- SQLite schema/migration/state access;
- flat-file import/export;
- derived identity/health/topology/relationship state;
- global option parsing;
- domain/action help and dispatch;
- subprocess policy and progress;
- command registry and workflows;
- jobs and process lifecycle;
- API/static server.

**`netops_platform/identity.py`** owns physical identity rules. Keep identity
normalization pure and heavily tested. A change can merge or split production
AP history, which has a larger blast radius than a display-only change.

**`netops_platform/devices.py`** owns the device-family registry, detection precedence,
capability states, semantic command templates, paging, logout, and MAC format.
Core workflows request operations from this module instead of embedding vendor
commands.

**`netops_platform/ingest.py`** owns versioned channel observations, provider
delivery, provenance, idempotency, quarantine, and materialization.
**`netops_platform/inventory_ingest.py`** owns the non-destructive merge used
by compatibility shell observations. All discovery/controller providers must
enter one of these boundaries so a sparse source cannot erase richer state.

**`netops_platform/mac_registry.py`** owns the authoritative IEEE registry cache,
validation, atomic refresh, longest-prefix lookup, and provenance.

**`netops_platform/network.py`** owns pure vendor-neutral parsers for network output.
It must not open transport or write state.

**`netops_platform/ask.py`** owns deterministic language behavior. Every new
intent should map to a bounded operation and return a workflow explanation.

**Shell helpers** own network protocols and the remaining compatibility
parsers. New parsing should move toward pure Python fixture-tested functions.
Shell helpers must not become the public policy layer.

### 27.2 Adding a public command

Do all of the following:

1. Choose an existing domain unless a genuinely new bounded context is needed.
2. Add domain/action help with usage, argument meaning, examples, and accurate risk language.
3. Implement dispatch in the appropriate `cmd_*` method.
4. Use argument arrays, never concatenate untrusted shell strings.
5. Decide whether it reads local state, reads network, writes local state, or writes devices.
6. Enforce dry-run/confirmation before any remote write.
7. Add a `CommandSpec` if WebUI/API/workflow access is intended.
8. Implement `command_for_action` and argument normalization.
9. Add unit tests for success, validation, dry-run, JSON, and failure exit code.
10. Add parser fixtures for any vendor output.
11. Update API/UI only after registry behavior is stable.
12. Update this handbook and examples.

Do not add a command only to one interface. Registry, CLI, API, UI, help, and documentation drift is already a project risk.

### 27.3 Adding a schema migration

1. Increment `SCHEMA_VERSION` from the current value 13.
2. Make every DDL/data step idempotent or explicitly version-gated.
3. Test an empty DB and copies of every supported prior schema.
4. Preserve append-only history unless the migration is a documented repair.
5. Run invalid-identity sanitation where relevant.
6. Reconcile derived state in migration mode.
7. Verify structural events are suppressed and logged in `scan_runs`.
8. Run quick/integrity checks.
9. Test interruption/restart behavior.
10. Document rollback or restore requirements.

Never edit a user's DB manually as the migration strategy.

### 27.4 Changing AP identity rules

Identity changes can alter counts, aliases, attachment history, health identities, and Natural Ask answers.

Required tests:

- the same AP under configured prefix/hyphen/spacing variants merges;
- meaningful different locations/AP numbers remain separate;
- conflicting valid physical MACs never merge;
- a no-MAC observation cannot bridge two conflicting MAC groups;
- malformed/blank generic AP rows are not active;
- placeholder and multicast MACs are rejected;
- canonical representative is deterministic regardless of input ordering;
- migration does not emit false move/history events;
- historical relationships remain interpretable after canonical changes.

Prefer explicit new evidence over increasingly broad fuzzy matching.

### 27.5 Adding an Ask retrieval or command intent

1. Decide whether this is state retrieval or an operation; do not blur the execution boundary.
2. Add diverse examples, including local naming and likely typos.
3. Specify extraction and entity-resolution rules.
4. Reuse canonical payload/query methods rather than duplicate SQL.
5. For retrieval, return answer, timestamped rows, suggestions, intent, and evidence steps.
6. For operations, add/extend a `CommandSpec`, validated argv builder, required-field rules, safety metadata, argument extraction, preview behavior, and execution policy.
7. Add no-data, ambiguous, stale, missing-argument, unsafe-input, confirmation, and follow-up tests.
8. Ensure controller evidence is not overstated.
9. Confirm no external AI, model-generated shell, arbitrary SQL, or helper bypass is introduced.

### 27.6 Changing a shell parser

Device output is untrusted, version-dependent input. Before changing regex/awk logic:

1. Capture sanitized fixtures from every known firmware variant.
2. Preserve original whitespace/control sequences in fixtures where parsing depends on them.
3. Define expected structured rows.
4. Test missing columns, wrapped lines, paging banners, timeouts, and error messages.
5. Reject malformed results instead of writing plausible-looking bad identities.
6. Record scan completeness/source status.
7. Keep parser and transport concerns separate where practical.

### 27.7 Changing the WebUI

`App.vue` currently contains state, API client, command forms, all views, and templates. Incremental extraction is warranted when adding features:

- typed API client and response schemas;
- resource store/composables;
- one component per major view;
- reusable tables/status/log components;
- route or URL state for deep links;
- explicit loading/empty/error states;
- test fixtures independent of a live network.

Do not hand-edit minified `dist` assets. Change source, build, test, then deploy the generated output.

### 27.8 Version consistency

Public launchers, package metadata, and help read the central `VERSION` file
(`8.5.0b2`). Historical helper comments may still describe adapter generations;
those are not release versions. New user-visible version output must come from
`VERSION`, and startup/package smoke tests enforce that behavior.

### 27.9 Observability expectations

Future code should emit enough structured data to answer:

- what user/service initiated the operation;
- exact target set after resolution;
- exact command/action ID and version;
- start/finish/duration/exit code;
- read/write/risk class;
- source completeness and parser version;
- records added/changed/removed;
- whether derived state refreshed successfully;
- secret-redacted error context.

TUI-created jobs record the local OS actor, UID, session, reason, and ticket.
That is accountable workstation context, not authenticated remote identity. The
unauthenticated HTTP API still needs an identity/authorization model before
shared or remote deployment.

---

## 28. Known Limitations and Defects

This section records observed implementation facts, not hypothetical feature requests.

### 28.1 P1: Internet benchmarking depends on external policy/services

The secure speed workflow cannot force a third-party benchmark through a gateway that blocks the category, requires browser-integrated authentication, rewrites uploads, rate-limits discovery, or returns `401`. NetOps reports the failure and retains chronology but cannot produce a valid Internet-speed number without a completed path. Add an organization-approved authenticated proxy/backend or operate controlled external iperf infrastructure; never weaken TLS to make a benchmark pass.

### 28.2 P1: legacy diagnostic persistence remains incomplete

v8.5 beta directly persists core ping, Internet speed, throughput, port-health, cable, and doctor output. The legacy continuous latency, filtering, and SNMP interface monitor still do not all share one schema-validated insertion path. Unify those remaining actions into `diagnostic_runs` and retain specialized rows only as indexed projections.

### 28.3 P0: unauthenticated operational API

`netops serve --host` can expose an API that starts network-read/local-write jobs with no authentication or authorization. Loopback default reduces exposure but does not make non-loopback binding safe. Either remove arbitrary host binding until controls exist or add a proper security layer.

### 28.4 Resolved in v8.5 beta: managed SSH host-key verification

All generic and prompt-aware adapters now use the private managed trust store.
The core provides status, scan, SHA-256-bound enrollment, forget, atomic mode
`0600` writes, and audit events. Changed keys fail closed. Deployments must still
move critical devices from compatibility `accept-new` to enrolled `strict`.

### 28.5 Resolved in v8.5 beta: direct helper write boundary

`netops-control config` and `vlan` now deny execution without the core's internal
audited-confirmation marker. Direct show/VLAN/MAC input remains independently
validated. The marker is deliberately process-local capability plumbing, not an
operator flag.

### 28.6 Resolved in v8.5 beta: backup DB path override

Shell backup metadata now honors `NETOPS_SQLITE_DB`, then `NETOPS_CACHE_DIR`, before choosing the effective-UID default. Subprocess tests also verify private atomic backup files, safe device-derived names, and reuse of the real prior path for unchanged content.

### 28.7 P1: partial scans can look like removals

Topology compares the current neighbor set directly with the prior snapshot. There is a `scan_runs` completeness concept, but current link replacement/event derivation does not robustly gate removals on a proven complete scan. Interrupted/auth-failed scans can create false link-removal alerts.

### 28.8 Resolved in v8.5 beta: workflow step policy and summaries

Workflow manifests now declare `continue` or `stop` per step, capture child JSON,
emit live progress, and produce one structured `SUCCESS`, `PARTIAL`, or `FAILED`
step matrix. Future dependency-heavy workflows may still need an `always-run`
cleanup policy.

### 28.9 P1: arbitrary configuration is not transactional

Arbitrary multi-command streams can still leave partial saved state. The typed
VLAN action now has preflight, required backup, apply, read-back verification,
audit, and manual rollback evidence, but it is not an automatic device
transaction. Additional write actions must earn runnable status independently.

### 28.10 P1: VLAN heuristics and non-Cisco writes remain incomplete

Read command selection is now explicit for Cisco IOS, Aruba AOS-S, Aruba
AOS-CX, and RUCKUS FastIron. Multi-root/multi-VLAN traversal uses the same
driver boundary. Aruba/RUCKUS writes fail closed. A legacy propagation parser
can still infer an uplink from a fixed native-VLAN convention, and only Cisco
VLAN writes have been promoted. Replace that heuristic with parsed
interface/LAG state and
accepted firmware fixtures before expanding write support.

### 28.11 P1: interface monitor is SNMPv2c-only

The shared library supports SNMPv3, but interface diagnostics read the first v2c community directly. This blocks secure SNMP-only deployments and conflicts with the configuration model.

### 28.12 Resolved in v8.5 beta: unsafe remote password sync removed

Legacy remote credential export is absent from effective configuration and
compatibility functions fail closed without a network request. Any future
secret-manager integration requires a new threat model, explicit authorization,
scoped identity, rotation, revocation, and audit design.

### 28.13 P1: no API body/rate limits

`read_body_json` trusts `Content-Length` and reads that many bytes. There is no rate limit or concurrency quota per client beyond global job concurrency. A local or exposed client can consume memory/disk/log capacity.

### 28.14 P1: remote authenticated audit identity absent

TUI jobs record local actor/UID/session, reason, ticket, preview hash, typed
confirmation, action, command, result, and timing. The HTTP API has no
authenticated identity or authorization model, and local OS identity alone is
insufficient for a shared operational service.

### 28.15 P2: helper command naming drift

The public core and compatibility launcher now share the central `VERSION` file and support `--version`. Some internal helper help/comments still expose historical adapter command names. Continue converging generated help around the public v8 noun-first interface and label helpers as internal.

### 28.16 P2: service deployment remains unpackaged

The Python package, locked environment, console entry point, helper scripts,
packaged stylesheet, migration guide, and doctor checks now exist. There is
still no system service unit, formal OS support declaration, automated state
backup hook, or authenticated shared-service deployment.

### 28.17 P2: shell library has source-time side effects

Sourcing `netops-lib.sh` creates directories, touches cache files, and can launch an interactive wizard. Libraries should load definitions without mutating state; initialization should be explicit.

### 28.18 P2: history grows without pruning

`memory prune` is reserved/disabled. Jobs, logs, relationship events, identity history, health events, topology events, and backups need retention policies and archive strategy.

### 28.19 P2: legacy HTTP API contracts are untyped and inconsistent

The new local application layer uses `ResultEnvelopeV1`, `DatasetV1`, typed
findings/provenance, previews, operator context, and job events. Legacy HTTP
endpoints still return inconsistent arrays/wrappers and the Vue client uses
broad `any` types. Adapt the API to the versioned contracts and generate client
types.

### 28.20 P2: UI stylesheet and component accretion

Multiple style passes remain in one file and one component owns the application. Dead/overridden selectors increase regression risk and bundle size. Refactor only with visual/accessibility tests.

### 28.21 P2: topology UI truncates and uses a simple circle

Only the first 36 nodes and 80 edges are drawn. Labels are sliced to 18 characters. Large networks need filtering, search, clustering, layout algorithms, and explicit truncation notices.

### 28.22 P2: incomplete shell/API/browser coverage

The automated suite covers identity, chronology, Ask retrieval/planning, every
public action family, registry previews/addressability, safety gates, operator
context, alias administration, AI delegation, secure paired speed-backend
contracts, synthetic Cisco/Aruba/RUCKUS VLAN/interface/cable parsers, IEEE MAC
registry caching, normalized ingest, driver registration, iperf JSON,
bounded traversal, core-ping/speed/port persistence, direct-PID descendant
cleanup, atomic vault/backup/trust behavior, direct-write denial, diagnostic
target extraction, optical-TDR blocking, MAC movement, dry-run isolation, job
repair/events/results, v8 contracts, and responsive Textual interaction. Real
firmware fixture libraries, active TDR, external benchmark policy variants,
backup restore, concurrent socket-level HTTP/SSE reconnect behavior,
accessibility, and browser end-to-end regressions remain incomplete.

### 28.23 P2: backup verification name overstates behavior

`backup verify` displays metadata rather than proving file hash/existence/restore quality. Implement verification or rename the action.

### 28.24 P2: API refresh log can overstate success

Selected jobs suppress exceptions around flat-file import and then log `canonical state refreshed`. Make refresh outcome explicit and fail/partially fail the job when canonical synchronization does not complete.

### 28.25 Resolved in v8.5 beta: external UI glossary removed

The unrelated third-party UI glossary is not distributed. The concise normative
console system lives in `docs/ui-design-system.md`, with dependency attribution
in `THIRD_PARTY_NOTICES.md`.

---

## 29. Improvement Roadmap

### 29.1 P0: correctness and exposure

1. Prevent non-loopback API binding until authentication, authorization, CSRF,
   body/rate limits, and an authenticated actor model exist.
2. Run authorized lab acceptance against every supported Cisco/Aruba/RUCKUS firmware
   family and preserve sanitized parser fixtures.
3. Add a scalable vendor parser for complete large trunk-list verification;
   v8.5 beta currently samples boundaries and explicitly returns partial.
4. Gate topology removals on a proven complete scan.
5. Add regression and failure-injection tests for every P0 change.

### 29.2 P1: operational safety

1. Add fixture-backed model/firmware capability profiles to the structured
   device registry.
2. Extend the guarded transaction lifecycle to additional writes only after lab
   proof, exact verification, and rollback design.
3. Make all helpers honor one path/config object.
4. Add SNMPv3 to interface monitoring.
5. Add backup existence/hash/restore verification.
6. Add retention, archive, and prune policy for jobs/audit/history.
7. Export audit events to an immutable central sink.
8. Add controlled endpoint agents or approved test appliances for true
   endpoint-to-core and endpoint-to-Internet measurements.
9. Add an operator review queue for high-confidence identity candidates that
   lack enough physical evidence for an automatic merge.

### 29.3 P2: maintainability and mastery

1. Adapt HTTP endpoints to the versioned application contracts and generate a
   typed client/OpenAPI description.
2. Split network transport from parsing and expand sanitized fixtures.
3. Split the WebUI into tested view components or retire it after operator-use
   evidence favors the TUI.
4. Improve topology filtering, layout, large-data behavior, and historical diff.
5. Add operator RBAC and remote-safe deployment only if the operational need
   justifies its attack surface.
6. Generate the support matrix and fixture coverage report
   from shared driver metadata.
7. Add endpoint agents, gNMI provider lifecycle, syslog/trap ingest,
   configuration compliance, and topology simulation as separately scoped
   post-8.5 work.

### 29.4 How to propose an improvement

A strong proposal should answer:

```text
Title:
Observed problem:
Evidence (file/function/command/log):
Operator or system impact:
Risk class:
Current workaround:
Proposed behavior:
Compatibility/migration impact:
Security implications:
Acceptance tests:
Rollback plan:
Documentation changes:
```

Evaluate proposals with these questions:

1. Does it improve correctness, safety, or operator decision quality?
2. Is the source of truth clear?
3. Does it preserve history and explainability?
4. Does it work with partial/failing networks?
5. Can it be tested without production access?
6. Does it reduce or add bypass paths?
7. Is vendor-specific behavior explicit?
8. Are limits, timeouts, and retention bounded?
9. Will CLI, API, UI, and documentation remain coherent?
10. Can an operator recover when it fails halfway?

### 29.5 Suggested success metrics

- percentage of scans marked complete versus partial;
- parser fixture pass rate by vendor/firmware;
- false topology-removal rate;
- canonical AP merge/split corrections;
- stale inventory age distribution;
- backup success, unchanged, failure, and verified-restore rates;
- job failure/timeout/cancel rates;
- mean time from attention signal to verified cause;
- percentage of device changes with preview, approval, actor, and post-check;
- API/UI contract test coverage;
- host-key verification adoption;
- SNMPv3 versus v2c coverage.

---

## 30. Command Cheat Sheet

### Help and state

```bash
netops                         # interactive TUI
netop tui                      # shortest explicit TUI command
netops tui --view inventory
netops --no-tui                # no-argument CLI help
netops --help
netops help <domain> [action]
netops db path
netops db status --json
netops db integrity --json
```

### Inventory and APs

```bash
netops inventory scan [target]
netops inventory list [pattern] [--status ONLINE|OFFLINE]
netops inventory details <target> --json
netops inventory activity --file targets.txt
netops inventory import-flat
netops inventory export-flat
netops ap scan
netops ap list [pattern]
netops ap unjoined [pattern]
netops ap on-switch <switch>
netops ap moves
netops ap timeline [ap]
```

### Topology, memory, health

```bash
netops topology scan
netops topology show [target]
netops topology neighbors [target]
netops topology changes
netops memory refresh
netops memory switch <switch>
netops memory device <entity>
netops memory ip <ip>
netops memory mac <mac>
netops memory port <switch> <port>
netops memory timeline [target]
netops memory explain [target]
netops health check [target]
netops health status
netops health offline
netops health attention
netops health timeline
```

### Backups and safe device access

```bash
netops backup run <target> [--redact-secrets]
netops backup history <target>
netops backup diff <target>
netops backup verify
netops device ssh [--legacy] <target>
netops device trust-scan <target>
netops device trust-enroll <target> --fingerprint SHA256:VALUE --confirm
netops device trust-status [target]
netops device support [target]
netops device identity <first> <second>
netops device show <target> "show ..."
netops device inventory [target|--view]
netops device config <exact-target> <commands...> --dry-run
netops device config <exact-target> <commands...> --confirm
```

### VLAN, lookup, diagnostics

```bash
netops vlan locate <target[,target...]> <vlan[,vlan|range...]> [--depth N]
netops vlan propagation <target[,target...]> <vlan[,vlan|range...]> [--depth N]
netops vlan propagation --target SW1 --target SW2 --vlan 10,20-22 --depth 1-10
netops vlan propagation <targets> <vlans> --depth N --refresh-neighbors [--max-nodes N]
netops vlan set <exact-target> <interface> --access <vlan> --dry-run
netops vlan set <exact-target> <interface> --trunk <list> [--native N] [--replace] --dry-run
netops lookup core <ip|mac>
netops lookup mac inspect <mac>
netops lookup mac locate <mac> [switch]
netops lookup mac profile <mac> [switch]
netops lookup mac history <mac>
netops lookup mac vendor <mac>
netops lookup mac online <mac> [--refresh]
netops lookup mac registry status|refresh
netops diagnose latency <target> [--count N]
netops diagnose core-ping <target> [--core SWITCH] [--count N]
netops diagnose speed [--profile quick|balanced|thorough] [--runs 1-5] [--ca-file PEM]
netops diagnose throughput <iperf3-server> [--direction both|upload|download]
netops diagnose port-health <device> on <interface> [--sample-seconds N]
netops diagnose cable <device> on <interface>
netops diagnose cable <device> on <interface> --test --dry-run|--confirm
netops diagnose doctor [--online]
netops diagnose filtering [domain]
netops diagnose interface <device> on <interface> [--chart classic|histogram]
```

### Workflows, jobs, registry, ask, server

```bash
netops workflow morning-check
netops workflow refresh-inventory
netops workflow backup-online [target]
netops workflow site-health <target>
netops workflow ap-audit
netops jobs list
netops jobs show <id>
netops jobs logs <id>
netops jobs cancel <id>
netops commands list
netops commands show <id> --json
netops commands run <id> [args] --preview
netops ask "question"
netops ask patterns
netops ask aliases
netops serve [--host 127.0.0.1] [--port 8787]
```

### Never normalize these shortcuts

```text
Do not routinely call netops-control directly for writes.
Do not expose netops serve beyond loopback without a security layer.
Do not use --all for a configuration change.
Do not trust a stale cache as live network truth.
Do not treat redacted backups as safe or restorable by default.
Do not call controller-only AP context a physical switch port.
```

---

## 31. Glossary

**AP observation:** One source-specific AP row. Several observations can represent one physical AP.

**Canonical AP:** Reconciled physical AP identity exposed by v8 list/count/memory paths.

**Compatibility state:** Pipe-delimited files retained for shell helper operation.

**Core lookup:** Live ARP/MAC/interface lookup beginning at the configured core switch.

**Derived state:** Identity, health, topology, movement, and relationship data computed from current observations.

**Flat import:** Transfer from helper pipe files into canonical SQLite.

**Flap:** A recorded health status transition. The current counter is cumulative.

**Identity confidence:** Fixed evidence-strength score used during AP/relationship reconciliation, not a statistical probability.

**Intent:** A deterministic Ask classification that selects either a bounded retrieval workflow or a registered command plan.

**Command plan:** Non-executing structured action, arguments, preview, missing inputs, safety class, state effects, and execution policy returned by Ask.

**Job:** A TUI or WebUI/API operation tracked in SQLite and by the live core
instance that owns its supervised process group.

**Result envelope:** Versioned application result containing status, summary,
metrics, datasets, findings, provenance, raw evidence, and timing.

**Provenance:** Source, observation time, completeness, freshness, parser, and
driver metadata explaining where a result came from.

**Operator context:** Local actor, UID, session, reason, and ticket bound to a
job request. It is not a substitute for authenticated remote identity.

**Local write:** Changes cache, SQLite, logs, or backups without intentionally configuring a network device.

**Memory:** NetOps relationship current-state and event-history layer.

**Network read:** Active ping, SNMP, SSH show, controller, or diagnostic operation that should not change device configuration.

**Observation source:** Origin such as SNMP inventory, controller, topology, AP inventory, or core lookup.

**Partial:** Exit code 3; the operation completed enough to report an operational issue or incomplete outcome.

**Physical MAC:** Valid unicast, nonzero hardware identity accepted for canonical grouping.

**Preview:** Rendered command/plan that is not executed. It validates construction, not eventual network correctness.

**Relationship:** Typed subject/object evidence such as IP ownership, AP attachment, neighbor link, alias, or port occupancy.

**SSE:** Server-Sent Events, the one-way HTTP stream used for live job log lines.

**Stale job:** A queued/running DB row left by an earlier TUI/server owner and reconciled on restart.

**Target resolution:** Conversion of IP, shorthand, range, file, inventory text, or DNS name into one or more IPs.

**Topology snapshot:** Prior neighbor tuple set used to generate link-added/removed events.

**v8 noun-first interface:** Supported `netops <domain> <action>` public command model.

---

## Closing Operating Principle

Use NetOps as an evidence system: refresh the smallest necessary scope, inspect source and recency, compare canonical and raw observations, preview every write, and verify the network after execution. Mastery is not memorizing commands; it is knowing which layer produced an answer, what that layer can prove, what it cannot prove, and how to recover when the evidence is partial.
