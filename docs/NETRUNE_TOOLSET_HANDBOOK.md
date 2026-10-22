# Netrune Toolset Operator and Maintainer Handbook

**Zero-to-expert guide for Netrune Platform v8.5.0b3**

**Audit date:** 2026-08-08
**Last revised:** 2026-08-08
**Audited source:** `$HOME/src/netrune`
**SQLite schema:** version 12
**Audience:** new operators, senior network engineers, system administrators, maintainers, reviewers, and future contributors

This handbook explains the toolset that is actually present in the audited source tree. It does not assume prior knowledge of Netrune. It covers setup, architecture, data ownership, every supported command domain and action, the terminal operator console, traffic monitoring, operational playbooks, safety boundaries, troubleshooting, tests, implementation details, known defects, and a concrete improvement framework.

In an interactive terminal, running `netrune` with no arguments opens the v8
operator console. The stable automation and expert interface remains the
noun-first command:

```text
netrune <domain> <action> [arguments] [global flags]
```

Examples:

```bash
netrune inventory list ZONE10
netrune health offline
netrune memory switch ZONE10
netrune diagnose latency 1.1.1.1 --count 10
```

The files named `netrune-discovery`, `netrune-control`, `netrune-probe`, `netrune-connect`, and `netrune-legacy` are implementation helpers or compatibility layers. Their own help text still shows older commands such as `netrune discover` and `netrune control`. Do not treat those old examples as the preferred public interface. Use the v8 commands in this handbook unless you are debugging internals and understand the consequences.

---

## Contents

1. [Read This First: Safety Contract](#1-read-this-first-safety-contract)
2. [What Netrune Is](#2-what-netrune-is)
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
21. [Traffic Monitoring](#21-traffic-monitoring)
21A. [Excel Workbooks](#21a-excel-workbooks)
22. [Local Interfaces](#22-local-interfaces)
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

Netrune combines passive reads, local state changes, active network probing, SSH access, backups, and device configuration. Those are not equivalent risk classes.

### 1.1 The supported safety boundary

Use these rules every time:

1. Use `netrune ...`, not `netrune-control ...`, for normal operations.
2. Preview any device configuration before execution.
3. Review the exact target, interface, state effects, and generated command before confirming it.
4. Use an exact IP or hostname for writes. Avoid broad patterns, ranges, site names, and `--all` for configuration changes.
5. Expect no network listener. Netrune has no server component; every interface is a local process on the operator's machine.
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

Registered configuration actions are preview-only for background jobs. The CLI can
run only the typed guarded VLAN workflow; arbitrary device configuration remains
preview-only. The synchronous CLI requires either `--dry-run` or `--confirm`
for `device config` and `vlan set`.

### 1.3 Internal helper boundary

The internal helper `netrune-control` denies direct `config` and `vlan` execution.
Only the core can supply the process-local audited-confirmation marker after its
public policy gate. Direct `show` also enforces a bounded read-only/diagnostic
allowlist. This direct write attempt must fail:

```bash
./netrune-control config switch1 "interface Gi1/0/7" "shutdown"
```

Use the guarded public form instead:

```bash
netrune device config switch1 "interface Gi1/0/7" "shutdown" --dry-run
netrune device config switch1 "interface Gi1/0/7" "shutdown" --confirm
```

### 1.4 What Netrune does not guarantee

Netrune is not a transactional network controller. It does not provide
multi-device rollback, candidate configuration, role-based authorization, or
guaranteed vendor-neutral syntax. Workflows declare stop/continue behavior per
step, but they do not replace an orchestration transaction. SSH host keys are
managed and changed keys fail closed; `accept-new` remains a compatibility mode
until an operator enrolls fingerprints and enables `strict`. Treat the toolset
as an operator automation platform, not as a substitute for change management.

---

## 2. What Netrune Is

Netrune is a local-first network operations toolkit for discovering devices and access points, keeping canonical inventory, recording relationship history, checking health, mapping topology, backing up configurations, running diagnostics, opening SSH sessions, and asking deterministic natural-language questions about stored state.

Its current design has six distinct layers:

1. **Public control plane:** `netrune`, implemented by
   `netrune/core.py`; `netrune_core.py` is the v8 compatibility alias.
2. **Network adapters:** Bash helpers for SNMP, ping, SSH, discovery, backup, VLAN, and diagnostics.
3. **Canonical state:** Profile-isolated SQLite schema version 12 plus derived history, ingest, diagnostics, path evidence, and relationship tables.
4. **Compatibility state:** pipe-delimited flat files used by the shell adapters.
5. **Application contracts and service:** versioned results, generated action metadata, previews, exports, jobs, audit context, and preferences in `netrune`.
6. **Operator interfaces:** terminal and JSON output, Natural Ask, a local traffic collector, and a loopback metrics exposition.

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
- Collect interface throughput and reachability for named targets, publish them for a time-series database, and graph them.
- Manage SSH host keys with scan, fingerprint-bound enrollment, status, forget, strict/accept-new modes, and private atomic storage.
- Run typed VLAN changes through preflight, backup, apply, read-back verification, and audit phases.
- Collect interface throughput and reachability for named targets, and graph them.
- Answer 178 example patterns through deterministic retrieval and registry-backed command planning.

### 2.2 What Natural Ask is and is not

The core Natural Ask path is not a large language model. It normalizes wording, detects deterministic retrieval or operational intent, resolves local aliases and entity names, queries SQLite, and plans commands only from the structured registry. Its answers and plans remain explainable and bounded by current Netrune state and audited command builders.

The optional local `ai/` wrapper delegates broad questions and command requests back to this core engine. Its fast mode does not require a model. Ollama may select or reword approved tool output when a local model is installed, but it cannot generate raw shell or execute a command plan.

Natural Ask has no remote model credential requirement. Optional local-model
wrappers remain outside the deterministic command and authorization boundary.

---

## 3. Architecture and Execution Flow

### 3.1 High-level flow

```text
Operator
   |
   +--> netrune or installed console entry point
           |
           +--> netrune (launcher, contracts, service, workbench)
                   |
                   +--> core.py (parser, policy, SQLite, registry, jobs, API)
                   |
                   +--> local SQLite queries
                   |
                   +--> helper subprocesses
                   |      +--> netrune-discovery
                   |      +--> netrune-control
                   |      +--> netrune-probe
                   |      +--> netrune-connect
                   |      +--> netrune-legacy (selected diagnostics only)
                   |
                   +--> traffic collector
                          +--> SNMP IF-MIB counter reads
                          +--> ICMP probes from this host

Network helper state
   +--> devices.db
   +--> ap_devices.db
   +--> neighbor.db
          |
          +--> import-flat --> canonical SQLite --> derived memory/history
```

### 3.2 Launcher behavior

The source-tree `netrune` launcher resolves its real path, selects a sibling
managed virtual environment when one is present, delegates the optional
AI wrapper, and executes the `netrune_core.py` compatibility alias. That alias
installs the canonical `netrune.core` module object in `sys.modules`,
so imports and monkeypatches see one implementation. The wheel's `netrune` and
`netrune` console scripts enter `netrune.launcher` directly. A source
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
   registry generates CLI action metadata, Markdown reference, `netrune(1)`,
   and shell completions; CI rejects drift.

Root help and version return before SQLite/runtime initialization. Stateful
operations open and migrate the selected database.
Point tests at temporary paths when isolation matters.

### 3.4 Flat files versus SQLite

The shell adapters were built around flat files. The v8 core treats SQLite as canonical for list, history, memory, Natural Ask, jobs, traffic, and console views. Scan helpers still write flat files; the v8 wrapper then imports them into SQLite and recomputes derived state.

The practical cycle is:

```text
network read -> helper flat files -> SQLite import -> identity reconciliation
             -> health/topology/relationship derivation -> operator queries
```

`inventory export-flat` runs the reverse bridge when legacy helpers need SQLite data reflected back into the flat files.

### 3.5 Legacy scheduler

`netrune-legacy` contains an older embedded server and scheduler
implementation. The v8 launcher does not use it, and nothing in the current
tree activates it. It remains only as a source of selected diagnostics.

---

## 4. Complete File Map

This audit classified every first-party file, generated artifact, and dependency boundary in the tree.

### 4.1 Top-level authored files

| File | Role | Normal users should execute it? |
|---|---|---|
| `netrune` | Public Python launcher | Yes |
| `netrune_core.py`, `netrune_ask.py`, `netrune_devices.py`, `netrune_identity.py`, `netrune_ingest.py`, `netrune_mac_registry.py`, `netrune_network.py`, `netrune_speed.py` | Temporary flat-module aliases to canonical `netrune` modules; retained through v8.x for imports and helpers | No |
| `netrune-lib.sh` | Shared Bash config, flat DB, SNMP, credential, SSH, and target helpers | No; it must be sourced |
| `netrune-discovery` | Device/AP/neighbor discovery and flat-file management | Internal/diagnostic only |
| `netrune-control` | SSH inventory, backups, bounded show/config, VLAN, core/MAC lookup | Internal; direct writes fail without the core capability marker |
| `netrune-probe` | ICMP/TCP latency and multi-server speed testing | Internal/diagnostic only |
| `netrune-connect` | Password vault, target resolution, interactive SSH | Internal; use `netrune device ssh` |
| `netrune_aruba_ssh.exp` | Prompt-aware Expect wrapper for complete Cisco/Aruba/RUCKUS read-only command capture | Internal |
| `netrune-legacy` | Compatibility router, filtering and interface diagnostics, obsolete server | Internal |
| `pyproject.toml` / `uv.lock` | Python package, dependency, console-script, helper-script, and reproducible environment metadata | Used by packaging tools |
| `netrune/core.py` | Canonical CLI, policy, schema, state, registry, jobs, API, and static server | Indirectly |
| `netrune/devices.py` | Profile-clonable device-family registry, capability matrix, detection, and semantic command plans | No |
| `netrune/ingest.py` | Versioned channel readers, observation provenance, quarantine, idempotency, and materialization | No |
| `netrune/inventory_ingest.py` | Non-destructive compatibility-observation merge for shell/provider records | No |
| `netrune/identity.py`, `ask.py`, `network.py`, `mac_registry.py`, `speed.py` | Canonical identity, language, parser, IEEE-registry, and speed implementations | No |
| `netrune/contracts.py`, `profiles.py`, `plugins.py`, `path_inspector.py` | Versioned contracts, profile lifecycle, trusted extension policy, and Ghoster engine | No |
| `netrune/launcher.py` | Installed console entry point | Indirectly |
| `netrune/support.py`, `privacy.py`, `release.py`, `docsgen.py` | Redacted support, publication scans, release metadata, and generated-reference tooling | Maintainers/release engineers |
| `docs/` | v8 architecture, operator console, design system, migration, and accepted decisions | Read before operation/maintenance |
| `.gitignore` | Excludes local environments, test/build output, bytecode, runtime databases, and generated agent logs | No |
| `examples/` | Neutral profile, channel, fixture, and declarative-driver examples | Copy into a test profile and adapt |
| `generate_reference.py` | Rebuilds command reference, man page, and shell completions from the command registry | Maintainers/packaging |
| `privacy_check.py` | Scans trees, archives, and clean public history for publication blockers | Maintainers/release engineers |

### 4.2 Tests

| File | Coverage |
|---|---|
| `tests/test_netrune_core.py` | Device/AP identity and aliases, state behavior, command intent, extraction, previews, execution gates, process-group cleanup, startup isolation, registry/help coverage, vendor write denial, vault lifecycle, health predicates, and ISO chronology |
| `tests/test_netrune_ai.py` | AI delegation, public-launcher-only argv, plan rendering, execution disclaimers, and ISO date rendering |
| `tests/test_netrune_network.py` | Fixture-driven interface normalization, Cisco/Aruba/RUCKUS VLAN, LLDP/CDP, ARP/MAC, ping, OUI, interface health, cable TDR, and `iperf3` parsing |
| `tests/test_netrune_devices.py` | Family detection, semantic command plans, declarative drivers, firmware profiles, capability reports, MAC formatting, and fail-closed writes |
| `tests/test_netrune_ingest.py` | Compatibility observation parsing and merge paths, sparse-field retention, source union, and status/hostname refresh |
| `tests/test_netrune_mac_registry.py` | Validated IEEE cache refresh, longest-prefix assignment, local/random handling, and stale-cache fallback |
| `tests/test_netrune_active_workflows.py` | Bounded matrix traversal, dry-run isolation, schema repair, jobs, profile-local drivers, unified built-in ingest, Ghoster refresh, core ping/lookup, MAC evidence, diagnostics, TDR gating, and helper-result classification |
| `tests/test_netrune_speed.py` | Explicit CA validation, retained TLS/hostname verification, server-list schema, paired client reuse, loaded latency sampling/cleanup, and transfer validation |
| `tests/test_netrune_shell_lifecycle.py` | Shell parsing, cancellation/descendant cleanup, three-day sudo/legacy vault lifecycle, real-GPG round trip, filtered legacy SSH, installed helper resolution, normalized ingest, secure writes, discovery, prompt-aware SSH, write denial, speed caching, and dry-run safety |
| `tests/test_netrune_v8.py` | Installed-version fallback, SSH enrollment, guarded VLAN lifecycle, and workflow summaries |
| `tests/test_netrune_85.py` | Contracts/profile migration, channel security/idempotency/provenance/quarantine, plugin runtime policy, built-in ingest, Ghoster outcomes, privacy scanning, support bundles, and release reproducibility |

Do not rely on a count copied into documentation. The release gate runs the
entire discovered suite and records its result in release provenance. Parser
tests use sanitized synthetic Cisco/Aruba/RUCKUS fixtures and workflow tests
use mocked transports. Real firmware, restore, and authorized write validation
remain separate lab gates.

### 4.3 Generated and third-party directories

- `__pycache__/` contains generated Python bytecode. It is not source.
- `.git/` is private development history and is never copied into a public
  export. Public releases start from a newly initialized, privacy-scanned tree.

---

## 5. Requirements and Installation

The repository now has a PEP 517 package (`pyproject.toml`) and an `uv.lock`
environment. It still has no service unit or formal operating-system support
matrix; background deployment remains an explicit operations decision.

### 5.1 Base runtime

Required for the public core:

- Linux or a sufficiently GNU-compatible Unix environment.
- Python 3.11 or newer. The core has no framework dependencies.
- Bash with associative arrays and `mapfile` support for helpers.
- SQLite 3 CLI for shell backup/history paths.
- Standard tools including `awk`, `sed`, `grep`, `sort`, `cut`, `date`, `stat`, `sha256sum`, `timeout`, `mktemp`, `find`, `getent`, and `ping`.

### 5.2 Capability dependencies

| Capability | Commands/tools required |
|---|---|
| SNMP discovery | `snmpget`, `snmpwalk`, MIB support where symbolic OIDs are used |
| SSH automation | OpenSSH `ssh`, `sshpass`, `gpg` |
| Aruba automated sessions | `expect` and executable `netrune_aruba_ssh.exp` beside `netrune-lib.sh`, or a wrapper selected with `NETRUNE_ARUBA_SSH_WRAPPER` |
| CIDR/range discovery | `ipcalc` is used in one CIDR path; shell arithmetic handles other patterns |
| Latency | `ping`; TCP mode also uses Perl `IO::Socket::INET` |
| Tracing | `traceroute` |
| Filtering diagnostics | `curl`, `openssl`, optional `dig`, optional `nc`, DNS resolver tools |
| Internet speed | Python `speedtest-cli` module, `jq`, `ping`, `timeout`, `awk`, and `ip`; WSL enterprise trust import also needs Windows PowerShell |
| Controlled throughput | `iperf3` on the client and a deliberately operated `iperf3` server at the core/remote test point |
| Port and cable health | SSH/Expect; switch support for interface counters and, for active cable tests, vendor TDR commands; optional local `ethtool` is readiness metadata only under WSL |
| Wi-Fi signal metadata | optional `iw` |
| Interface monitor | `snmpget`, `snmpwalk`, `jq`, `awk`, `sed` |

Package names vary by distribution. Verify commands rather than assuming a
package installed the expected binary. Netrune v8.5 beta imports the distro
`speedtest` Python module through `netrune/speed.py`; it does not depend
on parsing the external executable's text/JSON dialect.

### 5.3 Repository execution

For development, run from the source directory:

```bash
cd $HOME/src/netrune
uv sync --extra dev
uv run netrune --help
```

The source launcher remains usable for noun-first commands. If its shebang selects a
the sibling `.venv`; noun-first CLI commands do not pay that dependency cost.
The launcher and executable helpers should have execute permission; imported
modules and the shell library need read permission.

Packaged installation is also supported:

```bash
pipx install $HOME/src/netrune
netrune --version
```

The package installs canonical `netrune` plus the `netops` and `netop` v8
compatibility aliases. It also installs helper scripts and the TCSS theme.

### 5.4 Path deployment

A conservative deployment is an isolated wheel environment selected through
the atomic `install.sh` runtime link. Do not copy only a generated console
script; it requires its Python environment, package data, and helpers.

Example layout:

```text
$HOME/.local/share/netrune/runtime/
  current -> releases/release-TIMESTAMP/
  releases/release-TIMESTAMP/
    bin/netrune
    bin/netops                     v8 compatibility alias
    bin/netop                      v8 compatibility alias
    bin/netrune-control
    bin/netrune-connect
    lib/pythonX.Y/site-packages/netrune/
    lib/pythonX.Y/site-packages/netops_platform/  v8 import compatibility

$HOME/.local/bin/netrune -> $HOME/.local/share/netrune/runtime/current/bin/netrune
```

Prefer `install.sh` (section 5.5) over manually assembling this layout.
The Aruba helper is resolved relative to the loaded shell library, so keeping
`netrune_aruba_ssh.exp` beside `netrune-lib.sh` is sufficient. Set
`NETRUNE_ARUBA_SSH_WRAPPER` to an explicit executable path only when a deployment
intentionally stores the wrapper elsewhere. If no executable wrapper is
available, Aruba falls back to the generic SSH path.

### 5.5 A new machine in one run

From a checkout, `install.sh` does the whole job:

```bash
git clone <your netrune repository> netrune && cd netrune
./install.sh                          # or: ./install.sh --import ~/site-a.tgz
```

In order, it:

1. checks the system tools Netrune drives (SNMP, `sshpass`, `gpg`,
   `expect`, `jq`, `sqlite3`, `traceroute`, `iperf3`, and the rest) and
   offers to install the missing ones with apt-get, dnf, pacman, or zypper
   (`--deps` without asking, `--no-deps` to only report them);
2. installs Netrune into a fresh release with the `excel` extra (skipped
   without network), and links `netrune`, `netops`, and `netop` into
   `~/.local/bin`;
3. installs bash, zsh, and fish completions and the man pages, and offers to
   add a marked block to `~/.zshrc` or `~/.bashrc` with the PATH and
   completion lines (placed just before `zoxide init` when the file has one,
   so zoxide stays last; `--no-shell` skips all of this);
4. with `--import FILE`, restores a profile from another machine and offers
   to store the SSH password (`netrune vault set`);
5. validates the configuration and lists any tools still missing.

`--yes` answers every question; without a terminal and without `--yes` the
steps that change the system are skipped, so scripted installs edit nothing
they were not asked to.

#### Moving a profile to another machine

On the old machine:

```bash
netrune profile export ~/site-a.tgz                                 # configuration and caches
netrune profile export ~/site-a-full.tgz.gpg --with-state --with-secrets
```

The plain bundle carries the profile's configuration (controllers, site
filters, subnets, aliases, channels, drivers, the SSH `known_hosts`) and the
inventory caches, so the first command on the new machine already knows the
network. `--with-state` adds the memory (identity history, merges, your
review answers) and the configuration backups. `--with-secrets` adds the SNMP
communities and encrypts the whole file with a passphrase (asked, or from
`NETRUNE_BUNDLE_PASSPHRASE`). The SSH password vault and named secrets are
tied to each machine's sudo and are never exported: run `netrune vault set`
on the new one.

`netrune profile pack --confirm` is the one-command form of the second
line: it writes `~/site.tgz.gpg` (or the file you name) with everything,
encrypted, and records an audit event. Without `--confirm` it only lists what
would go in, since the file carries the SNMP communities.

On the new machine, `./install.sh --import ~/site-a-full.tgz.gpg`, or with
Netrune already installed, `netrune profile import ~/site-a-full.tgz.gpg`
(`--as NAME` to restore under another name; an existing profile is kept
unless `--force`, which keeps each replaced file beside the new one).

### 5.6 Root versus non-root operation

Do not alternate between root and non-root execution. Netrune follows the XDG
roots of the effective account, so each identity receives independent profiles,
state, cache, known hosts, and named secrets. Run the application as one normal
service account. Elevation is limited to the narrow vault-key broker through
`sudo`; running the whole application as root is not an installation method.

---

## 6. Configuration and Credentials

Netrune configuration is profile-scoped and data-only. The canonical file is
`profile.toml`; a profile-local `netsnmp.conf` remains as a temporary v8.x
compatibility layer for existing shell helpers. New secret values never belong
in TOML, key/value files, environment exports committed to disk, command
arguments, or aliases. Store them as named encrypted secrets and refer to them
with `vault:`, `env:`, or owner-only `file:` references where a channel contract
permits one.

Effective precedence is `CLI > environment > selected profile > global config
> neutral defaults`. `--profile NAME` selects one process without changing the
active profile; `netrune profile use NAME` changes the default for later
processes.

### 6.1 First-time initialization

Initialize a neutral profile explicitly. Initialization creates private XDG
directories, a schema-versioned profile, compatibility files, SQLite state,
channel and driver directories, and a capability report. It does not discover a
network or prompt for credentials.

```bash
netrune init --profile lab
netrune profile use lab
netrune profile paths
netrune config set ssh_user operator
netrune config show
netrune config validate
```

Use `netrune init --migrate-legacy` only when importing an existing pre-8.5
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
| `cisco_wlc_ap_ip_filter` | empty | AP address prefixes this site owns on a shared WLC (space-separated); kept if this **or** a name setting matches |
| `cisco_wlc_ap_name_contains` | empty | AP-name substrings this site owns (space-separated) |
| `cisco_wlc_ap_name_prefix` | empty | AP-name prefixes this site owns (space-separated) |
| `cisco_wlc_join_stats` | `true` | Enables optional SSH join-stat collection |
| `cisco_wlc_join_stats_cmd` | empty (automatic) | WLC command for unjoined APs; empty tries `show wireless stats ap join summary` (9800), then `show ap join stats summary all` (AireOS) |
| `cisco_wlc_join_stats_timeout` | `45` | Join-stat command timeout |
| `ruckus_vsz_ip` | empty | Ruckus vSZ controller address |
| `controller_walk_timeout` | `180` | Seconds allowed for one controller AP-table walk |
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
netrune secrets status
netrune secrets list
netrune secrets set ingest/netbox/token
netrune secrets delete ingest/netbox/token --confirm
netrune secrets import-ssh
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
| `NETRUNE_CONFIG_DIR` | Python core | Overrides the Python config directory |
| `NETRUNE_CACHE_DIR` | Python core | Overrides the Python cache directory |
| `NETRUNE_STATE_DIR` | Python core | Overrides profile state during compatibility/testing |
| `NETRUNE_DATA_DIR` | Python core | Overrides profile data during compatibility/testing |
| `NETRUNE_PROFILE` | Python/shell launch path | Selects a profile for the current process |
| `NETRUNE_SQLITE_DB` | Python core | Overrides the SQLite path |
| `NETRUNE_BACKUP_DIR` | Python core | Overrides the Python-visible backup path |
| `NETRUNE_JOB_CONCURRENCY` | Python server | Maximum concurrent server jobs; default `3` |
| `NETRUNE_EXPORT_DIR` | Application service | Overrides the private result-export directory |
| `NETRUNE_PROGRESS` | Python/shell launch path | Set `0` to suppress terminal progress animation where honored |
| `NO_COLOR` | Python/shell output | Disables color where honored |
| `NETRUNE_RESOLVE_MODE` | Shell target resolver | Selects interactive/default, `first`, or `all` ambiguity handling |
| `NETRUNE_CHECK_TIMEOUT` | `netrune-legacy` diagnostics | Connect timeout in seconds for port, DNS-adjacent, HTTP, HTTPS, and filtering probes; default `4`, and the legacy diagnostic parser can set/export it for that process |
| `NETRUNE_SWITCH_NAME_MAX` | `netrune-discovery` | Maximum accepted discovered switch hostname length; default `32` |
| `NETRUNE_SSH_SHOW_ERRORS` | Generic shell SSH helper | Set `true` to stop suppressing helper SSH stderr during troubleshooting |
| `NETRUNE_SSH_KNOWN_HOSTS_FILE` | Python/shell SSH paths | Overrides the private managed known-hosts file |
| `NETRUNE_SSH_HOST_KEY_MODE` | Shell SSH path | One-process override of `strict` or `accept-new` |
| `NETRUNE_SSH_BREAK_GLASS` | Shell SSH path | Must be explicitly `true` together with break-glass mode to disable verification for one process; emits a warning |
| `NETRUNE_PASSWORD_FILE` | Python/shell vault paths | Overrides the encrypted SSH-password vault path; default `~/.ssh/sshpass_cache.gpg` |
| `NETRUNE_MAC_REGISTRY_DIR` | Python core | Overrides the private IEEE MA-L/MA-M/MA-S cache directory |
| `NETRUNE_VAULT_MODE` | Shell vault writer | Selects `sudo-gpg` (default) or the explicit `legacy-gpg` fallback when setting a password |
| `NETRUNE_VAULT_NONINTERACTIVE` | Shell vault reader | When true, fails instead of requesting sudo authentication; useful for unattended jobs that must never block on a prompt |
| `NETRUNE_SECRETS_FILE` | Named-secret store | Overrides the encrypted store for isolated tests or managed deployment |
| `NETRUNE_PRIVACY_DENYLIST_FILE` | Release tooling | Adds deployment-specific publication blockers |

No environment variable or configuration key enables remote credential export.

Important: the shell helpers compute most config/cache paths directly from effective UID and `HOME`; they do not consistently honor all Python path overrides. Isolated Python tests therefore do not prove that a spawned shell helper will use the same paths. Run integration tests with a temporary `HOME` as well.

### 6.5 SSH password vault

`netrune device ssh` maps its credential to the named key
`ssh/default/password`. Existing deployments can retain the compatibility vault
during migration; `netrune secrets import-ssh` copies the decrypted value into
the profile's encrypted named store without printing it. The compatibility file
is:

```text
~/.ssh/sshpass_cache.gpg
```

The `-l`/`--legacy` SSH option sets the internal, process-local flag `CONFIG[legacy_ssh]=true`, enabling older key-exchange and host-key algorithms for that connection. `legacy_ssh` is not a recognized persistent `netsnmp.conf` key, so adding it to the file has no effect.

Inspect it without prompting:

```bash
netrune vault status
netrune vault status --json
```

The status includes the format, mode, file permissions, password-recorded time,
expected expiry, estimated expiry window, credential state, configured sudo/PAM
authenticator, sudo-cache state, and root-key state. Times use ISO 8601 UTC. It
uses `sudo -n` only and therefore never opens an authentication prompt.

The credential lifecycle is an operational estimate, not a query to the switch
or password authority. A successful `netrune vault set` or `connect -p` updates
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

Netrune warns during vault use when rotation is due, in-window, or likely
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
   `/etc/netrune/vault-keys/<numeric-uid>.key`, owned by root with mode `0600`,
   is validated and read by one narrowly scoped sudo broker process, then
   streamed to unprivileged GPG through a dedicated file descriptor. The
   broker checks the trusted owner, object types, directory and key modes, and
   non-empty key before it emits any key bytes.

On WSL, containers, and other user-namespaced filesystems, `stat` may display
the host-mapped privileged owner as UID `65534` rather than UID `0`. Netrune does
not weaken its file checks for that case: the key and protected key directory
must match the trusted `/etc` owner, the directory must be a `0700` directory,
and the key must be a regular `0400` or `0600` file.

The sudo/root password is never stored, passed to GPG, placed in an environment
variable, or used as the encryption key. GPG always runs with
`--pinentry-mode loopback`, so Netrune does not invoke the configured graphical
pinentry program. After the first successful terminal authentication, later
Netrune processes reuse sudo's normal credential timestamp until the operating
system's configured timeout expires. `--no-symkey-cache` prevents GPG Agent
from becoming a second, less-visible unlock cache. A private `flock` serializes
authentication, so parallel cascade workers cannot open competing sudo prompts;
the first authenticates and the rest reuse the resulting timestamp.

Windows Hello proves operator presence by signing a random PAM challenge; it
does not expose a reusable password or encryption secret to Linux. Netrune
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
netrune vault set
```

This first validates or creates the root-only random key, then asks twice for
the network-device SSH password. The password is symmetrically encrypted by
GPG into a mode-`0600` staged file and moved atomically over the local vault
only after successful encryption. A failed encryption leaves the previous
vault unchanged. The network-device password is decrypted into `SSHPASS` only
inside the requesting Netrune process for `sshpass`; it is not placed on a
command line.

#### One-time migration from the graphical legacy vault

An existing vault without the `NETRUNE-SUDO-GPG-V1` format marker is reported as
`legacy-gpg`. Migrate it once:

```bash
netrune vault status
netrune vault migrate
netrune vault status
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
known, use `netrune vault set` to replace the old vault directly. To verify the
new vault and establish a sudo timestamp before a sequence of operations, run:

```bash
netrune vault unlock
```

`unlock` verifies decryption and immediately removes the temporary password
from that helper process. It does not extend sudo beyond the host's configured
timeout. Set `NETRUNE_VAULT_NONINTERACTIVE=true` for unattended execution that
must fail closed rather than request authentication.

The explicit fallback is:

```bash
netrune vault set --legacy-vault
```

It asks for a separate GPG passphrase in the terminal and also forces loopback
mode, but each uncached process may require that passphrase. Prefer the
sudo-gated format on this workstation.

Back up both `~/.ssh/sshpass_cache.gpg` and the matching root-only key under
`/etc/netrune/vault-keys/`. Store them with separate access controls. Losing the
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
netrune device trust-scan SWITCH
netrune device trust-enroll SWITCH --fingerprint SHA256:VERIFIED_VALUE --confirm
netrune device trust-status SWITCH
```

The expected fingerprint must come from an independent trusted source. A
successful scan only reports what the current network path presented. Enroll
writes the matched key atomically to a mode `0600` store and records an audit
event. On approved device replacement, use `trust-forget`, verify the new key,
and enroll it again.

Break-glass mode disables verification only when both the mode and
`NETRUNE_SSH_BREAK_GLASS=true` are supplied to that process. It writes no trust
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

Use `netrune config set KEY VALUE` for a profile-local compatibility override,
`netrune config unset KEY` to remove it, and `netrune config paths` to see every
source. Secret-looking keys are rejected and must use `netrune secrets set`.

Do not paste real credentials into issue reports, command history, screenshots, or this handbook.

---

## 7. State, Files, and SQLite

Understanding state ownership is the difference between merely running Netrune and diagnosing it correctly.

### 7.1 Non-root state layout

```text
~/.config/netrune/
  active_profile
  config.toml                         optional global non-secret settings
  profiles/PROFILE/
    profile.toml                      canonical profile settings, mode 0600
    netsnmp.conf                      temporary shell compatibility settings
    known_hosts                       profile SSH trust store, mode 0600
    aliases.yaml                      profile aliases and naming rewrites
    channels/*.toml                   declarative ingest channels
    drivers/*.toml                    declarative read-only device drivers

~/.local/state/netrune/profiles/PROFILE/
  netrune.sqlite3                      canonical database
  netrune.sqlite3-wal                  SQLite WAL when active
  netrune.sqlite3-shm                  SQLite shared memory when active

~/.cache/netrune/profiles/PROFILE/
  devices.db              legacy device observations
  ap_devices.db           legacy AP observations
  neighbor.db             legacy LLDP/CDP observations
  snmp_cache.db           community/probe cache
  mac-registry/           downloaded IEEE assignment cache

~/.local/share/netrune/profiles/PROFILE/
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

AP sources commonly disagree about spelling, prefixes, addresses, and attachment detail. Netrune therefore exposes canonical AP rows rather than blindly counting raw rows.

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

Switch observations use the same evidence discipline. Netrune normalizes common
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
netrune                                      # help
netrune <domain> <action> [positional arguments] [global flags]
netrune help <domain> [action]
netrune <domain> <action> --help
```

The parser recognizes global flags throughout the argument list except where a
command deliberately owns the same option name. In particular,
`diagnose speed --profile quick` selects a speed profile. To select Netrune state
for that command, put the global selector first:

```bash
netrune --profile lab diagnose speed --profile quick
```

Other command-specific options are interpreted by the selected action or
forwarded to a helper.

Use the live help as the source of truth for the installed version:

```bash
netrune --version
netrune --help
netrune help inventory scan
netrune diagnose interface --help
netrune help --json
```

`netrune --version`, the public help banner, and `netrune-legacy --version` read
the central `VERSION` file and currently report `Netrune 8.5.0b3`. Root help,
version and root help do not initialize SQLite
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
netrune ... --first
netrune ... --all
netrune ... --interactive
```

The Python wrapper translates `--first` and `--all` into `NETRUNE_RESOLVE_MODE` for shell helpers. Not every action allows multiple targets, and broad writes remain unsafe even when resolution technically succeeds.

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
netrune inventory list ZONE10 --json
netrune db integrity --json
netrune ask "How many APs are offline in ZONE10?" --json
```

---

## 9. Safe First Run

The following sequence teaches the platform without changing a network device.

### 9.1 Confirm the installation

```bash
netrune --help
netrune help --json
netrune init --profile lab
netrune --profile lab profile paths
netrune --profile lab db path
```

Check that the reported install, config, cache, and database paths belong to the intended service account.

### 9.2 Initialize and inspect SQLite

```bash
netrune db migrate --json
netrune db status --json
netrune db integrity --json
```

Expected core conditions:

- schema version is `12`;
- `quick_check` contains `ok`;
- `integrity_check` contains `ok`.

### 9.3 Inspect existing state

```bash
netrune inventory list --limit 20
netrune ap list --limit 20
netrune health status --limit 20
netrune topology neighbors --limit 20
netrune health attention --limit 20
```

Empty output on a new installation is normal. It means no flat data has been imported or discovered.

### 9.4 Import existing helper data

```bash
netrune inventory import-flat --dry-run
netrune inventory import-flat --json
netrune memory refresh --json
```

Import writes only local SQLite state, but use dry-run first to verify the selected deployment and paths.

### 9.5 Preview active discovery

```bash
netrune inventory scan ZONE10 --dry-run
netrune health check ZONE10 --dry-run
netrune topology scan --dry-run
```

Then run only after confirming scope, credentials, timeout, worker count, and network authorization.

### 9.6 Preview a write guard

```bash
netrune vlan set 198.51.100.71 Gi1/0/7 --access 120 --dry-run --json
```

The output must show a command preview and `dry_run: true`; it must not connect to the device.

### 9.7 Start monitoring something

```bash
netrune traffic interfaces <switch>
netrune traffic watch <switch> <interface>
netrune traffic daemon
```

Collection is watchlist driven: nothing is polled until it is named. See 21.

### 9.8 Validate extension surfaces

These commands inspect local configuration only and are safe on a fresh
profile:

```bash
netrune --profile lab config validate
netrune --profile lab ingest validate
netrune --profile lab plugin groups
netrune --profile lab plugin list
netrune --profile lab device support
```

Do not enable a plugin merely because discovery found it. Confirm its package
source and version, review the code as trusted local Python, then enable the
exact `<group>:<name>` in a disposable profile first.

---

## 10. Inventory Commands

Inventory covers switches, routers, and the combined canonical search view.

### 10.1 `inventory scan`

```text
netrune inventory scan [target|CIDR|range]
```

Examples:

```bash
netrune inventory scan
netrune inventory scan 203.0.113.0/24
netrune inventory scan 198.51.100.20-60
netrune inventory scan ZONE10 --dry-run
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
netrune inventory list [pattern] [--status ONLINE|OFFLINE] [--site SITE]
```

Examples:

```bash
netrune inventory list
netrune inventory list ZONE10
netrune inventory list --status OFFLINE
netrune inventory list 192.0.2 --json --limit 100
```

This is a local canonical SQLite query. It searches device and reconciled AP fields, applies status/site filters where implemented, and does not contact the network.

Interpret raw versus canonical counts carefully: device rows are current observations; AP results are reconciled physical identities. `ap_observations` can exceed the canonical `aps` count.

### 10.3 `inventory show`

```text
netrune inventory show [pattern]
```

This is an alias for the canonical list/search path. Use it for quick lookup, not SSH enrichment.

### 10.4 Manual device lifecycle merge

Use a manual merge when an old active record and its verified replacement are
one operational asset lifecycle but physical evidence correctly prevents an
automatic merge:

```bash
netrune inventory merge SITE-A-OLD-SW01 SITE-A-ACCESS-01 \
  --reason "approved hardware replacement" --dry-run
netrune inventory merge SITE-A-OLD-SW01 SITE-A-ACCESS-01 \
  --reason "approved hardware replacement" --confirm
netrune inventory merges
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
are the same hardware. Registry previews are previews only; application
requires the explicit CLI `--confirm` gate.

To inspect or reverse the decision:

```bash
netrune inventory merges --all --json
netrune inventory unmerge mrg-example \
  --reason "association was incorrect" --confirm
```

Unmerge restores the captured source only when its former IP is not now owned
by a different device. It never deletes the merge or its audit/history record.

### 10.5 `inventory details`

```text
netrune inventory details <target>
```

Examples:

```bash
netrune inventory details sq34
netrune inventory details 198.51.100.92 --json
```

The output mode changes behavior:

- JSON uses canonical SQLite state and returns one device/AP record plus history, relationships, health, and backups.
- Plain output delegates to the legacy detailed view and may perform SSH enrichment/network reads.

Use `--json` when you need a guaranteed local-state inspection. Do not assume plain `details` is passive.

### 10.6 `inventory activity`

```text
netrune inventory activity --file devices.txt
netrune inventory activity <target...>
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
netrune inventory import-flat
```

Imports `devices.db`, `ap_devices.db`, and `neighbor.db`, performs MAC cleanup and AP reconciliation, writes canonical tables, and synchronizes identity, health, topology, AP movement, and relationship state.

Run it after out-of-band helper changes or when moving an existing flat-file deployment into v8.

### 10.8 `inventory export-flat`

```text
netrune inventory export-flat
```

Exports canonical current state to the three compatibility files. It is a local write and can affect subsequent helper resolution. Back up the existing flat files before using it during migration troubleshooting.

---

## 11. Access Point Commands

### 11.1 `ap scan`

```text
netrune ap scan
```

The AP scan combines available sources:

- Cisco WLC SNMP inventory: each AP's address, MAC, model, serial, and how
  long it has been up and joined;
- optional Cisco WLC SSH join statistics, for the APs that are not joined
  (the Catalyst 9800 command is used first, the AireOS one if the controller
  refuses it);
- Ruckus vSZ SNMP inventory, read whole in one pass: every AP with its MAC,
  model, serial, firmware, uptime, and whether the controller has it
  connected (a *Disconnect* AP is recorded offline). If the controller
  returns fewer APs than it counts, the scan says so, and the APs it missed
  keep their last reading;
- LLDP/CDP AP observations from switches;
- prior AP observations used to preserve continuity and mark unmatched rows offline.

A Cisco WLC shared with other sites is cut to this one by the filter settings: an AP is kept when its address starts with one of `cisco_wlc_ap_ip_filter`'s prefixes **or** its name starts with one of `cisco_wlc_ap_name_prefix`'s (or contains one of `cisco_wlc_ap_name_contains`'s). Several values are separated by spaces. For example `cisco_wlc_ap_ip_filter=192.0.2.` and `cisco_wlc_ap_name_prefix=SITEA` keep an AP named `SITEA…` wherever it is, and a default-named AP on 192.0.2. APs recorded for other sites before the filter was set are removed at the next scan. An AP excluded by the filter is absent, not offline. The Ruckus vSZ has no filter.

The merge process updates `ap_devices.db`; v8 then imports and reconciles canonical APs. Source records can have controller attachment context without a physical port. Switch LLDP/CDP evidence is stronger for a physical port.

Neither a maker's name ("Aruba", "Ruckus") nor a neighbour that calls itself
a switch or a phone counts as an AP, so Aruba and ICX switches seen as LLDP
neighbours no longer land in the AP list.

### 11.1a `ap neighbors`

```text
netrune ap neighbors --all
netrune ap neighbors SITE-A-CORE-SW01,SITE-A-BLDG2-SW01
netrune ap neighbors --all --dry-run       # which switches, which commands; connects to nothing
```

Reads each switch's own neighbour tables over SSH:

- Cisco: `show cdp neighbors detail` and `show lldp neighbors detail`;
- Aruba AOS-S: `show lldp info remote-device`, then the detail for each port
  it lists, and `show cdp neighbors detail`.

Each switch takes one login (two for Aruba). The tables name the port as
you would type it, so this is the most direct answer to "which port is this
AP on".

A neighbour counts as an AP when it advertises the WLAN capability, reports
an AP model (C9136I, CW9164I, AIR-AP2802I, R610, ...), or runs AP software.
Known switches, anything describing itself as a switch, and phones are left
out. APs are matched to the inventory by MAC, then name, then IP:

- an AP on a different port than recorded is corrected, and the change shows
  up in `ap moves`;
- an AP Netrune did not have is added;
- the rest are confirmed where they are.

It only runs `show` commands on the switches. Run it after `ap scan`, which
still rewrites the AP list from its own SNMP and controller data.

### Which source wins for an AP

Both scans now follow one rule:

- **Name and model:** from the controller. The model comes from whichever
  source actually names one (`C9136I`, `CW9164I`, `R610`), the controller
  first, so a software banner no longer replaces the model.
- **Where it is plugged in:** from the switch.
- **Matching:** controller and switch readings join by MAC, then hostname,
  then IP. Cisco controllers report the radio MAC and LLDP the Ethernet MAC,
  so the hostname is what usually joins them.

`ap neighbors` then checks every reading against the port's MAC table:

- the AP's MAC on the port **confirms** it;
- a CDP-only AP (CDP carries no MAC) whose port holds exactly one MAC
  **learns** that MAC;
- only randomized client MACs on the port means its **wireless clients**,
  which also supports the attachment;
- a port where the AP's own MAC has aged out is **pushed**: Netrune pings the
  AP from your machine (its reply crosses that port, so the switch learns it
  again) and re-reads just that port, up to twice. The whole MAC table is read
  in the same login as the neighbour tables, so a switch usually costs one
  login.

### 11.2 `ap list`

```text
netrune ap list [pattern] [--status ONLINE|OFFLINE]
```

Examples:

```bash
netrune ap list ZONE10
netrune ap list Cisco --status OFFLINE
netrune ap list --json --limit 200
```

Search includes AP names, aliases, addresses, platform, switch name, and port. Results are canonical identities, not raw controller rows.

### 11.3 `ap show`

```text
netrune ap show [pattern]
```

This is a quick alias for `ap list`.

### 11.3a `ap controller`

```text
netrune ap controller [pattern] [--limit N]
```

What the controllers said about each AP at the last scan: name, IP, MAC,
model, serial, firmware, whether the controller has it connected, how long it
has been up, and when it was polled. The pattern matches any of those
(`netrune ap controller T300`, `netrune ap controller OFFLINE`, or part of a
MAC in any notation). `--json` adds `booted_at`, the poll time minus the
uptime, which stays right between scans.

### 11.4 `ap unjoined`

```text
netrune ap unjoined [pattern] [--limit N]
```

Shows Cisco WLC observations from join statistics that are not currently joined: name, MAC, the address the AP last had (often reused by another AP since), and the controller's last failure and disconnect reason. An AP that has since joined under the same name with new hardware is not listed. It depends on:

- `cisco_wlc_join_stats=true`;
- a configured WLC;
- SSH credentials and `sshpass`, and an unlocked vault (the scan logs `did not return join statistics` when SSH fails);
- a WLC output format matched by the parser.

An empty result can mean no unjoined APs, disabled collection, failed SSH, filtered names, or parser drift. Check scan logs before declaring success.

### 11.5 `ap on-switch`

```text
netrune ap on-switch <switch>
```

Examples:

```bash
netrune ap on-switch ZONE10
netrune ap on-switch SITEAZONE34SW01 --json
```

Combines canonical AP inventory and relationship memory to find APs associated with a switch name, IP, short name, or site token. Review `source`, `switch_ip`, `switch_port`, and confidence before treating the result as cabling proof.

### 11.6 `ap moves`

```text
netrune ap moves [--limit N]
```

Lists recorded attachment changes. A move can be a real recable, controller/source correction, AP rename/reconciliation effect, or data disappearance/reappearance. Correlate it with topology, scan timestamps, and source.

### 11.7 `ap timeline`

```text
netrune ap timeline [target]
```

Searches AP relationship and attachment history by AP name, IP, MAC, alias, or related text. Use canonical aliases when names changed.

---

## 12. Topology Commands

### 12.1 `topology scan`

```text
netrune topology scan
```

Queries known switches for LLDP/CDP neighbors, parses local/remote port and identity fields, resolves remote IPs from inventory where possible, writes `neighbor.db`, imports it into SQLite, and compares the current link set with the previous snapshot.

Each tuple `(local_ip, local_port, remote_name, remote_port, remote_ip)` is treated as a link identity. A changed name or unresolved IP can therefore appear as remove-plus-add rather than an in-place edit.

### 12.2 `topology show`

```text
netrune topology show [target]
```

- Without a target, reads cached topology links.
- With a target in plain mode, it may open the legacy topology view and orient a breadth-first diagram relative to `core_switch_ip`.
- JSON paths use canonical cached state.

The diagram's upstream/downstream interpretation depends on a correct configured core and complete neighbor data.

### 12.3 `topology neighbors`

```text
netrune topology neighbors [target]
```

Lists cached raw neighbor rows, optionally filtered. This is the best first command when the graph seems wrong because it exposes the source link records before graph layout.

### 12.4 `topology changes`

```text
netrune topology changes [--limit N]
```

Shows `link_added` and `link_removed` events. A scan that is partial, unauthenticated, or interrupted can produce apparent removals; validate scan completeness before escalating.

### 12.5 `topology timeline`

```text
netrune topology timeline [target]
```

Reads neighbor relationship events, useful for reconstructing changes around one switch or site.

---

## 13. Relationship Memory Commands

Memory is the historical knowledge layer. It connects observations that inventory tables alone cannot answer, such as who used an IP before, where an AP was attached, or what occupied a port.

### 13.1 `memory refresh`

```text
netrune memory refresh
```

Recomputes desired relationships from current devices, reconciled APs, neighbors, and core lookup observations. It updates current relationships and emits appeared/changed/disappeared events.

Run it after a manual SQLite import or repair. Normal v8 scans already refresh canonical state after helper completion.

### 13.2 `memory switch`

```text
netrune memory switch <switch>
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
netrune memory device <name|ip>
```

Shows relationships in which the described device/AP appears as subject, object, or serialized attributes, plus matching history.

### 13.4 `memory ip`

```text
netrune memory ip <ip>
```

Shows current IP ownership and historical events. An IP can legitimately have different owners over time; compare event timestamps and sources instead of assuming the latest text match is permanent.

### 13.5 `memory mac`

```text
netrune memory mac <mac>
```

Accepts common colon, hyphen, dotted, and compact forms through normalization. It shows identity and movement history. Placeholder/multicast/broadcast MACs are intentionally excluded from canonical identity.

### 13.6 `memory port`

```text
netrune memory port <switch> <port>
```

Examples:

```bash
netrune memory port ZONE34 Gi1/0/7
netrune memory port 198.51.100.92 7
```

Numeric ports are matched as an interface suffix in the API payload path; explicit interface names are safer when devices have multiple slot/module forms. Results include current occupancy and prior events.

### 13.7 `memory timeline`

```text
netrune memory timeline [target]
```

Searches all relationship events. Use a narrow target and an explicit `--limit` on mature databases.

### 13.8 `memory explain`

```text
netrune memory explain [target]
```

Summarizes relationship sources and average confidence. Use it to answer, "Why does Netrune believe this?" It does not independently verify the evidence.

### 13.9 `memory export`

```text
netrune memory export --json
```

Exports current relationships. JSON is the appropriate format for analysis, graphing, and external audit.

### 13.10 `memory prune`

```text
netrune memory prune
```

This action is reserved and disabled. Relationship history is retained indefinitely in the current implementation. Plan database growth and archival externally.

### 13.11 Time and chronology semantics

Memory and history preserve integer Unix epoch seconds in SQLite and JSON for compatibility. Human-facing dates use ISO 8601 UTC:

```text
2026-01-15T12:34:56Z
```

Interpret the fields precisely:

- `first_seen` is when the current relationship was first entered into memory.
- `last_seen` is when the current canonical observation or relationship was most recently reconciled as present.
- `updated_at` is when the current-state row was last rewritten or changed.
- Event `created_at` is when Netrune recorded that transition; API event rows also expose `recorded_at_iso`.
- Current rows expose additive `first_seen_iso`, `last_seen_iso`, and `updated_at_iso` fields when those source values exist.
- Memory and event-history responses identify `chronology` as `newest_first`; `version 1` is the latest row.

`last_seen` is not guaranteed to be a fresh network poll. `memory refresh` can reconcile relationships from already-cached inventory, AP, and topology data. To prove current device state, run the relevant inventory/AP/topology/health operation first, confirm it completed, and then inspect memory. The existing `scan_runs` table does not yet provide complete per-target live-poll provenance.

---

## 14. Health Commands

### 14.1 `health check`

```text
netrune health check [target]
```

Examples:

```bash
netrune health check
netrune health check ZONE10
netrune health check 198.51.100.71 --json
```

This is a fast reachability refresh, not deep inventory discovery. It pings known or supplied devices/APs, updates flat status and timestamps, imports state, and updates health history.

Use it when you need a current online/offline view without waiting for SNMP, controller, and LLDP enrichment.

Limitations:

- ICMP blocking can produce false offline status.
- A successful ping does not prove SNMP, SSH, forwarding, controller join, or application health.
- A hostname can resolve differently from the address stored in inventory.

### 14.2 `health status`

```text
netrune health status [--limit N]
```

Reads current `health_state`, ordered to surface offline/attention/failure statuses and high flap counts.

### 14.3 `health offline`

```text
netrune health offline [--limit N]
```

Lists current offline devices and APs. The command can return exit code 3 when rows are found: the query succeeded, but its result indicates an operational problem.

### 14.4 `health attention`

```text
netrune health attention [--limit N]
```

Aggregates health, topology, AP movement, backup, and diagnostic signals into a review list. Investigate source recency before treating every item as a live incident.

### 14.4a `health review`

```text
netrune health review [--list] [--kind identity|excel]
netrune health review answer <id> <choice>
```

Everything waiting for a person to decide, one question at a time:

| Question | Answers | What happens |
| --- | --- | --- |
| A switch or AP disappeared and another appeared with matching signals: the same one, or a replacement? | `y` same / `n` different | `y` merges the old record into the new one (as `ap merge`/`inventory merge --confirm` would); `n` keeps them apart and never asks again |
| Several renamed together under a new site prefix? | `y` / `n` | the same, for each of them |
| A workbook row names something Netrune never saw and nothing answers: is the address free? | `y` free / `n` allocated | kept, and written by the next `excel sync … --free-ips --confirm` of that workbook |
| A workbook row's keys point at two switches: which is it? | `1`, `2`, … | kept, and the next `excel sync … --confirm` updates that row from the chosen key |

`s` skips a question (it is asked again next time), `q` stops. Workbook
questions come from the last `excel inspect`/`sync` of each workbook, and an
answer only applies while the row still reads the same. With `--list`, or
without a terminal, the questions are listed with their ids instead;
`answer <id> <choice>` answers one.

The morning check lists these as its last step and, in a terminal, offers
to go through them straight away.

### 14.5 `health timeline`

```text
netrune health timeline [--limit N]
```

Shows first-seen and status-change events. `flap_count` is cumulative for the current entity identity; it is not automatically reset after a quiet period.

---

## 15. Backup Commands

Backups are remote reads plus local writes. The supported v8 path skips known-offline targets, hashes normalized output, and avoids rewriting unchanged configuration.

### 15.1 `backup run`

```text
netrune backup run <target> [--redact-secrets]
```

Examples:

```bash
netrune backup run ZONE34
netrune backup run 198.51.100.92 --redact-secrets
netrune backup run ZONE10 --dry-run
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
netrune backup history <target>
```

Shows recent backup results for a resolved device. The underlying direct shell function chooses its SQLite path from root/non-root defaults and does not honor `NETRUNE_SQLITE_DB`; see the known path-consistency defect.

### 15.4 `backup diff`

```text
netrune backup diff <target>
```

Diffs the two latest successfully saved backups whose `changed` flag is 1. Unchanged history entries are skipped. A missing diff usually means fewer than two changed saved configurations, not necessarily a backup failure.

### 15.5 `backup verify`

```text
netrune backup verify [--limit N]
```

Despite the verb, v8.5.0b3 primarily displays backup metadata recorded in SQLite. It does not perform full restore validation, parse every configuration, or reconnect to prove the file can be applied. Verify file existence and SHA-256 independently for audit-grade restoration.

### 15.6 Restore procedure

Netrune has no automated restore command. A controlled restore should be manual:

1. Identify the target by exact IP, serial, and hostname.
2. Use `backup history` and `backup diff` to choose a version.
3. Verify the file hash against `backup_history`.
4. Review and remove prompts, redactions, or unsupported lines.
5. Back up the current device configuration again.
6. Generate a staged configuration plan.
7. Preview through `netrune device config ... --dry-run` where feasible.
8. Apply during an approved change window with console/out-of-band recovery.
9. Verify connectivity, intended state, and saved configuration.

Do not feed a redacted backup directly back to a device.

---

## 16. Device and VLAN Commands

### 16.1 `device ssh`

```text
netrune device ssh [-l|--legacy] <target>
```

Examples:

```bash
netrune device ssh ZONE34
netrune device ssh 198.51.100.92
netrune device ssh --legacy ZONE34
```

Flow:

1. A name matching several switches opens a numbered picker: move with the arrows or type the row's number, then Enter (`q` cancels). `netrune-connect` then resolves exactly one target unless resolution mode says otherwise.
2. It validates that the active profile has a non-empty, whitespace-free `ssh_user`; missing configuration fails before vault authentication or transport access.
3. It decrypts the local SSH password vault into `SSHPASS`.
4. It opens `sshpass -e ssh -tt -l <user> <host>`, keeping username and host as separate OpenSSH arguments.
5. It applies `strict` or `accept-new` against the private Netrune known-hosts file; a changed key fails closed.
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
netrune device support [target]
netrune device identity <first-target> <second-target>
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
netrune device trust-status [target]
netrune device trust-scan <target>
netrune device trust-enroll <target> --fingerprint SHA256:VALUE --confirm
netrune device trust-forget <target> --confirm
```

`trust-status` is local-only. `trust-scan` retrieves current keys without
enrolling them. `trust-enroll` accepts only scanned keys whose SHA-256
fingerprints exactly match independently verified values, writes the private
store atomically, and audits the enrollment. `trust-forget` removes all aliases
for the resolved host after confirmation and audits the removal. See section
6.6 for the production procedure.

### 16.4 `device show`

```text
netrune device show <target> <show-command>
```

Examples:

```bash
netrune device show ZONE34 show version
netrune device show 198.51.100.92 "show interface status"
```

The v8 policy permits commands beginning with read-like verbs such as `show`, `sh`, `display`, or `get`, then blocks separators, shell escapes, configuration transitions, secret-bearing outputs, running configuration, tech-support bundles, and other risky patterns.

Examples of policy rejection:

```bash
netrune device show ZONE34 "show running-config"
netrune device show ZONE34 "show version ; reload"
```

The public block occurs before device access and returns validation code 6. Direct `netrune-control show` independently rejects separators, configuration transitions, sensitive-output forms, missing/extra command arguments, and unsupported verbs with usage code 2; it is no longer a route around the read-only policy.

### 16.5 `device inventory`

```text
netrune device inventory [target|--view]
```

- `--view` displays the shell inventory database.
- A target performs SSH inventory enrichment and merges platform/model/serial data.

This path is distinct from `inventory list`, which is canonical/local. Use it when SNMP could not supply sufficient identity and an SSH read is authorized.

### 16.6 `device config`

```text
netrune device config <target[,target...]> <commands...> --dry-run|--confirm
netrune device config --file devices.txt [--target T] <commands...> \
  [--commands-file F] [--skip-offline] [--skip-unverified] \
  [--cisco] [--aruba] [--ruckus] --dry-run|--confirm
netrune device config --all [--cisco] [--aruba] [--ruckus] <commands...> \
  [--skip-offline] [--skip-unverified] --dry-run|--confirm
```

Example:

```bash
netrune device config 198.51.100.92 \
  "interface Gi1/0/7" \
  "description AP-ZONE34-07" \
  --dry-run
```

Only after review:

```bash
netrune device config 198.51.100.92 \
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
- Cisco IOS/NX-OS and Aruba AOS-S/AOS-CX drivers support configuration
  (with `device_writes_enabled=true`). RUCKUS FastIron, SmartZone, AP, and
  unknown drivers report configuration as unsupported and fail before
  transport.
- Any `--option` the command doesn't recognize is refused (exit 2) rather than
  sent to the switch as a config line, so a typo like `--skip-ofline` can't
  reach a device.
- There is no rollback if command N fails after commands 1 through N-1 succeed.

Cisco configuration remains model/firmware sensitive. A successful preview
proves construction and policy only; validate syntax and recovery explicitly.

#### Several devices at once

Give a comma list, repeat `--target`, or point `--file` at a list with one
hostname or IP per line (blank lines and `#` comments ignored), the same
format `inventory activity --file` reads. `--file` and `--target` combine.
With either of them, everything else on the line is a config command:

```bash
netrune device config SW1,SW2,SW3 "ntp server 198.51.100.5" --dry-run
netrune device config --file ./idf-switches.txt \
  --commands-file ./snmp-baseline.txt --skip-offline --dry-run
```

How a batch runs:

1. Every device is checked first: it must resolve to exactly one inventory
   device and pass the write gate. One bad entry refuses the whole batch
   before any switch is touched, unless `--skip-unverified` is given, which
   skips and reports it instead.
2. The same switch listed twice (by name and by IP, say) is configured once.
3. `--skip-offline` pings every device first, in parallel, and skips the ones
   that don't answer. Without it, an offline switch still fails safely (its
   pre-change backup can't connect, so nothing is applied), but only after a
   full SSH timeout. The ping also runs on `--dry-run`, so the preview shows
   exactly which switches a real run would touch.
4. `--cisco`, `--aruba` and `--ruckus` let only that manufacturer's switches
   through; combine them for more than one. Use this when a device list mixes
   vendors and the commands only suit one of them, for example
   `--file ./site-a.txt --cisco 'ip ssh version 2'`. Other switches are
   listed as filtered and aren't touched. They don't count against the run,
   and an off-vendor switch that isn't approved for writes doesn't block the
   batch. The manufacturer comes from the model number first (see
   "Manufacturer" below; `netrune device support <target>` and `netrune
   inventory list` show it), so a switch with no recognizable maker is
   filtered out by every vendor flag. RUCKUS configuration isn't supported
   yet, so `--ruckus` currently previews but won't apply.
5. Under `--confirm`, switches are configured one at a time, each through its
   own backup/apply/verify, and a failure on one doesn't stop the rest.

The run ends with one table of every device and its outcome. Exit code 0
means every listed device succeeded. 3 means at least one didn't, or was
skipped (vendor-filtered switches don't count). 4 means `--skip-offline`
found every device offline. 6 means nothing matched the vendor filter.

#### Every device in inventory: `--all`

A run that names no device needs `--all`. Without it the first command would
be read as a device name, so netrune refuses and suggests `--all` instead of
guessing. With `--all`, every positional is a command and every inventory
device is in scope; the vendor flags (and `--site`, `--status`) narrow it:

```bash
netrune device config --all --cisco "ip ssh version 2" --skip-offline --dry-run
netrune device config --all --aruba --commands-file ./aruba-ntp.txt \
  --skip-offline --skip-unverified --dry-run
```

Everything under "How a batch runs" applies, including the up-front check:
one switch that isn't approved for writes refuses the whole fleet unless
`--skip-unverified` is given. `--all` can't be combined with `--file` or
`--target`. Preview tables carry each device's name and manufacturer, since
`--all` passes devices by IP.

#### Manufacturer

Every switch and AP carries a `manufacturer` (Cisco, Aruba, Ruckus,
Ubiquiti) alongside its model. It is read from the model number first
(`C9200L-24P-4G` is Cisco whatever else a record says), then from maker words
in the platform or sysDescr. When a stored platform label names a different
maker than the model number, the model wins for driver selection too, and
`netrune db coherence --realign` (part of the morning check) corrects the
stored label.

### 16.7 `vlan locate`

```text
netrune vlan locate <target-list> <vlan-list> [--depth 0-10] [--max-nodes 1-256]
```

One target and one VLAN without `--depth` preserve the original one-switch
helper behavior. Multiple targets or VLANs use the structured cascade engine
even at depth 0.

```bash
netrune vlan locate SW1 10,20-22
netrune vlan locate SW1,SW2 10,20 --depth 3
netrune vlan locate --target SW1 --target SW2 --vlan 10,20-22 --depth 3
```

The limits are 16 roots and 128 distinct VLANs. Comma-separated IDs and
ascending ranges are accepted. Repeated `--target`/`--device` and `--vlan`
options avoid ambiguity when names contain unusual punctuation. The final
matrix has one row per root/VLAN pair; JSON includes every independent run.

With `--depth`, it becomes a bounded recursive location workflow:

```bash
netrune vlan locate site-a-core 131 --depth 5
netrune vlan locate site-a-core 131 --depth 5 --max-nodes 40 --json
netrune vlan locate site-a-core 131 --depth 5 --refresh-neighbors
netrune vlan locate site-a-core 131 --depth 5 --dry-run
```

The root switch is layer 0. A depth of 5 means Netrune inspects the root and reachable switch neighbors through layer 5, a maximum of five switch-to-switch hops from the root. Switches at layer 5 are inspected, but their neighbors are not followed. The hard depth cap is 10.

The cascade resolves the root uniquely from canonical inventory/aliases, then performs breadth-first traversal. At each switch it:

1. Runs the existing VLAN inspection through `netrune-control` over SSH.
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
netrune vlan propagation <target-list> <vlan-list> [--depth 0-10] [--max-nodes 1-256]
```

The one-switch form examines trunks/uplinks for VLAN propagation. The recursive form applies that inspection to every safely reachable switch layer:

```bash
netrune vlan propagation site-a-core 131 --depth 5
netrune vlan propagation site-a-core 131 --depth 5 --max-nodes 40 --json
netrune vlan propagation site-a-core 131 --depth 5 --refresh-neighbors
netrune vlan propagation site-a-core,plant-sw 10,20-22 --depth 5
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

Progress lines such as `[VLAN] 2/5 inspect SWITCH-NAME (192.0.2.2)` and `[VLAN] 2/5 SWITCH-NAME: VLAN 131 defined; trunks=2 gaps=0 next-switches=1` go to stderr and are flushed immediately. Locate mode also includes the access-port count. The CLI keeps the final report on stdout. This keeps concise progress visible without interleaving it into the final table or JSON document.

The underlying helper still uses VLAN 4 as one uplink-indicator heuristic. That is environment-specific and can misclassify networks where VLAN 4 is absent, local, or used differently. The recursive layer may use credible LLDP/CDP switch links to reach the next layer, but it does not count those links as trunks or assign them a propagation result unless the existing helper reports that evidence.

### 16.9 `vlan set`

```text
netrune vlan set <target> <interface> [--access N|--trunk LIST] --dry-run|--confirm
```

Examples:

```bash
netrune vlan set 198.51.100.92 Gi1/0/7 --access 120 --dry-run
netrune vlan set 198.51.100.92 Gi1/0/48 --trunk 10,20,120 --dry-run
netrune vlan set 198.51.100.92 Gi1/0/48 --trunk 10,20,120 --native 10 --dry-run
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

hash. VLAN writes are currently approved only for the Cisco driver. Known Aruba
and RUCKUS targets fail closed before preflight/backup/apply transport; their
read support does not imply write support.

---

## 17. Lookup and Diagnostic Commands

### 17.1 `lookup core`

```text
netrune lookup core <ip|mac>
```

Examples:

```bash
netrune lookup core 198.51.100.92
netrune lookup core 0200.0000.0025
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
netrune lookup mac <inspect|locate|profile|history|vendor|online|registry> ...
```

Examples:

```bash
netrune lookup mac inspect 0200.0000.0025
netrune lookup mac locate 0200.0000.0025 ZONE34
netrune lookup mac locate 0200.0000.0025 --site ZONE34 --limit 50
netrune lookup mac profile 0200.0000.0025 ZONE34
netrune lookup mac history 0200.0000.0025 --limit 100
netrune lookup mac vendor 00:00:5e:00:53:01
netrune lookup mac online 00:00:5e:00:53:01
netrune lookup mac online 00:00:5e:00:53:01 --refresh
netrune lookup mac registry status
netrune lookup mac registry refresh
```

The MAC may use colon, hyphen, dotted, or plain hexadecimal notation. Netrune normalizes it to a canonical physical-unicast identity.

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

Netrune classifies a hit on a topology-known inter-switch port as `switch-link`; other hits are `edge-candidate`. The likely physical endpoint is usually the furthest credible edge candidate, not every upstream CAM hit. `profile` gathers extra evidence only on the first three edge candidates to bound SSH load.

#### What a MAC can and cannot prove

A MAC table can locate a Layer-2 device without ARP, DHCP, or any known IP. Therefore a hit with no IP correlation is consistent with a device that is connected but has not obtained an address. It is not proof that the device is currently powered or functional: dynamic entries age out, may remain briefly after disconnect, and a silent endpoint may disappear from the table.

OUI/IEEE assignment data identifies the registered manufacturer/organization,
not an exact model. Netrune checks 36-bit MA-S and 28-bit MA-M assignments as
well as traditional 24-bit MA-L/OUI data. A more specific model hint is
possible only when LLDP/CDP, inventory, port description,
authentication/device-tracking, or another local observation supplies it.
Locally administered/randomized MACs have no authoritative IEEE manufacturer
assignment. Netrune reports these as evidence and hints, not certainties.

The older direct forms remain for compatibility:

```bash
netrune lookup mac CORE01 0200.0000.0025
netrune lookup mac all 0200.0000.0025 --limit 50
```

They query one switch or all current switches but provide less correlation than `locate`/`profile`. Prefer the explicit subcommands for new procedures.

### 17.3 `diagnose latency`

```text
netrune diagnose latency <target> [--count N]
```

Examples:

```bash
netrune diagnose latency 1.1.1.1
netrune diagnose latency ZONE34 --count 10
netrune diagnose latency 198.51.100.92 --count 5 --json
```

A name matching several switches or APs opens the same numbered picker as
`device ssh`: move with the arrows or type the row's number, then Enter.
Addresses and abbreviations are probed as typed.

Default terminal mode is continuous until interrupted. Finite mode reports sent/received/loss, min/average/max latency, and average absolute consecutive latency difference as jitter. JSON mode is always finite and defaults to five samples when no count is provided.

The probe helper can also perform TCP-port timing internally, print timestamped bar output, force/auto-run traceroute, beep on loss, collect background metadata, and offer an interactive SSH handoff. Those are mostly legacy helper options rather than fully surfaced v8 action flags.

### 17.4 `diagnose core-ping`

```text
netrune diagnose core-ping <target> [--core <switch>] [--count 1-20] [--packet-timeout 1-10]
```

Examples:

```bash
netrune diagnose core-ping 192.0.2.50 --count 5
netrune diagnose core-ping ZONE34 --core CORE01 --count 10
netrune diagnose core-ping 192.0.2.50 --dry-run --json
```

This is the point-of-truth probe requested from the network core rather than from the Netrune host. The destination can be an IP or an inventory name that resolves to an IP. The source is `--core` when supplied, otherwise `core_switch_ip`/`core_switch` from configuration. A named core must resolve uniquely; a literal configured core IP can be used before it is imported into inventory.

Netrune selects read-only device syntax from the core platform: Cisco-style `ping ... repeat ... timeout ...` or Aruba-style `ping ... repetitions ...`. If the inventory platform is unknown, it first reads `show version` and makes a best-effort vendor selection. It parses transmitted/received packets, loss, and minimum/average/maximum latency.

Each completed measurement is stored in `probe_results` with mode `core-ping:<core-ip>`, the raw structured payload, and an ISO 8601 UTC observation companion. This makes the core vantage point distinguishable from a host-origin latency probe in diagnostic history.

Interpret it as a measurement from one routing point, not universal reachability. ICMP policy, VRFs, source-interface selection, control-plane policing, and vendor output differences can affect the result. The current action does not expose VRF or source-interface options. `--dry-run` resolves source/destination and bounds but does not contact the core.

### 17.5 `diagnose speed`

```text
netrune diagnose speed [--profile quick|balanced|thorough] [--runs N] [--ca-file <PEM>]
```

Examples:

```bash
netrune diagnose speed
netrune diagnose speed --profile quick
netrune diagnose speed --profile thorough --runs 5
netrune diagnose speed --runs 5
netrune diagnose speed --runs 3 --json
netrune diagnose speed --profile balanced --dry-run
```

This measures the routed path from the machine running Netrune to Internet benchmark servers. It does **not** measure an arbitrary endpoint merely because that endpoint is connected to a named switch port.

Speed profiles trade runtime for confidence:

| Profile | Default runs | Purpose | Reliability meaning |
| --- | ---: | --- | --- |
| `quick` | 1 | Fast path check when you need a timely read | Fresh upload/download/loaded latency from one complete server; tries only a small candidate budget on failures; reliability is capped at medium because there is no cross-server agreement |
| `balanced` | 2 | Default operator mode | Two independent complete servers, shorter idle sampling than the old path, cross-server agreement still computed |
| `thorough` | 3 | Audit or disputed-result mode | Heavier sampling, old-style deeper candidate discovery, and optional `--runs 4`/`--runs 5` for stronger agreement |

`--runs` must be 1 through 5. Balanced and thorough require at least 2 runs; use `--profile quick` for a one-server check. The default command is now equivalent to `netrune diagnose speed --profile balanced --runs 2`, which is materially faster than the older three-server default while still comparing independent servers.

The v8.5 beta path:

1. Determines route interface, source IP, gateway, active VPN-like interfaces, whether the tested route uses one, and optional Wi-Fi signal.
2. Uses `netrune/speed.py` and the Python `speedtest-cli` module,
   always with certificate-chain and hostname verification enabled.
3. Under WSL, builds a temporary trust bundle from Linux roots plus certificates trusted by Windows Local Machine Root/CA stores. `--ca-file` or `NETRUNE_SPEED_CA_FILE` supplies an explicit PEM bundle. Netrune never silently falls back to `-k`/insecure TLS.
4. Reuses a short-lived server-discovery cache for the same routed path across profiles when it contains enough candidates, then still performs fresh upload/download traffic. Set `NETRUNE_SPEED_CACHE_TTL_SECONDS=0` to force fresh discovery every time.
5. Discovers more candidate servers than requested so unauthorized/broken endpoints can be skipped.
6. Measures an idle ICMP baseline, pins one verified client to each selected server, and reuses that session for sequential upload then download. Separate concurrent ICMP streams measure loaded latency, jitter, loss, and sample coverage for each direction. Sequential transfer preserves directional accuracy while eliminating a second client/server setup round trip.
7. Requires the profile-specific number of complete servers, rejects large outliers for the sustained aggregate, computes observed range and coefficient of variation, and rates reliability high/medium/low.
8. Writes a 14-field internal record containing both loaded-jitter values and byte totals; the v8.1 field-index defect is fixed.
9. Stores the structured result in both `speed_tests` and `diagnostic_runs`, with `observed_at_iso`/`recorded_at_iso` chronology.

Interpret the result with the path metadata. A VPN, proxy, TLS inspection gateway, server congestion, traffic shaping, Wi-Fi, and endpoint CPU can all become the bottleneck. Multiple independent servers reduce server-specific error but cannot remove enterprise policy from the path.

An error such as `HTTP Error 401: Authorization Required` during discovery/upload means the benchmark endpoint is being rejected by an upstream gateway or requires authentication. It is not a zero-speed result. Confirm with:

```bash
netrune diagnose doctor --online
netrune diagnose filtering speedtest.net
```

Then use an organization-approved authenticated proxy/browser stack, allow the benchmark category, or use a controlled `iperf3` endpoint. Do not bypass enterprise filtering or report a partial transfer as a valid speed.

### 17.6 `diagnose throughput`

```text
netrune diagnose throughput <iperf3-server> [--port 5201] [--seconds 10]
  [--parallel 1-16] [--direction both|upload|download] [--bind <source-ip>]
```

Examples:

```bash
netrune diagnose throughput 203.0.113.20
netrune diagnose throughput core --direction both --seconds 20 --parallel 2
netrune diagnose throughput 203.0.113.20 --dry-run --json
```

This is the defensible endpoint-to-core capacity test. It requires an intentionally managed server:

```bash
# On a host at the core-side measurement point:
iperf3 -s -p 5201

# On the endpoint attached to the switch port, or its Netrune agent:
netrune diagnose throughput <core-server-ip> --port 5201 --direction both
```

`upload` means Netrune client to server; `download` adds iperf3 reverse mode and means server to client. Each direction runs separately with a two-second omitted warm-up. Netrune parses JSON and reports receiver goodput, transferred bytes, elapsed time, streams, and TCP retransmits. Results are stored in `diagnostic_runs`.

`core` resolves `core_iperf_server`, then falls back to the configured core switch. A switch management plane is usually **not** an appropriate iperf3 server. Prefer a dedicated host connected at the desired core/distribution point, configure `core_iperf_server`, permit only the intended clients/port, and monitor the test host.

A switch cannot infer endpoint throughput from interface counters. To measure a particular device on a port, run the client on that device or deploy a controlled endpoint agent. Running against `127.0.0.1` only verifies the tool/parser and measures memory/loopback performance; it says nothing about the network.

### 17.7 `diagnose port-health`

```text
netrune diagnose port-health <switch> on <interface>
  [--sample-seconds 0-60] [--expected-speed <Mbps>]
```

Examples:

```bash
netrune diagnose port-health site-a-access on Gi1/0/12
netrune diagnose port-health 203.0.113.96 on 9 --sample-seconds 10 --expected-speed 1000
netrune diagnose port-health ZONE34 on Gi1/0/7 --dry-run --json
```

The command reads the interface twice and separates old cumulative totals from errors that increase during the observation window. Cisco IOS/IOS-XE parsing covers admin/oper/line state, link reason, negotiated speed/duplex/media, five-minute rates, CRC/frame/input/output errors, drops, collisions, and resets. Aruba AOS-Switch combines the detailed counter view with `show interfaces brief` to obtain mode and media.

Findings include admin/link down, half duplex, negotiated speed below `--expected-speed`, counter reset/wrap, and active increases in CRC, frame, input/output error, collision, runt, giant, or receive-error counters. Existing nonzero totals remain visible but do not become a current fault unless they increase during the sample. Exit 3 means the read succeeded and found `ATTENTION`, `DOWN`, or an incomplete result.

This command assesses the switch side. It does not prove cable pin continuity, application throughput, DHCP success, or endpoint health. Combine it with cable status/TDR and endpoint `iperf3` for a complete diagnosis.

### 17.8 `diagnose cable`

```text
netrune diagnose cable <switch> on <interface>
netrune diagnose cable <switch> on <interface> --test --dry-run
netrune diagnose cable <switch> on <interface> --test --confirm [--wait 2-60]
```

The default is a read-only query of the **previously recorded** TDR/cable result. `NOT_RUN` means exactly that: the switch has no previous result. It does not mean the cable passed or failed.

Starting a new TDR is potentially disruptive. Netrune therefore returns exit 7 unless `--dry-run` or `--confirm` is present. The dry run prints the exact sequence without touching the switch. Supported active syntax is:

| Family | Start | Read result |
|---|---|---|
| Cisco IOS/IOS-XE | `test cable-diagnostics tdr interface <port>` | `show cable-diagnostics tdr interface <port>` |
| Aruba AOS-Switch | `test cable-diagnostics <port>` | `show cable-diagnostics <port>` |
| Aruba CX | `diag cable-diagnostic test/show <port>` | Status reads are supported where recognized; automated active confirmation is deliberately blocked |

Before an active Aruba AOS-Switch test, Netrune merges the brief media view and refuses optical media such as `1000LX`. Cisco media is similarly checked when exposed. Never initiate TDR on a production uplink merely to see what happens; schedule a maintenance window and verify the exact port.

TDR estimates copper-pair continuity/impedance and fault distance. It can detect patterns such as normal/good, open, short, crossed, or impedance mismatch where firmware reports them. It cannot validate fiber, guarantee all eight pins under motion/load, prove application throughput, or reliably catch every intermittent break. Remote equipment, Auto-MDIX, patch panels, and firmware limitations affect interpretation. Repeat a suspicious result and use a certified physical cable tester when pin map, wiremap, NEXT/return loss, or certification is required.

Each read/test is stored in `diagnostic_runs` with device, port, platform family, whether a new test was started, pair rows, limitations, and standard UTC date.

### 17.9 `diagnose doctor`

```text
netrune diagnose doctor [--online]
```

The default performs local readiness checks only: required commands, Python speed backend, route to `1.1.1.1`, WSL detection, configured core, optional `core_iperf_server`, `iperf3`, `ethtool`, GPG/sudo availability, and SSH-vault format/readiness. Vault inspection uses only non-prompting sudo checks. `--online` additionally verifies Speedtest server discovery and TLS trust without running a full transfer.

Under WSL, a reported `ethN` speed from `ethtool` describes the virtual adapter presented to Linux, not the host's physical Ethernet cable. Use switch-side port health/TDR or Windows/physical test equipment for the actual cable. Doctor results are chronological `diagnostic_runs`, so readiness changes can be reviewed later.

### 17.10 `diagnose filtering`

```text
netrune diagnose filtering [domain]
```

Example:

```bash
netrune diagnose filtering google.com
```

This v8 command delegates to the selected filtering path in `netrune-legacy`. Checks can include:

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
netrune diagnose interface <device> on <interface> [--chart classic|histogram]
```

Examples:

```bash
netrune diagnose interface ZONE34 on Gi1/0/7
netrune diagnose interface 198.51.100.92 on Gi1/0/7 --chart histogram
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

This remains the legacy one-off rate chart. Registry jobs force `--once` so a background job terminates. Prefer `netrune traffic watch` when the goal is a recorded series over time, and `diagnose port-health` when link negotiation and active error deltas matter.

### 17.12 `path inspect` and `ghoster`

```text
netrune path inspect <endpoint> --vlan <1-4094>
  [--from <switch>] [--to <switch>] [--depth 1-16]
  [--max-nodes 1-256] [--cached|--live|--refresh] [--explain]

netrune ghoster <endpoint> --vlan <1-4094> [same options]
```

`ghoster` is an alias for the path domain, not a second implementation.
Defaults are hybrid mode, depth 8, and 64 nodes. Hard limits are depth 16 and
256 nodes; limits prevent a malformed or cyclic topology from becoming an
unbounded SSH walk.

Examples:

```bash
netrune path inspect 02:00:00:00:00:25 --vlan 120
netrune path inspect 192.0.2.25 --vlan 120 --from SITE-A-CORE-01 --explain
netrune ghoster 02:00:00:00:00:25 --vlan 120 --depth 5 --max-nodes 40
netrune path inspect 02:00:00:00:00:25 --vlan 120 --cached --json
netrune path history 02:00:00:00:00:25
netrune path show path-EXAMPLE
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
cannot parse policy semantics, Netrune emits `POLICY_SEMANTICS_UNKNOWN`; the
operator must inspect the referenced policy. Similarly, the chosen path is the
best path represented by current topology evidence, not packet-level tracing.
ECMP, MLAG, tunneling, asymmetric routing, controller overlays, stale CAM
learning, and unsupported firmware can produce alternate real paths.

Plain output presents a concise hop table and findings. JSON includes RFC 3339
`requested_at_iso`, `started_at_iso`, `finished_at_iso`, hop evidence times, and
`evidence_age_seconds`. Use `path history` and `path show` to compare what was
known at different times instead of overwriting the prior diagnosis.

---

## 17A. Everyday Checks by Name (`netrune check`)

Short names for the checks you reach for, grouped by the question they
answer. `netrune check` lists them all, and `netrune check <name> --show`
prints the command a name runs. A name is only shorthand: global flags such
as `--json`, `--dry-run`, `--all`, and `--limit` work exactly as on the real
command.

| Question | Check | What it does |
| --- | --- | --- |
| Start of day | `morning` | Reachability, topology, realign memory, database health, filtering, attention queue |
| Long jobs | `weekly`, `weekly-resume` | Every scan, SSH reads of every switch, backups; resume what waited for the vault |
| Anything to look at? | `attention` | Outages, flaps, link changes, AP moves, failed backups, merge candidates |
| Who is up? | `pulse [target]` | Ping every switch and AP (or one) and record up/down |
| What is down? | `down` | Down right now, from the last pulse |
| Are these alive? | `alive SW1 SW2` | Ping just these now |
| Up/down history | `status`, `uptime` | Current state with flaps; changes newest first |
| Links | `links` | Quick: known switch-to-switch links with confidence |
| What changed in topology? | `link-changes` | Links that appeared/disappeared |
| What does a switch see? | `neighbours [switch]` | LLDP/CDP neighbours per port |
| Uplinks / loops | `uplinks <switch>` | Live spanning tree: root, blocked and uplink ports |
| APs on a switch | `aps-on <switch>` | APs and their ports |
| Confirm AP ports | `ap-ports <switch>` / `--all` | Live CDP/LLDP plus MAC-table check |
| AP movement | `ap-moves`, `ap-history <ap>` | Moves newest first; one AP over time |
| Find a device | `find [text]` | By any part of name, IP, MAC, serial, model |
| Where is this MAC? | `find-mac <mac>` | Live: the access port it is on now |
| Who is this IP? | `find-ip <ip>` | Core ARP/MAC tables |
| Who had it? | `mac-history`, `ip-history`, `port-history <switch> <port>` | Over time |
| Where is a VLAN? | `vlan-where <switch> <vlan>` | Live VLAN presence |
| Does a VLAN propagate? | `vlan-trace <switch> <vlan>` | Follow it switch by switch, see where it stops |
| The path to something | `path <endpoint> <vlan>` | L2/L3 hops with findings |
| Is this port healthy? | `port-health <switch> <port>` | Negotiation and error growth |
| Last cable test | `cable <switch> <port>` | Recorded TDR result, no new test |
| Latency / Internet | `latency <target>`, `internet`, `speed` | RTT and loss; DNS/TLS/filtering; speed |
| One device in full | `device <name>` | Identity, history, relationships |
| Same switch? | `same <a> <b>` | Evidence and conflicts between two records |
| What can Netrune do on it? | `support <device>` | Maker, model, driver, safe capabilities |
| Re-read hardware | `hardware <device>` / `--all` | Model, Motherboard serial, base MAC over SSH |
| Database health | `db`, `db-fix`, `db-deep`, `db-size` | Quick coherence; and fix; full integrity; size and counts |
| Backups | `backups <device>`, `config-diff <device>`, `backup-all` | History; last change; back up everything changed |
| This machine | `doctor`, `vault` | Setup sanity; vault lock state |

Each line of `netrune check` also says how far it reaches: `none` (Netrune's
memory only, instant), `ping`, `SNMP`, `SSH`, or `Internet`. `writes` means it
updates Netrune's own records; no check changes a switch.

## 18. Workflows, Jobs, and Command Registry

### 18.1 Workflows

Workflows are typed manifests of existing v8 commands. Each step has a stable
ID, label, exact command, and `on_failure` policy (`continue` or `stop`). Steps
execute sequentially and return one structured final summary.

#### `workflow morning-check`

```bash
netrune workflow morning-check --dry-run
netrune workflow morning-check
```

Sequence: import the caches, check reachability, refresh LLDP/CDP topology,
realign memory and check the database (`db coherence --realign`), review
topology changes, run the filtering diagnostic, build the attention
summary, and list the decisions waiting for you. In a terminal it then asks
whether to go through them now (`health review`, section 14.4a): answer each
with y/n or a number, and the morning ends on a clean slate.

The realign step is the database half of the morning. It re-applies every
manual merge and re-derives relationships and identity-continuity
candidates (what `memory refresh` does, skipped when the caches haven't
changed since the topology scan imported them), relabels any switch whose
stored platform contradicts its model number, and checks SQLite health
(`quick_check`), dangling references, schema version, records carrying
several MACs or serials, merges whose surviving record has left inventory,
flat-cache drift, stuck jobs, and WAL growth. It also removes switches that
an old AP scan filed as APs, and reports one hostname answering on several
live switches (a naming or DNS mistake, kept apart rather than merged). It replaces the old separate
`memory refresh` step, so it adds about a second, not a second refresh.
Anything it can't fix with one right answer is reported (the step shows
`ATTENTION`) for you to act on; merge candidates still need an explicit
`inventory merge`/`ap merge --confirm`.

Run the same check on its own any time:

```bash
netrune db coherence            # report only
netrune db coherence --realign  # also refresh memory and fix labels
```

#### `workflow weekly`

```bash
netrune workflow weekly --dry-run
netrune workflow weekly
netrune workflow weekly --resume     # only the steps that had to wait
```

Everything too slow for the morning, in one run:

1. import, reachability, the network scan, the AP scan, and the topology scan
   (no credentials needed);
2. over SSH, under one vault unlock:
   - a hardware refresh of every switch (`device inventory --all`), which is
     how Cisco Motherboard serials are read;
   - `ap neighbors --all`;
   - a spanning-tree sweep;
   - changed-only backups of everything;
3. realignment, and the attention queue.

If the vault cannot be unlocked (nobody at the desk to answer Windows
Hello), or no switch answered the reachability step (the laptop is off the
site network), the SSH steps are marked `DEFERRED` instead of failing one
switch at a time. The attention queue (and so your morning check) then says
`weekly workflow: ... waiting since ...; run: netrune workflow weekly --resume`.

#### Scheduling the weekly run

```bash
netrune workflow schedule weekly                                   # Sundays 02:00
netrune workflow schedule weekly --when 'Sat *-*-* 22:00:00'
netrune workflow schedule weekly --dry-run                         # show the units
netrune workflow schedule weekly --remove
```

This installs a systemd user timer rather than a cron entry. The timer is
`Persistent=true`: if the laptop was off or asleep at the scheduled time, the
missed run starts as soon as it is back. When it runs, Windows Hello may ask
once for the SSH steps.

#### `workflow refresh-inventory`

```bash
netrune workflow refresh-inventory
```

Runs fast health, AP scan, topology scan, memory refresh, and attention review. It is not the same as a full switch/router inventory scan.

#### `workflow backup-online`

```bash
netrune workflow backup-online ZONE10
```

Runs changed-only backups for online matching devices.

#### `workflow site-health`

```bash
netrune workflow site-health google.com
```

Combines latency and filtering checks for the target. A site token that does not resolve as a network/DNS target can fail one or both steps.

#### `workflow ap-audit`

```bash
netrune workflow ap-audit
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

The registry is the shared catalog used by CLI registry commands, generated
forms, previews, background jobs, retry policy, and workflow metadata.

```bash
netrune commands list
netrune commands show backup-run --json
netrune commands run backup-run ZONE34 --preview
netrune commands run diagnose-latency --target 1.1.1.1 --count 10
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
background job execution remains blocked for configuration.

`preview_for_action` is the single rendering policy used by Natural Ask and registry previews. It reports missing arguments, validation failures, risk and safety classes, state effects, whether confirmation is required, and why an action is blocked. The job runner rejects unknown, preview-only, terminal, config, and danger actions before process creation.

`commands run` accepts both positional arguments and named option forms for registry fields. Prefer `commands show <id> --json` before automating a registry action.

### 18.4 Jobs

The core job system is used by long-running CLI actions.
Submitted jobs are queued in memory and SQLite, constrained by
`NETRUNE_JOB_CONCURRENCY` (default 3), and execute commands in supervised process
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
workflow actions write concise progress to stderr. Job readers render these events
in Activity as they arrive. The final
structured result remains separate and is adapted back into workbench datasets.

Job log records have monotonic IDs, so a reader can resume after the last line it displayed rather than replaying the whole log. Each event includes `created_at` plus `created_at_iso`.

Direct noun-first CLI commands are synchronous and generally do not create job
rows. `netrune jobs list` therefore primarily reflects registry-submitted jobs.

### 18.5 Job commands

```bash
netrune jobs list [--limit N]
netrune jobs show <id>
netrune jobs logs <id>
netrune jobs cancel <id>
```

Cancellation only works for a live process owned by the current core instance.
The CLI cannot resurrect an old in-memory process handle from a database row.
The owner sends `SIGTERM` to the process group, waits, and can escalate
internally while preserving prior events.

Automatic retry is offered only when the registered command is read-only and
all required arguments can be reconstructed from defaults.

---

## 19. Database Administration

### 19.1 `db migrate`

```bash
netrune db migrate --json
```

Creates/upgrades schema, cleans invalid MAC identity, recomputes derived state in migration mode, and reports suppressed structural events. v8.1 also repairs pre-v8 `jobs` tables that lack `created_at` or `writes_local`; existing rows are preserved and missing creation times are backfilled from start/finish chronology.

### 19.2 `db status`

```bash
netrune db status --json
```

Reports:

- DB/cache paths;
- current and expected schema version;
- SQLite, WAL, and SHM byte sizes;
- device, AP observation/canonical, neighbor, relationship, backup, and job counts.

### 19.3 `db path`

```bash
netrune db path
```

Use this before any direct `sqlite3` investigation. Never assume the non-root default when environment overrides or root execution are possible.

### 19.4 `db integrity`

```bash
netrune db integrity --json
```

Runs SQLite `quick_check` and `integrity_check` without intended data changes. Both should return `ok`.

### 19.5 `db repair`

```bash
netrune db repair
```

Runs migration, derived-state synchronization, WAL checkpoint, `ANALYZE`, optimizer maintenance, and integrity checks. It is not a universal corruption recovery tool and does not restore lost records.

Before repair:

1. Stop the traffic collector, the exporter, and other writers.
2. Copy the DB plus any `-wal` and `-shm` files consistently, or use SQLite's backup mechanism.
3. Record `db status` and integrity output.
4. Confirm disk space and file ownership.

### 19.6 `db vacuum`

```bash
netrune db vacuum
```

Checkpoints WAL and compacts SQLite. `VACUUM` needs temporary disk space and an exclusive-enough write window; run it during low activity after a backup.

### 19.7 Flat aliases

```bash
netrune db import-flat
netrune db export-flat
```

These are aliases of the inventory bridge commands.

### 19.8 Direct SQLite inspection

Read-only examples:

```bash
sqlite3 "$(netrune db path)" '.tables'
sqlite3 "$(netrune db path)" 'PRAGMA user_version;'
```

Do not manually edit derived tables unless you are repairing with a tested procedure. The next import/refresh may overwrite current state or emit misleading events.

---

## 19A. Profiles, Ingest, Plugins, and Extension Points

These domains turn Netrune from a fixed deployment script into a reusable local
platform. Profiles isolate operators and environments; channels ingest data;
plugins add reviewed Python implementations; declarative drivers add bounded
read commands without executable code.

### 19A.1 Profile lifecycle

```bash
netrune profile list
netrune profile create lab
netrune profile show lab
netrune profile use lab
netrune profile paths
netrune --profile production inventory list
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
netrune profile migrate-legacy legacy-local --json
netrune --profile legacy-local config validate
netrune --profile legacy-local db integrity
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
netrune config show
netrune config get core_switch_ip
netrune config set core_switch_ip 192.0.2.1
netrune config unset core_switch_ip
netrune config paths
netrune config validate
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
path = "/srv/netrune-input/devices.json"
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
netrune ingest validate
netrune ingest channels
netrune ingest run asset-export
netrune ingest history --limit 20
netrune ingest observations asset-export --limit 20
netrune ingest rejects --limit 20
```

Validation reads manifests but fetches no source records. `channels` syncs
valid manifests into SQLite while retaining an invalid row for each broken
file. One broken channel does not hide valid channels. Duplicate channel names
are invalid even when both files are individually parseable.

For every delivery, Netrune creates `IngestRunV1` and then:

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
`netrune ingest channels` shows these built-in channels alongside manifest
channels after they have produced evidence.

### 19A.7 Plugin lifecycle

Stable entry-point groups are:

- `netrune.ingest`
- `netrune.device_drivers`
- `netrune.parsers`
- `netrune.exporters`

```bash
netrune plugin groups
netrune plugin list
netrune plugin enable netrune.parsers:example
netrune plugin check netrune.parsers
netrune plugin disable netrune.parsers:example
```

Discovery reads package metadata but does not import disabled plugin code.
Enablement is profile-local and transactional: Netrune imports and validates the
exact entry point first, then records enablement; incompatible API versions,
name collisions, import failures, and write capability claims roll back. `check`
loads enabled entries one at a time and isolates failures so one package does
not prevent the rest from being reported.

Plugins are trusted Python code in the Netrune process, not a sandbox. Review
source, dependency tree, publisher, version, and hashes. Pin the package in the
deployment environment. Arbitrary shell hooks, third-party writes, and plugin
configuration actions are prohibited in 8.5.

Every plugin object declares `NETRUNE_PLUGIN_API_VERSION = "1"`. An optional
`NETRUNE_PLUGIN_CAPABILITIES` sequence is normalized and rejected when it claims
write, shell, subprocess, process, exec, execute, or system behavior. Each
entry-point group then has a required interface:

| Group | Required interface | 8.5 runtime boundary |
|---|---|---|
| `netrune.ingest` | `read_records(channel, reader, secrets)` returning mapping records | A `kind="plugin"` channel selects it by `reader.provider` |
| `netrune.device_drivers` | One `DeviceDriver` or `netrune_device_drivers()` | Drivers are revalidated and added only to the selected profile's cloned registry |
| `netrune.parsers` | `parse()` | Loaded into the internal parser extension registry |
| `netrune.exporters` | `export()` | Loaded into the internal exporter extension registry |

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

Netrune resolves only the references declared in `[secrets]`, passes those
values in memory, removes them from provider exception messages, and records
the plugin distribution in observation provenance. Provider records still
pass through normal mapping, validation, idempotency, stale-field, quarantine,
and current-state rules. Python device drivers receive a second validation:
read command allowlists, bounded match patterns and parser IDs, collision
checks, discarded firmware-write profiles, and forced-unsupported
configuration/VLAN writes.

Parser and exporter plugins are internal extension APIs in 8.5. Netrune does
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
netrune support bundle
netrune support bundle ./netrune-support.tar.gz
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
netrune ask "How many APs are offline in ZONE10?"
netrune ask "Where was SITE-SQ21-AP161 connected before?" --json
netrune ask "Run a fast health check for ZONE34"
netrune ask "Preview changing Gi1/0/7 on ZONE34 to access VLAN 120" --json
```

Retrieval returns an intent, answer, timestamped result rows, suggestions, and an evidence workflow. An operation returns `intent=command_plan` and a structured plan.

### 20.2 Command-plan contract

A command plan includes:

| Field | Meaning |
|---|---|
| `action` | Stable ID from `netrune commands list` |
| `args` | Extracted structured values; never a generated shell fragment |
| `command` | Shell-escaped preview built by the core registry |
| `status` | `ready`, `needs_clarification`, `preview_only`, or `blocked` |
| `missing_args` | Required fields that the wording did not supply |
| `safety_class` | `read-only`, `network-read`, `network-read/local-write`, `local-write`, `interactive-read`, or `config-write` |
| `state_effects` | Expected local/device effects from registry metadata |
| `run_supported` | Whether background job execution is permitted |
| `requires_confirmation` | Whether CLI/UI must obtain an additional explicit confirmation |
| `execution_hint` | Exact guarded CLI form when execution is supported |

Examples:

```bash
# Local read: plan, then execute without active-operation confirmation.
netrune ask "Prepare the database status command"
netrune ask --execute "Prepare the database status command"

# Active network/local-state operation: --execute and --confirm are both required.
netrune ask "Ping 198.51.100.92 five times"
netrune ask --execute --confirm "Ping 198.51.100.92 five times"

# Configuration stays preview-only in Ask even if --confirm is supplied.
netrune ask "Preview changing Gi1/0/7 on ZONE34 to access VLAN 120"
netrune vlan set ZONE34 Gi1/0/7 --access 120 --dry-run
# Only after independent review:
netrune vlan set ZONE34 Gi1/0/7 --access 120 --confirm
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
netrune ask
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
netrune ask patterns
netrune ask patterns --json
netrune ask aliases
netrune ask alias set "engineering office" "engg ofc"
netrune ask alias remove "engineering office"
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
netrune ask "Which APs are down on ZONE34?"

# Explicit verification
netrune ap on-switch ZONE34 --json
netrune ap list ZONE34 --status OFFLINE --json
netrune memory switch ZONE34 --json
```

### 20.9 Ask sessions

An Ask session carries a `session` object that is returned in its updated form after each turn and sent back for the next one. It keeps the latest eight question/answer pairs. A returned plan is never proof of execution: preview and run are separate steps.

### 20.10 Optional AI wrapper

The optional wrapper is included in the public source tree and source
distribution, but is not installed as part of the core wheel console in 8.5.
Use the source launcher for `netrune ai`; wheel-only installations retain the
fully deterministic `netrune ask` interface without undeclared model/runtime
dependencies.

`netrune ai` fast mode routes broad retrieval and all command requests through `answer_from_netrune_state`, which runs `netrune --json ask <question>`. Only narrow live interface and VLAN-summary questions use dedicated show workflows. A command response preserves the action, status, safety class, exact preview, and execution hint, then states that the AI wrapper did not execute it.

```bash
netrune ai "all APs that are down"
netrune ai "Run a fast health check for ZONE34"
netrune ai --ollama-select "Explain what changed around ZONE34"
```

Fast mode is deterministic and model-free. `--ollama-select` and `--model-summary` require a running local Ollama service and an installed model. If Ollama has no models, fast mode remains operational while model-assisted modes do not.

### 20.11 Failure modes

- **No intent matched:** Rephrase using `ask patterns` wording.
- **Wrong entity:** Use an exact hostname/IP/MAC or create a specific alias.
- **Stale answer:** Refresh inventory/health/memory first.
- **Duplicate-looking APs:** Inspect the `ap_aliases` intent and valid MAC evidence.
- **No diagnostic history:** The current v8 persistence gap may be responsible.
- **No prior location:** History starts only after Netrune observed and synchronized the relevant change.
- **Needs clarification:** Supply every field listed in `command_plan.missing_args`.
- **Blocked plan:** Read `reason`; do not move the request to a less guarded interface.
- **Wrong command match:** Rephrase with the public domain/action or ask for `commands list/show` metadata.
- **AI model unavailable:** Use default `netrune ai` fast mode or install/create the configured Ollama model deliberately.

---

## 21. Traffic Monitoring

Netrune collects interface throughput and reachability for targets you name, and
only for those. There is no discovery sweep and no all-ports poll: a target
enters the watchlist because an operator asked for it, which keeps SNMP load
proportional to what is actually being looked at.

### 21.1 What is collected

| Watch kind | Source | Metrics recorded |
| --- | --- | --- |
| `interface` | SNMP IF-MIB on the switch | octets, errors, and discards in both directions, link speed, operational and administrative status |
| `icmp` | ping from the collector host | `rtt_ms`, `jitter_ms`, `packet_loss_pct`, `reachable` |

Every reading is fetched in one batched SNMP request per device rather than one
request per OID. Counters are stored raw and monotonic. Netrune derives rates
for its own terminal views and offline report; the metrics stack derives them at
query time from the same raw counters, which is why a counter reset needs no
special handling there.

ICMP is measured from the collector, not from the device. That is deliberate:
the reading answers "can this collector reach that address", which is the
question a remote poller exists to answer.

### 21.2 Adding targets

```bash
netrune traffic interfaces SITE-A-SW01                      # what SNMP reports, and what is watched
netrune traffic watch SITE-A-SW01 Gi1/0/16 --interval 30
netrune traffic watch SITE-A-SW01 Gi1/0/16,Gi1/0/17,Te1/1/1 # one SNMP walk for the batch
netrune traffic ping 198.51.100.10
netrune traffic list
netrune traffic pause SITE-A-SW01                           # every port on that switch
netrune traffic resume Gi1/1/1                              # that port on every switch
netrune traffic interval Gi1/1/1 15
netrune traffic unwatch SITE-A-SW01 --confirm
```

`pause`, `resume`, `interval`, and `unwatch` accept a watch id, a device, or an
interface name, and act on everything that matches. Pausing keeps the history;
`unwatch` discards it, so a phrase matching more than one target needs
`--confirm`.

Pausing is not the same as removing. A paused target keeps its place in the
watchlist and its samples, stops being collected, and is still published to the
metrics stack with `netrune_interface_watch_enabled 0`, so a dashboard shows a
deliberate gap rather than an unexplained one.

`traffic watch` resolves the interface name against the device before accepting
it and refuses a name the switch does not have, listing what it does have. The
name is matched the way an operator types it, so `gi 1/0/16`, `Gi1/0/16`, and
`GigabitEthernet1/0/16` all resolve to the same port.

The resolved `ifIndex` is stored on the watch and reused, because walking the
whole IF-MIB every round costs far more than the counter read. Drift is detected
rather than assumed away: `ifName` travels with each counter read, and a watch
whose index now answers for a different port is re-resolved instead of being
graphed as though nothing moved.

### 21.3 Collecting

```bash
netrune traffic poll                       # one round, suitable for cron
netrune traffic daemon                     # continuous, each target on its own interval
netrune traffic daemon --interval 20       # continuous, one cadence for every target
netrune traffic status                     # is a collector running, and is anything stale
```

The collector re-reads the watchlist every tick, so `watch`, `pause`, `resume`,
and `unwatch` take effect within seconds without restarting it. Only one
collector runs at a time per profile; a second refuses to start rather than
double-polling the same devices.

One SNMP call serves every watch on the same device. A device that fails is
recorded as an error for that device only; the remaining targets in the round
still collect.

SNMP modes never open the SSH vault, so the collector runs unattended without a
Windows Hello or sudo prompt. If SNMPv3 is configured but blocked by an ACL, a
recent v2c success on that host suppresses the v3 attempt for 24 hours rather
than paying its timeout on every round.

### 21.4 Reading the data

```bash
netrune traffic show                       # sparklines for every target
netrune traffic show Gi1/1/1 --since 6h    # one target, wider window
netrune traffic report --since 24h         # self-contained HTML with charts
netrune traffic report --out ~/uplink.html
```

`--since` accepts seconds or a duration written as `15m`, `6h`, or `2d`.

`traffic show` prints current and peak values with a sparkline in which a gap in
collection renders as a blank cell, because a gap is information. `traffic
report` writes one HTML file with inline SVG charts, no scripts, and no external
assets; it opens from disk and can be published or mailed as-is.

### 21.5 Counter handling

A counter that goes backwards has either wrapped or been reset. Wrap is
recoverable and is recovered. A reset is not, and guessing would invent a spike
that never happened, so the interval is discarded and the series shows a gap.
The same applies across a device restart, which is detected from `sysUpTime`.

A computed rate above four times the reported link speed is treated as a counter
artefact rather than as traffic, and is discarded.

### 21.6 Collector identity

Every sample and every counter baseline is stamped with the collector that took
it, defaulting to this host's name and overridable with the
`traffic_collector_id` configuration key. Baselines are per collector, so a
second collector reading the same interface establishes its own baseline instead
of computing a delta against another host's reading.

This is the seam a remote poller uses: a small cloud instance running
`netrune traffic daemon` under its own collector ID writes samples that a laptop
can display without the two hosts corrupting each other's rate maths.

### 21.7 Retention

`traffic_samples` are retained for 30 days by default and pruned by
`netrune db prune` along with the rest of the history tables. Counter baselines
are current-value only and hold one row per watch, counter, and collector.

### 21.8 The metrics stack

Netrune collects and keeps evidence. It does not store a time series, query one,
or draw one. Those are separate jobs, and each is done by a component that does
only that:

| Component | Owns | Reached at |
| --- | --- | --- |
| `netrune traffic daemon` | Talking to devices. Holds the SNMP credentials. | local process |
| `netrune traffic exporter` | Publishing raw counters as Prometheus exposition. | `127.0.0.1:9713/metrics` |
| VictoriaMetrics | Retention and querying, in MetricsQL. | `127.0.0.1:8428` |
| vmalert | Alerting, evaluated against stored data. | `127.0.0.1:8880` |
| Perses | Dashboards, provisioned from files. | `127.0.0.1:8080` |

Generate every configuration file from the watchlist:

```bash
netrune traffic stack init
netrune traffic stack init --dir ~/netrune-metrics --retention 180d
netrune traffic stack show          # print without writing
```

The scrape interval is derived from the shortest watch interval, because
scraping more slowly than the collector polls throws away readings that were
actually taken.

### 21.9 Raw counters, rates at query time

The exposition publishes what the device reported and nothing else:

| Metric | Type | From |
| --- | --- | --- |
| `netrune_interface_receive_bytes_total` | counter | `ifHCInOctets` |
| `netrune_interface_transmit_bytes_total` | counter | `ifHCOutOctets` |
| `netrune_interface_receive_errors_total` | counter | `ifInErrors` |
| `netrune_interface_transmit_errors_total` | counter | `ifOutErrors` |
| `netrune_interface_receive_drops_total` | counter | `ifInDiscards` |
| `netrune_interface_transmit_drops_total` | counter | `ifOutDiscards` |
| `netrune_interface_speed_bits` | gauge | `ifHighSpeed` or `ifSpeed` |
| `netrune_interface_up` | gauge | `ifOperStatus` |
| `netrune_interface_admin_up` | gauge | `ifAdminStatus` |
| `netrune_interface_last_poll_timestamp_seconds` | gauge | the collector |
| `netrune_interface_watch_enabled` | gauge | the watchlist |
| `netrune_device_uptime_seconds` | gauge | `sysUpTime` |
| `netrune_icmp_rtt_seconds` | gauge | ping from the collector |
| `netrune_icmp_loss_ratio` | gauge | ping from the collector |
| `netrune_icmp_up` | gauge | ping from the collector |

No rate appears in the exposition. Throughput is `rate()` over the octet
counters in MetricsQL, which is also what makes a counter reset handle itself:
the database recognises the decrease and does not emit a spike. Netrune's own
`in_bps` samples still exist for `traffic show` and the offline report, and are
not what this endpoint serves.

Labels are `device`, `device_ip`, `interface`, `ifindex`, and `collector`. Every
series is bounded by the watchlist, so cardinality is what an operator asked
for rather than what a discovery sweep found.

`netrune_interface_up` and `netrune_interface_admin_up` are separate on purpose.
Operationally down while administratively up is a fault; both down is somebody's
decision. One gauge cannot tell those apart, and alerting on the wrong one wakes
people for shut ports.

### 21.10 The exposition endpoint

Netrune has no server. This endpoint is the single exception and is kept narrow:

- it binds `127.0.0.1` unless `--confirm` is given, because the exposition has no
  authentication and publishes the topology to whoever can reach it;
- it answers `GET` and `HEAD` on `/metrics` and `/health` and nothing else;
- it runs no command, reads no secret, and changes no state;
- it never contacts a device. The collector does that on its own schedule, and
  this only republishes what the collector already stored.

```bash
netrune traffic exporter                      # serve on 127.0.0.1:9713
netrune traffic exporter --once               # print the body and exit
netrune traffic exporter --bind 127.0.0.1:9714
```

### 21.11 Importing history collected before the stack existed

```bash
netrune traffic backfill                      # last 30 days
netrune traffic backfill --since 7d --dry-run
```

The history is rates Netrune computed at collection time; the raw counters
behind them were never retained. Reconstructing a counter by integrating those
rates would fabricate readings nobody took, so the history is imported under its
own names — `netrune_history_interface_receive_bits_per_second` and siblings —
as gauges. A derived value is never published under a measured value's name, and
a dashboard that mixes them says so by using two different metrics.

### 21.12 Alerting

Alerts live in vmalert, evaluated against stored data, so they fire whether or
not a browser is open. `netrune traffic stack init` generates rules for a
stopped collector, an interface that stopped being collected, an operationally
down port that is administratively up, sustained saturation above 85% of link
speed, sustained input errors, and unreachable or lossy ICMP targets.

Alerting on `netrune_interface_last_poll_timestamp_seconds` is what catches the
failure that otherwise looks like silence: a stopped collector leaves flat lines
rather than empty ones, because the exposition keeps serving the last reading it
has.

### 21.13 Choosing a grapher

The pipeline is grapher-neutral by construction. Netrune publishes Prometheus
exposition, VictoriaMetrics answers the Prometheus query API, and anything that
speaks it can draw the result. What differs between tools is only the dashboard
file format and how the tool is deployed, which is what an adapter supplies.

```bash
netrune traffic stack graphers                      # what is available
netrune traffic stack init --grapher grafana        # the default
netrune traffic stack init --grapher perses
netrune traffic stack init --grapher none           # vmui only
netrune config set traffic_grapher grafana          # make it stick
```

Switching graphers regenerates dashboards and the grapher's systemd unit.
`scrape.yml`, `alerts.yml`, and the collector, exposition, storage, and alerting
units are byte-identical whichever is chosen, which is the property that makes
the choice reversible.

| Grapher | Deployment | Queries reach storage via |
| --- | --- | --- |
| Grafana | `grafana/grafana` container on 3000 | its own server, proxied |
| Perses | `persesdev/perses` container on 8080 | the browser, `directUrl` |
| none | nothing to deploy | vmui, built into VictoriaMetrics |

That last column is not a detail. A grapher that proxies queries from its own
process resolves the storage URL *inside its container*, where `127.0.0.1` is
the container itself; Netrune rewrites it to `host.docker.internal` and adds the
matching `--add-host`. A grapher whose browser fetches directly resolves it on
the host, where `127.0.0.1` is right. Getting this backwards produces a
dashboard that loads and then shows nothing.

No grapher is given `--network host`. Under Docker Desktop that joins the Docker
VM's network namespace rather than the WSL distro's, and the published port is
unreachable from the host that needs it.

### 21.14 Adding a grapher

Implement the `Grapher` protocol in `netops_platform/traffic_graphers.py` and
add it to `GRAPHERS`. The dashboards themselves live in
`netops_platform/traffic_dashboards.py` as a neutral model -- panels, queries,
semantic units, variables -- and need no change. An adapter supplies:

| Member | Purpose |
| --- | --- |
| `files()` | Provisioning files, keyed by path |
| `container_mounts()` / `container_env()` / `container_args()` | How to run it |
| `resolve_datasource_url()` | Storage URL from the tool's own vantage point |
| `dashboard_url()` / `health_path()` | Where to open it, how to check it |

Semantic units are mapped per adapter: `bits_per_second` is `bps` in Grafana and
`bits/sec` in Perses, and neither spelling belongs in the shared model. The test
suite asserts that every adapter maps every unit, so a new grapher that forgets
one fails rather than rendering a blank axis.

### 21.15 Verifying the pipeline

```bash
netrune traffic verify
```

Checks run in the order data flows -- watchlist, collector, exposition, storage,
scraping, rate derivation, grapher -- so the first failure is the cause rather
than a symptom of something upstream.

```text
  ok    watchlist          4 active of 4 target(s)
  ok    collector          running as pid 52048
  ok    exposition         18 metric families on http://127.0.0.1:9713
  ok    victoriametrics    http://127.0.0.1:8428
  ok    scrape             VictoriaMetrics is scraping the exposition
  ok    rate derivation    3 interface series resolve to a rate
  ok    grapher            Grafana at http://127.0.0.1:3000
```

### 21.16 Remote pollers

SNMP and ICMP have to originate from the monitored network. A laptop does not
live there and moves; an always-on box on the LAN does. Netrune splits the two:
a poller collects, and any number of machines read what it collected.

```bash
# On the poller, once.
./scripts/poller-install.sh --collector-id site-a-poller --tailscale-authkey tskey-...

# On the laptop.
netrune traffic remote add site-a-poller --host 100.64.0.5 --ssh-user netrune
netrune traffic remote site-a-poller watch SITE-A-SW01 Gi1/0/16 --interval 30
netrune traffic pull --remote site-a-poller
netrune traffic show
```

Nothing new listens for this. Control rides SSH, which this project already
treats as an audited channel (ADR 0004), and the poller's exposition stays where
`traffic stack init` put it.

### 21.17 How the two halves stay distinct

`traffic_collector_id` is the only identity involved, and it was already stamped
on every reading before any of this existed. Three things follow from it:

- **Merging is safe.** Counter baselines are per collector, so a poller's
  readings are never differenced against this machine's.
- **A pull cannot duplicate.** Readings are keyed by collector, watch, metric,
  and second, so re-pulling an overlapping window after a dropped connection
  absorbs the overlap instead of storing it twice.
- **A pulled interface is never polled here.** It arrives owned by the collector
  that polls it, and the local scheduler only ever considers what it owns.
  Polling a device on someone else's network would produce failures that read
  as the device being down.

Two collectors sharing an id is the one thing that breaks all of this, so a pull
refuses outright when the remote's id matches the local one.

Output names the collector whenever it is not this machine:

```text
SITE-A-SW01 Gi1/1/1                     in_bps  ▃▅▃▄▃  now 29.92 Mbps
SITE-A-SW01 Gi1/1/1  @site-a-poller     in_bps  ▁▁▂▂▃  now 39.90 Mbps
```

Watching one interface from two vantage points is a reasonable thing to want.
Two identical labels for two different measurements is not.

### 21.18 Why rows rather than metrics

A pull could have scraped the poller's exposition instead. It does not, because
scraping returns metrics whose rate has already been computed, and the raw
counters behind them were never retained -- the same limitation `traffic
backfill` carries. Pulling stored rows keeps whatever the poller actually
recorded.

Both paths have a place. For live graphs, point the laptop's VictoriaMetrics at
the poller's exposition directly: raw counters, rates derived at query time, no
pulling involved.

```yaml
scrape_configs:
  - job_name: site-a-poller
    static_configs:
      - targets: ["100.64.0.5:9713"]
```

For terminal views, the offline report, and anything to be read while the
tailnet is unreachable, pull the rows.

### 21.19 Binding the exposition off loopback

A poller's exposition has to be reachable by the machine reading it, so the
install script binds it to the Tailscale address specifically -- not `0.0.0.0`,
which would also publish it to the LAN.

That is not loopback, and the exposition has no authentication of its own, so it
needs `--confirm`. A service cannot answer a prompt when systemd starts it, so
consent is taken once from whoever runs `traffic stack init` and carried into
the generated unit. `stack init` with a non-loopback bind and no `--confirm`
refuses rather than generating a unit that publishes the exposition with nobody
having agreed to it.

### 21.20 Installing the components

`victoriametrics-bin` and `vmutils-bin` are in the AUR. Grafana is in the
official repositories as `grafana`, and also runs as a container; Perses is
packaged for neither and is container-only. The generated `docker-compose.yml`
and systemd units leave the collector on the host, so no container ever needs
the SNMP or SSH credentials.

Grafana's first start installs its bundled plugins into an empty volume and can
take a couple of minutes before it answers. That is the container initialising,
not a failure.

VictoriaMetrics' own `vmui` answers queries as soon as it is running, so the
stack is useful before any dashboard exists.


---

### 21.21 Offline devices in a multi-device job

A device the last sweep could not reach costs a full SSH timeout -- about five
seconds -- before a job learns what the inventory already recorded. Any command
that spans more than one device skips those and says which:

```text
[WARN] Skipped 4 device(s) recorded offline: 198.51.100.2 198.51.100.8 198.51.100.40 198.51.100.93
[WARN] Add --include-offline to try them, or refresh with 'netrune inventory activity'.
```

Three rules make this safe to rely on:

- **A device named on its own is always attempted.** Naming it is how an
  operator asks whether it has come back. `--online-only` skips it anyway.
- **Unknown is not offline.** A target absent from the inventory has never been
  judged, so it is attempted.
- **`--include-offline` attempts everything**, for a sweep meant to find out
  what has recovered.

`netrune inventory activity` never skips, because it is the command that decides
the status everything else reads.

The equivalent selections on the Python side already worked this way:
`topology stp`, `lookup mac all`, and `lookup mac locate` all exclude recorded
offline devices before fanning out.

---

### 21.22 Workflow step outcomes

A step reports one of three things, and they are not the same:

| Status | Exit | Meaning |
| --- | --- | --- |
| `SUCCESS` | 0 | Ran, nothing to report. |
| `ATTENTION` | 3 | Ran, and found something worth looking at. |
| `FAILED` | anything else | Did not run, or could not finish. |

`health attention` exits `PARTIAL` exactly when it has findings, so a workflow
that treats every non-zero exit as a failure marks its most useful step red on
every healthy morning. An operator who sees that daily stops reading the
summary, which costs more than the step was worth.

`on_failure: stop` reacts to `FAILED` only. A step that found something is not a
reason to abandon the remaining steps.

`morning-check` refreshes LLDP/CDP topology before reviewing topology changes.
Reviewing recorded changes without scanning first reports the previous run's
picture. The scan is ordered after the reachability check so it has a current
status to skip unreachable devices by.

---

## 21A. Excel Workbooks

Netrune can keep the spreadsheets you already maintain in step with what it
has actually seen on the network, and can build a tracker workbook from
scratch. It runs entirely on the Linux box with openpyxl; nothing is sent
anywhere, and no switch is contacted.

### Install

The `netops`/`netrune` launchers run the system Python, so install openpyxl
there once:

```bash
sudo pacman -S python-openpyxl        # Arch; or: pip install 'netrune[excel]'
```

Without it every `netrune excel` command stops with that hint.

### Bring the inventory up to date first

The workbook can only be as current as Netrune's inventory. Run a scan (and
`netrune device inventory <target>` for switches that do not answer SNMP)
before syncing, so model, serial, and base MAC are fresh.

### See what Netrune would change

```bash
netrune excel inspect ~/Switches.xlsx
```

Netrune finds the header row on every sheet (title rows above it are fine),
works out which column is which from the header text -- `Device Name`,
`Switch`, `Hostname`; `Mgmt IP`, `IP Address`; `S/N`, `Serial Number`;
`MAC Address`, `Base MAC`; `Model`, `Hardware`; `Vendor`, `Manufacturer`,
`Make` (filled with the maker, e.g. `Cisco`); `Platform`, `OS` (netrune's
driver label, e.g. `Cisco IOS`) -- and
matches every row to one switch by serial, base MAC, IP, or hostname. The
report shows the columns it recognized, how many rows matched, every cell it
would change (old -> new and which keys matched), rows whose keys point at
different switches, and rows Netrune does not know.

If a column is not recognized, name it: `--map 'Asset Tag=serial,Mgmt Addr=ip'`
or by letter, `--map 'F=mac'`.

To work on one sheet only, name it with `--sheet`. Case and spacing do not
matter (`--sheet "spare stock"`), a number picks by position (`--sheet 2`; the
`inspect` heading numbers every sheet), and a comma list picks several
(`--sheet Switches,Spares`).

### Apply

```bash
netrune excel sync Switches.xlsx --dry-run      # same preview, nothing written
netrune excel sync Switches.xlsx --confirm      # apply
```

What happens on `--confirm`:

- The original is copied to the profile's `excel-backups/` folder.
- Empty cells are filled and out-of-date cells updated with Netrune's
  hostname, IP, manufacturer, model, serial, base MAC, and platform.
- Each written cell is shaded by how sure Netrune is of it (below).
  `--no-shade` leaves the fills alone; `--comments` also adds a note with the
  old value.
- Formula cells, every other column, and every other sheet are left as
  they are. MACs are written in the notation the column already uses, and
  names stay short if the column uses short names.
- The file is saved atomically and read back to check every written cell.
- An audit event is recorded.

Useful variations:

| Goal | Command |
| --- | --- |
| Only fill blanks, never overwrite | `--fill-only` |
| Rewrite whole columns from Netrune | `--refresh mac,serial` (or `all`) |
| Only one sheet | `--sheet Switches` (or `--sheet 2`) |
| Note what changed in the Remarks column | `--remarks` |
| Mark unused addresses "Free to use" | `--free-ips` |
| Only some columns | `--fields mac,serial,model` |
| Also write reachability | `--fields hostname,ip,model,serial,mac,platform,status,last_seen` |
| Add switches the sheet is missing | `--sheet Switches --add-missing` |
| Write a copy, leave the original alone | `--output ~/Switches-updated.xlsx` |
| Resolve rows whose name and IP disagree | `--prefer ip` (or `serial`, `mac`, `hostname`) |

Status is not written unless you ask for it: in most asset sheets "Status"
means *In service* / *In stock*, not online/offline.

### Confidence shading

The preview lists the least certain changes first, with a `confidence` and a
`why` column, and on `--confirm` each written cell is shaded to match:

| Shade | Confidence | When |
| --- | --- | --- |
| Green | certain | Row matched by serial or base MAC; or the same value only reformatted |
| Blue | strong | Matched by two keys that agree (name and IP); or a new row from `--add-missing` |
| Yellow | fair | Matched by one IP or name and filling a blank; or replacing a sheet serial/MAC that disagreed with the other keys |
| Tan | weak | Matched by one IP or name and overwriting a value |
| Red | doubtful | `--prefer` broke a conflict |

A switch Netrune has not heard from in 30 days (or never polled) drops every
cell one step (green to blue, blue to yellow, and so on; red stays red).
Green and blue cells need no second look; glance at yellow; read tan and red,
which a remark or note also marks `(verify)`. Earlier syncs' shading stays on
cells this run does not write.

The five fills were chosen to stay apart for colour-blind readers too (every
pair is at least 15 CIEDE2000 apart under deutan, protan, and tritan
simulation), and yellow, tan, and red get darker in that order, so a
greyscale printout still ranks them.

### Remarks

`--remarks` writes a short note on each row it touches into the sheet's
Remarks, Comments, or Notes column (a `Remarks` column is added at the end
when there is none). The notes read as yours, not as a tool's:

- `Renamed from OLD-NAME`, `Updated MAC and model`, `Added serial`, with
  `(verify)` when the change was low confidence;
- `Offline`, or `Last seen 2026-09-01` for a switch not heard from in 30
  days (these are refreshed every run, so they clear when it is back);
- `Check: IP is SW01, serial is SW02` when the row's keys disagree;
- `Duplicate of row 12` when one switch sits on several rows.

Anything already in the cell is kept, and the note is added after it.

### Free addresses

On an IP plan, `--free-ips` decides for every row with an IP whether the
address is free to use, and writes the answer into Remarks:

1. **Something Netrune knows is on it** (online, or seen before and offline
   now): not free. `In use (AP AP-LOBBY)`. If the row was empty, the device's
   name (and MAC, when known) is written into it: it is a real device the
   sheet did not have yet.
2. **Anything answers on it** (every address Netrune holds no device for is
   pinged, empty rows included): not free. `In use (answers ping)`.
3. **Used within the last 30 days:** not free. `Used by PLC-7 until 2026-10-17`.
4. **The row is empty** and nothing answered: free. `Free to use`, or
   `Free to use (was CAM-3 until 2026-04-02)` when something used it long ago.
5. **The row names something Netrune has never seen** and nothing answered:
   - Netrune asks you: `y` marks it
     `Free to use (old entry)`, `n` marks it `Allocated, offline` (spoken for,
     just off), Enter skips it.
   - Your answer stays in the remark, so you are not asked again.

```bash
netrune excel inspect ~/IP-Plan.xlsx --sheet "VLAN 20" --free-ips      # see the result first
netrune excel sync ~/IP-Plan.xlsx --sheet "VLAN 20" --free-ips --confirm
```

The report lists **Suggested for allocation**: empty rows first, then
addresses unused for a long time, then old entries you confirmed.

- Questions are only asked with `--confirm` in a terminal. Elsewhere (a
  preview, `--json`, a script) those rows are listed as awaiting you and left
  alone. Answer on the command line with `--accept-free 192.0.2.31,192.0.2.40`
  and `--reject-free 192.0.2.33`, or `all`.
- Each run checks again. A `Free to use` address that has since been taken
  becomes `In use (...)`.
- A remark that says the address is reserved, DHCP, a gateway, a VIP, or
  "do not use" is left alone.
- The ping is followed by plain TCP connects on the usual remote-access,
  Windows, camera, printer, and web ports. It never touches PLC protocols.
  Run it from a machine that is allowed to reach those subnets.
- Before checking, Netrune probes two addresses that cannot exist. A web
  proxy that answers port 80/443 for every address is detected that way:
  those ports are left out, and the report says so. If even ping answers for
  them (a VPN or NAT faking replies), `--free-ips` refuses to run.

### Refresh a whole column

`--refresh mac,serial` (or any fields, or `all`) rewrites those columns on
every matched row with Netrune's value:

- cells that already hold the same value in another notation are rewritten
  too, so the whole column ends up in one consistent form;
- `--fill-only` does not protect them;
- the refreshed columns do not decide which switch a row is, so a stale MAC
  copied from another row no longer turns the row into a conflict. Rows are
  matched by their other keys and only fall back to a refreshed column when
  they have nothing else.

```bash
netrune excel sync ~/Assets.xlsx --sheet Switches --refresh mac,serial --dry-run
```

Netrune refuses to save when:

- `~$Switches.xlsx` exists next to the file. That means the workbook is open
  in Excel, and saving from Excel afterwards would overwrite the update.
  Close it, or pass `--ignore-lock`.
- The workbook contains charts, images, pivot tables, slicers, or
  dynamic-array formulas, which openpyxl cannot carry through a save. Use
  `--output` to write a copy, or `--allow-feature-loss`.

`.xls` files must be saved as `.xlsx` first; `.xlsm` macros are kept.

### Reports

```bash
netrune excel report ~/netrune-reports.xlsx                    # every report, last 30 days of changes
netrune excel report ~/aps.xlsx --report active-aps,ap-history --since all
```

One workbook, one sheet per report. The first sheet, **Report Info**,
spells out exactly what each report lists, so nothing is left to
interpretation:

| Report | Sheet | What it lists |
| --- | --- | --- |
| `active-aps` | Active APs | APs online at the last check, with their model, switch, and port (switches hiding in the AP list are left out) |
| `active-switches` | Active Switches | Switches online at the last check |
| `transitions` | Transitions | Renames, IP changes, an IP now on another device, serial/model changes, AP moves |
| `switch-history` | Switch History | Every switch, online or offline, plus each switch replaced at the same name or IP |
| `ap-history` | AP History | Every AP, online or offline, plus each AP replaced at the same name |

A replacement is new hardware, not a relabel: a different serial (or, for
switches without one, a different MAC *and* model at once), or for an AP a
different MAC or model. A change that reverts later is treated as a misread
and left out.

`--since 30d` (the default), `12w`, `6m`, `2026-09-01`, or `all` sets how far
back the change rows go. An existing file is only replaced with `--confirm`,
and is backed up first.

A port on a neighbouring switch that used to see one switch or AP and now
sees another is the strongest sign of a replacement, even when the name and
the address both changed. Such swaps appear in Transitions:

- `Replaced at neighbour port` when the MACs differ;
- `Renamed (same MAC)` when they match;
- `Replaced or renamed (no MAC to compare)` until `ap neighbors` has learned
  the missing MAC.

The confident ones (the rest of that neighbour barely changed) also go into
the History sheets. The same evidence produces merge candidates for
`inventory merge` / `ap merge`.

### Build a tracker workbook

```bash
netrune excel export ~/network-tracker.xlsx
```

This creates three sheets:

- **Summary**: live counts of devices, online and offline, online %, not seen
  for 7+ days, and missing serials or MACs. Also per-model and per-platform
  counts, a chart by model, and migration progress (by status, % complete,
  overdue).
- **Inventory**: a filterable table of every switch, with Days Since Seen and
  free Site/Owner/Notes columns for you.
- **Migration Tracker**: rows with a device dropdown, automatic IP and
  current-model lookup, change-type and status dropdowns, planned and
  completed dates, and Days Overdue. Rows are coloured green when Done, red
  when Blocked, grey when Cancelled, amber when overdue.

Everything after the data is a formula, so the Summary keeps calculating as
you edit the tracker. To refresh the Inventory sheet later without touching
the tracker or your notes:

```bash
netrune excel sync ~/network-tracker.xlsx --sheet Inventory --add-missing \
  --fields hostname,ip,manufacturer,platform,model,serial,mac,status,last_seen --confirm
```

## 22. Local Interfaces

Netrune opens no listening socket. Every interface is a local process reading
the same SQLite state:

| Interface | Command | Notes |
| --- | --- | --- |
| Noun-first CLI | `netrune <domain> <action>` | Text, `--json`, and `--plain` output |
| Natural Ask | `netrune ask` | Stateful terminal session |
| Traffic collector | `netrune traffic daemon` | Long-running local process, no socket |
| Metrics exposition | `netrune traffic exporter` | The one listener, loopback and read-only |

### 22.1 Removed in this release line

The loopback HTTP server, the JSON API under `/api/`, the server-sent event job
stream, and the Vue browser console were removed along with their compiled
assets. `netrune serve` no longer exists.

The full-screen Textual console was removed after it, along with the headless
application service that existed to feed it and the Textual dependency. Every
operator interface is now the CLI.

What replaced each of them:

| Removed | Use instead |
| --- | --- |
| `netrune serve` and the browser console | The CLI directly |
| `netrune tui`, the Textual console | The CLI directly |
| `/api/*` JSON endpoints | Any command with `--json` |
| SSE job stream | `netrune jobs logs <job-id>` |
| Browser graphs | `netrune traffic show`, `netrune traffic report`, or the Perses stack |

The exposition endpoint added for the metrics stack is not a return of the API.
It serves collected readings on loopback and has no route that runs a command
or changes state. See 21.10.

The registry still records `run_supported` per command. It now governs whether a
command may run as a background job at all, rather than whether a remote client
may invoke it.

### 22.2 Machine-readable output

Every command accepts `--json` and writes one JSON document to stdout, with
progress and diagnostics on stderr. Stored timestamps are integer Unix epoch
seconds; human-facing output adds ISO 8601 UTC companions such as `created_at_iso`
and `last_seen_iso` without replacing the numeric fields.

```bash
netrune traffic show --json | jq '.series[] | select(.metric=="out_bps")'
netrune inventory list --json | jq '.rows[] | select(.status=="OFFLINE") | .hostname'
```

This is the supported integration surface. It is a local implementation
interface rather than a versioned public contract: inspect actual shape before
scripting against it.

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
netrune inventory scan 198.51.100.71 --dry-run
netrune inventory scan 198.51.100.71
netrune inventory details 198.51.100.71 --json
netrune ap scan
netrune topology scan
netrune topology neighbors --json
netrune memory refresh
netrune health attention
netrune backup run 198.51.100.71
```

### 23.2 Morning operations

```bash
netrune workflow morning-check
netrune health offline
netrune health attention
netrune topology changes --limit 50
netrune ap moves --limit 50
netrune jobs list --limit 30
```

Then classify each signal as current incident, stale-data artifact, expected change, or parser/source issue. Refresh only the affected domain before launching a broad deep scan.

### 23.3 Full observation refresh

For the broadest current picture:

```bash
netrune inventory scan
netrune ap scan
netrune topology scan
netrune memory refresh
netrune health attention
```

`workflow refresh-inventory` does not include the full switch inventory scan, so add it explicitly when device identity needs refresh.

### 23.4 Device reported offline

```bash
netrune health status --json
netrune diagnose latency <exact-ip> --count 10
netrune inventory details <exact-ip> --json
netrune memory device <exact-ip> --json
netrune topology neighbors <hostname> --json
netrune health timeline --limit 100
```

Decision path:

1. If ICMP works, investigate stale health import or ICMP target mismatch.
2. If ICMP fails but neighbors remain, check VLAN/routing/power and upstream port.
3. If topology link disappeared at the same time, inspect upstream device and cabling.
4. If many peers fail, treat it as a site/uplink event rather than one-device failure.
5. Do not run configuration changes until management reachability and recovery path are understood.

### 23.5 AP missing or offline

```bash
netrune ap list <name> --json
netrune ask "Show alternate names for <name>"
netrune ask "Where was <name> connected before?"
netrune ap unjoined <name>
netrune memory device <name> --json
netrune ap timeline <name>
netrune topology neighbors <switch> --json
```

Check whether the AP was filtered by WLC naming/IP rules, represented under an alias, unjoined, seen only by controller, or previously attached to another port.

### 23.6 Investigate an AP move

```bash
netrune ap moves --limit 100
netrune ap timeline <ap>
netrune memory device <ap> --json
netrune memory port <old-switch> <old-port>
netrune memory port <new-switch> <new-port>
netrune topology changes --limit 100
```

Validate both old/new source evidence and scan times. A naming merge can look like a move if source records changed concurrently.

### 23.7 Find an endpoint from IP or MAC

```bash
netrune memory ip 198.51.100.92
netrune lookup core 198.51.100.92
netrune memory mac 0200.0000.0025
netrune lookup mac CORE01 0200.0000.0025
```

Use memory first for historical/current cached evidence, then a live lookup for current switching state. Refresh memory afterward if you want the observation available to later questions.

### 23.8 VLAN investigation

```bash
netrune vlan locate <switch> 120
netrune vlan propagation <switch> 120
netrune device show <switch> "show interfaces trunk"
netrune topology neighbors <switch>
```

Before changing anything, verify vendor, target interface, intended access/trunk mode, existing native/allowed VLANs, spanning-tree implications, and out-of-band recovery.

### 23.9 Controlled VLAN change

```bash
netrune backup run <exact-switch-ip>
netrune vlan set <exact-switch-ip> Gi1/0/7 --access 120 --dry-run
netrune device show <exact-switch-ip> "show interface Gi1/0/7 switchport"
netrune vlan set <exact-switch-ip> Gi1/0/7 --access 120 --confirm
netrune device show <exact-switch-ip> "show interface Gi1/0/7 switchport"
netrune backup run <exact-switch-ip>
netrune backup diff <exact-switch-ip>
```

The command helper saves configuration automatically. Still verify startup/saved state through an approved read command.

### 23.10 Backup audit

```bash
netrune workflow backup-online ZONE10
netrune backup verify --limit 200
netrune health attention --limit 200
netrune backup history <critical-device>
netrune backup diff <critical-device>
```

Externally verify backup files, hashes, permissions, retention, off-host copy, and restore drills. Netrune metadata alone is not disaster recovery.

### 23.11 Filtering or interception investigation

```bash
netrune diagnose filtering example.com
netrune diagnose latency example.com --count 10
netrune diagnose filtering cloudflare.com
```

Compare multiple known domains and a known-good network. Preserve raw resolver, certificate issuer, proxy, and firewall context before concluding that a path is filtered or intercepted.

### 23.12 Database incident

```bash
netrune db status --json
netrune db integrity --json
netrune db path
```

Then stop writers, take a consistent backup, inspect disk/permissions, and use `db repair` only after preserving evidence. If integrity fails, prefer recovery from a known-good DB or SQLite recovery workflow over repeated mutation.

---

## 24. Security Model

### 24.1 Trust boundaries

Netrune crosses these boundaries:

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

- v8 configuration actions require preview or confirmation.
- Arbitrary generated config actions are preview-only.
- `device show` applies a read-only/sensitive-output policy.
- subprocess commands are represented as argument lists in the Python core rather than one shell string.
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
UserKnownHostsFile=<private Netrune known_hosts>
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

Direct `netrune-control config` and `netrune-control vlan` fail unless the core
provides its process-local audited-confirmation marker. Direct `show` enforces a
bounded read-only/diagnostic allowlist, argument-count validation, and
separator/secret blocking. File execution permissions are still useful defense
in depth, but the public `netrune` launcher is the supported policy boundary.

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
8. No network listener of any kind.
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
netrune --help
netrune db path
netrune db status --json
netrune db integrity --json
netrune health attention --json
```

Also record effective user, `HOME`, current command, target form, exit code, and whether output came from plain or JSON mode.

### 25.2 Unknown domain or old examples fail

Symptom:

```text
Unknown Netrune domain: probe
```

Cause: helper/legacy documentation uses the pre-v8 verb-first interface.

Use:

```bash
netrune diagnose latency <target>
netrune inventory scan <target>
netrune device ssh <target>
netrune backup run <target>
```

not `netrune probe`, `netrune discover`, `netrune connect`, or `netrune control`.

### 25.3 Verify the installed version

Use the central version command first:

```bash
netrune --version
netrune --help
netrune help --json
```

If these disagree, the launcher and sibling `VERSION` file came from different deployments. Reinstall the complete versioned directory rather than copying individual helpers.

### 25.4 A legacy helper asks for setup

Cause: a compatibility helper was invoked outside the profile environment or
under the wrong account. Exit instead of entering production values. Confirm
`netrune profile paths`, effective user, `HOME`, XDG variables, and the selected
profile, then run the public command. `netrune init` is the supported setup path;
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
netrune health check <exact-ip>
netrune inventory import-flat
netrune inventory details <exact-ip> --json
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
netrune vault status
netrune vault set
```

Verify `~/.ssh/sshpass_cache.gpg`, mode `0600`, `ssh_user`, `gpg`, `sudo`, and
`sshpass`. If status reports `legacy-gpg` and a graphical GPG dialog appears,
run `netrune vault migrate`; the legacy passphrase is requested once in the
terminal. If a sudo-gated vault reports `root_key: missing`, restore
`/etc/netrune/vault-keys/<uid>.key` from backup or use `netrune vault set` to
replace the vault with a known device SSH password. Root access cannot recover
GPG ciphertext after its random key has been lost.

If an older v8 build reports `A controlling terminal is required for secret
input` even though the command is running in an interactive terminal, update to
the current build. The helper now accepts its inherited terminal descriptor
when process-session isolation makes `/dev/tty` unavailable.

If `device ssh` reports that the SSH username is not configured, set the
non-secret profile value and validate it before touching the password vault:

```bash
netrune config set ssh_user operator
netrune config validate
```

### 25.10 SSH output is empty

Generic helper stderr is hidden unless `NETRUNE_SSH_SHOW_ERRORS=true`. Temporarily enable it for diagnosis, protect captured output, and check authentication, algorithms, prompt type, paging, command syntax, and Aruba wrapper resolution.

### 25.11 Aruba automation hangs or truncates

Check:

- `netrune_aruba_ssh.exp` exists beside the loaded `netrune-lib.sh` and is executable, or `NETRUNE_ARUBA_SSH_WRAPPER` names the intended executable wrapper;
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
netrune device config ... --dry-run
```

Review, then use `--confirm` only under an approved change.

### 25.14 Backup says unchanged

The SHA-256 equals the latest saved backup. This is expected changed-only behavior. Check history rather than looking for a new file.

### 25.15 Backup history is empty but files exist

Possible causes:

- shell helper wrote to a different SQLite default than `NETRUNE_SQLITE_DB`;
- operation ran as another user;
- old backups predate metadata;
- SQLite CLI was missing and record insertion was ignored;
- target resolved to another IP.

Compare `netrune db path`, default cache path, backup file owner, and exact device IP.

### 25.16 AP count seems too low

Canonical AP reconciliation intentionally merges aliases. Compare:

```bash
netrune db status --json
netrune ask "Which AP records were merged?" --json
netrune ap list --json
```

`ap_observations` versus canonical `aps` explains many count differences. Also check WLC filters and malformed observations.

### 25.17 AP count seems too high

Look for records without valid MAC/signature evidence, naming forms that do not normalize to the same location/AP number, conflicting valid MACs, and stale duplicate source rows. Conflicting physical MACs are intentionally kept separate.

### 25.18 Topology shows many removals

Do not assume a mass outage. Confirm the latest scan was complete and authenticated. Inspect `neighbor.db`, `topology neighbors`, scan logs, and source device reachability. A partial current set is compared against the full prior snapshot.

### 25.19 Memory has disappeared relationships

This means the latest derivation no longer found the relationship. It preserves historical evidence. Refresh source inventory/topology, inspect the relationship event's previous/current JSON, and evaluate source freshness.

### 25.20 Natural Ask gives no result

Use `netrune ask patterns`, provide an exact entity, inspect aliases, or name the public domain/action explicitly. Retrieval remains bounded to deterministic state workflows; operations remain bounded to the 95 registered actions. If a plan reports `needs_clarification` or `blocked`, supply the listed fields or honor the policy reason rather than trying to bypass it.

### 25.21 A monitored interface stops producing samples

Check:

```bash
netrune traffic list
netrune traffic interfaces <device>
netrune traffic poll --json | jq '.errors'
```

A watch whose `ifindex` is empty failed to resolve: the switch no longer reports
that interface name, usually because the port was renamed or the module was
removed. A watch that resolves but records nothing is answering SNMP with the
counters missing; confirm the community or v3 credentials reach that host.

Rates need two readings, so a freshly added watch shows no series until its
second poll. A gap in the middle of a series is a discarded interval: either the
counter was reset, or the device restarted between reads.

### 25.22 Job stays queued/running after restart

Starting a new job-owning core marks abandoned rows stale where applicable. A
dead TUI/server process cannot continue a job. Review logs and submit a fresh
safe job after understanding why the owner stopped.

### 25.23 Some diagnostics never gain structured history

`core-ping`, `speed`, `throughput`, `port-health`, `cable`, and `doctor` persist in their current-core workflows. Legacy continuous latency, filtering, and SNMP interface monitor paths can still finish with job logs but without the same unified record. Check `diagnostic_runs`, the specialized table, and the job log. Do not convert “no row” into a network pass/fail conclusion.

### 25.24 Internet speed cannot discover or complete servers

Run:

```bash
netrune diagnose doctor --online --json
netrune diagnose filtering speedtest.net
netrune diagnose speed --runs 2 --dry-run --json
```

Interpret common failures precisely:

| Symptom | Meaning/action |
|---|---|
| `CERTIFICATE_VERIFY_FAILED` | Required corporate/root CA is unavailable to the process; install it properly or use an approved `--ca-file` |
| `401 Authorization Required` | Proxy/filter/benchmark endpoint rejected the request; obtain approved authentication/policy or use controlled iperf3 |
| connection reset/read timeout | Retry once, check path/filtering, then stop treating the upstream service as reliable |
| fewer than two complete servers | Result is deliberately rejected; one server is insufficient for the reliable aggregate |
| high coefficient of variation/loss | Result is valid but low/medium confidence; investigate path load and retest |

Never add `-k`, disable hostname verification, or invent a speed from a partial download. Under WSL, Netrune imports trusted Windows roots securely, but it does not automatically inherit browser cookies or integrated gateway authentication.

### 25.25 Cable status says `NOT_RUN`

The read-only command found no previously stored TDR result. Preview a new test, verify that the exact port is copper and can tolerate interruption, then schedule/confirm it:

```bash
netrune diagnose cable <switch> on <port> --test --dry-run
netrune diagnose cable <switch> on <port> --test --confirm
```

For optical media, use optical diagnostics/DDM and link/error counters instead; Netrune refuses known fiber on the active AOS-Switch path. Use certified cable test equipment when a formal wiremap or category certification is required.

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
| TUI | Light and monochrome TUI snapshots pass |
| Generated docs | Registry-derived Markdown, man page, and Bash/Zsh/Fish completions have no drift |
| Packaging | Wheel/sdist build, metadata validation, isolated wheel smoke, checksums, SBOM, and provenance complete |
| Privacy | Source tree, clean public history, wheel, sdist, docs, completions, and AI files pass the private denylist and secret scan |

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
bash -n install.sh scripts/*.sh netrune-connect netrune-probe \
  netrune-discovery netrune-lib.sh netrune-control netrune-legacy
```

Add ShellCheck to CI even though it was not installed in the audited environment:

```bash
shellcheck netrune-connect netrune-probe netrune-discovery netrune-lib.sh netrune-control netrune-legacy
```

Expect needs at least parser/startup and mocked-session tests. Do not point automated tests at a real network by default.

### 26.4 Isolated CLI/database test pattern

Use an isolated environment:

```bash
export NETRUNE_CONFIG_DIR=/tmp/netrune-test/config
export NETRUNE_CACHE_DIR=/tmp/netrune-test/cache
export NETRUNE_SQLITE_DB=/tmp/netrune-test/cache/netrune.sqlite3
export NETRUNE_BACKUP_DIR=/tmp/netrune-test/backups
export NETRUNE_PROGRESS=0

./netrune db migrate --json
./netrune db status --json
./netrune db integrity --json
./netrune inventory list --json
./netrune commands list --json
./netrune ask patterns --json
```

For shell-backed tests, also set `HOME` to a fixture directory containing safe `~/.config/netsnmp/netsnmp.conf` and `.env`; Python overrides alone are not enough.

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

**`netrune/core.py`** owns public behavior. The root
`netrune_core.py` file is only its v8 compatibility alias:

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

**`netrune/identity.py`** owns physical identity rules. Keep identity
normalization pure and heavily tested. A change can merge or split production
AP history, which has a larger blast radius than a display-only change.

**`netrune/devices.py`** owns the device-family registry, detection precedence,
capability states, semantic command templates, paging, logout, and MAC format.
Core workflows request operations from this module instead of embedding vendor
commands.

**`netrune/ingest.py`** owns versioned channel observations, provider
delivery, provenance, idempotency, quarantine, and materialization.
**`netrune/inventory_ingest.py`** owns the non-destructive merge used
by compatibility shell observations. All discovery/controller providers must
enter one of these boundaries so a sparse source cannot erase richer state.

**`netrune/mac_registry.py`** owns the authoritative IEEE registry cache,
validation, atomic refresh, longest-prefix lookup, and provenance.

**`netrune/network.py`** owns pure vendor-neutral parsers for network output.
It must not open transport or write state.

**`netrune/ask.py`** owns deterministic language behavior. Every new
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
7. Add a `CommandSpec` if background job or workflow access is intended.
8. Implement `command_for_action` and argument normalization.
9. Add unit tests for success, validation, dry-run, JSON, and failure exit code.
10. Add parser fixtures for any vendor output.
11. Update the TUI only after registry behavior is stable.
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

### 27.8 Version consistency

Public launchers, package metadata, and help read the central `VERSION` file
(`8.5.0b3`). Historical helper comments may still describe adapter generations;
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

The secure speed workflow cannot force a third-party benchmark through a gateway that blocks the category, requires browser-integrated authentication, rewrites uploads, rate-limits discovery, or returns `401`. Netrune reports the failure and retains chronology but cannot produce a valid Internet-speed number without a completed path. Add an organization-approved authenticated proxy/backend or operate controlled external iperf infrastructure; never weaken TLS to make a benchmark pass.

### 28.2 P1: legacy diagnostic persistence remains incomplete

v8.5 beta directly persists core ping, Internet speed, throughput, port-health, cable, and doctor output. The legacy continuous latency, filtering, and SNMP interface monitor still do not all share one schema-validated insertion path. Unify those remaining actions into `diagnostic_runs` and retain specialized rows only as indexed projections.

### 28.3 Resolved in v8.5 beta: unauthenticated operational API

The loopback HTTP server could start network-read and local-write jobs with no
authentication or authorization, and `--host` allowed binding it beyond
loopback. The server, the API, and the browser console were removed rather than
secured, because a single-operator local tool has no need to listen.

### 28.4 Resolved in v8.5 beta: managed SSH host-key verification

All generic and prompt-aware adapters now use the private managed trust store.
The core provides status, scan, SHA-256-bound enrollment, forget, atomic mode
`0600` writes, and audit events. Changed keys fail closed. Deployments must still
move critical devices from compatibility `accept-new` to enrolled `strict`.

### 28.5 Resolved in v8.5 beta: direct helper write boundary

`netrune-control config` and `vlan` now deny execution without the core's internal
audited-confirmation marker. Direct show/VLAN/MAC input remains independently
validated. The marker is deliberately process-local capability plumbing, not an
operator flag.

### 28.6 Resolved in v8.5 beta: backup DB path override

Shell backup metadata now honors `NETRUNE_SQLITE_DB`, then `NETRUNE_CACHE_DIR`, before choosing the effective-UID default. Subprocess tests also verify private atomic backup files, safe device-derived names, and reuse of the real prior path for unchanged content.

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

### 28.13 Resolved in v8.5 beta: unbounded request bodies

The request reader that trusted `Content-Length` was removed with the HTTP
server. Nothing in the tree now reads an attacker-controlled length.

### 28.14 P1: no authenticated identity beyond local OS identity

Jobs record local actor/UID/session, reason, ticket, preview hash, typed
confirmation, action, command, result, and timing. That is sufficient for a
single-operator local tool and insufficient for a shared service. Any future
multi-operator deployment needs an authenticated identity and authorization
model before it is built, not after.

### 28.15 P2: helper command naming drift

The public core and compatibility launcher now share the central `VERSION` file and support `--version`. Some internal helper help/comments still expose historical adapter command names. Continue converging generated help around the public v8 noun-first interface and label helpers as internal.

### 28.16 P2: service deployment remains unpackaged

The Python package, locked environment, console entry point, helper scripts,
packaged stylesheet, migration guide, and doctor checks now exist. There is
still no system service unit, formal OS support declaration, automated state
backup hook, or authenticated shared-service deployment.

### 28.17 P2: shell library has source-time side effects

Sourcing `netrune-lib.sh` creates directories, touches cache files, and can launch an interactive wizard. Libraries should load definitions without mutating state; initialization should be explicit.

### 28.18 P2: history grows without pruning

`memory prune` is reserved/disabled. Jobs, logs, relationship events, identity history, health events, topology events, and backups need retention policies and archive strategy.

### 28.19 P2: topology rendering truncates large networks

Only the first 36 nodes and 80 edges are drawn. Labels are sliced to 18 characters. Large networks need filtering, search, clustering, layout algorithms, and explicit truncation notices.

### 28.20 P2: incomplete shell coverage

The automated suite covers identity, chronology, Ask retrieval/planning, every
public action family, registry previews/addressability, safety gates, operator
context, alias administration, AI delegation, secure paired speed-backend
contracts, synthetic Cisco/Aruba/RUCKUS VLAN/interface/cable parsers, IEEE MAC
registry caching, normalized ingest, driver registration, iperf JSON,
bounded traversal, core-ping/speed/port persistence, direct-PID descendant
cleanup, atomic vault/backup/trust behavior, direct-write denial, diagnostic
target extraction, optical-TDR blocking, MAC movement, dry-run isolation, job
repair/events/results, and v8 contracts. Real
firmware fixture libraries, active TDR, external benchmark policy variants,
backup restore, concurrent socket-level HTTP/SSE reconnect behavior,
accessibility, and browser end-to-end regressions remain incomplete.

### 28.21 P2: backup verification name overstates behavior

`backup verify` displays metadata rather than proving file hash/existence/restore quality. Implement verification or rename the action.

### 28.22 P2: refresh log can overstate success

Selected jobs suppress exceptions around flat-file import and then log `canonical state refreshed`. Make refresh outcome explicit and fail/partially fail the job when canonical synchronization does not complete.

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

1. Split network transport from parsing and expand sanitized fixtures.
2. Improve topology filtering, layout, large-data behavior, and historical diff.
3. Add operator RBAC and remote-safe deployment only if the operational need
   justifies its attack surface.
4. Generate the support matrix and fixture coverage report
   from shared driver metadata.
5. Add endpoint agents, gNMI provider lifecycle, syslog/trap ingest,
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
netrune                         # interactive TUI
netrune tui                      # shortest explicit TUI command
netrune tui --view inventory
netrune --no-tui                # no-argument CLI help
netrune --help
netrune help <domain> [action]
netrune db path
netrune db status --json
netrune db integrity --json
```

### Inventory and APs

```bash
netrune inventory scan [target]
netrune inventory list [pattern] [--status ONLINE|OFFLINE]
netrune inventory details <target> --json
netrune inventory activity --file targets.txt
netrune inventory import-flat
netrune inventory export-flat
netrune ap scan
netrune ap list [pattern]
netrune ap unjoined [pattern]
netrune ap on-switch <switch>
netrune ap moves
netrune ap timeline [ap]
```

### Topology, memory, health

```bash
netrune topology scan
netrune topology show [target]
netrune topology neighbors [target]
netrune topology changes
netrune memory refresh
netrune memory switch <switch>
netrune memory device <entity>
netrune memory ip <ip>
netrune memory mac <mac>
netrune memory port <switch> <port>
netrune memory timeline [target]
netrune memory explain [target]
netrune health check [target]
netrune health status
netrune health offline
netrune health attention
netrune health timeline
```

### Backups and safe device access

```bash
netrune backup run <target> [--redact-secrets]
netrune backup history <target>
netrune backup diff <target>
netrune backup verify
netrune device ssh [--legacy] <target>
netrune device trust-scan <target>
netrune device trust-enroll <target> --fingerprint SHA256:VALUE --confirm
netrune device trust-status [target]
netrune device support [target]
netrune device identity <first> <second>
netrune device show <target> "show ..."
netrune device inventory [target|--view]
netrune device config <exact-target> <commands...> --dry-run
netrune device config <exact-target> <commands...> --confirm
```

### VLAN, lookup, diagnostics

```bash
netrune vlan locate <target[,target...]> <vlan[,vlan|range...]> [--depth N]
netrune vlan propagation <target[,target...]> <vlan[,vlan|range...]> [--depth N]
netrune vlan propagation --target SW1 --target SW2 --vlan 10,20-22 --depth 1-10
netrune vlan propagation <targets> <vlans> --depth N --refresh-neighbors [--max-nodes N]
netrune vlan set <exact-target> <interface> --access <vlan> --dry-run
netrune vlan set <exact-target> <interface> --trunk <list> [--native N] [--replace] --dry-run
netrune lookup core <ip|mac>
netrune lookup mac inspect <mac>
netrune lookup mac locate <mac> [switch]
netrune lookup mac profile <mac> [switch]
netrune lookup mac history <mac>
netrune lookup mac vendor <mac>
netrune lookup mac online <mac> [--refresh]
netrune lookup mac registry status|refresh
netrune diagnose latency <target> [--count N]
netrune diagnose core-ping <target> [--core SWITCH] [--count N]
netrune diagnose speed [--profile quick|balanced|thorough] [--runs 1-5] [--ca-file PEM]
netrune diagnose throughput <iperf3-server> [--direction both|upload|download]
netrune diagnose port-health <device> on <interface> [--sample-seconds N]
netrune diagnose cable <device> on <interface>
netrune diagnose cable <device> on <interface> --test --dry-run|--confirm
netrune diagnose doctor [--online]
netrune diagnose filtering [domain]
netrune diagnose interface <device> on <interface> [--chart classic|histogram]
```

### Workflows, jobs, registry, ask, server

```bash
netrune workflow morning-check
netrune workflow refresh-inventory
netrune workflow backup-online [target]
netrune workflow site-health <target>
netrune workflow ap-audit
netrune jobs list
netrune jobs show <id>
netrune jobs logs <id>
netrune jobs cancel <id>
netrune commands list
netrune commands show <id> --json
netrune commands run <id> [args] --preview
netrune ask "question"
netrune ask patterns
netrune ask aliases
netrune traffic watch <device> <interface> [--interval SECONDS]
netrune traffic ping <target>
netrune traffic list
netrune traffic poll
netrune traffic daemon [--interval SECONDS]
netrune traffic show [target] [--since WINDOW]
netrune traffic report [target] [--since WINDOW] [--out PATH]
```

### Never normalize these shortcuts

```text
Do not routinely call netrune-control directly for writes.
Do not poll an interface you were not asked to watch.
Do not read a first traffic sample as a rate; the first round is a baseline.
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

**Job:** A TUI or long-running CLI operation tracked in SQLite and by the live core
instance that owns its supervised process group.

**Result envelope:** Versioned application result containing status, summary,
metrics, datasets, findings, provenance, raw evidence, and timing.

**Provenance:** Source, observation time, completeness, freshness, parser, and
driver metadata explaining where a result came from.

**Operator context:** Local actor, UID, session, reason, and ticket bound to a
job request. It is not a substitute for authenticated remote identity.

**Local write:** Changes cache, SQLite, logs, or backups without intentionally configuring a network device.

**Memory:** Netrune relationship current-state and event-history layer.

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

**v8 noun-first interface:** Supported `netrune <domain> <action>` public command model.

---

## Closing Operating Principle

Use Netrune as an evidence system: refresh the smallest necessary scope, inspect source and recency, compare canonical and raw observations, preview every write, and verify the network after execution. Mastery is not memorizing commands; it is knowing which layer produced an answer, what that layer can prove, what it cannot prove, and how to recover when the evidence is partial.
