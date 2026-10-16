# Netrune Complete Technical Reference

**Purpose of this document.** This is an internal, exhaustive reference to
how Netrune actually works, written for an AI assistant to load on
demand and answer precise questions about behavior, output shape, and
command combinations -- not a human-facing tutorial. Where the operator
handbook (`docs/NETRUNE_TOOLSET_HANDBOOK.md`) explains *how to use* the
tool, this document explains *exactly what happens* when you do: every
verb's internal decision sequence, every table's exact column list, every
JSON payload's exact keys, every exit code and what produces it, every
SQLite table touched, and the command combinations that accomplish real
goals. It is generated from and verified against the actual source, not
from the registry's human-facing descriptions alone. It will drift from the
code over time the way any doc can; when in doubt, the source file named in
each section is the ground truth, and this doc names exact file paths
specifically so that check is fast.

**How to use this file.** It's long by design -- point-lookup, not
read-front-to-back. Jump to a domain section for exact command behavior;
jump to "Cross-Domain Workflows" for goal-oriented command sequences;
jump to "Output Format System" to predict exactly what a command's output
will look like before running it. Use `grep -n "^## "` (or search for a
section's exact heading text below) to find where to `Read` with an
offset, rather than loading the whole file.

**Contents**

1. System Architecture -- process/dispatch shape, the `App` mixin
   composition, the `State` class, the command registry/generic execution
   engine, the guarded-configuration lifecycle (ADR 0005).
2. Global Flags Reference -- every flag `parse_global()` accepts, synonym
   groups, and per-command special cases.
3. Exit Codes -- the full `EXIT_CODE_HELP` table.
4. Output Format System -- the two-tier rich/plain renderer, status
   colors, key/value rendering, findings rendering, the interactive
   arrow-key device picker.
5. Data Model (SQLite) -- all 41 tables, categorized, plus the full
   retention-window defaults.
6. Cross-Domain Workflows -- the 5 built-in `netrune workflow <name>`
   recipes and 8 goal-oriented manual command-sequence recipes.
7. Device, VLAN, and Topology Domains -- `device`, `vlan`, `topology`
   (guarded config writes, SSH trust, VLAN cascade/locate, spanning-tree
   link derivation).
8. Lookup and Diagnose Domains -- `lookup` (core/MAC/IEEE-registry
   resolution) and `diagnose` (doctor, cable/TDR, port-health, speed,
   throughput, core-ping).
9. Traffic Domain -- the collector/poller model, SNMP polling, watches,
   dashboards, `traffic stack`/`export`/`push`/`pull`.
10. Inventory, AP, Memory, and Health Domains -- canonical inventory,
    manual device merges, AP reconciliation, relationship memory
    (`sync_derived_state`), flap-aware health tracking.
11. Backup, Vault, Secrets, DB, and Config Domains -- config backups, the
    SSH credential vault and named-secret store, database maintenance
    (`db prune`/`repair`/`vacuum`), profile configuration.
12. Meta and Orchestration Domains -- `ask` (natural-language retrieval
    and command planning), `commands` (generic registry executor),
    `setup`/`init`/`profile` (provisioning), `path` (forwarding-path
    inspection), `workflow`, `plugin`, `ingest`, `support`.

---

## 1. System Architecture

### 1.1 Process shape

Netrune is a single Python process per invocation -- there is no daemon,
server, or job queue in the core CLI (the traffic domain's collector is the
one long-running background process the tool manages, and it's a separate
`systemd` unit, not something `netrune` itself stays resident for). Every
`netrune <domain> <action> ...` invocation:

1. Parses global flags out of `argv` (`parse_global()` in `netops_platform/core.py`), producing a `GlobalOptions` dataclass and the remaining positional args.
2. Constructs one `App` instance (`netops_platform/core.py`), which wires up `Paths` (XDG-aware directory resolution), `Config` (profile config file), `State` (the SQLite layer), and `NaturalAskEngine` (the `ask` domain's NLU engine).
3. Calls `App.dispatch(argv)` (in `netops_platform/core.py`), which routes on the first positional argument (the "noun"/domain) to one of 26 `cmd_<domain>` handler methods via a flat dict, then that handler routes internally on the second argument (the "verb"/action).
4. The handler returns an integer exit code; `main()` propagates it as the process exit status.
5. In a `finally` block around the domain dispatch, `dispatch()` unconditionally calls `self.state.flush_inventory_exports()` -- any command that touched inventory owes the shell helpers (which read flat files, not SQLite) a refreshed export. No individual command has to remember to do this.

A handful of top-level special cases exist before domain routing:
`--version`/`version`, `-h`/`--help`, `help [domain] [action]`, and a hidden
alias: **`netrune ghoster <args>` rewrites to `netrune path inspect <args>`**
(in `App.dispatch`, `core.py`) -- a legacy/informal name for path inspection that
still works but isn't advertised in `netrune help`.

### 1.2 The `App` class: composed via mixins, not one god object

`App` used to be one ~7,200-line class holding all ~25 domains' logic
directly. It's now composed from mixin classes, one per larger domain, each
in its own file:

```
class App(
    DeviceCommandsMixin,      # netops_platform/device_cli.py
    InventoryCommandsMixin,   # netops_platform/inventory_cli.py
    VlanCommandsMixin,        # netops_platform/vlan_cli.py
    TopologyCommandsMixin,    # netops_platform/topology_cli.py
    LookupCommandsMixin,      # netops_platform/lookup_cli.py
    DiagnoseCommandsMixin,    # netops_platform/diagnose_cli.py
):
```

Every `self.foo(...)` call anywhere in the codebase resolves the same way
regardless of which mixin (or `core.py` itself) defines `foo` -- Python's
MRO doesn't care. This matters for reading the source: a method called from
`device_cli.py` might be *defined* in `core.py` if it's shared with another
domain (see "shared helper" callouts throughout this doc).

Three domains (`ask`, `setup`, `path`) are *not* mixins -- they're free
functions in their own files (`ask_cli.py`, `setup_cli.py`, `path_cli.py`),
each with a `dispatch(app, args, opts)` entry point, because unlike the six
mixin domains, nothing else in the codebase calls into their internals
directly (single caller boundary), so there was no MRO reason to keep them
as class methods. `App.cmd_ask`/`cmd_setup`/`cmd_path` are 2-line delegates:
`from netops_platform.X_cli import dispatch; return dispatch(self, args, opts)`.
The same pattern, established earliest, is used for `traffic` (`traffic_cli.py`).

The remaining 15 domains (`ap`, `backup`, `commands`, `config`, `db`,
`health`, `ingest`, `init`, `memory`, `plugin`, `profile`, `secrets`,
`support`, `vault`, `workflow`) are still directly in `core.py`'s `App`
class body -- they're individually small (10-150 lines each), so splitting
each into its own file would add file-count overhead without meaningfully
improving navigability; this was a deliberate scope decision, not an
oversight.

**Module map** (where to look for a given domain's actual logic):

| Domain(s) | File |
|---|---|
| device | `netops_platform/device_cli.py` |
| inventory | `netops_platform/inventory_cli.py` |
| vlan | `netops_platform/vlan_cli.py` |
| topology | `netops_platform/topology_cli.py` |
| lookup | `netops_platform/lookup_cli.py` |
| diagnose | `netops_platform/diagnose_cli.py` |
| ask | `netops_platform/ask_cli.py` (dispatch/CLI) + `netops_platform/ask.py` (NLU engine, `NaturalAskEngine`) |
| setup | `netops_platform/setup_cli.py` |
| path | `netops_platform/path_cli.py` (dispatch) + `netops_platform/path_inspector.py` (`PathInspector`, the real work) |
| traffic | `netops_platform/traffic_cli.py` (dispatch) + `traffic.py`/`traffic_stack.py`/`traffic_metrics.py`/`traffic_graphers.py`/`traffic_dashboards.py`/`traffic_report.py`/`traffic_sync.py`/`traffic_exporter.py` |
| ap, backup, commands, config, db, health, ingest, init, memory, plugin, profile, secrets, support, vault, workflow | `netops_platform/core.py`, directly on `App` |
| everything: shared infra, `State`, dispatch, command registry, output rendering | `netops_platform/core.py` |

### 1.3 `State`: the SQLite layer

One class (`netops_platform/core.py`, `class State:`), ~1,600 lines, 69
methods, one SQLite database per profile at
`Paths.sqlite_db` (XDG state dir). It was investigated as a decomposition
candidate alongside `App` and deliberately **not** split: one shared schema
script defines all ~40 tables in a single `executescript()` call, one
connection-lifecycle context manager (`State.connect()`) is used both
through generic `rows()`/`one()`/`execute()` helpers *and* raw by several
callers (`inventory_cli.py`, `ingest.py`, `path_inspector.py`), and
`sync_derived_state()` performs atomic cross-table reconciliation
(inventory-merge application, identity history, health, topology diff,
relationship sync) inside one transaction -- there's no clean seam to split
along without either breaking that atomicity or just relocating the
coupling into new files.

Roughly 30 of `State`'s 69 methods are generic plumbing used by every
domain (`rows`, `one`, `execute`, `execute_many`, `connect`, `migrate`,
`vacuum`, `repair`, `record_audit_event`, retention/pruning). Another ~15
are cross-domain orchestrators. Only about 20 are cleanly single-domain.

### 1.4 The command registry: `CommandSpec` and the generic executor

`command_registry()` (`core.py`, method on `App`) returns a list of 163
`CommandSpec` objects -- the single machine-readable source of truth for
every command's exact syntax, arguments, safety metadata, and examples.
This is what `scripts/generate_reference.py` reads to generate
`docs/reference/commands.md`, `docs/reference/command-registry.json`,
shell completions, and man pages -- and what `scripts/generate_reference.py
--check` verifies hasn't drifted from what's actually wired up. Every
`CommandSpec` carries: `id` (e.g. `"vlan-set"`), `domain`, `label`,
`description`, `command` (a template string), `args`/`arg_schema`,
`output_type` (`table`/`json`/`terminal`/etc), `read_only`, `risk_level`
(`safe`/`config`/`danger`), `safety_class` (effectively
`read-only`/`network-write`/`local-write`/etc), `state_effects`,
`writes_local`, `cancellable`, `preview_supported`, `run_supported`,
`timeout_seconds`, `examples`.

Two methods turn a `CommandSpec` + arguments into something executable or
previewable, and both are the *generic* path any registered action can go
through regardless of domain -- this is what `netrune commands run <id>`
and `ask`'s command-plan execution both use, as an alternative to calling
the noun-specific command directly:

- **`command_for_action(action, args)`** (in `core.py`) resolves an alias
  (`command_aliases()`), builds the exact `argv` for that action from its
  arguments (a `simple` dict of static-argv actions like `db-migrate` ->
  `["db","migrate"]`, plus per-action logic for anything needing real
  argument substitution -- e.g. `vlan-set` calls `self.vlan_change_request(args)`
  directly, which is why that method has to stay reachable via `self.` even
  though `vlan_cli.py` owns it), returns `(argv, read_only, writes_local)`.
- **`preview_for_action(action, args)`** (in `core.py`) wraps the above:
  computes missing required args, catches `PermissionError`/`ValueError` to
  fall back to a template-only preview, decides `blocked` (validation
  error, `risk_level == "danger"`, or `not run_supported`), and returns a
  rich preview payload (`ok`, `action`, `command` as a shell-joined string,
  `missing_args`, `blocked`, `reason`, `risk_level`, `safety_class`,
  `run_supported`, `requires_confirmation`). This is exactly the shape
  `ask`'s `command_plan` field carries, and what `netrune commands preview
  <id>` shows.

Config-changing (`risk_level == "config"`) actions are blocked from
`run_supported` execution through this generic path in some contexts
(Ask/API) -- reviewing the preview and running explicitly via the
noun-specific CLI command with `--confirm` is the only way to actually
apply a config change; the registry path can describe it but a defined set
of action IDs (`device-config`, `memory-prune`, `ask-chat`,
`commands-run`, plus `serve-run` kept as defensive code though the action
itself no longer exists) are explicitly blocked from ever executing via
`command_for_action` regardless.

### 1.5 Guarded configuration lifecycle (ADR 0005)

The pattern every config-changing action in this tool follows: **preflight
-> backup -> apply -> verify -> audit**. `apply_vlan_change` (`vlan_cli.py`)
is the canonical implementation; `apply_device_config_change`
(`device_cli.py`) extends the same pattern to arbitrary `device config
--confirm` commands. Concretely: capture a changed-only backup before
touching anything (abort with no changes if the backup itself fails),
apply the change, capture a second changed-only backup afterward and
compare to prove the running configuration actually changed rather than
trusting a clean subprocess exit code, then call
`self.state.record_audit_event(...)` with the outcome either way. A form
that changed since a preview was generated invalidates that preview (the
preview is bound to a hash of the exact normalized arguments). See each
domain's own section for which specific actions implement this.

---

## 2. Global Flags Reference

Parsed by `parse_global()` (in `netops_platform/core.py`) before domain routing; not every
flag applies to every command (a flag with no effect for a given command is
silently ignored, not an error).

| Flag | Effect |
|---|---|
| `--json` | Machine-readable output; bypasses all table/text rendering entirely (`emit()` short-circuits straight to `json_dumps(data)`). No ANSI, no partial text -- either full JSON or nothing from this flag. |
| `--plain` | Forces the plain-text rendering tier (see Output Format System) even on an interactive color-capable terminal. Also sets `NO_COLOR=1` in the process environment as a side effect, so it propagates to spawned helper subprocesses too. |
| `--no-color` | Suppresses ANSI color specifically (structure/tables still render, no box-drawing difference from `--plain` currently since both collapse to the same plain-text path). Also sets `NO_COLOR=1`. |
| `--dry-run` | Preview a state-changing command without applying it. Universally supported wherever a command can mutate state. |
| `--confirm` (aliases: `--approve`, `--yes`) | Explicit permission for a guarded state-changing command to actually apply. Also sets `NETRUNE_CORE_WRITE_REQUEST=audited-confirmation` in the child environment for any spawned helper. |
| `--execute` (alias: `--run-plan`) | Tells `ask` to actually execute a ready command plan rather than just preview it (still needs `--confirm` too for anything that isn't read-only). |
| `--limit N` | Row limit for list/history/timeline-shaped commands. Default 100. |
| `--since WHEN` | Time-window filter where supported. |
| `--status STATUS` | Status filter (commonly `ONLINE`/`OFFLINE`) where supported; normalized via `norm_status()`. |
| `--site SITE` | Site/location filter where supported. |
| `--source SRC` | Source filter where supported. |
| `--timeout N` | Per-command subprocess timeout in seconds. |
| `--workers N` | Concurrency hint for commands that parallelize (default 20, clamped 20-200). |
| `--depth N` | Max hop count for bounded path/VLAN traversal (0-16). |
| `--max-nodes N` | Hard node budget for recursive traversal (default 64, max 256). |
| `--refresh-neighbors` | Query live LLDP/CDP during traversal instead of relying only on cached topology. |
| `--first` | Resolve an ambiguous target to its first match, where supported. |
| `--all` | Resolve an ambiguous target to all matches, where supported. |
| `--interactive` | Allow interactive resolution where supported (see the `device ssh` arrow-key picker, section 6). |
| `--profile NAME` | Use one isolated profile for this invocation without changing the active default profile. **Special case:** `diagnose speed` has its own local `--profile` argument (a speed-test performance profile, unrelated to the state profile); `parse_global` detects `diagnose speed` or `commands run diagnose-speed` as the command path and lets that local `--profile` pass through untouched instead of being consumed as the global state-profile selector. |

---

## 3. Exit Codes

Every command returns one of these integers. `EXIT_CODE_HELP` in `netops_platform/core.py`:

| Code | Name | Meaning |
|---|---|---|
| 0 | `SUCCESS` | Completed as expected. |
| 2 | `USAGE` | Malformed invocation (unknown domain, bad flag combination at the parse level). |
| 3 | `PARTIAL` | Completed but with a caveat (e.g. some rows failed, a change applied but verification was inconclusive). |
| 4 | `UNREACHABLE` | A device/network target could not be reached. |
| 5 | `UNSUPPORTED` | The operation isn't supported for this device/driver/context (e.g. a config write on a driver without write support). |
| 6 | `VALIDATION` | Input failed validation (bad argument, ambiguous target, missing required value). This is what `usage_error()` returns by default. |
| 7 | `CONFIRM_REQUIRED` | The action needs `--confirm` (or `--dry-run` to preview) and wasn't given it. |
| 8 | `AUTH` | Authentication/credential failure. |
| 9 | `TIMEOUT` | A subprocess or network operation exceeded its timeout. |
| 10 | `INTERNAL` | An unhandled exception was caught by `dispatch()`'s outer `try/except Exception` and reported generically. |
| 130 | (interrupted) | `KeyboardInterrupt` (Ctrl+C) during dispatch. |
| 143 | (terminated) | Process received SIGTERM. |

---

## 4. Output Format System

Every command's non-JSON output goes through `App.emit(data, opts, text=None)`
(`core.py`): clears any in-flight progress line, then prints
`json_dumps(data)` if `opts.json`, else the explicit `text` string if the
caller built one, else `self.render_plain(data)` as a fallback.

### 4.1 Two rendering tiers, chosen automatically

`App._color_enabled(stream=None)` decides: `False` if `NO_COLOR` is set in
the environment (which `--plain` and `--no-color` both set), else
`stream.isatty()` (defaults to `sys.stdout`; `usage_error` passes
`sys.stderr` explicitly, since it prints there -- **stdout and stderr are
checked independently**, so `command 2>error.log` with stdout still a
terminal won't leak ANSI codes into the log file).

- **Plain tier** (the fallback, and what every automated/piped/tested
  context gets automatically, since `pytest` and pipes are never a tty):
  hand-rolled fixed-width text table. Header row uppercased, a dashed
  separator line, columns capped at `min(32, max(header_len, longest_value))`
  characters wide, longer values truncated with `...`. Zero ANSI codes ever.
- **Rich tier** (interactive terminal, color enabled): real `rich.table.Table`
  with `box.SIMPLE_HEAD` (a header rule, no side/corner borders --
  deliberately not a heavier boxed style), bold headers, and semantic color
  on any cell whose value exactly matches a known status word (see 4.2).
  Column widths are computed with the *same* algorithm as the plain tier
  (not rich's own auto-negotiated fit-to-terminal squeeze, which was found
  to starve short columns like `IP`/`STATUS` toward nothing whenever a long
  column like `NAME` was also present) and rendered at exactly that
  measured content width rather than the detected terminal width, so a
  narrower terminal soft-wraps the line rather than the columns getting
  unevenly squeezed.

### 4.2 Status-word coloring

`STATUS_STYLES` (`core.py`), applied to any table cell whose
stripped-uppercased value exactly matches (not substring -- a hostname
containing "PASS" won't trigger this), regardless of which column it's in:

- **Green:** `ONLINE`, `PASS`, `SUCCESS`, `OK`, `COMPLETE`
- **Red:** `OFFLINE`, `FAIL`, `FAILED`, `FAILURE`, `ERROR`, `CRITICAL`, `BLOCKED`, `UNREACHABLE`
- **Yellow:** `WARN`, `WARNING`, `ATTENTION`, `PARTIAL`, `UNSUPPORTED`, `DEGRADED`, `FLAPPING`, `CONFIRM_REQUIRED`

### 4.3 Other rendering helpers

- **`render_plain(data)`**: dispatches a list-of-dicts or a dict with a
  `"rows"` key to `render_table`; a plain dict (no `rows`) renders as a
  two-column key/value table in the rich tier (`_render_kv`, no box, bold
  left column) or `key: value` lines in the plain tier.
- **`render_findings(rows, empty="No findings.")`**: not a table -- a
  heading-per-finding text block (`SEVERITY  CODE  DEVICE  INTERFACE` then
  an indented message line), with the severity word colored
  (`critical`/`error`->red, `warning`->yellow, `info`->blue) in the rich
  tier via `rich.style.Style.parse(...).render(...)` rather than a full
  Table (lighter-weight for a single colored word). Used by `path`
  findings output.
- **`usage_error()`** and **`cmd_help()`** apply the same rich-tier styling
  to their section labels (`Error:`/`Try:`/`Usage:`/`Examples:`/`Help:` for
  errors; `Usage:`/`Domains:`/`Actions:`/etc for help) -- bold labels, red
  `Error:`, cyan `Try:`, dim `Help:`. Both fall back to identical plain text
  in the plain tier, and neither ever touches the underlying message
  *content*, only styling around fixed labels -- so this doesn't affect
  `scripts/generate_reference.py --check`'s drift detection, which reads
  registry data, not rendered output.

### 4.4 Interactive device picker

`App._select_row(rows, opts, *, label, prompt)` (`core.py`): a generic
arrow-key picker over an ambiguous match set, used today by `device ssh`
when a target resolves to multiple candidates. Reads raw keypresses off
`stdin` in `termios` cbreak mode (no new dependency) -- Up/Down to move,
Enter to pick, `q`/Esc/Ctrl+C to cancel. Returns `None` immediately (no
prompt shown, no hang) unless `stdin` and `stdout` are both a real tty and
neither `opts.json` nor `opts.plain` is set -- so piped/scripted/tested
invocations get the exact pre-existing pass-the-raw-text-through behavior,
unchanged.

---

## 5. Data Model (SQLite)

One database per profile (`Paths.sqlite_db`), ~40 tables, defined in one
`SCHEMA` script (`core.py`) executed via `State.init_db()`. Never manually
migrated table-by-table -- `netrune db migrate` re-runs the whole script
(idempotent `CREATE TABLE IF NOT EXISTS`) plus a few legacy-column repair
passes.

**Current-state tables** (not pruned -- they hold the latest known state,
not history): `devices`, `aps`, `neighbors`, `settings`, `schema_meta`,
`topology_snapshot`, `ingest_channels`, `traffic_counters`,
`traffic_remotes`, `traffic_watch`, `ask_aliases`.

**Provenance tables** (deliberately never pruned, by design -- append-only
evidence trails, not diagnostic noise): `audit_events`, `observations`,
`observation_fields`, `inventory_merges`, `relationships_current`.

**History/log tables with a retention window** (`RETENTION_DEFAULTS` in `netops_platform/core.py`, enforced by `netrune db prune`):

| Table | Days | Table | Days |
|---|---|---|---|
| `core_lookup_cache` | 7 | `command_history` | 90 |
| `traffic_counter_log` | 7 | `diagnostic_runs` | 90 |
| `job_logs` | 14 | `path_runs` | 90 |
| `probe_results` | 30 | `scan_runs` | 90 |
| `interface_samples` | 30 | `ingest_runs` | 90 |
| `filtering_checks` | 30 | `speed_tests` | 90 |
| `observation_rejects` | 30 | `topology_events` | 90 |
| `traffic_samples` | 180 | `ap_move_events` | 90 |
| `health_events` | 180 | `backup_history` | 365 |
| `relationship_events` | 180 | `inventory_history` | 365 |

Any table's window can be widened/narrowed per-profile via `netrune config
set <table>_retention_days N` (traffic tables share one
`traffic_retention_days` setting instead of per-table). `retention_days()`
(`core.py`) floors at 1 day regardless of configured value.

**Remaining tables** (`capability_evidence`, `health_state`,
`inventory_identity_state`, `jobs` [legacy schema kept, nothing writes to
it since the jobs domain's removal], `path_findings`, `path_hops`) are
covered in their owning domain's section below.

---

## 6. Cross-Domain Workflows

### 6.1 Built-in multi-step workflows (`netrune workflow <name>`)

Five predefined workflows exist, each a fixed sequence of real `netrune`
subcommands run in-process via `self.capture_streamed()` (`core.py`,
`workflow_manifest()` + `cmd_workflow`). Each step's `on_failure` is either
`"continue"` (default) or `"stop"`. A step's JSON `--json` output is parsed
if possible to extract a `summary`/`status`/`answer` field for the
headline; otherwise cleaned raw stdout/stderr is used, truncated to 500
chars. Overall workflow status: `FAILED` if a stop-on-failure step failed,
else `PARTIAL` if any step failed (non-stopping), else `ATTENTION` if any
step exited `PARTIAL` itself (health checks reporting real findings are
*not* a failure -- that's the point of running them), else `SUCCESS`.

- **`netrune workflow morning-check`** (no target) -- 7 steps: `inventory
  import-flat` -> `health check` -> `topology scan` -> `memory refresh` ->
  `topology changes` -> `diagnose filtering google.com` -> `health
  attention`. Order matters: reachability runs before the topology scan so
  the scan can skip devices already known offline; the topology-changes
  review runs after the scan so it reflects this run's fresh data, not
  yesterday's.
- **`netrune workflow refresh-inventory`** (no target) -- 5 steps: `health
  check` -> `ap scan` -> `topology scan` -> `memory refresh` -> `health
  attention`.
- **`netrune workflow ap-audit`** (no target) -- 4 steps: `ap scan` ->
  `memory refresh` -> `ap moves` -> `health attention`.
- **`netrune workflow backup-online <target>`** (target required) -- 1
  step, `on_failure: stop`: `backup run <target>`.
- **`netrune workflow site-health <target>`** (target required) -- 3
  steps: `diagnose latency <target> --count 5` -> `diagnose filtering
  <target>` -> `health status <target>`.

`netrune workflow list` shows all five with their description.
`netrune workflow <name> --dry-run` shows the exact step commands without
running them.

### 6.2 Goal-oriented recipes (not built-in workflows, but the natural command sequence)

These aren't single commands or registered workflows -- they're the
command *sequences* that accomplish a real operator goal, cross-referencing
multiple domains. `netrune ask "<question in plain English>"` can often
shortcut these (see section on `ask` below) by routing straight to the
right retrieval intent or command plan, but knowing the manual sequence
matters when the goal needs a decision partway through (an ambiguous
target, a choice between cached vs. live data) or when composing a script.

**Find where a MAC address physically is, right now:**
`netrune lookup mac-locate <mac>` (live forwarding-table search across
known switches) -> if you need vendor context, `netrune lookup mac-vendor
<mac>`; if you need history, `netrune lookup mac-history <mac>`; for deep
per-port evidence once you know the switch/port, `netrune lookup
mac-profile <mac> --port <port>` (or the target the locate step returned).

**Investigate whether a device is actually down vs. just stale in cache:**
`netrune health status <target>` (cached health state) -> `netrune diagnose
latency <target>` (live reachability probe) -> if unreachable and it's a
switch with neighbors, `netrune topology show <upstream-neighbor>` to see
if the *path* to it is the problem, not the device itself.

**Safely change a VLAN assignment:**
`netrune vlan set <target> <interface> --access N --dry-run` (preview: the
guarded lifecycle's exact plan, including the preflight/backup/apply/verify
phases it will run) -> review the preview -> `netrune vlan set <target>
<interface> --access N --confirm` (now actually preflight-captures,
backs up changed-only config, applies, re-captures to verify the running
config changed, and records an audit event either way). Never skip straight
to `--confirm` without having seen the `--dry-run` preview first for a
change you haven't run before -- the preview is what shows you the exact
resolved target and command before it's bound to an approval hash.

**Push an arbitrary (non-VLAN) config change safely:**
`netrune device config <target> "<command>" --dry-run` -> review -> `netrune
device config <target> "<command>" --confirm` (goes through
`apply_device_config_change`'s own preflight/backup/apply/verify/audit
lifecycle, the same shape as VLAN changes, added specifically because
arbitrary config pushes used to have a materially weaker guardrail than
`vlan set` despite being the more dangerous operation).

**Onboard a newly discovered device into inventory:**
`netrune inventory scan` (or `device inventory <target>` for one device) ->
`netrune inventory list <pattern>` to confirm it landed -> if it's a
duplicate of an existing historical record (renamed/re-IP'd hardware),
`netrune inventory merge <old> <current> --reason "..." --dry-run` then
`--confirm`.

**Set up a new poller or local collector machine, end to end:**
`netrune setup poller --community <snmp-community> --watch
<address>:<interface> --confirm` (or `setup local` for a combined
collect+store+dashboard machine) -- this single command runs the full
provisioning sequence itself (profile, identity, SNMP credential, database
init, stack generate+start, linger check); no manual multi-step sequence
needed. Follow with `netrune traffic watch <address> <interface>` for any
additional links beyond what `--watch` already registered, and `netrune
traffic dashboard` to view collected data.

**Full daily health sweep, human-readable:**
`netrune workflow morning-check` covers this in one command (see 6.1). The
manual equivalent, if you want to stop and inspect between steps, is the 7
sub-steps listed there run individually.

**Diagnose a suspected physical cabling problem:**
`netrune diagnose port-health <target> <interface>` (CRC/error counters,
negotiation) -> if inconclusive and the driver supports it, `netrune
diagnose cable <target> <interface>` (TDR test -- this is
`requires_confirmation`/guarded since it can briefly disrupt the link; run
with `--dry-run` first).

**Confirm the tool itself is correctly set up before relying on it (new
install, new machine, or after any environment change):**
`netrune diagnose doctor` -- one command, full readiness sweep (binaries
present, ICMP capability, SSH vault state, SQLite integrity, scan limits,
SSH trust store, helper-copy freshness). Run this first when something
seems wrong before assuming it's a network problem rather than a local
environment problem.

---


## 7. Device, VLAN, and Topology Domains


Source verified against: `netops_platform/device_cli.py` (`DeviceCommandsMixin`), `netops_platform/vlan_cli.py` (`VlanCommandsMixin`), `netops_platform/topology_cli.py` (`TopologyCommandsMixin`), and cross-referenced against shared helpers in `netops_platform/core.py`, driver definitions in `netops_platform/devices.py`, and `docs/adr/0004-managed-ssh-host-trust.md`, `0005-guarded-configuration-lifecycle.md`, `0006-job-and-audit-lifecycle.md`. Registry scaffold: `/tmp/registry_group1_device_vlan_topology.json`.

Global exit-code constants (`netops_platform/core.py:171-180`): `SUCCESS=0, USAGE=2, PARTIAL=3, UNREACHABLE=4, UNSUPPORTED=5, VALIDATION=6, CONFIRM_REQUIRED=7, AUTH=8, TIMEOUT=9, INTERNAL=10`. `run_subprocess`/`capture`/`run_vault_interactive` can additionally return `130` (SIGINT) or `TIMEOUT`/`UNSUPPORTED` from their own exception handling (timeout expired, or the helper binary is missing from `PATH`).

---

### DEVICE DOMAIN

#### `netrune device config` (id: `device-config`)
- **Purpose:** Send one or more configuration-mode commands to one device or a batch of devices: a preview under `--dry-run`, or the guarded backup/apply/verify lifecycle under `--confirm`.
- **Exact syntax:**
  - Single/inline: `netrune device config <target[,target...]> <command> [<command> ...] (--dry-run | --confirm)`
  - Batch: `netrune device config [--file devices.txt] [--target T ...] <command> [<command> ...] (--dry-run | --confirm)`
  - Options (any position): `--file F`, `--target T`/`--device T` (repeatable, comma lists allowed), `--commands-file F`, `--skip-offline`, `--skip-unverified`, `--danger-skip-verification`, `--cisco`/`--aruba`/`--ruckus` (vendor filter; combinable).
  - Parsing (`device_cli.py`, `cmd_device`, `verb=="config"`): when neither `--file` nor `--target` is given, the **first positional is the target spec** (comma-split) and every later positional is a command. When either is given, **every positional is a command**. `--file` lines are one target each (blank lines and `#` comments ignored); file targets come first, then `--target` values; exact-duplicate strings collapse. Any other token starting with `--` (a typo, or `--file` with no value) → `USAGE`(2) `"Unknown device config option (or missing value): …"` — it is never forwarded to the device as a config line.
- **Arguments:**
  - Targets (≥1) — hostname, IP, or alias; each must resolve to exactly one inventory device (`resolve_device_record`).
  - Commands (≥1) — inline, or `--commands-file` (one per line; mixing both → `VALIDATION`). Raw config-mode lines; no content allow-list (unlike `device show`), which is why the whole path is confirm-gated.
  - Missing target/commands → `USAGE`(2). Missing/empty `--file` or `--commands-file` → `VALIDATION`(6).
- **Routing:** `--file`, more than one target, `--skip-unverified`, `--skip-offline`, or any vendor flag → `apply_device_config_batch` (even for one target). Otherwise the single-device path.
- **Gate (`_device_config_gate`, both paths):** target must resolve (else unresolved); preview requires a built-in driver with `capability("configuration")` in `{supported, firmware-gated}`; `--confirm` additionally requires `device_writes_enabled` and, for a `firmware-gated` driver, certified firmware (built-in `firmware_profiles`, or operator `device_certified_firmware` / `device_certified_firmware_min`). `--danger-skip-verification` bypasses only the firmware check and is forwarded to `netrune-control config` as `--skip-verification` (the command-stream layer enforces certification independently). Cisco IOS/NX-OS and Aruba AOS-S/AOS-CX drivers are `supported`.
- **Batch behavior (`apply_device_config_batch`):**
  1. Gate every target up front. Targets resolving to the same device IP (hostname + IP, or two names identity-reconciled to one device) run **once**.
  2. Vendor filter (`--cisco`/`--aruba`/`--ruckus`): resolved devices whose `driver_family` prefix (`cisco-*`, `aruba-*`, `ruckus-*`) isn't one of the requested vendors are removed **before** the approval gate, so an unapproved off-vendor switch in the list can't refuse the batch. They're reported as filtered (reason `vendor filter: <family> is not <vendors>`) and **don't** make the exit `PARTIAL`. Unresolved targets aren't filtered (no family to judge) and go through step 3. Nothing left after filtering → `VALIDATION`(6). The filter uses detected family, so a device detected as `unknown` (e.g. a platform string detection doesn't recognize) is filtered out by every vendor flag; check with `netrune device support <target>`.
  3. Default: any unresolved target → `VALIDATION`(6); any unapproved → `UNSUPPORTED`(5); nothing touched. `--skip-unverified`: those are excluded and reported as skipped instead.
  4. `--skip-offline`: every remaining device is pinged in parallel (`self.ping`, same check as `inventory activity`; `--workers` bounds concurrency, default 20) and non-responders are skipped with reason `offline: no ping reply from <ip>`. Live ping, not stored inventory status. Runs on `--dry-run` too, so the preview lists exactly what a real run would touch.
  5. Nothing left → `UNREACHABLE`(4) if every skip was offline, else `UNSUPPORTED`(5).
  6. `--dry-run` → preview table (`target, ip, commands`) plus skipped and filtered tables; `SUCCESS`, no SSH.
  7. `--confirm` → one vault session; devices run **serially** through `_run_guarded_device_config_change`; a runtime failure on one device doesn't stop the rest.
- **Guarded lifecycle (`_run_guarded_device_config_change`, per device):** Phase 1 **backup** (`netrune-control backup <ip> --online-only --changed-only --summary`; non-zero → `BLOCKED`, nothing applied). Phase 2 **apply** (`netrune-control config <ip> <cmds…>`; non-zero → `FAILED`). Phase 3 **verify**: 2 s settle, re-run the backup; on SSH failure wait 4 s and retry once. Verify rc≠0 → `UNVERIFIED` (applied, but couldn't reconnect to confirm — not evidence of failure); rc 0 and "unchanged" → `ATTENTION`; else `SUCCESS`. Audit event `device_config_finished` per device.
- **Single-device dry-run:** `run_subprocess(netrune-control config <ip> <cmds…>)`, which under `--dry-run` emits `{"dry_run": True, "command": …}` without touching the network.
- **Output shape, `--json`:**
  - Single guarded: `{"ok", "status": "SUCCESS"|"ATTENTION"|"UNVERIFIED"|"BLOCKED"|"FAILED", "target", "commands", "steps", "phases", "changed", "started_at(_iso)", "finished_at(_iso)", "rollback"|"error"}`.
  - Batch dry-run: `{"ok": True, "dry_run": True, "targets", "commands", "devices": [{target, ip, commands}], "skipped": [{target, reason}], "filtered": [{target, reason}]}`.
  - Batch confirm: `{"ok", "commands", "devices": [<per-device payload>], "skipped_devices": [<gate dicts with reason; offline ones carry "offline": true>], "filtered_devices": [<gate dicts with reason>], "counts": {total, success, attention, unverified, blocked, failed, skipped, filtered}, "started_at(_iso)", "finished_at(_iso)"}`.
  - Gate refusal: `{"ok": False, "status": "UNSUPPORTED"|"UNREACHABLE", ...}`.
- **Exit codes:** `USAGE`(2) · `CONFIRM_REQUIRED`(7) · `VALIDATION`(6, unresolved target, bad file, or nothing matched the vendor filter) · `UNSUPPORTED`(5, gate) · `UNREACHABLE`(4, `--skip-offline` and every device offline) · `PARTIAL`(3, any device not `SUCCESS`, **or anything skipped** in a batch; vendor-filtered devices don't count) · `SUCCESS`(0).
- **Real example:** `netrune device config SW1,SW2,SW3 "ntp server 198.51.100.5" --skip-offline --confirm`
  ```
  Guarded device config batch: 2/2 attempted succeeded (0 attention, 0 unverified, 0 blocked, 0 failed, 1 skipped)
  TARGET  STATUS   CHANGED  DETAIL
  SW1     SUCCESS  True     ...
  SW2     SUCCESS  True     ...
  SW3     SKIPPED  False    offline: no ping reply from 198.51.100.13
  ```
- **Related commands:** `netrune inventory activity` (same reachability check, standalone), `netrune backup diff`/`backup verify` (inspect the before/after backups), `netrune device support` (driver capability and firmware certification), `netrune vlan set` (typed VLAN writes, also batchable with `--file`).
#### `netrune device identity` (id: `device-identity`)
- **Purpose:** Score whether two resolved device records are the same physical switch, using name similarity plus MAC/serial/IP/attachment evidence.
- **Exact syntax:** `netrune device identity <target1> <target2>` (alias: `netrune device compare <target1> <target2>`). Verified `device_cli.py:214-225`.
- **Arguments:** exactly two positional targets required (`rest[0]`, `rest[1]`); extra tokens beyond the first two are silently ignored (no validation on `len(rest) > 2`). Missing either → `usage_error("device","identity",…,"Two device targets are required.","netrune device identity <first> <second>", VALIDATION)`.
- **Preconditions / gating:** Both targets must resolve **unambiguously** via `resolve_device_record`; if either fails, `usage_error("device","identity",…,"Both device targets must resolve unambiguously.","netrune inventory list <target>", VALIDATION)`. No interactive picker offered here (unlike `device ssh`) — ambiguity is a hard error.
- **Step-by-step behavior:** Resolve both targets → `identity_match_evidence(left, right, "switch")` (`netops_platform/identity.py:145-230`), which computes: name similarity via `difflib.SequenceMatcher` against a profile-configurable threshold (`NETRUNE_SWITCH_SIMILARITY_THRESHOLD`/`NETOPS_SWITCH_SIMILARITY_THRESHOLD`, default **75**), MAC/serial/IP exact-match signals, asset-role/number conflict detection, and a weighted score (MAC match +100, serial +95, IP +80, attachment +75, asset-number +20, model +10, name-similarity-above-threshold +40). `conflicts` list populated on mismatched MAC/serial/asset-number. `same_device = not conflicts and (strong_identity_signal or name_identity)`.
- **Side effects:** None — pure read, no SQLite writes, no subprocess calls.
- **Output shape, table mode:** No `render_table` call at all despite the registry's `output_type: "table"` — the text is a hand-built prose summary: `"Identity assessment: {verdict}\nConfidence: {N}% | Name similarity: {N}% | Required name threshold: {N}%\nConflicts: {…or 'none'}"`.
- **Output shape, `--json` mode:** `{"ok": True, "left": <device row>, "right": <device row>, "assessment": {"same_device": bool, "candidate": bool, "confidence": int, "entity_type": "switch", "signals": {"name_similarity","name_threshold","same_mac","same_serial","same_ip","same_attachment","same_asset_number","same_model"}, "conflicts": [...], "left_normalized_name", "right_normalized_name"}, "observed_at": int}`.
- **Exit codes:** `USAGE`(2, missing arg) · `VALIDATION`(6, unresolved/ambiguous target) · `SUCCESS`(0, always on a completed comparison, regardless of same/different verdict).
- **Real example:** `netrune device identity SW-CORE-01 198.51.100.5`
  ```
  Identity assessment: same device
  Confidence: 96% | Name similarity: 100% | Required name threshold: 75%
  Conflicts: none
  ```
- **Related commands:** `netrune inventory list` (to find valid target strings first), `netrune memory device` (relationship history for a device once identity is confirmed), `netrune topology stp` (bridge-MAC based identity corroboration during a spanning-tree sweep uses the same underlying concept).

---

#### `netrune device inventory` (id: `device-inventory`)
- **Purpose:** Run the external enrichment/inventory-scan helper against one target and fold the result into Netrune's SQLite-backed device state.
- **Exact syntax:** `netrune device inventory [target ...]`. Verified `device_cli.py:295-310`.
- **Arguments:** the registry marks `target` required, but **the CLI itself performs no such check** — `*rest` is passed straight through to `netrune-control inventory` with zero validation; calling `netrune device inventory` with no arguments is accepted by this layer (the helper decides what to do with an empty argument list).
- **Preconditions / gating:** none in the Netrune layer itself (no `--dry-run`/`--confirm` gate — this is a read/enrichment action, not a config write).
- **Step-by-step behavior:**
  1. `rc = self.run_subprocess(legacy_cmd("netrune-control","inventory",*rest), opts)` — raw foreground passthrough.
  2. If `rc == SUCCESS` and not `opts.dry_run`: `self.import_flat_state(("device",), "device-inventory")` — reads the flat inventory cache the helper just wrote and re-imports it into SQLite via `ingest_manager.record_snapshot("built-in-ssh-scan", "device", rows, identity_fields=("ip",), source="device-inventory", confidence=85)`. The code comment explains *why* this step exists: without it, a device enriched via `netrune device inventory` is invisible to `inventory list`/`resolve_device_record` (which read SQLite, rebuilt only from the flat cache) even though `netrune device ssh` can already reach it (the shell resolver reads the flat file directly).
  3. If that import raises, `eprint(f"Enriched the device, but recording it failed: {exc}")` and the verb returns `PARTIAL` even though the helper itself succeeded.
- **Side effects:** Flat inventory cache file(s) written by the external `netrune-control` helper (path not owned by this Python layer). On success, SQLite `devices` table (and related ingest/observation tables) updated via `ingest_manager.record_snapshot`. No audit event is recorded for this verb.
- **Output shape, table mode:** None from Netrune — real-mode output is the raw stdout of `netrune-control inventory` (inherited, not captured). The SQLite re-import step produces no printed output on success (silent).
- **Output shape, `--json` mode:** Only the `--dry-run` preview is JSON: `{"dry_run": True, "command": "<shlex-joined command>"}`. Real-mode `--json` has no effect on the helper's own output stream.
- **Exit codes:** whatever `run_subprocess` returns for the child process (`SUCCESS`, non-zero helper exit code, `TIMEOUT`, `UNSUPPORTED` for missing binary, `130`), further downgraded to `PARTIAL` if the post-success SQLite re-import throws.
- **Real example:** `netrune device inventory 198.51.100.44` — enriches the target and, on success, silently makes it visible to `netrune inventory list`.
- **Related commands:** `netrune inventory list`/`inventory scan` (the always-does-this-step sibling the code comment contrasts against), `netrune device support` (check driver classification right after enrichment), `netrune device ssh` (works even before this step, since it reads the flat file directly).

---

#### `netrune device show` (id: `device-show`)
- **Purpose:** Run one policy-checked, read-only `show`/`display`/`get` command against a device over SSH.
- **Exact syntax:** `netrune device show <target> <command...>`. Verified `device_cli.py:265-271`.
- **Arguments:** `target` required; `command` required — `rest[1:]` is **joined with spaces** into a single command string (`command = " ".join(rest[1:])`), so `netrune device show SW1 show version` and `netrune device show SW1 "show version"` are equivalent. Missing either → `usage_error("device","show",…,"Missing target or show command.","netrune device show ZONE34 show version")` (USAGE=2).
- **Preconditions / gating:** `self.safe_show_command(command)` must pass, else `usage_error("device","show",…,"Only read-only show/display/get commands are allowed here.","netrune device config <target> <commands> --dry-run", VALIDATION)`. `safe_show_command` (`core.py:4809-4817`) rejects: shell metacharacters (`\n \r \x00 ; && || `` $(`), commands not starting with `show|sh|display|get`, and any command containing one of the blocked substrings — verbatim list: `["running-config", "startup-config", "tech-support", " run", " start", "secret", "password", "passwd", "community", "credential", "crypto", "private-key", "certificate", "write", "erase", "delete", "copy ", "reload", "configure", "conf t"]`. No `--dry-run`/`--confirm` gate needed since it's inherently read-only.
- **Step-by-step behavior:** `resolve_device_record(target)`; if it resolves **unambiguously** (`len(choices)==1`), the IP is substituted for the typed target — otherwise the raw typed string is passed through as-is (no error, no picker). Then `self.run_subprocess(legacy_cmd("netrune-control","show",resolved_target,command), opts)` — one foreground SSH login per invocation.
- **Side effects:** None from Netrune itself — no SQLite writes, no audit event. Purely a live network read via one `netrune-control show` subprocess.
- **Output shape, table mode:** None — real-mode stdout is the device's raw command output, inherited verbatim from the child process.
- **Output shape, `--json` mode:** Only `--dry-run` produces JSON: `{"dry_run": True, "command": "<shlex-joined command>"}`. Real execution ignores `--json` entirely (the external helper decides its own output format).
- **Exit codes:** whatever `run_subprocess` returns (`SUCCESS`, non-zero SSH/device error code, `TIMEOUT`, `UNSUPPORTED` for missing helper, `130`) plus `USAGE`(2)/`VALIDATION`(6) for the two local gates above.
- **Real example:** `netrune device show SW-CORE-01 "show interfaces status"` — streams the switch's raw CLI output to the terminal.
- **Related commands:** `netrune device config` (the write counterpart, gated by `--dry-run`/`--confirm`), `netrune device ssh` (full interactive session instead of one command), `netrune vlan locate` (a structured, parsed alternative to manually running `show vlan` commands).

---

#### `netrune device ssh` (id: `device-ssh`)
- **Purpose:** Open a fully interactive SSH session to a device in the foreground terminal.
- **Exact syntax:** `netrune device ssh [-l|--legacy] <target>`. Verified `device_cli.py:226-264`. Any other `-`-prefixed token is rejected: `usage_error("device","ssh",…,f"Unknown SSH option: {item}","netrune device ssh [-l|--legacy] <target>", VALIDATION)`.
- **Arguments:** `target` required (all non-flag tokens are joined with spaces into `target_query`, so a multi-word site-token target works without quoting). Missing → `usage_error("device","ssh",…,"Missing target.","netrune device ssh ZONE34")` (USAGE=2). `-l`/`--legacy` is a boolean flag with no value, appended to the helper invocation as `--legacy`.
- **Preconditions / gating:** No `--dry-run`/`--confirm` needed (interactive read access). **Ambiguity handling is the newest and most distinctive behavior in this file:** if `resolve_device_record` returns no single match but multiple `choices`, **and** the session is a real interactive terminal (`sys.stdin.isatty() and sys.stdout.isatty()`) **and** neither `--json` nor `--plain` was passed, Netrune launches `self._select_row(...)` — an arrow-key picker (`core.py:3250-3304`) that raw-mode-reads the tty, renders up to 20 candidates with a live-updating `> ` cursor (bold-cyan highlight when color is enabled), and accepts ↑/↓ + Enter to pick or `q`/Ctrl-C to cancel. Each row is labeled `f"{name:<24} {ip:<15} {platform+model:<24} {status}"`. If cancelled or not a real tty (piped, `--json`, `--plain`, non-tty), the picker returns `None` and the command falls back to the old behavior of just using the raw typed string as the target (no error — SSH will simply try to resolve it as a hostname).
- **Step-by-step behavior:**
  1. Parse `-l/--legacy` and target tokens.
  2. `resolve_device_record(target_query)`; if ambiguous and interactive, run the picker.
  3. `target = device.ip or target_query`.
  4. **Address-drift notice**: if the device resolved and the *typed* address (after `expand_abbreviated_target`) is an IPv4 literal that differs from the address actually being connected to, `eprint` a note on stderr distinguishing "a former address of this device" (matched against `device.addresses`) from "recorded for this device" — this exists specifically so an operator who typed one IP but is being connected to a different (current) one for the *same* device is told, rather than silently redirected.
  5. `self.run_vault_interactive(legacy_cmd("netrune-connect", *(["--legacy"] if legacy else []), target), opts)` — runs the helper in the true foreground (`start_new_session=False`) so PAM/Windows-Hello vault prompts keep their tty ticket.
- **Side effects:** None from Netrune's SQLite layer. The `netrune-connect` helper itself may touch the SSH known-hosts file and vault session state as part of establishing trust/auth, but that's outside this Python layer's direct writes.
- **Output shape, table mode:** N/A — `output_type: "terminal"`; the entire SSH session is drawn directly to the operator's tty by the child process.
- **Output shape, `--json` mode:** Only for `--dry-run`: `{"dry_run": True, "command": "<shlex-joined command>"}`. Also, if the picker is cancelled: `{"ok": False, "cancelled": True}` emitted with text `"Cancelled."`, returning `SUCCESS` (cancellation is not treated as failure).
- **Exit codes:** `USAGE`(2, missing target) · `VALIDATION`(6, unknown flag) · `SUCCESS`(0, dry-run preview, or a picker cancellation) · otherwise whatever the SSH session's own exit code normalizes to via `run_vault_interactive` (`TIMEOUT`=9 if `--timeout` elapses, `UNSUPPORTED`=5 if `netrune-connect` is missing, `130` on Ctrl-C).
- **Real example:** `netrune device ssh zone34` — if `zone34` matches 3 inventory rows and stdout is a real terminal, an arrow-key list appears; picking one connects to `198.51.100.5`.
- **Related commands:** `netrune device trust status/scan/enroll` (establish host-key trust before first connect), `netrune inventory list` (find the exact target string to avoid ambiguity), `netrune device show` (single non-interactive command instead of a full session).

---

#### `netrune device support` (id: `device-support`)
- **Purpose:** Classify a device's platform/driver family and report which capabilities (read and write) that driver supports, or list every registered driver's maturity when no target is given.
- **Exact syntax:** `netrune device support [target]` (alias: `netrune device compatibility [target]`). Verified `device_cli.py:196-213`.
- **Arguments:** `target` optional; all remaining tokens joined with spaces. If empty, lists every driver.
- **Preconditions / gating:** none (pure read). If a target is given, it must resolve unambiguously: `usage_error("device","support",…,f"Device could not be resolved: {target}" + candidates, "netrune inventory list <target>", VALIDATION)` on failure.
- **Step-by-step behavior:**
  - **No target:** `rows = [driver.report() for driver in self.device_drivers.all()]` — enumerates every registered `DeviceDriver` (built-in + loaded plugins/declarative), sorted by family.
  - **With target:** resolve → `detect_device_family(platform=…, model=…, hostname=…)` → `driver_for(family=detection.family)` → build `capability_rows` from `sorted(driver.capabilities.items())`.
- **Side effects:** None.
- **Output shape, table mode:**
  - No-target: `render_table(rows, ["family", "vendor", "os_name", "device_kind", "support_level"])`.
  - With target: `render_table(capability_rows, ["capability", "support"])`, prefixed by `f"Device support: {name}\nFamily: {driver.family} | OS: {driver.os_name} | Level: {driver.support_level}\n"`.
- **Output shape, `--json` mode:**
  - No-target: `{"ok": True, "target": "", "drivers": [<full driver.report() dicts>], "count": int, "observed_at": int}`. Each `driver.report()` dict itself carries: `family, vendor, os_name, device_kind, support_level, capabilities, parser_templates, detection_patterns, detection_confidence, firmware_profiles, source, read_only, notes`.
  - With target: `{"ok": bool, "device": <device row>, "detection": <DeviceDetection.as_dict(): family, vendor, os_name, device_kind, confidence, reasons, model_profile, firmware_profile>, "driver": <driver.report()>, "observed_at": int}`.
- **Exit codes:** `VALIDATION`(6, unresolved target) · `SUCCESS`(0, no-target list, or target resolved to a known family) · `UNSUPPORTED`(5, `detection.family == "unknown"`).
- **Real example:** `netrune device support sw-idf-3`
  ```
  Device support: sw-idf-3
  Family: cisco-ios | OS: IOS/IOS-XE CLI | Level: established-read
  CAPABILITY      SUPPORT
  cable_status    supported
  cable_test      supported
  cdp             supported
  configuration   firmware-gated
  vlan_write      firmware-gated
  ...
  ```
- **Related commands:** `netrune device config`/`netrune vlan set` (both gate their write path on exactly this capability data), `netrune device identity` (classification feeds identity comparisons), `netrune topology stp` (re-detects family automatically when a driver's command is rejected, reusing `detect_device_family`).

---

#### `netrune device trust status` (id: `device-trust-status`)
- **Purpose:** List managed SSH host-key fingerprints from Netrune's private known-hosts file, without any network access.
- **Exact syntax:** `netrune device trust status [target]`. Verified `device_cli.py:91-120` (`cmd_device_trust`, default `action="status"` when `netrune device trust` is called with no action at all).
- **Arguments:** `target` optional (hostname/IP/site token). `--fingerprint` is parsed by the shared option loop but has no effect for `status` (only used by `enroll`).
- **Preconditions / gating:** none — pure local file read, no `--dry-run`/`--confirm` needed.
- **Step-by-step behavior:** if a `target` is given, `self._trust_target(target)` resolves it (via `resolve_device_record`, falling back to a hostname/IP literal regex `[A-Za-z0-9][A-Za-z0-9_.:-]{0,252}`, raising `ValueError("SSH trust target must be a hostname or IP address.")` otherwise) and both the resolved `host` and the raw `target` are searched for; with no target, `wanted=[]` which matches **every** entry (`label = "all managed hosts"`). `self._known_host_rows(wanted)` (`core.py:5721-5748`) parses `self.paths.ssh_known_hosts_file` line by line, computing a `SHA256:` fingerprint from the base64 key blob via `_host_key_fingerprint`, and matching aliases either literally or via HMAC-SHA1 hashed-hostname comparison (`_known_host_alias_matches`, supporting OpenSSH's `|1|salt|digest` hashed-hostname format). `mode` is read from `NETRUNE_SSH_HOST_KEY_MODE`/`NETOPS_SSH_HOST_KEY_MODE` env or `config.public["ssh_host_key_mode"]`, defaulting to `"accept-new"` (ADR 0004: `accept-new` is the compatibility default, `strict` the production target).
- **Side effects:** None (read-only).
- **Output shape, table mode:** `render_table(rows, ["host", "key_type", "fingerprint", "line"])`.
- **Output shape, `--json` mode:** `{"ok": True, "target": label, "mode": str, "known_hosts_file": str(path), "rows": [{"host","key_type","fingerprint","line","managed_file"}], "count": int}`.
- **Exit codes:** `VALIDATION`(6, target given but unresolvable/invalid) · `SUCCESS`(0, always otherwise, even when zero keys are found).
- **Real example:** `netrune device trust status sw-idf-3`
  ```
  SSH trust: sw-idf-3 | mode=accept-new | keys=1
  HOST         KEY_TYPE          FINGERPRINT                                   LINE
  198.51.100.12   ssh-ed25519       SHA256:AbCd1234...                            17
  ```
- **Related commands:** `netrune device trust scan` (see what the device offers before enrolling), `netrune device trust enroll` (commit a verified fingerprint), `netrune device ssh` (the connection this trust store protects).

---

#### `netrune device trust scan` (id: `device-trust-scan`)
- **Purpose:** Retrieve SSH host keys and compute SHA-256 fingerprints for a target over the network, without enrolling anything.
- **Exact syntax:** `netrune device trust scan <target> [--dry-run]`. Verified `device_cli.py:121-135`.
- **Arguments:** `target` required (single, non-flag positional; a second bare token errors with `"SSH trust accepts one target."`). Missing → `"Missing SSH trust target."` (VALIDATION).
- **Preconditions / gating:** **No `--confirm` requirement** — scanning never writes local state, so only the shared `_trust_target` resolution can fail (VALIDATION). `--dry-run` is honored as a pure preview.
- **Step-by-step behavior:** `_trust_target(target)` resolves it. On `--dry-run`: emits a preview and returns without touching the network. Otherwise `self._scan_host_keys(host, opts.timeout or 8)` (`device_cli.py:46-69`) shells out to `ssh-keyscan -T <clamped 1..30> <host>` via `subprocess.run` (not `self.capture` — a direct, uncaptured-timeout call with its own `timeout=max(3,min(t,30))+3`), parses lines whose second field starts with `ssh-`, `ecdsa-`, or `sk-`, and computes each key's SHA-256 fingerprint. If `ssh-keyscan` isn't on `PATH`, returns `([], "ssh-keyscan is not installed")`.
- **Side effects:** None — read-only network probe, no known-hosts writes, no audit event.
- **Output shape, table mode:** `render_table(payload["rows"], ["host", "key_type", "fingerprint"])` — only when at least one key was found; otherwise the text is the raw error string.
- **Output shape, `--json` mode:** Real run: `{"ok": bool(rows), "target": label, "host": host, "observed_at": int, "observed_at_iso": str, "trusted": False, "rows": [{"host","key_type","fingerprint"} — "key_line" stripped], "error": str}`. Dry run: `{"ok": True, "dry_run": True, "target": label, "host": host, "command": f"ssh-keyscan -T {opts.timeout or 8} {host}"}`.
- **Exit codes:** `VALIDATION`(6, bad/missing target) · `SUCCESS`(0, dry-run, or at least one key found) · `UNREACHABLE`(4, scan produced zero rows — device unreachable, `ssh-keyscan` missing, or timeout).
- **Real example:** `netrune device trust scan sw-idf-3`
  ```
  HOST         KEY_TYPE          FINGERPRINT
  198.51.100.12   ssh-ed25519       SHA256:AbCd1234efGh5678...
  ```
- **Related commands:** `netrune device trust enroll` (the natural next step, pinning one of these fingerprints after out-of-band verification), `netrune device trust status` (check what's already trusted first).

---

#### `netrune device trust enroll` (id: `device-trust-enroll`)
- **Purpose:** Pin exactly the SSH host-key fingerprint(s) an operator has independently verified out-of-band, rejecting any unverified key the device also offers.
- **Exact syntax:** `netrune device trust enroll <target> --fingerprint <fp>[,<fp>...] (--dry-run | --confirm)`. `--fingerprint` may repeat. Verified `device_cli.py:136-186`.
- **Arguments:** `target` required; `--fingerprint` required with ≥1 value (comma-split, whitespace-trimmed). Missing fingerprints on a confirmed/dry-run enroll → `usage_error("device","trust-enroll",…,"Enrollment requires at least one independently verified --fingerprint.","netrune device trust scan <target>", VALIDATION)`.
- **Preconditions / gating:** Requires `--dry-run` or `--confirm` (checked once, shared with `forget`): `"SSH trust changes require --dry-run or --confirm."` → `CONFIRM_REQUIRED`(7).
- **Step-by-step behavior:** `--dry-run` emits a preview naming exactly the fingerprints that would be enrolled and returns. Otherwise: re-runs `_scan_host_keys(host, opts.timeout or 8)` (a **fresh** scan — enrollment never trusts a cached scan), case-folds both the wanted and observed fingerprints, and keeps only the keys whose fingerprint matches one supplied on the command line (`matched`). If none match, returns `AUTH`(8) with the scan error or `"None of the scanned SSH keys matched the verified fingerprint."`. On a match, reads the existing known-hosts file, **drops any existing line whose alias matches this host** (so a replaced device's stale key is implicitly superseded), appends the matched key line(s), and calls `self._write_known_hosts(retained)` (`device_cli.py:71-89`) — writes atomically via `tempfile.mkstemp` + `os.fsync` + `os.replace`, with `0o700`/`0o600` permissions enforced on the directory and file.
- **Side effects:** Rewrites `self.paths.ssh_known_hosts_file` (atomic replace). Audit event `ssh_trust_enrolled` (action `device-trust-enroll`, actor=`$SUDO_USER`/`$USER`/uid, target=`host`, result=`"success"`, detail=`{"fingerprints": [...]}`) → `audit_events` table.
- **Output shape, table mode:** **None despite the registry's `output_type: "table"`** — success and failure both emit plain prose text (`f"Enrolled {N} verified SSH host key(s) for {label} ({host})."` or the error message), never `render_table`.
- **Output shape, `--json` mode:** Dry run: `{"ok": True, "dry_run": True, "target": label, "host": host, "fingerprints": [...]}`. No-match failure: `{"ok": False, "target": label, "host": host, "error": str, "observed_fingerprints": [...]}`. Success: `{"ok": True, "target": label, "host": host, "known_hosts_file": str, "rows": [{"host","key_type","fingerprint"}], "count": int}`.
- **Exit codes:** `VALIDATION`(6, bad target, or missing `--fingerprint`) · `CONFIRM_REQUIRED`(7, no `--dry-run`/`--confirm`) · `SUCCESS`(0, dry-run or successful enroll) · `AUTH`(8, no scanned key matched the verified fingerprint).
- **Real example:** `netrune device trust enroll sw-idf-3 --fingerprint SHA256:AbCd1234efGh5678 --confirm` → `"Enrolled 1 verified SSH host key(s) for sw-idf-3 (198.51.100.12)."`
- **Related commands:** `netrune device trust scan` (must run first to discover the candidate fingerprint), `netrune device trust forget` (undo before a device replacement, per ADR 0004's audited forget/re-enroll procedure), `netrune device ssh` (the connection this enables).

---

#### `netrune device trust forget` (id: `device-trust-forget`)
- **Purpose:** Remove a target's entries from the managed SSH known-hosts file.
- **Exact syntax:** `netrune device trust forget <target> (--dry-run | --confirm)`. Verified `device_cli.py:136-159`.
- **Arguments:** `target` required.
- **Preconditions / gating:** Same shared gate as enroll: requires `--dry-run` or `--confirm` → `CONFIRM_REQUIRED`(7) otherwise.
- **Step-by-step behavior:** Reads the known-hosts file, and for every line, checks whether any of its comma-separated aliases matches either the resolved `host` or the raw typed `target` (via `_known_host_alias_matches`, covering both literal and OpenSSH hashed-hostname forms). Matching lines are dropped; `--dry-run` reports the count that *would* be removed without writing. Real run calls `self._write_known_hosts(retained)`.
- **Side effects:** Rewrites `ssh_known_hosts_file`. Audit event `ssh_trust_forgotten` (action `device-trust-forget`, target=`host`, result=`"success"`, detail=`{"removed": int}`).
- **Output shape, table mode:** **None** — plain prose only (`f"Would remove {N} managed SSH key(s)..."` / `f"Removed {N} managed SSH key(s)..."`), despite the registry marking this `output_type: "table"`.
- **Output shape, `--json` mode:** Dry run: `{"ok": True, "dry_run": True, "target": label, "host": host, "would_remove": int}`. Real: `{"ok": True, "target": label, "host": host, "removed": int}`.
- **Exit codes:** `VALIDATION`(6, bad/missing target) · `CONFIRM_REQUIRED`(7, no gate flag) · `SUCCESS`(0, always on completion, even if 0 keys were removed).
- **Real example:** `netrune device trust forget sw-idf-3 --confirm` → `"Removed 1 managed SSH key(s) for sw-idf-3 (198.51.100.12)."`
- **Related commands:** `netrune device trust enroll` (the paired re-trust step after a hardware swap), `netrune device trust status` (verify the removal).

---

### VLAN DOMAIN

#### `netrune vlan locate` (id: `vlan-locate`)
- **Purpose:** Find where a VLAN is defined/access-mode-assigned across one or many root switches, optionally traversing LLDP/CDP-confirmed switch links to a bounded depth.
- **Exact syntax:** `netrune vlan locate <target[,target...]> <vlan[,vlan-range,...]> [--depth N] [--max-nodes N] [--refresh-neighbors]` (also accepts `--target`/`--device` and `--vlan` as explicit flags instead of positionals — see `parse_vlan_scan_request`). Verified `vlan_cli.py:733-741`.
- **Arguments:** `target`/`vlan` required (comma-separated lists allowed on both, up to **16 targets** and **128 distinct VLANs** per invocation — `parse_vlan_scan_request`, `vlan_cli.py:693-731`, raises `ValueError("a VLAN scan accepts at most 16 root targets per invocation")` / `"...128 distinct VLANs..."`). VLAN syntax validated by `_validated_vlan_values(spec, allow_list=True)` — same rules as `vlan set`'s trunk list (see below). `--depth` clamped 0-16 by the global parser; `--max-nodes` clamped 64-256.
- **Preconditions / gating:** No `--dry-run`/`--confirm` needed (read-only). If root target(s) don't resolve, `usage_error("vlan", mode, …, f"Ambiguous switch target {target!r}: {labels}" or f"Switch target not found: {target}", "netrune inventory list <target>", VALIDATION)` — **and in a multi-target scan, one bad root aborts the entire scan immediately** rather than skipping just that root (`vlan_cascade_many` returns the raw int the moment any single `vlan_cascade` call returns a non-tuple).
- **Step-by-step behavior:**
  - **Single target, single VLAN, no `--depth`:** direct raw passthrough — `self.run_subprocess(legacy_cmd("netrune-control","locate-vlan",targets[0],str(vlans[0])), opts)`.
  - **Otherwise** (any of: `--depth` set, >1 target, >1 VLAN): `self.vlan_cascade_many(targets, vlans, "locate", opts)`, which for a true 1×1 case degenerates back to a single `vlan_cascade` call, and otherwise loops every target × VLAN pair calling `vlan_cascade(target, vlan, "locate", opts, collect=True)`.
  - `vlan_cascade` (`vlan_cli.py:241-422`) does a **breadth-first traversal**: resolve root → for each queued device (bounded by `depth_limit` and `node_limit`), call `self.inspect_vlan_node(device, vlan, "locate", opts)`, which: runs `netrune-control locate-vlan <ip> <vlan>` via `self.capture`, parses it with `parse_vlan_control_output`, pulls `self.cached_switch_neighbors(device)` from the `neighbors` SQLite table, and — only if `opts.refresh_neighbors` or the cache is missing/incomplete for a discovered trunk — calls `self.live_switch_neighbors(device, …)` which does a single batched SSH login (`self.capture_batch`) running the driver's LLDP/CDP neighbor-detail commands. It also runs a `trunk_summary` command (one more `self.capture`) to settle trunks the awk-based report left as `TRUNK_EVIDENCE_UNKNOWN`. Findings (`VLAN_NOT_DEFINED`, `VLAN_MISSING_ON_TRUNK`, `NEIGHBOR_DEVICE_UNRESOLVED`, `NODE_BUDGET_REACHED`) accumulate as the queue drains; a neighbor becomes a new queue entry only if it resolves to a known device (`self._neighbor_device`), hasn't been visited/scheduled, and the node budget isn't exhausted.
- **Side effects:** No SQLite writes at all from this traversal (purely a live-read tool; it reads `neighbors` but never writes it). No audit event. Multiple `netrune-control` subprocess invocations per node (`locate-vlan`, possibly `show-batch` for neighbors, possibly `show` for trunk summary).
- **Output shape, table mode (single-pair passthrough):** none — raw helper stdout.
- **Output shape, table mode (cascade, single root×VLAN):** two tables: switch-path `render_table(display_nodes, ["layer","device","ip","vlan","access","trunks","gaps","result"])` (the `"access"` column only appears for `mode=="locate"`) and findings `render_table(findings[:opts.limit], ["severity","code","depth","device","port","detail"])`.
- **Output shape, table mode (cascade-many, multi root/VLAN):** matrix `render_table(matrix, ["root","root_ip","vlan","switches","present","absent","trunk_gaps","errors","result"])` plus the same findings table shape with an added `root`/`vlan` prefix: `["severity","code","root","vlan","depth","device","port","detail"]`.
- **Output shape, `--json` mode:**
  - Single-pair passthrough: real mode is raw (unwrapped); `--dry-run` gives `{"dry_run": True, "command": …}`.
  - Single cascade: `{"ok", "healthy", "complete", "mode", "root":{"ip","name"}, "vlan", "depth", "max_nodes", "nodes":[...], "edges":[...], "findings":[...], "counts":{"visited_nodes","switch_links","switch_link_observations","present_nodes","missing_nodes","trunk_gaps","critical_findings","warnings","unresolved_links","inspection_errors"}, "observed_at", "observed_at_iso", "traversal":"breadth_first", "depth_semantics": "root is layer 0; depth is the maximum number of switch-link hops"}`.
  - Multi cascade: `{"ok","healthy","complete","mode","targets":[...],"vlans":[...],"depth","matrix":[...],"runs":[<full cascade payloads>],"findings":[...],"counts":{"roots","vlans","scans","visited_node_observations","trunk_gaps","inspection_errors"},"observed_at","observed_at_iso"}`.
- **Exit codes:** `VALIDATION`(6, malformed request/unresolved root) · `SUCCESS`(0, single-pair passthrough success, dry-run, or a cascade with zero inspection errors) · `PARTIAL`(3, cascade with ≥1 inspection error, or `vlan_cascade_many` if any sub-scan's code ≠ `SUCCESS`) · passthrough failure codes from `run_subprocess` otherwise.
- **Real example:** `netrune vlan locate sw-core-01,sw-idf-3 120 --depth 2`
  ```
  VLAN 120 locate: 2 root(s) x 1 VLAN(s), depth 2
  ROOT         ROOT_IP      VLAN  SWITCHES  PRESENT  ABSENT  TRUNK_GAPS  ERRORS  RESULT
  sw-core-01   198.51.100.1    120   4         4        0       0           0       PRESENT
  sw-idf-3     198.51.100.12   120   3         2        1       1           0       GAPS
  ```
- **Related commands:** `netrune vlan set` (fix a gap this command found), `netrune vlan propagation` (the deeper/matrix-oriented sibling), `netrune topology stp`/`topology links` (independent link evidence that corroborates the switch-link traversal here).

---

#### `netrune vlan propagation` (id: `vlan-propagation`)
- **Purpose:** Same bounded breadth-first cascade as `vlan locate`, but calling the `--deep` propagation-report helper mode and framed as "does this VLAN's trunk propagation reach every expected switch" rather than "where is it".
- **Exact syntax:** `netrune vlan propagation <target[,...]> <vlan[,...]> [--depth N] [--max-nodes N] [--refresh-neighbors]`. Verified `vlan_cli.py:742-746`.
- **Arguments / preconditions / step-by-step / side effects:** Identical machinery to `vlan locate` (`parse_vlan_scan_request`, `vlan_cascade`/`vlan_cascade_many` with `mode="propagation"`), with two source-level differences: (1) the single-pair passthrough calls `netrune-control propagated <target> <vlan>` instead of `locate-vlan`; (2) inside `inspect_vlan_node`, `mode=="propagation"` appends `--deep` to the `netrune-control propagated` command (`command.append("--deep")`, `vlan_cli.py:108-110`) and the live-log counters omit the `access=` prefix that `locate` mode adds.
- **Output shape, table mode:** Same shapes as `vlan locate`'s cascade tables, **minus** the `"access"` display column (that column is `mode=="locate"`-only).
- **Output shape, `--json` mode:** Identical payload shape to `vlan locate`'s cascade payloads, with `"mode": "propagation"`.
- **Exit codes:** Identical semantics to `vlan locate`.
- **Real example:** `netrune vlan propagation sw-core-01 130 --depth 3 --max-nodes 100` — walks up to 100 switches, 3 hops deep, checking VLAN 130's trunk presence at each hop.
- **Related commands:** `netrune vlan locate` (near-identical sibling), `netrune vlan set` (remediate a trunk gap this surfaces), `netrune topology scan` (refresh LLDP/CDP first if `--refresh-neighbors` results look stale).

---

#### `netrune vlan set` (id: `vlan-set`)
- **Purpose:** Apply one typed access- or trunk-VLAN assignment to a switch interface through Netrune's fully guarded, audited configuration lifecycle — the flagship example of ADR 0005.
- **Exact syntax:** `netrune vlan set <target> <interface> (--access <vlan> | --trunk <vlan-list>) [--native <vlan>] [--replace] (--dry-run | --confirm)`. Verified `vlan_cli.py:747-765`.
- **Arguments:**
  - `target`, `interface` positional, required (`interface` must be `rest[1]` — i.e. immediately after target).
  - `--access <vlan>` XOR `--trunk <vlan-list>` (mode is derived from whichever flag was used: `parsed["vlan_mode"] = item[2:]`).
  - `--native <vlan>` optional, valid **only** in trunk mode.
  - `--replace` optional boolean flag, valid **only** in trunk mode (replaces the whole allowed-VLAN list instead of adding to it).
  - Missing target/interface → `"Missing target or interface."` (USAGE=2). Unknown/incomplete option → `usage_error(...,f"Unknown or incomplete VLAN option: {item}", …, VALIDATION)`.
  - **Full validation chain** (`vlan_change_request`, `vlan_cli.py:515-550`, and `_validated_vlan_values`, `vlan_cli.py:491-513`):
    - Target empty after `normalize_target_literal` → `"VLAN change requires a switch target."`
    - Interface must match `^[A-Za-z0-9][A-Za-z0-9./:_-]{0,63}$` → `"Interface name is invalid."`
    - Mode must be `access` or `trunk` → `"Port mode must be access or trunk."`
    - VLAN value empty or >512 chars → `"VLAN value is missing or too long."`
    - Access mode requires a bare integer (`text.isdigit()`), else `"Access VLAN must be one integer from 1 through 4094."`
    - Both modes require the overall shape `\d{1,4}(?:-\d{1,4})?(?:,\d{1,4}(?:-\d{1,4})?)*`, else `"Trunk VLANs must be comma-separated IDs or ascending ranges."`
    - Each range must satisfy `1 <= first <= last <= 4094` else `"VLAN ranges must be ascending and within 1 through 4094."`; each single ID must satisfy `1 <= n <= 4094` else `"VLAN IDs must be within 1 through 4094."`
    - `--native` (if given) validated as a single integer 1-4094 the same way; `"Native VLAN is valid only for trunk mode."` if `mode != "trunk"`.
    - `--replace` set with `mode != "trunk"` → `"Replace is valid only for a trunk allowed list."`
- **Preconditions / gating:** Requires `--dry-run` or `--confirm` → `"VLAN changes require --dry-run or --confirm."` (`CONFIRM_REQUIRED`=7). Under `--confirm`, wrapped in `self.vault_session_scope(opts, minutes=30)` (single vault unlock covers preflight+backup+apply+verify).
- **Step-by-step behavior — `apply_vlan_change` (`vlan_cli.py:552-691`), full guarded lifecycle:**
  1. **`--dry-run`**: builds the exact **public-facing** command that would run (`netrune vlan set <target> <interface> --access/--trunk <vlan> [--native <n>] [--replace] --confirm`), lists the 4 named steps, and returns `SUCCESS` without any network I/O.
  2. `resolve_device_record(target)` — must resolve to **exactly one** device, else `usage_error("vlan","set",…,"Switch target could not be uniquely resolved." + matches, "netrune vlan set <target> <interface> --access 131 --dry-run", VALIDATION)`.
  3. **Firmware/driver gate**: `driver_for(...)`, `detect_device_family(...)`; write is approved only if **all** of: `driver.source == "built-in"`, `driver.capability("vlan_write") == "firmware-gated"`, the site config flag `device_writes_enabled` is truthy (`"1"/"true"/"yes"/"on"`), **and** `detection.firmware_profile in driver.firmware_profiles` (i.e. the exact detected firmware string, e.g. `ios-15.x`, is on the driver's certified list). Failing any → `UNSUPPORTED`(5) with a detailed payload naming which check failed.
  4. **Phase 1 preflight**: picks `show vlan ports <interface> detail` for Aruba/ProCurve/HP platforms or `show interfaces <interface> switchport` otherwise; `self.capture(legacy_cmd("netrune-control","show",ip,cmd), opts.timeout or 180, opts)`. Empty output or non-zero rc → `status="BLOCKED"`, `"Pre-change interface evidence could not be captured; no configuration was applied."`, return `PARTIAL`.
  5. **Phase 2 backup**: `netrune-control backup <ip> --online-only --changed-only --summary` (`opts.timeout or 300`). Failure → `"Configuration backup failed; no VLAN change was applied."`, `PARTIAL`.
  6. **Phase 3 apply**: `netrune-control` invoked with `request["helper_args"]` = `["vlan", target, interface, f"--{mode}", vlan_text, (["--native",native] if native), (["--replace"] if replace)]` (`opts.timeout or 300`). Failure → `"Device rejected the VLAN change. Review pre-change evidence before any manual rollback."`, `PARTIAL`.
  7. **Phase 4 verify**: for each VLAN to confirm — **all** requested VLANs if the request named ≤8 IDs, otherwise only the **first and last** (sampled) plus the native VLAN if any — runs `netrune-control locate-vlan <ip> <vlan>` and checks the interface appears among the expected ports (access ports for access mode, trunk-carrying ports for trunk mode) via `interface_matches`. `verification_complete = len(requested) <= 8`; `verified = all-checks-passed AND verification_complete`.
- **Side effects:** Audit event `vlan_change_finished` (action `vlan-set`, actor=`$SUDO_USER`/`$USER`/uid, target=`f"{ip}:{interface}"`, result=`status.lower()`, detail=`{request (minus helper_args), phases}`) → `audit_events` table. Multiple `netrune-control` subprocess calls (show ×1, backup ×1, vlan-set ×1, locate-vlan ×1-9). No direct SQLite table other than the audit event (the `neighbors`/`devices` tables are not touched by this verb).
- **Output shape, table mode:** `render_table(phase_results, ["phase", "status", "exit_code", "detail"])`.
- **Output shape, `--json` mode:**
  - Dry run: `{"ok": True, "dry_run": True, "request": {...minus helper_args}, "command": str, "steps": [...], "rollback": str}`.
  - Blocked/failed: `{"ok": False, "status": "BLOCKED"|"FAILED", "request", "device", "phases", "error", "started_at", "finished_at"}`.
  - Completed: `{"ok": bool, "status": "SUCCESS"|"ATTENTION", "request", "device", "phases", "verification_vlan", "verification_vlans", "verification_complete", "verification_observed", "verified", "started_at", "started_at_iso", "finished_at", "finished_at_iso", "rollback"}`.
  - Unsupported gate: `{"ok": False, "status": "UNSUPPORTED", "request", "device", "driver_family", "firmware_profile", "writes_enabled", "support", "error"}`.
- **Exit codes:** `USAGE`(2, missing target/interface) · `CONFIRM_REQUIRED`(7) · `VALIDATION`(6, any of the field-validation rules above, or unresolved target) · `UNSUPPORTED`(5, firmware/config gate) · `SUCCESS`(0, dry-run preview or a fully verified change) · `PARTIAL`(3, BLOCKED/FAILED/ATTENTION at any phase).
- **Real example:** `netrune vlan set sw-idf-3 Gi1/0/24 --access 131 --confirm`
  ```
  Guarded VLAN change: SUCCESS
  Device: sw-idf-3 (198.51.100.12) Gi1/0/24
  PHASE      STATUS  EXIT_CODE  DETAIL
  preflight  PASS    0          Gi1/0/24 switchport access vlan 10...
  backup     PASS    0          changed-only backup captured...
  apply      PASS    0          vlan access assignment accepted...
  verify     PASS    0          1/1 VLAN checks passed; complete=yes
  Recorded: 2026-08-28T14:10:03Z
  Not required; complete post-change verification passed.
  ```
- **Related commands:** `netrune vlan locate`/`vlan propagation` (find the gap first), `netrune device support` (check `vlan_write` capability/firmware profile before attempting), `netrune backup diff`/`backup verify` (inspect the backups this lifecycle produces), `netrune device trust status` (host key must already be trusted for the underlying SSH to succeed).

---

### TOPOLOGY DOMAIN

#### `netrune topology scan` (id: `topology-scan`)
- **Purpose:** Refresh LLDP/CDP neighbor data across the fleet via the discovery helper and fold it into SQLite.
- **Exact syntax:** `netrune topology scan`. Verified `topology_cli.py:37-42`.
- **Arguments:** none.
- **Preconditions / gating:** none (`--dry-run` supported as a pure preview via `run_subprocess`'s own dry-run short-circuit).
- **Step-by-step behavior:** `rc = self.run_subprocess(legacy_cmd("netrune-discovery","--discover-neighbors"), opts)`; if `rc==0` and not `opts.dry_run`: `self.import_flat_state(("topology",), "lldp-cdp-scan")` — reads the flat neighbor cache into SQLite via `ingest_manager.record_snapshot("built-in-lldp-cdp", "neighbor-link", rows, identity_fields=("local_ip","local_port","remote_name","remote_port"), source="lldp-cdp-scan", observed_at_field="observed_at", confidence=80, composite_identity=True)`. On import exception: `eprint(...)`, return `PARTIAL`.
- **Side effects:** Flat neighbor-cache files written by `netrune-discovery`. SQLite `neighbors` table (and topology-events/ingest bookkeeping) updated via the ingest pipeline. No audit event for this verb.
- **Output shape, table mode:** None from Netrune in real mode — raw `netrune-discovery` stdout, inherited.
- **Output shape, `--json` mode:** Only `--dry-run`: `{"dry_run": True, "command": …}`.
- **Exit codes:** whatever `run_subprocess` returns for the helper, downgraded to `PARTIAL` if the SQLite re-import throws.
- **Real example:** `netrune topology scan` — refreshes LLDP/CDP neighbor tables fleet-wide; typically run before `topology show`/`topology links`.
- **Related commands:** `netrune topology stp` (a second, independent link-discovery protocol), `netrune topology show`/`links` (read the results this writes), `netrune device inventory` (the equivalent enrichment step for the device domain).

---

#### `netrune topology stp` (id: `topology-stp`)
- **Purpose:** Read spanning-tree state from switches in parallel, derive switch-to-switch links from designated-bridge addresses (corroborated against LLDP/CDP where possible), and persist them as first-class relationships.
- **Exact syntax:** `netrune topology stp [target] [--jobs N] [--failed]` (alias `--retry-failed` for `--failed`). Verified `topology_cli.py:43-112`.
- **Arguments:** `target` optional (a bare "all"/"*"/"any" via `is_all_keyword` is treated as no target — sweep everything online). `--jobs N` optional, must be `1 <= N <= 32` else `usage_error("topology","stp",…,"--jobs requires a number between 1 and 32.","netrune topology stp [target] [--jobs N] [--failed]", VALIDATION)`. `--failed`/`--retry-failed` and `target` are **mutually exclusive**: `usage_error(...,"--failed re-reads every switch that still owes a result, so it takes no target.","netrune topology stp --failed", VALIDATION)`.
- **Preconditions / gating:** no `--dry-run`/`--confirm` needed (read-only); `--dry-run` previews the switch count that would be read. If `--failed` and nothing is outstanding, short-circuits with `{"ok":True,"switches_total":0,"links":[],"note":"every online switch has a parsed spanning-tree read"}` → `SUCCESS`.
- **Step-by-step behavior — `collect_spanning_tree_topology` (`topology_cli.py:414-731`):**
  1. Device set: explicit `target` resolved via `resolve_device_record` (VALIDATION if it matches 0 or >1 switches); `--failed` uses `self.devices_needing_stp()` (SQL: online devices whose latest `capability_evidence` row for `capability='stp'` isn't `state='supported'`); otherwise all non-`OFFLINE` devices.
  2. `workers = max(1, min(jobs or self._default_stp_jobs(), 32, total or 1))` — `_default_stp_jobs()` reads `config.public["stp_scan_workers"]`, clamped `1..8`, default `8`.
  3. Opens **one** `self.vault_session_scope(opts, minutes=30)` for the entire sweep — a `ThreadPoolExecutor(max_workers=workers)` fans out `self.inspect_spanning_tree(device, opts, record=False, neighbors=True)` per device (DB writes deferred to the main thread for a single stable connection).
  4. `inspect_spanning_tree` (`topology_cli.py:126-355`) per device: one batched SSH login (`self.capture_batch`) for the stp/stp_summary command **plus** the driver's `cdp_neighbors` and `trunk_summary` templates together; falls back to trying remaining STP command templates one at a time if the first didn't parse; if the device outright rejects the command and looks unsupported, it re-probes with `show version`, re-runs `detect_device_family` on the sysdescr, and — if a different family is detected — **retries once with a corrected platform** (never persisting the correction itself; that happens one level up). Uplink ports are classified via `classify_uplink_ports(ports, cdp_rows, trunks, management_vlan())`, and for each classified uplink, an LLDP/CDP neighbor-detail read names the far-end device precisely.
  5. Back in the aggregator: successful reads are stored via `state.record_capability_evidence(identity, "stp", "supported", facts, driver_family=…, confidence=95-if-ports-else-70, observed_at=…)` (→ `capability_evidence` table) and `state.record_device_bridge_mac(identity, switch_mac)` (fills a blank `devices.mac` only — never overwrites). Failed reads are recorded too, `state="unsupported"` (confidence 100) or `"unknown"` (confidence 40). Any platform reclassification found during the retry is applied via `UPDATE devices SET platform=? WHERE ip=?` and, if any occurred, `state.export_flat_files()` re-writes the flat inventory cache (so the next `netrune-control` invocation picks the corrected driver).
  6. Links are derived two ways and merged: (a) LLDP-named uplink neighbors (confidence **97**), and (b) STP's designated-bridge MAC resolved through a MAC→device index built from inventory + prior STP evidence (confidence **96** if the same pair also appears in LLDP/CDP's `neighbors` table, else **82**). A switch that never answers can still be reclassified from a neighbor's system description (`described` dict built from both this run's and historical `capability_evidence` rows).
  7. `self.state.record_stp_links(links, started)` (`core.py:2131-2186`) upserts each link into `relationships_current` (`rel_type='stp_link'`, key `stp_link|{local}|{port}|{remote}`) — kept **deliberately separate** from the `neighbors` table so mixing STP's view into LLDP/CDP-driven link-added/removed events wouldn't misrepresent what actually changed.
- **Side effects:** `capability_evidence` table (per-device STP facts, history capped at `CAPABILITY_EVIDENCE_HISTORY=5` per device/capability). `devices.mac` (fill-blank-only) and `devices.platform` (on reclassification) updates. `relationships_current`/`relationship_events` tables via `record_stp_links`. Flat inventory files re-exported on reclassification. No audit event (this is a read/observation action, not a config change). Vault session opened once for the whole sweep.
- **Output shape, table mode:** `render_table([{"switch","port","neighbor","role","state","confidence"} per link], ["switch","port","neighbor","role","state","confidence"])`.
- **Output shape, `--json` mode:** `{"ok": bool, "observed_at": int, "observed_at_iso": str, "vault_session_held": bool, "reclassified": [{"device","from","to","platform", optional "source":"neighbor-lldp"}], "parallel_jobs": int, "switches_total": int, "switches_inspected": int, "switches_failed": int, "links": [...], "links_recorded": {"added": int, "updated": int}, "corroborated_links": int, "new_links": int, "unresolved_bridges": [...], "failures": [{"device","error", optional "raw_bytes","raw_excerpt","reclassified_to"}]}`. (`payload["ok"] = not failures or bool(reads)`.)
- **Exit codes:** `VALIDATION`(6, `--jobs` out of range, `--failed`+target conflict, unresolved/ambiguous explicit target) · `SUCCESS`(0, dry-run, nothing-to-retry short-circuit, or `payload["ok"]` true) · `PARTIAL`(3, `payload["ok"]` false — every read failed and nothing parsed).
- **Real example:** `netrune topology stp --jobs 4`
  ```
  Inspected 11 of 12 switch(es); 1 could not be read.
  Derived 10 link(s): 7 also seen by LLDP/CDP, 3 not.
  Read 4 switch(es) at a time.
  Vault held open for this run and closed again; one authentication covered every switch.
  SWITCH        PORT        NEIGHBOR      ROLE          STATE        CONFIDENCE
  sw-core-01    Gi1/0/1     sw-idf-3      designated    forwarding   97
  ...
  ```
- **Related commands:** `netrune topology links` (read what this just wrote), `netrune topology scan` (the LLDP/CDP protocol this corroborates against), `netrune device support` (family/driver classification feeds the same-session reclassification logic), `netrune vlan locate` (uses `cached_switch_neighbors` fed by the `neighbors` table, a sibling but separate data source from what this command writes to `relationships_current`).

---

#### `netrune topology links` (id: `topology-links`)
- **Purpose:** List the switch-to-switch links Netrune has derived from spanning-tree evidence, with source confidence.
- **Exact syntax:** `netrune topology links`. Verified `topology_cli.py:113-118`.
- **Arguments:** none (respects the global `--limit`, default 100).
- **Preconditions / gating:** none — pure SQLite read.
- **Step-by-step behavior:** `self.state.rows("SELECT switch_name,switch_ip,switch_port,object_id,confidence,source,status,last_seen,attrs_json FROM relationships_current WHERE rel_type='stp_link' ORDER BY switch_name,switch_port LIMIT ?", (opts.limit,))`.
- **Side effects:** None.
- **Output shape, table mode:** `render_table(rows, ["switch_name", "switch_port", "object_id", "confidence", "source", "status"])` — note `switch_ip`, `last_seen`, and `attrs_json` are present in the JSON payload but **not** shown in the table.
- **Output shape, `--json` mode:** `{"ok": True, "rows": [{"switch_name","switch_ip","switch_port","object_id","confidence","source","status","last_seen","attrs_json"}]}`.
- **Exit codes:** `SUCCESS`(0) always.
- **Real example:** `netrune topology links --limit 20`
  ```
  SWITCH_NAME   SWITCH_PORT   OBJECT_ID    CONFIDENCE   SOURCE          STATUS
  sw-core-01    Gi1/0/1       sw-idf-3     97           spanning-tree   active
  ```
- **Related commands:** `netrune topology stp` (the only writer of this table), `netrune topology show` (the LLDP/CDP-sourced sibling table), `netrune topology changes` (event history for the same underlying relationship data, via a different table).

---

#### `netrune topology show` (id: `topology-show`)
- **Purpose:** Display current LLDP/CDP topology, either live-queried for one target or read from SQLite for a general listing.
- **Exact syntax:** `netrune topology show [target]`. Verified `topology_cli.py:119-121`.
- **Arguments:** `target` optional.
- **Preconditions / gating:** none.
- **Step-by-step behavior — two entirely different code paths depending on flags:**
  - If `rest` (a target was given) **and** it's not an `is_all_keyword` value **and** `not opts.json`: raw live passthrough — `self.run_subprocess(legacy_cmd("netrune-discovery","--topology",rest[0]), opts)`.
  - **Otherwise** (no target, or target is "all"/"*"/"any", or **`--json` was passed even with a target — in which case the target is silently ignored**): `self.state.rows("SELECT * FROM neighbors ORDER BY local_name,local_port LIMIT ?", (opts.limit,))`.
- **Side effects:** None from this verb (read-only in both branches).
- **Output shape, table mode:** SQLite branch: `render_table(rows, ["local_ip", "local_name", "local_port", "remote_name", "remote_port", "remote_ip"])`. Live-passthrough branch: raw helper stdout, no Netrune table.
- **Output shape, `--json` mode:** SQLite branch: `{"ok": True, "rows": [<full neighbors row>]}`. Live-passthrough branch is unreachable under `--json` (the code explicitly routes `--json` to the SQLite branch regardless of whether a target was given).
- **Exit codes:** `SUCCESS`(0) for the SQLite branch always; whatever `run_subprocess` returns for the live-passthrough branch.
- **Real example:** `netrune topology show --json` (returns all cached neighbors up to `--limit`, even if a target string were also passed) or `netrune topology show sw-idf-3` (plain text, live-queries just that switch).
- **Related commands:** `netrune topology scan` (populates the `neighbors` table this reads), `netrune topology links` (the STP-derived complement).

---

#### `netrune topology changes` (id: `topology-changes`)
- **Purpose:** Show recorded topology change events (links added/removed/moved), newest first.
- **Exact syntax:** `netrune topology changes`. Verified `topology_cli.py:122`.
- **Arguments:** none (respects global `--limit`).
- **Preconditions / gating:** none.
- **Step-by-step behavior:** `self.state.rows("SELECT * FROM topology_events ORDER BY created_at DESC,id DESC LIMIT ?", (opts.limit,))`.
- **Side effects:** None (read-only; this table is written elsewhere, by whatever compares successive `topology scan` snapshots — not by this verb).
- **Output shape, table mode:** `render_table(rows, ["created_at", "event_type", "local_ip", "local_port", "remote_name", "remote_port", "detail"])`.
- **Output shape, `--json` mode:** `{"ok": True, "rows": [<full topology_events row>]}`.
- **Exit codes:** `SUCCESS`(0) always.
- **Real example:** `netrune topology changes --limit 10`
  ```
  CREATED_AT            EVENT_TYPE     LOCAL_IP     LOCAL_PORT   REMOTE_NAME   REMOTE_PORT   DETAIL
  2026-08-27T09:14:02Z  link_removed   198.51.100.1    Gi1/0/12     sw-idf-9      Gi1/0/1       neighbor no longer seen
  ```
- **Related commands:** `netrune topology scan` (the trigger that produces new events), `netrune topology timeline` (per-relationship version history, a different table/shape covering more than just topology events), `netrune attention`/health-style commands that surface these same events as operational alerts (outside this scope).

---

#### `netrune topology timeline` (id: `topology-timeline`)
- **Purpose:** Show neighbor-link relationship history, newest first, as versioned snapshots.
- **Exact syntax:** `netrune topology timeline [target]`. Verified `topology_cli.py:123`.
- **Arguments:** `target` optional (free-text `LIKE` search against subject/object IDs and event JSON).
- **Preconditions / gating:** none.
- **Step-by-step behavior:** dispatches to the shared `self.relationship_timeline(rest[0] if rest else "neighbor_link", opts, rel_type="neighbor_link")` (`core.py:4163-4164`). **Verified quirk, not documented anywhere else:** when no target argument is given, the literal string `"neighbor_link"` is used as the search target (not an empty/no-filter value) — this is passed into `relationship_timeline_payload`'s `target` parameter, which builds a `LIKE '%neighbor_link%'` clause against `subject_id`/`object_id`/`previous_json`/`current_json`. In practice this rarely matches real device/port identifiers, so a bare `netrune topology timeline` with no argument will typically return very few or zero rows — to see the general timeline you likely need `netrune topology timeline all` or a real target/IP/hostname substring. `rel_type` is always hard-pinned to `"neighbor_link"` regardless of what's passed.
- **Side effects:** None (read-only).
- **Output shape, table mode:** `render_table(rows, ["version", "version_label", "created_at", "event_type", "rel_type", "subject_id", "object_id", "source"])`.
- **Output shape, `--json` mode:** `{"ok": True, "target": str, "rows": [<relationship_events row + "version":int + "version_label":"version 1 (latest/current)"|"older version N">], "count": int, "chronology": "newest_first", "time_format": "ISO 8601 UTC", "latest_recorded_at": int|None, "latest_recorded_at_iso": str}`.
- **Exit codes:** `SUCCESS`(0) always (hardcoded, regardless of row count).
- **Real example:** `netrune topology timeline sw-idf-3`
  ```
  VERSION  VERSION_LABEL              CREATED_AT            EVENT_TYPE    REL_TYPE       SUBJECT_ID   OBJECT_ID    SOURCE
  1        version 1 (latest/current) 2026-08-27T09:14:02Z  first_seen    neighbor_link  198.51.100.12   sw-core-01   lldp-cdp-scan
  ```
- **Related commands:** `netrune topology changes` (a flatter, non-versioned event log for the same kind of change), `netrune memory timeline`/`memory device` (the general-purpose, non-topology-specific version of this same `relationship_events` mechanism), `netrune topology scan` (the source of these events).

---

### Cross-cutting notes

**Shared helpers with domains outside this scope (`lookup`, `path`, `diagnose`):**

- **`cached_switch_neighbors(device)`** (`core.py:4377-4410`) — reads the `neighbors` SQLite table both by local identity and by reverse (remote) identity, synthesizing mirrored rows so a lookup from either side of a link succeeds, then filters through `_switch_neighbor_evidence` (accepts only rows whose remote end is either a known inventory device or whose platform/capabilities/name text matches a switch-ish keyword regex). Within scope, only `vlan_cli.py`'s `inspect_vlan_node` calls it (feeding `vlan locate`/`vlan propagation`'s trunk-to-neighbor correlation). Outside scope: `lookup_cli.py:262` (the `lookup mac` port-resolution flow) and `core.py:4504` (`inspect_path_forwarding_node`, backing `netrune path inspect`) both call it to resolve the switch on the far end of a MAC's access port without a live LLDP/CDP probe unless the cache is missing.

- **`capture_batch(target, commands, timeout)`** (`core.py:4527-4568`) — runs several read-only commands in a *single* SSH login via `netrune-control show-batch`, splitting the combined transcript on embedded markers (`CMD_MARKER_RE`) rather than authenticating once per command. Within scope: `vlan_cli.py`'s `live_switch_neighbors` (LLDP+CDP together) and `topology_cli.py`'s `inspect_spanning_tree` (stp+cdp+trunk-summary together, and again for per-uplink LLDP detail reads) both use it — this is *the* reason `topology stp` and depth-traversing `vlan locate`/`propagation` runs cost one login per switch instead of three-to-six. Outside scope: `lookup_cli.py:193` (batches multiple MAC/ARP-adjacent reads for a single-switch `lookup mac` query) and `core.py:4667` inside `collect_path_capabilities` (backing `netrune path inspect`'s per-hop SVI/LAG/VRF/route/ARP evidence collection).

- **`_default_stp_jobs()`** (`core.py:4604-4608`) — reads `config.public["stp_scan_workers"]`, clamps to `1..8`, defaults `8`. Despite the STP-specific name, it's the shared default-parallelism knob for *any* thread-pooled multi-switch sweep. Within scope: only `topology_cli.py`'s `collect_spanning_tree_topology` (`topology stp`, further re-clamped to `min(jobs, 32, total)`). Outside scope: `lookup_cli.py:580` (the fan-out MAC-locate-across-all-switches path under `lookup mac <mac> all`/similar) and `core.py:6062` (a MAC-attached/transit parallel-probe routine, most likely backing `path`/`lookup`'s MAC-based switch search) both reuse the exact same clamp expression `max(1, min(jobs or self._default_stp_jobs(), 32, len(targets)))`.

- **`vault_session_scope(opts, minutes=30)`** (`core.py:4570-4602`, a context manager) — checks whether a vault session is already open (`vault_session_payload().active`); if not, and the session is genuinely interactive (`stdin`/`stderr` are ttys, and `NETRUNE_VAULT_NONINTERACTIVE`/`NETOPS_VAULT_NONINTERACTIVE` isn't set), runs `netrune-connect --unlock-vault --ttl <1..480 min>` in the foreground and yields whether it succeeded; on exit, if *it* was the one that opened the session, it always locks it again (`netrune-connect --lock-vault`), even on exception/interrupt. If it can't hold the vault open, it logs a plain warning and lets the caller continue authenticating per-device. Within scope, used by three of the 19 commands: `device config --confirm` (wraps `apply_device_config_change`), `vlan set --confirm` (wraps `apply_vlan_change`), and `topology stp` (wraps the entire parallel STP sweep — the one case here where it's opened around a *read-only* but many-switch operation, purely to avoid N separate biometric/PAM prompts). Outside scope, it's used even more broadly: `lookup_cli.py` (`lookup core`, and two/three separate spots in the MAC-locate family), `path_cli.py:134` (`path inspect --live`/`--hybrid`), and `diagnose_cli.py:866` (`diagnose cable`) all wrap their own multi-device or single-privileged reads in it, plus `core.py:6076` (the same MAC-attached/transit probe mentioned above).

**The guarded-configuration-lifecycle pattern (ADR 0005), concretely:**

ADR 0005's stated decision — *"Background configuration begins with typed VLAN assignment only... Direct helper writes require an internal marker supplied by the core. Arbitrary device configuration remains preview-only outside the synchronous guarded CLI."* — maps onto the source exactly as follows:

- The **"internal marker"** is `NETRUNE_CORE_WRITE_REQUEST` / `NETOPS_CORE_WRITE_REQUEST = "audited-confirmation"`, set in `child_env(opts)` (`core.py:3129-3131`) **only** when `opts.confirm` is true, and passed to every subprocess spawned thereafter (`self.capture`, `run_subprocess`, `run_vault_interactive` all route through `child_env`). This is the mechanism that stops an operator from getting a write executed by any path that doesn't go through the CLI's own `--confirm` gate — the external `netrune-control` helper is expected to refuse a config-mode operation unless it sees this env var, and only Netrune's own confirmed dispatch ever sets it.
- **`vlan set`** is the fully certified implementation: 4 phases (preflight → backup → apply → verify), a firmware-profile allow-list gate (`driver.capability("vlan_write")=="firmware-gated"` AND `device_writes_enabled` AND `detection.firmware_profile in driver.firmware_profiles`), sampled-but-bounded post-change read-back verification, and an audit event recording the full phase trail — this is what the ADR means by "typed VLAN assignment" being the one fully-lifecycled write today.
- **`device config`** implements the *same shape* of lifecycle (backup → apply → verify — 3 phases, no separate preflight since there's no single semantic pre-check for arbitrary commands the way there is for a VLAN assignment; the code comment on `apply_device_config_change` explains this explicitly) but its capability gate checks `driver.capability("configuration") == "supported"` — a value **no built-in driver ever sets** (Cisco IOS/NX-OS use `"firmware-gated"`; everything else `"unsupported"`; every plugin/declarative driver is force-set to `"unsupported"` at load time in `devices.py`). Combined with the fact that this gate is only even evaluated **when the target resolves in inventory** — an unresolved/out-of-inventory target skips the gate entirely and reaches the real guarded lifecycle — this is the concrete, source-verified sense in which ADR 0005 calls arbitrary device configuration "preview-only outside the synchronous guarded CLI": for any device Netrune actually knows about, `device config --confirm` is currently unreachable and always returns `UNSUPPORTED`; it can only truly execute against a target Netrune's inventory resolver doesn't recognize.
- Both lifecycles write their audit event via the same `record_audit_event` → `audit_events` table mechanism (ADR 0006's still-current "audit half"), with `event_type` values `vlan_change_finished` / `device_config_finished` and `action` values `vlan-set` / `device-config` respectively, `result` set to the lowercased final status word (`success`/`attention`), and `detail_json` carrying the full phase trail for later forensic review.

**Other cross-cutting behaviors worth flagging for the master reference:**

- `run_subprocess` and `capture`-based real (non-dry-run) execution **does not wrap output through `self.emit`/JSON** — the child process's stdout/stderr are inherited/streamed directly. This means `--json` has zero effect on the actual output of `device show`, `device ssh`, `device inventory`'s helper phase, `vlan locate`/`propagation`'s single-pair passthrough, and `topology scan`/`topology show`'s live-passthrough branch — only their `--dry-run` previews and the fully-Python-driven commands (guarded-lifecycle verbs, all SQLite-reading verbs, all cascade/multi-target verbs) genuinely honor `--json`.
- `render_table`'s registry-declared `output_type: "table"` is not a reliable guide to actual behavior: three of the four `device trust` write actions (`forget`, `enroll`) emit **plain prose**, never a table, despite the registry classification — only `trust status` and `trust scan` (when rows exist) actually call `render_table`. This should be treated as a documented exception when generating any UI/console surface from the registry alone.
- The interactive arrow-key device picker (`_select_row`, `core.py:3250-3304`) is currently wired into exactly one of these 19 commands — `device ssh` — despite being general-purpose machinery; none of the other ambiguous-target paths in this scope (`device identity`, `device config`, `vlan set`, `vlan locate`/`propagation`'s root resolution) use it, they all hard-error on ambiguity instead.

---

## 8. Lookup and Diagnose Domains


Source of truth: `netops_platform/lookup_cli.py` (`LookupCommandsMixin`), `netops_platform/diagnose_cli.py` (`DiagnoseCommandsMixin`), cross-referenced against `netops_platform/core.py` (`class App(DeviceCommandsMixin, InventoryCommandsMixin, VlanCommandsMixin, TopologyCommandsMixin, LookupCommandsMixin, DiagnoseCommandsMixin)`, line 2883), `netops_platform/mac_registry.py`, and `netops_platform/network.py`. Exit-code constants (`core.py` lines 171–180): `SUCCESS=0, USAGE=2, PARTIAL=3, UNREACHABLE=4, UNSUPPORTED=5, VALIDATION=6, CONFIRM_REQUIRED=7, AUTH=8, TIMEOUT=9, INTERNAL=10` (plus `130` interrupted, `143` terminated, both outside the app's own vocabulary).

Two conventions worth knowing before reading the sections below: `self.usage_error(noun, action, opts, message, suggestion="", code=USAGE)` defaults to exit code `2` (`USAGE`) whenever a call site omits the trailing `code` argument — several call sites below rely on that default rather than passing `VALIDATION` explicitly, and the two are **not interchangeable** in this codebase (I flag every place this matters). `self.emit(data, opts, text)` prints `json_dumps(data)` when `opts.json`, else `text` if given, else `self.render_plain(data)`.

---

### LOOKUP DOMAIN

#### `netrune lookup core` (id: `lookup-core`)
- **Purpose:** Resolve one IP or MAC by querying the configured core switch's ARP table, then its MAC forwarding table, then the learned interface — i.e., find "where does this address live" from the network's single point of truth.
- **Exact syntax:** `netrune lookup core <ip-or-mac>` — exactly one positional argument. No verb-specific flags are parsed inside `cmd_lookup`; only the global flags (`--json`, `--dry-run`, `--timeout`, etc.) apply.
- **Arguments:**
  - `target` (required): an IPv4 literal or a physical-unicast MAC. Validated twice — once by `cmd_lookup` (arg count) and once inside `core_lookup_workflow` (format). Missing arg → `"Missing IP or MAC."` (exit `USAGE=2`, not `VALIDATION` — no code passed to `usage_error`). More than one token → `"Core lookup accepts exactly one IP or MAC."` (exit `VALIDATION=6`). Unparseable target (`norm_mac` returns empty AND `is_ipv4_literal(normalize_target_literal(target))` is false) → `"Target must be an IP address or physical unicast MAC."` (`VALIDATION`).
- **Preconditions / gating:** Requires `core_switch_ip` (or legacy `core_switch`) set in config — if empty: `"No core switch is configured."`, suggestion `"Set core_switch_ip, then run: netrune lookup core 198.51.100.92"` (`VALIDATION`). The configured core value is then resolved via `self.resolve_device_record(configured_core)`; if that returns no unique row, and the raw configured string is itself not a valid IPv4 literal, it errors `"Core switch could not be resolved safely."` plus up to 8 candidate labels (`VALIDATION`). No `--confirm`/`--dry-run` gate on execution (it's read-only), but `--dry-run` short-circuits before any command runs.
- **Step-by-step behavior:**
  1. `cmd_lookup` enters `with self.vault_session_scope(opts, minutes=30):` — the entire workflow runs inside one held-open vault session.
  2. `core_lookup_workflow` classifies the core switch's driver via `self.detect_device_family(...)` / `self.driver_for(...)`. If family is `"unknown"`, it runs `show version` on the core (`self.capture(self.legacy_cmd("netrune-control","show",core_ip,"show version"), opts.timeout or 90)`) and re-detects from the sysdescr text. If still unknown and the version command itself failed (`version_rc != 0`), aborts with `UNSUPPORTED`.
  3. If the resolved driver has no `arp_lookup` command template, aborts with `UNSUPPORTED` ("The core platform has no registered ARP lookup capability.").
  4. Builds a vendor-specific ARP lookup value: for a MAC target, formats per family (`cisco-ios`→dotted, `aruba-aos-switch`→`xxxxxx-xxxxxx`, `aruba-aos-cx`→colon, `ruckus-fastiron`→plain, default→colon); for an IP target, uses the IP directly.
  5. Runs the ARP command on the core (`self.capture(self.legacy_cmd("netrune-control","show",core_ip,arp_command), opts.timeout or 120)`), parses with `parse_arp_output`.
  6. If a MAC was found (from ARP result or from the original target), runs the switch forwarding-table lookup (`netrune-control mac-lookup <core_ip> <dotted-mac>`), parses with `parse_mac_table_output`.
  7. If a port was learned, validates it against `r"[A-Za-z0-9][A-Za-z0-9./:_-]{0,63}"` (silently discarding it if it fails — this is a security guard: "a malformed table row could append a second CLI command," per the inline comment) and, if the driver has an `interface_health` template, runs it on the core to pull the interface description.
  8. Records the combined evidence via `self.state.record_core_lookup(raw_target, combined_evidence, exit_code)` and, if a forwarding-table row was found, `self.state.record_mac_observation(...)`.
- **Side effects:** SQLite writes to `core_lookup_cache` (raw evidence blob, redacted) and `relationships_current`/`relationship_events` (via `record_core_lookup`'s IP/MAC extraction from the evidence text, `rel_type="core_lookup"`); if a forwarding-table hit was found, also to `relationships_current`/`relationship_events` with `rel_type="mac_location"` via `record_mac_observation`. Uses `vault_session_scope` (single core device, but 2–4 sequential SSH reads, so the session is held to avoid re-authenticating per read). Helper invoked: `netrune-control` (via `legacy_cmd`), subcommands `show` (×2–3) and `mac-lookup`.
- **Output shape, table mode:** No `render_table` call — the payload is a single dict, rendered as hand-built text (`f"Core lookup: {status}\n..."`), not a row table.
- **Output shape, `--json` mode:** top-level keys: `ok, complete, status, query, core{ip,name,platform}, driver_family, ip, mac, oui, vendor, vlan, port, description, arp, forwarding_table, commands{arp,interface}, exit_codes{arp,mac,interface}, observed_at, observed_at_iso`. `status` is one of `FOUND` (fdb hit), `ARP_ONLY` (ARP hit but no fdb entry), `NOT_FOUND`.
- **Exit codes:**
  - `USAGE` (2): no target given.
  - `VALIDATION` (6): >1 token; malformed target; no core configured; core doesn't resolve safely.
  - `UNSUPPORTED` (5): driver family still unknown after `show version` and that command failed; or driver has no `arp_lookup` capability.
  - `SUCCESS` (0): `--dry-run`; or live run where `payload["complete"]` is true (`fdb_rows` and `port` both present).
  - `PARTIAL` (3): live run where ARP or fdb evidence exists but is incomplete (ARP-only, or fdb without a usable port).
- **Real example:** `netrune lookup core 198.51.100.92` → text:
  ```
  Core lookup: FOUND
  Core: CORE01 (192.0.2.1) | Driver: cisco-ios
  IP: 198.51.100.92 | MAC: 0200.0000.0025 | VLAN: 40 | Port: Gi1/0/12
  Vendor/OUI: Some Vendor Inc.
  Description: printroom-printer
  Recorded: 2026-08-28T13:00:00Z
  ```
- **Related commands:** Often the first step before `netrune diagnose port-health <device> on <interface>` or `netrune diagnose cable <device> on <interface>` once the port is known. For a MAC-first workflow (no known IP), `netrune lookup mac locate <mac>` is the equivalent starting point since it doesn't require a core-switch ARP hit.

---

#### `netrune lookup mac` (id: `lookup-mac`)
- **Purpose:** Run a single MAC-address forwarding-table lookup against exactly one named switch/target, passed straight through to the legacy `netrune-control mac-lookup` helper (this is the "manual, single-target" MAC lookup, distinct from the cached-evidence and multi-switch-search variants below).
- **Exact syntax:** `netrune lookup mac <target> <mac>` — this is the fallback branch of `cmd_lookup`'s `"mac"` verb, reached only when the first token after `mac` is **not** one of the recognized subactions (`registry`, `inspect`, `vendor`, `online`, `history`, `locate`, `profile`), **not** the literal word `all`, and the remaining tokens are **not** exactly one bare valid MAC. `--jobs N` (1–32) may appear anywhere in the argument list and is stripped before dispatch (it only matters if `--all` is also passed). If the global `--all` flag is set, this same call is instead routed to `lookup_mac_all(rest[-1], opts, pattern=" ".join(rest[:-1]), jobs=mac_jobs)` — i.e. every token except the last is treated as a substring filter on switch hostname/IP/platform/model, and the last token is the MAC.
- **Arguments:** `target` and `mac` (both required, positional, forwarded verbatim to the legacy helper — **not** resolved through `resolve_device_record`). No dedicated usage-error message exists for this exact shape besides the domain-level `"Missing MAC address."` (`USAGE`, default code) if `rest` is empty entirely.
- **Preconditions / gating:** None beyond having at least one token after `mac`. This path does **not** use `vault_session_scope`.
- **Step-by-step behavior:** `cmd=self.legacy_cmd("netrune-control","mac-lookup",*rest)`; `rc,out,err=self.capture(cmd, opts.timeout or 120)`; records to SQLite (`self.state.record_core_lookup(" ".join(rest), text, rc)`); then, **critically**, this branch does not go through `self.emit`'s text path — in JSON mode it calls `self.emit({"ok":rc==0,"target":" ".join(rest),"exit_code":rc,"output":out,"stderr":err}, opts)` (no `text` arg, so `emit` prints JSON regardless), but in plain-text mode it bypasses `emit` entirely and just does `print(out, end="")` / `eprint(err.rstrip())` — raw passthrough of the legacy helper's own output.
- **Side effects:** SQLite write to `core_lookup_cache` plus MAC/IP relationship rows extracted from the raw output (same mechanism as `lookup core`, via `record_core_lookup`). Helper: `netrune-control mac-lookup <target> <mac>`.
- **Output shape, table mode:** None — raw stdout/stderr of the legacy helper, unmodified.
- **Output shape, `--json` mode:** `{ok, target, exit_code, output, stderr}` — a flat wrapper around the raw helper output, not a structured lookup result.
- **Exit codes:** The **raw subprocess exit code** from `netrune-control`, passed through `normalized_exit_code` (negative/signal codes become `128+abs(code)`; `None` becomes `INTERNAL`). This is **not** one of the domain's semantic constants — a "found" result is whatever `netrune-control` itself considers exit 0, which need not align with `SUCCESS=0` conceptually (it does numerically, but there's no `PARTIAL`/`UNREACHABLE` here at all, just the raw helper code, or `USAGE=2` if `rest` was empty).
- **Real example:** `netrune lookup mac ZONE34 0200.0000.0025` — output is literally the switch CLI's MAC-table grep output, not a Netrune-rendered table.
- **Related commands:** `netrune lookup mac all <mac>` and `netrune lookup mac locate <mac>` are the structured, multi-switch alternatives to this raw single-target form; prefer those for anything beyond ad hoc single-switch debugging.

---

#### `netrune lookup mac all` (id: `lookup-mac-all`)
- **Purpose:** Fan out a MAC forwarding-table search across every online switch in inventory (or a filtered subset), and separate the one access port the device is actually attached to from the uplink ports it merely transits.
- **Exact syntax:** `netrune lookup mac all <mac> [--jobs N]`. `--jobs` (1–32) may appear anywhere in the token stream; if present but malformed/out of range: `"--jobs requires a number between 1 and 32."` (`VALIDATION`). `<mac>` must follow `all` with `len(rest) >= 2` else `"Missing MAC address after all."` (`USAGE`, default code).
- **Arguments:** `mac` (required). No explicit pattern argument in this literal `all` form — the pattern-filtered variant is only reachable via the global `--all` flag on the bare `lookup mac <pattern...> <mac> --all` form (see `lookup-mac` above), which calls the same underlying `lookup_mac_all` with a non-empty `pattern`.
- **Preconditions / gating:** `self.canonical_mac(mac,"dotted")` must produce a non-empty MAC (falls back to `mac.strip()` if canonicalization fails, then checked for truthiness) — empty → `"Missing MAC address."` (`USAGE`, default). Target set is `self.current_switch_targets(opts, pattern)`: devices from the `devices` table where `status != OFFLINE` (or `= opts.status` if `--status` given), optionally filtered by hostname/ip/platform/model substring, `LIMIT opts.limit`. Zero matching switches → `PARTIAL` with `"No current online switch targets matched."`. `--dry-run` prints the planned per-switch commands and returns `SUCCESS` without probing anything.
- **Step-by-step behavior:**
  1. Compute `uplinks = self.known_uplink_ports()` — reads the most recent STP capability-evidence facts (`capability_evidence` table, `capability='stp'`) per device to build a set of known uplink interfaces per switch. This is the topology-derived signal used for attached-vs-transit classification.
  2. Compute worker count: `max(1, min(jobs or self._default_stp_jobs(), 32, len(targets)))`.
  3. `with self.vault_session_scope(opts, minutes=30):` opens one held vault session for the whole fan-out (this is the textbook multi-device case the session exists for).
  4. Inside, a `ThreadPoolExecutor` (`thread_name_prefix="macfan"`) submits one `probe(row)` per target, each doing a single `self.capture(self.legacy_cmd("netrune-control","mac-lookup",ip,mac), opts.timeout or 90)` and parsing with `parse_mac_table_output`. Progress is reported per completion via `self._progress_step("lookup mac", name, completed, len(targets), opts)`, cleared in a `finally`.
  5. Results are re-sorted back into original target order (thread completion order is nondeterministic).
  6. For every parsed hit, `self.state.record_mac_observation(...)` is called, and the hit's port is classified `"transit"` if `normalize_interface(port)` is in that switch's `uplinks` set, else `"attached"`.
  7. Also calls `self.mac_history_rows(mac)` to append previously-recorded switch-port evidence (from `relationships_current` where `rel_type='mac_location'`) below the live results.
- **Side effects:** SQLite writes: `core_lookup_cache` (one row per switch probed, via `record_core_lookup`), `relationships_current`/`relationship_events` (`rel_type='mac_location'`, one upsert per hit, via `record_mac_observation`). `vault_session_scope` held for the whole fan-out. Helper: `netrune-control mac-lookup <switch-ip> <mac>`, one process per switch, run concurrently.
- **Output shape, table mode:** Multiple `render_table` calls stitched into one text block: attached hits → `["switch","switch_ip","port","vlan","entry_type"]`; transit hits (same columns) if any; history → `["switch","port","vlan","source","status","last_seen"]`. Dry-run rows → `["target","ip","command"]`.
- **Output shape, `--json` mode:** top-level keys: `ok, scope, mac, oui, vendor, attached, transit, hits, history, rows, count, found, searched, parallel_jobs, uplink_data_available`. `rows` is the per-switch probe summary (`status, target, ip, exit_code, excerpt`); `hits` is the flattened, classified forwarding-table entries.
- **Exit codes:** `USAGE` (2) missing MAC; `VALIDATION` (6) bad `--jobs`; `SUCCESS` (0) dry-run, or `PARTIAL` (3) if `not targets`; then final: `SUCCESS` if `hits` non-empty, else `PARTIAL`.
- **Real example:** `netrune lookup mac all 0200.0000.0025` — table shows the MAC attached on exactly one access switch/port, with any other switches that saw it in transit listed separately under "Seen in transit".
- **Related commands:** `netrune topology stp` should be run first if `uplink_data_available` comes back false ("No uplink data yet, so attachment cannot be separated from transit" is printed verbatim in that case). Compare against `lookup mac locate` — that command uses a *different* attached/transit heuristic (cached LLDP/CDP neighbor presence on the port, not STP uplink membership); the two are not guaranteed to agree.

---

#### `netrune lookup mac locate` (id: `lookup-mac-locate`)
- **Purpose:** Search switch forwarding tables directly for a MAC without needing a known endpoint IP or a core-switch ARP hit first — the go-to command when only a MAC address is known.
- **Exact syntax:** `netrune lookup mac locate <mac> [<scope>]`. `scope` is an optional third positional token, only treated as a scope value if it does not start with `--` (`scope=rest[2] if len(rest)>2 and not rest[2].startswith("--") else "all"`).
- **Arguments:** `mac` (required) — missing → `"Missing MAC address."` (`USAGE`, default, message templated as `f"Missing MAC address."` via the shared `subaction in {...}` branch, suggestion `netrune lookup mac locate 0200.0000.0025`). Inside `locate_mac_live`, if `norm_mac(mac_value)` fails: `"MAC must be a valid physical unicast address."` (`VALIDATION`). `scope` (optional) — a switch identifier or the literal `all`/synonym recognized by `is_all_keyword`; if given and non-"all" but `resolve_device_record(scope)` doesn't return a unique row: `"Switch scope could not be resolved uniquely: {scope}"` plus up to 8 candidate labels (`VALIDATION`).
- **Preconditions / gating:** Read-only; `--dry-run` prints the per-switch command plan and returns `SUCCESS`. If the target switch set (after scope resolution) is empty: `PARTIAL` with `"No current online switch targets matched."`.
- **Step-by-step behavior:**
  1. `cmd_lookup` wraps the whole call in `with self.vault_session_scope(opts, minutes=30):`.
  2. `locate_mac_live` resolves the switch target set: either the single scoped device, or (scope `all`/omitted) `self.current_switch_targets(opts, opts.site)`.
  3. If `core_switch_ip` is configured, first queries the core for ARP/MAC evidence (`netrune-control core-lookup <colon-mac>`) and records it via `self.state.record_core_lookup`.
  4. Sequentially (not threaded, unlike `mac all`) probes every target switch with `netrune-control mac-lookup <switch-ip> <dotted-mac>`, parses hits, and for each hit looks up `self.cached_switch_neighbors(row)` and calls `self._neighbor_on_port(neighbors, port)` — if a cached LLDP/CDP neighbor exists on that exact port, the hit is classified `role="switch-link"`; otherwise `role="edge-candidate"`. This is a **different heuristic** from `lookup mac all`'s STP-uplink-based attached/transit split.
  5. Every hit is recorded via `self.state.record_mac_observation(...)`.
  6. If `profile=True` (only reached via the `profile` subaction, see next section), up to the first 3 `edge-candidate` hits get a deep per-port evidence pull via `self.profile_mac_port(hit, opts)`.
  7. Merges IP evidence from the core-lookup output, from any profile results, and from `self.mac_cached_payload(clean, opts.limit)` (prior cached evidence) into one `ip_candidates` list, and similarly merges `model_hints`.
- **Side effects:** SQLite: `core_lookup_cache` (one row for the core query if configured, `relationships_current` `rel_type='core_lookup'`), `relationships_current`/`relationship_events` `rel_type='mac_location'` (one upsert per forwarding-table hit). `vault_session_scope` held across the core query and the sequential per-switch probes. Helpers: `netrune-control core-lookup <mac>` (if core configured), `netrune-control mac-lookup <switch-ip> <mac>` (once per target switch).
- **Output shape, table mode:** Main hits table columns: `["role","switch_name","switch_ip","vlan","port","entry_type","neighbor_name","observed_at"]`. Dry-run rows: `["switch","ip","command"]`.
- **Output shape, `--json` mode:** top-level keys: `ok, mode ("mac-locate"), mac, scope, oui, hits, likely_edge_locations, profiles, ip_candidates, model_hints, layer2_present, ip_evidence_present, assessment, errors, counts{switches_checked,hits,edge_candidates,errors}, observed_at, observed_at_iso, limitations`.
- **Exit codes:** `USAGE` (2) missing MAC; `VALIDATION` (6) bad MAC format, or ambiguous scope; `SUCCESS` (0) dry-run, or live run with `PARTIAL` (3) if no targets, else `SUCCESS` if any hits were found, `PARTIAL` if none.
- **Real example:** `netrune lookup mac locate 0200.0000.0025` — table lists every switch that saw the MAC, tagging each row `switch-link` or `edge-candidate`; text summary states counted checks, hits, likely edges, IP evidence, and an assessment sentence.
- **Related commands:** Natural sequence for a full trace: `lookup mac locate <mac>` → `lookup mac profile <mac>` (adds LLDP/CDP/PoE/device-tracking evidence at the likely edge) → `lookup mac history <mac>` (movement over time) → `lookup mac inspect <mac>` (single-shot correlation of everything cached, no live probing).

---

#### `netrune lookup mac profile` (id: `lookup-mac-profile`)
- **Purpose:** Everything `lookup mac locate` does, plus a deep, batched evidence pull (interface status, LLDP/CDP neighbor, PoE, device-tracking, 802.1X session, ARP) on up to the first 3 likely edge ports found.
- **Exact syntax:** `netrune lookup mac profile <mac> [<scope>]` — identical CLI shape to `mac locate`; the only difference is `profile=True` is passed to `locate_mac_live`.
- **Arguments / preconditions / gating:** Identical to `lookup mac locate` above (same validation, same scope resolution, same dry-run/empty-target handling).
- **Step-by-step behavior:** Same as `mac locate` steps 1–6, plus:
  1. `edge_hits = [row for row in hits if row.get("role")=="edge-candidate"][:3]` — only the first 3 non-switch-link hits are profiled (cost control: each profile call is itself an extra SSH login).
  2. For each, `self.profile_mac_port(hit, opts)`: builds a vendor-specific command list via `self._mac_profile_commands(platform, port, mac)` — Aruba/HP families get `{interface, lldp, poe, arp}`; everything else (Cisco-style) gets `{interface, lldp, cdp, poe, device_tracking, authentication}`. The port name is validated against `r"[A-Za-z0-9][A-Za-z0-9./:_-]{0,63}"` first — an invalid port yields an empty command list (no commands run, no evidence). All commands for one switch are sent in **one SSH login** via `self.capture_batch(switch_ip, commands, opts.timeout or 90)`, explicitly to avoid "four to six" separate authentications per port (per the inline comment).
  3. Each command's output is parsed for extracted IPs (`extract_ip_candidates`), neighbor platform/name hints (`parse_neighbor_detail_output`), and a `description`/`name` line via regex.
- **Side effects:** Same SQLite writes as `mac locate` (`core_lookup_cache`, `relationships_current`/`relationship_events` `mac_location`), plus no additional table writes from the profiling step itself (its evidence lives only in the response payload, not persisted to SQLite). Helper: `netrune-control show-batch <switch-ip> <cmd1> <cmd2> ...` — one batched SSH session per profiled edge port (up to 3 extra logins total), in addition to the same core-query and per-switch mac-lookup calls as `mac locate`.
- **Output shape, table mode:** Same hits table as `mac locate`, plus an "Edge profile" section: `["switch_name","switch_ip","port","description","ip_candidates","model_hints"]`.
- **Output shape, `--json` mode:** Same keys as `mac locate`, with `mode` = `"mac-profile"` and `profiles` populated (each profile entry: `switch_ip, switch_name, port, description, ip_candidates, model_hints, evidence[{type,command,exit_code,excerpt}]`).
- **Exit codes:** Identical set/conditions to `lookup mac locate`.
- **Real example:** `netrune lookup mac profile 0200.0000.0025` — same top table as `locate`, plus a second "Edge profile" table showing the port description and any IPs/model hints scraped from LLDP/CDP/ARP output on the likely-edge port(s).
- **Related commands:** Follows `lookup mac locate` in the natural workflow; typically followed by `netrune diagnose port-health <switch> on <port>` or `netrune diagnose cable <switch> on <port>` once the edge port is confirmed.

---

#### `netrune lookup mac history` (id: `lookup-mac-history`)
- **Purpose:** Show newest-first identity and switch-port change events recorded for a MAC, without touching the network.
- **Exact syntax:** `netrune lookup mac history <mac>` — no other flags parsed.
- **Arguments:** `mac` (required) — missing → `"Missing MAC address."` (`USAGE`, default). Malformed MAC (raised inside `mac_cached_payload` as `ValueError`) → `"MAC must be a valid physical unicast address."` (`VALIDATION`).
- **Preconditions / gating:** Purely a SQLite read; no dry-run/confirm concept applies (registry marks `writes_local: false`, `state_effects: []`).
- **Step-by-step behavior:** Calls `self.mac_cached_payload(mac, opts.limit)` (see below), then combines `relationship_history` + `inventory_history` from that payload, sorts by `(created_at, id)` descending, and slices to `opts.limit`. No live network calls at all — this is a pure read of `relationship_events` and `inventory_history`.
- **Side effects:** None — no SQLite writes, no subprocess calls, no vault interaction.
- **Output shape, table mode:** `self.render_table(payload["rows"], ["version_label","created_at","event_type","rel_type","subject_id","object_id","switch_ip","switch_port","source"])`. `version_label` and `version` are added by `self.version_rows(...)` inside `mac_cached_payload` (`"version 1 (latest/current)"` for the newest row, `"older version N"` thereafter). Note the column list is shared across two different underlying record shapes (`relationship_events` and `inventory_history` rows), so some columns will be blank depending on which table a given row came from.
- **Output shape, `--json` mode:** the full `mac_cached_payload` dict (see `lookup mac inspect` below for its full key list) plus `rows` (the combined, sorted, limited list) and `count`.
- **Exit codes:** `USAGE` (2) missing MAC; `VALIDATION` (6) malformed MAC; `SUCCESS` (0) if `combined` non-empty, else `PARTIAL` (3).
- **Real example:** `netrune lookup mac history 0200.0000.0025 --limit 20` — table of the most recent 20 identity/location events for that MAC, newest first.
- **Related commands:** Pairs with `lookup mac locate`/`lookup mac profile` (live search) and `lookup mac inspect` (single-shot cached correlation) to build a complete before/after picture of a device's movement.

---

#### `netrune lookup mac inspect` (id: `lookup-mac-inspect`)
- **Purpose:** Correlate every piece of cached evidence about a MAC (inventory identity, current L2 location, IP correlation, OUI vendor, and prior core-lookup evidence) into one assessment, entirely from SQLite — no live probing.
- **Exact syntax:** `netrune lookup mac inspect <mac>` — no other flags.
- **Arguments:** `mac` (required) — missing → `"Missing MAC address."` (`USAGE`, default). Malformed → `"MAC must be a valid physical unicast address."` (`VALIDATION`, raised as `ValueError` inside `mac_cached_payload` and caught here).
- **Preconditions / gating:** Pure read; no gating.
- **Step-by-step behavior:** `mac_cached_payload(mac, opts.limit)`:
  1. Computes 3 MAC string representations (dotted/colon/hyphen) to match against loosely-formatted stored text.
  2. Queries `devices` and `aps` tables for exact MAC match (normalized comparison via a nested SQL `replace()` chain).
  3. Queries `inventory_history` for MAC or identity-value match (limited, versioned via `version_rows`).
  4. Queries `relationships_current` (current state) and `relationship_events` (history) for subject-id match or a substring match against `attrs_json`.
  5. Queries `core_lookup_cache` for target match or the MAC appearing anywhere in stored `output` text (dotted/colon/hyphen forms).
  6. Aggregates IP candidates from device/AP rows and from `extract_ip_candidates()` run over every matching cache row's output.
  7. Computes an `assessment` string from 4 mutually exclusive cases: L2-only ("no current IP correlation... consistent with a device that has not obtained an IP"), L2+IP ("both are present"), inventory-only-no-L2 ("no current structured switch-port observation is cached"), or nothing ("Run MAC locate for a direct forwarding-table search").
- **Side effects:** None (read-only against `devices`, `aps`, `inventory_history`, `relationships_current`, `relationship_events`, `core_lookup_cache`).
- **Output shape, table mode:** `render_mac_cached(payload)` builds two tables: "Current L2 locations" → `["switch_name","switch_ip","switch_port","status","source","last_seen"]`; "Inventory identities" → `["kind","name","ip","platform","model","status","last_seen"]`, both preceded by a text header (mac, vendor/OUI, IP evidence, assessment, last recorded).
- **Output shape, `--json` mode:** top-level keys: `ok, mac, mac_colon, oui, inventory, current_locations, relationships, inventory_history, relationship_history, core_lookup_evidence, ip_candidates, model_hints, layer2_present, ip_evidence_present, assessment, last_recorded_at, last_recorded_at_iso, chronology ("newest_first"), time_format ("ISO 8601 UTC"), limitations`.
- **Exit codes:** `USAGE` (2) missing MAC; `VALIDATION` (6) malformed MAC; `SUCCESS` (0) if `ok` (any of devices/aps/relationships/cache_rows non-empty), else `PARTIAL` (3).
- **Real example:** `netrune lookup mac inspect 0200.0000.0025` — a two-table dossier plus a one-line network-forensics assessment.
- **Related commands:** The read-only endpoint of the mac-* family; typically run last after `mac locate`/`mac profile` have populated fresh evidence, or run first as a zero-cost check before deciding whether a live search is even needed.

---

#### `netrune lookup mac vendor` (id: `lookup-mac-vendor`)
- **Purpose:** Resolve a MAC's OUI/vendor from the locally installed OUI database file (`nmap-mac-prefixes` or `ieee-data`/`misc` `oui.txt`), with no network access by default.
- **Exact syntax:** `netrune lookup mac vendor <mac> [--online|--refresh] [--offline]`. This verb shares its implementation with `mac online` (see below): both land in the same `if subaction in {"vendor","online"}:` block in `cmd_lookup`, and `vendor` is only "local-only" when neither `--online` nor `--refresh` is passed. `mac vendor <mac> --online` will actually run the full IEEE registry lookup, identical to `mac online <mac>`.
- **Arguments:** `mac` (required) — missing → `f"Missing MAC address."` (`USAGE`, default). Malformed (`norm_mac` fails) → `"MAC must be a valid physical unicast address."` (`VALIDATION`). Flags after the MAC are collected into a set and checked against `{"--online","--refresh","--offline"}`; anything else → `f"Unknown MAC vendor option: {flag}"` (`VALIDATION`, sorted-first offender named).
- **Preconditions / gating:** None beyond MAC validity; this is always read-only regardless of flags.
- **Step-by-step behavior (local path, no `--online`/`--refresh`):** `lookup_oui(clean)` — checks, in order, `/usr/share/nmap/nmap-mac-prefixes`, `/usr/share/ieee-data/oui.txt`, `/usr/share/misc/oui.txt`, trying progressively shorter MAC prefixes (12 down to 6 hex chars) against each file's table until a match is found.
- **Side effects:** None — no SQLite writes, no network. (When escalated to the online path via `--online`/`--refresh`, see `mac online` below for its side effects.)
- **Output shape, table mode:** No table — single-line text: `f"{mac}: {vendor} ({prefix or 'no prefix match'})\n{note}"`.
- **Output shape, `--json` mode:** `{ok: true, mac, oui: {prefix, vendor, source}, note}`. The `note` field explicitly points at `mac online` for authoritative data: `"Local OUI data identifies the registered organization, not an exact model. Use 'netrune lookup mac online <mac>' for the cached IEEE MA-L/MA-M/MA-S registries."`
- **Exit codes:** `USAGE` (2) missing MAC; `VALIDATION` (6) bad MAC format or unknown flag; `SUCCESS` (0) always for the local-only path (no failure mode once the MAC is valid — `Unknown` vendor is still `SUCCESS`).
- **Real example:** `netrune lookup mac vendor 00:00:5e:00:53:01` → `00.00.5e.00.53.01: IANA (00005e)`.
- **Related commands:** `lookup mac online` for authoritative/refreshable IEEE data; `lookup mac registry status`/`refresh` to manage the underlying IEEE cache the online path reads from.

---

#### `netrune lookup mac online` (id: `lookup-mac-online`)
- **Purpose:** Resolve the longest matching authoritative IEEE MA-L/MA-M/MA-S assignment for a MAC from the locally cached IEEE registry CSVs, refreshing them from IEEE if stale or online lookup is requested.
- **Exact syntax:** `netrune lookup mac online <mac> [--refresh] [--offline]`. (`--online` is also accepted here as a no-op flag since `subaction=="online"` already forces the online path.)
- **Arguments:** `mac` (required, same missing/malformed handling as `mac vendor`). Flags restricted to `{--online, --refresh, --offline}`, same unknown-flag error as `mac vendor`.
- **Preconditions / gating:** `--dry-run` prints the equivalent CLI invocation and returns `SUCCESS` without touching the registry. Otherwise always attempts the lookup; network access to IEEE only happens if the cache is stale (default max age 7 days) or `--refresh` forces it, and only if `--offline` was **not** passed (`online=not offline` inside `IeeeMacRegistry.lookup`).
- **Step-by-step behavior (`lookup_ieee_mac` → `IeeeMacRegistry.lookup`):**
  1. Normalizes the MAC (`normalize_lookup_mac`); rejects all-zero/broadcast.
  2. If the address is locally-administered (bit 1 of the first octet set), short-circuits with `found: False` and a note that locally-administered/randomized MACs have no IEEE assignment — no cache access at all.
  3. Otherwise, if `online` and (`force_refresh` or any of the 3 registries — MA-L/oui.csv, MA-M/mam.csv, MA-S/oui36.csv — is stale beyond `max_age_seconds`), calls `self.refresh(...)`, which downloads each stale/missing source from `https://standards-oui.ieee.org/...`, validates the CSV shape (`assignment`+`organization name` columns present, at least 1 well-formed assignment row), and atomically writes it to the cache dir (`mode=0o600`, dir `mode=0o700`) plus a `manifest.json` with per-registry `sha256`/`fetched_at`/`rows`.
  4. Scans all 3 cached CSVs for assignments that are a prefix of the MAC, picks the longest-prefix match (most specific: MA-S 36-bit > MA-M 28-bit > MA-L 24-bit).
  5. `payload["local_fallback"] = lookup_oui(clean)` is always attached in addition to the IEEE result, for comparison.
- **Side effects:** Files written: `<mac_registry_dir>/oui.csv`, `mam.csv`, `oui36.csv`, and `manifest.json` (only when a refresh actually occurs). No SQLite writes at all for this command (registry marks `state_effects: [local-state, sqlite]` but the sqlite write component doesn't actually apply to `mac-online`/`mac-vendor` — verified: neither code path calls any `self.state.record_*` method). Network: HTTPS GET to `standards-oui.ieee.org` per stale/forced registry, only when online mode is in effect.
- **Output shape, table mode:** No table — multi-line text: MAC, organization; registry/assignment/prefix-bits/block-size; organization address; registry recorded timestamp; provider/URL; note.
- **Output shape, `--json` mode:** keys from `IeeeMacRegistry.lookup`: `ok, found, mac, address_type, provider, provider_url, registry_updated_at, registry_updated_at_iso, refresh, note`, plus on a match: `registry, prefix_bits, assignment, organization, organization_address, source_url, cache_path, block_size`; plus always `local_fallback` (the `lookup_oui` result).
- **Exit codes:** `USAGE` (2) missing MAC; `VALIDATION` (6) bad MAC/flags, or a `ValueError` from `lookup_ieee_mac` (e.g. broadcast/all-zero MAC) caught and reported as `VALIDATION`; `SUCCESS` (0) for `--dry-run`; `SUCCESS` if `payload.get("ok")` else `PARTIAL` (3) — note `ok` here is true even for an unmatched-but-cache-present result (`ok = bool(match) or any cache file exists`), so `PARTIAL` really means "no cache at all yet."
- **Real example:** `netrune lookup mac online 00:00:5e:00:53:01` → `00:00:5e:00:53:01: IANA` with registry `MA-L`, block size `16777216`.
- **Related commands:** Depends on `lookup mac registry status`/`refresh` for the underlying cache; `lookup mac vendor` is the always-local, non-network sibling.

---

#### `netrune lookup mac registry status` (id: `lookup-mac-registry`)
- **Purpose:** Show what's currently cached in the local IEEE registry mirror — which of the 3 registries are present, row counts, checksums, and last-refresh time — without touching the network.
- **Exact syntax:** `netrune lookup mac registry status` (also the default when `netrune lookup mac registry` is given with no further action token — `action = rest[1].lower() if len(rest) > 1 else "status"`). No arguments accepted.
- **Arguments:** None. Any action word other than `status`/`refresh` → `f"Unknown registry action: {action}"` (`VALIDATION`).
- **Preconditions / gating:** None — pure local file read (`registry._manifest()` reads `manifest.json` from `self.paths.mac_registry_dir`).
- **Step-by-step behavior:** Reads and parses `manifest.json` (or returns an empty default shape if absent/corrupt), lists its `registries` dict values as rows.
- **Side effects:** None — no writes, no network.
- **Output shape, table mode:** `render_table(rows, ["registry","prefix_bits","rows","fetched_at_iso","sha256"])`, only if rows exist; otherwise plain text `"No registry cache exists. Run: netrune lookup mac registry refresh"`.
- **Output shape, `--json` mode:** `{ok, provider, provider_url, updated_at, updated_at_iso, rows, cache_dir}`.
- **Exit codes:** `SUCCESS` (0) if rows exist, else `PARTIAL` (3). `VALIDATION` (6) only reachable via an unrecognized action word (not reachable through the literal `status` path itself).
- **Real example:** `netrune lookup mac registry status` → table of MA-L/MA-M/MA-S rows with their fetch timestamps and SHA-256s, or the "no cache" message on a fresh install.
- **Related commands:** `lookup mac registry refresh` to populate it; `lookup mac online` is the consumer.

---

#### `netrune lookup mac registry refresh` (id: `lookup-mac-registry-refresh`)
- **Purpose:** Force-download all 3 IEEE public MAC-assignment CSVs (MA-L, MA-M, MA-S) into the local cache, bypassing the normal 7-day staleness check.
- **Exact syntax:** `netrune lookup mac registry refresh` — no arguments.
- **Arguments:** None.
- **Preconditions / gating:** `--dry-run` emits `{"ok":true,"dry_run":true,"command":"netrune lookup mac registry refresh"}` and returns `SUCCESS` without any network call. No `--confirm` gate (registry marks it `risk_level: safe`, read-only from the target network's perspective — it only talks to `standards.ieee.org`, never a managed device).
- **Step-by-step behavior:** `registry.refresh(force=True, timeout=opts.timeout or 15)` — see the download/validate/atomic-write sequence documented under `mac online` above, run unconditionally for all 3 sources regardless of current freshness.
- **Side effects:** Files written: `oui.csv`, `mam.csv`, `oui36.csv`, `manifest.json` under `self.paths.mac_registry_dir` (dir mode `0700`, files mode `0600`, atomic replace via a tempfile in the same directory). No SQLite writes. Network: 3 HTTPS GETs to `standards-oui.ieee.org`, each capped at 32 MiB and validated for CSV shape before being trusted.
- **Output shape, table mode:** `render_table(payload["rows"], ["registry","status","rows","fetched_at_iso","error"])` — `status` per row is one of `cached` (fresh, skipped), `downloaded`, `stale-cache` (download failed but an old copy exists), or `failed`.
- **Output shape, `--json` mode:** `{ok, complete, provider, provider_url, rows, errors, available_registries, required_registries, recorded_at, recorded_at_iso}`.
- **Exit codes:** `SUCCESS` (0) for `--dry-run`, or if `payload.get("complete")` (no errors and all 3 registries present); `PARTIAL` (3) otherwise (any registry failed or fell back to a stale copy).
- **Real example:** `netrune lookup mac registry refresh` → `IEEE MAC registry refresh: 3/3 registries available` plus a per-registry status table.
- **Related commands:** Run before `lookup mac online` on a fresh install, or periodically to keep vendor data current; `lookup mac registry status` to check without downloading.

---

### DIAGNOSE DOMAIN

#### `netrune diagnose doctor` (id: `diagnose-doctor`)
- **Purpose:** Audit every prerequisite a live diagnostic depends on — required/optional binaries, ICMP capability, the speed-test backend, Internet routing, filesystem permissions, SSH vault state, SSH trust-store health, SQLite integrity, scan-limit configuration, and (optionally) live TLS/server-discovery reachability.
- **Exact syntax:** `netrune diagnose doctor [--online]`. Any other token → `f"Unknown option: {item}"` (`VALIDATION`).
- **Arguments:** `--online` (boolean, optional) — enables one extra live network check (see below). No other flags.
- **Preconditions / gating:** None — always runs; not gated by `--dry-run`/`--confirm` (registry's `preview_supported` is somewhat moot here since the function performs no destructive action).
- **Step-by-step behavior — the full check list, in source order (`checks` list, each appended via a local `add(name, status, detail)` closure):**
  1. **Required/optional binaries** (`shutil.which`): required (`FAIL` if missing) — `python3, jq, ping, ip, timeout, awk, perl, ssh, flock, mktemp, pgrep, realpath, grep, sed, sort, tr, xargs`; optional (`WARN` if missing) — `ssh-keyscan, ssh-keygen, sshpass, expect, gpg, sudo, curl, traceroute, iperf3, ethtool, iw`.
  2. **Netrune helper binaries present and executable**: `netrune-probe, netrune-control, netrune-connect` — `PASS` if `Path(self.paths.tool(name)).is_file() and os.access(path, os.X_OK)`, else `FAIL`.
  3. **ICMP capability**: `ping -n -c 1 -W 1 127.0.0.1` (5s timeout) — `PASS` if exit 0, else `FAIL`.
  4. **Speed backend**: `python3 -c "import netops_platform.speed, speedtest"` (15s) — `PASS`/`FAIL`.
  5. **Internet route**: `ip route get 1.1.1.1` (10s) — `PASS` if exit 0 and output contains `" dev "`, else `FAIL`.
  6. **Host environment**: `WARN` if `/proc/version` mentions `"microsoft"` (WSL — "local ethtool data describes a virtual adapter, not the physical cable"), else `PASS` reporting `sys.platform`.
  7. **Configuration directory** / **cache directory** readability/writability — `PASS`/`FAIL` via `os.access`.
  8. **Credential config permissions** (`self.paths.env_file`) and **SSH vault permissions** (`NETRUNE_PASSWORD_FILE`/`NETOPS_PASSWORD_FILE`, default `~/.ssh/sshpass_cache.gpg`): `WARN` if the file doesn't exist yet; else `PASS` only if `mode & 0o077 == 0` (no group/other access), else `FAIL`.
  9. **SSH vault mode** (`self.vault_status_payload()`): if `sudo-gpg-v1`, `PASS` when `root_key=="available"`, `FAIL` when `missing`/`insecure`, else `WARN`; if `legacy-gpg`, `WARN` ("run 'netrune vault migrate'..."); otherwise `WARN` with the raw mode string.
  10. **SSH host-key mode** (`NETRUNE_SSH_HOST_KEY_MODE`/config `ssh_host_key_mode`, default `accept-new`): `PASS` only for `strict`; `WARN` for `accept-new`/`accept_new`/`managed`; `FAIL` for anything else.
  11. **SSH username** (`NETRUNE_SSH_USER`/config/secret `ssh_user`): `PASS` if `valid_ssh_username(...)` (1–255 chars, no whitespace), else `FAIL`.
  12. **SSH trust store** (`self.paths.ssh_known_hosts_file`): if it doesn't exist, `WARN` ("use netrune device trust scan/enroll"); if it does, `PASS` only if file mode has no group/other bits, else `FAIL`, and the detail string reports `keys={len(self._known_host_rows())}` — i.e. it parses and counts every valid host-key entry in the file via the shared SSH-trust helper (see Cross-cutting notes).
  13. **SQLite integrity** (`self.state.integrity_check()` — runs `PRAGMA integrity_check` and `PRAGMA quick_check`): `PASS` iff both return exactly `["ok"]`.
  14. **Scan limits** (`scan workers` 1–256, `scan host limit` 1–65536, `scan host timeout` 1–300, each from env override or config, default `30`/`4096`/`20`): `PASS` iff the configured value is a digit string within range, else `FAIL`.
  15. **Core switch** / **core iperf3 server** configuration presence: `PASS` if set, else `WARN`.
  16. **Online TLS/server discovery** (only if `--online`) — see below; **this check currently crashes the entire command.**
  17. **Helper copies match the working tree**: for each of `netops-lib.sh, netops-control, netops-discovery, netops-probe, netops-connect, netops_aruba_ssh.exp`, checks whether a shadow copy under `sys.prefix/bin` or `<install_dir>/.venv/bin` is older than the canonical copy in `install_dir` — `WARN` (listing up to 3) if any stale shadow exists, else `PASS`.
  18. Computes `failed`/`warnings`/`passed` counts, builds the final payload, records it via `self.state.record_diagnostic_run("doctor","local","netops-host",status,summary,payload)`, and emits.
- **⚠️ Confirmed defect — `--online` path is broken:** at `diagnose_cli.py:735`, the code reads `if online and helper.is_file():` — but **no variable named `helper` is ever assigned anywhere in `diagnostics_doctor`** (it is not a parameter, not a local, not a class attribute; `grep` across the file confirms this). Because Python evaluates `and` left-to-right, this line only executes when `--online` is passed — so `netrune diagnose doctor` (no flag) is unaffected, but `netrune diagnose doctor --online` **always raises `NameError: name 'helper' is not defined`**. Because step 16 falls between the "core iperf3 server" check (step 15) and the "helper copies match working tree" check (step 17), and because the function never reaches its `payload`/`emit`/`record_diagnostic_run` call before the exception, **all 15+ checks already gathered are discarded** — nothing is written to `diagnostic_runs`, and no output is produced by `diagnostics_doctor` itself. The exception propagates up to `App.dispatch()`'s top-level `except Exception as exc:` handler (`core.py:3709`), which prints `Error: name 'helper' is not defined` (or, in `--json` mode, `{"ok":false,"error":"name 'helper' is not defined","exit_code":10}`) and returns `INTERNAL` (10) — a generic internal error, not a check `FAIL` row. The intended behavior (inferable from the surrounding code, which mirrors the "speed backend" check's pattern of invoking a Python helper module by path with `[sys.executable, str(helper), ...]`) was almost certainly to check TLS trust and Speedtest server discovery by invoking some helper script's `servers --limit 1` support — but as shipped, `--online` is non-functional and should not be used until this is fixed.
- **Side effects:** SQLite write to `diagnostic_runs` (`kind="doctor"`, `target="local"`, `source="netops-host"`) — **only on the non-`--online` path**, since the `--online` path never reaches that code. No files written by `doctor` itself.
- **Output shape, table mode:** `render_table(checks, ["check","status","detail"])`.
- **Output shape, `--json` mode:** `{ok, status, online, checks, summary:{passed,warnings,failed}, observed_at, observed_at_iso, record_id}` — again, only reachable without `--online`.
- **Exit codes:** `VALIDATION` (6) unknown flag; without `--online`: `SUCCESS` (0) if `failed==0` else `PARTIAL` (3); with `--online`: always `INTERNAL` (10) due to the bug above (never `SUCCESS`/`PARTIAL`).
- **Real example:** `netrune diagnose doctor` → a ~30-row PASS/WARN/FAIL table covering the full readiness surface.
- **Related commands:** The instructed first step "before any live diagnostic" — run once per environment/after any config change, before `diagnose cable`, `diagnose port-health`, `diagnose core-ping`, `diagnose speed`, or `diagnose throughput`. Complements `netrune device trust scan/enroll` for the SSH trust-store warning path, and `netrune vault migrate` for the legacy-gpg vault warning.

---

#### `netrune diagnose core-ping` (id: `diagnose-core-ping`, aliases `point-ping`, `truth-ping`)
- **Purpose:** Issue an ICMP ping *from the configured core switch itself* (not from the Netrune host) to a target, so operators see the network's own point-of-truth reachability rather than a client-side ping that might cross an unrelated path.
- **Exact syntax:** `netrune diagnose core-ping <target> [--core|--source <core>] [--count|-c <n>] [--packet-timeout <n>]`.
- **Arguments:** `target` (required, positional) — missing → `"Missing destination device/IP."` (`USAGE`, default). `--core`/`--source <core>` (optional, overrides `opts.source` as the core-switch override; default is the configured `core_switch_ip`/`core_switch`). `--count`/`-c <n>` (optional, default 5, clamped 1–20 inside `point_of_truth_ping`; a non-integer value → `"Count must be an integer."`, `VALIDATION`). `--packet-timeout <n>` (optional, default 2, clamped 1–10; non-integer → `"Packet timeout must be an integer."`, `VALIDATION`). Any unrecognized flag → `f"Unknown option: {flag}"` (`VALIDATION`).
- **Preconditions / gating:** Target must resolve to an IP: `normalize_target_literal(target)` first, then `self.resolve_one(target)` (see Cross-cutting notes) if not already a literal IPv4; failure → `"Could not resolve destination to a device IP: {target}"` (`VALIDATION`). Core switch must be configured and must resolve safely via `resolve_device_record`, same pattern as `lookup core` — `"No core switch is configured..."` / `"Core switch could not be resolved safely: ..."` (both `VALIDATION`). `--dry-run` short-circuits with `SUCCESS` before any device is touched. Not wrapped in `vault_session_scope` (single device, at most 2 sequential capture calls).
- **Step-by-step behavior:**
  1. Resolve destination IP (literal, or via `resolve_one`).
  2. Resolve/validate the core switch record; clamp `count`/`packet_timeout`.
  3. Detect the core's driver family; if unknown, runs `show version` on the core first to reclassify (mirrors `lookup core`'s pattern), and if still unknown after that, falls back to forcing `family="cisco-ios"` (unlike `lookup core`, which aborts `UNSUPPORTED` — `core-ping` never gives up on family detection).
  4. Formats the vendor ping template (`driver.command_templates.get("ping")`, default `"ping {destination} repeat {count} timeout {timeout}"`), runs it on the core via `netrune-control show <core-ip> <ping-command>`.
  5. Parses with `parse_ping_output(raw, count)`.
  6. Records the result to `probe_results` via `self.state.record_probe_result(destination, f"core-ping:{core_ip}", payload)`.
- **Side effects:** SQLite write to `probe_results` (columns include `target, mode, created_at, packet_loss_pct, min_ms, avg_ms, max_ms, jitter_ms, raw_json`). Helper: `netrune-control show <core-ip> <vendor-ping-command>` (and, if family unknown, an extra `show version` call first).
- **Output shape, table mode:** No table — hand-built text summary.
- **Output shape, `--json` mode:** `ok, healthy, mode ("core-ping"), source{ip,name,platform}, driver_family, target, target_ip, command, exit_code, helper_exit_ignored`, plus the spread of `parse_ping_output`'s result (`parsed, status, transmitted, received, packet_loss_pct, min_ms, avg_ms, max_ms`), plus `observed_at, observed_at_iso, output_excerpt`.
- **Exit codes:** `USAGE` (2) missing target; `VALIDATION` (6) unresolved target, no/bad core config, bad `--count`/`--packet-timeout`, unknown flag; `SUCCESS` (0) `--dry-run`; live: `PARTIAL` (3) if the output couldn't be parsed at all; `UNREACHABLE` (4) if parsed but `received <= 0`; `PARTIAL` (3) if parsed with nonzero packet loss; `SUCCESS` (0) if parsed with 0% loss.
- **Real example:** `netrune diagnose core-ping 192.0.2.50 --count 5` →
  ```
  Point-of-truth ping from CORE01 (192.0.2.1) to 192.0.2.50
  Status: REACHABLE | Received: 5/5 | Loss: 0.0%
  Latency min/avg/max: 0.4 / 0.6 / 1.1 ms
  ```
- **Related commands:** Compare against `diagnose latency` (pings *from the Netrune host*, a different vantage point) to isolate whether a reachability problem is local to the client or exists from the network core outward.

---

#### `netrune diagnose latency` (id: `diagnose-latency`)
- **Purpose:** Run latency probing from the Netrune host itself (as opposed to `core-ping`'s core-switch vantage point), via the legacy `netrune-probe` helper.
- **Exact syntax:** `netrune diagnose latency <target> [--count|-c <n>] [--port|-p <n>] [<anything else>]`. This is the domain's default verb (`verb=args[0] if args else "latency"` — so `netrune diagnose` with no verb at all runs latency against... actually requires a target, so an empty-args invocation still errors).
- **Arguments:** `target` (required, positional) — missing → `"Missing target."` (`USAGE`, default). `--count`/`-c <n>` and `--port`/`-p <n>` are recognized and forwarded as `-c`/`-p` to the underlying helper. **Any other token is passed through unmodified and unvalidated** to `netrune-probe` — unlike every other diagnose verb, `latency` has no `"Unknown option"` rejection branch at all; this is a deliberate permissiveness gap worth knowing about operationally.
- **Preconditions / gating:** None beyond having a target; not resolved via `resolve_device_record` or `resolve_one` at all — `normalize_target_literal(rest[0])` only (bracket/whitespace cleanup), then handed straight to the external helper, which does its own resolution.
- **Step-by-step behavior:** Builds `self.legacy_cmd("netrune-probe", target, *extra)`, appends `--json` if `opts.json` and not already present, and calls `self.run_subprocess(cmd, opts)` — a direct, non-captured subprocess run (child inherits stdout/stderr; Netrune does not parse or wrap the output at all).
- **Side effects:** None from the Python layer itself — whatever `netrune-probe` does internally (the registry's `writes_local: true` reflects the external helper's own behavior, not anything in `diagnose_cli.py`). Helper: `netrune-probe <target> [-c N] [-p N] [--json]`.
- **Output shape, table mode / `--json` mode:** Entirely owned by `netrune-probe`'s own stdout — not constructed by this codebase.
- **Exit codes:** `USAGE` (2) missing target; otherwise whatever `run_subprocess` returns: `SUCCESS` (0) for `--dry-run` (prints the would-be command); the helper's own exit code (via `normalized_exit_code`) on a normal run; `TIMEOUT` (9) if `opts.timeout` is exceeded; `UNSUPPORTED` (5) if the helper binary is missing; `130` on Ctrl-C.
- **Real example:** `netrune diagnose latency 1.1.1.1 --count 10` — raw `netrune-probe` output, human or JSON per `--json`.
- **Related commands:** `diagnose core-ping` for the core-switch vantage point; `diagnose speed` for throughput rather than latency alone.

---

#### `netrune diagnose speed` (id: `diagnose-speed`)
- **Purpose:** Measure the Netrune host's own routed path to the Internet (download/upload throughput, idle and loaded latency, reliability rating) using a profile-based multi-server methodology, with TLS-verified server discovery.
- **Exact syntax:** `netrune diagnose speed [--runs|--speed-runs <n>] [--profile <quick|balanced|thorough>] [--quick] [--thorough] [--ca-file <path>]`.
- **Arguments:** `--runs`/`--speed-runs <n>` (optional; non-integer → `"Runs must be an integer from 1 to 5."`, `VALIDATION`). `--profile <name>` (optional, default `balanced`; `--quick`/`--thorough` are shorthand for `--profile quick`/`thorough`; invalid profile name → `"Profile must be quick, balanced, or thorough."`, `VALIDATION`). `--ca-file <path>` (optional, forwarded to the helper as `--ca-file`). Unknown flag → `f"Unknown option: {flag}"` (`VALIDATION`).
- **Preconditions / gating:** Profile-based run-count defaults: `quick=1, balanced=2, thorough=3`; explicit `--runs` must be 1–5 (`"Runs must be from 1 to 5."`, `VALIDATION`); if profile is `balanced`/`thorough` and `runs < 2`: `"Balanced/thorough profiles require at least 2 runs; use --profile quick for a one-server check."` (`VALIDATION`). `--dry-run` prints the planned `netrune-probe` invocation and returns `SUCCESS` — "Quick uses one complete server by default; balanced uses two; thorough uses three or more for stronger agreement."
- **Step-by-step behavior:**
  1. Re-clamps `runs`/`profile` inside `internet_speed_diagnostic` itself (same rules as the CLI-layer validation, defensively re-applied).
  2. Builds `self.legacy_cmd("netrune-probe", "-s", "--profile", profile, "--speed-runs", str(runs), "--json")` (+ `--ca-file` if given).
  3. Runs via `self.capture_streamed(cmd, opts.timeout or 1800)` — captures stdout for JSON parsing while forwarding the child's stderr progress lines live to this process's stderr (so a slow multi-run test shows progress in real time).
  4. Parses stdout as JSON. **If parsing fails**: classifies as `"BLOCKED"` (if the error text matches `401|authorization required|access denied|blocked|filter(?:ed|ing)?`) or `"ERROR"` otherwise, records to `diagnostic_runs`, and returns early.
  5. On successful parse: reads `reliability.rating`, computes `status` = `"PASS"` (ok + rating HIGH/MEDIUM), `"ATTENTION"` (ok but low-confidence rating), or `"ERROR"` (not ok). Records to both `speed_tests` and `diagnostic_runs`.
- **Side effects:** SQLite writes: `speed_tests` (`created_at, interface, download_mbps, upload_mbps, idle_latency_ms, loaded_down_ms, loaded_up_ms, packet_loss_pct, reliability, raw_json`) via `record_speed_result`, and `diagnostic_runs` (`kind="internet-speed", target="internet", source="netops-host"`) via `record_diagnostic_run`, in **both** the parse-failure and parse-success paths. Helper: `netrune-probe -s --profile <profile> --speed-runs <n> --json [--ca-file <path>]`.
- **Output shape, table mode:** No table — manual text block (profile, servers completed/attempted, download/upload Mbps, reliability, idle/loaded latency, TLS trust source, interface, explicit scope disclaimer: "this is not a measurement of an arbitrary endpoint").
- **Output shape, `--json` mode:** Whatever `netrune-probe -s --json` emits, passed through and augmented with `observed_at, observed_at_iso, speed_test_id, record_id` (success path) or, on parse failure: `{ok:false, status, exit_code, error, failure_class, remediation, observed_at, observed_at_iso, record_id}`.
- **Exit codes:** `VALIDATION` (6) for any of the arg-validation failures above; `SUCCESS` (0) `--dry-run`; parse-failure path: the helper's own `rc` if truthy, else `INTERNAL` (10); parse-success path: the helper's `rc` if it's exactly `SUCCESS` or `PARTIAL`, else `SUCCESS` if `payload.get("ok")` else `INTERNAL` (10).
- **Real example:** `netrune diagnose speed --profile quick` → `Internet speed from this Netrune host / Profile: quick | Servers: 1/1 / Download: 850 Mbps | Upload: 210 Mbps | Reliability: HIGH`.
- **Related commands:** `diagnose throughput` measures a *controlled* iperf3 path instead of the open Internet — use `speed` for Internet-egress health, `throughput` for a specific internal/known-server path. `diagnose doctor` checks the speed backend and TLS trust prerequisites this command depends on.

---

#### `netrune diagnose throughput` (id: `diagnose-throughput`, aliases `iperf`, `iperf3`)
- **Purpose:** Measure TCP receiver goodput between the Netrune client and a controlled `iperf3` server (not an arbitrary Internet path) — upload, download, or both.
- **Exact syntax:** `netrune diagnose throughput <server|core> [--port|-p <n>] [--seconds|--time|-t <n>] [--parallel|-P <n>] [--direction <both|upload|download>] [--bind|--source <ip>]`.
- **Arguments:** `server` (required, positional; the literal token `core` substitutes `core_iperf_server` / `core_switch_ip` / `core_switch` from config) — missing → `"Missing controlled iperf3 server."` (`VALIDATION`, explicit). `--port`/`-p` (default 5201; non-integer → `"Port must be an integer."`, `VALIDATION`). `--seconds`/`--time`/`-t` (default 10; non-integer → `"Seconds must be an integer."`, `VALIDATION`). `--parallel`/`-P` (default 1; non-integer → `"Parallel streams must be an integer."`, `VALIDATION`). `--direction` (default `both`; not range-checked at the CLI-parsing layer, only inside `throughput_diagnostic`). `--bind`/`--source` (default `opts.source`, i.e. the global `--source` flag). Unknown flag → `f"Unknown option: {flag}"` (`VALIDATION`).
- **Preconditions / gating:** Inside `throughput_diagnostic`: `server` resolved via `_diagnostic_device` if it matches inventory (substitutes the resolved IP); still-empty server → `"Missing iperf3 server. Configure core_iperf_server or supply a host/IP."` (`VALIDATION`). Range re-validation: port 1–65535, seconds 1–300, parallel 1–16 → `"Use port 1-65535, seconds 1-300, and parallel streams 1-16."` (`VALIDATION`). `direction` must be `both`/`upload`/`download` → `"Direction must be both, upload, or download."` (`VALIDATION`). `--dry-run` returns `SUCCESS` with the planned `iperf3` command lines. If `iperf3` isn't installed (`shutil.which`), returns `UNSUPPORTED` before running anything.
- **Step-by-step behavior:**
  1. Builds one or two `iperf3` client invocations depending on `direction` (`both` → `["upload","download"]`, each its own phase): `iperf3 -c <server> -p <port> -t <seconds> -P <parallel> -O 2 -J` (+ `--bind <ip>` if given; `-R` for the download phase — reverse mode, server sends).
  2. Runs each phase sequentially (not parallel phases — `-P` controls parallel *streams within* a phase, not phases against each other) via `self.capture(cmd, opts.timeout or (seconds+45))`, parses with `parse_iperf3_output`.
  3. Any phase with a nonzero/`None` exit code has its `ok` forced `False` regardless of what the JSON payload claimed, and an `error` message attached from stderr.
- **Side effects:** SQLite write to `diagnostic_runs` (`kind="throughput", target="{server}:{port}", source="netops-host"`) via `record_diagnostic_run`. No `probe_results`/`speed_tests` writes. Helper: `iperf3` (external binary, not a Netrune helper), invoked directly (no vault/SSH involved — this is a plain TCP client, no device authentication).
- **Output shape, table mode:** `render_table(rows, ["direction","mbps","retransmits","seconds","status","error"])` where each row's `status` is `PASS`/`ERROR` per phase.
- **Output shape, `--json` mode:** `ok, status ("PASS"/"ERROR"), scope ("netops-client-to-controlled-iperf3-server"), server, port, seconds, parallel, bind, results (list of parsed per-phase iperf3 output), observed_at, observed_at_iso, interpretation, record_id`.
- **Exit codes:** `VALIDATION` (6) for every arg-validation case above; `SUCCESS` (0) `--dry-run`; `UNSUPPORTED` (5) if `iperf3` missing; live: `SUCCESS` (0) if every phase reports `ok`, else `PARTIAL` (3) — never `ERROR`/`INTERNAL` regardless of how badly a phase failed.
- **Real example:** `netrune diagnose throughput 203.0.113.20 --seconds 10 --parallel 2` → table showing `upload 940 Mbps` / `download 912 Mbps`, both `PASS`.
- **Related commands:** `diagnose speed` for open-Internet egress instead of a controlled server; `diagnose doctor` flags whether `iperf3` is even installed and whether `core_iperf_server` is configured, both prerequisites here.

---

#### `netrune diagnose port-health` (id: `diagnose-port-health`, aliases `port`, `interface-health`)
- **Purpose:** Sample a switch interface's link negotiation and error-counter deltas across a short observation window, to distinguish cumulative historical error counts from errors actively occurring right now.
- **Exact syntax:** `netrune diagnose port-health <device> on <interface> [--sample-seconds|--sample|--interval <n>] [--expected-speed|--speed <n>]`.
- **Arguments:** `device`, literal `on`, `interface` (all required and positional; `len(rest)<3 or rest[1]!="on"` → `"Use: netrune diagnose port-health <device> on <interface>"`, `VALIDATION`, explicit code). `--sample-seconds`/`--sample`/`--interval <n>` (default 5, clamped 0–60 inside the workflow; non-integer → `"Sample seconds must be an integer."`, `VALIDATION`). `--expected-speed`/`--speed <n>` (default 0/none, clamped 0–400000 Mbps; non-integer → `"Expected speed must be integer Mbps."`, `VALIDATION`). Unknown flag → `VALIDATION`.
- **Preconditions / gating:** `device` resolved via `_diagnostic_device` (tries `resolve_device_record`, falls back to treating it as a raw IPv4 literal) — unresolved → `f"Device could not be resolved: {target}"` plus up to 8 candidate labels (`VALIDATION`). `interface` validated against `r"[A-Za-z][A-Za-z0-9./:_-]{0,63}|\d{1,4}"` — invalid → `"Interface name is invalid."` (`VALIDATION`). `--dry-run` returns `SUCCESS` with the planned command list, no device contact. **Not** wrapped in `vault_session_scope` despite making 2 sequential SSH reads to the same device.
- **Step-by-step behavior:**
  1. Builds the driver's `interface_health` command template(s) for the target interface.
  2. `snapshot()` (called twice — baseline, then current): if the driver needs more than one command for interface health, batches them in **one SSH login** via `netrune-control show-batch <ip> <cmd1> <cmd2> ...` and splits the transcript on `self.CMD_MARKER_RE`; otherwise a single `netrune-control show <ip> <cmd>` call. Parses with `parse_interface_health_output`.
  3. Reads the baseline. If it's unparseable, logs a note and **skips the sleep** ("retry immediately instead of waiting for a delta sample") — `sample_seconds` is forced to 0 for this run.
  4. Otherwise sleeps `sample_seconds` (`time.sleep`), then reads current counters.
  5. Computes per-counter deltas (`current - baseline`); a negative delta (counter reset/wrap) is recorded as `None` in `deltas` and flagged in `counter_resets`, not treated as a real decrease.
  6. Builds a `findings` list: `BASELINE_UNAVAILABLE` (warning) if baseline didn't parse; `OUTPUT_UNPARSED` (critical) if current didn't parse; `ADMIN_DOWN`/`LINK_DOWN` (critical) from current state; `HALF_DUPLEX` (warning); `SPEED_BELOW_EXPECTED` (warning) if `expected_speed` given and actual is lower; `COUNTER_INCREASE` for any of `crc_errors, frame_errors, input_errors, output_errors, collisions, late_collisions, excessive_collisions, runts, giants, rx_errors` that increased (critical for `crc_errors`/`late_collisions`/`excessive_collisions`, warning otherwise); `COUNTER_RESET` (warning) if any counter wrapped during the sample.
  7. `status` = `"ERROR"` (current unparsed) → `"DOWN"` (oper_status down) → `"ATTENTION"` (any findings) → `"HEALTHY"`.
  8. Computes `utilization_pct` from `max(input_bps, output_bps) / (speed_mbps * 1e6) * 100`.
- **Side effects:** SQLite writes: `interface_samples` (`created_at, device_ip, interface_name, in_bps, out_bps, utilization_pct, oper_status, raw_json`) via `record_interface_result`, and `diagnostic_runs` (`kind="port-health", target="{ip}:{interface}", source="switch"`) via `record_diagnostic_run`. Helper: `netrune-control show-batch <ip> <cmd...>` (or `show` if only one command), invoked exactly twice.
- **Output shape, table mode:** `render_table(findings, ["severity","code","counter","delta","detail"])` if any findings exist, else `"No active link or counter-delta findings."`; not a top-level row table (payload is a single dict).
- **Output shape, `--json` mode:** `ok, healthy, status, device, device_ip, platform, driver_family, interface, sample_seconds, baseline_exit_code, current_exit_code, helper_exit_ignored, expected_speed_mbps, baseline, current, counter_deltas, utilization_pct, findings, observed_at, observed_at_iso, interpretation, output_excerpt, interface_sample_id, record_id`.
- **Exit codes:** `VALIDATION` (6) for every arg/device/interface validation case; `SUCCESS` (0) `--dry-run`; live: `SUCCESS` (0) only if `status=="HEALTHY"`, else `PARTIAL` (3) for `ATTENTION`/`DOWN`/`ERROR`.
- **Real example:** `netrune diagnose port-health ZONE34 on Gi1/0/7 --sample-seconds 10 --expected-speed 1000` → status `ATTENTION`, findings table showing `SPEED_BELOW_EXPECTED` and possibly `COUNTER_INCREASE` on `crc_errors`.
- **Related commands:** Usually preceded by `lookup mac locate`/`lookup core` (to find the port), and followed by `diagnose cable` if physical-layer suspicion remains after ruling out negotiation/error-counter issues.

---

#### `netrune diagnose cable` (id: `diagnose-cable`) and `netrune diagnose cable --test` (id: `diagnose-cable-test`)
- **Purpose:** Read the last recorded copper TDR (Time-Domain Reflectometry) result for an interface (`cable`), or start a new active TDR test and then read its result (`cable --test`, also reachable via the `tdr`/`cable-test` verb aliases) — an active TDR can briefly interrupt a live copper link, so it is gated behind `--confirm`.
- **Exact syntax:** `netrune diagnose cable <device> on <interface> [--test|--start] [--wait <n>]`. The verb aliases `tdr`/`cable-test` set `start_test=True` by default even without `--test`/`--start`. Registry id `diagnose-cable-test`'s documented form `... on '<interface>' --test --dry-run` is simply the disruptive path previewed safely; **confirmed execution of the test remains CLI-only** per the registry description (no `--confirm` path is exposed through whatever UI layer consumes this registry — the underlying code does support `--confirm`, it's a UI-level restriction, not a code-level one).
- **Arguments:** `device`, `on`, `interface` (required; same `VALIDATION` shape as `port-health`'s "Use: ..." message). `--test`/`--start` (boolean, sets `start_test=True`). `--wait <n>` (default 8s, clamped 2–60; non-integer → `"Wait must be an integer number of seconds."`, `VALIDATION`). Unknown flag → `VALIDATION`. Interface validated with the identical regex as `port-health`.
- **Preconditions / gating:** `device` resolution identical to `port-health` (`_diagnostic_device`, `VALIDATION` on failure). Driver must expose a `cable_status` command template at all — if not, `UNSUPPORTED` ("Cable diagnostics are not supported by the {family} driver."). If `start_test` and the driver has no `cable_start` template, `UNSUPPORTED`. **If `start_test` and neither `opts.dry_run` nor `opts.confirm` is set: `CONFIRM_REQUIRED` (7)** — `"Starting cable diagnostics may interrupt a live copper link. Review with --dry-run or execute with --confirm."` — this is the one command among all 21 with a hard confirmation gate. `--dry-run` (with or without `--test`) returns `SUCCESS` listing the planned command sequence, with an explicit `"disruptive"` flag and warning text if `start_test`. If `start_test` and the driver family is `aruba-aos-cx`, always `UNSUPPORTED` — "Aruba CX interactive confirmation is not automated; run the preview and execute directly on the switch during a maintenance window."
- **Step-by-step behavior (when `start_test` and confirmed/non-dry-run):**
  1. **Media precheck**: runs the driver's `interface_health` command(s) on the target interface first, to verify it's actually copper before disrupting it. If the precheck output doesn't parse: aborts with `PARTIAL` and `status="ERROR"` — "Active TDR was not started because Netrune could not verify the interface media." (no test is attempted).
  2. If the parsed media string matches an optical-fiber pattern (`sfp|fiber|fibre|...sx|lx|zx|er|lr|sr...`), aborts `UNSUPPORTED` — "TDR is a copper diagnostic and this port reports optical/removable media."
  3. Runs the driver's `cable_start` command. The raw output is checked against two regexes: a rejection pattern (`invalid input|unknown command|not supported|permission denied|authorization failed|authentication failed|connection failed/timed out|unable to|failed to|cannot|can't`) and an acceptance pattern (`(tdr|cable diagnostic).{0,60}(started|initiated|running|scheduled|in progress)` or the reverse order). If rejected, or the helper exited nonzero without an acceptance phrase: aborts with `UNSUPPORTED` (if the rejection looked like "not supported") or `PARTIAL` otherwise.
  4. Sleeps `wait_seconds`.
  5. Reads the status command. **Aruba fallback**: if family is `aruba-aos-switch`, the status output didn't parse, and the raw text says `invalid input|unknown command`, retries with `diag cable-diagnostic show {interface}` and re-tags `family="aruba-aos-cx"` for the rest of the response — the code explicitly notes some Aruba inventory records don't distinguish AOS-Switch from CX.
  6. Parses with `parse_cable_diagnostics_output`.
- **Side effects:** SQLite write to `diagnostic_runs` (`kind="cable", target="{ip}:{interface}", source=<driver family>`) via `record_diagnostic_run` — on every terminal path including the media-precheck-failed and start-rejected paths. Uses `vault_session_scope` (wrapped at the `cmd_diagnose` dispatch level, `minutes=30`) — one of only a handful of commands that hold the vault open despite targeting a single device, because a full active-test run makes up to 3 sequential SSH calls (precheck, start, status-read, plus a possible Aruba fallback status re-read). Helper: `netrune-control show <ip> <interface_health-cmd>` (precheck, if starting), `netrune-control show <ip> <cable_start-cmd>` (if starting), `netrune-control show <ip> <cable_status-cmd>` (always, possibly twice for the Aruba fallback).
- **Output shape, table mode:** `render_table(parsed.get("pairs") or [], ["pair","status","distance_m"])` if pair-level TDR data was parsed, else `parsed.get("message")`.
- **Output shape, `--json` mode:** `ok, healthy, device, device_ip, interface, platform_family, test_started, command`, plus the spread of `parse_cable_diagnostics_output` (includes at least `status`, `pairs`, `message`, `parsed`), plus `status, exit_code, helper_exit_ignored, precheck_exit_code, precheck_exit_ignored, test_start_exit_code, test_start_exit_ignored, observed_at, observed_at_iso, limitations, output_excerpt, record_id`.
- **Exit codes:** `VALIDATION` (6) bad device/interface/`--wait`/unknown flag; `UNSUPPORTED` (5) driver lacks cable capability, lacks start capability, Aruba-CX interactive block, optical media detected, or a rejected/"not supported" start attempt; `CONFIRM_REQUIRED` (7) `start_test` without `--dry-run`/`--confirm`; `SUCCESS` (0) `--dry-run`, or a live `status=="HEALTHY"` result; `PARTIAL` (3) media-precheck failure, a start attempt that failed without being "not supported," or any parsed-but-not-healthy result (e.g. a detected fault); `INTERNAL` (10) only when the final status read is completely unparseable **and** the helper's own exit code was 0/None (an unparseable result with a nonzero helper exit becomes `PARTIAL` instead).
- **Real example:** `netrune diagnose cable ZONE34 on Gi1/0/7` (read-only, no `--test`) → previous stored TDR result, pair-by-pair status/distance table. `netrune diagnose cable ZONE34 on Gi1/0/7 --test --confirm --wait 10` → starts a new TDR, waits 10s, reads the fresh result.
- **Related commands:** Usually follows `diagnose port-health` when link-layer symptoms (errors, half-duplex, low negotiated speed) point at a physical-layer cause. `diagnose doctor` should be run first to confirm the SSH trust/vault prerequisites this command's multi-call sequence depends on.

---

#### `netrune diagnose filtering` (id: `diagnose-filtering`)
- **Purpose:** Run DNS/TLS/content-filtering diagnostics against a target via the legacy `netrune-legacy check` helper.
- **Exact syntax:** `netrune diagnose filtering [<target>]` — `target` defaults to `"google.com"` if omitted.
- **Arguments:** `target` (optional positional; no validation of any kind is applied to it in this codebase).
- **Preconditions / gating:** None — no usage-error branch exists for this verb at all in `cmd_diagnose`.
- **Step-by-step behavior:** `cmd=[self.paths.tool("netrune-legacy"),"check"]`; appends `--json` if `opts.json`; appends `target` if truthy; runs via `self.run_subprocess(cmd, opts)` — direct passthrough, no output parsing by Netrune.
- **Side effects:** None from the Python layer; whatever `netrune-legacy check` does internally. Helper: `netrune-legacy check [--json] [<target>]`.
- **Output shape, table mode / `--json` mode:** Entirely owned by `netrune-legacy`'s own output.
- **Exit codes:** `SUCCESS` (0) `--dry-run`; otherwise the helper's own exit code via `run_subprocess` (or `TIMEOUT`/`UNSUPPORTED`/`130` per the same rules as `diagnose latency`).
- **Real example:** `netrune diagnose filtering example.com` — raw `netrune-legacy check` output for that target.
- **Related commands:** Independent of the other diagnose commands; typically run when a user reports "I can't reach a specific website" as opposed to a general connectivity issue (`core-ping`/`latency`) or a link-layer issue (`port-health`/`cable`).

---

#### `netrune diagnose interface` (id: `diagnose-interface`)
- **Purpose:** Legacy interface rate monitor (bps/utilization over time), delegated entirely to `netrune-legacy interface`; command-center/scheduled jobs default to one finite sample rather than a continuous live monitor.
- **Exact syntax:** `netrune diagnose interface <device> on <interface> [<any further tokens, e.g. --chart classic|histogram, --once>]`.
- **Arguments:** `device`, `on`, `interface` (required; `len(rest)<3 or rest[1]!="on"` → `"Use: netrune diagnose interface <device> on <interface>"` — **note this omits the `code` argument to `usage_error`, so it defaults to `USAGE=2`, unlike the structurally identical checks in `port-health` and `cable`, which both explicitly pass `VALIDATION=6` for the same kind of message.** This is a real inconsistency between otherwise-parallel code paths.) Everything after the interface (`--chart`, `--once`, etc., per the registry's `arg_schema`) is forwarded to the legacy helper **completely unvalidated** — Python performs no parsing of these flags at all.
- **Preconditions / gating:** `device` resolved via `_diagnostic_device` (same as `port-health`/`cable`) — unresolved → `f"Device could not be resolved: {target}"` (`VALIDATION`, explicit this time).
- **Step-by-step behavior:** `cmd=[self.paths.tool("netrune-legacy"),"interface",str(device.get("ip") or rest[0]),*rest[1:]]` (note: `rest[1:]` still includes the literal `"on"` token and the interface name — the legacy helper's own arg parser is expected to handle that shape); appends `--json` if `opts.json` and not already present; runs via `run_subprocess`.
- **Side effects:** None from Python directly; delegated to `netrune-legacy interface`. Helper: `netrune-legacy interface <ip> on <interface> [extra flags...] [--json]`.
- **Output shape, table mode / `--json` mode:** Entirely owned by the legacy helper.
- **Exit codes:** `USAGE` (2) malformed `<device> on <interface>` shape (the inconsistent default noted above); `VALIDATION` (6) device doesn't resolve; otherwise the helper's own exit code via `run_subprocess`.
- **Real example:** `netrune diagnose interface ZONE34 on Gi1/0/7 --once` — one finite bps/utilization sample from the legacy monitor.
- **Related commands:** `diagnose port-health` is the modern, structured, Python-native equivalent for a point-in-time health check; use `diagnose interface` specifically when the legacy rate-over-time chart output is wanted.

---

### Cross-cutting notes

**`resolve_one` — correction to the received premise.** `resolve_one` does **not** live in `core.py`. It is defined directly inside `DiagnoseCommandsMixin`, at `diagnose_cli.py:39`:
```python
def resolve_one(self,target:str)->str:
    from netops_platform.core import IP_RE, normalize_target_literal
    target = normalize_target_literal(target)
    if IP_RE.fullmatch(target.strip()): return target.strip()
    device, choices = self.resolve_device_record(target)
    if device and len(choices) == 1:
        return str(device.get("ip") or "")
    row=self.state.one("SELECT ip FROM aps WHERE lower(name)=lower(?) OR lower(name) LIKE lower(?) ORDER BY name LIMIT 1",(target,f"%{target}%"))
    if row: return row["ip"]
    with contextlib.suppress(Exception): return socket.gethostbyname(target)
    return ""
```
A repo-wide `grep -rn "resolve_one(" netops_platform/*.py` turns up exactly two hits, both in `diagnose_cli.py` — the definition itself and its one call site inside `point_of_truth_ping` (`core-ping`'s implementation). So the "diagnose is its only real caller" half of the premise is accurate, but the "lives in core.py" half is not — it's a diagnose-domain-local method, not a shared core helper, and it doesn't need to be one since nothing outside this file calls it. (This may be a mix-up with the *actually* cross-file-shared helpers documented next, or with `locate_endpoint_live`, which `lookup_cli.py`'s own module docstring explains stays in `core.py` because `path_inspector.py` calls it externally — a genuinely analogous but different situation.) Functionally, `resolve_one` is a lighter-weight sibling of `resolve_device_record`: it tries, in order, (1) a literal IPv4 match, (2) a unique inventory-device match via `resolve_device_record` (deliberately requiring `len(choices)==1` — an ambiguous match returns nothing rather than guessing), (3) an AP-table name/substring match, (4) a plain DNS `socket.gethostbyname` lookup, swallowing any exception. It returns `""` on total failure, which `core-ping` treats as an unresolvable-destination `VALIDATION` error.

**SSH-trust-store helpers (`_known_host_rows`, `_known_host_alias_matches`, `_host_key_fingerprint`) — genuinely shared, and genuinely in `core.py`.** Unlike `resolve_one`, these three *are* correctly described as living in `core.py` (`core.py:5696–5748`) rather than in either domain file, because they have two real cross-domain callers: `diagnostics_doctor` (diagnose domain, this file) and `cmd_device_trust` in `device_cli.py` (confirmed via `grep`: `device_cli.py` calls `self._host_key_fingerprint`, `self._known_host_rows`, and `self._known_host_alias_matches` at lines 65, 116, 147, and 178). Because `DiagnoseCommandsMixin` and `DeviceCommandsMixin` are both mixed into the same `App` class, `self._known_host_rows(...)` resolves via normal Python MRO regardless of which file defines it — moving it into either domain file would work mechanically but would violate the project's stated rule that a helper used by two or more extracted domains stays centralized.
- `_host_key_fingerprint(key_data)`: base64-decodes an SSH known-hosts public-key field and returns its `SHA256:<base64-sha256-digest>` fingerprint (OpenSSH's own fingerprint format), or `""` if the field doesn't decode.
- `_known_host_alias_matches(alias, target)`: true if `alias` is a literal match for `target` (or its `[ip]:22` bracketed form), or, for hashed known-hosts entries (`|1|salt|digest` format), true if HMAC-SHA1(`salt`, `target`) constant-time-matches the stored digest — i.e., it can test membership against a hashed known-hosts alias without needing to reverse the hash.
- `_known_host_rows(targets=())`: reads `self.paths.ssh_known_hosts_file` line by line, skipping comments/blank lines and the optional leading `@revoked`/`@cert-authority` marker token, and — if `targets` is non-empty — keeps only lines where any alias matches any wanted target via `_known_host_alias_matches`. Each kept row becomes `{host, key_type, fingerprint, line, managed_file}`.

**What `diagnostics_doctor`'s "SSH trust store" check actually does with them:** it does *not* call `_known_host_alias_matches` or `_host_key_fingerprint` directly — it calls `self._known_host_rows()` with **no `targets` argument**, i.e. it wants every parseable entry in the trust file, not a lookup against a specific host. The check first verifies file permissions (`mode & 0o077 == 0`, no group/other access — `FAIL` otherwise), and only if the file exists at all; if it doesn't exist yet, the check is `WARN` with `"use netrune device trust scan/enroll"` and `_known_host_rows` is never even called in that branch. When the file does exist and permissions pass, the check's detail string embeds `keys={len(self._known_host_rows())}` — so it's using the shared helper purely as a **count** of how many valid, fingerprint-able host-key entries are currently trusted, as a quick sanity signal (zero keys with a permission-correct file is a strong "trust store exists but nothing has been enrolled yet" signal, even though the check still reports `PASS` in that case since only permissions gate pass/fail here).

**`diagnose doctor` as a whole — the complete readiness-check taxonomy** (see the exhaustive per-check breakdown under `diagnose-doctor` above for exact PASS/WARN/FAIL triggers; summarized by category here):
| Category | Checks | What triggers FAIL | What triggers WARN |
|---|---|---|---|
| Required binaries | `python3, jq, ping, ip, timeout, awk, perl, ssh, flock, mktemp, pgrep, realpath, grep, sed, sort, tr, xargs` | not on `$PATH` | never (always PASS/FAIL only) |
| Optional binaries | `ssh-keyscan, ssh-keygen, sshpass, expect, gpg, sudo, curl, traceroute, iperf3, ethtool, iw` | never | not on `$PATH` |
| Netrune helpers | `netrune-probe, netrune-control, netrune-connect` | missing or not executable | — |
| ICMP | loopback `ping` | ping exits nonzero | — |
| Speed backend | `import netops_platform.speed, speedtest` | import fails | — |
| Internet route | `ip route get 1.1.1.1` | nonzero exit or no `dev` in output | — |
| Host environment | WSL detection via `/proc/version` | never | running under WSL (ethtool data describes a virtual adapter) |
| Filesystem | config dir, cache dir, credential file perms, vault file perms | not accessible / group-or-other-readable perms | credential/vault file simply doesn't exist yet |
| SSH vault mode | `vault_status_payload()` | `sudo-gpg-v1` with `root_key` missing/insecure | `legacy-gpg`, or any other/unrecognized mode |
| SSH host-key mode | config/env `ssh_host_key_mode` | anything other than `strict`/`accept-new`/`accept_new`/`managed` | `accept-new`/`accept_new`/`managed` (not `strict`) |
| SSH username | `valid_ssh_username()` | empty, >255 chars, or contains whitespace | — |
| SSH trust store | permissions + `_known_host_rows()` count | group/other-readable permissions | file doesn't exist yet |
| SQLite integrity | `PRAGMA integrity_check` + `quick_check` | either returns anything other than exactly `["ok"]` | — |
| Scan limits | `scan_workers` (1–256), `scan_max_hosts` (1–65536), `scan_host_timeout` (1–300) | configured value non-numeric or out of range | — |
| Core config | `core_switch_ip`, `core_iperf_server` | never | not configured |
| Online TLS/server discovery (`--online` only) | intended to check Speedtest server discovery + TLS trust | *(currently always crashes before evaluating — see the confirmed defect above)* | — |
| Helper-copy freshness | mtime comparison of shadow copies vs. canonical `install_dir` copies | never | a shadow copy in `sys.prefix/bin` or `.venv/bin` is older than the canonical file (stale code may silently run instead of the current working tree) |

**`vault_session_scope` usage across these 21 commands — the actual pattern, not a simple "single vs. multi-device" rule.** Exactly 5 of the 21 wrap themselves: `lookup core` (dispatch-level wrap around `core_lookup_workflow`), `lookup mac all` (wrapped *inside* `lookup_mac_all` itself, around its `ThreadPoolExecutor` fan-out), `lookup mac locate` and `lookup mac profile` (dispatch-level wrap around `locate_mac_live`, shared by both subactions), and `diagnose cable`/`diagnose cable --test` (dispatch-level wrap around `cable_diagnostic`). The obvious case is `lookup mac all` — a genuine N-switch parallel fan-out, exactly the scenario `vault_session_scope`'s docstring describes ("Each device read otherwise costs a separate vault unlock, which on a Windows Hello PAM stack is one biometric prompt per switch"). But `lookup core`, `lookup mac locate`/`profile`, and `diagnose cable` all wrap despite touching a comparatively small, sometimes single-digit number of devices — the shared trait is actually **multiple sequential SSH logins within one logical operation** (core lookup: up to 4 sequential reads to the core; mac locate: N sequential switch reads plus an optional core read plus optional per-hit profiling; cable: up to 3 sequential reads to one device for a `--test` run). Conversely, `diagnose port-health` (2 sequential reads to one device) and `diagnose core-ping` (1–2 reads to one device) do **not** wrap, which is an inconsistency in the codebase relative to `cable`'s identical-shape reasoning — `port-health`'s baseline/current pair will re-authenticate per call unless a session happens to already be open from an outer command. The remaining commands — `mac inspect`, `mac history`, `mac vendor`, `mac online`, `mac registry status/refresh` (all pure reads or non-SSH network calls), `diagnose speed`, `diagnose throughput` (iperf3, no SSH at all), `diagnose latency`, `diagnose filtering`, `diagnose interface` (all delegate wholesale to an external legacy helper that manages its own auth), and `diagnose doctor` (no device SSH at all) — correctly have no need for a held vault session.

---

## 9. Traffic Domain


Source verified against: `netops_platform/traffic_cli.py` (1999 lines), `traffic.py` (1229 lines), `traffic_stack.py` (753 lines), `traffic_metrics.py` (478 lines), `traffic_exporter.py` (147 lines), `traffic_sync.py` (310 lines), `traffic_report.py` (408 lines), `traffic_graphers.py`, `traffic_dashboards.py`, `docs/poller-arch.md`, and `netops_platform/setup_cli.py`. Registry scaffold: `/tmp/registry_group3_traffic.json`.

Global facts that apply to every command below and are not repeated per-command unless notable:
- Every `usage(message, example)` closure inside `dispatch()` calls `app.usage_error("traffic", verb, opts, message, example, VALIDATION)` — **every validation failure in this domain exits `6` (VALIDATION)**, never the generic `USAGE=2`.
- Exit code constants used anywhere below: `SUCCESS=0`, `PARTIAL=3`, `VALIDATION=6`, `INTERNAL=10`.
- `--json` does not wrap output in an envelope — `app.emit(data, opts, text)` prints `json_dumps(data)` verbatim when `opts.json`, so the "JSON top-level keys" listed per command are exactly the dict literal passed to `app.emit(...)` in that handler.
- `--since` is a global flag (not domain-specific) parsed once by `parse_global()`; the domain-local helper `window_seconds()`/`resolve_window()` turns it into seconds, accepting bare seconds or `Ns/Nm/Nh/Nd`, clamped to `[60, 90*86400]`. An unparseable value returns `None`, and every command that calls `resolve_window()` explicitly checks for `None` and emits `"'<value>' is not a window. Use seconds or 15m, 6h, 2d."` (VALIDATION) — except `traffic health`, which instead does `resolve_window() or 21600`, silently falling back to 6 hours on a bad `--since` rather than erroring.
- The dispatcher (`dispatch()` in `traffic_cli.py`, lines 306–1561) is a `handlers` dict of closures, each closed over `app`, `opts`, `verb`, `rest`, `monitor`, `actor`. Verb aliases: `list`/`watches`; `unwatch`/`remove`; `name`/`rename`/`label`/`color`/`colour`; `subscribe`/`service`; `dashboard`/`dashboards`/`open`; `health`/`switches`; `show`/`graph`.

---

### `netrune traffic watch` (id: `traffic-watch`)

- **Purpose:** Start SNMP-polling one or more interfaces on a device, creating an interface watch (and, derived, a device-health watch for the parent switch).
- **Exact syntax:** `netrune traffic watch <device> <interface[,interface2,...]> [--interval <seconds>]`
- **Arguments:**
  - `device` (required, positional 1): resolved via `app.resolve_device_record(rest[0])`. If it doesn't resolve to an inventory device **and** `_is_address(rest[0])` is true (parses as an IP), a synthetic device record is built on the fly: `{"ip": rest[0], "hostname": _snmp_system_name(app, rest[0], opts)}` — one extra SNMP read (`snmp-health`) purely to learn the switch's `sysName` for labelling; an address needs no inventory entry at all. If resolution fails and it's not an address either, error lists up to 8 candidate hostnames/IPs from the ambiguous match.
  - `interface` (required, positional 2+): everything after the device is joined with spaces, then split on `,` if a comma is present (multiple interfaces), else treated as one name (so `"gi 1/0/16"` with an internal space is a single interface name). Each name is matched against the SNMP interface index via `TrafficMonitor.match_interface()` (vendor-abbreviation-normalizing match — `_normalize()` maps `GigabitEthernet`→`gi`, `TenGigabitEthernet`→`te`, `Port-channel`→`po`, etc., and strips punctuation).
  - `--interval <seconds>` (optional, default `60`): must be `str.isdigit()`; not otherwise clamped at parse time (clamping to `[10,3600]` happens inside `TrafficMonitor.add_watch`).
- **Preconditions / gating:** None beyond the above; `--dry-run` short-circuits before any SNMP call and before requiring rest[1] to exist... actually the interface-count check (`len(rest) < 2`) happens *before* the dry-run emit, so dry-run still requires an interface argument to be present.
- **Step-by-step behavior:**
  1. Resolve device (inventory or bare address+SNMP sysName lookup).
  2. If `--dry-run`: emit and stop — no SNMP calls made at all.
  3. Run `netrune-control snmp-index <device_ip>` once (single index walk serves the whole batch of interface names), parsed by `parse_interface_index()` (expects `ifIndex|ifName|ifAlias` lines).
  4. If SNMP returned nothing, error via `_snmp_failure()` — which distinguishes "no credentials configured" (looks for a line `ERROR: ... credentials are configured`) from a generic no-answer message.
  5. For each requested interface name: match against the walked index; if matched, `monitor.find_watch("interface", device_ip, interface_name)` checks for an existing watch first (dedup), else `monitor.add_watch(...)` creates it with `ifindex` pre-cached (avoids a second SNMP resolve on first poll).
  6. `monitor.sync_device_watches(actor)` is called unconditionally afterward — this derives/reconciles a `kind="device"` health watch for every switch that now has ≥1 watched interface port, deleting device watches for switches that no longer have any.
- **Side effects:** Inserts row(s) into `traffic_watch` (SQLite). No files on disk beyond the state DB. Network: one `snmp-index` subprocess call (via legacy `netrune-control` helper) regardless of interface count; if the device was resolved as a bare address, one additional `snmp-health` call for the sysName label.
- **Output shape, table/text mode:** Lines: `"Watching N new interface(s) on <device> every <interval>s:"` + one line per added interface (`"  <name>  SNMP index <ifindex>"`); `"Already watched: ..."` line if some matched an existing watch; `"Not found on the device: ..."` line (with up to 12 seen names) for unmatched names; `"Also collecting switch health for ..."` line if `sync_device_watches` added any; `"Collect with 'netrune traffic poll' or run 'netrune traffic daemon'."` if anything was newly added.
- **Output shape, `--json` mode:** `{"ok": bool(added or existing), "added": [...watch dicts], "already_watched": [...], "not_found": [names], "device_health": {"added":[...], "removed":[...]}}`
- **Exit codes:** `VALIDATION` if the device didn't resolve, interface missing, `--interval` non-numeric, or SNMP index walk failed. `VALIDATION` again if some names were not found **and nothing at all** was added (`missing and not added`). Otherwise `SUCCESS`.
- **Real example:**
  ```
  $ netrune traffic watch SITE-A-SW01 Gi1/0/16,Gi1/0/17 --interval 30
  Watching 2 new interface(s) on SITE-A-SW01 every 30s:
    Gi1/0/16         SNMP index 17
    Gi1/0/17         SNMP index 18
  Also collecting switch health for SITE-A-SW01: uptime, CPU, memory, temperature, and rejected management access, every 300s.
  Collect with 'netrune traffic poll' or run 'netrune traffic daemon'.
  ```
- **Related commands:** `traffic interfaces <device>` to see what's watchable first; `traffic poll`/`traffic daemon` to actually start collecting; `traffic interval`/`pause`/`unwatch` to manage afterward; `traffic subscribe` and `traffic name`/`color` to annotate the new watch for dashboards.

---

### `netrune traffic ping` (id: `traffic-ping`)

- **Purpose:** Start ICMP reachability/latency monitoring against one address, hostname, or known device.
- **Exact syntax:** `netrune traffic ping <target> [--interval <seconds>]`
- **Arguments:**
  - `target` (required): if it parses as an IP (`_is_address`), used verbatim. Otherwise resolved as an inventory device first (`app.resolve_device_record`) — if found, its IP becomes the actual ping target and its cleaned hostname becomes the display label (so a watch is never stored under a name DNS can't resolve, which would report the device "down" forever). If not an inventory device, it must resolve in DNS (`_resolves_in_dns`, via `socket.getaddrinfo`) or the command errors.
  - `--interval <seconds>` (optional, default `60`, `isdigit()`-validated, no error path — non-numeric silently falls back to 60 rather than erroring, unlike `watch`'s `--interval`).
- **Preconditions / gating:** None beyond resolvability. `--dry-run` supported, emits before creating the watch.
- **Step-by-step behavior:** Resolve target → dry-run check → `monitor.add_watch("icmp", target=..., label=..., interval_seconds=..., actor=actor)`.
- **Side effects:** One row in `traffic_watch`. No network call made by this command itself (the actual ping happens later, on poll/daemon).
- **Output shape, table/text mode:** `"Watching ICMP reachability for <label> (<target>) every <N>s."` (label omitted if it equals the target).
- **Output shape, `--json` mode:** `{"ok": true, "watch": {...watch row...}}`
- **Exit codes:** `VALIDATION` if no target given, or target is unresolvable (not an address, not inventory, not DNS-resolvable). `SUCCESS` otherwise.
- **Real example:**
  ```
  $ netrune traffic ping 198.51.100.10 --interval 30
  Watching ICMP reachability for 198.51.100.10 every 30s.
  ```
- **Related commands:** `traffic poll`/`daemon` to collect; `traffic show`/`report` to view `rtt_ms`/`packet_loss_pct`/`jitter_ms`.

---

### `netrune traffic pause` (id: `traffic-pause`)

- **Purpose:** Stop collecting a watch without discarding history.
- **Exact syntax:** `netrune traffic pause <target-phrase>`
- **Arguments:** `target-phrase` is matched via `TrafficMonitor.match_watches()` — an exact `watch_id` wins outright; otherwise every whitespace-separated word must match somewhere across `watch_id, device_name, device_ip, interface_name, target, label, display_name` (AND semantics per word), so `"SITE-A-SW01 Gi1/1/1"` narrows to exactly that port while `"Gi1/1/1"` alone matches it on every switch.
- **Preconditions / gating:** No `--confirm` needed for `pause`/`resume`/`interval` even with multiple matches (only `unwatch`/`remove` require it — see below).
- **Step-by-step behavior:** Resolve matches → `monitor.set_enabled(watch_id, False)` for each. If a collector daemon is running, output notes it "picks this up on its next tick" (watchlist re-read every tick, no restart needed).
- **Side effects:** `UPDATE traffic_watch SET enabled=0` per matched row.
- **Output shape, table/text mode:** `"Paused N target(s):"` + one `_label(watch)` line per target; optional "running collector picks this up" note.
- **Output shape, `--json` mode:** `{"ok": true, "action": "pause", "changed": [...watches...], "count": N, "device_health": {"added":[], "removed":[]}}`
- **Exit codes:** `VALIDATION` if nothing matched. `SUCCESS` otherwise (no multi-match confirm gate for pause).
- **Real example:** `netrune traffic pause Gi1/0/16` → `Paused 1 target(s):\n  SITE-A-SW01 Gi1/0/16`
- **Related commands:** `traffic resume` (inverse); `traffic list`/`status` show `state: paused`.

---

### `netrune traffic resume` (id: `traffic-resume`)

- **Purpose:** Re-enable a paused watch.
- **Exact syntax:** `netrune traffic resume <target-phrase>` — same matcher, gating, and handler (`_cmd_watch_control`) as `pause`, with `verb == "resume"` calling `monitor.set_enabled(watch_id, True)`.
- **Output/exit codes:** identical shape to `pause`, verb label `"Resumed"`.
- **Related commands:** `traffic pause`, `traffic status` to confirm it's collecting again.

---

### `netrune traffic interval` (id: `traffic-interval`)

- **Purpose:** Change a watch's poll cadence.
- **Exact syntax:** `netrune traffic interval <target-phrase> <seconds>`
- **Arguments:** Trailing argument must be `isdigit()` — popped off `rest` before the matcher runs (`if len(rest) < 2 or not rest[-1].isdigit(): usage(...)`); the phrase is everything before it. Seconds is clamped `[10, 3600]` inside `TrafficMonitor.set_interval`.
- **Step-by-step behavior:** Match watches → `monitor.set_interval(watch_id, seconds)` per match. No "collector picks this up" note is printed for `interval` (explicitly excluded: `if running_collector(app) and verb != "interval"`), because a re-timed watch is picked up by the daemon's per-tick `due_watches()` check regardless.
- **Output shape, table/text:** `"Re-timed N target(s) to every <seconds>s:"` + labels.
- **JSON:** `{"ok": true, "action": "interval", "changed": [...], "count": N, "device_health": {...}}`
- **Exit codes:** `VALIDATION` if no match or trailing arg isn't digits; `SUCCESS` otherwise.
- **Related commands:** `traffic stack init` warns separately if a service link's interval is slower than the dashboard's tile-rate window needs, and suggests exactly this command with the computed minimum interval.

---

### `netrune traffic unwatch` (id: `traffic-unwatch`) — alias `remove`

- **Purpose:** Stop monitoring a target and discard its collected samples.
- **Exact syntax:** `netrune traffic unwatch <target-phrase> [--confirm]`
- **Preconditions / gating:** **This is the one watch-control verb that gates on multi-match.** If the phrase matches more than one watch and `--confirm` was not passed, the command refuses (`VALIDATION`) and lists every matched watch with its `watch_id`, telling the operator to either narrow the phrase or add `--confirm` to remove all of them — because removing discards samples irreversibly.
- **Step-by-step behavior:** Match → (confirm gate) → `monitor.remove_watch(watch_id)` per match (hard `DELETE FROM traffic_watch`; associated `traffic_samples`/`traffic_counters` rows for that watch_id are **not** explicitly deleted by this call — they become orphaned and are cleaned up later only by retention pruning, not immediately). Then `monitor.sync_device_watches(actor)` runs — if the switch behind the removed port(s) has no remaining watched ports, its derived device-health watch is also removed (but its own history is left in place, discoverable until retention expires it).
- **Side effects:** `DELETE FROM traffic_watch WHERE watch_id=?` (one or more rows). Possible cascading device-watch removal.
- **Output shape:** `"Stopped monitoring N target(s):"` + labels; `"Stopped collecting switch health for ..."` if a device watch was also dropped; "running collector picks this up" note.
- **JSON:** `{"ok": true, "action": "unwatch", "changed": [...], "count": N, "device_health": {"added": [...], "removed": [...]}}`
- **Exit codes:** `VALIDATION` — no match, or ambiguous multi-match without `--confirm`. `SUCCESS` otherwise. (Registry lists this as `risk_level: warning`, `safety_class: config-write`, `run_supported: false` — it's the only command among the 25 the registry marks as not directly runnable/previewable in the same way as the rest, consistent with it being destructive.)
- **Real example:**
  ```
  $ netrune traffic unwatch "SITE-A-SW01"
  'SITE-A-SW01' matches 3 targets and removing them discards their samples:
    wch-...  SITE-A-SW01 Gi1/0/16
    wch-...  SITE-A-SW01 Gi1/0/17
    wch-...  SITE-A-SW01 health
  Re-run with --confirm to remove all of them.
  ```
- **Related commands:** `traffic pause` if the intent is temporary rather than destructive; `traffic list` beforehand to see exactly what a phrase will match.

---

### `netrune traffic name` (id: `traffic-name`) — aliases `rename`, `label`, `color`, `colour`

- **Purpose:** Give a monitored port (or ICMP target) an operator-chosen display name and/or a fixed dashboard color, independent of its series identity so history is never split.
- **Exact syntax:** `netrune traffic name <target-phrase> <name...> [--color <name-or-#hex>] [--clear] [--confirm]`, or the shorthand `netrune traffic color <target-phrase> <color>` / `netrune traffic colour <target-phrase> <color>`.
- **Arguments:**
  - `--name` is parsed and stripped via `_flag(rest, "--name")` but **its captured value is discarded** (`rest, _ = _flag(rest, "--name")`) — the actual name always comes from the positional words after the target, not from a `--name` flag value. This is a real quirk: passing `--name foo` only removes `foo` from the token stream, it does not set the name to `foo`.
  - `--color <value>` / `--colour <value>`: resolved via `resolve_color()` — accepts one of the four checked palette names `teal, orange, green, violet` (from `SERIES_COLORS`) or an explicit `#rrggbb` hex. Anything else errors, quoting: `"'<value>' is not a colour. Use one of green, orange, teal, violet, or an explicit #rrggbb. Those four were checked together for separation, lightness, and colour-blind readability; a fifth of your own is not."`
  - Shorthand form: when `verb in {"color","colour"}` and no `--color` flag was given but ≥2 positional tokens remain, the **last** positional token is taken as the color value and popped off.
  - `--clear`: removes the name (reverts to device-derived label). Filtered out of `rest` as a bare boolean.
  - Naming requires either `--clear` or ≥2 remaining positional tokens (target + at least one name word); if neither naming nor coloring is requested, errors.
- **Preconditions / gating:** Multi-match (>1 watch matched by the phrase) without `--confirm` → `VALIDATION`, listing candidates by `watch_id` — because naming several distinct ports identically would make them indistinguishable.
- **Step-by-step behavior:** Parse flags → resolve color → match watches → confirm gate → for each match: `monitor.set_display_name(watch_id, chosen)` if naming, `monitor.set_display_color(watch_id, color_or_empty)` if a color was given or clearing.
- **Side effects:** `UPDATE traffic_watch SET display_name=...` and/or `display_color=...`. The name/color travel on separate exposition metrics (`netrune_interface_info`), never as part of a series' label set, so renaming never starts a new time series.
- **Output shape:** `"Named/Recoloured/Cleared the name on N target(s):"` + `"  <label>  ->  <display_name>  <color>"` lines; if color changed, a reminder: `"Regenerate the dashboards to apply it: 'netrune traffic stack init'."`; closing note that history is unaffected.
- **JSON:** `{"ok": true, "renamed": [...watch rows...], "name": chosen}`
- **Exit codes:** `VALIDATION` — no match, ambiguous without confirm, invalid color, or neither name nor color given. `SUCCESS` otherwise.
- **Real example:** `netrune traffic name Gi1/0/12 "Warehouse uplink" --color teal`
- **Related commands:** `traffic subscribe` (also per-link metadata); `traffic stack init` to regenerate dashboards after a color change.

---

### `netrune traffic subscribe` (id: `traffic-subscribe`) — alias `service`

- **Purpose:** Record the contracted (sold) rate of a service link so utilization is measured against the subscription rather than the port's raw line rate.
- **Exact syntax:** `netrune traffic subscribe <target-phrase> [--down <rate>] [--up <rate>] [--facing isp|lan] [--clear] [--confirm]`
- **Arguments:**
  - `--down`/`--up`: parsed by `parse_rate()` — accepts `"100M"`, `"100 Mbps"`, `"1.5G"`, or a bare integer, decimal (not binary) multiples (`k=1e3, m=1e6, g=1e9, t=1e12`). At least one of `--down`/`--up` is required unless `--clear`. Error text: `"'<raw>' is not a rate. Write it as 100M, 20 Mbps, or 1.5G."`
  - `--facing`: `isp` (default) or `lan` — which physical direction the port faces, used to map "download" onto the correct counter (`receive` on an ISP-facing port, `transmit` on a LAN-facing one).
  - `--clear`: removes the subscription, falling back to line-rate-based utilization.
  - Only matches watches of `kind == "interface"` (`monitor.match_watches(needle)` filtered) — an ICMP or device watch can never carry a subscription.
- **Preconditions / gating:** Same multi-match → `--confirm` requirement as `name`.
- **Step-by-step behavior:** Parse/validate → match interface watches → confirm gate → `monitor.set_subscription(watch_id, down, up, faces_lan=...)` per match, storing `subscribed_down_bps`, `subscribed_up_bps`, `faces_lan` columns.
- **Side effects:** `UPDATE traffic_watch SET subscribed_down_bps=?, subscribed_up_bps=?, faces_lan=?`. These are explicitly **soft limits** — nothing is enforced, nothing is discarded; they're purely what the "WAN"/overview dashboard bars are drawn against (`netrune_interface_subscribed_bits` gauge in the exposition, and `ServiceLink` entries feeding `overview_dashboard()`'s tiles).
- **Output shape:** `"Recorded the subscription on N link(s):"` + per-link line showing humanized down/up and facing direction, plus the soft-limit disclaimer; or `"Cleared the subscription..."` when `--clear`.
- **JSON:** `{"ok": true, "links": [...updated watch rows...]}`
- **Exit codes:** `VALIDATION` — no interface match, ambiguous without confirm, unparseable rate, invalid `--facing`, or neither rate given without `--clear`. `SUCCESS` otherwise.
- **Real example:** `netrune traffic subscribe Gi1/0/12 --down 100M --up 20M --facing isp`
- **Related commands:** `traffic stack init` (generates the WAN/overview dashboard tiles from `monitor.service_links()`, and separately warns if a subscribed link's poll interval is too slow for the tile's rate window); `traffic name`/`color` for the same link's display identity.

---

### `netrune traffic list` (id: `traffic-list`) — alias `watches`

- **Purpose:** Show every monitored target with a one-hour activity summary.
- **Exact syntax:** `netrune traffic list` (no arguments/flags parsed).
- **Step-by-step behavior:** `monitor.list_watches()` (all watches, any collector/owner) → for each, a "headline" metric is chosen by kind (`interface→out_bps`, `icmp→rtt_ms`, `device→cpu_percent`) and `monitor.summarize(watch_id, metric, 3600)` (fixed 1-hour window, **not** affected by `--since`) supplies `samples`, `latest` (humanized per kind), and `recent` (a 48-char sparkline).
- **Side effects:** none (read-only).
- **Output shape, table:** columns `watch_id, kind, device_name, interface_name, name, target, collector, interval_seconds, state, samples, latest, recent`. Empty-list message: `"No targets are being monitored. Add one with 'netrune traffic watch <device> <interface>'."`
- **JSON:** `{"ok": true, "rows": [...], "count": N}`
- **Exit codes:** `PARTIAL` if the watchlist is empty, else `SUCCESS`.
- **Related commands:** `traffic watch`/`ping` to add entries; `traffic status` for a freshness/health view instead of a 1h summary; `traffic show` for a deeper per-target read.

---

### `netrune traffic interfaces` (id: `traffic-interfaces`)

- **Purpose:** List every interface SNMP reports on a device, and which are already watched.
- **Exact syntax:** `netrune traffic interfaces <device>`
- **Arguments:** `device` required, resolved via `app.resolve_device_record` — **no bare-address fallback here** (unlike `watch`), so an address not in inventory errors with `"'<x>' did not resolve to one device."` and points at `netrune inventory list <target>`.
- **Step-by-step behavior:** `netrune-control snmp-index <ip>` (timeout `opts.timeout or 60`) → `parse_interface_index()` → mark each row `watched: "yes"|""` by cross-referencing this device's existing `interface_name` watches (case-insensitive).
- **Side effects:** One SNMP subprocess call; no writes.
- **Output shape, table:** columns `ifindex, name, alias, watched`. On empty result, prints `_snmp_failure()` text instead of a table.
- **JSON:** `{"ok": bool(rows), "rows": [...], "count": N}`
- **Exit codes:** `PARTIAL` if SNMP returned nothing (bad community, ACL, or unreachable device), `SUCCESS` otherwise. `VALIDATION` if device didn't resolve.
- **Related commands:** Run before `traffic watch` to find the exact interface spelling/index.

---

### `netrune traffic health` (id: `traffic-health`) — alias `switches`

- **Purpose:** Show uptime, control-plane CPU, memory, temperature, and session count for every switch behind a watched port.
- **Exact syntax:** `netrune traffic health [<device>] [--since <window>]`
- **Arguments:** `device` optional — if given, resolved and used to filter to that device's health watch only; if it fails to resolve, errors listing candidates.
- **Step-by-step behavior:** Filters `list_watches()` to `kind == "device"` (optionally matching `device_ip`). If none exist, explains these are auto-added by `traffic watch` and stops. Window = `resolve_window() or 21600` (6h fallback, silently swallowing an invalid `--since` — see the global-facts note above). For each device watch, pulls `summarize()` for `uptime_seconds, cpu_percent, memory_percent, temperature_celsius, logged_in_users`, formatting a dash `-` for any metric the device doesn't answer (absence ≠ zero), plus a CPU sparkline.
- **Side effects:** none.
- **Output shape, table:** columns `switch, address, state, uptime, cpu, memory, temp, sessions, cpu_trend`, followed by 3 static footnotes (dash meaning, failed-SSH-login caveat — that's not in any standard MIB).
- **JSON:** `{"ok": true, "rows": [...], "count": N}`
- **Exit codes:** `PARTIAL` if no device-health watches exist at all; `SUCCESS` otherwise (note: never fails just because a metric is missing per-switch — dashes are normal).
- **Related commands:** Watches are created automatically by `traffic watch`/removed by `sync_device_watches` when the last port on a switch is unwatched; not independently addable.

---

### `netrune traffic poll` (id: `traffic-poll`)

- **Purpose:** Collect exactly one round from every enabled watch, synchronously, in the foreground.
- **Exact syntax:** `netrune traffic poll` (no flags; respects global `--timeout`).
- **Step-by-step behavior:**
  1. `monitor.sync_device_watches(actor)` — reconcile derived device-health watches first.
  2. `monitor.poll(opts=opts)`.
- **Important architectural nuance verified in `traffic.py`:** `TrafficMonitor.poll()`'s default watch selection is `self.list_watches(enabled_only=True)` — **it does not pass `owned_only=True`**. This differs from the daemon's loop, which calls `due_watches(..., )` → internally `self.list_watches(enabled_only=True, owned_only=True)`. Practically: a manual `traffic poll` on a laptop that has pulled watches from a remote poller will attempt to poll those remote-owned interface/device watches too (their device lives on a network this machine can't reach), producing spurious per-target errors in the `errors` list — this is a real, verifiable behavior difference between `poll` and `daemon`, not a documentation gap.
  3. Inside `poll()`: work is grouped into per-device SNMP interface-counter jobs, per-target ICMP jobs, and per-device health jobs, run concurrently (`ThreadPoolExecutor`, `POLL_WORKERS=8` max) when there's more than one job. Counter deltas are computed against the last stored reading per `(watch_id, collector)`, guarded against counter wrap/reset (`counter_delta`) and implausible rates above line-rate/ceiling (`plausible_rate`, `MAX_PLAUSIBLE_BPS=800 Gbps` absolute backstop, `RATE_TOLERANCE=1.05`). A device restart (uptime decreased) discards that interval's delta as unmeasurable. A counter-width mismatch (64-bit ↔ 32-bit octet counter swap) discards the reading and reports it as an error rather than storing a corrupted rate.
- **Side effects:** Writes to `traffic_samples` (rate/gauge readings), `traffic_counters` (latest raw counter per watch/collector, used by the exposition), and `traffic_counter_log` (throttled to one row per 60s per counter — `COUNTER_LOG_INTERVAL` — for replay/backfill). Network: one SNMP `snmp-counters` call per device with watched interfaces, one `snmp-health` call per device-health watch, one `ping -c 3 -W 2` per ICMP watch (via `app.icmp_probe`).
- **Output shape, table/text:** `"Collected N sample(s) from M watch(es) as '<collector>'."` + up to 5 error lines (`  <device-or-target>: <error>`).
- **JSON:** `{"ok": bool, "observed_at": epoch, "collector": id, "watches": N, "samples_recorded": N, "errors": [...], "counter_width_mismatches": N}`
- **Exit codes:** `SUCCESS` if `payload["ok"]` (no errors, or at least one sample was recorded despite some errors); `PARTIAL` if there were errors and zero samples recorded.
- **Related commands:** `traffic daemon` for continuous collection; `traffic status` to check freshness after.

---

### `netrune traffic daemon` (id: `traffic-daemon`)

- **Purpose:** Run the collector continuously in the foreground until interrupted — the long-running collector process the systemd unit wraps.
- **Exact syntax:** `netrune traffic daemon [--interval <seconds>]`
- **Arguments:** `--interval` (optional) is a **global override** applied to every watch (clamped `[10, 3600]`), replacing each watch's own configured interval for this run only; without it, each watch keeps its own cadence.
- **Preconditions / gating:** Errors (`VALIDATION`) if a collector is already running (checked via `running_collector()` reading and validating the PID in `traffic-collector.json`), pointing at `traffic status`. Errors if nothing is enabled to monitor.
- **Step-by-step behavior:**
  1. `sync_device_watches(actor)`.
  2. Writes PID file `<state_dir>/traffic-collector.json` = `{"pid", "collector", "started_at", "override_interval"}`, mode `0600`.
  3. Installs a SIGTERM handler that raises the same `KeyboardInterrupt` subclass Ctrl+C would (`_stop_on_sigterm`) — this is what lets the systemd unit's `KillSignal=SIGTERM` trigger the identical cleanup path (pidfile removal) as a manual Ctrl+C, rather than dying mid-statement and leaving a stale "running" pidfile.
  4. Loop: every ~5s tick, `monitor.due_watches(attempts, override_interval)` computes which watches have crossed their own interval since last attempt (per-watch, not global), `monitor.poll(due, opts=opts)` if any are due, progress line updated (`app._progress_update`). The watchlist is **re-read every tick** — `watch`/`pause`/`resume`/`unwatch`/`interval` issued from another terminal take effect without restarting the daemon.
  5. On Ctrl+C/SIGTERM: prints round/sample summary, `finally:` unlinks the pidfile.
- **Side effects:** Same per-round writes as `poll`, repeated indefinitely. Writes/deletes the PID file. Runs SNMP/ICMP network calls on each due watch's own schedule.
- **Output shape:** Everything goes to stderr (`eprint`)/a live progress line — `output_type: terminal`, and the registry correctly marks `run_supported: false` (it never exits on its own).
- **Exit codes:** `SUCCESS` on clean Ctrl+C/SIGTERM stop. `VALIDATION` if already running or nothing to watch.
- **Real example:** `netrune traffic daemon` → `Traffic collector 'laptop' is collecting on each target's own interval, from 30s. Ctrl+C stops it.`
- **Related commands:** Normally started as `netrune-collector.service` via `traffic stack up`, not run manually except for foreground debugging; `traffic status` to check it; `traffic stack status` for the systemd view of the same process.

---

### `netrune traffic status` (id: `traffic-status`)

- **Purpose:** Show whether a collector is running and each target's freshness/health.
- **Exact syntax:** `netrune traffic status` (no domain flags).
- **Step-by-step behavior:** `running_collector(app)` reads/validates the pidfile. For every watch (any owner), computes `age` from a **fixed 24-hour** `summarize()` window (metric = `out_bps` for interfaces, `rtt_ms` for ICMP — device-health watches get no row here at all, oddly, since the loop only computes `metric` for those two kinds but iterates `watches` which includes device-kind too... actually re-checking: the loop iterates all watches including device kind, and for device kind `metric` defaults to `"rtt_ms"` via the ternary `"out_bps" if watch["kind"]=="interface" else "rtt_ms"`, which is wrong for device watches but harmless — `summarize` just returns no samples for a metric name that doesn't exist on that watch, so device rows show `last_sample: never`). `_next_poll()` and `_health()` (module-level helpers) compute display strings from `owner`, `enabled`, collector-running state, and age vs. `interval*2+15` staleness threshold.
- **Side effects:** none.
- **Output shape, table:** Header line naming the running collector's id/pid/start-time, or "No collector is running..."; then columns `target, state, every, last_sample, next_poll, health`. `next_poll` values: `"on next pull"` (remote-owned), `"paused"`, `"no collector"`, `"now"`, or `"in Ns"`. `health` values: `"remote"`/`"pulled Ns ago"` (remote-owned), `"paused"`, `"no data yet"`, `"ok"`, or `"stale"` (age > 2×interval+15s).
- **JSON:** `{"ok": true, "collector": {...pidfile record or {}...}, "running": bool, "rows": [...]}`
- **Exit codes:** Always `SUCCESS`.
- **Related commands:** `traffic daemon` to start a collector; `traffic verify` for the full pipeline (not just the collector).

---

### `netrune traffic show` (id: `traffic-show`) — alias `graph`

- **Purpose:** Terminal sparkline view of throughput/latency for one or more watches.
- **Exact syntax:** `netrune traffic show [<target-phrase>] [--since <window>]`
- **Arguments:** `target-phrase` optional — if omitted, **all** watches are shown (`monitor.list_watches()`, not filtered to enabled); if given, `monitor.match_watches(phrase)` (same word-AND matcher as pause/name/etc., no confirm gate since this is read-only). `--since` window default 3600s via `resolve_window()`, errors on unparseable value.
- **Step-by-step behavior:** Per watch, picks metric pair by kind (`in_bps,out_bps` for interface; `rtt_ms,packet_loss_pct` for icmp) and calls `summarize()` per metric over the window, rendering a 48-char sparkline plus "now X peak Y" (or "no samples yet").
- **Side effects:** none.
- **Output shape:** Block per watch: `"<label>  [<watch_id>]"` (+`(paused)` if disabled), then one line per metric with the sparkline.
- **JSON:** `{"ok": true, "window_seconds": N, "series": [{"watch_id":..., "metric":..., "samples":..., "latest":..., "peak":..., "mean":..., ...}, ...]}`
- **Exit codes:** `PARTIAL` if the phrase matched nothing; `SUCCESS` otherwise.
- **Related commands:** `traffic report` for the persisted HTML equivalent; `traffic dashboard` for the live Grafana/Perses view.

---

### `netrune traffic report` (id: `traffic-report`)

- **Purpose:** Render a self-contained HTML report (inline SVG charts, no external assets) for the collected window.
- **Exact syntax:** `netrune traffic report [<target-phrase>] [--since <window>] [--out <path>]`
- **Arguments:** `target-phrase` optional (same matcher/fallback as `show`). `--out`: if given, must be non-empty (`--out ""` errors "`--out requires a file path.`"); path is `os.path.expanduser`'d. Default path: `<state_dir>/reports/traffic-<unix-epoch>.html`.
- **Step-by-step behavior:** Resolve window/watches → for each watch, build a "card": `readings` = `summarize()` per relevant metric, `series` = full `series()` rows per metric (for the SVG polyline), `speed_bps` extracted from the `raw_json` blob of any `in_bps`/`out_bps` sample (carries `{"speed_bps": ...}`), `collectors` = union of collectors that contributed. `render_report()` (in `traffic_report.py`) draws inline SVG line/area charts (teal=rx, rust=tx) with a 3-tier status chip (`ok`/`warn`/`crit`) per card based on peak utilization or ICMP loss/unreachability, and a page-level headline reflecting the worst card.
- **Side effects:** Writes exactly one HTML file to disk; `path.parent.mkdir(parents=True, exist_ok=True)`; `os.chmod(path, 0o600)` after writing (report may contain topology/naming info, kept private).
- **Output shape, table/text:** `"Wrote a traffic report for N target(s) covering the last M minute(s):\n<path>"`
- **JSON:** `{"ok": true, "path": str, "targets": N, "window_seconds": N}`
- **Exit codes:** Always `SUCCESS` (no error path beyond the window/`--out` validation, which are `VALIDATION`).
- **Related commands:** `traffic show` for the live terminal equivalent; `traffic backfill`/`stack` for the persistent dashboard alternative.

---

### `netrune traffic exporter` (id: `traffic-exporter`)

- **Purpose:** Serve the collected readings as a Prometheus exposition endpoint for VictoriaMetrics (or any Prometheus-compatible scraper) to pull.
- **Exact syntax:** `netrune traffic exporter [--bind <host:port>] [--once] [--confirm]`
- **Arguments:**
  - `--bind` (default `127.0.0.1:9713`, via `split_bind()` — accepts `HOST:PORT`, `[v6]:PORT`, a bare port, or a bare host). Parse failure → `VALIDATION` with the raised `ValueError` text.
  - `--once`: renders one snapshot to stdout via `MetricsExporter(monitor).render()` and exits immediately — **no server is started at all**, this is a one-shot dump for debugging/piping.
- **Preconditions / gating — the non-loopback confirm rule:** If the parsed bind host is not loopback (`is_loopback()` — checks `127.0.0.1`/`::1`/`localhost`/any IP whose `.is_loopback` is true) and `--confirm` was not passed, the command refuses with: `"'<host>' is not a loopback address. The exposition has no authentication of its own, so binding it there publishes your topology. <reach-text> Re-run with --confirm if that is the intent."` where `<reach-text>` is `"Anyone on the same tailnet can read it."` if the host falls in the Tailscale CGNAT range `100.64.0.0/10` (`is_tailnet()`), else `"Anyone who can reach that address can read it."` **This exposition endpoint has zero authentication of its own** — the Basic Auth added this session applies to VictoriaMetrics, not to this exporter; a confirmed non-loopback exporter bind is still an open read of every counter/topology label.
- **Step-by-step behavior:** Bind check → confirm gate → `serve_forever(monitor, host, port)` starts a `ThreadingHTTPServer` on a background daemon thread → SIGTERM converted to KeyboardInterrupt → foreground `while True: sleep(3600)` loop, woken only by Ctrl+C/SIGTERM → `server.shutdown()`.
- **Side effects:** Opens a listening TCP socket (only, no writes to disk, no device contact — the module docstring is explicit: "it talks to no device and runs no command"). Serves `GET/HEAD /metrics` and `/` (Prometheus text, `Content-Type: text/plain; version=0.0.4; charset=utf-8`), `GET/HEAD /health` (`200 ok`), 404 on anything else. Every response includes `Cache-Control: no-store` and `X-Content-Type-Options: nosniff`.
- **Output shape:** stderr only — `"Exposition on http://<host>:<port>/metrics for VictoriaMetrics to scrape. Ctrl+C stops it."` + the no-device/no-command disclaimer line.
- **Exit codes:** `VALIDATION` — bad `--bind` syntax, non-loopback without `--confirm`, or `OSError` binding the port (address in use, permission). `SUCCESS` on clean stop (or immediately after `--once`).
- **Related commands:** Normally run as `netrune-exporter.service` by `traffic stack up`, which passes `--confirm` automatically into the unit's `ExecStart` when the operator confirmed a non-loopback bind at `stack init` time (a systemd service can't answer an interactive prompt itself). `traffic verify` checks this endpoint is answering as step 3 of its chain.

---

### `netrune traffic backfill` (id: `traffic-backfill`)

- **Purpose:** One-time import of history collected before the metrics stack existed (derived rates sitting in SQLite `traffic_samples`) into VictoriaMetrics, so old data appears alongside live-scraped data.
- **Exact syntax:** `netrune traffic backfill [--url <victoriametrics-url>] [--since <window>]`
- **Arguments:** `--url` defaults to config `traffic_victoriametrics_url` or `http://127.0.0.1:8428`. Window: **special-cased** — `window = window if opts.since else 30 * 86400`; i.e. without an explicit `--since`, this command backfills the last **30 days**, not the domain-wide 1-hour default other commands fall back to.
- **Step-by-step behavior:** `_backfill_body()` queries `traffic_samples` directly (`SELECT watch_id,metric,value,observed_at,collector ... WHERE observed_at>=? AND metric IN (in_bps,out_bps,in_utilization_pct,out_utilization_pct,rtt_ms,packet_loss_pct) ORDER BY observed_at`), and renders each row as a Prometheus exposition line **with an explicit millisecond timestamp**, under gauge names prefixed `netrune_history_*` (e.g. `netrune_history_interface_transmit_bits_per_second`) — deliberately distinct from the live `netrune_interface_*` counter names, because these are derived rates Netrune already computed, not raw counters, and the code is explicit that re-deriving a counter by integrating them back "would invent readings nobody took."
  - Dry-run: shows count + first 5 lines, no network call.
  - POST body to `{url}/api/v1/import/prometheus`.
  - On success, **best-effort** POST to `{url}/internal/resetRollupResultCache` (VictoriaMetrics-specific cache-busting endpoint) — because a time range already queried before the import keeps returning its cached empty answer otherwise; failure here is noted in output but not fatal.
- **Side effects:** Only network (VictoriaMetrics import + optional cache reset); no local writes. Read-only against the local SQLite store.
- **Output shape:** `"Imported N historical sample(s) into <url>."` + explanation of the `netrune_history_*` naming and that imported points must be queried over a range (`query_range`), not an instant `query`, plus cache-reset status note.
- **JSON:** `{"ok": true, "samples": N, "url": str, "status": http_code, "cache_reset": bool}`
- **Exit codes:** `PARTIAL` if nothing to import (`{"ok": false, "samples": 0}`). `VALIDATION` on unreachable VictoriaMetrics (via `usage()`, not a plain `PARTIAL` emit — worth noting this command routes connection failure through the usage-error path rather than `PARTIAL`). `SUCCESS` on import (even if the cache-reset sub-step failed).
- **Related commands:** Run once, right after `stack init`/`stack up`, per the generated README's "Order of operations" (§4, after starting the collector/exporter/VictoriaMetrics/vmalert/grapher).

---

### `netrune traffic stack` (id: `traffic-stack`)

This single id fronts several sub-actions: `init` (default), `show`, `graphers`, `up`, `down`, `restart`, `status`, `install`.

- **Purpose:** Generate (and optionally install/start) the entire local metrics stack — systemd units, scrape config, alert rules, dashboard provisioning, docker-compose file, and (conditionally) a VictoriaMetrics Basic Auth credential file.
- **Exact syntax:**
  `netrune traffic stack [init|show] [--dir <path>] [--url <vm-url>] [--bind <host:port>] [--retention <duration>] [--scrape-interval <seconds>] [--unit-dir <path>] [--grapher <name>] [--grapher-port <port>] [--role full|collector] [--publish <host>] [--accept-push] [--grapher-deploy auto|container] [--confirm]`
  `netrune traffic stack graphers`
  `netrune traffic stack up|down|restart|status|install`
- **Arguments (init/show):**
  - `--role`: `full` (default) or `collector`. Validated against `ROLES = (ROLE_FULL, ROLE_COLLECTOR)`.
  - `--grapher`: `grafana` (default, from config `traffic_grapher`), `perses`, or `none` (vmui built into VictoriaMetrics). Validated via `get_grapher()`.
  - `--publish <host>`: sets the exporter bind host while **preserving the existing port** — implemented as `bind_arg = f"{publish_arg}:{(bind_arg or DEFAULT_EXPORTER_BIND).rsplit(':',1)[-1]}"`.
  - `--accept-push`: boolean, stripped from `rest`.
  - `--dir`/`--unit-dir`: override the default `<state_dir>/metrics-stack` root and unit-output directory respectively.
  - `--grapher-deploy`: `auto` (default — prefers a native binary if `shutil.which()` finds `grafana`/`grafana-server`) or `container` (forces the Docker unit even if a native binary is present).
- **Preconditions / gating — this session's unified non-loopback rule:**
  1. **`--accept-push` always requires `--confirm`**, independent of bind address: `"--accept-push lets anything that can reach this machine write readings into its store. Publishing dashboards is read-only; this is not, so confirm it."`
  2. If `--role collector`, the exporter bind host is forced to `127.0.0.1` regardless of `--bind`/`--publish` (a collector generates no exposition to publish, "so there is nothing to publish and nothing to consent to").
  3. **The same non-loopback-bind gate `traffic exporter` enforces is duplicated here** for the *generated unit's* bind: if the resolved `bind_host` is not loopback and `--confirm` was not given, refuse with wording nearly identical to `exporter`'s ("A service cannot be asked to confirm at start time, so confirm here."). A code comment states explicitly this rule is intentionally mirrored between `traffic_cli.py`'s `stack init` and `setup_cli.py`'s `cmd_setup` — `setup` hardcodes `--confirm` onto the `stack init` args it forwards internally, so `stack init`'s own gate is a no-op when reached via `setup`, and the comment flags that **any future new way to expose data beyond loopback must be mirrored in both places**.
- **Step-by-step behavior (`init`):**
  1. Parse/validate all flags, resolve `root` (default `<state_dir>/metrics-stack`), `bind` (default `127.0.0.1:9713`), `url` (default `http://127.0.0.1:8428`), `retention` (default `90d`), `scrape` (`--scrape-interval` or `_suggested_scrape(monitor)` — half the shortest enabled watch's interval, clamped `[5,300]`s, 30s if no watches, to avoid the collector/scraper aliasing artifact the code comments explain in detail).
  2. Detect installed binaries via `shutil.which` for `netrune, victoria-metrics, vmalert, grafana/grafana-server`.
  3. **`storage_bind` computation — this is the Basic Auth trigger:** `storage_bind = f"{publish_arg or '0.0.0.0'}:{url.rsplit(':',1)[-1]}" if accept_push else ""`. So `--accept-push` alone (with confirm) binds **VictoriaMetrics itself** to `0.0.0.0:<vm-port>` by default, or to `<--publish host>:<vm-port>` if `--publish` was also given.
  4. `stack_files(...)` (in `traffic_stack.py`) builds every file. When `storage_bind` is truthy, it additionally includes `root / "victoriametrics.auth"` in the returned file map, generated by `_victoriametrics_credential(root)`: **reads the existing file's contents if one is already there and reuses it verbatim** (idempotent across repeated `stack init` runs — regenerating would silently invalidate every remote poller's already-distributed push URL), else generates a fresh `secrets.token_urlsafe(24)` random token.
  5. `action == "show"`: prints every generated file's path+body without writing anything, `SUCCESS`.
  6. Otherwise, writes each file (`mkdir parents`, then `write_text`); the credential file specifically gets `chmod(0o600)` right after writing (every other generated file keeps default permissions).
  7. Retires (`unlink`s) any `netrune-*.service` file under `root/systemd` that the current generation no longer produces (e.g. switching `--grapher`).
  8. Warns (stderr, outside the JSON payload) if any subscribed service link's poll interval exceeds what the overview dashboard's tile rate-window (`TILE_RATE_WINDOW="1m"`, needs polling at least every `window/4`≈15s) can render accurately without overstating.
  9. `role == collector` output branch: short message, no `root/storage` dir created, no push-note.
     `role == full` branch: creates `root/storage`; if `accept_push`, builds `push_note` embedding the actual generated token read back out of `files[credential_path]`, printing the exact command to hand the remote poller: `netrune config set traffic_push_url http://netrune:<token>@<storage_bind>`.
- **What exactly gets generated for the Basic Auth flow:**
  - Credential file: `<root>/victoriametrics.auth`, mode `0600`, plain text = the bearer token (no username stored — username is the hardcoded constant `VM_CREDENTIAL_USER = "netrune"`).
  - VictoriaMetrics systemd unit (`netrune-victoriametrics.service`) `ExecStart` gets two extra flags appended **only when `storage_bind` is set**: ` -httpAuth.username=netrune -httpAuth.password=file://<root>/victoriametrics.auth`. This gates VictoriaMetrics's **entire HTTP API** (query, `/api/v1/import/*`, `/admin`, delete) — not just the import path, since `-httpAuth.*` is a server-wide VictoriaMetrics flag.
  - `-httpListenAddr` on that same unit becomes `storage_bind` (e.g. `0.0.0.0:8428`) instead of the loopback default.
  - `docker-compose.yml`'s `victoriametrics` service gets the equivalent `-httpAuth.username`/`-httpAuth.password=file:///etc/netrune/victoriametrics.auth` command args plus a read-only volume mount of the credential file into the container.
  - `README.md` gets a generated "Accepting a remote poller's push" section spelling out the exact `traffic_push_url` value (with embedded `user:token@host:port`) and a rotation caveat (rotating means manually editing the file and re-pasting the URL everywhere it's used — there's no rotate subcommand).
- **Side effects:** Files written under `root` (`systemd/*.service[.timer]`, `scrape.yml`, `alerts.yml`, `docker-compose.yml`, `README.md`, grapher-specific provisioning under `root/grafana` or `root/perses`, and conditionally `victoriametrics.auth`). No subprocess/network calls during `init`/`show` themselves.
- **Output shape, table/text:** File listing + role-specific guidance block (see step 9 above).
- **JSON (`init`):** `{"ok": true, "root": str, "files": [paths...], "scrape_interval": N, "grapher": name}` (collector role: `{"ok": true, "root": str, "role": "collector", "files": [...]}`).
- **JSON (`show`):** `{"ok": true, "files": {path: body, ...}}`
- **`stack graphers` sub-action:** table of `grafana/perses/none` — columns `grapher, name, deployment (image or "built into VictoriaMetrics"), port, selected`; always `SUCCESS`.
- **`stack up`/`down`/`restart`/`status`/`install`:** delegate to `_stack_service()` (module-level helper, ~lines 1878–1998), all operating on `~/.config/systemd/user/` and the `netrune-metrics.target`:
  - `install`/`up`: copies changed unit files from `root/systemd` into `~/.config/systemd/user/` (content-diffed, only rewrites what changed), removes+disables units the current generation no longer produces, `systemctl --user daemon-reload`. `up` additionally `enable --now netrune-metrics.target`, then individually `enable --now` any unit that is a `.timer` or a `.service` with no matching `.timer` (oneshot services driven by a timer are deliberately **not** enabled themselves, or they'd fire once at boot and never again on schedule), and reports whether `loginctl ... Linger` is `yes` (units stop at logout otherwise). `install` alone stops after copying — no start.
  - `down`/`restart`: `systemctl --user stop|restart netrune-metrics.target` plus explicit per-service stop/restart (since `PartOf=` propagates stop/restart to member units, but a unit the target doesn't reference wouldn't be covered).
  - `status`: per-service `systemctl --user is-active`/`is-enabled`, diffs the installed copy's content against the generated copy to flag `stale` units, reports linger state. If the user systemd manager itself isn't reachable, returns the specific diagnosis from `user_manager_problem()` instead of a unit table.
  - All of these error with `"No generated units at <root>/systemd."` (`VALIDATION`) if `stack init` was never run.
- **Exit codes:** `init`/`show`: `SUCCESS` (validation failures are `VALIDATION`). `up`/`install`: `SUCCESS`, or `PARTIAL` if `systemctl enable --now` on the target failed. `down`/`restart`: `SUCCESS`/`PARTIAL` on `systemctl` return code. `status`: `SUCCESS`, or `PARTIAL` if the user manager isn't running.
- **Real example:**
  ```
  $ netrune traffic stack init --accept-push --confirm
  Wrote the metrics stack to ~/.local/state/netrune/metrics-stack:
    .../systemd/netrune-collector.service
    .../systemd/netrune-exporter.service
    .../systemd/netrune-victoriametrics.service
    ...
    .../victoriametrics.auth

  Grapher: Grafana on http://127.0.0.1:3000.
  Scrape interval set to 30s to stay inside the shortest watch interval.
  Read .../README.md for the order to start things in.

  Accepting pushes on 0.0.0.0:8428, gated by the token in .../victoriametrics.auth (mode 0600). Give the remote poller:
    netrune config set traffic_push_url http://netrune:AbC123.../@0.0.0.0:8428
  ```
- **Related commands:** `traffic stack init` → `traffic stack up` → `traffic stack status`/`traffic verify` is the standard lifecycle (see Subsystem architecture below). `traffic backfill` right after first bring-up. `traffic dashboard`/`traffic dashboard --open` once the grapher is answering.

---

### `netrune traffic verify` (id: `traffic-verify`)

- **Purpose:** Walk the entire metrics pipeline link by link and report exactly where it breaks, in dependency order so the first failure is the cause, not a downstream symptom.
- **Exact syntax:** `netrune traffic verify [--url <vm-url>] [--bind <host:port>] [--grapher <name>] [--grapher-port <port>]`
- **Step-by-step behavior (`_verify_chain`):** Detects whether the local stack was generated with `--role collector` (`root/metrics-stack/systemd` exists but has no `netrune-exporter.service`) — if so, stops after step 2 and reports the pipeline as intentionally ending there (no false failures for components a collector deliberately doesn't run). Otherwise runs, in order:
  1. **watchlist** — fail if nothing monitored, warn if all paused, pass with active/total count.
  2. **collector** — pass if a daemon is running (pidfile+PID alive); warn if not running but the newest sample is <900s old (was recently polled manually); fail otherwise.
  3. **exposition** — `GET http://<bind>/metrics`; fail if unreachable; else counts distinct `# TYPE` metric families, warn if zero.
  4. **victoriametrics** — `GET {vm_url}/health`; fail if unreachable (and marks `scrape` failed-skipped too).
  5. **scrape** — `{vm_url}/api/v1/query?query=up`; `"1"`→pass, `"0"`→fail ("target is down"), no series→fail ("is promscrape.config pointed at the exposition?").
  6. **rate derivation** — probes `8 * rate(netrune_interface_receive_bytes_total[2m])`; pass if any series resolves, else warn ("a counter needs two scrapes before it has one").
  7. **grapher** — pass trivially for `none`/vmui; else `GET <health_path>` on the grapher's base URL.
  On a collector-only stack: check 3 is replaced by a single `"role"` pass line, plus an `"ownership"` warn if any watches here are owned by a different (remote) collector.
- **Side effects:** Read-only HTTP GETs against the local exposition, VictoriaMetrics, and the grapher's health endpoint; no writes.
- **Output shape, table/text:** One line per check: `"  ok  /WARN/FAIL  <check name padded>  <detail>"`, then a summary count line; if any failed, appends `user_manager_problem()` diagnosis (all these are user services — a down `systemctl --user` manager fails every one of them for one shared cause, so it's surfaced once rather than as N separate mysteries).
- **JSON:** `{"ok": not_failed, "checks": [{"check","state","detail"}, ...], "failed": N, "warnings": N}`
- **Exit codes:** `PARTIAL` if any check failed; `SUCCESS` otherwise (warnings alone don't fail it).
- **Related commands:** Run after `traffic stack up`; complements `traffic stack status` (which only checks systemd unit state, not the data actually flowing end-to-end).

---

### `netrune traffic export` (id: `traffic-export`)

- **Purpose:** Print this collector's own stored readings as JSONL to stdout, for another install to pull/merge — the file-based half of the sync mechanism.
- **Exact syntax:** `netrune traffic export [--since <window>]`
- **Arguments:** `--since` window; if given, `since = now - window`; if omitted, **defaults to a fixed 24 hours** (`now - 86400`), independent of the domain's usual 3600s fallback.
- **Step-by-step behavior:** `export_rows(monitor, since=since)` — a generator yielding, in strict order: one `{"record":"meta", "schema":1, "collector": id, "since", "until", "generated_at"}` line; then one `{"record":"watch", ...}` line per watch **this collector owns** (`monitor.owns(watch)` — empty/self owner only, never re-exporting something already pulled from elsewhere); then `{"record":"sample", ...}` lines from `traffic_samples` for those watch_ids in the window; then `{"record":"counter", ...}` lines from `traffic_counters` (unwindowed — always the latest raw counter state, needed so the receiving side can compute deltas going forward). Each row rendered via `render_jsonl()` as one compact, key-sorted JSON object per line, `print()`ed directly.
- **Side effects:** None — purely reads local SQLite. **Bypasses `app.emit` entirely** — this is deliberately raw stdout, meant to be piped over SSH and parsed by `parse_jsonl()` on the other end; `--json` has no special effect on this command's output shape.
- **Output shape:** Raw JSONL stream, one row object per line, `meta` line always first.
- **Exit codes:** Always `SUCCESS` unless `--since` is unparseable (`VALIDATION`).
- **Real example:** `netrune traffic export --since 24h > poller.jsonl`
- **Related commands:** Consumed by `traffic pull --file <path>` (direct) or `traffic remote <name> status`-style SSH invocation from the puller (`traffic pull --remote <name>` runs `traffic export --since <window>` on the remote for you). This is the mechanism `netrune-export.service`/`.timer` (generated for `--role collector` stacks when `--export-to` was configured) automates on a schedule, writing atomically via a `.part` temp file + `mv`.

---

### `netrune traffic pull` (id: `traffic-pull`)

- **Purpose:** Fetch a remote poller's readings (via SSH or a file) and merge them into this machine's local store.
- **Exact syntax:** `netrune traffic pull (--remote <name> | --file <path> | <name>) [--since <window>]`
- **Arguments:**
  - `--remote <name>`: looked up in `RemoteStore`; error lists known remotes if not found.
  - `--file <path>`: reads a local export file instead of SSH; `--file -` reads stdin. If a filename doesn't exist, errors. If a `name` positional/`--remote` is *also* given alongside `--file`, that name must already be a known remote (used only to record the pull's bookkeeping against it) or it errors.
  - Bare positional (no `--remote`/`--file`): treated as the remote name.
  - `--since`: **ignored entirely when `--file` is used** — the whole file is always merged regardless of window, because "a window would silently drop readings the operator already carried across," and merging is idempotent so re-reading costs nothing. For an SSH pull without `--since`, resumes from the target remote's own `last_sample_at` marker (or `now-86400` if never pulled) — same catch-up-from-marker pattern as `push`.
- **Step-by-step behavior:**
  1. Resolve source (remote lookup or file read).
  2. For SSH: `run_remote(remote, ["traffic","export","--since", f"{elapsed}s"], timeout=min(opts.timeout or 120, 900))` — this literally invokes the *other machine's* `netrune traffic export` command over `ssh -o BatchMode=yes -o ConnectTimeout=... <dest> -- 'netrune [--profile P] traffic export --since Ns'`. `BatchMode=yes` means a missing SSH key fails fast rather than hanging on a password prompt.
  3. `parse_jsonl(body)` validates strictly — rejects non-JSON lines, unknown `record` values, requires the first line to be `record:"meta"`, and refuses (`RemoteError`) if the export's `schema` is newer than this install's `EXPORT_SCHEMA=1` (forward-compat guard telling the operator to upgrade).
  4. `merge_export(monitor, rows, dry_run=opts.dry_run)`:
     - **Refuses outright** (`RemoteError`) if the export's declared `collector` equals this machine's own `collector_id()` — two collectors sharing an identity would produce one series that's neither's, so this is a hard stop, not a warning.
     - Watch rows: `INSERT ... ON CONFLICT(watch_id) DO UPDATE ...`, always stamped with `owner = <remote's collector id>` — so a laptop never accidentally tries to poll a switch only the remote can reach.
     - Sample rows: `INSERT OR IGNORE` against the unique identity index `(collector, watch_id, metric, observed_at)` — a repeated pull of overlapping data is a true no-op, not a duplicate; `merged` count = actually-inserted rows, `already_present` = the rest.
     - Counter rows: `INSERT OR REPLACE` (always take the newest raw counter state from the remote).
  5. On success (non-dry-run, named remote), `store.record_pull(name, collector, newest_sample_at)` updates `traffic_remotes.last_pull_at`/`last_sample_at`/`collector_id` bookkeeping (used by the next resume-from-marker pull).
- **Side effects:** Writes to `traffic_watch`, `traffic_samples`, `traffic_counters` locally. One SSH subprocess call for a remote pull; one file read for a file pull. **Does not** feed the local exposition/`MetricsExporter` — pulled data stays owned by the remote's collector id and `render()`/`render_replay()` explicitly only publish `owned_only=True` watches, so pulled watches never appear on *this* machine's scrape target (this is why `push`, not `pull`, is the route onto dashboards for cross-machine data — documented explicitly in `poller-arch.md`).
- **Output shape:** `"Merged N new sample(s) from '<collector>' via <remote-or-file>."` + already-present count, watch/counter counts, newest-reading timestamp, and (if merged and not dry-run) a note that the data now appears in `traffic show`/`traffic report`.
- **JSON:** `{"ok": true, "remote": name_or_none, "file": path_or_none, "dry_run": bool, "collector", "watches", "samples", "counters", "newest_sample_at", "window", "merged", "already_present"}`
- **Exit codes:** `VALIDATION` — no remote/file resolvable. `PARTIAL` — `RemoteError` (SSH failure, malformed export, schema mismatch, self-collector-id collision) or file-read `OSError`. `SUCCESS` otherwise.
- **Related commands:** `traffic remote add` first (to register the SSH destination); `traffic export`/`push` on the other end; `traffic list`/`show`/`report` afterward to see the merged data.

---

### `netrune traffic remote` (id: `traffic-remote`)

- **Purpose:** Manage registered remote pollers, and act as a transparent SSH forwarding shim for running arbitrary `netrune traffic ...` subcommands on one.
- **Exact syntax:**
  - `netrune traffic remote list` (default action if no sub-verb given)
  - `netrune traffic remote add <name> --host <address> [--ssh-user <user>] [--ssh-port <port>] [--profile-name <profile>]`
  - `netrune traffic remote remove <name>` / `netrune traffic remote forget <name>`
  - `netrune traffic remote <name> <command...>` — forwards `<command...>` to the remote's `netrune traffic <command...>`
- **Arguments:**
  - `add`: `name` must be alphanumeric plus `-`/`_` only (`RemoteStore.add` validation). `--host` required. `--profile-name` defaults to `"poller"`. Both `host` and `--ssh-user` are validated by `check_destination()` against regexes (`HOST_RE`, `SSH_USER_RE`) that specifically reject anything starting with `-` — a defense against SSH argument injection (a hostname of `-oProxyCommand=...` would otherwise be read by `ssh` as an option rather than a destination). Adding an existing name upserts (`ON CONFLICT(name) DO UPDATE`).
  - `remove`/`forget`: deletes the `traffic_remotes` row only — **pulled samples are explicitly not removed**; the output says so and points at `traffic unwatch` if that's the intent.
  - Passthrough (`<name> <command...>`): `<name>` must already be a registered remote. The forwarded argv is `["traffic", *rest]`; if the *local* invocation carried `--confirm` or `--json`, those are auto-appended to the forwarded command (so `netrune traffic remote poller1 watch 198.51.100.11 Gi1/0/16 --confirm` propagates confirm through). `--dry-run` shows the assembled `ssh ...` argv without executing it.
- **Step-by-step behavior (passthrough):** `remote_netrune(remote, forwarded)` builds `["ssh","-o","BatchMode=yes","-o","ConnectTimeout=N", ["-p",port] if set, "--", "user@host", shlex.join(["netrune", "--profile", profile, *forwarded])]` — the whole remote command is shell-quoted as one word since SSH runs it through the remote's login shell. Runs via `subprocess.run` with `timeout=min(opts.timeout or 300, 900)`. On non-zero exit, raises `RemoteError` using the last stderr/stdout line as the hint.
- **Side effects:** `traffic_remotes` row insert/update/delete for `add`/`remove`. Passthrough: one SSH subprocess invoking an arbitrary remote command — since the wrapper "deliberately does not know what those verbs mean," any state-changing traffic verb (`watch`, `pause`, etc.) can be run this way and will actually alter the remote's state.
- **Output shape:**
  - `list`: table `remote, host, ssh_user, profile, collector, last_pull`.
  - `add`: confirmation line with resolved `user@host`, profile, and suggested next commands (`remote <name> status`, `pull --remote <name>`).
  - `remove`/`forget`: confirmation or `"No remote called '<x>'."`
  - passthrough: the remote command's raw stdout, printed as-is (ensuring a trailing newline) — bypasses `app.emit`.
- **JSON:**
  - `list`: `{"ok": bool, "rows": [...], "count": N}`
  - `add`: `{"ok": true, "remote": {...}}`
  - `remove`: `{"ok": bool, "remote": name}`
  - passthrough with `--dry-run`: `{"ok": true, "dry_run": true, "command": [...ssh argv...]}`; otherwise raw text only (the remote's own `--json` output if the caller passed `--json`, since it gets forwarded).
- **Exit codes:** `list`: `PARTIAL` if empty, else `SUCCESS`. `add`: `VALIDATION` on bad name/missing host/bad destination. `remove`: `VALIDATION` if the name didn't exist. Passthrough: `VALIDATION` if unknown remote or no command given; `PARTIAL` on `RemoteError` (SSH failure/timeout/non-zero remote exit); `SUCCESS` otherwise.
- **Real example:**
  ```
  $ netrune traffic remote add site-a-poller --host 100.64.0.5 --ssh-user netrune --profile-name poller
  Remote 'site-a-poller' is netrune@100.64.0.5, profile 'poller'.
  Check it with 'netrune traffic remote site-a-poller status', then pull with 'netrune traffic pull --remote site-a-poller'.

  $ netrune traffic remote site-a-poller watch 198.51.100.11 Gi1/0/16 --interval 30
  ```
- **Related commands:** `traffic pull` (the actual data-merge step, separate from adding/using a remote); `ssh-copy-id` beforehand (not a netrune command) since `BatchMode=yes` requires key-based auth already working.

---

### Traffic subsystem architecture

#### The collector/poller model, end to end

A machine running Netrune's traffic subsystem plays one of two roles, chosen at `netrune setup <role>` or `netrune traffic stack init --role <role>` time:

- **`full`** (the default, and what `netrune setup local` provisions): collects, stores, and draws. Generates and runs the collector, an exposition endpoint, VictoriaMetrics, vmalert, and a grapher (Grafana/Perses/none).
- **`collector`** (what `netrune setup poller` provisions): collects and nothing else. No exposition, no storage, no dashboards, no alerting — because a poller exists purely to be *somewhere the switches can be reached from*, and SNMP/ICMP credentials shouldn't have to travel anywhere they don't need to. It stores readings in its own local SQLite (`traffic_samples`/`traffic_counters`/`traffic_counter_log`) as a rolling buffer, and its retention default is longer (365d vs. 180d for `full`) precisely because it's meant to survive a gap until something pulls from it.

**Watchlist-driven collection.** The poller never touches anything not explicitly named via `traffic watch`/`ping`. Watches live in the `traffic_watch` SQLite table, each with a `kind` (`interface`, `icmp`, or `device`), an `interval_seconds`, an `enabled` flag, and (for pulled/remote watches) an `owner` column carrying the collector id that actually polls it. `monitor.due_watches()` (used only by the daemon loop) checks each watch against its own interval independently and filters to `owned_only=True` — so a laptop that has pulled a poller's watches into its local `traffic_watch` table never tries to poll them itself. **Note:** `traffic poll` (the one-shot command) does *not* apply this `owned_only` filter — it will attempt every enabled watch regardless of owner, which is a real behavior gap worth being aware of when a laptop that also pulls from remotes is polled manually.

**SNMP pull mechanics.** The collector never speaks SNMP itself in Python — it shells out through `app.legacy_cmd("netrune-control", <subcommand>, ...)` to a helper binary/script, using three subcommands: `snmp-index` (walks `ifIndex|ifName|ifAlias`, used by `watch`/`interfaces` and to resolve an interface name to an index), `snmp-counters` (reads `ifHCInOctets`/`ifHCOutOctets` — 64-bit counters preferred, with a recorded `counter_width` per reading so a fallback to the 32-bit `ifInOctets`/`ifOutOctets` variant is detected and the reading discarded rather than silently corrupting the rate), and `snmp-health` (device-level CPU/memory/temperature/session/SNMP-abuse counters, plus `sysName`/`sysDescr`/`sysLocation`/`sysContact`). ICMP watches go through `app.icmp_probe()`, which shells `ping -c 3 -W 2 <target>` directly (no SNMP). Credentials (community string / SNMPv3) live in the profile's `.env` file, written by `netrune setup <role> --community <x>` via `write_snmp_community()` in `setup_cli.py` (mode 0600).

**Collector-id collision handling.** Every sample is stamped with the collector that took it (`traffic.collector_id()` — config `traffic_collector_id` or the machine's hostname, truncated to 64 chars). This is the mechanism that lets two machines' readings coexist without becoming indistinguishable: the exposition (`render()`/`render_replay()`) publishes only `owned_only=True` watches (never republishing a pulled watch's counters, because a republished counter would sit still between pulls and read as zero traffic rather than "not measured here"); and `merge_export()` in `traffic_sync.py` **hard-refuses** a pull whose declared collector id equals the local machine's own id, since two collectors sharing an identity would merge into one indistinguishable series. Poller installs are told explicitly (`docs/poller-arch.md` step 4) to set a distinct `traffic_collector_id` for exactly this reason.

#### The exposition format

`traffic_metrics.py`'s `MetricsExporter` renders Prometheus text format 0.0.4 from the **latest stored counter/sample rows** — it computes nothing itself; rates are left to MetricsQL at query time (`rate()` over raw monotonic counters), which is also what makes counter resets self-healing without any special-casing in Netrune. Families include: interface byte/error/discard counters (`netrune_interface_*_total`), interface gauges (`speed_bits`, `up`, `admin_up`), a `netrune_interface_info` identity gauge (always `1`, carrying the operator-chosen `name`, a `link` label combining device+name, and a `downlink` label saying which counter carries "download" for subscribed links), `netrune_interface_subscribed_bits` (the soft-limit rate from `traffic subscribe`), freshness gauges (`*_last_poll_timestamp_seconds`) and a `*_watch_enabled` gauge (so a paused watch is distinguishable from a stopped collector), device-level equivalents (`netrune_device_*`), and ICMP gauges (`netrune_icmp_rtt_seconds`, `_jitter_seconds`, `_loss_ratio`, `_up`).

**Staleness horizon.** A reading older than `max(5 × watch_interval, 300)` seconds (`stale_horizon()`) stops being published as a counter/gauge at all — the series goes *absent* rather than holding its last value, because a rate derived across a held-still gap would attribute hours of accumulated traffic to a single scrape interval (the code's own example: "a 10 Gb port reporting hundreds of gigabits per second"). Freshness and enabled gauges keep publishing through a gap so a dashboard can tell "stopped collector" from "idle link." A **paused** watch's counters are excluded from the live exposition entirely (same reasoning — held-still counter reads as zero traffic, not as "not measured"), while its `watch_enabled=0` gauge keeps publishing so the pause reads as deliberate.

#### Push flow: how a remote poller writes into central storage (this session's Basic Auth work)

1. On the storage side, `netrune setup local --accept-push --confirm` (or `netrune traffic stack init --accept-push --confirm [--publish <host>]`) binds VictoriaMetrics to `<publish-host-or-0.0.0.0>:<vm-port>`, generates `<stack-root>/victoriametrics.auth` (a `secrets.token_urlsafe(24)` token, mode 0600, idempotent across re-`init`), and adds `-httpAuth.username=netrune -httpAuth.password=file://<path>` to VictoriaMetrics's `ExecStart` (systemd unit) and command args (docker-compose), gating the *entire* VictoriaMetrics HTTP API — not just writes.
2. The generated README prints the exact push URL with credentials embedded: `netrune config set traffic_push_url http://netrune:<token>@<host>:<port>`.
3. On the poller side, `traffic_push_url` (config) or `--to <url>` is what `traffic push` targets. `_split_push_credentials()` in `traffic_cli.py` strips `user:pass@` out of the URL into a `Authorization: Basic <base64>` header *before* anything is logged, so a `--dry-run` or error message never echoes the token — only the credential-free URL is ever printed.
4. `traffic push` renders either a full snapshot (`MetricsExporter.render()`) or a **replay** (`render_replay(since, now)`, reading from `traffic_counter_log` — logged at most once per 60s per counter, retained 7 days by default) covering everything since the last successful push, tracked via a `state.get_marker("push:<url>")`/`set_marker` pair. This is what lets a poller that was cut off from storage catch up on reconnect: every replayed line carries its **own original timestamp**, so an outage is drawn as the traffic that actually happened rather than a flat gap followed by a vertical wall.
5. The POST target is `{url}/api/v1/import/prometheus?extra_label=job=netrune&extra_label=instance=netrune-collector&extra_label=source=netrune` — these three extra labels exactly match what the local scrape config attaches (`SCRAPE_JOB`/`SCRAPE_INSTANCE`/`SCRAPE_SOURCE` constants), because a pushed series missing them would become a second, differently-labelled series for the same port and break every vector match a dashboard makes on identity labels.
6. This is intended to be automated on the poller by the `netrune-push.service`/`.timer` pair (generated only when `push_url` is configured, `ExecStart=netrune traffic push --to <url>`, default `OnUnitActiveSec=1min`).

#### `export`/`import` (file-based) vs. `push`/`pull` (network-based)

- **`traffic export`** dumps this collector's *own* raw rows (watches it owns + their samples/counters in a window) as JSONL to stdout — read-only, no network call by itself. **`traffic pull --file <path>`** (or `--file -` for stdin) reads that JSONL and merges it into local SQLite via `merge_export()`. **`traffic pull --remote <name>`** does the same merge but fetches the export by running `netrune traffic export` on the far end over SSH instead of reading a pre-made file. All three land data in the local `traffic_watch`/`traffic_samples`/`traffic_counters` tables, **stamped as owned by the remote's collector id** — which means pulled data shows up in `traffic show`/`traffic list`/`traffic report` (local terminal/HTML views) but is explicitly excluded from this machine's own Prometheus exposition/dashboards (since `render()` only serves `owned_only` watches). Use export/pull when you want the raw history on this machine for ad-hoc inspection, when SSH is available between the two machines, or when it isn't and a file has to be moved by hand/USB/rsync instead.
- **`traffic push`** sends rendered exposition-format samples over HTTP straight into VictoriaMetrics's import endpoint, carrying the *current* labels a scrape would attach — this is the only route by which a remote poller's data ends up on the shared Grafana/Perses dashboards, because storage treats a pushed series identically to a scraped one. Use push when the poller can reach the laptop's storage (even if the laptop can't reach the poller) and you want the data on dashboards, not just archived locally.
- Both can run simultaneously and are non-conflicting (`netrune setup poller --push-to ... --export-to ...`): push puts data on dashboards immediately; export/pull is a durable file-based record that survives a laptop rebuild and is the fallback if the push path ever breaks. Merging via either path is idempotent (duplicate application is a no-op via `INSERT OR IGNORE`/marker resumption), so there is no harm in running both.

#### `stack init` → `stack up` → `stack status` lifecycle

`stack init` (or `show`, its non-writing preview) is purely a **file generator** — deterministic from the current watchlist/config, safe to re-run anytime, explicitly documented as overwrite-safe except for the credential file (preserved) and any dashboards an operator explicitly `keep`/`save`d via `traffic dashboard save` (written to `<root>/dashboards-kept/<uid>.json` and re-injected verbatim by later `init` runs instead of being regenerated). `stack up` (=`install`+start) is the only step that actually touches the live system: copies unit files into `~/.config/systemd/user/`, retires anything the current generation dropped, `daemon-reload`s, and enables/starts the target plus timer-driven units. `stack status` never writes anything — it's a read-only diff between what's on disk in `<root>/systemd` (the generated source of truth) and what's installed/running under `~/.config/systemd/user/` and `systemctl --user`, flagging drift as `stale`. The intended cycle after any change to watches, dashboards config, or role/bind settings is: edit config → `stack init` (regenerate files) → `stack up` (install+restart what changed) → `stack status` or `traffic verify` (confirm). Editing the *watchlist* itself (`watch`/`pause`/`unwatch`/`interval`) needs none of this — the running collector re-reads it every ~5s tick.

#### `netrune setup poller` vs `netrune setup local`

Both are thin orchestrators in `setup_cli.py` that call into the same primitives, differing only in the facts that differ between the two kinds of install:

| Step | `setup poller` | `setup local` |
|---|---|---|
| Profile | creates/selects a profile named `--profile-name` or `poller` | same, named `local` by default |
| `traffic_retention_days` default | 365 (a poller is a durable buffer) | 180 |
| `traffic export_path`/`push_url` | written from `--export-to`/`--push-to` if given | same mechanism, same flags |
| Stack role forwarded | `stack init --role collector` | `stack init` (role omitted → `full`) |
| Non-loopback gate | if `--publish`/`--accept-push` given, `setup` itself requires `--confirm` once, then **hardcodes `--confirm` onto the forwarded `stack init` args** so `stack init`'s own gate is a no-op reached through `setup` | identical logic, same code path |
| `--watch ADDR:INTERFACE` | forwarded as `traffic watch <addr> <interface>` per entry, address-only (no inventory lookup, by design) | identical |
| Final guidance printed | "collects only; whatever pulls from it keeps the readings," suggests `export`/being pulled from | suggests `netrune traffic dashboard` to look at collected data |

Both run: profile create+use → write `traffic_collector_id` (from `--collector-id` or hostname) and retention → `write_snmp_community()` if `--community` given (mode 0600 `.env`) → `app.state.init_db()` → `stack init` → `stack up` → check `loginctl ... Linger` (the single most common poller failure mode: units enabled but never running because the user manager never starts without a login session) → apply any `--watch` entries. Every step's pass/fail is collected into a `steps` list and reported as an `N/M steps done` checklist, exiting `PARTIAL` if any step failed, `SUCCESS` if all did.

---

## 10. Inventory, AP, Memory, and Health Domains


Source files verified directly: `netops_platform/inventory_cli.py` (class `InventoryCommandsMixin`), `netops_platform/core.py` (class `App`, `cmd_ap`/`cmd_memory`/`cmd_health` and helpers, `State.sync_derived_state` and its `_sync_*` helpers), `netops_platform/identity.py` (`identity_match_evidence`, `reconcile_device_rows`, `reconcile_ap_rows`, `ap_rows_match`).

Global mechanics that apply to every command below (stated once, not repeated per command): `parse_global()` strips global flags (`--json`, `--dry-run`, `--confirm`/`--approve`/`--yes`, `--limit N` via `clean_limit(N,100,1000)`, `--status`, `--site`, `--timeout`, `--workers`, `--all`, etc.) out of argv **before** the domain handler ever sees its `args` list — so a merge/unmerge's own tiny arg-parser never has to special-case those flags. `emit(data, opts, text)` prints `json_dumps(data)` (indent 2, `sort_keys=True`) when `opts.json`, otherwise prints `text` (or `render_plain(data)` if no `text` was supplied). `handle_help()` intercepts `-h`/`--help`/`help` as the first or second token for any noun and always returns `SUCCESS`. Exit codes used across this group: `SUCCESS=0`, `USAGE=2`, `PARTIAL=3`, `VALIDATION=6`, `CONFIRM_REQUIRED=7`.

---

### AP domain

#### `netrune ap list` (id: `ap-list`)
- **Purpose:** Search the reconciled (alias-collapsed) AP inventory.
- **Exact syntax:** `netrune ap list '<target>'` — from `cmd_ap`, verb in `{"list","show"}`.
- **Arguments:** `target` — free-text pattern, joined from all remaining words (`" ".join(rest).strip()`), passed through `pattern_or_all()`. Despite the registry marking it required, it is **optional in practice**: an empty string, `all`, `*`, or `any` (case-insensitive) all mean "no filter" and return everything.
- **Preconditions / gating:** None; pure read.
- **Step-by-step behavior:** Calls `self.ap_rows(pattern, opts)` → `self.reconciled_ap_rows(pattern_or_all(pattern), opts)`, which reads `SELECT * FROM aps`, runs it through `identity.reconcile_ap_rows()` (union-find alias collapsing keyed on MAC/name-signature/name/IP plus fuzzy serial/attachment/role-model blocks scored by `identity_match_evidence`), applies `State._overlay_manual_ap_merges()` (folds in aliases/historical addresses from any active manual AP merge, the AP counterpart of the device inventory list's `_overlay_manual_device_merges` overlay), then filters by `ap_rows_match(row, pattern)` if a pattern was given, by `opts.status` (exact match after `norm_status`), by `opts.site` (substring match against the JSON-serialized row), then truncates to `opts.limit`.
- **Side effects:** None (read-only).
- **Output shape, table mode:** columns `["ip","name","platform","switch_name","switch_port","status","last_seen"]`.
- **Output shape, --json mode:** `{"ok": true, "rows": [...], "count": N}`.
- **Exit codes:** Always `SUCCESS`.
- **Real example:** `netrune ap list ZONE10` → table of every canonical AP whose name/ip/alias/switch matches "ZONE10".
- **Related commands:** `netrune ap on-switch <switch>` to scope to one switch; `netrune ap unjoined` to find APs with no controller attachment; `netrune memory switch <switch>` for the same data plus neighbors/relationship timeline.

#### `netrune ap merge` (id: `ap-merge`)
- **Purpose:** Manually retire an old/historical AP identity into a current AP, preserving chronology — the AP counterpart of `netrune inventory merge`, closing the gap that AP identity previously had no manual override path at all (automatic reconciliation in `identity.reconcile_ap_rows()` only merges APs that still share a MAC/serial-equivalent/attachment/name signal; a vendor swap that changes all of those at once needs a human to confirm the link).
- **Exact syntax:** `netrune ap merge <old-ap> <current-ap> --reason 'vendor replacement' [--dry-run | --confirm]`. Same `into`-filler-dropping token grammar as `inventory merge` (shared `_manual_merge_arguments()`, which lives on `App` in `core.py` rather than in a domain mixin specifically because both `ap merge` and `inventory merge` need it).
- **Arguments:** Two positionals (`source`, `target`) via `_manual_merge_arguments(args, expected=2)` — identical validation/error text to `inventory merge`, just with "AP" substituted for "device" in the messages produced by `_ap_merge_endpoint_detail()`.
- **Preconditions / gating (exact preview-before-confirm behavior):**
  - Both endpoints are resolved via `_resolve_ap_merge_endpoint()`, a three-tier resolver: (1) exact IP/name match against the raw `aps` table (`_resolve_raw_ap_record`); (2) the alias-aware `resolve_ap_record()` (built on `reconciled_ap_rows()`, which already includes reconciliation aliases and any prior AP-merge overlay) mapped back to whichever address that reconciled AP currently owns in `aps`; (3) a historical-memory fallback against `inventory_identity_state WHERE entity_type='ap'`, deduped by `(ip, mac, name)` since that table carries one row per identity kind (ip/mac/name) for the same physical AP. **Tier 3 exists because it is the normal case, not an edge case:** `ap scan` replaces the entire `aps` table from the controller's current sweep (unlike devices, which persist in `devices` until explicitly `inventory forget`-ten), so the old AP an operator is trying to retire is routinely already gone from the live table by the time a continuity candidate is reviewed in `health attention`.
  - If either side fails to resolve to exactly one record, `_ap_merge_endpoint_detail()` produces the same three message shapes as `_merge_endpoint_detail()` (ambiguous/historical/not-found), with `label` `"old-ap"`/`"current-ap"` and "APs"/"AP record" substituted for "devices"/"device record". Exit `VALIDATION`.
  - If both endpoints resolve to the same IP: `f"'{source}' and '{target}' both resolve to {name} ({ip}). They are already one AP, so there is nothing to merge."` (`VALIDATION`).
  - `assessment = identity_match_evidence(source, target, "ap")` is computed for display/audit only, same as `inventory merge` — it never blocks the merge.
  - Same `--dry-run`/`--confirm`/neither-passed (`CONFIRM_REQUIRED`) gating as `inventory merge`, with preview text headed `Manual AP merge preview` and `Historical source:`/`Current target:` lines using AP name/IP.
- **Step-by-step behavior (on `--confirm`):** `actor` resolved the same way as `inventory merge`. `merge = state.create_manual_merge("ap", source, target, reason, actor)` — the generalized form of `create_device_merge`, parametrized by `entity_type`: snapshots both endpoints via `_ap_snapshot()` (same key shape as `_device_snapshot()` plus `switch_ip`/`switch_name`/`switch_port`; `model`/`serial`/`source` are always empty since the `aps` table has no such columns), computes merge keys via `_merge_key(row, "ap")` (priority: `mac:<mac>` > `sig:<ap_name_evidence signature>` > `ip:<ip>` > `name:<compact_name>` — the AP branch substitutes the location+AP-number signature from `identity.ap_name_evidence()` for devices' `serial:` tier, since the `aps` table has no serial column), same empty-key/key-collision/reason-validation errors as the device version. Inside one `connect()` transaction: same active-merge and cycle checks as the device version (scoped to `entity_type='ap'`), inserts one `inventory_merges` row with `entity_type='ap'`, then one `inventory_history` row per non-empty identity kind (`ip`/`mac`/`name`) with `event_type='manually_merged'`, and upserts `inventory_identity_state` (`entity_type='ap'`, `status='HISTORICAL'`, now also carrying `switch_ip`/`switch_name`/`switch_port` from the source snapshot, unlike the device path which always writes empty strings there). Back in `cmd_ap_merge`: `reconciliation = state.sync_derived_state()` (applies the merge immediately via `_apply_manual_ap_merges`, the AP counterpart of `_apply_manual_merges` — deletes the source's live `aps` row — and this same pass also retires any matching `identity_swap_candidate` relationship for this exact `(old, new)` pair, since `_continuity_candidate_rels()` excludes pairs already covered by an active manual merge), then `compatibility = state.export_flat_files()`, then `record_audit_event("ap_device_merged", "ap-merge", ..., detail={"merge_id","source_ip","target_ip"})`.
- **Side effects:** Inserts into `inventory_merges` (1 row, `entity_type='ap'`), `inventory_history` (1-3 rows), upserts `inventory_identity_state` (1-3 rows, `status='HISTORICAL'`); `sync_derived_state()` deletes the source's row from `aps`, retracts any `identity_swap_candidate` relationship this merge resolves, and reconciles `relationships_current`/`relationship_events`; writes flat files; inserts one `audit_events` row with **event_type `"ap_device_merged"`**.
- **Output shape, table/`--json` mode:** Identical structure to `inventory merge`'s, with `"operation": "manual-ap-merge"` and AP snapshots in place of device snapshots.
- **Exit codes:** Same as `inventory merge` (`VALIDATION=6`, `CONFIRM_REQUIRED=7`, `SUCCESS=0`).
- **Real example:** `netrune ap merge SITE-A-AP12 NEWCISCO-AP-01 --reason "Ruckus to Cisco hardware replacement, same port" --dry-run` → preview showing `Automatic assessment: manual override` (vendor swap means MAC/model never match) and the retained conflicts; re-run with `--confirm` to apply.
- **Related commands:** `netrune ap merges` to list active AP merges and get a `merge_id`; `netrune ap unmerge <merge_id>` to revoke; `netrune health attention` surfaces the candidate pairing this command is meant to confirm, with a copy-pasteable `ap merge ... --dry-run` suggestion already filled in (see "Identity continuity candidates" under the Health domain).

#### `netrune ap merges` (id: `ap-merges`)
- **Purpose:** List manual AP merges (active by default; `--all` includes revoked ones) — the AP counterpart of `netrune inventory merges`.
- **Exact syntax:** `netrune ap merges [--all]` (verb `merges`).
- **Arguments:** None positional; global `--all` flag controls `include_revoked`.
- **Preconditions / gating:** None.
- **Step-by-step behavior:** `state.list_ap_merges(include_revoked=opts.all)`: `SELECT merge_id,entity_type,source_key,target_key,source_name,source_ip,target_name,target_ip,reason,actor,created_at,last_applied_at,suppressed_observations,revoked_at,revoked_by,revoke_reason FROM inventory_merges WHERE entity_type='ap' [AND revoked_at IS NULL] ORDER BY created_at DESC, merge_id DESC`. Unlike `inventory merges` (which does not filter by `entity_type` at all and so also lists AP merges), this is scoped to `entity_type='ap'` only. Rows wrapped via `timestamp_rows()`.
- **Side effects:** None (read-only).
- **Output shape, table mode:** columns `["created_at","merge_id","source_name","source_ip","target_name","target_ip","reason","suppressed_observations","revoked_at"]`.
- **Output shape, --json mode:** `{"ok": true, "rows": [...], "count": N, "chronology": "newest_first"}`.
- **Exit codes:** Always `SUCCESS`.
- **Real example:** `netrune ap merges --all` → every AP merge ever created, including revoked ones.
- **Related commands:** `netrune ap unmerge <merge_id>` to revoke one listed here; `netrune inventory merges` for the unfiltered listing that includes both devices and APs.

#### `netrune ap moves` (id: `ap-moves`)
- **Purpose:** Show recorded AP-to-switch reattachment events, newest first.
- **Exact syntax:** `netrune ap moves` (no arguments).
- **Arguments:** None.
- **Preconditions / gating:** None.
- **Step-by-step behavior:** `SELECT * FROM ap_move_events ORDER BY created_at DESC, id DESC LIMIT ?` bound to `opts.limit`. Rows in `ap_move_events` are written exclusively by `State._sync_relationships()` (see Cross-cutting notes) whenever an `ap_attachment` relationship's `switch_ip`/`switch_port` changes between two reconciliation passes.
- **Side effects:** None (read-only).
- **Output shape, table mode:** columns `["created_at","ap_ip","ap_name","previous_switch_ip","previous_switch_port","current_switch_ip","current_switch_port"]`.
- **Output shape, --json mode:** `{"ok": true, "rows": [...]}` — **note: no `count` key**, unlike almost every other list command in this group.
- **Exit codes:** Always `SUCCESS`.
- **Real example:** `netrune ap moves --limit 20` → the 20 most recent AP reattachments.
- **Related commands:** `netrune ap timeline <ap>` for one AP's full attachment history (superset, includes first-seen/disappeared events too, not just moves); `netrune health attention` surfaces the most recent 20 AP moves as attention items.

#### `netrune ap on-switch` (id: `ap-on-switch`)
- **Purpose:** Show canonical APs attached to one switch or site, plus that switch's recent relationship timeline.
- **Exact syntax:** `netrune ap on-switch '<target>'` — verb in `{"on-switch","switch"}`.
- **Arguments:** `target` — required in practice (unlike most others): if `rest` is empty, `usage_error("ap","on-switch",opts,"Missing switch target.","netrune ap on-switch ZONE10")` (code `USAGE=2`). Otherwise all words are joined (multi-word switch names supported).
- **Preconditions / gating:** None once target is supplied.
- **Step-by-step behavior:** Delegates entirely to `self.memory_switch(target, opts, aps_only=True)`, which builds the full `memory_switch_payload(target, opts)` (see `memory switch` below for its exact query logic) but renders **only two of its four text sections**: the header/counts line, the APs table, and — because the `if not aps_only:` guards only wrap the Neighbors and Current-relationships sections, not the trailing timeline block — the "Recent relationship timeline" table is **still appended** even though Neighbors/Relationships are suppressed.
- **Side effects:** None (read-only).
- **Output shape, table mode:** Header text `Memory: <target>\nSwitch matches: N | APs: N | Neighbors: N | Events: N`, then an APs table with columns `["switch_port","name","ip","mac","status","last_seen"]`, then a "Recent relationship timeline" table with columns `["created_at","event_type","rel_type","subject_id","object_id","source","detail"]`.
- **Output shape, --json mode:** Identical top-level shape to `memory switch`'s JSON payload — `{"ok","target","switches","attachments":{"aps","neighbors","relationships"},"timeline","counts","sources","chronology","time_format","latest_recorded_at","latest_recorded_at_iso","timestamp_note"}`. **In `--json` mode `ap on-switch` and `memory switch` return byte-identical payloads for the same target** — `aps_only` only affects the human-readable text rendering, never the JSON.
- **Exit codes:** `USAGE=2` if no target; otherwise always `SUCCESS`.
- **Real example:** `netrune ap on-switch ZONE10-SW01` → APs table for that switch plus its recent AP-attachment/neighbor/port-occupancy event history.
- **Related commands:** `netrune memory switch <target>` for the unabridged view (adds Neighbors and Current-relationships sections); `netrune ap moves` for cross-switch move history.

#### `netrune ap scan` (id: `ap-scan`)
- **Purpose:** Refresh AP inventory by querying wireless controllers live.
- **Exact syntax:** `netrune ap scan` (no arguments — any extra words typed after `scan` are silently ignored; they are never forwarded to the helper, unlike `inventory scan`).
- **Arguments:** None accepted.
- **Preconditions / gating:** None beyond the global `--dry-run` behavior of `run_subprocess` (see below).
- **Step-by-step behavior:** `rc = self.run_subprocess(self.legacy_cmd("netrune-discovery","--discover-aps"), opts)`. If `opts.dry_run`, `run_subprocess` short-circuits, prints `{"dry_run": true, "command": "..."}`, and returns `SUCCESS` **without launching the helper**. Otherwise the shell helper `netrune-discovery --discover-aps` runs (querying live wireless controllers) and writes the legacy flat AP cache. If `rc==0` and not dry-run, `self.import_flat_state(("ap",), "wireless-controller-scan")` is called inside a `try/except Exception`: this re-reads all three flat files into SQLite via `state.import_flat_files()` (which itself ends by calling `sync_derived_state()`), then records one `ingest_manager.record_snapshot(...)` provenance run per non-empty AP channel bucket (`built-in-cisco-wlc`, `built-in-smartzone`, `built-in-ap-scan`, split by a regex over the `platform` string). If that import step raises, the exception is caught, logged to stderr, and `PARTIAL` is returned; otherwise the subprocess's own `rc` is returned.
- **Side effects:** Rewrites `devices`/`aps`/`neighbors` tables wholesale from flat files; triggers full `sync_derived_state()` (identity history, health, topology events, relationships — see Cross-cutting notes); writes `ingest_runs`/observation provenance rows for the AP channel(s) that had data. No `audit_events` row.
- **Output shape, table mode / --json mode:** `output_type: log` — output is whatever `netrune-discovery --discover-aps` prints to stdout/stderr (streamed), not a structured `emit()` payload, except for the dry-run echo shape above.
- **Exit codes:** `SUCCESS` on dry-run; the legacy helper's own exit code if the scan and re-import both succeed; `PARTIAL` if the scan succeeded but re-import raised; `TIMEOUT`/`UNSUPPORTED`/`130` from `run_subprocess`'s own signal/timeout/missing-binary handling.
- **Real example:** `netrune ap scan` → runs the controller query, then reports "Observation recording failed: ..." to stderr and exits `PARTIAL` only if the post-scan SQLite import throws.
- **Related commands:** `netrune ap list` afterward to see the refreshed inventory; `netrune ap moves`/`ap timeline` to see what changed.

#### `netrune ap timeline` (id: `ap-timeline`)
- **Purpose:** Show AP-attachment relationship events for one AP (or, given no target, for AP attachments generally), newest first.
- **Exact syntax:** `netrune ap timeline '<target>'`.
- **Arguments:** `target` — nominally required by the registry, but the code has a fallback: `self.relationship_timeline(rest[0] if rest else "ap_attachment", opts, rel_type="ap_attachment")`. Only `rest[0]` is used; extra words are ignored. **Implementation quirk:** if no target is supplied, the literal string `"ap_attachment"` is used as the *target* search term (not just the `rel_type` filter). Because `relationship_events.current_json`/`previous_json` always embed `"rel_type":"ap_attachment"` for these rows, a `LIKE '%ap_attachment%'` match against those JSON blobs still captures every AP-attachment event — so `netrune ap timeline` with no argument behaves as "show all AP attachment events," just via this indirect mechanism rather than an explicit "no filter" code path.
- **Preconditions / gating:** None.
- **Step-by-step behavior:** `relationship_timeline()` → `relationship_timeline_payload(target, opts.limit, rel_type="ap_attachment", subject_kind="")`, which queries `relationship_events` filtered by `(subject_id LIKE ? OR object_id LIKE ? OR previous_json LIKE ? OR current_json LIKE ?) AND rel_type='ap_attachment'`, ordered `created_at DESC, id DESC`, `LIMIT opts.limit`, then wraps rows through `version_rows()` (adds `version`/`version_label` — "version 1 (latest/current)" for the first row, "older version N" thereafter).
- **Side effects:** None (read-only).
- **Output shape, table mode:** columns `["version","version_label","created_at","event_type","rel_type","subject_id","object_id","source"]`.
- **Output shape, --json mode:** `{"ok","target","rows","count","chronology":"newest_first","time_format":"ISO 8601 UTC","latest_recorded_at","latest_recorded_at_iso"}`.
- **Exit codes:** Always `SUCCESS`.
- **Real example:** `netrune ap timeline AP-LOBBY-03` → every recorded first-seen/changed/disappeared event for that AP's switch attachment.
- **Related commands:** `netrune ap moves` for a purely move-focused feed (subset, structurally different table); `netrune memory ip`/`memory mac` for identity-level (not attachment-level) history of the same device.

#### `netrune ap unjoined` (id: `ap-unjoined`)
- **Purpose:** List AP observations that report no controller/switch join.
- **Exact syntax:** `netrune ap unjoined '<target>'`.
- **Arguments:** `target` — optional in practice despite the registry marking it required; empty means "all unjoined APs."
- **Preconditions / gating:** None.
- **Step-by-step behavior:** Runs a raw SQL filter **first** (not through `reconciled_ap_rows`'s own filtering path): `SELECT * FROM aps WHERE lower(COALESCE(switch_port,'')) IN ('not-joined','not joined','unjoined','nonjoined') ORDER BY last_seen DESC, name`, then reconciles those rows with `identity.reconcile_ap_rows()`. If a pattern was given, applies `ap_rows_match()`. Truncates to `opts.limit`. Note this path **ignores `opts.status`/`opts.site` entirely** (unlike `ap list`, which applies both).
- **Side effects:** None (read-only).
- **Output shape, table mode:** columns `["ip","name","mac","switch_name","switch_port","status","last_seen"]`.
- **Output shape, --json mode:** `{"ok": true, "rows": [...], "count": N}`.
- **Exit codes:** Always `SUCCESS`.
- **Real example:** `netrune ap unjoined` → every AP the controller reports without a resolved switch/port.
- **Related commands:** `netrune ap list` for the full joined+unjoined picture; `netrune ap scan` to refresh before checking.

#### `netrune ap unmerge` (id: `ap-unmerge`)
- **Purpose:** Revoke an active manual AP merge, restoring the historical source AP to active inventory — the AP counterpart of `netrune inventory unmerge`.
- **Exact syntax:** `netrune ap unmerge <merge-id> --reason 'incorrect association' --confirm`.
- **Arguments:** One positional (`merge_id`) via `_manual_merge_arguments(args, expected=1)` — identical parsing/error text to `inventory unmerge`.
- **Preconditions / gating:** Same gotcha as `inventory unmerge`: **no `--dry-run` handling** — the only gate is `if not opts.confirm`. `--dry-run --confirm` together still applies for real.
- **Step-by-step behavior (on `--confirm`):** `actor` resolved the same way as `inventory unmerge`. `merge = state.revoke_manual_merge("ap", merge_id, reason, actor)` — the generalized form of `revoke_device_merge`: looks up the active, non-revoked `inventory_merges` row with `entity_type='ap'` by id; the historical source's snapshot must carry a valid IPv4; if an `aps` row already exists at that IP and does **not** identity-match the stored source snapshot (via `_matches_snapshot(row, snapshot, "ap")`), raises the AP-worded equivalent of the device error; otherwise (re-)inserts an `aps` row from the source snapshot (`ip,name,platform,switch_ip,switch_name,switch_port,mac,last_seen,status` — the AP table's own column set, distinct from `devices`' `hostname,model,serial,source`) if none currently occupies that IP; marks the merge row revoked; inserts one `inventory_history` row (`event_type='manual_merge_revoked'`, `entity_type='ap'`). Back in `cmd_ap_unmerge`: `reconciliation = state.sync_derived_state()` (the source becomes visible again, and any `identity_swap_candidate` the merge had resolved can be freshly re-detected on a later tick if the same pattern recurs), `compatibility = state.export_flat_files()`, then `record_audit_event("ap_device_merge_revoked", "ap-unmerge", ..., detail={"merge_id"})`.
- **Side effects:** Possibly inserts an `aps` row (only if the IP is unoccupied); updates the `inventory_merges` revocation fields; inserts 1 `inventory_history` row; `sync_derived_state()` reconciliation cascade; flat files exported; inserts 1 `audit_events` row with **event_type `"ap_device_merge_revoked"`**.
- **Output shape, table mode:** `Restored AP merge <merge_id> | Recorded: <iso revoked_at>`.
- **Output shape, --json mode:** `{"ok": true, "merge": {...timestamped, revoked merge row...}, "reconciliation": {...}, "compatibility_export": {...}}`.
- **Exit codes:** `VALIDATION=6` for argument errors and `ValueError`s from `revoke_manual_merge`; `CONFIRM_REQUIRED=7` if `--confirm` is absent; `SUCCESS=0` once revoked.
- **Real example:** `netrune ap unmerge mrg-example --reason "merge was a mistake, different AP" --confirm` → restores the old AP row and reconciles.
- **Related commands:** `netrune ap merges` to find the `merge_id`; `netrune ap merge` to re-apply a corrected merge afterward if needed.

---

### Health domain

#### `netrune health attention` (id: `health-attention`)
- **Purpose:** One combined feed of health, topology-change, AP-move, backup, and identity-continuity items an operator should look at.
- **Exact syntax:** `netrune health attention` (no arguments).
- **Arguments:** None.
- **Preconditions / gating:** None.
- **Step-by-step behavior:** Calls `self.attention_payload(opts.limit)` (shared with the `ask` domain's attention summarization). Internally: `limit = clean_limit(limit, 80, 300)` — **this re-clamps independently of `opts.limit`'s own clamp**, floor default 80, hard ceiling 300, regardless of what `--limit` was passed. Queries: (1) `health_state` rows where `status='OFFLINE' OR flap_count>=3 OR (last_seen < now-86400)`, ordered `status, flap_count DESC, last_seen`; (2) the 20 most recent `topology_events`; (3) the 20 most recent `ap_move_events`; (4) the 20 most recent `backup_history` rows, of which only those with `status NOT IN ('saved','unchanged')` become attention items; (5) **identity-swap candidates** via `_identity_candidate_items()` (new) — see "Identity continuity candidates" below. Each source is mapped into a normalized `{"kind","level","title","text","row"}` item (`level` is `"danger"` for OFFLINE health rows, `"warning"` for everything else), concatenated, and truncated to `limit`.
- **Side effects:** None (read-only).
- **Output shape, table mode:** columns `["kind","level","title","text"]`.
- **Output shape, --json mode:** `{"ok": true, "items": [...capped list...], "health": [...raw health_state rows...], "topology_changes": [...], "ap_moves": [...], "backups": [...], "identity_candidates": [...raw active identity_swap_candidate relationship rows, within the TTL window...]}`.
- **Exit codes:** `SUCCESS` if `items` is empty, else `PARTIAL` (i.e., "there is something to look at" reads as a non-zero/degraded exit for scripting).
- **Real example:** `netrune health attention` → mixed table of flapping switches, new/removed neighbor links, AP reattachments, failed backups, and possible device/AP identity continuations.
- **Related commands:** `netrune health offline` / `netrune health status` for health-only detail; `netrune ap moves` / `netrune topology changes` for the underlying feeds individually; `netrune inventory merge` / `netrune ap merge` to act on an identity-continuity item.

##### Identity continuity candidates (new `health attention` item kinds)
- **Purpose:** Detect that a device/AP which just disappeared is plausibly the *same logical thing* as one that just appeared — a vendor swap (Aruba→Cisco, Ruckus→Cisco, same or different naming scheme), a physical move-and-rename, an in-place naming realignment, or a whole-site rename cascading across many devices at once — using signals beyond the pairwise identity matcher (`identity.identity_match_evidence`) that reconciliation already runs on every scan. Detection is automatic (runs inside `sync_derived_state()`, so it fires on `inventory scan`, `ap scan`, `health check`, `memory refresh`, `inventory merge`/`unmerge`, and therefore inside the `morning-check`/`ap-audit`/`refresh-inventory` workflows with no manifest changes); **application is never automatic** — every candidate still requires an explicit `inventory merge`/`ap merge ... --confirm`.
- **Detection (`State._continuity_candidate_rels`, called from the end of `_relationship_desired`):** Builds an "old" pool from `inventory_identity_state` rows absent from this tick's canonical rows but with `last_seen` inside `continuity_window_days`, and a "new" pool from this tick's canonical rows whose own `first_seen` (looked up the same way) is inside the same window. Pairs them via `identity.identity_continuity_candidates()`, which buckets by shared attachment (AP same switch+port), shared location+role-number (`identity._asset_location_prefix` + `_asset_role_number`, across differing vendor naming conventions), or shared role-number-only (location changed — the move/rename/site-rename case), then scores each pair with `identity.continuity_match_evidence()`. **Temporal proximity can never by itself produce a candidate** — at least one of those structural signals is required first; timing only adds a bonus on top (`+round(20 * max(0, 1 - gap_days/window_days))`). Scoring: same-attachment-transition +45 (AP only), same-location-and-role +35, role-number-only +15, same-model +10.
- **Storage:** One more managed relationship in `relationships_current`/`relationship_events`, `rel_type='identity_swap_candidate'` (not a new table — reuses the existing generic model, which gets auto-retraction for free: if the old side reappears or the new side itself vanishes on a later tick, the normal "not in desired → disappeared" loop in `_sync_relationships` retracts it with no extra code). A pair already covered by an active manual merge (`inventory_merges`) is excluded from being (re-)proposed. `attrs_json` carries both sides' full snapshot (`name`,`ip`,`mac`,`model`,`switch_ip/name/port`,`first_seen`/`last_seen`,`canonical_id`) plus the `signals` breakdown.
- **Surfacing (`App._identity_candidate_items`, called from `attention_payload`):** A confidence floor (`continuity_confidence_floor`, default 55) is applied **only here, not at write time** — reads every active, non-TTL-expired candidate, runs `identity.cluster_rename_candidates()` over the full set (grouping pairs that share an old-location→new-location mapping with the role-number preserved, `continuity_cluster_min_members` or more required, default 3), then: a qualifying **cluster** is always surfaced as one `kind:"identity_rename_cluster"` item regardless of each member's own confidence (the pattern across 3+ consistent pairs is itself the evidence — this is deliberately how a weak isolated signal like role-number-only, which would never clear the floor alone, still becomes actionable once it recurs enough times to look like a real site rename); an **unclustered single** still has to clear the floor on its own as `kind:"identity_swap_candidate"`. Both item kinds carry a copy-pasteable next command in `text`, e.g. `Review: netrune ap merge 'SITE-A-AP12' 'NEWCISCO-AP-01' --reason '...' --dry-run`.
- **TTL, not deletion:** `continuity_attention_ttl_days` (default 30) controls how long a candidate keeps *appearing* in `health attention`; the underlying `relationships_current` row is retained indefinitely either way (same precedent as `ap_move_events`), inspectable via `netrune memory export`/`memory timeline` even after it stops being surfaced.
- **Config keys** (profile `[identity]` section, `netrune config set <key> <value>`): `continuity_window_days` (14) — how far back to search for a pairing partner; `continuity_confidence_floor` (55) — minimum confidence for an unclustered single to surface; `continuity_cluster_min_members` (3) — minimum pairs sharing a rename pattern before the cluster bypasses the floor; `continuity_attention_ttl_days` (30) — how long a surfaced candidate keeps appearing before it quietly stops (without being deleted).
- **Known limit:** if a replacement changes vendor, naming scheme, *and* attachment (new switch/port too) all at once, no signal survives and this cannot detect it — same as before this feature existed; the manual merge commands remain the only path there.

#### `netrune health check` (id: `health-check`)
- **Purpose:** Ping known/supplied devices and APs, then refresh canonical health state from the result.
- **Exact syntax:** `netrune health check '<target>'`.
- **Arguments:** `target` — optional despite registry `required: true`; `target = " ".join(rest).strip()`. If empty, the helper is invoked with no target (checks everything known).
- **Preconditions / gating:** Standard `run_subprocess` dry-run short-circuit only.
- **Step-by-step behavior:** `cmd = legacy_cmd("netrune-discovery","--fast-health", target)` if target else `legacy_cmd("netrune-discovery","--fast-health")` (an empty string is never passed as a positional). `rc = run_subprocess(cmd, opts)`. If `rc==0` and not `opts.dry_run`: `self.state.import_flat_files()` is called **directly, with no `try/except`** — unlike `inventory scan`/`ap scan`, a failure here is **not caught and does not degrade to `PARTIAL`**; it propagates as an unhandled exception. This call also does **not** record any `ingest_runs` provenance entry (it calls `state.import_flat_files()` directly rather than `self.import_flat_state(...)`), unlike `inventory scan`/`ap scan`/`inventory import-flat`.
- **Side effects:** `state.import_flat_files()` rewrites `devices`/`aps`/`neighbors` wholesale from the flat caches the helper just wrote, then internally calls `sync_derived_state()` — so `health_state`, `health_events`, `inventory_history`, `topology_events`, `relationships_current`, `relationship_events`, `ap_move_events` can all be touched as a side effect. No `audit_events` row.
- **Output shape, table mode / --json mode:** `output_type: log` — streams the legacy helper's own output (or the dry-run echo).
- **Exit codes:** `SUCCESS` on dry-run; otherwise whatever `--fast-health` itself returns; an uncaught exception from the post-check import surfaces as a Python traceback (not gracefully mapped to `PARTIAL` the way scan/import failures are elsewhere).
- **Real example:** `netrune health check ZONE10-SW01` → pings that device (and any APs it's associated with), then refreshes health_state.
- **Related commands:** `netrune health status` / `health offline` afterward to see the refreshed state; `netrune memory refresh` performs the same flat-file reimport without the live ping step.

#### `netrune health offline` (id: `health-offline`)
- **Purpose:** List entities currently recorded OFFLINE in canonical health state.
- **Exact syntax:** `netrune health offline '<target>'`.
- **Arguments:** `target` — optional; empty means "all offline entities."
- **Preconditions / gating:** None.
- **Step-by-step behavior:** `health_state_rows(target, opts, status="OFFLINE")`: builds `WHERE (entity_id LIKE ? OR name LIKE ? OR platform LIKE ? OR switch_ip LIKE ? OR switch_port LIKE ?) AND upper(status)='OFFLINE'`, ordered by the same `CASE upper(status) ...` priority, then `flap_count DESC`, then `COALESCE(last_failed,last_seen,updated_at) DESC`, `LIMIT opts.limit`. **Important caveat:** `health_state` has **no IP column** — `entity_id` is a reconciliation canonical id (`mac:...`, `serial:...`, `switch:...`, `ap:...`, `ip:...` only as a last-resort fallback), so searching by bare IP address will silently return nothing for any device/AP whose canonical identity is MAC- or serial-based, unless that IP also happens to appear inside `name`/`platform`/`switch_ip`/`switch_port`.
- **Side effects:** None (read-only).
- **Output shape, table mode:** columns `["entity_type","entity_id","name","platform","status","last_failed","flap_count"]`.
- **Output shape, --json mode:** `{"ok": true, "target": "...", "rows": [...], "count": N}`.
- **Exit codes:** `SUCCESS` if no offline rows found, else `PARTIAL` (non-zero signals "there is something offline," inverted from the usual "0 = clean" instinct but consistent with `health attention`).
- **Real example:** `netrune health offline` → every device/AP currently OFFLINE, worst flappers first.
- **Related commands:** `netrune health status` for the unfiltered/all-status view; `netrune health timeline <target>` to see when it went offline; `netrune inventory list --status OFFLINE` for the plain inventory-status view (see Cross-cutting notes for how these two "offline" views differ).

#### `netrune health status` (id: `health-status`)
- **Purpose:** Read current canonical health for all entities, or one matching target.
- **Exact syntax:** `netrune health status '<target>'`.
- **Arguments:** `target` — optional; empty means everything. Same IP-searchability caveat as `health offline` applies (no dedicated IP column in `health_state`).
- **Preconditions / gating:** None.
- **Step-by-step behavior:** `health_summary_payload(target, opts)` → `health_state_rows(target, opts)` (no status filter this time) plus a tally: `counts[status] += 1` over the returned rows (**note**: counts are computed only over the rows actually returned, which are already capped at `opts.limit` — so `counts` is not a true global tally once more rows exist than the limit).
- **Side effects:** None (read-only).
- **Output shape, table mode:** Header text `Health status[: target]\nTotal: N | ONLINE: n | OFFLINE: n | ...`, then a table with columns `["entity_type","entity_id","name","platform","status","last_seen","last_failed","flap_count"]`.
- **Output shape, --json mode:** `{"ok": true, "target": "...", "counts": {...}, "rows": [...], "total": N}`.
- **Exit codes:** Always `SUCCESS` (unlike `offline`, this verb never returns `PARTIAL` even if OFFLINE rows are present).
- **Real example:** `netrune health status ZONE10` → ONLINE/OFFLINE tally and per-entity rows for anything matching "ZONE10".
- **Related commands:** `netrune health offline` for the filtered, non-zero-signaling variant; `netrune health timeline` for how a row got to its current state; `netrune inventory list` for the plain device/AP status view.

#### `netrune health timeline` (id: `health-timeline`)
- **Purpose:** Read `health_events` (status transitions) newest first.
- **Exact syntax:** `netrune health timeline '<target>'`.
- **Arguments:** `target` — optional; empty returns the global event feed.
- **Preconditions / gating:** None.
- **Step-by-step behavior:** If target given: `SELECT * FROM health_events WHERE entity_id LIKE ? OR detail LIKE ? ORDER BY created_at DESC, id DESC LIMIT ?` (note: `detail` in `health_events` is populated only with the entity's `name`, from `_sync_health`'s insert — it is not a rich description field). If no target: the same query unfiltered. Wrapped through `version_rows()`.
- **Side effects:** None (read-only).
- **Output shape, table mode:** columns `["version","version_label","created_at","entity_type","entity_id","event_type","previous_value","current_value"]`.
- **Output shape, --json mode:** `{"ok": true, "target": "...", "rows": [...], "count": N}`.
- **Exit codes:** Always `SUCCESS`.
- **Real example:** `netrune health timeline ZONE10-SW01` → every `first_seen`/`status_changed` event for that device's canonical health row.
- **Related commands:** `netrune health status` for the current snapshot; `netrune memory timeline` for the parallel relationship-level event feed.

---

### Inventory domain (`netops_platform/inventory_cli.py`)

#### `netrune inventory activity` (id: `inventory-activity`)
- **Purpose:** Concurrently ping a list of targets (from arguments and/or a file) and report live reachability alongside cached inventory metadata.
- **Exact syntax:** `netrune inventory activity '<target>' [--file devices.txt]` (verb `activity`).
- **Arguments:** `target` — one or more positional words, each treated as a separate target; `--file <path>` reads additional newline-delimited targets (blank lines and lines starting with `#` skipped). At least one target (from either source) is required: with none, `usage_error(..., "Missing target list. Provide --file or one or more targets.", code=USAGE)` (note: **`USAGE=2`**, the default, not `VALIDATION`). If `--file` points at a nonexistent path: `usage_error(..., f"List file not found: {p}", ..., VALIDATION)` (`VALIDATION=6` explicitly this time).
- **Preconditions / gating:** None beyond having at least one target.
- **Step-by-step behavior:** Loads the full reconciled inventory once (`inventory_rows("", GlobalOptions(limit=100000))`, i.e. device+AP union, not capped by the caller's own `--limit`). For each target: normalizes it, looks for an exact match in the loaded inventory by IP/name/alias/historical-address (case-insensitive) or by short-hostname match; falls back to DNS resolution (`socket.gethostbyname`) if the resolved value isn't already an IPv4 literal; pings via `ping -c 1 -W <timeout clamped 1-10>` (`subprocess`); records `{"target","ip","kind","name","platform","status","checked_at"}`. Runs concurrently via `ThreadPoolExecutor(max_workers = min(len(targets), bounded_int(opts.workers, 20, 1, 64)))` — note the **hard 64-worker ceiling** regardless of the global `--workers` flag's own 200 ceiling.
- **Side effects:** None (no writes; this is a live network read only, matching its `network-read` safety class).
- **Output shape, table mode:** columns `["status","target","ip","kind","name","platform","checked_at"]`, sorted OFFLINE-first.
- **Output shape, --json mode:** `{"ok": true, "rows": [...], "count": N}`.
- **Exit codes:** `SUCCESS` if every target pinged ONLINE, else `PARTIAL`; `USAGE`/`VALIDATION` for the argument errors above.
- **Real example:** `netrune inventory activity ZONE10-SW01 ZONE10-SW02 --timeout 2` → concurrent pings, table of live status alongside cached name/platform for each.
- **Related commands:** `netrune inventory scan` for a deeper live inventory refresh; `netrune health check` for the equivalent under the health domain (which also refreshes canonical health state, which `activity` does not).

#### `netrune inventory details` (id: `inventory-details`)
- **Purpose:** Show detailed inventory for one target — a **live SSH collection**, not merely a cached-state read, in interactive/text mode.
- **Exact syntax:** `netrune inventory details '<target>'` (verb `details`).
- **Arguments:** `target` — the full joined `rest` string, run through `pattern_or_all()`.
- **Preconditions / gating:** None, but the behavior branches sharply on mode:
- **Step-by-step behavior:** `pattern = pattern_or_all(" ".join(rest).strip())`. **If `verb=="details"` AND `pattern` is non-empty AND `not opts.json`:** the command resolves the pattern via `resolve_device_record(pattern)`; if it resolves to exactly one device, uses its `ip` as `detail_target`, else falls back to the raw pattern text; then **shells out live**: `run_subprocess(legacy_cmd("netrune-discovery","--details", detail_target), opts)` — this SSHes to the device and streams its own output, honoring the standard dry-run echo. **Otherwise** (pattern is empty/`all`, **or** `--json` was passed) it falls through to exactly the same code path as `inventory list`: `inventory_rows(pattern, opts)` against cached SQLite state, rendered as a table. **This means `--json` mode never performs a live SSH collection for `details` — only interactive/text mode with a specific target does.**
- **Side effects:** Live-collection branch: none directly to SQLite from this command (the legacy helper may write its own flat-file cache, which is not re-imported by this command itself). Cached-state branch: none (read-only).
- **Output shape, table mode:** Live branch: streamed helper output (`output_type: log`-like, unstructured). Cached-state branch: identical to `inventory list`'s table — columns `["kind","ip","name","platform","status","last_seen"]`.
- **Output shape, --json mode:** Always the cached-state shape: `{"ok": true, "rows": [...], "count": N}` (never the live SSH branch).
- **Exit codes:** Live branch: the helper's own return code (or `SUCCESS` on dry-run). Cached branch: always `SUCCESS`.
- **Real example:** `netrune inventory details ZONE10-SW01` (no `--json`, terminal) → live SSH detail dump for that switch. `netrune inventory details ZONE10-SW01 --json` → structured cached-inventory row(s) instead.
- **Related commands:** `netrune inventory list` for the always-cached, always-structured equivalent; `netrune inventory scan` to refresh the cache the JSON branch reads from.

#### `netrune inventory export-flat` (id: `inventory-export-flat`)
- **Purpose:** Export the current SQLite-canonical `devices`/`aps`/`neighbors` tables back out to the legacy pipe-delimited flat files the shell helpers read.
- **Exact syntax:** `netrune inventory export-flat` (verb `export-flat` or `export`).
- **Arguments:** None.
- **Preconditions / gating:** **None — `--dry-run` has no effect on this command.** Unlike `scan`/`check` verbs that route through `run_subprocess` (which short-circuits on `opts.dry_run`), this verb calls `self.state.export_flat_files()` directly with no dry-run guard anywhere in the code path, so it always performs the write.
- **Step-by-step behavior:** `export_flat_files()` reads `devices`, `aps`, `neighbors` via plain `SELECT ... ORDER BY ip`/`local_ip,local_port,remote_name` and writes each to its flat file via `_write_pipe()` (write to a `.tmp` sibling, then atomic `Path.replace`).
- **Side effects:** Overwrites `devices_file`, `aps_file`, `neighbors_file` on disk. No SQLite writes, no audit event.
- **Output shape, table mode:** `output_type: log` — text `Exported flat caches: devices=N aps=N neighbors=N`.
- **Output shape, --json mode:** `{"ok": true, "exported": {"devices": N, "aps": N, "neighbors": N}}`.
- **Exit codes:** Always `SUCCESS`.
- **Real example:** `netrune inventory export-flat` → refreshes the flat caches other shell tools (and `child_env()`, which every `run_subprocess` call invokes first) depend on.
- **Related commands:** `netrune inventory import-flat` for the reverse direction; any live-collection command (`inventory scan`, `ap scan`) implicitly calls this export path first via `child_env()`.

#### `netrune inventory forget` (id: `inventory-forget`)
- **Purpose:** Drop a device's derived state (but not its history/backups/audit trail) so the next scan re-adopts it from scratch.
- **Exact syntax:** `netrune inventory forget '<target>' [--with-names] --confirm` (verb `forget` or `readopt`).
- **Arguments:** `target` — required; missing yields `usage_error(..., "A device is required.", "netrune inventory forget SITE-A-SW01 --confirm", VALIDATION)`. `--with-names` — optional flag (`forget_identity`); stripped out of `rest` before the rest is joined into the query string. If the query doesn't resolve to exactly one device: `usage_error(..., f"'{query}' did not resolve to one device." + (f" Candidates: {labels}" if any), "netrune inventory list <target>", VALIDATION)`.
- **Preconditions / gating:** **`--confirm` gate; the exit code on the missing-confirm path is `VALIDATION` (6), not `CONFIRM_REQUIRED` (7)** — this differs from `merge`/`unmerge`, which use `CONFIRM_REQUIRED`. The exact preview shown, **every time `--confirm` is absent (regardless of `--dry-run`)**:
  ```
  Would forget <name> and every address it has answered on:
    <addr1>, <addr2>, ...

  Rows that would be removed:
    <table>                     <count>
    ...(or "(none)" if empty)

  Backups, audit events, and collected traffic history are not touched.
  The next 'netrune inventory scan' adopts it again from what it reports.
  Re-run with --confirm.
  [Add --with-names to drop the recorded naming history too, so an old
  name is not re-derived on the next reconciliation.]  <- only if --with-names wasn't already passed
  ```
  The row counts in the preview come from `state.device_footprint(addresses)` — a dry count against `DEVICE_STATE_TABLES` (`devices`, `health_state`, `neighbors`, `capability_evidence`, `topology_snapshot`) plus `inventory_identity_state` — computed **before** any deletion, so it is an accurate pre-image, not an estimate.
- **Step-by-step behavior:** Resolves `target` via `resolve_device_record()`. Collects every address the device has ever answered on: `ip`, `addresses` (current aliases), and `historical_addresses` (merged-in aliases) — so a reconciled multi-address device is forgotten whole. On `--confirm`: `removed = state.forget_device(addresses, forget_identity)` deletes matching rows from each of `DEVICE_STATE_TABLES` (`devices` by `ip`, `health_state` by `entity_id`, `neighbors` by `local_ip`, `capability_evidence` by `device_id`, `topology_snapshot` by `local_ip`) and, only if `--with-names`, from `inventory_identity_state` (`entity_type='device' AND ip IN (...)`); sets `self.inventory_dirty = True`. Then `state.flush_inventory_exports()` writes the flat files since inventory changed. Then `record_audit_event("inventory", "inventory-forget", result="success", target=name, detail={...})`.
- **Side effects:** SQLite: `DELETE` from `devices`, `health_state`, `neighbors`, `capability_evidence`, `topology_snapshot` by address, plus `inventory_identity_state` if `--with-names`. **Note: `audit_events` here is recorded with `event_type="inventory"` and `action="inventory-forget"`** (not a more specific event-type string like `inventory_device_forgotten`), and — unlike merge/unmerge — **no explicit `actor`/`actor_uid` is passed**, so the audit row always shows actor `"local"` rather than the real OS user. Flat files exported. Backups, `audit_events`, and traffic/diagnostic history are explicitly untouched.
- **Output shape, table mode:** `output_type: log` — on success: `Forgot <name> (N address(es): a, b, ...).` followed by one line per removed table (`  <table:<28>  N row(s) removed`), then `Run 'netrune inventory scan' to adopt it again from what it reports now.`
- **Output shape, --json mode:** Preview (no confirm): `{"ok": false, "requires_confirm": true, "device": {...}, "addresses": [...], "footprint": {...}}`. Applied: `{"ok": true, "device": name, "addresses": [...], "removed": {...}, "forgot_names": bool}`.
- **Exit codes:** `VALIDATION=6` for missing/ambiguous target and for the unconfirmed preview; `SUCCESS=0` once applied with `--confirm`.
- **Real example:** `netrune inventory forget ZONE10-SW01 --confirm` → deletes its `devices`/`health_state`/`neighbors`/`capability_evidence`/`topology_snapshot` rows and reports counts removed per table.
- **Related commands:** `netrune inventory scan <target>` afterward to re-adopt it fresh; `netrune inventory merge` is the alternative when the goal is re-pointing an old identity at a *different* current device rather than wiping it.

#### `netrune inventory import-flat` (id: `inventory-import-flat`)
- **Purpose:** Import the legacy flat pipe-delimited caches (`devices`, `aps`, `neighbors` files) into SQLite, deduping AP rows and recording ingest provenance.
- **Exact syntax:** `netrune inventory import-flat` (verb `import-flat` or `import`).
- **Arguments:** None.
- **Preconditions / gating:** **No `--dry-run` guard anywhere in this code path** — always executes for real, same caveat as `export-flat`.
- **Step-by-step behavior:** `self.import_flat_state(("device","ap","topology"), "flat-import")` → `state.import_flat_files()`: touches the three flat files if missing, reads them via `_read_pipe` (device rows expect 9 fields, ap rows 9, neighbor rows 6), dedupes AP rows via `_dedupe_ap_pipe_rows()` (keyed by IP else MAC else name; a controller's "wireless" placeholder attachment can never overwrite a real switch-learned port already recorded for the same key), then `DELETE FROM devices/aps/neighbors` and bulk `INSERT OR REPLACE` from the parsed rows, then calls `self.sync_derived_state()`. If that reconciliation suppressed any manual-merge-covered rows, `export_flat_files()` is called again to keep the flat cache consistent. Back in `import_flat_state`, for `"device"` and `"ap"` (split into `built-in-cisco-wlc`/`built-in-smartzone`/`built-in-ap-scan` channels by a platform-string regex) and `"topology"`, one `ingest_manager.record_snapshot(...)` provenance run each is recorded (`confidence=85` for device/ap, `80` for topology; composite identity keyed by `(local_ip, local_port, remote_name, remote_port)` for topology).
- **Side effects:** Full `devices`/`aps`/`neighbors` overwrite; full `sync_derived_state()` cascade (identity history, health, topology events, relationships); `ingest_runs`/observation provenance rows for device/ap/topology channels that had data. No `audit_events` row.
- **Output shape, table mode:** `output_type: log` — text `Imported flat caches: devices=N aps=N neighbors=N; observation runs=M`.
- **Output shape, --json mode:** `{"ok": true, "imported": {"devices","aps","neighbors","aps_raw","aps_deduped","reconciliation"}, "ingest_runs": [...], "db": "<sqlite path>"}`.
- **Exit codes:** Always `SUCCESS`.
- **Real example:** `netrune inventory import-flat` → typically run after some external tool wrote the legacy flat files directly.
- **Related commands:** `netrune inventory export-flat` for the reverse; `netrune memory refresh` performs the same `import_flat_files()` call but without the ingest-provenance recording step.

#### `netrune inventory list` (id: `inventory-list`)
- **Purpose:** Search current canonical device **and** AP inventory together.
- **Exact syntax:** `netrune inventory list '<target>'` (verb `list`, or `details` when the fallback path applies — see above).
- **Arguments:** `target` — optional, `pattern_or_all()`-normalized.
- **Preconditions / gating:** None.
- **Step-by-step behavior:** `inventory_rows(pattern, opts)` in `inventory_cli.py`: reads `devices` (all rows, with `switch_ip`/`switch_name`/`switch_port` forced `NULL`), runs `reconcile_device_rows()`, overlays active manual merges (`state._overlay_manual_device_merges`) so a merged-away source device's aliases/addresses appear folded into its target; tags each row `"kind": "device"`. Then calls `self.reconciled_ap_rows(pattern, GlobalOptions(limit=100000, status=opts.status, site=opts.site))` (note: AP-side limit is uncapped internally at this stage; the final `[:opts.limit]` slice happens once, after devices+APs are combined) and tags each `"kind": "ap"` with `model`/`serial` defaulted to `""` and `source` defaulted to `"AP"`. Filters by `opts.status` (devices only, since AP status filtering already happened via `reconciled_ap_rows`'s own `opts.status`), by substring match of the JSON-serialized row against `pattern.lower()` (devices only — a JSON-blob "contains" search, much broader than the AP side's `ap_rows_match`), and by `opts.site` (both, JSON-blob substring). Final sort: OFFLINE-first, then `kind`, then name/ip.
- **Side effects:** None (read-only).
- **Output shape, table mode:** columns `["kind","ip","name","platform","status","last_seen"]`.
- **Output shape, --json mode:** `{"ok": true, "rows": [...], "count": N}`.
- **Exit codes:** Always `SUCCESS`.
- **Real example:** `netrune inventory list ZONE10 --status OFFLINE` → all offline devices/APs matching "ZONE10".
- **Related commands:** `netrune ap list` for AP-only; `netrune inventory details <target>` for a deep dive on one match; `netrune memory device <target>` for identity/relationship history on one device rather than a snapshot.

#### `netrune inventory merge` (id: `inventory-merge`)
- **Purpose:** Manually retire an old/historical device identity into a current device, preserving chronology (used when automatic reconciliation can't or shouldn't merge them, e.g. hardware replacement that changed MAC/serial).
- **Exact syntax:** `netrune inventory merge <old-device> <current-device> --reason 'hardware replacement' [--dry-run | --confirm]`. Positional order also accepts the natural-language filler `into` between the two device tokens (it's silently dropped): `netrune inventory merge OLD-SW into NEW-SW --reason '...'`.
- **Arguments:** Two positionals (`source`, `target`) — `_manual_merge_arguments(args, expected=2)` walks tokens: `--reason` consumes the next token as `reason`; any other token starting with `-` is rejected with `f"unknown option: {value}"`; the literal (case-insensitive) token `into` is dropped rather than counted as positional; anything else is appended to `positional`. If the resulting positional count isn't exactly 2: error `f"expected {expected} positional argument{'s' if expected!=1 else ''}"`. Missing `--reason` value: `"--reason requires text"`. Missing `reason` text entirely: `"A merge reason is required for chronology and audit."` (`VALIDATION`).
- **Preconditions / gating (exact preview-before-confirm behavior):**
  - Both endpoints are resolved via `_resolve_merge_endpoint()`, which tries the **raw devices table** first (`resolve_raw_device_record`, exact IP/hostname/short-hostname match against `devices`), then falls back to the alias-aware `resolve_device_record()` mapped back to whichever address row that reconciled device currently owns in `devices`. If either side fails to resolve to exactly one row, `_merge_endpoint_detail()` produces one of three exact messages: `f"The {label} '{target}' matched {N} devices: {names}{more}. Use an exact hostname or management IP."`; or, if it's found only in `inventory_identity_state` history, `f"The {label} '{target}' is historical memory, not an active record. It was last seen as {name} ({ip}) on {iso_time}. Review 'netrune inventory merges' and revoke an existing merge before retiring it again."`; or `f"The {label} '{target}' matched no active or historical device record."` (`label` is `"old-device"` for source, `"current-device"` for target). Exit `VALIDATION`.
  - If both endpoints resolve to the same IP: `f"'{source}' and '{target}' both resolve to {hostname} ({ip}). They are already one device, so there is nothing to merge."` (`VALIDATION`).
  - Otherwise `assessment = identity_match_evidence(source, target, "switch")` is computed (see Cross-cutting notes for the scoring formula) purely for display/audit — it does **not** block the merge even if `same_device` is false; a manual merge is by definition an operator override.
  - **`--dry-run` shows the full preview and applies nothing, returning `SUCCESS`:**
    ```
    Manual device merge preview
    Historical source: <hostname> (<ip>)
    Current target: <hostname> (<ip>)
    Automatic assessment: same device|manual override | Confidence: N%
    Conflicts retained as evidence: mac, serial | none
    Reason: <reason>
    ```
  - **If `--dry-run` was NOT passed and `--confirm` was NOT passed, the command does *not* show this preview at all** — it goes straight to `usage_error(..., "Manual merge requires --dry-run for review or --confirm to apply.", usage, CONFIRM_REQUIRED)` (`CONFIRM_REQUIRED=7`). The full preview is only ever shown via `--dry-run`.
  - `--confirm` (with or without a prior `--dry-run` run — there's no stateful token linking the two) performs the merge for real.
- **Step-by-step behavior (on `--confirm`):** `actor = $SUDO_USER or $USER or str(uid)`. `merge = state.create_device_merge(source, target, reason, actor)`: snapshots both endpoints via `_device_snapshot()` (ip/hostname/name/platform/model/serial/mac/source/last_seen/status), computes merge keys via `_device_merge_key()` (priority: `mac:<mac>` > `serial:<serial>` > `ip:<ip>` > `name:<compact_name>`), rejects if either key is empty, if source/target keys collide, or if reason fails validation (`1-500 chars, no CR/LF/NUL`) — raising `ValueError("both devices require a stable MAC, serial, IP, or hostname identity")`, `ValueError("source and target resolve to the same active device")`, or `ValueError("a one-line merge reason of 1-500 characters is required")`. Inside one `connect()` transaction: checks the source key doesn't already have an active merge (`ValueError(f"source device already has an active manual merge: {source_key}")`), walks the merge-target chain to detect cycles (`ValueError("manual merge would create an identity cycle")`), inserts one `inventory_merges` row, then inserts one `inventory_history` row **per identity kind the source had** (`ip`, `mac`, `name` — each only if non-empty) with `event_type='manually_merged'`, and upserts `inventory_identity_state` for each of those kinds with `status='HISTORICAL'`. Back in `cmd_inventory_merge`: `reconciliation = state.sync_derived_state()` (applies the newly-created merge immediately — deletes the source's live `devices` row via `_apply_manual_merges`, and rebuilds `relationships_current`/events with a `manual_identity_merge` relationship of `confidence=100`), then `compatibility = state.export_flat_files()`, then `record_audit_event("inventory_device_merged", "inventory-merge", actor=actor, actor_uid=os.getuid(), target=f"{source_key}->{target_key}", result="success", reason=reason, detail={"merge_id","source_ip","target_ip"})`.
- **Side effects:** Inserts into `inventory_merges` (1 row), `inventory_history` (1-3 rows depending on identity kinds present), upserts `inventory_identity_state` (1-3 rows, `status='HISTORICAL'`); `sync_derived_state()` deletes the source's row from `devices` (via manual-merge suppression), and updates `relationships_current`/`relationship_events` (adds a `manual_identity_merge` relationship at confidence 100, and reconciles every other relationship since the source's `devices` row vanished); writes flat files; inserts one `audit_events` row with **event_type `"inventory_device_merged"`**.
- **Output shape, table mode:** Preview (`--dry-run`) text as above. Applied text: same preview text plus `\nMerge: <merge_id> | Recorded: <iso timestamp>`.
- **Output shape, --json mode:** Preview: `{"ok": true, "operation": "manual-device-merge", "source": {...snapshot...}, "target": {...snapshot...}, "assessment": {...}, "reason": "...", "effects": [4 fixed strings], "requires_confirmation": true}`. Applied: the same preview dict spread, plus `{"merge": {...timestamped merge row...}, "reconciliation": {...sync_derived_state() result...}, "compatibility_export": {...export_flat_files() counts...}, "applied": true}`.
- **Exit codes:** `VALIDATION=6` for argument/resolution errors and for `ValueError`s raised by `create_device_merge`; `CONFIRM_REQUIRED=7` when neither `--dry-run` nor `--confirm` was passed; `SUCCESS=0` for a successful dry-run preview or a successful apply.
- **Real example:** `netrune inventory merge ZONE10-SW01-OLD ZONE10-SW01 --reason "board swap, new serial" --dry-run` → preview showing confidence and conflicts; then re-run with `--confirm` to apply and get back a `merge_id` like `mrg-3f9a1...`.
- **Related commands:** `netrune inventory merges` to list active merges and get a `merge_id`; `netrune inventory unmerge <merge_id>` to revoke; `netrune memory device <name>` afterward to see the merge reflected as a `manual_identity_merge` relationship.

#### `netrune inventory merges` (id: `inventory-merges`)
- **Purpose:** List manual device merges (active by default; `--all` includes revoked ones).
- **Exact syntax:** `netrune inventory merges [--all]` (verb `merges` or `merge-history`).
- **Arguments:** None positional; global `--all` flag controls `include_revoked`.
- **Preconditions / gating:** None.
- **Step-by-step behavior:** `state.list_device_merges(include_revoked=opts.all)`: `SELECT merge_id,entity_type,source_key,target_key,source_name,source_ip,target_name,target_ip,reason,actor,created_at,last_applied_at,suppressed_observations,revoked_at,revoked_by,revoke_reason FROM inventory_merges [WHERE revoked_at IS NULL] ORDER BY created_at DESC, merge_id DESC`. Rows wrapped via `timestamp_rows()`.
- **Side effects:** None (read-only).
- **Output shape, table mode:** columns `["created_at","merge_id","source_name","source_ip","target_name","target_ip","reason","suppressed_observations","revoked_at"]`.
- **Output shape, --json mode:** `{"ok": true, "rows": [...], "count": N, "chronology": "newest_first"}` — **note: no `time_format` key here**, unlike most other payloads in this group that carry both `chronology` and `time_format`.
- **Exit codes:** Always `SUCCESS`.
- **Real example:** `netrune inventory merges --all` → every merge ever created, including revoked ones (with `revoked_at`/`revoked_by`/`revoke_reason` populated for those).
- **Related commands:** `netrune inventory unmerge <merge_id>` to revoke one listed here.

#### `netrune inventory scan` (id: `inventory-scan`)
- **Purpose:** Refresh switch/router inventory via a live SSH scan.
- **Exact syntax:** `netrune inventory scan '<target>'` (verb `scan`).
- **Arguments:** `target` — optional; **only the first word of `rest` is ever forwarded** (`*(rest[:1])`) to the legacy helper — any additional words are silently dropped.
- **Preconditions / gating:** Standard `run_subprocess` dry-run short-circuit.
- **Step-by-step behavior:** `rc = run_subprocess(legacy_cmd("netrune-discovery","--update", *(rest[:1])), opts)`. If `rc==0` and not dry-run: `self.import_flat_state(("device",), "ssh-scan")` in `try/except Exception` → logs `f"Observation recording failed: {exc}"` to stderr and returns `PARTIAL` on failure. Only the `"device"` channel is re-imported/recorded here (unlike `import-flat`'s three channels).
- **Side effects:** Rewrites `devices`/`aps`/`neighbors` wholesale (via `import_flat_files()` inside `import_flat_state`) and runs full `sync_derived_state()`; records one `built-in-ssh-scan` ingest provenance run. No `audit_events` row.
- **Output shape, table mode / --json mode:** `output_type: log` — streamed helper output, or the dry-run echo.
- **Exit codes:** `SUCCESS` on dry-run; the helper's own rc on success; `PARTIAL` if the post-scan import throws; standard `TIMEOUT`/`UNSUPPORTED`/`130` from `run_subprocess`.
- **Real example:** `netrune inventory scan ZONE10-SW01` → SSHes to that switch, refreshes its `devices` row and cascades a full reconciliation.
- **Related commands:** `netrune inventory list`/`details` afterward; `netrune inventory forget` first if the device's identity needs to be reset before re-adoption.

#### `netrune inventory unmerge` (id: `inventory-unmerge`)
- **Purpose:** Revoke an active manual device merge, restoring the historical source device to active inventory.
- **Exact syntax:** `netrune inventory unmerge <merge-id> --reason 'incorrect association' --confirm`.
- **Arguments:** One positional (`merge_id`) — `_manual_merge_arguments(args, expected=1)`, same token-parsing rules as `merge` (including the `into` filler being droppable, though irrelevant here). Missing/invalid positional count: `f"expected 1 positional argument"`. Missing `--reason`: `"A revocation reason is required."` (`VALIDATION`).
- **Preconditions / gating: this is the sharpest gotcha in the whole group.** There is **no `--dry-run` handling anywhere in `cmd_inventory_unmerge`** — the only gate is `if not opts.confirm: return usage_error(..., "Restoring a retired device requires --confirm.", usage, CONFIRM_REQUIRED)`. **No preview is ever shown before applying** (unlike `merge`'s `--dry-run` path). If a caller passes `--dry-run --confirm` together, the command still executes for real — `--dry-run` is silently ignored because this handler never checks `opts.dry_run`. The registry's `preview_supported: true` / `run_supported: false` metadata reflects that a UI should only ever offer this as a "prepare" step, but the CLI itself has no such split enforced in code.
- **Step-by-step behavior (on `--confirm`):** `actor` resolved the same way as `merge`. `merge = state.revoke_device_merge(merge_id, reason, actor)`: looks up the active, non-revoked `inventory_merges` row by id (`ValueError(f"active manual merge not found: {merge_id}")` if absent/already revoked); the historical source's snapshot must carry a valid IPv4 (`ValueError("historical source has no restorable IP address")`); if a `devices` row already exists at that IP and it does **not** identity-match the stored source snapshot (via `_device_matches_snapshot`, MAC/serial/IP-key equality or `identity_match_evidence`), raises `ValueError(f"source IP is now owned by a different active device: {source_ip}")`; otherwise (re-)inserts a `devices` row from the source snapshot if none currently occupies that IP; marks the merge row `revoked_at`/`revoked_by`/`revoke_reason`; inserts one `inventory_history` row (`event_type='manual_merge_revoked'`). Back in `cmd_inventory_unmerge`: `reconciliation = state.sync_derived_state()` (the source becomes visible again since `_apply_manual_merges` no longer suppresses it), `compatibility = state.export_flat_files()`, then `record_audit_event("inventory_device_merge_revoked", "inventory-unmerge", actor=..., actor_uid=os.getuid(), target=merge_id, result="success", reason=reason, detail={"source_ip","target_ip"})`.
- **Side effects:** Possibly inserts a `devices` row (only if the IP is currently unoccupied); updates the `inventory_merges` row's revocation fields; inserts 1 `inventory_history` row; `sync_derived_state()` reconciliation cascade; flat files exported; inserts 1 `audit_events` row with **event_type `"inventory_device_merge_revoked"`**.
- **Output shape, table mode:** `Manual merge revoked: <merge_id>\nHistorical device restored: <source_name or source_ip>\nRecorded: <iso revoked_at>`.
- **Output shape, --json mode:** `{"ok": true, "merge": {...timestamped, revoked merge row...}, "reconciliation": {...}, "compatibility_export": {...}}`.
- **Exit codes:** `VALIDATION=6` for argument errors and `ValueError`s from `revoke_device_merge`; `CONFIRM_REQUIRED=7` if `--confirm` is absent; `SUCCESS=0` once revoked.
- **Real example:** `netrune inventory unmerge mrg-3f9a1b2c4d5e6f708192 --reason "merge was a mistake, different device" --confirm` → restores the old device row and reconciles.
- **Related commands:** `netrune inventory merges` to find the `merge_id`; `netrune inventory merge` to re-apply a corrected merge afterward if needed.

---

### Memory domain

#### `netrune memory device` (id: `memory-device`)
- **Purpose:** Show current identity/attachment relationships and history involving one device/AP/IP/MAC-ish target string.
- **Exact syntax:** `netrune memory device '<target>'`.
- **Arguments:** `target` — required; missing yields `usage_error(..., "Missing device name or IP.", "netrune memory device ZONE34", USAGE)`. Only `rest[0]` is used (extra words ignored, unlike `memory switch`).
- **Preconditions / gating:** None.
- **Step-by-step behavior:** `memory_device_payload(target, opts.limit)`: `current = SELECT * FROM relationships_current WHERE status!='disappeared' AND (object_id LIKE ? OR subject_id LIKE ? OR attrs_json LIKE ?) ORDER BY COALESCE(last_seen,updated_at,first_seen,0) DESC, rel_type, confidence DESC LIMIT ?` — the `attrs_json LIKE` clause means this can match on anything embedded in a relationship's attrs blob (aliases, canonical_id, switch name, etc.), not just the exact subject/object id. `timeline = relationship_timeline_payload(target, limit)["rows"]` (no `rel_type`/`subject_kind` filter — all relationship types).
- **Side effects:** None (read-only).
- **Output shape, table mode:** columns `["rel_type","subject_kind","subject_id","object_kind","object_id","status","first_seen","last_seen"]`.
- **Output shape, --json mode:** `{"ok","mode":"device","target","current","timeline","count","chronology","time_format","latest_recorded_at","latest_recorded_at_iso","timestamp_note"}`.
- **Exit codes:** `USAGE=2` if no target; else always `SUCCESS`.
- **Real example:** `netrune memory device ZONE34-SW01` → its identity_ip/identity_mac/device_alias relationships plus any `ap_attachment`/`port_occupancy` rows where it's the switch, plus a full event timeline.
- **Related commands:** `netrune memory explain <target>` for a source/confidence summary instead of raw rows; `netrune inventory details <target>` for live SSH detail; `netrune memory switch <target>` if the target is itself a switch and you want AP/neighbor scoping instead.

#### `netrune memory explain` (id: `memory-explain`)
- **Purpose:** Summarize relationship sources and average confidence, grouped by relationship type and source.
- **Exact syntax:** `netrune memory explain '<target>'`.
- **Arguments:** `target` — optional; empty string is valid and means "summarize everything" (no missing-target error, unlike `memory device`/`memory switch`). Only `rest[0]` used.
- **Preconditions / gating:** None.
- **Step-by-step behavior:** `memory_explain_payload(target)`: `SELECT rel_type, source, COUNT(*) AS count, ROUND(AVG(confidence),1) AS avg_confidence, MAX(COALESCE(last_seen,updated_at,first_seen,0)) AS last_seen FROM relationships_current WHERE (?='' OR subject_id LIKE ? OR object_id LIKE ? OR attrs_json LIKE ?) GROUP BY rel_type, source ORDER BY last_seen DESC, rel_type, source`. Note this query is **not filtered by `status!='disappeared'`**, so it includes stale/disappeared relationships in its counts and averages — the one command in this group where that's true.
- **Side effects:** None (read-only).
- **Output shape, table mode:** columns `["rel_type","source","count","avg_confidence","last_seen"]`.
- **Output shape, --json mode:** `{"ok","mode":"explain","target","rows","chronology","time_format","latest_recorded_at","latest_recorded_at_iso"}`.
- **Exit codes:** Always `SUCCESS`.
- **Real example:** `netrune memory explain ZONE34` → e.g. `identity_ip | inventory | 3 | 95.0 | ...`, `ap_attachment | controller | 12 | 91.3 | ...`.
- **Related commands:** `netrune memory device <target>` for the underlying raw rows this summarizes.

#### `netrune memory export` (id: `memory-export`)
- **Purpose:** Bulk-export every current relationship row as JSON (or a plain table).
- **Exact syntax:** `netrune memory export --json` (the `--json` in the registry's template is a strong hint, not enforced by code).
- **Arguments:** None.
- **Preconditions / gating:** None.
- **Step-by-step behavior:** `SELECT * FROM relationships_current ORDER BY COALESCE(last_seen,updated_at,first_seen,0) DESC, rel_type, subject_id, object_id`, wrapped via `timestamp_rows()`. **This query is unbounded — it ignores `opts.limit` entirely and returns every row in the table**, the only list command in the group that does not cap output by `--limit`.
- **Side effects:** None (read-only).
- **Output shape, table mode:** No explicit column list is passed to `emit()` (the third `text` argument is omitted entirely), so it falls back to `render_plain()` → `render_table(rows)` with `columns=None`, which defaults to **the first 8 keys of the first row dict** — for a `relationships_current` row that's `["rel_key","rel_type","subject_kind","subject_id","object_kind","object_id","switch_ip","switch_name"]` (matching the table's native column order; `attrs_json`/`confidence`/`status`/timestamps/`_iso` fields are all cut off by the 8-column default).
- **Output shape, --json mode:** `{"ok": true, "rows": [...ALL rows...], "chronology": "newest_first", "time_format": "ISO 8601 UTC"}` — **note: no `count` key**.
- **Exit codes:** Always `SUCCESS`.
- **Real example:** `netrune memory export --json > relationships.json` → a complete relationship-memory dump for offline analysis.
- **Related commands:** `netrune memory refresh` beforehand to make sure the export reflects the latest canonical state; `netrune memory explain` for an aggregated view instead of a raw dump.

#### `netrune memory ip` (id: `memory-ip`)
- **Purpose:** Show historical ownership and relationship events for one IP address.
- **Exact syntax:** `netrune memory ip '<target>'`.
- **Arguments:** `target` — required; missing yields `usage_error(..., "Missing ip value.", "netrune memory ip <value>", USAGE)`. Only `rest[0]` used, passed through unnormalized (no IP-literal validation — any string is accepted and just substring-matched).
- **Preconditions / gating:** None.
- **Step-by-step behavior:** `relationship_timeline(rest[0], opts, subject_kind="ip")` → `relationship_timeline_payload(target, limit, rel_type="", subject_kind="ip")`: `WHERE (subject_id LIKE ? OR object_id LIKE ? OR previous_json LIKE ? OR current_json LIKE ?) AND subject_kind='ip'`. Because `subject_kind='ip'` is only ever set on `identity_ip` relationships (see `_relationship_desired` in Cross-cutting notes), this effectively returns identity_ip first-seen/changed/disappeared events for that address, across whichever device or AP has ever claimed it.
- **Side effects:** None (read-only).
- **Output shape, table mode:** columns `["version","version_label","created_at","event_type","rel_type","subject_id","object_id","source"]`.
- **Output shape, --json mode:** `{"ok","target","rows","count","chronology","time_format","latest_recorded_at","latest_recorded_at_iso"}`.
- **Exit codes:** `USAGE=2` if no target; else always `SUCCESS`.
- **Real example:** `netrune memory ip 198.51.100.30` → shows every device/AP that has ever owned that address and when ownership changed hands.
- **Related commands:** `netrune memory mac <mac>` for the MAC-keyed equivalent; `netrune inventory forget` if an address's ownership history is wrong and needs correcting at the source.

#### `netrune memory mac` (id: `memory-mac`)
- **Purpose:** Show identity and movement history for one MAC address.
- **Exact syntax:** `netrune memory mac '<target>'`.
- **Arguments:** `target` — required, same missing-value error as `memory ip` but with `verb="mac"` substituted into the message/usage. **Unlike `memory ip`, the value is normalized first**: `norm_mac(rest[0])` (via `identity.normalize_mac`) before being used as the search target.
- **Preconditions / gating:** None.
- **Step-by-step behavior:** `relationship_timeline(norm_mac(rest[0]), opts, subject_kind="mac")` → same query shape as `memory ip` but `subject_kind='mac'`, matching `identity_mac` relationships.
- **Side effects:** None (read-only).
- **Output shape, table mode / --json mode:** identical shape to `memory ip`.
- **Exit codes:** `USAGE=2` if no target; else always `SUCCESS`.
- **Real example:** `netrune memory mac aabb.ccdd.eeff` → every device/AP identity event tied to that normalized MAC.
- **Related commands:** `netrune memory ip`, `netrune memory device`.

#### `netrune memory port` (id: `memory-port`)
- **Purpose:** Show current and historical occupancy for one switch port.
- **Exact syntax:** `netrune memory port '<target>' '<interface>'`.
- **Arguments:** Two required positionals, `switch` and `interface` — `if len(rest)<2: usage_error(..., "Missing switch and/or port.", "netrune memory port ZONE34 Gi1/0/7", USAGE)`. Extra words beyond `rest[1]` are ignored.
- **Preconditions / gating:** None.
- **Step-by-step behavior:** `memory_port_payload(switch, port, opts.limit)`. Two distinct matching modes depending on whether `port` is purely digits: **digits-only** (e.g. `"7"`) matches `switch_port = ? OR switch_port LIKE '%/<port>'` — i.e. it also matches an interface like `Gi1/0/7` by its trailing numeric segment, and the companion event search uses `%/<port>"%` against the JSON blobs. **Non-digit** (e.g. `"Gi1/0/7"`) requires an **exact** `switch_port = ?` match, and the companion event search uses `%"switch_port":"<port>"%`. Both modes filter `rel_type='port_occupancy' AND status!='disappeared'` for current rows, and scope by switch name/ip substring match (`subject_id LIKE %switch% OR switch_name LIKE %switch% OR switch_ip LIKE %switch%`).
- **Side effects:** None (read-only).
- **Output shape, table mode:** Two sections — "Current port occupancy (newest recorded first)" with columns `["subject_id","object_kind","object_id","source","confidence","status","first_seen","last_seen"]`, then "Timeline (newest first)" with columns `["created_at","event_type","subject_id","object_id","source","detail"]`.
- **Output shape, --json mode:** `{"ok","mode":"port","target","port","current","timeline","count","chronology","time_format","latest_recorded_at","latest_recorded_at_iso","timestamp_note"}`.
- **Exit codes:** `USAGE=2` if fewer than 2 positionals; else always `SUCCESS`.
- **Real example:** `netrune memory port ZONE34-SW01 Gi1/0/7` → shows whatever AP or neighbor currently occupies that port, plus its occupancy history (e.g. an AP that moved off it three weeks ago).
- **Related commands:** `netrune ap moves`/`ap timeline` for AP-attachment-specific views of the same underlying `port_occupancy` relationships; `netrune memory switch <switch>` for all ports on that switch at once.

#### `netrune memory prune` (id: `memory-prune`)
- **Purpose:** Documented/intended to prune relationship memory — but is **permanently disabled**.
- **Exact syntax:** `netrune memory prune`.
- **Arguments:** None; whatever is passed is never even inspected.
- **Preconditions / gating:** The handler is a one-line stub: `return self.usage_error("memory","prune",opts,"Relationship history is retained forever by default. Pruning is not enabled yet.","netrune memory export --json",CONFIRM_REQUIRED)`. This always runs, unconditionally, regardless of any flags passed — **no code path in this command ever touches the database.** The registry's metadata (`writes_local: true`, `state_effects: ["local-state","sqlite"]`, `risk_level: "danger"`) describes an aspirational/future capability, not current behavior; treat it as purely documentary.
- **Step-by-step behavior:** None (see above).
- **Side effects:** None, ever.
- **Output shape, table mode / --json mode:** Standard `usage_error` shape: text `Error: Relationship history is retained forever by default. Pruning is not enabled yet.` / `Try: netrune memory export --json` / usage/help lines; JSON `{"ok": false, "error": "...", "usage": "...", "suggestion": "netrune memory export --json", "examples": [...], "exit_code": 7}`.
- **Exit codes:** Always `CONFIRM_REQUIRED=7`.
- **Real example:** `netrune memory prune` → always errors with the message above, suggesting `memory export --json` instead (as the closest thing to "get this data out before it's needed").
- **Related commands:** `netrune memory export` (the suggested alternative); `netrune db prune` for the actually-functional operational-history pruning command (a different domain, not in scope here, governed by `State.RETENTION_DEFAULTS`/`prune_history()` — note `relationship_events` **does** have a real retention default there of 180 days, which is a different, general-purpose mechanism from this always-disabled `memory prune` verb).
- **Note:** `relationship_events`/`health_events`/`inventory_history` are in fact subject to a completely separate, working retention mechanism — `State.prune_history()`, reachable via `netrune db prune` (outside this scope) — which is unrelated to this always-stubbed `memory prune` verb. The stub's message ("retained forever by default") is only true with respect to *this* verb; the `db prune` path can and does delete `relationship_events` older than its configured retention window (180 days by default).

#### `netrune memory refresh` (id: `memory-refresh`)
- **Purpose:** Recompute relationship memory from canonical state by re-importing the flat caches into SQLite and re-running full derived-state reconciliation.
- **Exact syntax:** `netrune memory refresh`.
- **Arguments:** None.
- **Preconditions / gating:** **No `--dry-run` guard** — same caveat as `inventory import-flat`/`export-flat`: this always executes.
- **Step-by-step behavior:** `self.state.import_flat_files()` — reads `devices`/`aps`/`neighbors` flat files, dedupes AP rows, bulk-replaces the three SQLite tables, then calls `sync_derived_state()`. **Despite its `network-read/local-write` registry safety class, this command never contacts the network itself** — it only reimports whatever the flat files already contain (which only change via an actual scan elsewhere). Then `self.state.counts()` is computed for the response.
- **Side effects:** Full `devices`/`aps`/`neighbors` overwrite from flat files; full `sync_derived_state()` cascade (identity history, health, topology, relationships — see Cross-cutting notes); no ingest-provenance rows (unlike `inventory import-flat`, this calls `state.import_flat_files()` directly, bypassing `import_flat_state`'s ingest-recording wrapper — same asymmetry noted for `health check`); no `audit_events` row.
- **Output shape, table mode:** Fixed text: `Memory refreshed from canonical inventory, AP, topology, and lookup observations.`
- **Output shape, --json mode:** `{"ok": true, "counts": {...state.counts() dict: devices, neighbors, offline_devices, relationships, relationship_events, running_jobs, partial_jobs, failed_jobs, backups, diagnostic_runs, audit_events, manual_merges, aps, offline_aps, ap_observations, ap_alias_records...}}`.
- **Exit codes:** Always `SUCCESS`.
- **Real example:** `netrune memory refresh` → typically run after manually editing the flat files, or to force a reconciliation pass without waiting for the next scan.
- **Related commands:** `netrune inventory scan`/`ap scan` if the underlying flat files themselves are stale and need a live refresh first; `netrune memory export` afterward to inspect the result.

#### `netrune memory switch` (id: `memory-switch`)
- **Purpose:** One-call combined view of a switch/site's matching device rows, attached APs, LLDP/CDP neighbors, current relationships, and recent relationship-event timeline.
- **Exact syntax:** `netrune memory switch '<target>'`.
- **Arguments:** `target` — required; missing yields `usage_error(..., "Missing switch target.", "netrune memory switch ZONE10", USAGE)`. All words joined (multi-word supported).
- **Preconditions / gating:** None.
- **Step-by-step behavior:** `memory_switch_payload(target, opts)` branches on whether the normalized target is a full IPv4 literal (`IP_RE.fullmatch`): **IP branch** matches `devices` by exact ip/hostname/short-hostname; `aps` by exact `switch_ip`; `neighbors` by exact `local_ip`; `relationships_current`/`relationship_events` by exact `subject_id`/`object_id`/`switch_ip` equality (or JSON substring for events). **Name/site branch** uses `LIKE %target%` substring matching throughout instead of exact equality for hostname/switch_name/relationship fields (still exact for `switch_ip = target` where applicable). In both branches, relationship/event queries are scoped to `rel_type IN ('ap_attachment','neighbor_link','port_occupancy')` only — identity/alias/merge relationship types are excluded from this view. AP rows are further reconciled via `reconcile_ap_rows()` and capped to `opts.limit`.
- **Side effects:** None (read-only).
- **Output shape, table mode:** Header `Memory: <target>\nSwitch matches: N | APs: N | Neighbors: N | Events: N`, then four sections: APs (columns `["switch_port","name","ip","mac","status","last_seen"]`), Neighbors (columns `["local_port","remote_name","remote_port","remote_ip"]`), Current relationships (columns `["rel_type","subject_id","object_id","source","status","first_seen","last_seen"]`), Recent relationship timeline (columns `["created_at","event_type","rel_type","subject_id","object_id","source","detail"]`).
- **Output shape, --json mode:** `{"ok","target","switches":[...matched device rows...],"attachments":{"aps","neighbors","relationships"},"timeline","counts":{"switches","aps","neighbors","relationships","events"},"sources":["controller","topology","core_lookup","relationship_events"],"chronology","time_format","latest_recorded_at","latest_recorded_at_iso","timestamp_note"}`.
- **Exit codes:** `USAGE=2` if no target; else always `SUCCESS`.
- **Real example:** `netrune memory switch ZONE10-SW01` → single call combining everything about that switch: matched device row(s), its currently-attached APs, its LLDP/CDP neighbors, current port-occupancy/attachment relationships, and the recent event timeline — the canonical way to answer "what's on this switch and what changed recently."
- **Related commands:** `netrune ap on-switch <target>` for the AP-and-timeline-only subset of the same JSON; `netrune memory device <target>` if the target itself is an end device rather than a switch; `netrune topology show <target>` (different domain) for a more topology-centric neighbor view.

#### `netrune memory timeline` (id: `memory-timeline`)
- **Purpose:** Search all relationship events (of any type), newest first.
- **Exact syntax:** `netrune memory timeline '<target>'`.
- **Arguments:** `target` — optional despite the registry marking it required: `relationship_timeline(rest[0] if rest else "", opts)` — empty target means "every relationship event, unfiltered by type or subject_kind."
- **Preconditions / gating:** None.
- **Step-by-step behavior:** `relationship_timeline_payload(target, opts.limit, rel_type="", subject_kind="")` — the only one of the `memory` timeline-style commands with **no** `rel_type`/`subject_kind` restriction at all (contrast with `ap timeline`'s forced `rel_type='ap_attachment'` or `memory ip`/`mac`'s forced `subject_kind`).
- **Side effects:** None (read-only).
- **Output shape, table mode / --json mode:** identical shape to `memory ip`/`memory mac`/`ap timeline` (`version`/`version_label`-decorated rows; JSON `{"ok","target","rows","count","chronology","time_format","latest_recorded_at","latest_recorded_at_iso"}`).
- **Exit codes:** Always `SUCCESS`.
- **Real example:** `netrune memory timeline` → the global relationship-change firehose across identity, attachment, neighbor, and port-occupancy events; `netrune memory timeline ZONE10` → scoped to anything matching that substring anywhere in subject/object id or the event's JSON payload.
- **Related commands:** `netrune memory device <target>` to combine this with current-state rows for one target; `netrune health timeline` for the parallel health-event feed (a structurally distinct table).

---

### Cross-cutting notes

#### Where model, serial, and base MAC come from

Two collectors write hardware identity into the `devices` pipe file, both through `netops_platform/inventory_ingest.py` so they produce one canonical string per field:

- **SNMP scan** (`netops-discovery` `scan_host`): the ENTITY-MIB chassis is the lowest-indexed `entPhysicalClass == 3` entity — index 1 on standalone Arubas, 1000 on Catalyst 9000 (1 is the "c92xx Stack" container), 1001 on 2960/3560CX and stackable Arubas; one `snmpget` checks all three, a class-column walk is the fallback. `parse-snmp-hardware` takes Cisco's model from that entity's `entPhysicalModelName` (never `sysDescr`, which names the software image) and Aruba's from `entPhysicalDescr`/`sysDescr` via `aruba_model_name()` (vendor and product number such as `JL258A` dropped: `2930F-8G-PoE+-2SFP+`, `5412Rzl2`). Serial is the chassis `entPhysicalSerialNum`; base MAC is `dot1dBaseBridgeAddress` (returned as space-separated hex).
- **SSH** (`netops-control` `refine_inventory_from_ssh`, after every SSH job): `parse-cli-hardware` reads labelled fields only — Cisco `Model Number` (then `show inventory` PID), `Motherboard Serial Number` (then System serial, inventory SN, Processor board ID), `Base Ethernet MAC Address`; Aruba the `show modules` `Chassis:` model, `Serial Number`/`Chassis Serial Nbr`, `Base MAC Addr`/`Base MAC Address`, including AOS-S `show system`'s right-hand column. Unlabelled output yields nothing, so a non-inventory job never records an interface MAC as the base MAC.
- **Merge precedence** (`merge_device_observations`): any meaningful incoming value replaces the stored one, except that on `cisco-ios` an SNMP-only observation does not replace an SSH-recorded serial while the model is unchanged — Cisco's SNMP chassis serial is the System serial, the device serial is the Motherboard serial, and on 2960/3560CX they differ. Models containing `"`, `(`, `)`, `:` or `\` (captured error text) normalize to `N/A`.

#### `sync_derived_state()` and relationship-memory reconciliation

`State.sync_derived_state(origin="operational")` (`core.py:1460`) is the single atomic reconciliation pass that every write-triggering command in this group ultimately calls, directly or via `state.import_flat_files()` / `state.create_device_merge()` / `state.revoke_device_merge()`. Inside one `connect()` transaction it:

1. Records a high-water mark (`MAX(id)`) for each of the five append-only event tables (`inventory_history`, `health_events`, `topology_events`, `ap_move_events`, `relationship_events`) — used only when `origin="migration"` to retroactively suppress noise generated by a schema migration replay (it deletes and counts any event rows inserted past that high-water mark, recording the suppressed counts into a `scan_runs` row rather than leaving fabricated "something changed" events from a migration).
2. `_apply_manual_merges(con, ts)` — walks every active `inventory_merges` row and physically deletes the corresponding source device's row from `devices` if a live row still matches that merge's source snapshot (by merge key, or by falling back to `identity_match_evidence` for ambiguous IP-based matches), so a manually-merged-away device stops appearing as a second live device on the very next reconciliation, even if it's still being observed by a scan. Bumps `last_applied_at`/`suppressed_observations` on the merge row each time it fires.
3. `_current_inventory_rows(con)` — builds the canonical device+AP row set: raw `devices` through `reconcile_device_rows()` with manual-merge aliases overlaid (`_overlay_manual_device_merges`), plus raw `aps` through `reconcile_ap_rows()`. This is the shared input to steps 4-6.
4. `_sync_identity_history(con, ts, inventory_rows)` — writes `inventory_history` (append-only) and `inventory_identity_state` (upsert) for every `(kind, value)` identity key (`ip`, `mac`, `name`) of every canonical row: a `first_seen` event on first encounter, or a `field_changed` event per changed field (`ip,mac,name,platform,model,serial,switch_ip,switch_name,switch_port,source,status`) on subsequent passes.
5. `_sync_health(con, ts, inventory_rows)` — rebuilds `health_state`/`health_events` (see next section).
6. `_sync_topology(con, ts)` — diffs the current `neighbors` snapshot against the previous `topology_snapshot` table, writing `link_added`/`link_removed` rows to `topology_events` for the delta, then replaces `topology_snapshot` with the current set.
7. `_sync_relationships(con, ts, inventory_rows)` — the relationship-memory engine itself (below).

**What "relationship memory" models.** `_relationship_desired()` (`core.py:1954`) builds the full *desired* set of relationships from the canonical inventory rows, keyed by a deterministic `rel_key` string, covering exactly these `rel_type`s: `identity_ip` (an IP address currently belongs to a device or AP, confidence 95), `identity_mac` (a MAC belongs to a device or AP, confidence 99), `device_alias`/`identity_alias` (an alias name resolves to a canonical device/AP id, confidence = the row's own `identity_confidence`, default 75/80), `manual_identity_merge` (an operator-created merge, confidence 100 — this is how `inventory merge`'s effect becomes visible in relationship memory), `ap_attachment` (an AP is attached to a switch, confidence 95 if switch-learned via `switch_ip`, 84 if controller-only), `port_occupancy` (a specific switch port is occupied by an AP or a neighbor, confidence 92/82 respectively), and `neighbor_link` (an LLDP/CDP-discovered switch-to-neighbor link, confidence 88, sourced straight from the `neighbors` table). `_sync_relationships()` then diffs this desired set against `relationships_current`: new keys get `INSERT` + a `first_seen` event; changed keys (any of `object_kind,object_id,switch_ip,switch_name,switch_port,source,confidence,status,attrs_json` differs) get `UPDATE` + a `changed` (or `reappeared`, if it was previously `disappeared`) event — and specifically for `ap_attachment` rows where the switch identity changed, an additional row is inserted into `ap_move_events`; unchanged keys just get their `last_seen`/`updated_at` bumped; and any previously-`active` managed-type key **absent** from this pass's desired set is marked `status='disappeared'` with a `disappeared` event (rather than being deleted — relationship history is retained). So in plain terms: relationship memory is the record of *who currently (or historically) owns which IP/MAC, which alias resolves to which canonical device/AP, which AP is attached to which switch/port, and which switches see which neighbors* — plus the append-only `relationship_events` audit trail of every time one of those facts changed. `record_stp_links()` and `record_core_lookup()` (used by other domains, not the 31 in scope) add two more relationship types (`stp_link`, `core_lookup`) into the same `relationships_current`/`relationship_events` tables but are **not** part of the managed set `_sync_relationships` reconciles/expires — they're written and refreshed independently.

**How confidence scores get computed.** Two distinct mechanisms feed the numbers users see: (1) the **fixed per-relationship-type confidence constants** baked into `_relationship_desired()` and listed above (95/99/92/82/88/95/84/100/75-80), which is what `netrune memory explain`'s `avg_confidence` column aggregates; and (2) `identity.identity_match_evidence(left, right, entity_type)`, a pairwise scoring function used for *deciding whether two observations are the same device/AP* (during `reconcile_device_rows()`/`reconcile_ap_rows()`'s union-find grouping, `inventory merge`'s preview `assessment`, and `_device_matches_snapshot()` during merge application/revocation). It computes a name-similarity ratio (`difflib.SequenceMatcher`, threshold configurable via `NETRUNE_AP_SIMILARITY_THRESHOLD`/`NETRUNE_SWITCH_SIMILARITY_THRESHOLD`, defaults 85/75), adds weighted points for `same_mac` (+100), `same_serial` (+95), `same_ip` (+80), `same_attachment` (+75, AP-only — switches never get this bonus), `same_asset_number` (+20), `same_model` (+10), and a name-similarity bonus (+45/+40 if above threshold, else a fractional +0.25×similarity); a differing MAC, serial, or matching-role-but-different-asset-number is a hard **conflict** that forces `same_device=False` regardless of score. Final `confidence` is `min(100, max(threshold, score))` if judged the same device, else `min(score, 74)` — so a "same device" verdict is always ≥ the configured threshold (75/85), and a "different device" verdict is always capped below 75.

#### `health` vs. inventory's plain `status` column

`devices.status` and `aps.status` are single columns, normalized on write via `norm_status()` (folds `UP/ACTIVE/ALIVE/REACHABLE`→`ONLINE`, `DOWN/INACTIVE/DEAD/UNREACHABLE`→`OFFLINE`, anything else→`UNKNOWN`) — they hold only the most recent observed reachability at whatever moment a scan/check last wrote them, with no history and no flap tracking. `health_state`/`health_events` is a materially richer, **separate** derived layer populated exclusively by `_sync_health()` inside `sync_derived_state()`: it tracks `first_seen`, `last_seen` (only bumped while ONLINE), `last_failed` (only bumped while OFFLINE), `outage_started_at` (set when a row transitions to OFFLINE, cleared on return to ONLINE), and `flap_count` (incremented on every observed status transition, never reset) — none of which exist on the plain `devices`/`aps` rows. It's populated only by commands that trigger `sync_derived_state()` — `inventory scan`, `ap scan`, `health check`, `memory refresh`, `inventory import-flat`, `inventory merge`/`unmerge` — never by a mere `SELECT`-only command. Two structural facts matter for querying it correctly: (a) `health_state`'s primary key `entity_id` is a **reconciliation canonical id** (`mac:...`/`serial:...`/`ip:...` fallback for devices, `mac:...`/`ap:<signature>`/`row:...` for APs) rather than a plain IP address — there is no dedicated IP column at all, so `health status <ip>`/`health offline <ip>` will silently miss any device whose canonical id isn't literally `ip:<that address>`; and (b) `switch_ip`/`switch_port` in `health_state` are only ever populated for AP rows (device rows always carry `NULL` there, since `_current_inventory_rows()` hard-codes `NULL AS switch_ip` for the `devices` query). In short: `status` is "what a device last reported," while `health_state`/`health_events` is "the flap-aware, timestamped, canonically-keyed reachability record derived from that plus prior history" — and `netrune health *` reads the latter, `netrune inventory list --status ...` reads the former.

#### `reconciled_ap_rows()` — shared role across `ap` and `inventory`

`App.reconciled_ap_rows(pattern, opts)` (`core.py:4819`) is a thin wrapper — `reconcile_ap_rows(state.rows("SELECT * FROM aps"))` filtered by `ap_rows_match()`, `opts.status`, `opts.site`, then sliced to `opts.limit` — and it is **exclusively shared by the `ap` and `inventory` domains, confirmed by grep**: `ap.ap_rows()` (`core.py:4084`) calls it directly for `ap list`; `InventoryCommandsMixin.inventory_rows()` (`inventory_cli.py:306`) calls it (with a synthetic `GlobalOptions(limit=100000, ...)` so the AP side isn't prematurely truncated before merging with devices) to supply the `"kind":"ap"` half of `inventory list`/`details`. It is **not** used by `db`, `memory`, or `health` — `memory switch`'s AP section instead builds its own SQL (`SELECT * FROM aps WHERE switch_ip=?`/`switch_name LIKE ?`) and reconciles that narrower result directly with `reconcile_ap_rows()`, and `health_state_rows()` doesn't touch `aps` at all (it reads only the already-derived `health_state` table). So `reconciled_ap_rows()`'s actual role is specifically: *the shared, whole-table, pattern/status/site-filterable canonical AP reader used by the two domains (`ap`, `inventory`) that present a general-purpose AP list view*, not a general-purpose AP accessor used everywhere APs are touched.

#### Other cross-domain sharing worth knowing about (found via grep, not assumed)

- `memory_switch_payload`, `memory_port_payload`, `relationship_timeline_payload`, and `attention_payload` are all also called from `ask.py` (the `ask` domain, out of scope here) to answer natural-language questions like "what's on switch X" or "what needs attention" — so changing their query logic affects `ask` output too.
- `relationship_timeline` (the command-handler-level function, not just the payload builder) is also called by `topology_cli.py`'s `topology timeline` verb with `rel_type="neighbor_link"` — it is a three-domain-shared dispatcher (`ap`, `memory`, `topology`), not memory-exclusive.
- `inventory_history_payload` (`core.py:4251`) is defined but has **zero callers anywhere in the codebase** (confirmed by grep) — none of the 31 commands in scope, nor `ask.py`, wire it up. There is no `inventory history` verb in `cmd_inventory`. It appears to be dead/unreachable code as of this session; useful to know if you go looking for "why can't I run `inventory history`" — you can't, it isn't registered anywhere despite the payload builder existing.
- Only three commands in this entire 31-command group ever write an `audit_events` row: `inventory merge` (`event_type="inventory_device_merged"`), `inventory unmerge` (`event_type="inventory_device_merge_revoked"`), and `inventory forget` (`event_type="inventory"`, `action="inventory-forget"` — notably generic compared to the other two, and the only one of the three that doesn't capture a real OS `actor`/`actor_uid`, always logging actor `"local"`). Every other command — all of `ap`/`health`/`memory`, and `inventory scan`/`import-flat`/`export-flat` — performs its writes without an audit trail, even though several of them mutate `devices`/`aps`/`health_state`/`relationships_current` at scale.
- Three commands ignore `--dry-run` entirely despite being flagged `preview_supported: true` in the registry, because they never route through `run_subprocess` (the only place that flag is actually honored) and have no dry-run branch of their own: `inventory import-flat`, `inventory export-flat`, and `memory refresh`. A fourth, `inventory unmerge`, similarly has no dry-run branch even though `preview_supported: true`/`run_supported: false` in the registry implies a UI would only ever "preview" it.

---

## 11. Backup, Vault, Secrets, DB, and Config Domains


All 28 commands below are handled directly inside the `App` class in `netops_platform/core.py`, in the methods `cmd_backup`, `cmd_vault`, `cmd_secrets`, `cmd_db`, and `cmd_config`. None of these domains have been extracted into their own module yet (unlike `vlan`, `device`, `path`, `setup`, `ask`, etc., which now live in separate `*_cli.py` files). Several of these commands are thin Python dispatchers that hand off to two Bash helpers that carry the real logic: `netops-connect` (vault/secrets) and `netops-control` (backup). Both of those source their functions from `netops-lib.sh` (the file `netrune-lib.sh` is just a one-line compatibility bridge that sources `netops-lib.sh`).

A note on exit codes used throughout (defined as module constants in `core.py`): `SUCCESS=0`, `USAGE=2`, `PARTIAL=3`, `UNREACHABLE=4`, `UNSUPPORTED=5`, `VALIDATION=6`, `CONFIRM_REQUIRED=7`, `AUTH=8`, `TIMEOUT=9`, `INTERNAL=10`.

---

### backup domain

#### `netrune backup diff <target>` (id: `backup-diff`)
- **Purpose:** Show a unified diff between the two most recent *changed* backups recorded for one device.
- **Exact syntax:** `netrune backup diff <target>`. Verified against `App.cmd_backup`'s `verb=="diff"` branch: it requires a positional target and calls `self.run_subprocess(self.legacy_cmd("netrune-control","diff",rest[0]),opts)`. No other flags are read on the Python side.
- **Arguments:** `target` (required) — hostname, IP, or site/abbreviation token, resolved the same way as every other device command (`resolve_targets` in `netops-lib.sh`, called with `allow_multiple=false` from `show_backup_diff` in `netops-control`). If omitted, `usage_error("backup","diff",...)` returns `USAGE` with the message "Missing target." and suggestion `netrune backup diff ZONE34`. If the target resolves to more than one device, `resolve_targets` errors out (ambiguous match) rather than diffing multiple devices.
- **Preconditions / gating:** None — always read-only, no `--confirm` needed. `--dry-run` is honored generically by `run_subprocess` (prints the would-be command and returns `SUCCESS` without running it).
- **Step-by-step behavior:** Delegates entirely to `show_backup_diff()` in `netops-lib.sh`: resolves the target to one IP, queries the shared SQLite `backup_history` table for the two most recent rows where `status='saved' AND changed=1` for that `device_ip`, and if both backup files still exist on disk runs `diff -u <older> <newer>`. If fewer than two *changed* backups exist (e.g. only one backup ever taken, or all subsequent backups were unchanged), it prints "Need at least two changed backups for <ip>." and returns exit 1. Note the CLI's help text advertises a `--last` flag, but the actual argument-parsing loop in `netops-control` (`if [[ "$MODE" == "backup-history" || "$MODE" == "diff" ]]`) accepts `--last` syntactically and silently ignores it — it has no effect.
- **Side effects:** None — pure read against `backup_history` and the on-disk backup files. No SQLite writes, no audit event.
- **Output shape, table mode:** None — this is raw `diff -u` text streamed straight from the subprocess (`output_type` in the registry says `log`, which is accurate: it's unstructured log/diff text, not a rendered table).
- **Output shape, --json mode:** **No effect.** `cmd_backup`'s `diff` branch calls `run_subprocess` directly and never routes through `App.emit`, so passing `--json` does not wrap the output — you still get the raw `diff -u` text (or nothing, if the two-backups precondition fails). To get structured JSON you'd have to invoke `netrune-control diff <target>` — but that mode doesn't even implement its own `--json` (only `backup-history` does).
- **Exit codes:** `SUCCESS` on a successful diff; `1` if fewer than two changed backups exist or resolution fails; `USAGE` if the target argument is missing; whatever `netops_ssh`/subprocess plumbing errors propagate (`UNSUPPORTED` if the helper binary itself is missing).
- **Real example:**
  ```
  $ netrune backup diff ZONE34-CORE
  --- ~/.local/share/netrune/backups/2026-08-20/ZONE34-CORE.conf
  +++ ~/.local/share/netrune/backups/2026-08-27/ZONE34-CORE.conf
  @@ -118,7 +118,7 @@
  -vlan 40
  +vlan 40,45
  ```
- **Related commands:** `netrune backup history <target>` to see the full timeline before diffing two specific points; `netrune backup verify` to check checksums/paths across all devices at once.

#### `netrune backup history <target>` (id: `backup-history`)
- **Purpose:** Show newest-first backup metadata (status, changed flag, checksum, path, message) for one device.
- **Exact syntax:** `netrune backup history <target>`. From `App.cmd_backup`'s `verb=="history"` branch: `self.run_subprocess(self.legacy_cmd("netrune-control","backup-history",rest[0]),opts)`.
- **Arguments:** `target` (required, single device, same resolution rules as `backup diff`). Missing target → `usage_error("backup","history",...)`, `USAGE`, suggestion `netrune backup history ZONE34`.
- **Preconditions / gating:** None.
- **Step-by-step behavior:** `show_backup_history()` in `netops-lib.sh` resolves the target to one IP, then queries `backup_history` for up to 20 rows (plain text mode) ordered `created_at DESC, id DESC`, formatted as fixed-width columns via `awk`: `datetime | status | changed=N | sha256(first 12 chars) | path | message`.
- **Side effects:** None (read-only).
- **Output shape, table mode:** Not a Netrune-rendered table — plain `awk`-formatted fixed columns from the bash helper: `%-20s %-10s changed=%s %-12s %s %s` mapping to (created_at as local datetime, status, changed, sha256 prefix, path, message).
- **Output shape, --json mode:** **No effect from the Netrune CLI.** Like `backup diff`, this bypasses `App.emit` entirely via `run_subprocess`. The underlying bash helper *does* support its own `--json` (`sqlite3 -json ... LIMIT 50`), but `cmd_backup` never forwards Netrune's `--json` flag to it, so `netrune backup history <target> --json` still prints the plain-text table, not JSON.
- **Exit codes:** `SUCCESS` normally; `USAGE` for missing target; nonzero from `resolve_targets` on ambiguous/unresolvable target.
- **Real example:**
  ```
  $ netrune backup history ZONE34-CORE
  2026-08-27 14:02:10   saved      changed=1  a1b2c3d4e5f6  ~/.local/share/netrune/backups/2026-08-27/ZONE34-CORE.conf  running-config captured
  2026-08-20 09:15:44   unchanged  changed=0  a1b2c3d4e5f6  ~/.local/share/netrune/backups/2026-08-20/ZONE34-CORE.conf  same as latest backup
  ```
- **Related commands:** `netrune backup diff <target>` for the actual delta; `netrune backup verify` for a cross-device view.

#### `netrune backup run <target> [-o DIR] [--include-offline] [--redact-secrets] [--changed-only|extra netops-control flags]` (id: `backup-run`)
- **Purpose:** Take an online-only, changed-only backup of one or more devices' running configuration and record the result.
- **Exact syntax:** `App.cmd_backup`'s `verb=="run"` branch builds: `netrune-control backup <target> --online-only --changed-only --summary <extra…>`, where `extra` is every token in `rest[1:]` that is *not* `--online-only`, `--changed-only`, or `--summary` (those three are always force-added and de-duplicated by exclusion, not by the shell). So a user-supplied `--changed-only` is silently absorbed into the fixed set; genuinely extra flags like `-o /custom/dir`, `--redact-secrets`, `--include-offline`, `-t/--threads N` pass straight through to `netops-control`.
- **Arguments:** `target` (required) — same fuzzy resolution as elsewhere, but here `resolve_targets` is called with `allow_multiple=true` (from the general `netops-control` argument path), so a prefix/site token that matches many devices fans out to all of them, running in parallel bounded by `${CONFIG[scan_workers]}` (default worker count; overridable with `-t/--threads`). Missing target → `usage_error("backup","run",...)`, `USAGE`, suggestion `netrune backup run ZONE34`.
- **Preconditions / gating:** No `--confirm` required (this is intentionally a read-from-network/write-locally action, not a device-mutating one). `--online-only` is always forced, so devices whose `devices.status` is `OFFLINE` are skipped automatically by `filter_offline_targets()` in `netops-control` (this filtering is skipped entirely if the target names exactly one device — a single explicit target is always attempted even if marked offline). `get_password_from_store` is called before any SSH connection is opened — this is the point where the vault/named-secret layer is touched (see Cross-cutting notes).
- **Step-by-step behavior:** For each resolved online target, in `netops-control`'s `perform_task`/backup branch: (1) SSH in and capture `show running-config` (sanitized via `sanitize_output`); (2) optionally redact secret-looking lines if `--redact-secrets` was passed (`control_redact_config`, a `sed` pass over password/secret/key-string/community/PSK lines); (3) SHA-256 the cleaned text; (4) look up the latest `saved` backup for that IP via `control_backup_latest_record`; (5) if `--changed-only` (always on here) and the new hash matches the latest saved hash, skip the write and record a `backup_history` row with `status='unchanged', changed=0`; (6) otherwise write the config atomically (`mktemp` in the day-stamped directory → `chmod 600` → `mv`) to `<default_backup_dir>/<YYYY-MM-DD>/<safe-hostname>.conf`, refresh a `<safe-hostname>.latest.conf` symlink, and record a `backup_history` row with `status='saved', changed=1`. If `--summary` (always on) is set, after all devices finish it prints a per-status/changed count summary (`control_backup_summary`, grouped `SELECT status,changed,COUNT(*) ...`).
- **Side effects:** Writes one `.conf` file per changed device under `${DATA_DIR}/backups/<date>/` (default backup dir; overridable with `-o`) plus a refreshed `.latest.conf` symlink; inserts one row per device into the `backup_history` SQLite table (written directly via the `sqlite3` CLI from the bash helper — **not** through `State.record_audit_event`, so `backup run` never produces an `audit_events` row). Touches the vault/named-secret layer once per process invocation via `get_password_from_store` (see Cross-cutting notes) — not once per device, since the password is fetched once up front.
- **Output shape, table mode:** Plain colorized bash log lines (`[ip] Backup saved to <path>` / `[ip] Backup unchanged; skipped write.`) plus the `--summary` block; not a Netrune `render_table`.
- **Output shape, --json mode:** **No effect** — `run_subprocess` passthrough again, same caveat as `backup diff`/`backup history`.
- **Exit codes:** `SUCCESS` if every attempted device succeeded; nonzero (`overall_rc=1` inside the bash loop, surfaced as the subprocess's exit code) if any device was skipped for an unsupported platform or failed; `USAGE` for a missing target.
- **Real example:**
  ```
  $ netrune backup run ZONE34.
  Attempting to connect to ZONE34-CORE (198.51.100.34)...
  [198.51.100.34] Backup saved to ~/.local/share/netrune/backups/2026-08-28/ZONE34-CORE.conf
  [198.51.100.35] Backup unchanged; skipped write.
  backup saved changed=1: 1
  backup unchanged changed=0: 1
  Operation completed.
  ```
- **Related commands:** `netrune vault unlock` first if backing up many devices, to avoid one sudo/Windows-Hello prompt per device (though `backup run` fetches the password once per process anyway, not per device, so this mostly helps when chaining several separate `backup run` invocations). `netrune vlan set <target> ... --confirm` internally calls the exact same `netops-control backup <ip> --online-only --changed-only --summary` command as its own "backup" phase (see `apply_vlan_change` in `netops_platform/vlan_cli.py`) — running `netrune backup run` manually beforehand is a redundant-but-harmless extra safety net, not a requirement, since the guarded VLAN lifecycle (ADR 0005) already performs preflight + backup + apply + verify on its own.

#### `netrune backup verify` (id: `backup-verify`)
- **Purpose:** Review recorded backup checksums, paths, and statuses across all devices from Netrune's own SQLite view (not the bash helper).
- **Exact syntax:** `netrune backup verify` (no arguments). Implemented natively in `App.cmd_backup`'s `verb=="verify"` branch — this is the one `backup` verb that does **not** shell out.
- **Arguments:** None. Respects the global `--limit` option (default 100).
- **Preconditions / gating:** None; pure read.
- **Step-by-step behavior:** `self.state.rows("SELECT * FROM backup_history ORDER BY created_at DESC,id DESC LIMIT ?",(opts.limit,))` — reads the same `backup_history` table that `netops-control` writes into directly via raw `sqlite3` calls, so this correctly reflects backups taken outside of a `netrune backup run` invocation too (e.g. from a cron job calling `netops-control backup` directly).
- **Side effects:** None.
- **Output shape, table mode:** `self.render_table(rows, ["created_at","device_ip","hostname","status","changed","sha256","path","message"])` — a real Netrune Rich table this time (unlike the other three `backup` verbs).
- **Output shape, --json mode:** `{"ok": true, "rows": [<full backup_history rows: id, created_at, device_ip, hostname, path, sha256, changed, size_bytes, status, message>]}` — this one *does* honor `--json` correctly since it goes through `App.emit`.
- **Exit codes:** Always `SUCCESS`, even with zero rows (table renders "No records.").
- **Real example:**
  ```
  $ netrune backup verify --limit 5
  CREATED_AT           DEVICE_IP    HOSTNAME       STATUS   CHANGED SHA256        PATH                                          MESSAGE
  2026-08-28 09:12:01  198.51.100.34   ZONE34-CORE    saved    1       a1b2c3d4e5f6  ~/.../backups/2026-08-28/ZONE34-CORE.conf running-config captured
  ```
- **Related commands:** `netrune backup history <target>` for a single-device deep-dive; `netrune backup diff <target>` to see the actual content delta implied by `changed=1` rows here.

---

### config domain

#### `netrune config get <key>` (id: `config-get`)
- **Purpose:** Read one effective (already layered: CLI → environment → active profile → global config → neutral defaults) non-secret configuration value.
- **Exact syntax:** `netrune config get <key>`.
- **Arguments:** `key` (required). Validated against `self.config.public` (the *unredacted* effective dict) — must already be a known key. Unknown key → `usage_error("config","get",...)`, `VALIDATION`, message `Unknown configuration key: <key>`, suggestion `netrune config show`. Missing key argument → `usage_error(...)`, `VALIDATION`, message "Missing key.", suggestion `netrune config get core_switch_ip`.
- **Preconditions / gating:** None.
- **Step-by-step behavior:** Looks the key up in `self.config.public_safe()` (the redacted view) so that even a valid *known* key whose name matches the secret pattern (see below) prints `"configured"`/`"missing"` rather than a real value.
- **Side effects:** None.
- **Output shape, table mode:** Not a table — `output_type: text`; prints just the value (`str(...)`), nothing else.
- **Output shape, --json mode:** `{"ok": true, "key": "<key>", "value": "<redacted-or-real value>"}`.
- **Exit codes:** `SUCCESS`; `VALIDATION` for missing/unknown key.
- **Real example:**
  ```
  $ netrune config get core_switch_ip
  192.0.2.10
  ```
- **Related commands:** `netrune config show` to see everything at once; `netrune config validate` to check whether the currently-set values are actually well-formed.

#### `netrune config paths` (id: `config-paths`)
- **Purpose:** Show the three on-disk configuration file locations Netrune reads/writes.
- **Exact syntax:** `netrune config paths` (also accepts the alias `netrune config path`, since `cmd_config` matches `verb in {"path","paths"}`).
- **Arguments:** None.
- **Preconditions / gating:** None.
- **Step-by-step behavior:** Returns three fixed paths computed from `self.paths`: the global config file (`config_root/config.toml`), the active profile's TOML file (`self.paths.profile_file`), and the legacy key=value compatibility file (`self.paths.config_file`).
- **Side effects:** None.
- **Output shape, table mode:** Not `render_table` — plain `key: value` lines (`global: …`, `profile: …`, `compatibility: …`), even though the registry lists `output_type: table`.
- **Output shape, --json mode:** `{"ok": true, "global": "<path>", "profile": "<path>", "compatibility": "<path>"}`.
- **Exit codes:** Always `SUCCESS`.
- **Related commands:** `netrune profile paths` (a different, broader command covering the full per-profile XDG layout — config, state, cache, data dirs — not just these three config files).

#### `netrune config set <key> <value>` (id: `config-set`)
- **Purpose:** Write one non-secret override into the active profile's compatibility config file (`self.paths.config_file`) and update the in-memory config immediately.
- **Exact syntax:** `netrune config set <key> <value...>` — everything after the key is rejoined with a single space (`" ".join(rest[1:])`), so a multi-word value does not need quoting the way the registry's `netrune config set '<key>' '<value>'` template implies, though quoting is still recommended for values containing shell-special characters.
- **Arguments:** `key`, `value` (both required; fewer than two remaining tokens → `usage_error("config","set",...)`, `VALIDATION`, "Provide a key and value.", suggestion `netrune config set core_switch_ip 192.0.2.10`). Validated inside `App._write_profile_config_value`, which is called with **no surrounding try/except** in `cmd_config`:
  - Key must match `r"[a-z][a-z0-9_]{1,63}"` (lowercase start, lowercase/digits/underscore, 2–64 chars total) or a `ValueError("configuration keys use lowercase letters, digits, and underscores")` is raised.
  - Key must **not** match `SECRET_KEY_RE` = `r"(password|passwd|secret|credential|community|token|key|snmpv3_.*pass|sshpass)"` (case-insensitive) or a `ValueError("secret values must be stored with 'netrune secrets set'")` is raised. This is broad — it also blocks innocuous-sounding keys like `ssh_key_path` or `api_key_hint` purely because they contain the substring "key".
  - Value must not contain `\r`, `\n`, or `\x00` or a `ValueError("configuration values cannot contain control lines")` is raised.
  Because none of these are caught locally, a rejected key/value does **not** produce the tool's usual friendly `usage_error` output — it propagates all the way up to `App.dispatch`'s outer `except Exception`, which returns exit code `INTERNAL` (10) and prints `Error: <message>` (or, with `--json`, `{"ok": false, "error": "<message>", "exit_code": 10}`) instead of the normal `VALIDATION` (6) usage-error shape. This is worth knowing precisely: a bad `config set` call exits 10, not 6, and skips the usage/suggestion/examples block entirely.
- **Preconditions / gating:** No `--confirm` needed — despite writing to disk, this is treated as an always-immediate local-write. (Registry note: the pre-extracted JSON labels `config-set` as `"read_only": true` even though `"writes_local": true` and `"safety_class": "local-write"` — that combination is self-contradictory registry metadata; the actual code unconditionally writes to `self.paths.config_file` with no read-only mode.)
- **Step-by-step behavior:** `_write_profile_config_value` reads the current key=value file via `read_kv`, sets/overwrites the key, re-serializes all keys sorted alphabetically with a `# Netrune profile compatibility configuration` header, writes to a PID-suffixed temp file (`.{filename}.{pid}.tmp`), `chmod 600`s it, then atomically `os.replace`s it over the real file. It also updates `self.config.public[key]` in the same process so a script that does `config set` then immediately acts on the new value in the same invocation sees it.
- **Side effects:** One file write (atomic replace) to `self.paths.config_file`; updates the in-process `Config.public` dict. No SQLite write, no audit event (config domain never calls `State.record_audit_event`).
- **Output shape, table mode:** Not a table — `output_type: log`; prints `Updated <key> in profile <profile>.`
- **Output shape, --json mode:** `{"ok": true, "profile": "<profile>", "key": "<key>", "updated": true}`.
- **Exit codes:** `SUCCESS`; `VALIDATION` (missing args); `INTERNAL` (10) for any key/value validation failure (see above, an important deviation from the tool's normal validation-error convention).
- **Real example:**
  ```
  $ netrune config set core_switch_ip 192.0.2.10
  Updated core_switch_ip in profile default.
  ```
- **Related commands:** `netrune config unset` to remove the override; `netrune config validate` to sanity-check the result; `netrune secrets set` for anything that would be rejected as secret-shaped.

#### `netrune config show` (id: `config-show`)
- **Purpose:** Show every effective setting, redacted, with the precedence order that produced it.
- **Exact syntax:** `netrune config show` — also the default verb when `netrune config` is called with no subcommand at all (`verb = args[0] if args else "show"`).
- **Arguments:** None.
- **Preconditions / gating:** None.
- **Step-by-step behavior:** Builds `self.config.public_safe()` — every key in `self.config.public` and `self.config.secret` (the legacy `.env` values), with any key matching `SECRET_KEY_RE` (except the literal exception `ssh_host_key_mode`, which is allowed through even though it contains "key") replaced with the literal string `"configured"` (or `"missing"` if the legacy `.env` key is empty/absent). Non-secret keys show their real value.
- **Side effects:** None.
- **Output shape, table mode:** `f"Profile: {profile}\n"` followed by `self.render_table([{"key":k,"value":v} for k,v in sorted(settings.items())], ["key","value"])`.
- **Output shape, --json mode:** `{"ok": true, "profile": "<profile>", "precedence": ["CLI","environment","active profile","global config","neutral defaults"], "settings": {<redacted key/value map>}, "profile_file": "<path>", "compatibility_file": "<path>"}`.
- **Exit codes:** Always `SUCCESS`.
- **Related commands:** `netrune config get <key>` for one value only; `netrune config validate` for correctness checks (this command never validates anything, just displays).

#### `netrune config unset <key>` (id: `config-unset`)
- **Purpose:** Remove one profile-level override, falling back to whatever the global config or neutral defaults specify.
- **Exact syntax:** `netrune config unset <key>`.
- **Arguments:** `key` (required; missing → `usage_error("config","unset",...)`, `VALIDATION`, "Missing key.", suggestion `netrune config unset target_abbreviation_prefix`). Goes through the exact same `_write_profile_config_value(key, None)` validation path as `config set` (key-format regex; the secret-key-name check is moot here since `value=None` skips that branch's relevance, but the key-format regex still applies) — same **uncaught-`ValueError`→`INTERNAL`(10)** behavior on a malformed key.
- **Preconditions / gating:** None.
- **Step-by-step behavior:** Same file as `config set`: reads the key=value file, pops the key if present, rewrites atomically. Also pops `self.config.public[key]` from memory if present — note this does **not** restore any lower-precedence default into `self.config.public` for the rest of the process; it removes the override outright, so subsequent reads within the same process fall through to whatever `_resolved_public` computed at startup minus this key (effectively empty unless a global/neutral default is separately layered by a later call).
- **Side effects:** One atomic file write; in-memory dict pop. No SQLite write, no audit event.
- **Output shape, table mode:** `output_type: log`; prints `Removed profile override: <key>`.
- **Output shape, --json mode:** `{"ok": true, "profile": "<profile>", "key": "<key>", "removed": true}`.
- **Exit codes:** `SUCCESS`; `VALIDATION` (missing key); `INTERNAL` (10) for malformed key.
- **Related commands:** `netrune config set` (inverse); `netrune config show` to confirm the value reverted.

#### `netrune config validate` (id: `config-validate`)
- **Purpose:** Check the currently effective settings for structural correctness and flag legacy plaintext-secret leftovers.
- **Exact syntax:** `netrune config validate` (no arguments accepted beyond the verb).
- **Arguments:** None.
- **Preconditions / gating:** None.
- **Step-by-step behavior:** Three independent checks, each appending a finding dict `{"severity","key","detail"}` to a list:
  1. `target_abbreviation_prefix`: if set and non-empty (after stripping leading/trailing dots), must parse as 1–3 dot-separated integers each in `[0,255]`; otherwise `severity: "error"`, detail "must contain one to three IPv4 octets".
  2. Legacy `.env` file (`self.paths.env_file`): if it exists **and** `read_kv` on it returns any keys, `severity: "warning"`, detail "plaintext legacy credentials remain; migrate them to named secrets".
  3. `ssh_user`: read from `self.config.public` or `self.config.secret`; if empty, `severity: "warning"`, detail "required for device SSH; set with 'netrune config set ssh_user <username>'"; if non-empty but fails `valid_ssh_username` (must be 1–255 chars, no whitespace), `severity: "error"`.
- **Side effects:** None (pure read of config + `.env` presence).
- **Output shape, table mode:** `self.render_table(findings, ["severity","key","detail"])` if any findings exist, else the plain string `"Configuration is valid."`.
- **Output shape, --json mode:** `{"ok": <true iff no severity=="error" finding>, "profile": "<profile>", "findings": [<the finding dicts>]}`.
- **Exit codes:** `SUCCESS` if `ok` is true (no error-severity findings — warnings alone still return `SUCCESS`); `VALIDATION` (6) if any finding has `severity: "error"`.
- **Real example:**
  ```
  $ netrune config validate
  SEVERITY  KEY        DETAIL
  warning   ssh_user   required for device SSH; set with 'netrune config set ssh_user <username>'
  ```
- **Related commands:** `netrune init` (also checks tool availability, a superset concern); `netrune secrets import-ssh` / `netrune vault migrate` to resolve the legacy-`.env` warning.

---

### db domain

Every `db` verb is implemented directly in `App.cmd_db`, calling into methods on the `State` class (also in `core.py`). None of the `db` verbs ever call `State.record_audit_event` — the entire `db` domain is unaudited, even though it controls the retention of every other domain's audit trail.

#### `netrune db history` (id: `db-history`)
- **Purpose:** Show recorded command executions with their exit codes.
- **Exact syntax:** `netrune db history`.
- **Arguments:** None; respects `--limit` (default 100).
- **Preconditions / gating:** None.
- **Step-by-step behavior:** `SELECT created_at,action,command,exit_code,read_only FROM command_history ORDER BY created_at DESC,id DESC LIMIT ?`.
- **Important verified finding:** searching the entire codebase (`core.py`, every `*_cli.py`, every shell helper) turns up **no code path that ever inserts into `command_history`** in normal operation. The only `INSERT INTO command_history` in the repository is a direct SQL statement inside the retention test (`tests/test_netops_core.py`), used purely to exercise `prune_history`'s retention logic. In practice this means `netrune db history` will almost always show "No records." on a real install — the table and its reader exist, but nothing currently populates it.
- **Side effects:** None.
- **Output shape, table mode:** `self.render_table(timestamp_rows(rows), ["created_at","action","exit_code","read_only","command"])` — note the column order puts `command` last even though the SQL selects it third.
- **Output shape, --json mode:** `{"ok": true, "rows": [<created_at, action, command, exit_code, read_only>], "count": <n>}`. Note `ok` is always `true` in the JSON body even when the process exit code below is not.
- **Exit codes:** `SUCCESS` if `rows` is non-empty; `PARTIAL` (3) if empty — which, per the finding above, is the common case in this build.
- **Related commands:** `netrune db status` for a live row-count summary that would confirm `command_history` is empty; `netrune audit`-style review is instead done through the `audit_events` table, which is populated (by `vault set/migrate/unlock/lock` and `secrets delete` — see Cross-cutting notes) but has no dedicated `db` reader command in this domain.

#### `netrune db integrity` (id: `db-integrity`)
- **Purpose:** Run SQLite's built-in integrity checks without modifying anything.
- **Exact syntax:** `netrune db integrity`.
- **Arguments:** None.
- **Preconditions / gating:** None.
- **Step-by-step behavior:** `State.integrity_check()` runs `PRAGMA integrity_check` and `PRAGMA quick_check` on a fresh connection and returns `ok` true only if both return exactly `["ok"]`.
- **Side effects:** None (both pragmas are read-only checks).
- **Output shape, table mode:** Not a table — single line: `"SQLite integrity: ok"` or `"SQLite integrity: failed: <comma-joined integrity_check messages>"`.
- **Output shape, --json mode:** `{"ok": bool, "integrity_check": [...], "quick_check": [...]}`.
- **Exit codes:** `SUCCESS` if `ok`; `INTERNAL` (10) if the integrity check fails.
- **Related commands:** `netrune db repair` runs this same check as its final step, after attempting a repair; `netrune db vacuum` if the file is just bloated rather than actually corrupt.

#### `netrune db migrate` (id: `db-migrate`)
- **Purpose:** (Re-)apply the SQLite schema (idempotently) and reconcile derived state (health/topology/relationships) from canonical inventory.
- **Exact syntax:** `netrune db migrate` (also reachable as `netrune db init`, since `cmd_db` matches `verb in {"init","migrate"}`).
- **Arguments:** None.
- **Preconditions / gating:** None.
- **Step-by-step behavior:** `State.migrate()` calls `init_db()` again (re-runs the full `SCHEMA` script — all `CREATE TABLE IF NOT EXISTS`/`CREATE INDEX IF NOT EXISTS` statements, plus `ALTER TABLE ... ADD COLUMN` shims for columns introduced by newer releases on `traffic_watch` and the pre-v7 `jobs`/`job_logs` tables, plus a de-duplication pass on `traffic_samples`), then runs `_sanitize_invalid_mac_identities()` (scrubs parser-placeholder or malformed MAC values out of `devices`, `aps`, `inventory_identity_state`, `inventory_history`, `relationships_current`, `relationship_events`), then bumps the `schema_meta` row for `schema_version` to the current `SCHEMA_VERSION` (`"13"`). `cmd_db` then separately calls `self.state.sync_derived_state(origin="migration")` (recomputes `health_state`/`topology_snapshot`/`relationships_current` from canonical `devices`/`aps`/`neighbors`, applying any pending manual `inventory_merges`; because `origin="migration"`, any *new* rows written to the five structural event-log tables — `inventory_history`, `health_events`, `topology_events`, `ap_move_events`, `relationship_events` — above each table's pre-call high-water mark are deleted again immediately afterward, so that re-running migrate never spams the event history with synthetic "everything changed" entries) and `self.state.counts()`.
- **Side effects:** Potentially many schema-level `ALTER TABLE`/`CREATE` statements (all idempotent no-ops on an up-to-date DB); rows written and then possibly deleted again in the five event-log tables (net effect on a healthy DB: none); a `scan_runs` row logging the MAC-identity cleanup only if it actually changed anything; a `settings` row `invalid_mac_identity_v1` recording what was cleaned, again only if something changed.
- **Output shape, table mode:** Not a table — `f"SQLite ready: {sqlite_db_path} (schema {schema_version})"`.
- **Output shape, --json mode:** `{"ok": true, "schema_version": "...", "db_path": "...", "mac_identity_cleanup": {"changed": N, "counts": {...}}, "reconciliation": {"origin": "migration", "timestamp": ..., "manual_merges": {...}, "suppressed_structural_events": {...}}, "counts": {<the full counts() dict>}}`.
- **Exit codes:** Always `SUCCESS` in the visible code path (exceptions bubble to `INTERNAL` via `dispatch`).
- **Related commands:** `netrune db repair` runs this as its first internal step; `netrune profile create`/`netrune init` implicitly rely on the schema already being current.

#### `netrune db path` (id: `db-path`)
- **Purpose:** Print the active SQLite database file path.
- **Exact syntax:** `netrune db path`.
- **Arguments:** None.
- **Preconditions / gating:** None.
- **Step-by-step behavior:** `print(self.paths.sqlite_db)` — this is a bare Python `print()`, **not** routed through `App.emit`.
- **Important verified finding:** because it's a raw `print`, `--json` has **zero effect** — `netrune db path --json` prints exactly the same plain path string, not a JSON envelope. This differs from `config paths`/`db status`, which do honor `--json` correctly.
- **Side effects:** None.
- **Output shape, table mode:** Bare path string, e.g. `~/.local/state/netrune/netrune.sqlite3` (default is `state_dir/netrune.sqlite3`, overridable with `NETRUNE_SQLITE_DB`/`NETOPS_SQLITE_DB`).
- **Output shape, --json mode:** Same bare path string (no JSON, see above).
- **Exit codes:** Always `SUCCESS`.
- **Related commands:** `netrune db status` for size/schema/row-count context around this same file; note `netops-control`'s own `control_sqlite_db()` shell function falls back to `${CACHE_DIR}/netrune.sqlite3` (a *different* default directory than Python's `state_dir` default) only when invoked standalone without `NETRUNE_SQLITE_DB`/`NETOPS_SQLITE_DB` set — in normal operation `App.child_env` (via `profile_environment` in `netops_platform/profiles.py`) always exports `NETRUNE_SQLITE_DB` pointing at the same `state_dir/netrune.sqlite3` path, so `backup_history` writes from `netops-control` and reads from `db status`/`backup verify` stay consistent.

#### `netrune db prune` (id: `db-prune`)
- **Purpose:** Delete operational/diagnostic history rows older than each table's retention window. Never touches audit or provenance data.
- **Exact syntax:** `netrune db prune` (no arguments; per-table windows are configured separately via `netrune config set <table>_retention_days <N>`, or `netrune config set traffic_retention_days <N>` for the two `traffic_*`-prefixed tables).
- **Arguments:** None on the CLI itself.
- **Preconditions / gating:** None — runs immediately, no `--confirm`.
- **Step-by-step behavior:** `State.prune_history()`:
  1. Starts from `RETENTION_DEFAULTS` (see full table below), then for every table calls `self.retention_days(table, configured)` where `configured = self.state.retention_settings` (set once, at `App.__init__` time, to `self.config.public` — so a user override via `netrune config set <table>_retention_days N` *is* honored during a live `netrune db prune` invocation, clamped to `[1, 3650]` days; an invalid/unparsable override silently falls back to the hardcoded default).
  2. For each table with a resolved retention `> 0` days, computes `cutoff = now() - days*86400` and runs `DELETE FROM <table> WHERE <timestamp_column> < ?`. The timestamp column defaults to `created_at` except for five tables with a different name: `path_runs`→`started_at`, `traffic_samples`→`observed_at`, `traffic_counter_log`→`observed_at`, `scan_runs`→`started_at`, `ingest_runs`→`started_at`, `observation_rejects`→`received_at`.
  3. Additionally deletes orphaned children of `path_runs` — any `path_hops`/`path_findings` row whose `run_id` no longer exists in `path_runs` (a belt-and-suspenders cleanup; both child tables already have `ON DELETE CASCADE` foreign keys to `path_runs`, and `connect()` sets `PRAGMA foreign_keys=ON`, so this mostly catches rows that predate the foreign-key constraint or connections where the pragma wasn't honored).
  4. A table whose `DELETE` raises `sqlite3.OperationalError` (table doesn't exist yet on a very old DB) is silently skipped, not fatal.

  **Complete current `RETENTION_DEFAULTS` table** (expanded this session from roughly 8 entries to 20; source: `State.RETENTION_DEFAULTS` in `core.py`):

  | Table | Retention (days) | Notes |
  |---|---|---|
  | `topology_events` | 90 | |
  | `ap_move_events` | 90 | |
  | `probe_results` | 30 | |
  | `job_logs` | 14 | |
  | `core_lookup_cache` | 7 | |
  | `path_runs` | 90 | children `path_hops`/`path_findings` follow via cascade/orphan cleanup, not their own age |
  | `traffic_samples` | 180 | deliberately generous — a link that saturates only at month-end needs more than a month of history to show it; cheap per-row so the window is affordable; override with `traffic_retention_days` |
  | `traffic_counter_log` | 7 | raw polling-resolution counters, kept only long enough to let a disconnected collector replay what it missed, not to be a history |
  | `command_history` | 90 | (see `db-history` finding above: currently unpopulated in practice) |
  | `backup_history` | 365 | |
  | `speed_tests` | 90 | |
  | `interface_samples` | 30 | |
  | `filtering_checks` | 30 | |
  | `diagnostic_runs` | 90 | |
  | `health_events` | 180 | |
  | `inventory_history` | 365 | |
  | `relationship_events` | 180 | |
  | `scan_runs` | 90 | |
  | `ingest_runs` | 90 | |
  | `observation_rejects` | 30 | a debugging aid for the ingest channel that produced the rejects, not evidence |

  **Tables that are never in `RETENTION_DEFAULTS` and are therefore never pruned by this command, by design:** `audit_events` (a privileged-operation record that could expire is not an audit trail — explicitly called out in `State.prune_history`'s own docstring), `observations` and `observation_fields` (the append-only provenance trail described by ADR 0002 and `architecture-v8.md`; erasing it on a timer would contradict its purpose), `inventory_merges` (the record of manual device-identity merges, which must persist so a merge can later be explained or reversed), and `relationships_current` (the *current-state* table, not history — it's overwritten by reconciliation, not aged out). Also never pruned, though not called out in the task's list: the `jobs` table itself (distinct from `job_logs`, which *is* pruned at 14 days) and `settings`/`schema_meta`.
- **Side effects:** Row deletions across up to 22 tables (20 by direct retention + 2 path children). No file writes, no audit event.
- **Output shape, table mode:** `self.render_table([{"table":k,"rows_removed":v} for k,v in sorted(removed.items())], ["table","rows_removed"])`, prefixed with `f"Pruned {total} row(s) past retention."`, or the plain string `"Nothing past retention. Audit events are never pruned."` if `removed` is empty.
- **Output shape, --json mode:** `{"ok": true, "removed": {<table: rows_removed, only tables that actually had deletions>}, "rows_removed": <sum>, "retention_days": <RETENTION_DEFAULTS, the static defaults dict>}`. **Caveat:** the `retention_days` key in the JSON payload always reports the hardcoded `RETENTION_DEFAULTS`, not the effective (possibly config-overridden) windows actually used for that run's cutoffs — if an operator has set `netrune config set backup_history_retention_days 30`, the prune still uses 30 days internally but the JSON payload's `retention_days.backup_history` still shows `365`. Don't trust this field to reflect what actually happened; cross-check against `netrune config show`.
- **Exit codes:** Always `SUCCESS`.
- **Real example:**
  ```
  $ netrune db prune
  Pruned 143 row(s) past retention.
  TABLE               ROWS_REMOVED
  probe_results        88
  interface_samples    41
  filtering_checks     14
  ```
- **Related commands:** `netrune db repair` calls this as its final step automatically; `netrune db vacuum` afterward to reclaim the freed disk space (prune alone does not shrink the file).

#### `netrune db repair` (id: `db-repair`)
- **Purpose:** Run a full maintenance bundle — re-migrate, checkpoint/analyze, reconcile derived state, verify integrity, and prune history — in one call.
- **Exact syntax:** `netrune db repair` (no arguments).
- **Arguments:** None.
- **Preconditions / gating:** None.
- **Step-by-step behavior — the full bundle, in exact order** (verified against `State.repair()` plus `cmd_db`'s `verb=="repair"` branch, which adds one more step on top):
  1. **Migrate:** `self.migrate()` — same as `netrune db migrate` above (re-run schema script, sanitize invalid MAC identities, bump `schema_meta`).
  2. **Checkpoint + analyze (not a full reindex, not a full vacuum despite the registry's description saying "Reindex and repair"):** `PRAGMA wal_checkpoint(TRUNCATE)`, then `ANALYZE`, then `PRAGMA optimize`. There is no `REINDEX` statement anywhere in this path, and no `VACUUM` — that's reserved for the separate `db vacuum` command. The registry's description text ("Reindex and repair recoverable SQLite structures, then verify integrity") is imprecise about the actual pragmas run; the real effect is refreshed query-planner statistics and a WAL checkpoint, not a structural reindex/rebuild.
  3. **Reconcile:** `self.sync_derived_state(origin="migration")` — same suppression-of-synthetic-events behavior as in `db migrate`.
  4. **Verify:** `self.integrity_check()` — `PRAGMA integrity_check` + `PRAGMA quick_check`, becomes the base of the returned payload.
  5. **Prune** (this step lives in `cmd_db`, not in `State.repair()` itself): `self.state.prune_history()`, attached to the payload under the key `pruned`.
- **Side effects:** Everything listed under `db migrate` and `db prune` combined, plus the checkpoint/analyze pragmas. No audit event.
- **Output shape, table mode:** Not a table — `"SQLite repair complete: ok"` or `"SQLite repair complete: integrity check failed"`.
- **Output shape, --json mode:** Top-level keys: `ok`, `integrity_check` (list), `quick_check` (list), `schema_version`, `counts` (the full `counts()` dict), `db_path`, `reconciliation` (the `sync_derived_state` payload), `migration` (the `migrate()` payload), `pruned` (the `prune_history()` removed-rows dict).
- **Exit codes:** `SUCCESS` if the final integrity check passes; `INTERNAL` (10) if it fails (in which case the schema/reconciliation/prune steps still ran — this is not transactional across the whole bundle).
- **Related commands:** `netrune db integrity` alone if you just want the check without the side effects; `netrune db vacuum` afterward for actual file-size compaction, which `repair` does not do.

#### `netrune db status` (id: `db-status`)
- **Purpose:** Show database path, schema version, cache directory, applied-migration markers, row counts, and file sizes.
- **Exact syntax:** `netrune db status` (also the default verb: `verb = args[0] if args else "status"`).
- **Arguments:** None.
- **Preconditions / gating:** None.
- **Step-by-step behavior:** `State.db_status_payload()` reads `schema_version()`, the last 20 rows of the `settings` table (used as "applied migrations" markers — anything with `updated_at`, most recently updated first — this is a slightly loose proxy since `settings` also holds non-migration keys, but currently the main such key is `invalid_mac_identity_v1`), `self.counts()`, and file sizes for the main DB file plus its `-wal`/`-shm` sidecar files (0 if a sidecar doesn't currently exist, e.g. right after a checkpoint).
- **`counts()` field list** (from `State.counts()`): `devices`, `neighbors`, `offline_devices`, `relationships` (excludes `status='disappeared'`), `relationship_events`, `running_jobs`, `partial_jobs`, `failed_jobs` (all three job counts will read 0 in this build, since the `jobs` domain and its writer were removed but the empty `jobs` table and this query remain), `backups` (row count of `backup_history`), `diagnostic_runs`, `audit_events`, `manual_merges` (active, non-revoked `inventory_merges`), `aps` (canonical/reconciled count via `reconcile_ap_rows`), `offline_aps`, `ap_observations` (raw pre-reconciliation row count), `ap_alias_records` (difference between raw and canonical AP counts).
- **Side effects:** None.
- **Output shape, table mode:** Not `render_table` — a flat list of `label: value` lines: `SQLite: <path>`, `Schema: <version> (expected <version>)`, `Cache: <cache_dir>`, `Applied migrations: <count>`, then one line per `counts()` entry, then `sqlite_bytes: <n>` and `wal_bytes: <n>`.
- **Output shape, --json mode:** `{"ok": true, "db_path": "...", "cache_dir": "...", "schema_version": "...", "expected_schema_version": "13", "applied_migrations": [{"key","applied_at","applied_at_iso"}...], "counts": {...}, "files": {"sqlite_bytes","wal_bytes","shm_bytes"}}`.
- **Exit codes:** Always `SUCCESS`.
- **Related commands:** `netrune db integrity` for an actual correctness verdict (status only reports sizes/counts, it does not validate); `netrune support bundle` embeds a redacted subset of this same payload (`ok`, `schema_version`, `expected_schema_version`, `counts`, `files`) as `database.json` inside the bundle.

#### `netrune db vacuum` (id: `db-vacuum`)
- **Purpose:** Compact the SQLite file, reclaiming space freed by prior deletes.
- **Exact syntax:** `netrune db vacuum`.
- **Arguments:** None.
- **Preconditions / gating:** None.
- **Step-by-step behavior:** `State.vacuum()`: `PRAGMA wal_checkpoint(TRUNCATE)` → `VACUUM` → `PRAGMA optimize`.
- **Side effects:** Rewrites the entire SQLite file (can be slow/IO-heavy on a large DB); truncates the WAL file.
- **Output shape, table mode:** Not a table — `f"SQLite vacuum complete: {bytes} bytes"` (the new file size after vacuuming).
- **Output shape, --json mode:** `{"ok": true, "db_path": "...", "bytes": <int>}`.
- **Exit codes:** Always `SUCCESS` in the visible path.
- **Related commands:** `netrune db prune` first, so vacuum has something to reclaim; `netrune db repair`, which does *not* itself vacuum, only checkpoints/analyzes — running `db vacuum` after `db repair` is the way to actually shrink the file.

---

### secrets domain

`cmd_secrets` is a thin Python dispatcher over `netrune-connect --secret-*`, which in turn calls the `named_secret_*` functions in `netops-lib.sh`. Named secrets are stored together in one GPG-encrypted blob (`SECRETS_FILE`, default `${DATA_DIR}/secrets.gpg`), keyed by base64-encoded name inside the decrypted payload, with a separate plaintext-but-permission-restricted metadata index (`SECRETS_META_FILE`, default `${STATE_DIR}/secrets.meta`, lines of `base64(name)|recorded_at_epoch`) that records *when* each secret was last set, without ever needing to decrypt the blob just to answer "does this exist and when was it recorded."

#### `netrune secrets list` (id: `secrets-list`)
- **Purpose:** List every named secret's name and recording time, without ever decrypting values.
- **Exact syntax:** `netrune secrets list`.
- **Arguments:** None.
- **Preconditions / gating:** None — reading the metadata index requires no vault authentication at all (it's not GPG-encrypted).
- **Step-by-step behavior:** `cmd_secrets` maps `"list"` to `[helper, "--secret-list"]` and calls `run_subprocess`. `named_secret_list()` in `netops-lib.sh` prints a header `NAME|RECORDED` then, for every line in `SECRETS_META_FILE`, base64-decodes the name and converts the recorded epoch to `"never"` or an ISO-8601 UTC string via `_vault_iso_time`.
- **Side effects:** None.
- **Output shape, table mode:** **Not `render_table`.** This is raw pipe-delimited text streamed straight from the bash helper: `NAME|RECORDED` header, then `<name>|<iso-or-never>` per secret — unaligned, unpadded, unlike every genuine Netrune table.
- **Output shape, --json mode:** **No effect.** `run_subprocess` passthrough — `--json` is never forwarded to the helper and the helper has no JSON mode for this action, so `netrune secrets list --json` produces the identical pipe-delimited text.
- **Exit codes:** `SUCCESS` (0) normally.
- **Real example:**
  ```
  $ netrune secrets list
  NAME|RECORDED
  ssh/default/password|2026-08-15T10:03:22Z
  snmp/site-a/auth|never
  ```
- **Related commands:** `netrune secrets status` for the store's security posture; `netrune secrets set <name>` to add one.

#### `netrune secrets status` (id: `secrets-status`)
- **Purpose:** Show the named-secret store's format, permissions, count, and sudo/lock state.
- **Exact syntax:** `netrune secrets status`.
- **Arguments:** None.
- **Preconditions / gating:** None; does not prompt.
- **Step-by-step behavior:** Maps to `[helper, "--secret-status"]` → `named_secret_status()`: if `SECRETS_FILE` exists, `mode="sudo-gpg-v1"`, reads its octal permission bits and counts metadata rows (`awk` count of well-formed `name|epoch` lines). Then, without prompting (`sudo -n -v`, non-interactive), checks whether the sudo session is already unlocked and, if so, whether the root-owned vault key file passes `_sudo_vault_key_is_secure` (ownership/mode/parent-directory checks) — `key_state` becomes `available` or `missing-or-insecure`.
- **Side effects:** None (the `-n` sudo probe never prompts).
- **Output shape, table mode:** **Not `render_table`** — fixed key:value lines: `Named secrets: <path>`, `Mode: <mode>`, `Permissions: <octal>`, `Recorded names: <count>`, `Authentication: sudo/PAM`, `Sudo session: <locked|unlocked>`, `Root key: <available|missing-or-insecure|not-checked>`.
- **Output shape, --json mode:** **No effect** — same passthrough caveat as `secrets list`.
- **Exit codes:** `SUCCESS` always (this is a status probe, not a validator — it never returns nonzero even if the store is missing).
- **Related commands:** `netrune vault status` for the SSH-password-specific view (which cross-references this same store when `ssh/default/password` is the live credential); `netrune secrets list` for what's actually stored.

#### `netrune secrets set <name>` (id: `secrets-set`)
- **Purpose:** Interactively prompt for and GPG-encrypt one new named secret value.
- **Exact syntax:** `netrune secrets set <name>`.
- **Arguments:** `name` (required on the Python side — missing → `usage_error("secrets","set",...)`, `USAGE`, "Missing secret name.", suggestion `netrune secrets set snmp/site-a/auth`). Name *format* validation happens only in the bash layer, not in Python: `_named_secret_name_valid` requires `^[a-z0-9][a-z0-9_.-]*(/[a-z0-9][a-z0-9_.-]*)*$` (lowercase-alnum path segments separated by `/`, similar to a namespaced key like `ssh/default/password` or `snmp/site-a/auth`); an invalid name is only caught once the subprocess runs, printing `Error: Invalid secret name '<name>'.` and returning exit 2.
- **Preconditions / gating:** No `--confirm` needed (setting a new value is not treated as destructive the way `delete` is). This is the action that triggers the sudo/root-vault-key provisioning path the first time it's ever run (`_sudo_vault_prepare_key`, invoked transitively through `_named_secrets_write_payload`) — see Cross-cutting notes for the full authentication trace.
- **Step-by-step behavior:** `named_secret_set()` prompts twice (via `_read_secret_value`, which reads from `/dev/tty` if available, falling back to stdin if it's a real terminal, and refuses non-interactively unless in test mode) for the value and its confirmation, rejects an empty value or a mismatch, then calls `_named_secret_set_value`, which: decrypts the existing store (if any) via `_named_secrets_decrypt`, rebuilds the tab-separated `base64(name)\tbase64(value)` payload with the new/updated entry, and commits via `_named_secret_commit` — a two-file transactional-ish write (backs up the existing `SECRETS_FILE`/`SECRETS_META_FILE` to temp copies first; if the metadata write fails after the encrypted store succeeded, it rolls both files back to their pre-write backups and reports whether the rollback itself succeeded).
- **Side effects:** Rewrites `SECRETS_FILE` (`chmod 600`) and appends/updates a line in `SECRETS_META_FILE` (`chmod 600`) with the current epoch as `recorded_at`. First use on a fresh machine also provisions the root-owned vault key under `/etc/netops/vault-keys/<uid>.key` via a `sudo` broker. **No audit event** — unlike `secrets delete`, `secrets set` never calls `State.record_audit_event`, since the entire mapping falls through to the generic `run_subprocess(mapping[verb], opts)` tail with no post-processing.
- **Output shape, table mode:** `output_type: terminal` — this is fully interactive; on success it prints `Named secret recorded: <name>` **to stderr**, not stdout.
- **Output shape, --json mode:** **No effect** — passthrough, and inherently incompatible with `--json` anyway since it requires interactive terminal input.
- **Exit codes:** `0` on success; `1` on empty/mismatched value or a decrypt/commit failure; `2` on an invalid secret name.
- **Related commands:** `netrune secrets delete <name>` (inverse); `netrune secrets import-ssh` / `netrune vault set` for the specific `ssh/default/password` name; `netrune secrets list` to confirm it landed.

#### `netrune secrets delete <name> --confirm` (id: `secrets-delete`)
- **Purpose:** Permanently remove one named secret, with a mandatory preview step first.
- **Exact syntax:** `netrune secrets delete <name> --confirm` (also accepts the alias `netrune secrets remove <name> --confirm`, since `cmd_secrets` matches `verb in {"delete","remove"}`).
- **Arguments:** `name` (required — missing → `usage_error("secrets","delete",...)`, `USAGE`, "Missing secret name.", suggestion `netrune secrets delete snmp/site-a/auth`).
- **Preconditions / gating — the exact preview-then-confirm flow (added this session, matching `inventory forget`'s pattern):**
  1. Before anything else, Python captures `[helper, "--secret-list"]` output itself (`self.capture(...)`) and scans it line-by-line for a row whose name matches. If not found: `usage_error("secrets","delete",...)`, `VALIDATION` (6), message `f"No named secret '{name}' is recorded."`, suggestion `netrune secrets list`.
  2. If found but `opts.confirm` is not set, it does **not** touch the store at all — it emits a preview and returns `VALIDATION` (6):
     - JSON: `{"ok": false, "requires_confirm": true, "name": "<name>", "recorded": "<iso-or-never, taken verbatim from the secret-list row>"}`
     - Text (exact wording): 
       ```
       Would delete secret: <name> (recorded <recorded>).
       This cannot be undone; the value is not backed up anywhere.
       Re-run with --confirm: netrune secrets delete <name> --confirm
       ```
  3. Only once `opts.confirm` is set does it call `run_subprocess([helper, "--secret-delete", name], opts)`.
- **Step-by-step behavior after confirmation:** `named_secret_delete()` in the bash helper decrypts the store, rewrites it without the target entry (name-not-found here would be a race — extremely unlikely given the Python-side pre-check — and returns `Error: Named secret not found: <name>` with exit 1), and commits via the same `_named_secret_commit` rollback-safe path as `secrets set`, this time with `operation="delete"` so the metadata line for that name is dropped too.
- **Side effects:** Rewrites `SECRETS_FILE` and `SECRETS_META_FILE`. Records exactly one audit event: `self.state.record_audit_event("secrets", "secret-delete", result=("success" if rc==SUCCESS else "failed"), target=name, detail={"recorded": recorded})` — event_type `"secrets"`, action `"secret-delete"`.
- **Important verified finding — dry-run/confirm interaction bug:** the audit-event call has **no `and not opts.dry_run` guard**, unlike the equivalent logic in `cmd_vault`. Concretely: `netrune secrets delete <name> --confirm --dry-run` skips the preview branch (because `opts.confirm` is set) and calls `run_subprocess`, which — because `opts.dry_run` is also set — short-circuits immediately, printing `{"dry_run": true, "command": "..."}` and returning `SUCCESS` **without ever running the delete helper**. Back in `cmd_secrets`, that `SUCCESS` return code is then used to write an audit event with `result: "success"` and the secret's name as `target`, even though nothing was actually deleted. This is a real, reproducible quirk of the current code, not a hypothetical — the audit trail can claim a deletion happened when `--dry-run` prevented it.
- **Output shape, table mode:** Preview step: as shown above. Confirmed-delete step: `output_type: terminal`, raw bash output — `Named secret deleted: <name>` printed **to stderr**.
- **Output shape, --json mode:** Preview step *does* honor `--json` correctly (goes through `self.emit`). The confirmed-delete step does **not** — `run_subprocess`'s normal (non-dry-run) path never calls `emit`, so the actual deletion's stdout/stderr is whatever the bash helper printed, unwrapped, regardless of `--json`.
- **Exit codes:** `VALIDATION` (6) if the secret doesn't exist, or if `--confirm` was omitted (preview shown); `SUCCESS` (0) on a real successful delete, or on the dry-run/confirm no-op described above; `1` from the helper on an unexpected not-found race.
- **Real example:**
  ```
  $ netrune secrets delete snmp/site-a/auth
  Would delete secret: snmp/site-a/auth (recorded 2026-07-01T12:00:00Z).
  This cannot be undone; the value is not backed up anywhere.
  Re-run with --confirm: netrune secrets delete snmp/site-a/auth --confirm

  $ netrune secrets delete snmp/site-a/auth --confirm
  Named secret deleted: snmp/site-a/auth
  ```
- **Related commands:** `netrune secrets list` to see what exists before deleting; `netrune secrets set <name>` to re-create it (there's no undo — the preview text says so explicitly).

#### `netrune secrets import-ssh` (id: `secrets-import-ssh`)
- **Purpose:** One-time migration of the legacy single-file SSH vault (`PASSWORD_FILE`) into the named-secret store under the fixed name `ssh/default/password`.
- **Exact syntax:** `netrune secrets import-ssh` (no arguments).
- **Arguments:** None.
- **Preconditions / gating:** No `--confirm`. If `ssh/default/password` is already recorded in the metadata index, it's a no-op success (`echo "SSH password is already mapped to ssh/default/password."` to stderr, return 0) — safe to run repeatedly.
- **Step-by-step behavior:** `named_secret_import_ssh()`: requires `PASSWORD_FILE` (default `~/.ssh/sshpass_cache.gpg`) to exist, reads its file-modification time as the `recorded_at` to preserve (rather than reset) the original rotation clock, decrypts it via whichever mode it's actually in (`_vault_is_sudo_gated` checks the file's first-line magic marker to pick `_decrypt_sudo_vault` vs `_decrypt_legacy_vault` — the latter may prompt for a passphrase), then calls `_named_secret_set_value("ssh/default/password", value, recorded_at)`.
- **Side effects:** Writes into `SECRETS_FILE`/`SECRETS_META_FILE` exactly like `secrets set`, but leaves the original legacy vault file completely untouched on disk (both files coexist afterward — this is why `vault status` can show a "Note: an unused legacy vault file remains…" line once the named secret becomes the live credential). **No audit event** (falls through the same unaudited `run_subprocess(mapping[verb], opts)` tail as `secrets set`/`list`/`status`).
- **Output shape, table mode:** `output_type: terminal`; success message `SSH password imported as ssh/default/password. The legacy vault was left unchanged.` on stderr.
- **Output shape, --json mode:** No effect (passthrough).
- **Exit codes:** `0` on success or already-imported no-op; `1` if the legacy vault file doesn't exist or decrypts empty/fails.
- **Related commands:** `netrune vault migrate` — functionally overlapping but distinct: `vault migrate` is the vault-domain command that performs this same underlying migration (and also handles the already-sudo-gated-but-not-yet-named-secret case); `secrets import-ssh` is the secrets-domain equivalent focused specifically on the legacy passphrase file. `netrune vault status` afterward to confirm `credential_store` now reads `named-secret ssh/default/password`.

---

### vault domain

The vault domain manages the SSH device-login password specifically (as opposed to the general named-secret store, though as of this session the SSH password is itself stored *inside* that same named-secret store under the name `ssh/default/password` once migrated). All interactive verbs (`set`, `migrate`, `unlock`, `lock`) share one dispatcher in `cmd_vault`.

#### `netrune vault status` (id: `vault-status`)
- **Purpose:** Show the SSH vault's format, permissions, recorded/expected rotation time, sudo session state, and whether an unlock session is currently open — without prompting for anything.
- **Exact syntax:** `netrune vault status` (no arguments; passing any extra token returns `usage_error("vault","status",...)`, `VALIDATION`, `f"Unknown vault status option: {rest[0]}"`).
- **Arguments:** None.
- **Preconditions / gating:** Never prompts. Every sudo probe inside `App.vault_status_payload` uses `sudo -n -v` (non-interactive) so a locked sudo session simply reports `sudo_session: "locked"` rather than blocking.
- **Step-by-step behavior — `App.vault_status_payload()`, entirely native Python** (does not shell out to `netops-connect --vault-status`; it independently re-implements the same logic so it can merge in the named-secret view):
  1. Determines which credential store is authoritative: if `ssh/default/password` has a recorded timestamp in `SECRETS_META_FILE` *and* `SECRETS_FILE` exists, the named-secret store wins (`credential_store = "named-secret ssh/default/password"`); otherwise falls back to the legacy single-file vault (`credential_store = "legacy-ssh-vault"`, path from `NETRUNE_PASSWORD_FILE`/`NETOPS_PASSWORD_FILE`, default `~/.ssh/sshpass_cache.gpg`).
  2. Reads the winning file's first line to classify `mode`: for the named-secret store, `"sudo-gpg-v1"` if the marker is `NETOPS-NAMED-SECRETS-GPG-V1`, else `"unreadable"`; for the legacy file, `"sudo-gpg-v1"` if the marker is `NETOPS-SUDO-GPG-V1`, else `"legacy-gpg"`.
  3. Checks sudo session state (`sudo -n -v`) and, if unlocked and mode is `sudo-gpg-v1`, whether the root-owned key file at `/etc/netops/vault-keys/<uid>.key` passes ownership/mode/parent-directory checks (`root_key`: `available`/`missing`/`insecure`/`not-checked`).
  4. Detects whether `sudo` is PAM-gated through Windows Hello by grepping `/etc/pam.d/sudo` for `pam_wsl_hello.so` (`sudo_authenticator`: `"windows-hello"` or `"password"`).
  5. Computes a purely arithmetic rotation-lifecycle estimate from `modified_at` (the recorded-at timestamp, not file mtime, when the named-secret store is authoritative) plus three config-tunable policy values: `vault_password_ttl_hours` (default 72, clamped 1–8760), `vault_expiry_window_minutes` (default 20, clamped 0–720), `vault_expiry_warning_hours` (default 12, clamped 0–720). Yields `credential_state` ∈ `{UNKNOWN, ACTIVE, DUE_SOON, EXPIRY_WINDOW, EXPIRED}` — explicitly documented as a local reminder only, never a real check against the device.
  6. Reads `App.vault_session_payload()` for whether an unlock session (see `vault unlock` below) is currently open.
- **Side effects:** None — every check is a non-blocking probe.
- **Output shape, table mode:** Not `render_table` — a multi-line narrative block: SSH vault path, credential store, mode, permissions, password-recorded time (with a note on whether it came from `vault set`'s own record or a file mtime), rotation-reminder line with the explicit disclaimer that it's arithmetic-only, authentication method, sudo session, root key, an optional "unused legacy vault file" note (shown only when the named-secret store is authoritative *and* the legacy file still exists on disk), and finally the live unlock-session line (`"Vault session: open until <iso> (<N>m left, key cached at <path>)"` or `"Vault session: closed (each command authenticates; 'netrune vault unlock' holds it open)"`).
- **Output shape, --json mode:** Full key set from `vault_status_payload()`: `ok`, `configured`, `path`, `credential_store`, `legacy_vault_path`, `legacy_vault_present`, `mode`, `permissions`, `modified_at`/`modified_at_iso`, `password_recorded_at`/`password_recorded_at_iso`, `expected_expiry_at`/`_iso`, `expiry_window_start`/`_iso`, `expiry_window_end`/`_iso`, `credential_state`, `seconds_to_expected_expiry`, `password_ttl_hours`, `expiry_window_minutes`, `sudo_session`, `sudo_authenticator`, `root_key`, `session` (nested: `supported`, `active`, `expires_at`/`_iso`, `seconds_remaining`, `path`), `graphical_pinentry` (always `false` when mode is `legacy-gpg`/`sudo-gpg-v1`, `None` otherwise — documents that Netrune's GPG invocations always use `--pinentry-mode loopback`, never a graphical prompt).
- **Exit codes:** Always `SUCCESS`, **even when `ok` is `false`** inside the payload (e.g. wrong permissions or an unreadable file) — the process exit code cannot be used to detect vault health; only the `ok` field can.
- **Real example:**
  ```
  $ netrune vault status
  SSH vault: ~/.local/share/netrune/secrets.gpg
  Credential store: named-secret ssh/default/password
  Mode: sudo-gpg-v1
  Permissions: 0600
  Password recorded: 2026-08-15T10:03:22Z (recorded by vault set)
  Rotation reminder: DUE_SOON | due 2026-08-18T10:03:22Z (recorded + 72h policy)
    This is a local reminder only. It does not check the password against any device;...
  Authentication: sudo password/PAM
  Sudo session: locked
  Root key: not-checked
  Vault session: closed (each command authenticates; 'netrune vault unlock' holds it open)
  ```
- **Related commands:** `netrune secrets status` for the general named-secret store view; `netrune vault set` to rotate when `credential_state` is `DUE_SOON`/`EXPIRY_WINDOW`/`EXPIRED`; `netrune vault unlock` to open the session referenced in the last line.

#### `netrune vault set [--legacy-vault]` (id: `vault-set`)
- **Purpose:** Store a new SSH device-login password, encrypted.
- **Exact syntax:** `netrune vault set [--legacy-vault]`.
- **Arguments:** `--legacy-vault` (optional flag) — forces the *older* passphrase-gated GPG mode instead of the default sudo-gated mode. Any other token, or `--legacy-vault` given more than once, → `usage_error("vault","set",...)`, `VALIDATION`, message naming the bad token or "duplicate --legacy-vault", usage `netrune vault set [--legacy-vault]`.
- **Preconditions / gating:** `cmd_vault` refuses to run any of `set`/`migrate`/`unlock`/`lock` under `--json` at all: `if opts.json: return usage_error("vault", verb, opts, "Interactive vault actions do not emit JSON.", f"netrune vault {verb}", VALIDATION)`. All four are fully interactive terminal flows and cannot be scripted through JSON output.
- **Step-by-step behavior:** `set_password()` in `netops-lib.sh`: if the sudo-gated mode is requested (the default), first calls `_sudo_vault_prepare_key` — authenticates via `sudo -v` (prompting through PAM, which on a Windows Hello–enabled `/etc/pam.d/sudo` means a biometric prompt, otherwise a password prompt), then provisions the root-owned AES key at `/etc/netops/vault-keys/<uid>.key` if it doesn't already exist (48 random bytes, base64, `chmod 0600`, directory `chmod 0700`), or validates an existing key's ownership/mode/parent chain. Then prompts twice for the new password (`_read_secret_value`), rejects empty/mismatched input, and — for sudo-gated mode — writes it via `_named_secret_set_value("ssh/default/password", ...)` into the **same named-secret store** `secrets set` uses (so after this, `netrune secrets list` will show `ssh/default/password` too); for `--legacy-vault` mode, writes a standalone single-secret file via `_write_legacy_vault` (prompts for a separate legacy vault passphrase, symmetric AES-256 GPG with `--passphrase-fd`, to `PASSWORD_FILE`). Finally prints the newly recorded/expected-expiry times using the same lifecycle arithmetic as `vault status`.
- **Side effects:** Writes into `SECRETS_FILE`/`SECRETS_META_FILE` (default sudo-gated path) or `PASSWORD_FILE` (`--legacy-vault`). First real use on a machine also provisions the root vault key under `/etc/netops/vault-keys/`. Audit event recorded by `cmd_vault` on success (see below).
- **Output shape, table mode:** `output_type: terminal`; interactive prompts, then confirmation lines to stderr, e.g. `Password encrypted as named secret ssh/default/password.`, `Password rotation recorded: <iso>`, `Expected password expiry: <iso> (estimated window <iso> to <iso>)`.
- **Output shape, --json mode:** Blocked entirely (`VALIDATION`, see above).
- **Exit codes:** `0` on success; `1` on cancelled/empty/mismatched input, or a key-provisioning/encryption failure; `2` for an unrecognized vault mode (shouldn't occur through the CLI's own flag parsing).
- **Side effects — audit event:** `cmd_vault` records, only `if code == SUCCESS and not opts.dry_run`: `event_type = "vault_password_set"`, `action = "vault-set"`, `actor` = `$SUDO_USER`/`$USER`/uid fallback, `actor_uid = os.getuid()`, `result = "success"`, `detail = {"vault": "<current vault_status_payload path>"}`.
- **Related commands:** `netrune vault status` immediately after, to see the new rotation reminder; `netrune vault migrate` if you already have a legacy vault and just want to move it forward rather than typing a brand-new password.

#### `netrune vault migrate` (id: `vault-migrate`)
- **Purpose:** Move an existing SSH password — from either the legacy passphrase-gated vault *or* the older single-file sudo-gated vault — into the current named-secret store, without ever displaying the password.
- **Exact syntax:** `netrune vault migrate` (no arguments; any token → `usage_error`, `VALIDATION`, `f"Vault {verb} does not accept arguments."`).
- **Arguments:** None.
- **Preconditions / gating:** Blocked under `--json` (same as `vault set`). No-op success if `ssh/default/password` is already recorded (`SSH password is already stored as ssh/default/password.`). Fails if `PASSWORD_FILE` doesn't exist at all (`Error: Password file not found. Run 'netrune vault set'.`).
- **Step-by-step behavior — the three-generation vault model this command bridges:**
  1. **legacy-gpg**: `PASSWORD_FILE`'s first line does not match the sudo-vault magic marker; decrypting requires the operator's own passphrase (`_decrypt_legacy_vault`), which may itself first try an empty/no-prompt decrypt before falling back to an interactive passphrase prompt.
  2. **sudo-gpg-v1 (old single-secret form)**: `PASSWORD_FILE`'s first line is `NETOPS-SUDO-GPG-V1`; decrypted via the root-owned key broker with no interactive passphrase (`_decrypt_sudo_vault`).
  3. **named-secret store (current)**: the migration target — `SECRETS_FILE` holding many named secrets, SSH password at `ssh/default/password`, same sudo-gated key mechanism as #2.

  `migrate_password_store()` calls `_sudo_vault_prepare_key` first (this is the step that authenticates and, if needed, provisions the root key — happens *before* it even checks which of the two source formats it's dealing with), detects the format via `_vault_is_sudo_gated`, decrypts accordingly (printing a notice if a legacy passphrase prompt is about to happen), then calls `_named_secret_set_value("ssh/default/password", decrypted, recorded_at)` where `recorded_at` is the *original* `PASSWORD_FILE`'s modification time — this preserves the original rotation clock rather than resetting it to "now," which matters for the `vault status` expiry-window arithmetic.
- **Side effects:** Writes into `SECRETS_FILE`/`SECRETS_META_FILE`. **Deliberately leaves the original `PASSWORD_FILE` on disk, unchanged** — this is why `vault status`'s "Note: an unused legacy vault file remains…" line can appear afterward; migration is additive, not destructive. Audit event on success: `event_type = "vault_migrated"`, `action = "vault-migrate"`, same actor/detail shape as `vault set`.
- **Output shape, table mode:** `output_type: terminal`; success message `SSH password migrated to named secret ssh/default/password. The original vault was left unchanged.` to stderr.
- **Output shape, --json mode:** Blocked (`VALIDATION`).
- **Exit codes:** `0` on success or already-migrated no-op; `1` if `PASSWORD_FILE` is missing, decrypts empty, or the legacy decrypt fails.
- **Related commands:** `netrune vault set` for a brand-new password instead of migrating an old one; `netrune secrets import-ssh` — functionally near-identical for the legacy-file case specifically, invoked from the `secrets` domain instead.

#### `netrune vault unlock [--ttl MINUTES]` (id: `vault-unlock`)
- **Purpose:** Authenticate once and hold the vault's decryption key open in memory for a bounded window, so a batch of subsequent commands (backups, SSH sessions, MAC locates) doesn't re-prompt per device.
- **Exact syntax:** `netrune vault unlock [--ttl MINUTES]`.
- **Arguments:** `--ttl MINUTES` (optional) — must be a bare digit string in `[1, 480]`; otherwise `usage_error("vault","unlock",...)`, `VALIDATION`, `f"--ttl must be between 1 and 480 minutes, not {raw!r}."`, usage `netrune vault unlock [--ttl MINUTES]`. If `--ttl` is given without a following value, same error but "requires a whole number of minutes." Omitting `--ttl` entirely defers to the bash side's own default of `${CONFIG[vault_session_ttl_minutes]:-15}` (i.e. 15 minutes unless overridden via `netrune config set vault_session_ttl_minutes N`), clamped the same way.
- **Preconditions / gating:** Blocked under `--json`.
- **Step-by-step behavior — trace of `unlock_password_store()` and the session mechanism it uses (`_vault_session_*` functions in `netops-lib.sh`):**
  1. Resolves a session directory: `${NETRUNE_VAULT_SESSION_DIR:-${NETOPS_VAULT_SESSION_DIR:-${XDG_RUNTIME_DIR}}}/netrune-vault`. If none of those environment variables are set, unlock fails outright (`Error: No per-user runtime directory is available for a vault session.`) — this is deliberately restricted to a per-user runtime directory (normally tmpfs-backed under `/run/user/<uid>` on Linux) rather than any writable path.
  2. Reads the vault key fresh through `sudo`, **deliberately bypassing any already-open session** (`NETRUNE_VAULT_SESSION_BYPASS=1`), so an unlock always re-authenticates rather than silently extending a stale window.
  3. Writes the key into `<session_dir>/key` (`chmod 600`, directory `chmod 700`) and an expiry epoch into `<session_dir>/expires-at`, both via atomic temp-file-then-rename, and **refuses to proceed if the session directory doesn't verify as a user-owned, mode-0700, `tmpfs`/`ramfs`-backed path** (`_vault_session_path_is_secure`) — so the cached key can never land on a real disk.
  4. Proves the newly cached key actually opens the vault by calling `get_password_from_store()` immediately (and then unsetting the resulting `SSHPASS` — this call is purely a verification side-effect, not meant to leave a password in the environment); if that fails, the session is torn down immediately (`_vault_session_clear`) and unlock reports failure rather than promising a window that doesn't actually work.
  5. Prints the expiry time and a reminder that the key is now readable by this user (not just root) until the window closes.
- **How the session is subsequently consumed:** `_sudo_vault_emit_key()` (called by every later vault-dependent operation, e.g. `get_password_from_store`) checks for a live, validated session first (`_vault_session_read`) and, if found, returns the cached key **without touching `sudo` at all** — this is the entire point: one authentication answers every subsequent command until the TTL expires. If the session is missing, expired, or fails its tmpfs/ownership/mode checks, it's discarded and a fresh `sudo`-gated read happens instead (prompting again).
- **Automatic (non-CLI) use of the same mechanism:** `App.vault_session_scope` in `core.py` (used internally by, e.g., `locate_endpoint_live` for parallel multi-switch MAC searches) opens a short session automatically around a batch of parallel operations — but only when it's interactive (`sys.stdin.isatty() and sys.stderr.isatty()`, and not overridden by `NETRUNE_VAULT_NONINTERACTIVE`/`NETOPS_VAULT_NONINTERACTIVE`) and only if no session is already open; if one is already open it's left exactly as found (not extended, not closed early by the automatic scope). This is separate from — and does not require — the user having run `netrune vault unlock` themselves first, though running it manually beforehand avoids even that one internal prompt.
- **Side effects:** Writes `key` and `expires-at` files under the tmpfs session directory. Audit event on success: `event_type = "vault_unlocked"`, `action = "vault-unlock"`, `detail = {"vault": "<path>", "session_ttl_minutes": <ttl_minutes or "configured default">}`.
- **Output shape, table mode:** `output_type: terminal`; prints the expiry time, the session-file location, and a reminder that `netrune vault lock` ends it early.
- **Output shape, --json mode:** Blocked.
- **Exit codes:** `0` on success; `1` if no runtime directory is available, the TTL bounds check fails at the bash layer, the key can't be cached, or the post-cache verification decrypt fails; `2` if TTL parsing itself fails at the bash layer (Python's own `--ttl` validation normally catches this first and returns `VALIDATION`).
- **Real example:**
  ```
  $ netrune vault unlock --ttl 30
  Unlocking the Netrune SSH vault with sudo authentication...
  SSH vault unlocked until 2026-08-28 15:42:10 (30m).
  The key is held in memory at /run/user/1000/netrune-vault and is readable by this user until then.
  Run 'netrune vault lock' to end the session early.
  ```
- **Related commands:** `netrune vault lock` to close it early; `netrune vault status` shows the live session countdown in its last output line; `netrune backup run` on a multi-device target, or any bulk MAC-locate/topology-scan operation, benefits from an unlocked session beforehand to avoid repeated prompts (though many of those already open their own short-lived internal session automatically).

#### `netrune vault lock` (id: `vault-lock`)
- **Purpose:** End an open unlock session immediately and erase the cached key.
- **Exact syntax:** `netrune vault lock` (no arguments; any token → `usage_error`, `VALIDATION`).
- **Arguments:** None.
- **Preconditions / gating:** Blocked under `--json`.
- **Step-by-step behavior:** `lock_password_store()` reads the current session's expiry (if any) purely to decide which message to print, then unconditionally calls `_vault_session_clear()`: shreds (`shred -u`, falling back to plain `rm -f` if `shred` is unavailable) the cached `key` file, removes `expires-at`, and removes the now-empty session directory. Safe to call even if no session is open.
- **Side effects:** Deletes the session's `key`/`expires-at` files (securely, via `shred` where available) and the session directory. Audit event on success: `event_type = "vault_locked"`, `action = "vault-lock"`.
- **Output shape, table mode:** `output_type: terminal`; `SSH vault session ended; the next command will authenticate again.` or `No SSH vault session was active.`
- **Output shape, --json mode:** Blocked.
- **Exit codes:** Always `0` (bash function ends with an explicit `return 0` regardless of whether a session existed).
- **Related commands:** Inverse of `netrune vault unlock`; `netrune vault status`'s last line reflects whether a session is open before/after.

---

### Cross-cutting notes

#### What "the vault" actually is
"The vault" is not one file — it is a small family of GPG-encrypted local credential stores plus, as of this session, a unifying named-secret layer that the SSH vault increasingly sits inside of. Concretely, from `netops-lib.sh`:

- **`PASSWORD_FILE`** (default `~/.ssh/sshpass_cache.gpg`, override `NETRUNE_PASSWORD_FILE`/`NETOPS_PASSWORD_FILE`): the original single-secret SSH-password vault. Its first line is a plaintext magic marker that determines how it's read:
  - **`legacy-gpg`**: no recognized marker (or a marker other than the sudo-gated one). Encrypted with `gpg --symmetric --cipher-algo AES256` using an operator-chosen passphrase (`--passphrase-fd`, loopback pinentry — never a graphical prompt). Every decrypt (unless GPG's own agent has cached the passphrase) prompts the operator to type that passphrase again. This is the oldest, most portable mode, and the one `vault migrate`/`secrets import-ssh` exist to move operators away from.
  - **`sudo-gpg-v1`** (marker `NETOPS-SUDO-GPG-V1`): a single secret encrypted with a symmetric key that itself lives root-owned on disk at `/etc/netops/vault-keys/<uid>.key`, readable only through a `sudo`-gated broker script (`_sudo_vault_key_broker`/`_sudo_vault_emit_key` in `netops-lib.sh`). Authentication is whatever PAM backs `sudo` on the host — a typed sudo password normally, or Windows Hello (biometric/PIN) when `/etc/pam.d/sudo` includes `pam_wsl_hello.so` (WSL). The GPG passphrase itself is machine-generated random bytes the operator never sees or types; what gates access is the OS-level sudo/PAM prompt, not a memorized GPG passphrase. This mode still stores exactly one secret.
- **`SECRETS_FILE`** (default `${DATA_DIR}/secrets.gpg`, override `NETRUNE_SECRETS_FILE`/`NETOPS_SECRETS_FILE`), paired with **`SECRETS_META_FILE`** (default `${STATE_DIR}/secrets.meta`): the current named-secret store, marker `NETOPS-NAMED-SECRETS-GPG-V1`. Uses the *same* sudo-gated root key mechanism as `sudo-gpg-v1` (in fact the same physical key file), but holds an arbitrary number of named secrets (tab-separated `base64(name)\tbase64(value)` pairs inside the decrypted payload) rather than just one. The SSH device password, once migrated or freshly set through `vault set`, lives here under the fixed name `ssh/default/password`. This is the mode both `netrune secrets *` and (as of this session) `netrune vault set` default to.

So "vault" (SSH-specific) and "secrets" (general named-credential) are converging on one encrypted store and one authentication mechanism (`sudo-gpg-v1`), with the SSH password being just one entry (`ssh/default/password`) in that store once migrated. `vault status`/`secrets status` both independently re-derive which physical file is authoritative and report `mode: sudo-gpg-v1` for either generation of the sudo-gated format, distinguishing them only via the `credential_store` field (`"named-secret ssh/default/password"` vs `"legacy-ssh-vault"`).

**When each mode is used / how a prompt is triggered:**
- The *first* time any sudo-gated write happens on a machine (`vault set` default mode, `vault migrate`, `secrets set`, `secrets import-ssh`), `_sudo_vault_prepare_key` provisions the root key via `sudo -n /usr/bin/install -d ...` + a root shell snippet that writes 48 random bytes if the key doesn't already exist — this requires one real (non-`-n`) `sudo -v` authentication.
- Every subsequent *read* of a sudo-gated secret (`get_password_from_store`, `named_secret_get`, any live SSH connection) calls `_sudo_vault_emit_key`, which first checks for a live vault-unlock session (see below) and only falls through to a fresh `sudo` authentication if no session is open or the session fails validation.
- A credential prompt is therefore triggered by: (a) no unlock session being open and `sudo -n -v` failing (cached sudo ticket expired/absent), or (b) the legacy-gpg mode, which always prompts for its passphrase unless the local `gpg-agent` already cached it independently of Netrune's own session mechanism.
- A prompt is *avoided* (session reused) when: `netrune vault unlock` was run recently and its TTL hasn't elapsed, **or** the ambient `sudo` ticket is still cached from an unrelated recent `sudo` command (`sudo -n -v` succeeds) — the vault mechanism piggybacks on the OS sudo ticket cache in addition to its own explicit session.

**`vault_session_scope` (`App.vault_session_scope` in `core.py`), traced precisely:** used internally (not directly user-facing) by multi-device parallel operations such as `locate_endpoint_live`. It checks `vault_session_payload().active` first; if a session is *already* open it does nothing further and yields `opened=False` (meaning: "this call didn't open it, so this call won't close it either" — an already-open session set up by an explicit `netrune vault unlock` is left exactly as found, never extended or shortened). If no session is open, it only attempts to open one when the process is fully interactive (`sys.stdin.isatty() and sys.stderr.isatty()`, unless `NETRUNE_VAULT_NONINTERACTIVE`/`NETOPS_VAULT_NONINTERACTIVE` forces it off) — a piped or `--json` invocation never attempts this, and simply falls through to per-device authentication instead. If it does open a session (default TTL 30 minutes internally for this caller, distinct from the CLI's own 15-minute default), it always closes that session again in a `finally` block, including on exception or `Ctrl-C` — but only the session it opened; a pre-existing one is still left alone. If opening fails, it's logged as non-fatal (`self.live_log("vault", "Could not hold the vault open; each switch will authenticate separately.")`) and the caller proceeds with per-device authentication.

#### `NETRUNE_CORE_WRITE_REQUEST=audited-confirmation`
Set inside `App.child_env` (in `core.py`) — every subprocess Netrune spawns goes through this method to build its environment — with exactly one condition: `if opts.confirm: env["NETRUNE_CORE_WRITE_REQUEST"] = "audited-confirmation"` (and the legacy-aliased `NETOPS_CORE_WRITE_REQUEST` alongside it). It is **not** set for a plain `--dry-run` invocation, and it is set for *any* command that passes `--confirm`/`--approve`/`--yes` on the CLI, not only VLAN/config changes — so `netrune secrets delete --confirm` and `netrune vault set` (which is inherently a confirmed action) also carry it into their child processes, even though those subprocesses don't check for it.

The one place that *does* check it is `netops-control`'s raw `config` mode (the internal, non-public device-configuration write path): `if [[ "$MODE" == "config" && "${NETOPS_CORE_WRITE_REQUEST:-}" != "audited-confirmation" ]]; then error "Direct configuration execution is blocked. Use 'netrune device config ... --confirm' or 'netrune vlan set ... --confirm' ..."; exit 7; fi`. This is the marker ADR 0005 calls "an internal marker supplied by the core" for "direct helper writes" — it exists specifically so that nobody can invoke `netops-control config <target> <commands>` directly (bypassing preview, the preview-hash/exact-phrase approval binding, reason/ticket requirements, and the audit trail) and still have the write actually take effect. The env var only ever gets set by `App.child_env` in response to `opts.confirm`, and Netrune's own confirmed code paths (`apply_vlan_change`, the guarded `device config --confirm` path) are the only callers that reach `netops-control config` with `opts.confirm=True` already validated against a preview hash — so in practice the marker is a defense against someone shelling out to the helper binary directly, not a gate `netrune` itself has to work around.

#### The guarded-configuration-lifecycle pattern (ADR 0005)
ADR 0005 ("Guarded Configuration Lifecycle," accepted, `docs/adr/0005-guarded-configuration-lifecycle.md`) establishes that any command capable of writing device configuration must implement a five-part sequence — **preflight → backup → apply → verify → audit** — rather than trusting a clean subprocess exit code alone. `App.apply_vlan_change` (in `netops_platform/vlan_cli.py`, the engine behind `netrune vlan set --confirm`) is the concrete reference implementation:
1. **Preflight** — capture current interface/VLAN evidence (`show vlan ports ... detail` or `show interfaces ... switchport`, platform-dependent) before touching anything; a failed or empty capture blocks the whole run (`BLOCKED`, no configuration applied).
2. **Backup** — run `netrune-control backup <ip> --online-only --changed-only --summary` — **the exact same command** `netrune backup run <target>` builds by hand. A backup failure also blocks the apply step entirely.
3. **Apply** — run the actual typed-intent helper invocation (`netrune-control vlan ...`) through `netops-control`'s internal `vlan`/`config` mode, gated by the `NETRUNE_CORE_WRITE_REQUEST` marker described above.
4. **Verify** — read the device back (`locate-vlan`) and confirm the requested VLAN(s) actually landed on the expected interface/ports; verification failure is reported as `PARTIAL` with the pre-change evidence retained for manual rollback (ADR 0005's consequence: "Verification failure is reported as partial with manual rollback evidence").
5. **Audit** — (not shown in the excerpt above but implied by the pattern and ADR text) the confirmed, verified change is what the broader guarded-CLI records as an approved, executed change.

This cluster of domains (`backup`, `vault`, `secrets`, `db`, `config`) supplies the *building blocks* this pattern is assembled from, without any single command here running the full five-part sequence itself: `backup run` is literally the same subprocess call used as step 2 above; `vault`/`secrets` supply the credential the SSH connection in every step needs; `db repair`'s migrate→reconcile→verify→prune bundle is a *different*, maintenance-flavored echo of the same "do the risky thing, then check your own work" shape, but for the local database rather than a device; `config set`/`unset` are explicitly *not* gated by this pattern at all (no `--confirm`, no backup, no verify) because they only ever touch local, non-device state. Running `netrune backup run <target>` by hand immediately before a manual `netrune vlan set <target> ... --confirm` is redundant in the sense that `apply_vlan_change` already performs its own preflight+backup automatically — but it is a legitimate extra precaution for an operator who wants a backup timestamped strictly before their own review of the preflight evidence, independent of whatever the guarded pipeline captures a few seconds later on its own.

#### Audit-trail asymmetry across this cluster (verified, not assumed)
Only two commands in this entire 28-command set ever call `State.record_audit_event`: the four `vault` write verbs (`set`→`vault_password_set`/`vault-set`, `migrate`→`vault_migrated`/`vault-migrate`, `unlock`→`vault_unlocked`/`vault-unlock`, `lock`→`vault_locked`/`vault-lock`) and `secrets delete`→`"secrets"`/`"secret-delete"`. Every other command — every `backup` verb, every `config` verb, every `db` verb, and `secrets set`/`list`/`status`/`import-ssh` — writes no `audit_events` row at all, even the ones that mutate local state or fetch device configuration over the network. `backup run` writes to `backup_history` (a plain operational-data table) but not `audit_events`. This means an operator relying on `audit_events` for a complete picture of "what changed" will not see profile config edits, database maintenance, or new/imported secrets — only vault credential lifecycle events and secret deletions.

#### Support-bundle rotation (touches this cluster's data, lives in the `support` domain)
Not one of the 28 commands, but worth noting because `netrune support bundle` embeds a redacted slice of `db status`'s payload (`database.json`, via `_database_summary` in `netops_platform/support.py`) and `db integrity`'s payload (`integrity.json`) verbatim, and because its rotation behavior was added the same session as the retention-table expansion. `create_support_bundle` writes to `<data_dir>/support/netrune-support-<epoch>.tar.gz` by default, then calls `_rotate_support_bundles(bundle_dir, KEPT_BUNDLES=10)`, which globs `netrune-support-*.tar.gz` in that **specific default directory**, sorts by filename (which sorts chronologically since the name embeds the epoch), and deletes everything except the newest 10. Passing an explicit output path (`netrune support bundle /custom/path.tar.gz`) writes there instead and the rotation function is never even called with that path — a custom destination is never pruned, by construction, not just by convention.

---

## 12. Meta and Orchestration Domains (ask, commands, ingest, init, path, plugin, profile, setup, support, workflow)


Source files verified against current code: `netops_platform/ask_cli.py`, `netops_platform/ask.py`, `netops_platform/setup_cli.py`, `netops_platform/path_cli.py`, `netops_platform/path_inspector.py`, `netops_platform/contracts.py`, `netops_platform/support.py`, `netops_platform/ingest.py`, `netops_platform/plugins.py`, `netops_platform/profiles.py`, `netops_platform/core.py`.

Shared exit-code vocabulary (all from `netops_platform/core.py`): `SUCCESS=0`, `USAGE=2`, `PARTIAL=3`, `UNREACHABLE=4`, `UNSUPPORTED=5`, `VALIDATION=6`, `CONFIRM_REQUIRED=7`, `AUTH=8`, `TIMEOUT=9`, `INTERNAL=10`. `usage_error()` defaults to `USAGE` unless a domain explicitly passes a different code (most of these domains pass `VALIDATION` explicitly for bad arguments). Any uncaught exception anywhere in dispatch bubbles to the top-level `App.dispatch` handler and returns `INTERNAL` with `{"ok": false, "error": ..., "exit_code": 10}` under `--json`.

Global flags relevant throughout (`GlobalOptions` in `core.py`, parsed by `parse_global`): `--json`, `--plain`, `--no-color`, `--dry-run`, `--confirm` (aliases `--approve`, `--yes`), `--execute` (alias `--run-plan`), `--limit` (default 100), `--depth`, `--max-nodes` (default 64), `--refresh-neighbors`, `--site`.

---

### ASK domain

#### `netrune ask '<question>'` (id: `ask-query`)
- **Purpose:** Run a deterministic natural-language question against current inventory/relationship memory, or against the registered command catalog, and return either a retrieval answer or a command plan.
- **Exact syntax:** `netrune ask "<question>" [--execute] [--confirm] [--json]`. Dispatch (`ask_cli.dispatch`): if `args` is non-empty and the first token is not `patterns`, `aliases`, or `alias`, all remaining args are joined with spaces into `question`.
- **Arguments:** `question` (free text, required — an empty string after normalization returns `{"ok": false, "error": "Ask a question or run: netrune ask patterns"}` from `NaturalAskEngine.ask`).
- **Preconditions / gating:** Plain `netrune ask "..."` never executes anything — it only ever returns a retrieval answer or a *plan* (preview). Actual execution requires `--execute` (`ask_cli.execute_ask_plan`); state-changing/active plans additionally require `--confirm` in the same invocation (checked against `spec.effective_safety_class() != "read-only"`). `opts.dry_run` on the `ask` invocation itself has no bearing on whether a spawned action is a dry run — `execute_ask_plan` never inspects `opts.dry_run`.
- **Step-by-step behavior (`NaturalAskEngine.ask`):**
  1. Normalize whitespace/typos (`_normalize_question` — fixes things like "hoa many"→"how many", "access points"→"APs", "bldg 9"→"building9").
  2. `_session_followup(question, session, limit)` — if a `session` dict was passed (only true from the interactive `ask-chat` REPL; a single `netrune ask "..."` CLI call always passes a fresh empty session so this never fires there) and it has a `last_command_plan`, check `_command_followup` first (words like run/execute/change target); otherwise if it has `last_result` rows and the question references "them/those/these/their/that list", answer from the cached result set instead of re-querying.
  3. `_plan_command(question, session)` — score the question against ~53 command rules plus a token-overlap fallback across the full registry (see Cross-cutting notes). If any action scores, build and return a `command_plan` response (never falls through to retrieval).
  4. If no command plan, run an ordered cascade of ~20 regex-gated retrieval intents (ap_aliases → unjoined_aps → attention → topology_changes → ap_moves → backup_history → diagnostic_history → job_status → ap_on_switch → port_memory → ap_location/identity_history → mac/ip_memory → identity_history(again) → switch_summary → topology → health → ap_inventory → switch_inventory → entity_details), each implemented by one `_ask_*` method.
  5. If nothing matches, fall through to a final generic `_target_from_question` + `_ask_details` attempt; if that also yields no target, return `{"ok": false, "error": "That wording does not match a predefined Natural Ask workflow.", "suggestions": [...]}`.
- **Side effects:** None by default (pure SQLite reads via `self.app.state`). If `--execute --confirm` is used and the planned action itself writes (e.g. a workflow, an alias write, a backup), that underlying action's own side effects apply — `execute_ask_plan` ultimately calls `app.run_subprocess(cmd, opts)` (or `run_interactive` for terminal-output actions), spawning `netrune <resolved-command>` as a child process.
- **Output shape, table/text mode:** Built by `ask_cli._format_ask_text(payload)`: starts with `payload["answer"]` (or `payload["error"]`), then if a `command_plan` dict is present appends, one per line: `Plan: <label> [<status>]`, `Preview: <command>` (if present), `Needs: <missing_args joined>` (if any), `Execute: <execution_hint>` (if present); then if `payload["choices"]` is non-empty appends `Choices: <up to 12 names/ips>`; then if `payload["suggestions"]` is non-empty and (`not ok` or a plan exists) appends `Try: <up to 4 suggestions, | -joined>`. **Known gap confirmed in source:** this text formatter never renders `payload["result"]["rows"]` as a table — the row data that every `_ask_*` method carefully assembles (via `_response()`) is present in the JSON payload but invisible in the default human-readable text output; only the prose `answer` sentence surfaces to a plain-text caller.
- **Output shape, `--json` mode:** Top-level keys from `NaturalAskEngine._response`: `ok`, `engine` ("deterministic-command-center"), `question`, `intent`, `answer`, `result: {rows, count}`, `workflow` (list of `{step, source, operation}` describing the internal query pipeline), `provenance: {scope: "current-memory-and-command-registry", engine: "deterministic-workflow"}`, plus intent-specific extras (`selected`, `events`, `total_count`, `status_counts`, `target`, `choices`, `ambiguous`, `names`, `ips`, `macs`, `summary`, `neighbors`, `comparison`, `evidence`, `attachment`, `kind_counts`, `status`, `suggestions`). When the intent is `command_plan` (or `command_followup`), the payload additionally carries `mode: "command"` and `command_plan: {action, label, description, args, command, status, missing_args, read_only, writes_local, risk_level, safety_class, state_effects, output_type, run_supported, requires_confirmation, reason, execution_hint, alternatives}`. `status` is one of `needs_clarification` / `blocked` / `preview_only` / `ready`.
- **Exit codes:** `VALIDATION(6)` if `payload["ok"]` is false (no match, ambiguous target resolved to zero rows treated as not-found, etc.) or `--execute` failed a precondition (see `ask-alias-*`/`commands-run` style gating logic in `execute_ask_plan`: `VALIDATION` for an unknown/missing-plan/missing-args action, `CONFIRM_REQUIRED(7)` for a preview-only/config/danger action or missing `--confirm`); otherwise `SUCCESS(0)`, or, when `--execute` actually runs a subprocess, whatever exit code that child command returns.
- **Real example:** `netrune ask "How many APs are offline in ZONE10?"` → text: `12 APs for ZONE10; 8 online, 4 offline.` with `--json` exposing all 12 AP rows under `result.rows` (invisible in plain-text mode per the gap above).
- **Related commands:** `ask-chat`, `ask-patterns`, `ask-alias-set`/`ask-alias-remove`, `commands-run` (the generic executor `ask`'s command-plan half ultimately targets), `commands-show`.

#### `netrune ask` (id: `ask-chat`)
- **Purpose:** Open a stateful, multi-turn REPL over the same deterministic ask engine, with follow-up/session memory.
- **Exact syntax:** `netrune ask` (no arguments; any arguments route to `ask-query`/`ask-alias`/`ask-patterns`/`ask-aliases` instead). Implemented by `ask_cli._cmd_ask_chat`.
- **Arguments:** None. `--json` is explicitly rejected: `app.usage_error("ask", "chat", opts, "Interactive Natural Ask is plain text only.", 'netrune ask "question" --json', VALIDATION)`.
- **Preconditions / gating:** None beyond the `--json` rejection above. Works both as a real TTY (prompts `ask> `, prints a banner) and non-interactively (reads one line from stdin per turn, stops at EOF or a blank line).
- **Step-by-step behavior:** Maintains `session = {"history": []}` across turns. Recognizes slash-commands before treating input as a question: `/exit`, `/quit`, `exit`, `quit` (breaks loop, returns `SUCCESS`); `/patterns`/`/help` (prints every example from `QUESTION_PATTERNS`); `/history` (dumps `session["history"]` as JSON, or "No session history."); `/reset` (clears the session dict); `/alias phrase = target` (calls `app.natural_ask.set_alias`). Any other input is passed to `ask_payload(app, question, opts, session=session)`, and the result is folded back into the session via `app.natural_ask.update_session(question, payload, session)` (this is what powers `last_result`/`last_target`/`last_command_plan` used by `_session_followup`/`_command_followup` on the *next* turn).
- **Side effects:** None beyond whatever a `/alias` command or (not directly supported here — chat mode never calls `execute_ask_plan`) writes; **chat mode cannot execute command plans at all**, it only ever previews them, since there is no `--execute` equivalent inside the REPL.
- **Output shape, table/text mode:** Each turn prints a blank line, then `answer>` (styled bold cyan if color is enabled) on its own line, then `_format_ask_text(payload)` (same formatter/known-rows-gap as `ask-query`).
- **Output shape, `--json` mode:** Not supported (rejected at entry, see above).
- **Exit codes:** `VALIDATION(6)` if invoked with `--json`; `SUCCESS(0)` on `/exit`/`/quit`/EOF/`KeyboardInterrupt`, or when stdin drains in non-interactive mode.
- **Real example:** `netrune ask` → `Netrune Ask` banner → `ask> where is SITE-SQ21-AP161 connected?` → an `ap_location` answer → `ask> where is it now?` is unlikely to resolve via session follow-up (that keys off "them/those/these/their/that list", not singular pronouns) but a plan follow-up like `ask> run it` after a command-plan turn will reuse `session["last_command_plan"]`.
- **Related commands:** `ask-query`, `ask-patterns`, `ask-alias-set`/`ask-alias-remove`.

#### `netrune ask patterns` (id: `ask-patterns`)
- **Purpose:** List every supported retrieval intent and command-center example question.
- **Exact syntax:** `netrune ask patterns` (no arguments). Dispatch: `payload = app.natural_ask.patterns_payload()`.
- **Arguments:** None.
- **Preconditions / gating:** None; always read-only.
- **Step-by-step behavior:** `NaturalAskEngine.patterns_payload()` returns the full `QUESTION_PATTERNS` list (20 retrieval intents + the appended `command_plan` intent) verbatim, plus a `count` of total example strings and a fixed `notes` list describing the ask engine's operating rules.
- **Side effects:** None.
- **Output shape, table/text mode:** `app.render_table(rows, ["intent", "purpose", "examples"])` where `examples` is every example string ` | `-joined per intent.
- **Output shape, `--json` mode:** `{ok, engine: "deterministic-command-center", patterns: QUESTION_PATTERNS, count, notes}`.
- **Exit codes:** Always `SUCCESS(0)`.
- **Real example:** `netrune ask patterns` → a 21-row table, one row per intent (`ap_on_switch`, …, `command_plan`).
- **Related commands:** `ask-chat`'s `/patterns` slash command surfaces the same data inline.

#### `netrune ask aliases` (id: `ask-aliases`)
- **Purpose:** List durable deterministic phrase→target aliases (e.g. "engineering office" → "engg-ofc-sw01").
- **Exact syntax:** `netrune ask aliases` (no arguments).
- **Arguments:** None.
- **Preconditions / gating:** None.
- **Step-by-step behavior:** `rows = app.natural_ask.aliases()` → `SELECT phrase,target,created_at,updated_at FROM ask_aliases ORDER BY phrase`.
- **Side effects:** None (read-only SQLite select).
- **Output shape, table/text mode:** `app.render_table(rows, ["phrase", "target", "updated_at"])`.
- **Output shape, `--json` mode:** `{"ok": true, "rows": [...], "count": N}` (raw rows, `created_at`/`updated_at` as epoch integers, not ISO-stamped — unlike most other list endpoints, `aliases()` does not pass rows through `timestamp_rows`).
- **Exit codes:** Always `SUCCESS(0)`.
- **Real example:** `netrune ask aliases` → table of every alias currently defined.
- **Related commands:** `ask-alias-set`, `ask-alias-remove`.

#### `netrune ask alias set '<phrase>' '<alias_target>'` (id: `ask-alias-set`)
- **Purpose:** Create or update a durable deterministic phrase alias, used by `apply_aliases`/`resolve_alias` to rewrite loose site/device phrasing before matching.
- **Exact syntax:** `netrune ask alias set '<phrase>' '<alias_target>'`. In `ask_cli.dispatch`, this requires `verb == "alias"` and `args[1].lower() == "set"` with at least 4 total tokens (`ask`, `alias`, `set`, phrase, then everything after is joined with spaces as the target — so the target need not be quoted as one shell word, only the phrase's own boundary matters via positional index).
- **Arguments:** `phrase` (required, `args[2]`), `alias_target` (required, `" ".join(args[3:])`). `NaturalAskEngine.set_alias` collapses internal whitespace on both and rejects empty values: `"Alias requires both a phrase and a target."`.
- **Preconditions / gating:** None beyond non-empty phrase/target; this is a plain local-state write, no `--confirm` required at the CLI-verb level (though `command_for_action("ask-alias-set", ...)` marks `writes_local=True`).
- **Step-by-step behavior:** `set_alias` does a case-insensitive lookup for an existing `created_at` (preserving original creation time on update), then `INSERT OR REPLACE INTO ask_aliases(phrase,target,created_at,updated_at) VALUES(?,?,?,?)`.
- **Side effects:** One SQLite upsert into `ask_aliases`.
- **Output shape, table/text mode:** `f"Alias saved: {phrase} -> {target}"` or the error string if it failed.
- **Output shape, `--json` mode:** `{"ok": true, "phrase", "target", "created_at", "updated_at"}` or `{"ok": false, "error": ...}`.
- **Exit codes:** `SUCCESS(0)` on success; `VALIDATION(6)` if phrase/target empty.
- **Real example:** `netrune ask alias set 'engineering office' 'engg-ofc-sw01'` → `Alias saved: engineering office -> engg-ofc-sw01`.
- **Related commands:** `ask-alias-remove`, `ask-aliases`; also directly reachable as a command-center action via `_command_matches`' `ask-alias-set` regex rule from a natural question like *"set alias engineering office to engg ofc"*.

#### `netrune ask alias remove '<phrase>'` (id: `ask-alias-remove`)
- **Purpose:** Remove a durable deterministic phrase alias.
- **Exact syntax:** `netrune ask alias remove '<phrase>'` (verbs `remove`, `delete`, `unset` are all accepted synonyms in `ask_cli.dispatch`, requiring at least 3 tokens after `ask alias`).
- **Arguments:** `phrase` (required, `" ".join(args[2:])`).
- **Preconditions / gating:** None; fails cleanly if the phrase doesn't exist.
- **Step-by-step behavior:** `NaturalAskEngine.remove_alias` looks up the row case-insensitively; if absent returns `{"ok": false, "error": f"Alias not found: {phrase}"}`; otherwise `DELETE FROM ask_aliases WHERE lower(phrase)=lower(?)` and returns the deleted row under `removed`.
- **Side effects:** One SQLite delete from `ask_aliases`.
- **Output shape, table/text mode:** `f"Alias removed: {payload['removed']['phrase']}"` or the error string.
- **Output shape, `--json` mode:** `{"ok": true, "removed": {phrase, target, created_at, updated_at}}` or `{"ok": false, "error": "Alias not found: ..."}`.
- **Exit codes:** `SUCCESS(0)` on success; `VALIDATION(6)` if not found.
- **Real example:** `netrune ask alias remove 'engineering office'` → `Alias removed: engineering office`.
- **Related commands:** `ask-alias-set`, `ask-aliases`.

---

### COMMANDS domain

#### `netrune commands list` (id: `commands-list`)
- **Purpose:** List every registered action in the structured command registry with its safety metadata.
- **Exact syntax:** `netrune commands list` (default verb when no args given).
- **Arguments:** None.
- **Preconditions / gating:** None.
- **Step-by-step behavior:** `rows = [app.command_dict(c) for c in app.command_registry()]` — `command_registry()` builds the full in-memory `CommandSpec` list (all actions across every domain, not just these 39); `command_dict` recomputes each entry's `arg_schema[].required` flags via `command_required_args` (which applies per-action "actually optional" overrides — see Cross-cutting notes).
- **Side effects:** None.
- **Output shape, table/text mode:** `app.render_table(rows, ["id", "domain", "risk_level", "read_only", "writes_local", "description"])`.
- **Output shape, `--json` mode:** `{"ok": true, "commands": [full CommandSpec.as_dict() per action]}` — each entry: `id, label, command (shlex-joined template), description, read_only, writes_local, args, domain, risk_level, preview_supported, run_supported, output_type, arg_schema, state_effects, safety_class, timeout_seconds, cancellable, examples`.
- **Exit codes:** Always `SUCCESS(0)`.
- **Real example:** `netrune commands list` → one row per registered action (well over the 39 in this document — this lists the entire platform registry).
- **Related commands:** `commands-show`, `commands-run`.

#### `netrune commands show '<action>'` (id: `commands-show`)
- **Purpose:** Show full metadata for one registry action by id.
- **Exact syntax:** `netrune commands show <action-id>`.
- **Arguments:** `action` (required positional; missing → `"Missing command id."` at default `USAGE(2)`). Unknown id → `f"Unknown command id: {rest[0]}"` at `VALIDATION(6)`.
- **Preconditions / gating:** None.
- **Step-by-step behavior:** `spec = app.command_spec(action)` (resolves through `command_aliases()` first, e.g. `ap-show`→`ap-list`), then `payload = app.command_dict(spec)`.
- **Side effects:** None.
- **Output shape, table/text mode:** `app.render_plain(payload)` — since `payload` is a dict without a `"rows"` key, this renders as either a colorized key/value block or plain `key: value` lines (list/dict-valued fields like `args`, `arg_schema`, `state_effects`, `examples` are dropped from the plain-text rendering by `render_plain`'s dict branch, which only prints non-list/non-dict values when color is off).
- **Output shape, `--json` mode:** `{"ok": true, "command": {...same shape as one row of commands-list...}}`.
- **Exit codes:** `USAGE(2)` if no action id given; `VALIDATION(6)` if unknown; else `SUCCESS(0)`.
- **Real example:** `netrune commands show backup-run` → full metadata for the `backup-run` action.
- **Related commands:** `commands-list`, `commands-run`; this is also how `_extract_command_args` resolves an `action` argument when the ask engine plans a `commands-show` request itself.

#### `netrune commands run '<action>' --preview` (id: `commands-run`)
- **Purpose:** Registry-backed generic executor/previewer — run (or preview) any registered action by id and freeform `--flag value` args, without needing that action's own noun-specific CLI form.
- **Exact syntax:** `netrune commands run <action-id> [--<argname> <value> ...] [--preview]`.
- **Arguments:** `action` (required positional, `rest[0]`); everything else in `rest[1:]` other than the literal token `--preview` is parsed by `app.parse_registry_args(raw)` into a free-form dict: any `--key value` pair becomes `{key.replace('-','_'): value}`; a `--key` with no following value (or one followed by another `--flag`) becomes a boolean `True`; leftover bare positionals populate `target` (first) and `positional` (all), and if there are 2+ positionals, `command` (space-joined tail), `mac` (last), and `interface` (second) are also inferred generically. Global `opts.depth`/`opts.max_nodes`/`opts.refresh_neighbors`/`opts.site` are merged in as defaults (`setdefault`) for compatible actions.
- **Preconditions / gating:** `--preview` (or the global `--dry-run` flag) short-circuits to a preview-only render of the exact resolved command line, never executing it. Without `--preview`/`--dry-run`: if the target `spec.run_supported` is `False`, refused at `CONFIRM_REQUIRED(7)` with `"This registry action is preview-only. Run its public CLI form directly if the documented policy permits it."`; if `spec.risk_level == "config"` and `--confirm` was not passed, refused at `CONFIRM_REQUIRED(7)` with `"Config-changing command requires --dry-run/--preview or --confirm."`.
- **Step-by-step behavior:** Resolve `spec = app.command_spec(action)` (unknown id → `VALIDATION(6)`); apply the two gates above; build the real argv via `cmd, read_only, writes_local = app.command_for_action(action, parsed)` (raises `PermissionError`→`CONFIRM_REQUIRED(7)`, or `ValueError`→`VALIDATION(6)` on bad/missing args); if previewing, emit the `shlex.join(cmd)` string and stop; otherwise `return app.run_subprocess(cmd, opts)`, spawning `netrune <resolved subcommand>` as a real child process.
- **Side effects:** Whatever the *resolved* action does (`command_for_action` is the same dispatch table `ask`'s command-plan half ultimately calls) — this command is a pure pass-through executor, not itself a source of new behavior. Notably, `commands-run` is itself in `command_for_action`'s hard-blocked action set (`{"device-config", "memory-prune", "serve-run", "ask-chat", "commands-run"}` all raise `PermissionError`) — meaning **`commands run commands-run ...` (recursively targeting itself) is refused**, as is targeting `ask-chat`/`device-config`/`memory-prune`/the stale `serve-run` id through this executor.
- **Output shape, table/text mode:** Preview: the raw resolved command string. Real run: whatever the spawned subprocess prints.
- **Output shape, `--json` mode:** Preview: `{"ok": true, "preview": true, "command": "<shlex-joined>", "read_only": bool, "writes_local": bool}`. Real run: whatever the spawned subprocess's own `--json` payload is (this command forwards `opts`, including `--json`, to the child).
- **Exit codes:** `USAGE(2)` if action id missing; `CONFIRM_REQUIRED(7)` for preview-only/config-without-confirm/blocked actions; `VALIDATION(6)` for unknown id or bad args; `SUCCESS(0)` for a successful preview; otherwise the spawned subprocess's own return code.
- **Real example:** `netrune commands run health-check --target ZONE34 --preview` → `netrune health check ZONE34`.
- **Related commands:** `commands-show` (to inspect an action's schema before running it), `commands-list`; `ask-query`'s command-plan path is a natural-language front end to the same `command_for_action` table.

---

### INGEST domain

#### `netrune ingest channels` (id: `ingest-channels`)
- **Purpose:** List declarative ingest channels (from `.toml` manifests under the active profile's `channels/` directory, plus any built-in channels) and sync them into SQLite.
- **Exact syntax:** `netrune ingest channels` (verb `list` is an accepted alias).
- **Arguments:** None.
- **Preconditions / gating:** None; no `--dry-run`/`--confirm` handling exists in this branch at all despite `writes_local: true`.
- **Step-by-step behavior:** `rows = app.ingest_manager.sync_channels()` — for every *valid* manifest, upserts `INSERT INTO ingest_channels(name,kind,enabled,manifest_path,config_json,created_at,updated_at) ... ON CONFLICT(name) DO UPDATE ...`; invalid manifests are appended to the result as `status: "invalid"` rows without a DB write; built-in channels already recorded in the table (`manifest_path='<built-in>'`) and not superseded by a file manifest are appended as `status: "built-in"` rows.
- **Side effects:** One SQLite upsert per valid manifest into `ingest_channels` (this is why the registry correctly marks `writes_local: true` even though the CLI verb is literally named "channels"/read-oriented).
- **Output shape, table/text mode:** `app.render_table(rows, ["status", "enabled", "name", "kind", "entity_kind", "manifest_path", "updated_at", "error"])`.
- **Output shape, `--json` mode:** `{"ok": <no invalid rows>, "profile": <name>, "rows": [{name, kind, enabled, entity_kind, source_id_field, observed_at_field, configuration, secret_references, schema_version, status, error, manifest_path, updated_at}, ...]}`.
- **Exit codes:** `SUCCESS(0)` if no row has `status == "invalid"`; else `PARTIAL(3)`.
- **Real example:** `netrune ingest channels` → table of every declared channel plus its validity status.
- **Related commands:** `ingest-validate`, `ingest-run`, `ingest-history`.

#### `netrune ingest validate` (id: `ingest-validate`)
- **Purpose:** Validate channel manifest `.toml` files without fetching any records or touching SQLite.
- **Exact syntax:** `netrune ingest validate`.
- **Arguments:** None.
- **Preconditions / gating:** None; genuinely side-effect-free (unlike `ingest channels`).
- **Step-by-step behavior:** `rows = [row minus "manifest" key for row in app.ingest_manager.validation()]` — parses every `*.toml` in the channels directory via `load_manifest`, catching exceptions per-file as `status: "invalid"`; then flags duplicate channel *names* across multiple files as invalid too (`"duplicate ingest channel name"`).
- **Side effects:** None (pure filesystem read + parse).
- **Output shape, table/text mode:** `app.render_table(rows, ["status", "name", "kind", "path", "error"])`, or `"No ingest channel manifests found."` if empty.
- **Output shape, `--json` mode:** `{"ok": <all valid>, "rows": [{name, kind, status, path, error}, ...]}`.
- **Exit codes:** `SUCCESS(0)` if every row is `"valid"`; else `VALIDATION(6)`.
- **Real example:** `netrune ingest validate` → confirms a newly added channel manifest parses correctly before running it.
- **Related commands:** `ingest-channels`, `ingest-run`.

#### `netrune ingest run '<channel>'` (id: `ingest-run`)
- **Purpose:** Execute one provenance-preserving ingest channel — fetch/parse records from its configured source and write accepted observations into SQLite.
- **Exact syntax:** `netrune ingest run <channel-name>`.
- **Arguments:** `channel` (required positional; missing → `"Missing channel name."` at `VALIDATION(6)`). Reads stdin as the record source when stdin is not a TTY (`stdin=sys.stdin if not sys.stdin.isatty() else None`) — relevant for manifests configured to read from stdin rather than a file/URL.
- **Preconditions / gating:** **None — verified gap.** `cmd_ingest`'s `run` branch has no `opts.dry_run` check anywhere; `netrune ingest run <channel> --dry-run` performs the real fetch and the real writes exactly like a normal invocation, despite the registry marking `preview_supported: true`.
- **Step-by-step behavior:** `result = app.ingest_manager.run(channel, stdin=...)` (raises `ValueError` for an unknown/invalid channel → `VALIDATION(6)`); on `result.accepted > 0`, additionally calls `app.state.sync_derived_state()` to reconcile the newly ingested observations into the canonical inventory/relationship tables.
- **Side effects:** Writes an `ingest_runs` row, `observations`/`observation_fields` rows for every accepted record, and (if any records were rejected) quarantine rows readable via `ingest rejects`; on acceptance, triggers a full derived-state reconciliation pass (touches canonical `devices`/`aps`/relationship tables).
- **Output shape, table/text mode:** `f"Ingest {channel}: {status}\nReceived: N | Accepted: N | Duplicates: N | Rejected: N\nRun: {run_id} | Recorded: {finished_at}"` plus an `Error:` line if `result.message` is set.
- **Output shape, `--json` mode:** `IngestRunV1.to_dict()` fields — `run_id, channel, status ("running"|"completed"|"partial"|"failed"), started_at, finished_at, received, accepted, duplicates, rejected, message, schema_version` — plus `ok` and, when records were accepted, `reconciliation` (the `sync_derived_state()` payload).
- **Exit codes:** `VALIDATION(6)` for a missing/unknown channel; `SUCCESS(0)` if `status == "completed"`; `PARTIAL(3)` if `"partial"`; `INTERNAL(10)` otherwise (i.e. `"failed"`).
- **Real example:** `netrune ingest run inventory-csv` → `Ingest inventory-csv: completed\nReceived: 40 | Accepted: 38 | Duplicates: 2 | Rejected: 0`.
- **Related commands:** `ingest-channels`, `ingest-history`, `ingest-rejects`, `ingest-observations`.

#### `netrune ingest history` (id: `ingest-history`)
- **Purpose:** Show ingest runs newest-first.
- **Exact syntax:** `netrune ingest history [--limit N]`.
- **Arguments:** None positional; respects the global `--limit` (default 100).
- **Preconditions / gating:** None.
- **Step-by-step behavior:** `SELECT run_id,channel,status,started_at,finished_at,received,accepted,duplicates,rejected FROM ingest_runs ORDER BY started_at DESC, id DESC LIMIT ?` — wrapped through `timestamp_rows` to attach `*_iso` fields.
- **Side effects:** None.
- **Output shape, table/text mode:** `app.render_table(rows, ["run_id", "channel", "status", "started_at", "finished_at", "received", "accepted", "duplicates", "rejected"])`.
- **Output shape, `--json` mode:** `{"ok": true, "rows": [...], "chronology": "newest_first"}`.
- **Exit codes:** Always `SUCCESS(0)` (no empty-result failure branch).
- **Real example:** `netrune ingest history --limit 10` → last 10 runs across all channels.
- **Related commands:** `ingest-run`, `ingest-rejects`.

#### `netrune ingest rejects '<run_id>'` (id: `ingest-rejects`)
- **Purpose:** Show redacted quarantine metadata for rejected records from one run (or all runs).
- **Exact syntax:** `netrune ingest rejects [<run_id>]`.
- **Arguments:** `run_id` — **effectively optional despite the registry's `arg_schema` marking it required.** `cmd_ingest`'s `rejects` branch is `rows = timestamp_rows(app.ingest_manager.rejects(rest[0] if rest else "", opts.limit))` — an empty string is a legal "all runs" query, and `App.command_required_args` explicitly overrides `ingest-rejects` to treat `run_id` as optional (it's in that method's per-action `optional` exception dict), so `netrune commands show ingest-rejects` and any `ask`-planned execution of this action will *not* flag `run_id` as missing even with none supplied.
- **Preconditions / gating:** None.
- **Step-by-step behavior:** `app.ingest_manager.rejects(run_id, limit)` reads quarantined-record metadata (error code/message, not the raw rejected payload) for the given run or across all runs.
- **Side effects:** None.
- **Output shape, table/text mode:** `app.render_table(rows, ["received_at", "run_id", "channel", "record_index", "error_code", "message"])`.
- **Output shape, `--json` mode:** `{"ok": true, "rows": [...], "chronology": "newest_first"}`.
- **Exit codes:** Always `SUCCESS(0)`.
- **Real example:** `netrune ingest rejects run-abc123` → the specific malformed records from that run.
- **Related commands:** `ingest-run`, `ingest-history`.

#### `netrune ingest observations '<channel>'` (id: `ingest-observations`)
- **Purpose:** Show append-only channel observations plus their field-level provenance.
- **Exact syntax:** `netrune ingest observations [<channel>]`.
- **Arguments:** `channel` — **also effectively optional**, same pattern as `ingest-rejects`: `channel = rest[0] if rest else ""`; an empty channel queries observations across every channel. `command_required_args` overrides `ingest-observations` to mark `channel` optional, contradicting the raw `arg_schema` "required" flag surfaced by `commands show`.
- **Preconditions / gating:** None.
- **Step-by-step behavior:** `SELECT id,entity_kind,stable_source_id,channel,observed_at,received_at,completeness,status,confidence,raw_evidence_hash FROM observations [WHERE channel=?] ORDER BY observed_at DESC,id DESC LIMIT ?`. If any rows come back, a second query pulls per-field provenance for exactly those observation ids: `SELECT observation_id,field_name,value_json,source,confidence,observed_at FROM observation_fields WHERE observation_id IN (...) ORDER BY observation_id DESC,field_name`, and each observation row gets a computed `field_count`.
- **Side effects:** None (both queries are reads).
- **Output shape, table/text mode:** Primary table `["observed_at", "entity_kind", "stable_source_id", "channel", "completeness", "status", "confidence", "field_count"]`, followed (if any fields exist) by a second "Field provenance" table `["observation_id", "field_name", "source", "confidence", "observed_at"]` (note: `value_json` is fetched but not rendered in the text table).
- **Output shape, `--json` mode:** `{"ok": true, "rows": [...with field_count...], "fields": [...full field rows including value_json...], "chronology": "newest_first"}`.
- **Exit codes:** Always `SUCCESS(0)`.
- **Real example:** `netrune ingest observations inventory-csv` → recent observations for that channel plus which specific fields each one contributed.
- **Related commands:** `ingest-run`, `ingest-channels`.

---

### INIT domain

#### `netrune init` (id: `init-run`)
- **Purpose:** Create/ensure the current profile's neutral state directories exist and report which host capabilities (tools) are available.
- **Exact syntax:** `netrune init [--migrate-legacy]`. **Not represented in the registry's `arg_schema` (which lists no args at all)** — `cmd_init` actually checks `migrate = "--migrate-legacy" in args` directly against the raw arg list.
- **Arguments:** `--migrate-legacy` (optional flag, undeclared in the registry). No other arguments accepted; `init` always operates on `self.paths.profile` (whichever profile is currently active — there is no way to target a different profile from this command).
- **Preconditions / gating:** **None — verified gap.** There is no `opts.dry_run` handling in `cmd_init` at all. `netrune init --migrate-legacy --dry-run` performs the real legacy-profile migration copy (`app.profile_store.migrate_legacy("legacy-local")`) exactly as without `--dry-run`, despite the registry marking `preview_supported: true`.
- **Step-by-step behavior:** Checks presence of 10 host tools via `shutil.which`: required (`ssh`, `ping`, `ip`) and optional (`gpg`, `sudo`, `snmpwalk`, `iperf3`, `speedtest`, `traceroute`, `ethtool`), each tagged with the capability it unlocks. If `--migrate-legacy`, runs `app.profile_store.migrate_legacy("legacy-local")` (copies legacy `~/.config/netsnmp`/`~/.cache/netsnmp` state into the active profile's private directories without deleting the source — same routine `profile-migrate-legacy` uses, just hardcoded to the `"legacy-local"` destination name). Builds a `next_commands` suggestion list (`netrune config show`, conditionally `netrune config set ssh_user <username>` if none is valid, `netrune ingest channels`, `netrune diagnose doctor`).
- **Side effects:** Directory creation for the active profile's config/state/cache dirs (idempotent — this happens implicitly via profile resolution, not a new write here specifically); if `--migrate-legacy`, real file copies into the profile's private storage.
- **Output shape, table/text mode:** `Netrune profile initialized: <profile>\nConfig: ...\nState: ...\nCache: ...\n\n<checks table>\n\nMissing required tools: <list>` (or `"Required capabilities are available."`) `\n\nNext:\n  <next_commands...>`.
- **Output shape, `--json` mode:** `{"ok": <all required tools present>, "profile", "paths": ProfileLayout.to_dict(), "checks": [{command, required, available, path, capability}], "migration": <migrate_legacy() payload or null>, "next_commands": [...]}`.
- **Exit codes:** `SUCCESS(0)` if every *required* tool (`ssh`, `ping`, `ip`) is available; `PARTIAL(3)` otherwise.
- **Real example:** `netrune init` → confirms `ssh`/`ping`/`ip` are present, flags `iperf3`/`speedtest` as missing if not installed.
- **Related commands:** `profile-migrate-legacy` (the non-hardcoded, name-taking version of the same migration), `profile-create`/`profile-use` (what a fresh `setup poller`/`setup local` actually calls instead of `init`).

---

### PATH domain

#### `netrune path inspect '<endpoint>' --vlan '<vlan>'` (id: `path-inspect`)
- **Purpose:** Inspect a bounded Layer 2/Layer 3 forwarding path from the core toward one endpoint on one VLAN, combining cached topology with optional live read-only device evidence, and persist the result.
- **Exact syntax:** `netrune path inspect <endpoint> --vlan <1-4094> [--from <source>] [--to <destination>] [--cached|--hybrid|--live] [--refresh] [--depth N] [--max-nodes N] [--explain]`. Delegated entirely to `path_cli.dispatch`, which builds a `PathRequestV1` and calls `app.path_inspector.inspect(request, opts)`.
- **Arguments:** `endpoint` (required — MAC, IP, or hostname-like token; a bare positional or `--vlan`-tagged value both work), `vlan` (required, `1`–`4094`, validated both by `path_cli` and again by `PathRequestV1.__post_init__`); optional `--from`/source, `--to`/destination, mode flags (`--cached` sets cached-only, `--hybrid` is the default, `--live` forces live probing, `--refresh` keeps hybrid mode but sets `opts.refresh_neighbors = True`), `--explain` (adds a plain-English evidence footer), `depth`/`max_nodes` inherited from global `--depth`/`--max-nodes` (default depth 8, max_nodes from `opts.max_nodes`). Missing endpoint or vlan → `"Endpoint and --vlan are required."` at `VALIDATION(6)`.
- **Preconditions / gating:** `opts.dry_run` **forces `mode = "cached"`** (skips all live device reads) but **does not prevent the run from executing or persisting** — a `path_runs`/`path_hops`/`path_findings` row set is still written even under `--dry-run`. For `live`/`hybrid` modes, the whole inspection runs inside `app.vault_session_scope(opts, minutes=30)` — a single vault-password prompt/session covers every device read this one run needs (forwarding-table walk, VLAN inspection, spanning tree, capability collection, and any switch-wide MAC search), rather than prompting per device.
- **Step-by-step behavior (`PathInspector.inspect`):**
  1. Resolve the source (core) switch from `--from` or the configured `core_switch_ip`/`core_switch`.
  2. Resolve the endpoint's cached attachment (switch/port) from relationship memory.
  3. If the endpoint is a MAC and mode is `live`/`hybrid` and no explicit destination was given: attempt a **live forwarding-table (FDB) walk** hop-by-hop from the source toward the endpoint.
  4. If that walk didn't complete, and `app.locate_endpoint_live` is available, fall back to an **exhaustive live search** across inventory switches for the MAC (covers cases where the hop-by-hop walk dead-ends on an uplink port even though other switches do see the endpoint).
  5. If still no live path, **BFS the cached topology graph** (bounded by `--depth`/`--max-nodes`) from source to the resolved destination switch.
  6. Per hop (endpoint-to-core order in output; computed core-to-endpoint internally then reversed), in `live`/`hybrid` mode: live VLAN inspection (`inspect_vlan_node`) to classify `vlan_state`, trunk-membership checks on both link directions, a spanning-tree read (`inspect_spanning_tree`) to catch a blocking/discarding port even when the VLAN is correctly trunked, an L3/SVI termination check on the source hop only (`inspect_path_layer3`), and a generic capability-evidence pass (`collect_path_capabilities` → STP/LAG/SVI/VRF/routes/ARP-ND) that can independently mark a hop `blocked` with a specific finding code (`STP_BLOCKING`, `LAG_DOWN`, `SVI_DOWN`, `VRF_MISMATCH`, `ROUTE_MISSING`, `NEIGHBOR_RESOLUTION_MISSING`).
  7. Compute overall `status`: `BLOCKED` if any critical finding exists; `UNKNOWN` if no hops were resolved at all; `PARTIAL` if there were live failures, unknown-forwarding hops, any warning/error finding, or the mode was plain `cached`; otherwise `COMPLETE`. `confidence` is the mean per-hop confidence, capped at 74 whenever status is `PARTIAL`/`UNKNOWN`.
  8. Persist via `PathInspector._persist` and return the `PathResultV1`.
- **Side effects:** Writes one row each to `path_runs`, `path_hops` (one per resolved hop), and `path_findings` (one per finding) — this happens on every call including dry-run/cached mode. In `live`/`hybrid` mode, also triggers real SSH/read-only device sessions for every hop inspected (VLAN, STP, L3, capability reads), and may call `state.record_mac_observation` when a live FDB walk completes.
- **Output shape, table/text mode:** `f"{status}: {summary}\nConfidence: {confidence}% | VLAN: {vlan} | Mode: {mode} | Recorded: {finished_at} | Run: {run_id}\n\nHop path\n<hops table>\n\nFindings\n<findings block>"`, where the hop table columns are `["sequence", "device_name", "management_ip", "ingress_interface", "egress_interface", "layer", "vlan_state", "forwarding_state", "confidence"]` and the findings block (`render_findings`) prints, per finding, a heading line `SEVERITY  CODE  device_id  interface` followed by an indented message line. `--explain` appends a fixed evidence-methodology paragraph.
- **Output shape, `--json` mode:** `PathResultV1.to_dict()`: `run_id, request (with requested_at_iso), status, confidence, started_at, finished_at, hops (each with evidence_observed_at_iso), findings (each with evidence_observed_at_iso), summary, schema_version`, plus `ok` (true for `COMPLETE`/`PARTIAL`, false otherwise).
- **Exit codes:** `VALIDATION(6)` for bad/missing arguments; else `SUCCESS(0)` if `status == "COMPLETE"`; `UNREACHABLE(4)` if `"BLOCKED"`; `PARTIAL(3)` for anything else (`"PARTIAL"` or `"UNKNOWN"` both map to the same exit code — the JSON `status` field is the only way to tell them apart programmatically).
- **Real example:** `netrune path inspect 02:00:00:00:00:25 --vlan 120 --hybrid` → `PARTIAL: Built a 3-switch device-to-core path, but some evidence is stale, missing, or unparsed.` with a 3-row hop table and one or more warning findings.
- **Related commands:** `path-history`, `path-show`, `path-findings`; internally reuses `app.inspect_vlan_node`/`app.inspect_spanning_tree`/`app.inspect_path_layer3`/`app.collect_path_capabilities`/`app.locate_endpoint_live` (shared with the `vlan`/`lookup` domains).

#### `netrune path history '<endpoint>' --vlan '<vlan>'` (id: `path-history`)
- **Purpose:** Show chronological path inspections (optionally filtered to one endpoint/VLAN) with reusable short run references.
- **Exact syntax:** `netrune path history [<endpoint>] [--vlan <1-4094>]`.
- **Arguments:** `endpoint` and `vlan` are **both optional at the CLI and in the effective registry schema**, despite the given registry `arg_schema` marking both `required: true` — `path_cli.dispatch`'s `history` branch defaults `endpoint = ""` and `vlan = 0` when omitted (`netrune path history` alone is valid and lists every recorded run), and `App.command_required_args` explicitly overrides `path-history` to treat both `endpoint` and `vlan` as optional. A malformed `--vlan` yields `"--vlan must be an integer."`; out of range yields `"--vlan must be between 1 and 4094."` (both `VALIDATION(6)`).
- **Preconditions / gating:** None.
- **Step-by-step behavior:** `PathInspector.history(endpoint, vlan, limit)` — matches MAC-formatted endpoints via a normalized (colon/dot/dash/space-stripped) comparison, otherwise a case-insensitive exact match; optional VLAN filter; `SELECT run_id,status,endpoint,vlan,source,destination,mode,depth,confidence,started_at,finished_at,summary FROM path_runs [...] ORDER BY started_at DESC,run_id DESC LIMIT ?`, then attaches a `run_ref` (first 12 hex chars after the `path-` prefix) to each row for convenient reuse with `path show`.
- **Side effects:** None.
- **Output shape, table/text mode:** `app.render_table(rows, ["started_at", "status", "endpoint", "vlan", "source", "destination", "mode", "confidence", "run_ref"])`.
- **Output shape, `--json` mode:** `{"ok": true, "rows": [...with run_ref, *_iso timestamps...], "chronology": "newest_first", "time_format": "ISO 8601 UTC"}`.
- **Exit codes:** Always `SUCCESS(0)` (no PARTIAL-on-empty branch here, unlike `path findings`).
- **Real example:** `netrune path history 02:00:00:00:00:25 --vlan 120` → every prior inspection of that MAC on VLAN 120.
- **Related commands:** `path-show` (open one specific run by the `run_ref` this command prints), `path-inspect`.

#### `netrune path show '<reference>' --vlan '<vlan>'` (id: `path-show`)
- **Purpose:** Open one previously recorded path run by full run id, unique id prefix, endpoint(+VLAN), or the literal `last`/`latest`.
- **Exact syntax:** `netrune path show <reference> [--vlan <1-4094>]`.
- **Arguments:** `reference` (required — missing → `"Missing path run id."` at `VALIDATION(6)`); `vlan` is optional (registry's raw schema marks it required, but `command_required_args` overrides `path-show` to treat `vlan` as optional, and the CLI itself only uses it as a tie-breaker when `reference` is `last`/`latest` or an endpoint string, not when it's a run id).
- **Preconditions / gating:** None.
- **Step-by-step behavior (`PathInspector.show`):** Tries, in order: (1) exact `run_id` match; (2) if `reference` is `"last"`/`"latest"`, the most recent run (optionally VLAN-filtered); (3) if `reference` starts with `path-`, treats it as a hex prefix (must be ≥8 hex chars after `path-`, else `ValueError`) and requires the prefix to resolve to exactly one run (ambiguous prefixes raise `ValueError` listing the candidates); (4) otherwise treats `reference` as an endpoint (MAC-normalized or literal) and finds the most recent matching run, optionally VLAN-filtered. Not found → `None` → CLI returns `"Path run not found: <ref>"` at `VALIDATION(6)`. Once a run row is found, `_compose_result` rebuilds hops/findings from the normalized `path_hops`/`path_findings` tables (falling back to the legacy `result_json` blob only for pre-migration rows where those tables are empty).
- **Side effects:** None (pure read).
- **Output shape, table/text mode:** `f"{status}: {summary}\nConfidence: {confidence}% | VLAN: {vlan} | Recorded: {finished_at} | Run: {run_id}\n\n<hops table>\n\nFindings\n<findings block>"` — same hop columns and findings format as `path-inspect`.
- **Output shape, `--json` mode:** Same shape as `path-inspect`'s JSON output (it's the same `PathResultV1`-shaped dict, reconstructed rather than freshly computed), merged under `{"ok": true, ...}`.
- **Exit codes:** `VALIDATION(6)` for missing/malformed reference or vlan, ambiguous prefix, or not-found; else `SUCCESS(0)`.
- **Real example:** `netrune path show last --vlan 120` → the most recent VLAN-120 path run. `netrune path show path-9f3a2b1c` → that run by 8-hex-char prefix.
- **Related commands:** `path-history` (source of the `run_ref` values), `path-inspect`.

#### `netrune path findings` (id: `path-findings`)
- **Purpose:** Query findings (not full runs) across every recorded path inspection, with a frequency summary of the most common finding codes.
- **Exact syntax:** `netrune path findings [--severity critical|error|warning|info]`.
- **Arguments:** `--severity` (optional; invalid value → `"--severity must be critical, error, warning, or info."` at `VALIDATION(6)`). Any other unrecognized token → `f"Unknown path findings option: {rest[index]}"` at `VALIDATION(6)`. Respects global `--limit`.
- **Preconditions / gating:** None.
- **Step-by-step behavior:** Two queries: (1) `SELECT f.code,f.severity,f.device_id,f.interface,f.message,f.confidence,r.endpoint,r.vlan,r.status,r.started_at FROM path_findings f JOIN path_runs r ON r.run_id=f.run_id [WHERE f.severity=?] ORDER BY r.started_at DESC,f.id DESC LIMIT ?` (this is the reason the code comment in `path_cli.py` explicitly calls out: "path_findings and path_hops were written on every run and never read... Querying them across runs is what the normalised tables are for" — this endpoint is the first cross-run reader of that table); (2) `SELECT code,severity,COUNT(*) AS occurrences FROM path_findings GROUP BY code,severity ORDER BY occurrences DESC LIMIT 20` for the frequency summary.
- **Side effects:** None.
- **Output shape, table/text mode:** `f"Path findings ({N} shown)\n<detail table>\n\nMost frequent\n<counts table>"` — detail columns `["severity", "code", "device_id", "interface", "endpoint", "vlan", "started_at"]`, counts columns `["severity", "code", "occurrences"]`.
- **Output shape, `--json` mode:** `{"ok": true, "rows": [...detail...], "count": N, "by_code": [...top-20 code/severity/occurrences...]}`.
- **Exit codes:** `VALIDATION(6)` for a bad `--severity` or unknown flag; `SUCCESS(0)` if any rows matched; `PARTIAL(3)` if zero rows.
- **Real example:** `netrune path findings --severity critical` → every `STP_BLOCKING`/`VLAN_NOT_DEFINED`/etc. finding ever recorded, newest first, plus the top 20 most frequent finding codes overall.
- **Related commands:** `path-show` (see a finding in the context of its full run), `path-inspect`.

---

### PLUGIN domain

#### `netrune plugin list` (id: `plugin-list`)
- **Purpose:** Discover installed plugin entry points across all supported/legacy plugin groups without importing any disabled plugin's code.
- **Exact syntax:** `netrune plugin list` (verb `discover` is an accepted alias).
- **Arguments:** None.
- **Preconditions / gating:** None.
- **Step-by-step behavior:** `PluginManager.discover()` reads `importlib.metadata.entry_points()` across `netrune.ingest`/`netrune.device_drivers`/`netrune.parsers`/`netrune.exporters` (and their legacy `netops.*` equivalents), cross-references the profile's `plugins.toml` enabled set (`{group}:{name}` ids), and marks each discovered entry `enabled`/`disabled`, or `collision` if two installed distributions expose the same group/name; any id listed as enabled in `plugins.toml` but not actually discoverable is reported separately with `load_status: "missing"`. **Nothing is imported at this stage** — this is purely `importlib.metadata` introspection.
- **Side effects:** None.
- **Output shape, table/text mode:** `app.render_table(rows, ["enabled", "load_status", "group", "name", "distribution", "version", "api_version", "error"])`.
- **Output shape, `--json` mode:** `{"ok": true, "rows": [PluginDescriptorV1 fields], "groups": [the 4 current PLUGIN_GROUPS]}`.
- **Exit codes:** Always `SUCCESS(0)`.
- **Real example:** `netrune plugin list` → every discoverable plugin entry point and whether it's currently enabled.
- **Related commands:** `plugin-enable`, `plugin-disable`, `plugin-check`, `plugin-groups`.

#### `netrune plugin enable '<plugin_id>'` (id: `plugin-enable`)
- **Purpose:** Enable one trusted plugin entry point (`<group>:<name>`) in the active profile, verifying it actually loads before committing.
- **Exact syntax:** `netrune plugin enable <group>:<name>` — id must match `PLUGIN_NAME_RE` and the group must be one of the discovery groups (missing id → `"Missing plugin id (<group>:<name>)."` at `VALIDATION(6)`).
- **Arguments:** `plugin_id` (required, format `<group>:<name>`).
- **Preconditions / gating:** `--dry-run` short-circuits to a preview (`{"ok": true, "dry_run": true, "plugin": descriptor, "would_enable": true}`) without writing `plugins.toml`.
- **Step-by-step behavior (`PluginManager.set_enabled`):** Validates the id resolves to exactly one discovered plugin (raises for not-found/ambiguous). Adds the id to the enabled set and atomically rewrites `plugins.toml`. **Then immediately attempts to load it** via `load_enabled()`, validating the implementation exposes the interface its group requires (`read_records` for ingest, `parse` for parsers, `export` for exporters, a `DeviceDriver` instance or `netrune_device_drivers()`/`netops_device_drivers()` callable for device drivers). If it fails to load or load status isn't `"loaded"`, the write is **rolled back** (`plugins.toml` restored to its previous enabled set) and a `ValueError` is raised with the load error as detail.
- **Side effects:** One atomic rewrite of the active profile's `plugins.toml` (mode 0600, in its own 0700 config dir), which is reverted automatically if the post-enable load-and-verify step fails.
- **Output shape, table/text mode:** `f"Plugin {plugin_id} is now enabled."`, or the dry-run preview line.
- **Output shape, `--json` mode:** `{"ok": true, "plugin": PluginDescriptorV1.to_dict()}` (post-load descriptor, `load_status: "loaded"`).
- **Exit codes:** `VALIDATION(6)` for missing id or any `ValueError` (not found, ambiguous, or failed-to-load-and-rolled-back); else `SUCCESS(0)`.
- **Real example:** `netrune plugin enable netrune.parsers:custom_csv` → `Plugin netrune.parsers:custom_csv is now enabled.` (or a rollback error if the parser module doesn't expose `parse()`).
- **Related commands:** `plugin-disable`, `plugin-list`, `plugin-check`.

#### `netrune plugin disable '<plugin_id>'` (id: `plugin-disable`)
- **Purpose:** Disable one plugin in the active profile.
- **Exact syntax:** `netrune plugin disable <group>:<name>`.
- **Arguments:** `plugin_id` (required, same format/validation as `plugin-enable`).
- **Preconditions / gating:** `--dry-run` previews without writing, same shape as `plugin-enable`'s dry run (`would_enable: false`).
- **Step-by-step behavior:** `PluginManager.set_enabled(plugin_id, False)` — validates the id resolves to a known descriptor, removes it from the enabled set, atomically rewrites `plugins.toml`. No load-and-verify step is needed for disabling (only enabling re-verifies).
- **Side effects:** One atomic rewrite of `plugins.toml`.
- **Output shape, table/text mode:** `f"Plugin {plugin_id} is now disabled."`.
- **Output shape, `--json` mode:** `{"ok": true, "plugin": PluginDescriptorV1.to_dict()}` (`enabled: false`).
- **Exit codes:** `VALIDATION(6)` for missing id or unknown plugin; else `SUCCESS(0)`.
- **Real example:** `netrune plugin disable netrune.parsers:custom_csv`.
- **Related commands:** `plugin-enable`, `plugin-list`.

#### `netrune plugin check '<group>'` (id: `plugin-check`)
- **Purpose:** Actually load every currently-enabled plugin (optionally scoped to one group) and report per-plugin load success/failure, isolating any one plugin's failure from the rest.
- **Exact syntax:** `netrune plugin check [<group>]` (verb `load` is an accepted alias).
- **Arguments:** `group` — optional; if given, must be one of the discovery groups (`netrune.ingest`, `netrune.device_drivers`, `netrune.parsers`, `netrune.exporters`, or their legacy `netops.*` equivalents) or `PluginManager.load_enabled` raises `ValueError`.
- **Preconditions / gating:** None; this is a read/diagnostic action, though it does import real plugin code (unlike `plugin list`).
- **Step-by-step behavior:** `PluginManager.load_enabled(group)` iterates every id currently marked enabled in `plugins.toml`, attempts to import and instantiate each, runs the same interface validation `plugin-enable` runs, and records per-plugin `load_status`/`error` independently — one plugin's import failure does not prevent the others from being checked.
- **Side effects:** Real Python imports of enabled plugin modules occur (this is the one plugin-domain command that actually executes third-party code, by design — it's the explicit "did my enabled plugins survive an upgrade" check).
- **Output shape, table/text mode:** `app.render_table(rows, ["load_status", "group", "name", "distribution", "version", "api_version", "error"])`.
- **Output shape, `--json` mode:** `{"ok": <all loaded>, "rows": [...], "driver_manifests": app.driver_manifest_report}`.
- **Exit codes:** `SUCCESS(0)` if every enabled plugin's `load_status == "loaded"`; else `PARTIAL(3)`.
- **Real example:** `netrune plugin check netrune.parsers` → confirms every enabled parser plugin still imports cleanly.
- **Related commands:** `plugin-list`, `plugin-enable`, `plugin-disable`.

#### `netrune plugin groups` (id: `plugin-groups`)
- **Purpose:** List the stable, currently-supported entry-point groups and their fixed policy statement.
- **Exact syntax:** `netrune plugin groups`.
- **Arguments:** None.
- **Preconditions / gating:** None.
- **Step-by-step behavior:** Returns one row per entry in `PLUGIN_GROUPS` (`netrune.ingest`, `netrune.device_drivers`, `netrune.parsers`, `netrune.exporters`) with a fixed policy string: `"trusted Python entry point; disabled until enabled; writes prohibited"` for all four — this is static text, not derived from any actual per-group write permission check.
- **Side effects:** None.
- **Output shape, table/text mode:** `app.render_table(rows, ["group", "policy"])`.
- **Output shape, `--json` mode:** `{"ok": true, "rows": [{group, policy}, ...]}`.
- **Exit codes:** Always `SUCCESS(0)`.
- **Real example:** `netrune plugin groups` → the 4-row fixed policy table.
- **Related commands:** `plugin-list`.

---

### PROFILE domain

#### `netrune profile list` (id: `profile-list`)
- **Purpose:** List every isolated Netrune profile known on this machine.
- **Exact syntax:** `netrune profile list`.
- **Arguments:** None.
- **Preconditions / gating:** None.
- **Step-by-step behavior:** `ProfileStore.list()` scans `<config_root>/profiles/*` for directories matching the profile name pattern, and for each reports whether `profile.toml` exists (`configured`) and its mtime (`updated_at`); marks whichever matches `active()` (read from the `active_profile` pointer file). If no profile directories exist yet but the layout resolved via explicit legacy env-var paths, synthesizes a single implicit row.
- **Side effects:** None.
- **Output shape, table/text mode:** `app.render_table(rows, ["active", "name", "configured", "updated_at"])`.
- **Output shape, `--json` mode:** `{"ok": true, "active": <name>, "rows": [{name, active, configured, updated_at}, ...]}`.
- **Exit codes:** Always `SUCCESS(0)`.
- **Real example:** `netrune profile list` → `default`, `lab`, `poller-1`, with `default` (say) flagged active.
- **Related commands:** `profile-create`, `profile-use`, `profile-show`.

#### `netrune profile show '<name>'` (id: `profile-show`)
- **Purpose:** Show one profile's XDG paths and non-secret settings.
- **Exact syntax:** `netrune profile show [<name>]` (verb `status` is an accepted alias).
- **Arguments:** `name` — **effectively optional despite the registry marking it required**: `name = rest[0] if rest else self.paths.profile` defaults to the currently active profile; `command_required_args` explicitly overrides `profile-show` to treat `name` as optional too, so `ask`'s command-plan preview will never flag it missing.
- **Preconditions / gating:** None.
- **Step-by-step behavior:** `ProfileStore.show(name)` resolves the target layout, loads `profile.toml` (validates `schema_version` matches `PROFILE_SCHEMA_VERSION`, raising `ValueError` on mismatch), and returns the flattened non-secret settings alongside the layout paths.
- **Side effects:** None (read-only; may raise if the profile's `profile.toml` schema is stale/incompatible, which surfaces as an `INTERNAL(10)` from the top-level dispatch handler since `cmd_profile` doesn't catch it specially).
- **Output shape, table/text mode:** `app.render_plain(payload)`.
- **Output shape, `--json` mode:** `{"ok": true, "name", "active": bool, "layout": ProfileLayout.to_dict(), "settings": {...}}`.
- **Exit codes:** Always `SUCCESS(0)` on the happy path (unhandled `ValueError` from a schema mismatch → `INTERNAL(10)`).
- **Real example:** `netrune profile show lab` → lab profile's config/state/cache/data directory paths and current settings.
- **Related commands:** `profile-list`, `profile-paths`, `profile-use`.

#### `netrune profile create '<name>'` (id: `profile-create`)
- **Purpose:** Create a fresh, neutral, isolated profile (directories + a default `profile.toml`/compatibility config) without activating it.
- **Exact syntax:** `netrune profile create <name>`.
- **Arguments:** `name` (required — missing → `"Missing profile name."` at `VALIDATION(6)`).
- **Preconditions / gating:** None (idempotent — safe to re-run against an existing profile name).
- **Step-by-step behavior (`ProfileStore.ensure`):** Creates `config_dir`, `state_dir`, `cache_dir`, `data_dir` (each `mkdir(parents=True, exist_ok=True)` then `chmod(0o700)`); writes `profile.toml` from the fixed `NEUTRAL_PROFILE` template only if it doesn't already exist (existing profiles are never overwritten); same for a `netsnmp.conf` compatibility shim; ensures `channels/` and `drivers/` subdirectories exist under config.
- **Side effects:** Filesystem: up to 4 new 0700 directories and up to 2 new default config files under the profile's private storage. Does **not** switch the active profile.
- **Output shape, table/text mode:** `f"Profile ready: {name}\nConfig: {config_dir}"`.
- **Output shape, `--json` mode:** `{"ok": true, "created": name, "layout": ProfileLayout.to_dict()}`.
- **Exit codes:** `VALIDATION(6)` if name missing; else `SUCCESS(0)`.
- **Real example:** `netrune profile create lab` → `Profile ready: lab`.
- **Related commands:** `profile-use` (switch to it), `profile-list`, `setup-poller`/`setup-local` (call this internally as their first provisioning step).

#### `netrune profile use '<name>'` (id: `profile-use`)
- **Purpose:** Select which profile future `netrune` invocations use by default.
- **Exact syntax:** `netrune profile use <name>`.
- **Arguments:** `name` (required — missing → `"Missing profile name."` at `VALIDATION(6)`).
- **Preconditions / gating:** None.
- **Step-by-step behavior (`ProfileStore.use`):** Calls `ensure(name)` first (creating the profile if it doesn't exist yet — `profile use` on a brand-new name silently also creates it), then atomically writes the profile name into the `active_profile` pointer file under the shared config root.
- **Side effects:** Writes/overwrites the single `active_profile` pointer file (0700 dir, atomic write); may also perform the same directory/file creation as `profile create` if the named profile is new. Affects only *future* process invocations (this process's own `app.paths` was already resolved at startup and is not retroactively changed).
- **Output shape, table/text mode:** `f"Active profile: {name}\nNew processes will use {config_dir}"`.
- **Output shape, `--json` mode:** `{"ok": true, "active": name, "layout": ProfileLayout.to_dict()}`.
- **Exit codes:** `VALIDATION(6)` if name missing; else `SUCCESS(0)`.
- **Real example:** `netrune profile use lab` → subsequent `netrune ...` calls (from new processes) operate against the `lab` profile's isolated state.
- **Related commands:** `profile-create`, `profile-list`, `profile-show`.

#### `netrune profile paths` (id: `profile-paths`)
- **Purpose:** Show the active profile's resolved XDG-style paths.
- **Exact syntax:** `netrune profile paths`.
- **Arguments:** None.
- **Preconditions / gating:** None.
- **Step-by-step behavior:** Returns `app.paths.profile_layout.to_dict()` directly — no store lookup, just the already-resolved layout for the process's active profile.
- **Side effects:** None.
- **Output shape, table/text mode:** One `key: value` line per path field.
- **Output shape, `--json` mode:** `{"ok": true, "profile": <active name>, "paths": {name, home, config_root, state_root, cache_root, data_root, config_dir, state_dir, cache_dir, data_dir, explicit_legacy_paths}}`.
- **Exit codes:** Always `SUCCESS(0)`.
- **Real example:** `netrune profile paths` → the active profile's directory tree.
- **Related commands:** `profile-show`, `profile-list`.

#### `netrune profile migrate-legacy '<name>'` (id: `profile-migrate-legacy`)
- **Purpose:** Copy legacy (pre-profile) `~/.config/netsnmp` / `~/.cache/netsnmp` state — including the old SQLite database — into a named private profile, without touching or deleting the legacy source.
- **Exact syntax:** `netrune profile migrate-legacy [<name>]` (verbs `migrate` and `export-legacy` are accepted aliases).
- **Arguments:** `name` — **also effectively optional**: `destination = rest[0] if rest else "legacy-local"`; `command_required_args` overrides `profile-migrate-legacy` to treat `name` as optional, matching the CLI's real default.
- **Preconditions / gating:** None; the operation is designed to be non-destructive and idempotent (skips files that already exist at the destination rather than overwriting).
- **Step-by-step behavior (`ProfileStore.migrate_legacy`):** `ensure(destination)` (creates the target profile if needed). Merges non-secret legacy environment keys and the legacy `netsnmp.conf` (minus anything that looks like a secret name) into the target's compatibility config, preferring existing target values over legacy ones if the target file was already customized. Copies every other file/subdirectory from legacy config/cache into the target (skipping `.env`, `*.tmp`, `*.lock`, and the legacy SQLite files specifically, which are handled separately), tightening permissions on every copied file (0600) and directory (0700) as it goes. Migrates the legacy SQLite database into `state_dir/netrune.sqlite3` via a dedicated schema-aware migration helper. Tracks which secret-looking environment keys were *not* imported (`pending_secret_names`) so the operator knows what still needs to be moved into the named-secrets store manually.
- **Side effects:** Real file copies (config/cache files, directories, the legacy database) into the target profile's private storage; original legacy files are never modified or deleted.
- **Output shape, table/text mode:** `f"Legacy migration prepared private profile {destination}. Original files were not changed.\nDatabase: {action} | Copied: {N} | Skipped: {N} | Pending named secrets: {N}"`.
- **Output shape, `--json` mode:** `{"ok": true, ...full migration manifest: database_migration, copied, skipped, pending_secret_names, ...}`.
- **Exit codes:** Always `SUCCESS(0)` on the happy path (name is never actually required, so there's no `VALIDATION` branch reachable through this verb in practice).
- **Real example:** `netrune profile migrate-legacy` → migrates into a profile literally named `legacy-local`. `netrune profile migrate-legacy lab-import` → migrates into `lab-import` instead.
- **Related commands:** `init-run` (its `--migrate-legacy` flag calls this exact method, hardcoded to the `"legacy-local"` destination), `profile-create`.

---

### SETUP domain

#### `netrune setup local --community '<community>'` (id: `setup-local`)
- **Purpose:** One-command provisioning of a full "look-at-it-here" install — collector, SQLite storage, and dashboards on this one machine.
- **Exact syntax:** `netrune setup local --community <community> [--collector-id <id>] [--profile-name <name>] [--retention <days>] [--publish <addr> --confirm] [--export-to <path>] [--push-to <url>] [--accept-push --confirm] [--watch <address:interface> ...] [--dry-run]`. **Only `--community` is represented in the command registry's `arg_schema`** — all the other flags exist and work only when invoking `netrune setup local` directly on the command line; they are invisible to `commands run setup-local`/`ask`'s command-plan machinery, which can only ever populate `community`.
- **Arguments:** `role` is the fixed positional `local` (or `poller`, handled by the sibling command below) — an unknown/missing role lists both roles' one-line descriptions and errors at `VALIDATION(6)`. `--community` (required for a fully working install — if omitted, the run still completes but "nothing can be read until one is set"). `--collector-id` (defaults to the local short hostname, lowercased). `--profile-name` (defaults to the role name, `"local"`). `--retention` (defaults to 180 days for `local`, 365 for `poller`). `--publish <address>` and `--accept-push` both **require `--confirm`** in the same invocation, or the whole command refuses to run at `VALIDATION(6)` with an explanation of what each flag exposes. `--watch <address:interface>` may be repeated any number of times; a malformed one (missing the `:interface` part) is recorded as a failed step rather than aborting the whole run.
- **Preconditions / gating:** `--dry-run` returns a full ordered plan list (`profile '<name>'`, `collector identity`, `SNMP community` or `SNMP community (not given)`, `database`, `<role> stack`, `services`, `linger`, one `watch <target>` per requested watch) without executing anything. `--publish`/`--accept-push` each independently require `--confirm` (this is the *only* enforcement point for this rule for `setup` — it hardcodes `--confirm` onto the `traffic stack init` call it delegates to internally, so `stack init`'s own equivalent check never actually fires from inside `setup`).
- **Step-by-step behavior (verified in order from `setup_cli.dispatch`):**
  1. **Profile**: `profile create <profile>` then `profile use <profile>` (both run "quietly" via `_dispatch_quietly`, which redirects the sub-invocation's stdout/stderr into a buffer so it doesn't pollute this command's own output, and swallows any `SystemExit`).
  2. **Identity**: writes `traffic_collector_id` (from `--collector-id` or the lowercased short hostname) and `traffic_retention_days` into the profile config via `app._write_profile_config_value`; also writes `traffic_export_path`/`traffic_push_url` if `--export-to`/`--push-to` were given.
  3. **SNMP community**: if `--community` was given, calls `write_snmp_community(app, community)` (see below); otherwise records a failed step noting nothing can be read yet.
  4. **Database**: `app.state.init_db()`.
  5. **Stack generate + start**: `traffic stack init` (with `--role collector` for the `poller` role, and `--publish <addr> --confirm`/`--accept-push --confirm` forwarded if set) followed by `traffic stack up` — both dispatched quietly; this is the step that actually generates and installs the systemd units / compose files and starts them.
  6. **Linger check**: `loginctl show-user $USER -p Linger --value` to determine whether user services survive a reboot; reports the exact `sudo loginctl enable-linger "$USER"` remediation command if not.
  7. **Watches**: for each `--watch ADDRESS:INTERFACE`, dispatches `traffic watch <address> <interface>` quietly.
- **Side effects:** New/updated profile directories and `profile.toml`; a rewritten `.env` file at `<config_dir>/.env` (mode 0600) if `--community` was given; profile config keys written for identity/retention/export/push; SQLite database initialized; generated systemd unit files / compose stack files on disk plus started services (via the delegated `traffic stack init`/`up`); zero or more `traffic watch` registrations (their own SQLite/config writes).
- **Output shape, table/text mode:** `f"{N}/{total} steps done.\n  {ok|TODO}  <step>  <detail>\n..."` followed by role-specific guidance (poller: reminders to add a watch and to hand readings over via `traffic export`/SSH pull; local: reminders to watch something and run `traffic dashboard`) and, if no community was given, a note plus the exact `.env` path to write one to manually.
- **Output shape, `--json` mode:** `{"ok": <all steps ok>, "role", "profile", "steps": [{step, ok, detail}, ...]}` (dry-run: `{"ok": true, "dry_run": true, "role", "profile", "plan": [...]}`).
- **Exit codes:** `VALIDATION(6)` for an unknown/missing role or a `--publish`/`--accept-push` without `--confirm`; `SUCCESS(0)` if every step succeeded; `PARTIAL(3)` if any step failed (including "no community given").
- **Real example:** `netrune setup local --community public --watch 192.0.2.10:Gi1/0/1` → 7+ steps reported done, ending with `Watch something:`/`Then look at it:  netrune traffic dashboard` guidance if no watch was actually supplied (irrelevant here since one was).
- **Related commands:** `setup-poller` (the collector-only sibling), `profile-create`/`profile-use`, `init-run` (a much lighter-weight alternative that only checks host capabilities and optionally migrates legacy state — does not provision any stack).

#### `netrune setup poller --community '<community>'` (id: `setup-poller`)
- **Purpose:** One-command provisioning of a collector-only machine — collects and stores nothing beyond raw readings, no dashboards.
- **Exact syntax / arguments / preconditions:** Identical flag surface and gating to `setup-local` above; the only functional differences are the `role` value itself (`poller`) and its downstream effects.
- **Step-by-step behavior:** Same 7-step sequence as `setup-local`, with two role-specific differences: retention defaults to 365 days (vs 180) instead of the general default, and the `traffic stack init` call additionally passes `--role collector` so the generated stack omits the dashboard/storage-serving pieces `local` gets.
- **Side effects:** Same categories as `setup-local` (profile, config, SNMP `.env`, SQLite init, generated+started stack, watches), just with a collector-shaped generated stack.
- **Output shape, table/text mode:** Same step-report format as `setup-local`, but with poller-specific guidance: reminder to `traffic watch`, and instructions to hand readings to another machine via `traffic export --since 24h > ...` or an SSH pull from the other end (no `traffic dashboard` mention, since a poller has none).
- **Output shape, `--json` mode:** Same shape as `setup-local`.
- **Exit codes:** Same as `setup-local`.
- **Real example:** `netrune setup poller --community public --collector-id branch-office-1 --watch 192.0.2.10:Gi1/0/1` → provisions a headless collector reporting readings to be pulled/exported elsewhere.
- **Related commands:** `setup-local`, `profile-create`/`profile-use`.

*(Both `setup` commands additionally call the module-level helper `write_snmp_community` — `netops_platform/setup_cli.py` — which reads any existing `.env` at `<config_dir>/.env`, strips prior `communities=`/`snmp_version=` lines, appends fresh `communities="<value>"` and `snmp_version="v2c"` lines, and rewrites the file at mode 0600. This same helper is exposed as `App.write_snmp_community` for direct callers/tests.)*

---

### SUPPORT domain

#### `netrune support bundle` (id: `support-bundle`)
- **Purpose:** Package a fully redacted diagnostic archive (version, redacted config summary, DB/integrity status, driver/plugin manifests, and aggregate run-history counts) for sharing with support — explicitly excluding inventory, secrets, raw evidence, known hosts, aliases, and configuration backups.
- **Exact syntax:** `netrune support bundle [<output-path>]`. **The optional output-path positional is not represented in the registry's `arg_schema` at all** (registry shows zero args) — `cmd_support`'s bundle branch is `output = Path(rest[0]).expanduser() if rest else None`, so a real, undeclared positional argument exists and works from the CLI but is invisible to `commands run support-bundle`/ask's argument extraction.
- **Arguments:** `output-path` (optional; defaults to `<data_dir>/support/netops-support-<epoch>.tar.gz`).
- **Preconditions / gating:** **None — verified gap.** There is no `opts.dry_run` check anywhere in `cmd_support`; `netrune support bundle --dry-run` still creates the real archive on disk, despite the registry marking `preview_supported: true`.
- **Step-by-step behavior (`create_support_bundle` in `netops_platform/support.py`):** Builds, in a temp directory, `system.json` (Python version, platform string, WSL detection, Netrune version, a *hashed* profile-name token — not the plaintext name), `configuration.json` (every profile setting collapsed to `"configured"`/`"not-configured"` except a fixed allowlist of genuinely-safe-to-show operational toggles), `database.json` (schema version + table counts + file sizes, no paths), `integrity.json` (`state.integrity_check()`), `drivers.json` (built-in driver reports + hashed/redacted profile driver-manifest errors), `plugins.json` (group/enabled/api_version/load_status/redacted error per plugin), `recent_runs.json` (aggregate counts only — ingest/path/diagnostic run counts grouped by status, never individual rows), and a fixed `README.txt`. Every payload is passed through a recursive `_redact()` that blanks any key matching `pass|secret|token|community|credential|private[_-]?key|api[_-]?key`, and scrubs IPv4 addresses and MAC addresses out of any string value anywhere in the tree, plus collapses the home directory to `~`. Writes a `MANIFEST.sha256.json` hashing every file, tars+gzips the directory atomically (staged file + `os.replace`, mode 0600), then **rotates old bundles**: keeps only the newest 10 files matching `netops-support-*.tar.gz` in the bundle's own default directory (custom `--output-path` targets are never touched by this rotation).
- **Side effects:** Writes one `.tar.gz` (mode 0600) to disk; may delete older auto-named bundles beyond the 10 most recent kept.
- **Output shape, table/text mode:** `f"Redacted support bundle: {path}\nSHA-256: {sha256}\nBytes: {bytes} | Recorded: {recorded_at_iso}\nExcluded: inventory, raw evidence, secrets, known hosts, aliases, configuration backups"`.
- **Output shape, `--json` mode:** `{"ok": true, "path", "sha256", "bytes", "recorded_at", "recorded_at_iso", "redacted": true, "excluded": [...]}`.
- **Exit codes:** Always `SUCCESS(0)` on the happy path (an unhandled exception during bundle creation would surface as `INTERNAL(10)` from the top-level dispatch handler).
- **Real example:** `netrune support bundle ./netops-support.tar.gz` → writes to that exact path (bypassing the default directory and its 10-bundle rotation).
- **Related commands:** none in this domain group; conceptually parallels `db-status`/`db-integrity` and `plugin-check`, which it aggregates redacted summaries from.

---

### WORKFLOW domain

#### `netrune workflow morning-check` (id: `workflow-morning-check`)
- **Purpose:** A fixed 7-step daily-open sequence: import legacy caches, check reachability, refresh LLDP/CDP topology, refresh relationship memory, review topology changes, check Internet filtering, and build the attention queue.
- **Exact syntax:** `netrune workflow morning-check`.
- **Arguments:** None (a bare name; anything after `morning-check` on the command line would be joined into an unused `target` string, but this manifest never consults it).
- **Preconditions / gating:** `--dry-run` prints the resolved step table (id/label/on_failure/command) without executing anything.
- **Step-by-step behavior (`App.workflow_manifest("morning-check")`, executed by `cmd_workflow`):** Runs each step's command as a real child process (`netrune inventory import-flat` → `netrune health check` → `netrune topology scan` → `netrune memory refresh` → `netrune topology changes` → `netrune diagnose filtering google.com` → `netrune health attention`), forcing `--json` on each child invocation to parse a machine-readable summary back out. Steps run sequentially; each step's `on_failure` policy is `"continue"` for all steps here, so a failing step does not stop the sequence (there is no `"stop"` step in this manifest). Progress is streamed live via `app.live_log("workflow", ...)` between steps.
- **Side effects:** Everything the 7 child commands individually do — legacy-flat import writes, health-check reachability probes + `health_state` writes, topology scan writes to `neighbors`, memory refresh recomputes `relationships_current`/emits `relationship_events`, a live Internet filtering probe against `google.com`, and an attention-queue read.
- **Output shape, table/text mode:** Per-step live progress line `[i/N] <label> (<STATUS>)` plus that step's own stdout, then a final headline `Workflow morning-check: <STATUS> | completed=i/N | failed=N [| needing attention=N] | recorded=<iso>` followed by a results table `["step", "label", "status", "exit_code", "duration_ms", "on_failure", "summary"]`.
- **Output shape, `--json` mode:** `{"ok": <no failed steps>, "workflow": "morning-check", "description", "status" ("SUCCESS"|"PARTIAL"|"ATTENTION"|"FAILED"), "steps": [{step, id, label, status ("SUCCESS"|"ATTENTION"|"FAILED"), exit_code, duration_ms, on_failure, summary, result: <redacted child JSON or null>}], "completed_steps", "total_steps", "failed_steps", "attention_steps", "stopped", "started_at(_iso)", "finished_at(_iso)"}`. Note: a step exiting with `PARTIAL(3)` is deliberately classified `"ATTENTION"` rather than `"FAILED"` — this is explicit, commented behavior: `health attention` (and similarly-shaped steps) exits `PARTIAL` precisely *because* it found something to show, and treating that as a failure would train operators to ignore a red row that appears on every healthy morning.
- **Exit codes:** `SUCCESS(0)` if no step failed and none needed attention; `PARTIAL(3)` if any step failed or needed attention (the richer 4-way status distinction only exists inside the JSON payload's `status` field, not in the process exit code).
- **Real example:** `netrune workflow morning-check` → 7 steps, ending with an attention-queue summary; exits `PARTIAL(3)` on a normal morning with anything flagged.
- **Related commands:** `workflow-refresh-inventory` (a lighter subset), `workflow-ap-audit`, `health-attention`, `topology-changes` (individually re-runnable pieces of this sequence).

#### `netrune workflow refresh-inventory` (id: `workflow-refresh-inventory`)
- **Purpose:** A fixed 5-step refresh: reachability, AP discovery, topology scan, relationship refresh, attention queue.
- **Exact syntax:** `netrune workflow refresh-inventory`.
- **Arguments:** None.
- **Preconditions / gating:** Same `--dry-run` behavior as `morning-check`.
- **Step-by-step behavior:** `netrune health check` → `netrune ap scan` → `netrune topology scan` → `netrune memory refresh` → `netrune health attention`, all `on_failure: "continue"`, same JSON-forced/streamed execution model as `morning-check`.
- **Side effects:** Health-check writes, AP-scan writes to `aps`, topology-scan writes to `neighbors`, memory-refresh relationship recomputation, attention-queue read.
- **Output shape, table/text mode / `--json` mode / exit codes:** Identical shape/semantics to `morning-check` (same `cmd_workflow` execution engine), just 5 steps instead of 7.
- **Real example:** `netrune workflow refresh-inventory` → quick "did anything change" refresh without the filtering probe or legacy import `morning-check` includes.
- **Related commands:** `workflow-morning-check` (superset), `workflow-ap-audit` (AP-focused subset).

#### `netrune workflow ap-audit` (id: `workflow-ap-audit`)
- **Purpose:** A fixed 4-step AP-focused refresh: scan APs, refresh relationships, review AP moves, build attention queue.
- **Exact syntax:** `netrune workflow ap-audit`.
- **Arguments:** None.
- **Preconditions / gating:** Same `--dry-run` behavior.
- **Step-by-step behavior:** `netrune ap scan` → `netrune memory refresh` → `netrune ap moves` → `netrune health attention`, all `on_failure: "continue"`.
- **Side effects:** AP-scan writes to `aps`, memory-refresh relationship recomputation (which is what actually populates `ap_move_events`), an `ap moves` read, attention-queue read.
- **Output shape / exit codes:** Same engine/shape as `morning-check`, 4 steps.
- **Real example:** `netrune workflow ap-audit` → surfaces any APs that changed switch/port since the last audit.
- **Related commands:** `workflow-refresh-inventory`, `ap-moves`.

#### `netrune workflow backup-online '<target>'` (id: `workflow-backup-online`)
- **Purpose:** Run changed-only configuration backups against the online devices in a scope.
- **Exact syntax:** `netrune workflow backup-online <target>`.
- **Arguments:** `target` (required — hostname, IP, or site token; `App.workflow_manifest("backup-online", target)` raises `ValueError("backup-online requires target")` if empty, surfaced by `cmd_workflow` at `VALIDATION(6)`).
- **Preconditions / gating:** `--dry-run` shows the single resolved step.
- **Step-by-step behavior:** A single-step manifest: `netrune backup run <target>` with `on_failure: "stop"` (the only workflow in this group whose step is `"stop"` rather than `"continue"` — since it's a single step, this only affects the final `stopped` flag/status wording, there's nothing after it to skip).
- **Side effects:** Whatever `backup run` does — SSH/read config retrieval per online device in scope, changed-only diff+save into the backups store, `backup_history` rows.
- **Output shape / exit codes:** Same engine as `morning-check` (1-step version); `SUCCESS(0)`/`PARTIAL(3)` as above, plus `VALIDATION(6)` if target is missing.
- **Real example:** `netrune workflow backup-online ZONE10` → backs up every currently-online device matching `ZONE10`.
- **Related commands:** `backup-run`, `backup-history`, `workflow-site-health` (the other target-taking workflow).

#### `netrune workflow site-health '<target>'` (id: `workflow-site-health`)
- **Purpose:** Run a 3-step latency/filtering/recorded-health check against one target/site.
- **Exact syntax:** `netrune workflow site-health <target>`.
- **Arguments:** `target` (required — `ValueError("site-health requires target")` if empty → `VALIDATION(6)`).
- **Preconditions / gating:** `--dry-run` shows the 3 resolved steps.
- **Step-by-step behavior:** `netrune diagnose latency <target> --count 5` → `netrune diagnose filtering <target>` → `netrune health status <target>`, all `on_failure: "continue"`.
- **Side effects:** A live 5-packet latency probe, a live filtering/DNS/TLS check, and a read of already-recorded health state for the target — the first two are real network probes against the target, not cache-only reads.
- **Output shape / exit codes:** Same engine as `morning-check` (3-step version), plus `VALIDATION(6)` if target missing.
- **Real example:** `netrune workflow site-health ZONE34` → latency + filtering + health snapshot for that site in one call.
- **Related commands:** `workflow-backup-online`, `diagnose-latency`, `diagnose-filtering`, `health-status`.

---

### Cross-cutting notes

#### 1. The ~20 retrieval intents in `ask.py`'s `QUESTION_PATTERNS`, in the order `NaturalAskEngine.ask` actually tries them

- **ap_aliases** — questions about same/merged/duplicate/canonical AP identity or "alternate names" ("Are X and Y the same AP?"). Handled by `_ask_ap_aliases`; when exactly two explicit `...AP<N>...`-shaped tokens appear in the question, it does a direct same/different comparison via alias-exact-match and identity-signature comparison instead of a generic list.
- **unjoined_aps** — "unjoined/not joined/nonjoined/awaiting join/unregistered" APs. Handled by `_ask_unjoined_aps`, reading `aps` rows whose `switch_port` is one of `not-joined`/`not joined`/`unjoined`/`nonjoined`.
- **attention** — "needs attention / warnings / network problems / outstanding issues / what failed / important changes". Handled by `_ask_attention`, which wraps `App.attention_payload` (offline/flapping/stale health rows + recent topology events + AP moves + non-saved/unchanged backups).
- **topology_changes** — topology/link/neighbor questions paired with change words (changed/new/added/removed/disappeared). Handled by `_ask_topology_changes`, reading `topology_events`.
- **ap_moves** — AP move/movement/attachment-change questions. Handled by `_ask_ap_moves`, reading `ap_move_events`.
- **backup_history** — backup/backed-up/config-backup questions. Handled by `_ask_backup_history`, reading `backup_history`.
- **diagnostic_history** — latency/speed-test/packet-loss/filtering/DNS/TLS/interface-utilization questions. Handled by `_ask_diagnostic_history`, which unions `probe_results`, `speed_tests`, `filtering_checks`, and `interface_samples` and tags each row with a `kind`.
- **job_status** — running/pending/queued/failed/completed/cancelled "jobs/operations/workflows" questions. Handled by `_ask_jobs`, which reads `SELECT * FROM jobs ...`. **Confirmed stale**: `jobs`/`job_logs` are legacy schema tables that still exist and are migrated (columns added) on every `init_db()` call, but grepping the entire codebase turns up zero `INSERT INTO jobs` statements anywhere — the only remaining reference is a schema-migration `UPDATE jobs SET created_at=COALESCE(...)` fix-up, and there is no `cmd_jobs`/jobs dispatch noun left in `core.py`'s dispatch table. This confirms the jobs domain itself was removed from the codebase at some point, leaving this one `ask` intent (and the underlying table) permanently empty in any profile created since.
- **ap_on_switch** — "APs on/attached to/connected to <switch description>" (via `_extract_ap_switch_query`'s pattern set). Handled by `_ask_ap_on_switch`, which resolves the switch first, then reads its current AP attachments through `App.memory_switch_payload`.
- **port_memory** — a recognized interface token (`Gi1/0/2`, `port 7`, etc.) followed by `on/of/from/at <switch>`. Handled by `_ask_port`, via `App.memory_port_payload`.
- **ap_location** / **identity_history** — an explicit `...AP<N>...` token combined with where/connected/attached/location wording, or with rename/identity/older-names wording respectively. Handled by `_ask_ap_location` (current/previous switch+port from `relationship_events` where `rel_type='ap_attachment'`) or `_ask_identity_history` (see below).
- **mac_memory** / **ip_memory** — a recognized MAC or IPv4 token combined with where/history/which/who/moved/etc. wording. Both handled by the single `_ask_ip_or_mac` method (kind-parameterized), reading `relationships_current` plus `App.relationship_timeline_payload`.
- **identity_history** (second entry point) — rename/renamed/"called before"/older-or-previous-names/serial-or-model-changed wording without an explicit AP token. Handled by `_ask_identity_history`, unioning `inventory_history` and `relationship_events` matches across every known name/IP/MAC/alias for the resolved entity.
- **switch_summary** — summarize/summary/overview/"what do we know"/"switch context"/"memory summary" wording. Handled by `_ask_switch_summary`, combining `App.memory_switch_payload` with a `health_state` lookup.
- **topology** — neighbors/downstream/upstream/topology/LLDP/CDP/"what is connected" wording (without change words, which would have already matched `topology_changes` earlier). Handled by `_ask_topology`, reading `neighbors`.
- **health** — health/flapping/stale/outages/"not seen" wording, or a bare online/offline/reachable/down/up word *not* also naming APs/switches/routers/devices (which would instead fall to the inventory intents below). Handled by `_ask_health`, reading `health_state`.
- **ap_inventory** — any question mentioning "APs"/"access points" that didn't match anything earlier. Handled inline in `ask()` via `_all_aps()` + `_collection_answer`.
- **switch_inventory** — any question mentioning "switches"/"routers"/"network devices" that didn't match anything earlier. Handled inline via `_all_devices()` + `_collection_answer`.
- **entity_details** — the final fallback: a recognized field keyword (ip/mac/model/platform/status/details/"tell me about"/"last seen"/aliases) with an extractable target, or (if nothing else matched at all) any extractable target on its own. Handled by `_ask_details`.
- **command_plan** — not a retrieval intent at all; checked *first*, before any of the above, by `_plan_command`/`_command_matches` (see note 2).

#### 2. How the command-plan half (`_command_matches`) scores requests against actions

`_command_matches` runs two passes and merges their scores (higher wins per action id):

1. **~53 hand-written regex rules**, each `(action_id, pattern, base_score)`, covering things like SSH-trust workflows (`device-trust-enroll/forget/scan/status`), VLAN set/locate/propagation, device show/config/ssh, every `workflow-*` name, inventory scan/import/export/activity, health-check, AP/topology scan, memory-refresh, backup run/verify, the full `diagnose-*` family (core-ping, doctor, cable/cable-test, port-health, throughput, latency, speed, filtering, interface), the full `lookup-mac-*` family, `lookup-core`, `db-*` (integrity/repair/vacuum/migrate), and `ask-alias-set`/`ask-alias-remove`. Scores range roughly 89–104; when multiple rules match the same action, the *maximum* matching score wins.
2. **A token-overlap fallback** against the *entire* `App.command_registry()` (not just these 39 actions), but **only engaged when the question itself contains a "meta" word** — `command/action/tool/preview/prepare/plan/execute/run` — via `meta_request = bool(re.search(...))`. When engaged, it tokenizes the question (minus stopwords/meta-words), builds a haystack per registry action from its id/label/description/domain/examples, counts token overlap × 10, adds a flat +150 bonus if the action's id-with-spaces or label literally appears in the question text, and only keeps candidates scoring ≥20. `ask-query` itself is explicitly excluded from this fallback pool (so `ask` never "plans" a call to itself).

Both passes are merged into one `{action_id: score}` dict and returned sorted descending by score (id as tiebreaker). `_plan_command` takes the top scorer, extracts arguments for it via `_extract_command_args` (a large per-action regex extractor: MAC/IP/interface/VLAN/depth/max-nodes/count tokens, quoted strings for alias/config actions, session-carried `last_target` fallback for target-taking actions), previews it through `App.preview_for_action`, and reports `status` as `needs_clarification` / `blocked` / `preview_only` / `ready` accordingly. Up to 3 next-best alternatives (score ≥30) are surfaced under `alternatives` in the plan.

**Confirmed stale rule:** the `serve-run` regex rule (`\b(?:start|run|launch)\b.*\b(?:server|webui|api)\b`) still exists in `_command_matches`, and `App.command_for_action` still special-cases `serve-run` in its hard-blocked action set (alongside `device-config`, `memory-prune`, `ask-chat`, `commands-run`) — but `serve-run` does **not** exist as a `CommandSpec` anywhere in `App.command_registry()`, and there is no `cmd_serve`/`serve` noun left in `core.py`'s dispatch table at all. A question like *"start the webui"* will therefore score against a dead action id: `_plan_command` calls `app.command_spec("serve-run")`, gets `None`, and (per `_plan_command`'s `if not spec: return None`) silently falls through as if no command plan matched at all — the question then continues into the retrieval cascade and most likely ends in the generic "That wording does not match a predefined Natural Ask workflow" error, with no indication to the caller that a command rule *did* fire internally.

#### 3. The `ai/` directory — a separate layer, not part of `netops_platform`

`ai/` (top-level, sibling to `netops_platform/`) is a standalone, Ollama-optional operator layer with its own `bin/` (`netrune_ai_agent.py`, `netrune_ai_chat.py`, `netrune_ai_rag.py`), `config/` (`tools.yaml` approved-workflow registry, `aliases.yaml`, `system_prompt.txt`), and `docs/`. Per its own `README.md`, it talks to the core "only through approved public commands," is authoritative-*subordinate* to `netrune ask` for broad retrieval/planning ("The core `netrune ask` engine is authoritative for broad retrieval and command planning"), defaults to a deterministic router that doesn't load Ollama at all, and — when `--ollama-select` is used — delegates broad/ambiguous requests to a local `qwen3:8b` model (its "thinking" phase always disabled for latency) while keeping the three live-device-read workflows pre-decided deterministically for safety. It explicitly cannot execute command plans or configuration actions itself; execution stays an explicit CLI/WebUI step through the core registry.

**One verified discrepancy worth flagging:** the `ai/README.md` and `argparse` `prog` string in `ai/bin/netrune_ai_chat.py` both present `netrune ai <question>` as the entry point ("Use the fast assistant through the public `netrune` launcher... `netrune ai \"...\"`"), but `netops_platform/core.py`'s `App.dispatch` noun table has no `"ai"` entry, and `pyproject.toml`'s `[project.scripts]` wires `netrune`/`netops`/`netop` only to `netrune.launcher:main` → `netops_platform.core.main`, with no interception of `ai` anywhere in that path. As shipped in this repository, `netrune ai "..."` does not currently resolve through the installed `netrune` console script; the actually-working invocation is `python3 ai/bin/netrune_ai_chat.py "..."` (or `ai/bin/netrune_ai_agent.py ...` directly).

#### 4. `netrune commands run <action-id>` vs. calling the noun-specific command directly

`commands run` (id `commands-run`) is the generic, registry-backed executor: given any action id from `App.command_registry()` plus loosely-typed `--flag value` args (parsed positionally/generically by `App.parse_registry_args`, not through that action's own noun-specific arg parser), it resolves the exact same `App.command_for_action(action, args)` dispatch table that `ask`'s command-plan execution path (`ask_cli.execute_ask_plan`) also calls, and either previews the resolved command line or spawns it as a real `netrune <resolved subcommand>` child process. It is the single generic on-ramp any of the ~39+ registered actions can be driven through uniformly (useful for a UI/API driving the registry generically, or for `ask` planning a request in natural language), as opposed to typing that domain's own dedicated CLI form directly (e.g. `netrune health check ZONE34` vs. `netrune commands run health-check --target ZONE34`). The two paths converge on identical underlying behavior once `command_for_action` resolves the argv, but `commands run` additionally enforces the registry-level safety gates (`run_supported`, `risk_level == "config"` needing `--confirm`) *before* ever reaching the noun-specific command's own argument validation — and it is itself deliberately excluded from being targeted recursively (along with `ask-chat`/`device-config`/`memory-prune`/the stale `serve-run`) via `command_for_action`'s hard `PermissionError` block.

---

## 13. Excel Domain (`netops_platform/excel.py`, `netops_platform/excel_cli.py`)

Correlates an operator's own `.xlsx`/`.xlsm` workbooks with Netrune's reconciled inventory and writes Netrune's fresher values into them, and builds new tracker workbooks. Never touches a switch or Netrune's database (only `audit_events`). `excel.py` is pure planning and workbook mechanics (no `App`); `excel_cli.py` is a free-function `dispatch(app, args, opts)` module owning the preview/backup/apply/verify/audit lifecycle. Requires **openpyxl** (optional extra `netrune[excel]`; on Arch `sudo pacman -S python-openpyxl` for the system Python the `netops` launcher uses). Without it every verb exits `VALIDATION` with the install hint.

**Device source:** `inventory_rows("", GlobalOptions(limit=1_000_000))` filtered to `kind=="device"` — the same reconciled rows as `inventory list`, including `addresses`, `aliases`, `macs`, `serials`. APs are never matched or added.

**Header detection (`detect_layout`):** scans the first 30 rows; the header row is the first row naming the most fields, needing at least one identity field (`serial`, `mac`, `ip`, `hostname`) and two fields total. Header text is normalized to lowercase alphanumerics and looked up in `HEADER_SYNONYMS` (e.g. `S/N`→serial, `Mgmt IP`→ip, `Device Name`/`Switch`→hostname, `Base Ethernet MAC Address`→mac, `Vendor`/`Make`→platform), then loose rules (`*mac*`, `*serial*`, `*model*`, `*ip`/`*ipaddress*`). `--map 'Header=field,C=field,3=field'` overrides by header text, column letter, or 1-based index. Data rows run from the row after the header to the last row with any mapped cell filled. The column's MAC notation (colon/hyphen/dotted/hyphen-six/bare, upper/lower) and hostname style (FQDN if most existing names are dotted, else short) are detected and reused for written values.

**Matching (`plan_sheet`):** each row's serial, MAC, IP (first IPv4 in the cell, so `192.0.2.1/24 (mgmt)` works), and hostname (host label, domain stripped, alphanumerics only) are looked up against the device index. A key hitting exactly one device is a vote; a key hitting several is ambiguous and ignored. One distinct device → matched (`matched_by` lists the agreeing keys). None → `unmatched`. Several → `conflict`, row left alone unless `--prefer serial|mac|ip|hostname` names the key to trust. A device matched by several rows is reported under `duplicates` and every row is updated.

**What is written:** for matched rows, each mapped field in `--fields` (default `hostname,ip,model,serial,mac,platform`; `status` and `last_seen` only when named, because an asset sheet's Status is usually lifecycle, not reachability) gets Netrune's value when the cell is blank/placeholder (`fill`) or differs (`update`; skipped and listed under `kept` with `--fill-only`). Equality is by identity key for identity fields, substring either way for platform (`Cisco` agrees with `Cisco IOS`), within 60 s for `last_seen`, case-insensitive otherwise. Formula cells and merged non-anchor cells are never written. Netrune placeholders (`N/A`) and implausible models are never written. `--add-missing` (requires `--sheet` when more than one sheet has a header) appends a row per unmatched Netrune device after the last data row, copying the row above's styles and translating its formulas, and extends any Excel Table whose range covered the data.

#### `netrune excel inspect <workbook> [--sheet NAME] [--map SPEC] [--fields LIST]` (id `excel-inspect`, read-only)
Prints detected layout per sheet, a summary table (`rows, matched, unmatched, conflicts, cell_changes, new_rows, devices_not_in_sheet`), the would-be cell changes, conflicts, unmatched rows, duplicates, kept cells, and warnings for features openpyxl would drop on save and for an Excel lock file. Exit `SUCCESS`; `VALIDATION` for workbook/argument problems.

#### `netrune excel sync <workbook> [options] (--dry-run | --confirm)` (id `excel-sync`, local-write)
Options: `--sheet`, `--map`, `--fields`, `--fill-only`, `--add-missing`, `--prefer`, `--output PATH` (write a copy, source untouched), `--highlight` (light-yellow fill on written cells), `--no-comments` (default adds a cell note `Netrune <time>: was '<old>'`/`filled from <device>`/`added <device>`), `--ignore-lock`, `--allow-feature-loss`.
- Without `--confirm`: the inspect report plus "Nothing written"; exit `SUCCESS` with `--dry-run` or when nothing differs, else `CONFIRM_REQUIRED` (7). The file is not opened for writing.
- With `--confirm`: refuses (`VALIDATION`) if `~$<name>` exists beside the workbook (open in Excel; `--ignore-lock` overrides), or if writing in place and the zip contains parts openpyxl does not round-trip — `xl/charts/`, `xl/drawings/`, `xl/media/`, `xl/pivotTables/`, `xl/slicers/`, `xl/timelines/`, `xl/metadata.xml` (dynamic-array formulas), `xl/externalLinks/` — unless `--output` or `--allow-feature-loss`. Then copies the original (when writing in place, or when `--output` already exists) to `<data_dir>/excel-backups/<stem>-<YYYYmmdd-HHMMSS><suffix>`, applies, saves to a temp file in the destination directory and `os.replace`s it, reopens the result and checks every written cell, and records `audit_events(event_type='excel', action='excel-sync', result='success'|'verify-failed')` with source, destination, backup, counts. Exit `SUCCESS`, or `INTERNAL` if verification found differences. `.xlsm` is loaded with `keep_vba=True`; `.xls`/`.csv` are refused with a save-as hint.

#### `netrune excel export <tracker.xlsx> [--migration-rows N] [--confirm]` (id `excel-export`, local-write)
Writes a new workbook (`build_tracker`): **Summary** (live COUNTA/COUNTIF/COUNTIFS KPIs — devices, online, offline, online %, not seen 7+ days, missing serial/MAC — per-model and per-platform counts, a bar chart by model, and Migration Tracker progress by status, complete %, overdue), **Inventory** (Excel Table `Inventory`: Hostname, IP Address, Platform, Model, Serial Number, Base MAC, Status, Last Seen, Days Since Seen formula, and empty Site/Owner/Notes for the operator; OFFLINE/ONLINE/7+-days conditional formatting), **Migration Tracker** (Table `MigrationTracker`, default 300 rows: device dropdown from Inventory, INDEX/MATCH lookups of IP and current model, change-type and status dropdowns, date validation, Days Overdue formula, Done/Blocked/Cancelled/overdue/not-in-inventory highlighting). Classic functions only (no `_xlfn` dynamic arrays), so it calculates identically in Excel 365 and older builds. An existing destination needs `--confirm` (exit 7 otherwise) and is backed up first; the written file is reopened to verify; audited as `excel-export`. The Inventory sheet's headers are recognized by `excel sync`, so `netrune excel sync <tracker> --sheet Inventory --add-missing --fields hostname,ip,platform,model,serial,mac,status,last_seen --confirm` refreshes it without disturbing the formulas, Site/Owner/Notes, or the tracker.
