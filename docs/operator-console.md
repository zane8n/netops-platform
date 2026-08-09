# NetOps v8 Operator Console Guide

## 1. What the console is

The NetOps operator console is a full-screen terminal application for routine
network operations. It combines canonical inventory, topology, VLAN evidence,
diagnostic history, jobs, audit records, and the command catalog in one
workspace. It does not replace the noun-first CLI; every action still resolves
through the same command registry and core policy.

Opening and navigating the console reads local SQLite state only. Network
traffic begins only after an operator opens an action, reviews its preview, and
runs it.

## 2. Starting it

From an installed package, the shortest explicit form is:

```bash
netop tui
```

From the source checkout after `uv sync`:

```bash
uv run netop tui
```

Explicit forms are:

```bash
netop tui
netops tui
netops tui open
netops tui --view inventory --target SW1
```

The no-argument default opens the console only when stdin and stdout are an
interactive terminal and `TERM` is usable. Scripts, pipes, redirected output,
and headless sessions keep CLI behavior. To request help explicitly:

```bash
netops --no-tui
netops --plain
netops --help
```

Set `NETOPS_TUI=0` to disable the no-argument console default for a deployment.
Explicit noun-first commands such as `netops health offline` are unchanged.

## 3. Screen structure

The default screen is one full-width **Action Hub**: a search field and a
four-column action table. It does not show status cards, topology, evidence,
metrics, history, or the inspector until those surfaces are requested.

Additional surfaces are explicit:

1. **Functions:** opens Inventory, Diagnostics, Topology/VLAN, Status overview,
   History/Audit, or Configuration.
2. **Details:** reveals metrics and the Topology, Findings, Evidence, and Raw
   result tabs for the current function.
3. **Inspector / Activity:** opens a dismissible side drawer with complete row
   evidence, context actions, or chronological job progress.

The header shows the application identity and a standard 24-hour clock. The
footer lists available keys. No view uses hidden network refresh on entry.

## 4. Navigation and keys

| Key | Result |
|---|---|
| Arrow keys / Enter | Move through navigation, tables, tabs, and controls |
| `Ctrl+P` | Open Textual's searchable command palette |
| `/` | Focus the active result filter |
| `A` | Return to the Action Hub |
| `F` | Open the Functions chooser |
| `J` | Open Jobs and show Activity |
| `D` | Show or hide metrics and advanced result tabs |
| `I` | Show or hide the Inspector |
| `L` | Show or hide Activity |
| `R` | Refresh the current view from local canonical state |
| `E` | Export the currently visible table rows to CSV |
| `T` | Cycle terminal-neutral, optional light, and optional dark themes |
| `?` | Open console help |
| `Esc` | Return focus to the result table where applicable |
| `Q` / `Ctrl+Q` | Save preferences and exit, subject to active-job policy |

Text fields consume normal typing. Use Tab/Shift+Tab when a key is meaningful to
the focused control. The command palette also exposes navigation and registered
actions, which means an operator can discover work without memorizing IDs.

## 5. Action Hub and functions

### Action Hub

This is the startup surface and the console's primary role. It lists Action,
Function, Safety, and Purpose for every registered operation. Search for a task
such as `core ping`, `mac`, `vlan`, `cable`, `speed`, or `backup`, then press
Enter to open the generated form. Jobs are available separately with `J`.

### Overview

The Status overview function summarizes device/AP counts, offline and attention totals,
running/problem jobs, recent diagnostics, the attention queue, recent jobs, and
source freshness. Start here when taking over a shift.

### Inventory

Displays canonical devices and access points with status, identity, platform,
attachment, and last-seen time. Filtering searches all loaded row fields, not
only the visible columns. Selecting a row populates the inspector and enables
context actions such as Health, Core ping, Memory, SSH, and Backup.

### Topology / VLAN

Shows LLDP/CDP neighbor links and recent topology changes. The Topology tab
builds a bounded tree from recorded links, marks cycles, and preserves edge
evidence. Live recursive VLAN inspection is an explicit action; merely opening
this view never contacts switches.

### Diagnostics

Contains diagnostic runs plus dedicated Internet-speed, latency, and interface
sample datasets. Return to the Action Hub to start fresh tests.
A row is a recorded observation with its original timestamp, not a claim about
current network state.

### History / Audit

Provides relationship, inventory, health, and audit timelines in newest-first
order. Human-facing timestamps are ISO 8601 UTC so events can be correlated
across devices and tools. Filter by target, actor, event, or ticket text.

### Configuration

Shows public non-secret configuration, runtime paths, database schema/integrity,
dependency readiness, credential presence, and SSH host-key mode. Secret values
are never rendered here.

## 6. Working with results

Every view uses the same workbench.

### Metrics and advanced tabs

The default result surface is the Data table. Press `D` or choose **Details** to
show up to six metrics and the Topology, Findings, Evidence, and Raw tabs.
Metrics summarize the loaded envelope; filtering does not redefine them.

### Datasets

One result may contain several named datasets. Select the dataset from the
toolbar. The console remembers a saved filter per dataset, so changing from
Jobs to Action Catalog does not destroy either filter.

### Filter

Filtering is case-insensitive and checks the complete serialized row. It applies
immediately to the loaded data. It does not perform network I/O or an unbounded
database search. Press `R` when newer canonical state is required.

### Sort

Select a table header to sort ascending; select it again for descending order.
Number and timestamp columns sort numerically, while text sorts
case-insensitively. The selected stable row is preserved where possible.

### Detail tabs

- **Data:** sortable/filterable table.
- **Topology:** rooted neighbor tree when graph data is present.
- **Findings:** coded warnings, failures, and remediation evidence.
- **Evidence:** summary, metrics, and provenance.
- **Raw:** complete structured payload retained by the adapter.

### Inspector

Moving the table cursor prepares the inspector without occupying screen space.
Press `I`, choose **Activity**, or activate a non-command result row to open the
drawer. Context buttons are based on dataset and row type. A disabled or absent
context action means the row cannot safely provide its required target.

### Export

`E` exports the active, filtered, sorted rows and visible columns to a private
CSV file. The default directory is:

```text
${XDG_STATE_HOME:-~/.local/state}/netops/exports
```

Set `NETOPS_EXPORT_DIR` to an approved alternative. Directories are mode `0700`
and files mode `0600`. Filenames use UTC time plus a unique suffix so rapid
exports do not overwrite one another.

## 7. Running actions

### Generated form

Every field comes from registry metadata. Required fields have `*`, inventory
targets provide suggestions, numeric fields enforce bounds, select fields show
approved values, and field help explains accepted syntax.

Choose **Preview** after entering arguments. The preview displays:

- policy state (`READY`, `BLOCKED`, or `TERMINAL`);
- missing fields;
- exact rendered public command;
- block reason where applicable;
- exact typed phrase for configuration;
- a shortened digest of the full preview hash.

Preview is not execution. Changing an argument changes the hash and invalidates
old approval evidence.

### Read-only actions

Read-only actions can run when required fields are valid. They execute as jobs
unless classified terminal-only. Their output and events remain available in
Operations and History.

### Active network actions

Discovery, backup, active diagnostics, and other network reads require an
operator reason. The reason should explain intent, not repeat the command, for
example `Investigating INC-2841 packet loss from Finance floor`.

### Configuration actions

The enabled background configuration path is **Guarded VLAN change**. It
requires:

1. Exact target, interface, mode, and VLAN data.
2. A reviewed preview.
3. Operator reason.
4. Change or incident ticket.
5. Exact typed phrase, such as `APPLY SW1 Gi1/0/7`.

The service recalculates the preview before submission. A changed target,
interface, VLAN, or policy blocks the request. Execution then performs
preflight, backup, apply, read-back verification, and audit. Do not interpret a
queued job as proof of change; inspect the terminal job result and verification
phase.

Up to eight requested VLAN IDs are verified individually. Larger trunk sets are
boundary-sampled and deliberately finish as `ATTENTION` with incomplete
verification, even if the sample passes. Finish an approved full vendor check
before closing the change.

Arbitrary Device Config remains preview-only from the console. Use the public
synchronous CLI under an approved change process if that path is deliberately
required.

### Interactive SSH

SSH is terminal-only. Running it suspends the console, opens the core-managed
interactive session, and restores the console afterward. Host trust and target
resolution remain core responsibilities.

## 8. Jobs and live activity

When a job is submitted, the on-demand Activity drawer opens with its ID and
live structured events. Event lines distinguish system, stdout, stderr, failure, phase, and
progress. The final result opens in the normal workbench with Job Metadata,
adapted result datasets, events, findings, and raw evidence.

Terminal states are `completed`, `partial`, `failed`, `cancelled`, and `stale`.
`partial` means usable work exists but at least one required component did not
succeed. It must not be treated as full success.

Use the Jobs dataset to open, rerun, or request cancellation. Rerun opens a new
form populated from the recorded request; it never silently repeats an active
operation. Cancellation retains completed events and audit evidence.

If jobs are active when you press `Q`, the console requires one choice:

- stay in the console;
- open Jobs and wait;
- request cancellation for all active jobs and exit.

## 9. SSH host-key operations

Recommended production enrollment:

```bash
netops device trust-scan SW1
netops device trust-enroll SW1 --fingerprint SHA256:VERIFIED_VALUE --confirm
netops device trust-status SW1
```

Obtain the expected fingerprint through a channel independent of this SSH
connection: device console, configuration-management inventory, or an approved
asset record. `trust-scan` is observation, not verification. After enrollment,
set `ssh_host_key_mode="strict"` in public configuration.

A legitimate device replacement requires an approved forget and fresh
enrollment. Never accept a changed key only because the old connection stopped
working.

## 10. Preferences and responsive behavior

Preferences are stored privately at
`${XDG_CONFIG_HOME:-~/.config}/netops/tui.json`, or `NETOPS_TUI_CONFIG` when
set. Theme mode, density metadata, last view, pins, filters, and visible-column
preferences are normalized, atomically replaced, and mode `0600`.

The default `auto` theme is grayscale and selects a light or dark neutral
palette from `COLORFGBG` or `NETOPS_TERMINAL_THEME`; when no hint exists it
uses light. `NO_COLOR` forces this neutral mode. Set `NETOPS_TUI_THEME` to
`auto`, `light`, or `dark`, or use `T` to cycle modes.

Responsive layout is deterministic:

- **140 columns and wider:** full-width workspace; an explicitly opened drawer
  appears beside it.
- **100-139 columns:** full-width workspace; the requested drawer is narrower.
- **Below 100 columns:** workspace only; an opened drawer temporarily replaces
  it, while low-priority result controls remain hidden.

Use `F`, `Ctrl+P`, `A`, and `J` for direct navigation. A larger terminal remains
preferable for topology and wide diagnostic evidence.

## 11. Troubleshooting

### Console reports a non-interactive terminal

Run it from a real terminal, verify stdin/stdout are not redirected, and ensure
`TERM` is not `dumb`. Use noun-first CLI commands in automation.

### TUI dependency unavailable

Install the package environment rather than running the source launcher with a
bare interpreter:

```bash
uv sync
uv run netop tui
```

The source-linked `netops` and `netop` launchers automatically hand TUI requests
to the sibling `.venv` when their shebang selected a system Python without
Textual. If the message remains, the environment is absent or incomplete; rerun
`uv sync --extra dev` and verify `.venv/bin/python -c 'import textual'`.

### View says load error

Open Configuration from Functions, then run:

```bash
netops db status
netops db integrity
netops diagnose doctor
```

The console catches view exceptions and does not start transport recovery
automatically.

### Data is stale

Read the freshness label and recorded UTC time. Refreshing a view reloads local
state. Run an explicit scan or health action when a new network observation is
needed.

### Action is blocked

Read the preview reason. Common causes are missing arguments, a preview-only
classification, invalid target syntax, absent reason/ticket, stale preview hash,
or mismatched typed confirmation. Do not call internal helpers to bypass it.

### SSH changed-key failure

Stop and independently verify whether the device was replaced or rekeyed. Use
the approved forget/enroll workflow only after that verification.

## 12. Shift workflow

A practical shift sequence is:

1. Press `F`, open Status overview, and read source freshness and attention findings.
2. Open Jobs and inspect partial/failed work from the previous period.
3. Run Morning Check with a meaningful reason if a fresh observation is due.
4. Inspect offline/attention rows in Inventory and correlate History timestamps.
5. Use explicit diagnostics from the selected device context.
6. Export the filtered evidence when attaching it to an incident.
7. Review terminal job status before closing the incident or change.

The console makes operations discoverable; it does not replace authorization,
maintenance windows, peer review, or independent post-change validation.
