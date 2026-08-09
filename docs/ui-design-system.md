# NetOps v8 Terminal UI Design System

## Design intent

The console is an operations surface for repeated use under time pressure. It
uses dense, stable, scan-oriented layouts; quiet neutral surfaces; explicit
state labels; and one reusable result workbench. Decorative composition,
marketing language, oversized headings, nested cards, and animation are outside
the design language.

## Structural rules

1. Preserve one application shell: header, command-first workspace, optional
   on-demand drawer, footer.
2. Render domain data through `ResultWorkbench`; do not invent a view-specific
   table unless the shared contract cannot represent it.
3. Keep stable heights for the header, action toolbar, result toolbar, and footer
   so dynamic labels do not shift the workspace.
4. Keep action forms modal and generated from registry fields.
5. Do not place panels inside decorative cards. Borders separate functional
   regions only.
6. Long evidence scrolls within its region and must not expand the screen.

## Responsive layout

The implementation uses terminal-cell breakpoints:

| Width | Class | Visible structure |
|---:|---|---|
| `>= 140` | wide/default | full-width workspace; requested 39-cell drawer |
| `100-139` | `compact` | full-width workspace; requested 34-cell drawer |
| `< 100` | `compact narrow` | workspace or requested full-width drawer |

The Functions dialog, command palette, `A`, and `J` replace persistent
navigation at every width. The DataTable remains the primary surface. New controls must be
tested at 160x48, 120x36, and 80x24 without overlap or clipped command text.

## Color and non-color state

The default `auto` mode is grayscale. It selects the neutral light or dark
palette from terminal hints and falls back to light. `NO_COLOR` forces neutral
mode. This keeps the console aligned with light-terminal users and ensures hue
is never required.

Dark theme tokens:

| Role | Value |
|---|---|
| Background | `#101315` |
| Surface | `#181c1f` |
| Panel | `#20262a` |
| Foreground | `#e7ecef` |
| Primary/accent | `#60c8d5` |
| Success | `#6fd17a` |
| Warning | `#e5b454` |
| Error | `#e56b70` |

Light theme uses `#f3f6f7`, `#e7ecef`, and `#d8dfe2` surfaces with dark text,
teal `#006b76`, green `#267834`, amber `#946200`, and red `#b3262d`.

Color never carries status alone. Use stable textual markers:

- `[OK]` success/online/up/completed
- `[WARN]` warning/attention/partial
- `[FAIL]` failed/offline/down/error/critical
- `[STALE]` old evidence
- `[RUN]`, `[WAIT]`, `[STOP]`, and `[?]` for job lifecycle

Colored light and dark themes remain opt-in. Every result must remain
interpretable without hue.

## Typography and copy

- Use terminal-default monospace rendering.
- Headings identify a real view, dialog, or selected entity.
- Labels are literal and concise: `Core ping`, `Guarded VLAN change`, `Export`.
- Help belongs in field metadata, help dialogs, and documentation rather than
  persistent feature narration.
- Use `READY`, `BLOCKED`, `TERMINAL`, and exact policy reasons in previews.
- Use ISO 8601 UTC in all human-facing chronology.

## Components

### Action Hub

The startup surface contains one search field and one table with Action,
Function, Safety, and Purpose. It must not display metrics, topology, history,
raw evidence, or an inspector until the operator asks for them.

### Functions

Inventory, Diagnostics, Topology/VLAN, Status overview, History/Audit, and
Configuration live in a compact modal chooser. Adding a persistent top-level
control requires evidence that it is part of command execution itself.

### Metric strip

At most six metrics are shown after **Details** is requested. Labels are
uppercase and subordinate; values are bold.

### Workbench toolbar

The filter receives flexible width. Dataset select, Details, Refresh, Export,
and freshness have fixed constraints. Action Hub hides every control except
search. A control must not change width when content or status changes.

### DataTable

Headers are sortable, rows use subtle alternating surfaces, and the cursor uses
primary-muted emphasis. Column metadata determines status/timestamp/number
rendering. Low-priority columns remain available in Inspector/Raw instead of
forcing an unreadably wide table.

### Inspector and Activity

Inspector shows complete selected-row evidence and context-sensitive actions.
Activity is chronological, stream-aware job output. They share a closed-by-
default drawer and appear only after explicit inspection or job execution.

### Action form

The dialog is at most 78 cells and 94 percent of the screen, with a scrollable
field region, fixed eight-line preview, and Cancel/Preview/Run command row.
Risk and capability are visible before input. Run remains unavailable for
missing or policy-blocked operations, with terminal SSH as the deliberate
exception.

### Confirmation and exit dialogs

Confirmation, help, and active-job exit dialogs use one centered bounded panel
and a theme-matched backdrop. Destructive commands use the error variant and never become
the only/default escape route.

## Interaction rules

1. Navigation and data loading are local-only.
2. Every active action has an exact preview before execution.
3. Generated fields preserve registry validation and defaults.
4. Row context actions derive their target from canonical row fields.
5. Rerun reopens a populated form; it does not execute immediately.
6. Export uses the visible materialized result, not hidden unfiltered source.
7. An active job must remain inspectable and cancellable.
8. App exit saves normalized preferences atomically.

## Verification checklist

For every visual change:

1. Mount with network transport methods patched to fail.
2. Capture/render at 160x48, 120x36, and 80x24.
3. Check dark, light, and `NO_COLOR` meaning.
4. Exercise keyboard-only navigation, form preview, cancel, and result tabs.
5. Use long targets, labels, findings, and timestamps to detect clipping.
6. Confirm no worker or child process remains after exit.
7. Run the headless service and TUI test suites.

The reference stylesheet is `netops_platform/tui/netops.tcss`; package metadata
must continue shipping it as `netops_platform` package data.
