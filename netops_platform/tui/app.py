"""NetOps v8 full-screen operator console."""

from __future__ import annotations

import asyncio
from functools import partial
import json
import os
from pathlib import Path
import shlex
import time
from typing import Any, Iterable

from textual import on, work
from textual.app import App, ComposeResult, SystemCommand
from textual.binding import Binding
from textual.containers import Grid, Horizontal, Vertical, VerticalScroll
from textual.events import Resize
from textual.message import Message
from textual.theme import Theme
from textual.widgets import Button, Footer, Header, Input, Label, RichLog, Static, TabbedContent, TabPane

from netops_platform.core import GlobalOptions
from netops_platform.contracts import QuerySpec, ResultEnvelopeV1
from netops_platform.preferences import PreferenceStore
from netops_platform.service import NetOpsService, VIEW_TITLES

from .forms import ActionForm, ConfirmScreen, ExitScreen, FunctionScreen, HelpScreen
from .widgets import ResultWorkbench, inspector_table


NAVIGATION = [
    ("inventory", "Inventory", "devices, access points, and contextual actions"),
    ("diagnostics", "Diagnostics", "latency, speed, ports, and cable history"),
    ("topology", "Topology / VLAN", "recorded links, changes, and propagation evidence"),
    ("overview", "Status overview", "attention, health, freshness, and recent jobs"),
    ("history", "History / Audit", "chronology, evidence, and operator actions"),
    ("settings", "Configuration", "readiness, public settings, and local paths"),
]


class NetOpsConsole(App[None]):
    class ViewLoading(Message):
        def __init__(self, view_id: str):
            super().__init__()
            self.view_id = view_id

    class ViewLoaded(Message):
        def __init__(self, envelope: ResultEnvelopeV1, elapsed: float):
            super().__init__()
            self.envelope = envelope
            self.elapsed = elapsed

    class ViewLoadFailed(Message):
        def __init__(self, view_id: str, error: str):
            super().__init__()
            self.view_id = view_id
            self.error = error

    class JobUpdatesLoaded(Message):
        def __init__(self, updates: dict[str, dict[str, Any]]):
            super().__init__()
            self.updates = updates

    class JobUpdatesFailed(Message):
        def __init__(self, error: str):
            super().__init__()
            self.error = error

    CSS_PATH = "netops.tcss"
    TITLE = "NetOps Operator Console"
    SUB_TITLE = "local network operations"
    COMMAND_PALETTE_BINDING = "ctrl+p"
    ENABLE_COMMAND_PALETTE = True

    BINDINGS = [
        Binding("q", "request_quit", "Quit", show=True),
        Binding("ctrl+q", "request_quit", "Quit", show=False),
        Binding("r", "refresh", "Refresh", show=True),
        Binding("/", "focus_filter", "Filter", show=True),
        Binding("a", "action_catalog", "Actions", show=True),
        Binding("f", "functions", "Functions", show=True),
        Binding("j", "jobs", "Jobs", show=True),
        Binding("i", "inspector", "Inspector", show=False),
        Binding("l", "activity", "Activity", show=False),
        Binding("d", "details", "Details", show=False),
        Binding("e", "export", "Export", show=False),
        Binding("t", "toggle_theme", "Theme", show=False),
        Binding("?", "help", "Help", show=True),
        Binding("escape", "focus_table", "Results", show=False),
    ]

    def __init__(
        self,
        service: NetOpsService,
        *,
        initial_view: str = "operations",
        initial_target: str = "",
        preference_store: PreferenceStore | None = None,
    ):
        super().__init__()
        self.service = service
        self.preferences = preference_store or PreferenceStore()
        self.preference_values = self.preferences.load()
        preferred_view = str(self.preference_values.get("last_view") or "operations")
        self.current_view = initial_view if initial_view in VIEW_TITLES else preferred_view if preferred_view in VIEW_TITLES else "operations"
        self.initial_target = initial_target
        self.current_row: dict[str, Any] = {}
        self.current_dataset_id = ""
        self.context_action_map: dict[str, str] = {}
        self.preferred_dataset_id = "commands" if self.current_view == "operations" else ""
        self.active_jobs: dict[str, int] = {}
        self._poll_running = False
        self._last_view_load = 0.0

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True, icon="N", time_format="%H:%M:%S")
        with Horizontal(id="body"):
            with Vertical(id="workspace"):
                with Horizontal(id="workspace-heading"):
                    yield Label(VIEW_TITLES[self.current_view], id="view-title")
                    yield Static("LOCAL STATE", id="view-state")
                    yield Button("Actions", id="hub-actions", compact=True)
                    yield Button("Functions", id="hub-functions", compact=True)
                    yield Button("Jobs", id="hub-jobs", compact=True)
                    yield Button("Activity", id="hub-activity", compact=True)
                yield ResultWorkbench(id="workbench")
            with Vertical(id="side-panel"):
                with Horizontal(id="drawer-heading"):
                    yield Label("Details", id="drawer-title")
                    yield Button("Close", id="drawer-close", compact=True)
                with TabbedContent(id="side-tabs"):
                    with TabPane("Inspector", id="inspector-tab"):
                        with VerticalScroll(id="inspector-scroll"):
                            yield Label("No selection", id="inspector-title")
                            yield Static("Select a row or topology node to inspect its complete evidence.", id="inspector-body", expand=True)
                        with Grid(id="context-actions"):
                            yield Button("Inspect", id="context-inspect", compact=True)
                            yield Button("Health", id="context-health", compact=True)
                            yield Button("Core ping", id="context-core-ping", compact=True)
                            yield Button("Memory", id="context-memory", compact=True)
                            yield Button("SSH", id="context-ssh", compact=True)
                            yield Button("Backup", id="context-backup", compact=True)
                    with TabPane("Activity", id="activity-tab"):
                        yield RichLog(id="activity-log", wrap=True, markup=True, highlight=False)
        yield Footer()

    def on_mount(self) -> None:
        self.register_theme(Theme("netops-dark", primary="#60c8d5", secondary="#93a1aa", warning="#e5b454", error="#e56b70", success="#6fd17a", accent="#60c8d5", foreground="#e7ecef", background="#101315", surface="#181c1f", panel="#20262a", dark=True))
        self.register_theme(Theme("netops-light", primary="#006b76", secondary="#52616a", warning="#946200", error="#b3262d", success="#267834", accent="#006b76", foreground="#172025", background="#f3f6f7", surface="#e7ecef", panel="#d8dfe2", dark=False))
        self.register_theme(Theme(
            "netops-plain-light", primary="#4c4c4c", secondary="#666666", warning="#444444",
            error="#242424", success="#383838", accent="#555555", foreground="#202020",
            background="#f7f7f7", surface="#eeeeee", panel="#dfdfdf", dark=False,
        ))
        self.register_theme(Theme(
            "netops-plain-dark", primary="#c8c8c8", secondary="#aaaaaa", warning="#c0c0c0",
            error="#eeeeee", success="#d2d2d2", accent="#b8b8b8", foreground="#e6e6e6",
            background="#181818", surface="#222222", panel="#303030", dark=True,
        ))
        requested_theme = os.environ.get("NETOPS_TUI_THEME", "").strip().lower() or str(self.preference_values.get("theme") or "auto")
        self._apply_theme_mode(requested_theme)
        self.screen.set_class(self.current_view == "operations", "command-hub")
        self.query_one(ResultWorkbench).set_filter_values(dict(self.preference_values.get("saved_filters") or {}))
        self._configure_context_actions("")
        self.set_interval(0.5, self.poll_active_jobs)
        self.load_view(self.current_view, self.initial_target)

    def get_system_commands(self, screen) -> Iterable[SystemCommand]:
        yield from super().get_system_commands(screen)
        yield SystemCommand("Open Action Hub", "Search and run registered commands", self.action_action_catalog)
        for view_id, label, hint in NAVIGATION:
            yield SystemCommand(f"Open {label}", hint, partial(self.switch_view, view_id))
        for command in self.service.registry():
            yield SystemCommand(str(command["label"]), str(command["description"]), partial(self.open_action, str(command["id"])), discover=False)

    @on(Resize)
    def resized(self, event: Resize) -> None:
        self.screen.set_class(event.size.width < 140, "compact")
        self.screen.set_class(event.size.width < 100, "narrow")

    @staticmethod
    def _terminal_prefers_dark() -> bool:
        hint = os.environ.get("NETOPS_TERMINAL_THEME", "").strip().lower()
        if hint in {"dark", "light"}:
            return hint == "dark"
        colorfgbg = os.environ.get("COLORFGBG", "").strip()
        try:
            background = int(colorfgbg.replace(",", ";").split(";")[-1])
        except (TypeError, ValueError):
            return False
        if background < 16:
            return background in {0, 1, 2, 3, 4, 5, 6, 8}
        if background >= 232:
            return background < 244
        background -= 16
        red, green, blue = background // 36, (background % 36) // 6, background % 6
        levels = (0, 95, 135, 175, 215, 255)
        luminance = 0.2126 * levels[red] + 0.7152 * levels[green] + 0.0722 * levels[blue]
        return luminance < 140

    def _apply_theme_mode(self, mode: str) -> str:
        aliases = {
            "light": "netops-light",
            "dark": "netops-dark",
            "terminal": "auto",
            "monochrome": "auto",
        }
        normalized = aliases.get(mode.strip().lower(), mode.strip().lower())
        if os.environ.get("NO_COLOR"):
            normalized = "auto"
        if normalized not in {"auto", "netops-light", "netops-dark"}:
            normalized = "auto"
        if normalized == "auto":
            resolved = "netops-plain-dark" if self._terminal_prefers_dark() else "netops-plain-light"
        else:
            resolved = normalized
        self.theme = resolved
        self.screen.set_class(resolved.startswith("netops-plain-"), "monochrome")
        return normalized

    def switch_view(self, view_id: str, dataset_id: str = "") -> None:
        if view_id not in VIEW_TITLES:
            return
        self.current_view = view_id
        self.preferred_dataset_id = dataset_id or ("commands" if view_id == "operations" else "")
        self.preference_values["last_view"] = view_id
        self.screen.set_class(view_id == "operations" and self.preferred_dataset_id != "jobs", "command-hub")
        self.hide_drawer()
        self.query_one(ResultWorkbench).set_details(False)
        self.query_one("#view-title", Label).update(VIEW_TITLES[view_id])
        self.load_view(view_id)

    @work(exclusive=True, group="view", exit_on_error=False)
    async def load_view(self, view_id: str, query: str = "") -> None:
        self.post_message(self.ViewLoading(view_id))
        await asyncio.sleep(0)
        started = time.monotonic()
        try:
            envelope = self.service.query(view_id, QuerySpec(query=query, limit=500))
        except Exception as exc:
            self.post_message(self.ViewLoadFailed(view_id, str(exc)))
            return
        elapsed = time.monotonic() - started
        self.post_message(self.ViewLoaded(envelope, elapsed))

    @on(ViewLoading)
    def view_loading(self, event: ViewLoading) -> None:
        self._set_loading(event.view_id)

    def _set_loading(self, view_id: str) -> None:
        self.query_one("#view-state", Static).update("LOADING LOCAL STATE")
        self.query_one("#view-title", Label).update(VIEW_TITLES.get(view_id, view_id.title()))

    @on(ViewLoaded)
    def view_loaded(self, event: ViewLoaded) -> None:
        self._apply_envelope(event.envelope, event.elapsed)

    def _apply_envelope(self, envelope: ResultEnvelopeV1, elapsed: float) -> None:
        self._last_view_load = elapsed
        workbench = self.query_one(ResultWorkbench)
        workbench.show_envelope(envelope)
        if self.preferred_dataset_id:
            workbench.select_dataset(self.preferred_dataset_id)
            self.preferred_dataset_id = ""
        state = envelope.provenance.freshness.upper()
        self.query_one("#view-state", Static).update(f"{state}  |  {elapsed * 1000:.0f} ms")
        self.query_one("#activity-log", RichLog).write(f"[dim][VIEW][/] {envelope.title} loaded in {elapsed * 1000:.0f} ms")

    def _show_load_error(self, view_id: str, error: str) -> None:
        self.query_one("#view-state", Static).update("[FAIL] LOAD ERROR")
        self.query_one("#activity-log", RichLog).write(f"[bold][FAIL][/] {view_id}: {error}")
        self.notify(error, title="Could not load view", severity="error", timeout=8)

    @on(ViewLoadFailed)
    def view_load_failed(self, event: ViewLoadFailed) -> None:
        self._show_load_error(event.view_id, event.error)

    @on(ResultWorkbench.RefreshRequested)
    def workbench_refresh_requested(self) -> None:
        self.action_refresh()

    @on(ResultWorkbench.ExportRequested)
    def workbench_export_requested(self, event: ResultWorkbench.ExportRequested) -> None:
        self.export_dataset(event.dataset)

    @on(ResultWorkbench.RowFocused)
    def workbench_row_focused(self, event: ResultWorkbench.RowFocused) -> None:
        self.current_row = dict(event.row)
        self.current_dataset_id = event.dataset_id
        title = str(event.row.get("name") or event.row.get("hostname") or event.row.get("title") or event.row.get("action") or event.row.get("id") or "Selection")
        self.query_one("#inspector-title", Label).update(title)
        self.query_one("#inspector-body", Static).update(inspector_table(self.current_row))
        self._configure_context_actions(event.dataset_id)

    @on(ResultWorkbench.RowActivated)
    def workbench_row_activated(self, event: ResultWorkbench.RowActivated) -> None:
        if event.dataset_id == "commands":
            self.open_action(str(event.row.get("id") or ""))
        elif event.dataset_id == "jobs":
            self.open_job(str(event.row.get("id") or ""))
        else:
            self.show_drawer("inspector")

    @on(ResultWorkbench.FilterChanged)
    def workbench_filter_changed(self, event: ResultWorkbench.FilterChanged) -> None:
        saved = self.preference_values.setdefault("saved_filters", {})
        if event.value:
            saved[event.dataset_id] = event.value
        else:
            saved.pop(event.dataset_id, None)

    @on(Button.Pressed)
    def button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id or ""
        if button_id == "hub-actions":
            self.action_action_catalog()
            return
        if button_id == "hub-functions":
            self.action_functions()
            return
        if button_id == "hub-jobs":
            self.action_jobs()
            return
        if button_id == "hub-activity":
            self.action_activity()
            return
        if button_id == "drawer-close":
            self.hide_drawer()
            return
        context = self.context_action_map.get(button_id)
        if context:
            self.run_context_action(context)

    def _configure_context_actions(self, dataset_id: str) -> None:
        actions: list[tuple[str, str]]
        if dataset_id == "commands":
            actions = [("Open action", "open-action")]
        elif dataset_id == "jobs":
            actions = [("Open job", "open-job"), ("Cancel", "cancel-job"), ("Rerun", "rerun-job")]
        elif dataset_id in {"inventory", "topology"}:
            actions = [
                ("Inspect", "inspect"), ("Health", "health-check"), ("Core ping", "diagnose-core-ping"),
                ("Memory", "memory-device"), ("SSH", "device-ssh"), ("Backup", "backup-run"),
            ]
        else:
            actions = [("Inspect", "inspect")]
        button_ids = ["context-inspect", "context-health", "context-core-ping", "context-memory", "context-ssh", "context-backup"]
        self.context_action_map = {}
        for index, button_id in enumerate(button_ids):
            button = self.query_one(f"#{button_id}", Button)
            if index < len(actions):
                label, action = actions[index]
                button.label = label
                button.display = True
                button.disabled = action == "cancel-job" and str(self.current_row.get("status") or "") not in {"queued", "running", "cancelling"}
                self.context_action_map[button_id] = action
            else:
                button.display = False

    def row_target(self) -> str:
        return str(self.current_row.get("ip") or self.current_row.get("hostname") or self.current_row.get("name") or self.current_row.get("target") or self.current_row.get("device_ip") or "").strip()

    def run_context_action(self, action_id: str) -> None:
        if action_id == "open-action":
            self.open_action(str(self.current_row.get("id") or ""))
            return
        if action_id == "open-job":
            self.open_job(str(self.current_row.get("id") or ""))
            return
        if action_id == "cancel-job":
            self.confirm_job_cancel(str(self.current_row.get("id") or ""))
            return
        if action_id == "rerun-job":
            self.rerun_job(str(self.current_row.get("id") or ""))
            return
        target = self.row_target()
        if action_id == "inspect":
            if not self.current_row:
                self.notify("Select a row first.", severity="warning")
            else:
                self.show_drawer("inspector")
            return
        if not target:
            self.notify("The selected row has no usable device target.", severity="warning")
            return
        initial = {"target": target, "device": target}
        if action_id == "memory-device" and self.current_row.get("kind") == "ap":
            action_id = "memory-device"
        self.open_action(action_id, initial)

    def open_job(self, job_id: str) -> None:
        if not job_id:
            return
        detail = self.service.job_detail(job_id)
        job = detail.get("job") or {}
        if not job:
            self.notify(f"Job {job_id} was not found.", severity="warning")
            return
        enriched = dict(job)
        enriched["events"] = len(detail.get("events") or [])
        self.current_row = enriched
        self.query_one("#inspector-title", Label).update(f"Job {job_id}")
        self.query_one("#inspector-body", Static).update(inspector_table(enriched))
        envelope = self.service.job_result(job_id)
        if envelope is not None:
            self.query_one(ResultWorkbench).show_envelope(envelope)
            self.query_one("#view-title", Label).update(envelope.title)
            self.query_one("#view-state", Static).update(str(job.get("status") or "UNKNOWN").upper())
        log = self.query_one("#activity-log", RichLog)
        log.write(f"[bold][JOB][/] {job_id} {job.get('action')} {job.get('status')}")
        for event in detail.get("events") or []:
            style = "bold" if event.get("stream") == "stderr" else "none"
            log.write(f"[{style}]{event.get('created_at_iso', '')}  {event.get('message', '')}[/]")
        self.show_drawer("activity")

    def confirm_job_cancel(self, job_id: str) -> None:
        if not job_id:
            return
        self.push_screen(
            ConfirmScreen("Cancel active job", f"Request cancellation for job {job_id}? Completed work is retained in the audit trail.", "Cancel job"),
            partial(self._job_cancel_choice, job_id),
        )

    def _job_cancel_choice(self, job_id: str, confirmed: bool | None) -> None:
        if not confirmed:
            return
        ok, message = self.service.cancel(job_id)
        self.notify(message, severity="information" if ok else "warning")
        if ok:
            self.active_jobs.setdefault(job_id, 0)

    def rerun_job(self, job_id: str) -> None:
        detail = self.service.job_detail(job_id)
        job = detail.get("job") or {}
        try:
            request = json.loads(str(job.get("request_json") or "{}"))
        except (TypeError, ValueError):
            request = {}
        action_id = str(request.get("action") or job.get("action") or "")
        args = request.get("args") if isinstance(request.get("args"), dict) else {}
        if not action_id:
            self.notify("This job has no reusable action metadata.", severity="warning")
            return
        self.open_action(action_id, args)

    def open_action(self, action_id: str, initial: dict[str, Any] | None = None) -> None:
        command = self.service.command(action_id)
        if not command:
            self.notify(f"Unknown action: {action_id}", severity="error")
            return
        self.push_screen(ActionForm(self.service, command, initial), self._action_form_closed)

    def _action_form_closed(self, result: dict[str, Any] | None) -> None:
        if not result:
            return
        if result.get("output_type") == "terminal":
            self.run_terminal_action(str(result["action"]), dict(result.get("args") or {}))
            return
        try:
            job = self.service.submit(
                str(result["action"]), dict(result.get("args") or {}), reason=str(result.get("reason") or ""),
                ticket=str(result.get("ticket") or ""), preview_hash=str(result.get("preview_hash") or ""),
                typed_confirmation=str(result.get("typed_confirmation") or ""),
            )
        except (PermissionError, ValueError) as exc:
            self.notify(str(exc), title="Operation blocked", severity="error", timeout=8)
            return
        job_id = str(job.get("id") or "")
        if job_id:
            self.active_jobs[job_id] = 0
            self.query_one("#activity-log", RichLog).write(f"[bold][JOB][/] {job_id} {job.get('action')} queued")
            self.show_drawer("activity")
            self.notify(f"Job {job_id} queued", title=str(job.get("action") or "Operation"))

    def run_terminal_action(self, action_id: str, args: dict[str, Any]) -> None:
        try:
            command, _, _ = self.service.core.command_for_action(action_id, args)
        except ValueError as exc:
            self.notify(str(exc), severity="error")
            return
        self.query_one("#activity-log", RichLog).write(f"[bold][TERMINAL][/] {shlex.join(command)}")
        with self.suspend():
            code = self.service.core.run_interactive(command, GlobalOptions())
        severity = "information" if code == 0 else "warning"
        self.notify(f"Terminal action exited with code {code}", severity=severity)
        self.action_refresh()

    def poll_active_jobs(self) -> None:
        if self.active_jobs and not self._poll_running:
            self._poll_jobs_worker(dict(self.active_jobs))

    @work(exclusive=True, group="job-poll", exit_on_error=False)
    async def _poll_jobs_worker(self, jobs: dict[str, int]) -> None:
        self._poll_running = True
        await asyncio.sleep(0)
        try:
            updates = {job_id: self.service.job_detail(job_id, after_id) for job_id, after_id in jobs.items()}
        except Exception as exc:
            self.post_message(self.JobUpdatesFailed(str(exc)))
            return
        self.post_message(self.JobUpdatesLoaded(updates))

    @on(JobUpdatesLoaded)
    def job_updates_loaded(self, event: JobUpdatesLoaded) -> None:
        self._poll_running = False
        self._apply_job_updates(event.updates)

    @on(JobUpdatesFailed)
    def job_updates_failed(self, event: JobUpdatesFailed) -> None:
        self._poll_running = False
        self.query_one("#activity-log", RichLog).write(f"[bold][FAIL][/] job polling: {event.error}")

    def _apply_job_updates(self, updates: dict[str, dict[str, Any]]) -> None:
        log = self.query_one("#activity-log", RichLog)
        terminal: list[str] = []
        for job_id, detail in updates.items():
            for event in detail.get("events") or []:
                self.active_jobs[job_id] = max(self.active_jobs.get(job_id, 0), int(event.get("id") or 0))
                stream = str(event.get("stream") or "system")
                style = "bold" if stream == "stderr" else "dim" if stream == "system" else "none"
                progress = ""
                if event.get("progress_current") is not None and event.get("progress_total"):
                    progress = f" {event['progress_current']}/{event['progress_total']}"
                log.write(f"[{style}]{event.get('created_at_iso','')} {job_id}{progress}  {event.get('message','')}[/]")
            job = detail.get("job") or {}
            if str(job.get("status") or "") in {"completed", "partial", "failed", "cancelled", "stale"}:
                terminal.append(job_id)
                severity = "information" if job.get("status") == "completed" else "warning"
                self.notify(f"Job {job_id} {job.get('status')} (exit {job.get('exit_code')})", severity=severity)
        for job_id in terminal:
            self.active_jobs.pop(job_id, None)
        if terminal:
            self.load_view(self.current_view)

    def export_dataset(self, dataset) -> None:
        try:
            path = self.service.export_dataset(dataset, "csv")
        except (OSError, ValueError) as exc:
            self.notify(str(exc), title="Export failed", severity="error")
            return
        self.notify(str(path), title="Export created", timeout=8)
        self.query_one("#activity-log", RichLog).write(f"[bold][EXPORT][/] {path}")

    def action_refresh(self) -> None:
        self.load_view(self.current_view)

    def action_focus_filter(self) -> None:
        self.query_one("#result-filter", Input).focus()

    def action_focus_table(self) -> None:
        self.query_one("#result-table").focus()

    def action_action_catalog(self) -> None:
        self.switch_view("operations", "commands")

    def action_functions(self) -> None:
        self.push_screen(FunctionScreen(NAVIGATION), self._function_selected)

    def _function_selected(self, view_id: str | None) -> None:
        if view_id:
            self.switch_view(view_id)

    def action_jobs(self) -> None:
        self.switch_view("operations", "jobs")
        self.show_drawer("activity")

    def show_drawer(self, tab: str) -> None:
        tab_id = "activity-tab" if tab == "activity" else "inspector-tab"
        self.query_one("#side-tabs", TabbedContent).active = tab_id
        self.query_one("#drawer-title", Label).update("Activity" if tab == "activity" else "Inspector")
        self.screen.add_class("drawer-open")

    def hide_drawer(self) -> None:
        self.screen.remove_class("drawer-open")

    def action_inspector(self) -> None:
        active = self.screen.has_class("drawer-open") and self.query_one("#side-tabs", TabbedContent).active == "inspector-tab"
        self.hide_drawer() if active else self.show_drawer("inspector")

    def action_activity(self) -> None:
        active = self.screen.has_class("drawer-open") and self.query_one("#side-tabs", TabbedContent).active == "activity-tab"
        self.hide_drawer() if active else self.show_drawer("activity")

    def action_details(self) -> None:
        workbench = self.query_one(ResultWorkbench)
        workbench.set_details(not workbench.has_class("details-open"))

    def action_export(self) -> None:
        workbench = self.query_one(ResultWorkbench)
        visible = workbench.current_export_dataset()
        if visible:
            self.export_dataset(visible)
        else:
            self.notify("There is no active dataset to export.", severity="warning")

    def action_toggle_theme(self) -> None:
        current = str(self.preference_values.get("theme") or "auto")
        modes = ["auto", "netops-light", "netops-dark"]
        next_mode = modes[(modes.index(current) + 1) % len(modes)] if current in modes else "auto"
        self.preference_values["theme"] = self._apply_theme_mode(next_mode)
        label = {"auto": "Terminal", "netops-light": "Light", "netops-dark": "Dark"}[self.preference_values["theme"]]
        self.notify(label, title="Theme")

    def action_help(self) -> None:
        self.push_screen(HelpScreen())

    def action_request_quit(self) -> None:
        if self.active_jobs:
            self.push_screen(ExitScreen(len(self.active_jobs)), self._exit_choice)
        else:
            self._save_and_exit()

    def _exit_choice(self, choice: str | None) -> None:
        if choice == "cancel":
            for job_id in list(self.active_jobs):
                self.service.cancel(job_id)
            self._save_and_exit()
        elif choice == "wait":
            self.action_jobs()

    def _save_and_exit(self) -> None:
        try:
            self.preferences.save(self.preference_values)
        except OSError as exc:
            self.notify(str(exc), title="Preferences not saved", severity="warning")
        self.exit()
