"""Registry-generated action and help dialogs."""

from __future__ import annotations

from typing import Any

from textual import on
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.suggester import SuggestFromList
from textual.widgets import Button, Input, Label, ListItem, ListView, Select, Static, Switch

from netops_platform.contracts import ActionPreviewV1
from netops_platform.service import NetOpsService


def field_id(name: str) -> str:
    return "field-" + name.replace("_", "-")


class ActionForm(ModalScreen[dict[str, Any] | None]):
    def __init__(self, service: NetOpsService, command: dict[str, Any], initial: dict[str, Any] | None = None):
        super().__init__()
        self.service = service
        self.command = command
        self.initial = dict(initial or {})
        self.preview: ActionPreviewV1 | None = None
        options = service.core.ui_options().get("targets") or []
        self.target_suggestions = sorted(({str(item.get("label") or "") for item in options} | {str(item.get("value") or "") for item in options}) - {""})

    def compose(self) -> ComposeResult:
        with Vertical(id="action-dialog"):
            yield Label(str(self.command.get("label") or self.command.get("id")), id="action-heading")
            yield Static(str(self.command.get("description") or ""), id="action-description")
            yield Static(f"{str(self.command.get('safety_class') or 'read-only').upper()}  |  {str(self.command.get('output_view') or 'result').upper()}  |  {str(self.command.get('capability') or 'core').upper()}", id="action-policy")
            with VerticalScroll(id="action-fields"):
                for schema in self.command.get("arg_schema") or []:
                    name = str(schema.get("name") or "")
                    required = " *" if schema.get("required") else ""
                    with Vertical(classes="field-row"):
                        yield Label(f"{schema.get('label') or name}{required}", classes="field-label")
                        yield self._field_widget(schema)
                        yield Static(str(schema.get("help") or ""), classes="field-help")
                if self.command.get("safety_class") != "read-only":
                    with Vertical(classes="field-row"):
                        yield Label("Operator reason *", classes="field-label")
                        yield Input(placeholder="Why this active operation is needed", id="operator-reason")
                    with Vertical(classes="field-row"):
                        config_change = self.command.get("risk_level") == "config"
                        yield Label("Change ticket *" if config_change else "Change ticket", classes="field-label")
                        yield Input(placeholder="Required change/incident identifier" if config_change else "Optional incident/change identifier", id="operator-ticket")
                if self.command.get("risk_level") == "config":
                    with Vertical(classes="field-row"):
                        yield Label("Typed confirmation *", classes="field-label")
                        yield Input(placeholder="Preview generates the exact phrase", id="typed-confirmation")
            yield Static("Preview the exact operation before running it.", id="preview-output")
            with Horizontal(id="action-buttons"):
                yield Button("Cancel", id="action-cancel", compact=True)
                yield Button("Preview", id="action-preview", variant="default", compact=True)
                yield Button("Run", id="action-run", variant="primary", compact=True, disabled=True)

    def _field_widget(self, schema: dict[str, Any]):
        name = str(schema.get("name") or "")
        initial = self.initial.get(name, schema.get("default", ""))
        widget_id = field_id(name)
        if schema.get("type") == "boolean":
            return Switch(value=str(initial).lower() in {"1", "true", "yes", "on"}, id=widget_id)
        if schema.get("type") == "select":
            options = [(str(item).replace("_", " ").title(), str(item)) for item in schema.get("options") or []]
            value = str(initial) if initial not in (None, "") else Select.NULL
            return Select(options, allow_blank=not schema.get("required"), value=value, id=widget_id, compact=True)
        input_type = "integer" if schema.get("type") == "number" else "text"
        suggester = SuggestFromList(self.target_suggestions, case_sensitive=False) if schema.get("options_source") == "inventory" else None
        return Input(value=str(initial if initial is not None else ""), placeholder=str(schema.get("placeholder") or ""), type=input_type, suggester=suggester, id=widget_id)

    def values(self) -> dict[str, Any]:
        values: dict[str, Any] = {}
        for schema in self.command.get("arg_schema") or []:
            name = str(schema.get("name") or "")
            widget = self.query_one(f"#{field_id(name)}")
            if isinstance(widget, Switch):
                value: Any = bool(widget.value)
            elif isinstance(widget, Select):
                value = "" if widget.value is Select.NULL else widget.value
            else:
                value = widget.value.strip()
                if schema.get("type") == "number" and value:
                    value = int(value)
                    if schema.get("min") is not None and value < int(schema["min"]):
                        raise ValueError(f"{schema.get('label') or name} must be at least {schema['min']}.")
                    if schema.get("max") is not None and value > int(schema["max"]):
                        raise ValueError(f"{schema.get('label') or name} must be at most {schema['max']}.")
            if value not in ("", None, False) or schema.get("type") == "boolean":
                values[name] = value
        return values

    def refresh_preview(self) -> None:
        output = self.query_one("#preview-output", Static); run = self.query_one("#action-run", Button)
        try:
            self.preview = self.service.preview(str(self.command.get("id") or ""), self.values())
        except (ValueError, TypeError) as exc:
            self.preview = None; output.update(f"[FAIL] {exc}"); run.disabled = True; return
        missing = ", ".join(self.preview.missing_args) or "none"
        terminal_allowed = self.command.get("output_type") == "terminal" and self.command.get("id") == "device-ssh"
        state = "TERMINAL" if terminal_allowed and self.preview.blocked else "BLOCKED" if self.preview.blocked else "READY"
        reason = f"\nReason: {self.preview.reason}" if self.preview.reason else ""
        confirmation = f"\nType exactly: {self.preview.confirmation_phrase}" if self.preview.confirmation_phrase else ""
        output.update(f"[{state}] Missing: {missing}\n{self.preview.command}{reason}{confirmation}\nPreview: {self.preview.preview_hash[:16]}")
        run.disabled = (self.preview.blocked and not terminal_allowed) or bool(self.preview.missing_args)

    @on(Button.Pressed, "#action-preview")
    def preview_pressed(self) -> None:
        self.refresh_preview()

    @on(Button.Pressed, "#action-run")
    def run_pressed(self) -> None:
        self.refresh_preview()
        terminal_allowed = self.command.get("output_type") == "terminal" and self.command.get("id") == "device-ssh"
        if not self.preview or (self.preview.blocked and not terminal_allowed) or self.preview.missing_args:
            return
        reason_nodes = self.query("#operator-reason"); ticket_nodes = self.query("#operator-ticket")
        confirmation_nodes = self.query("#typed-confirmation")
        reason = reason_nodes.first(Input).value.strip() if reason_nodes else ""
        ticket = ticket_nodes.first(Input).value.strip() if ticket_nodes else ""
        typed_confirmation = confirmation_nodes.first(Input).value.strip() if confirmation_nodes else ""
        if self.preview.requires_confirmation and not reason:
            self.query_one("#preview-output", Static).update("[BLOCKED] Active operations require an operator reason."); return
        if self.preview.confirmation_phrase and typed_confirmation != self.preview.confirmation_phrase:
            self.query_one("#preview-output", Static).update(f"[BLOCKED] Type {self.preview.confirmation_phrase!r} exactly."); return
        if self.preview.confirmation_phrase and not ticket:
            self.query_one("#preview-output", Static).update("[BLOCKED] Configuration changes require a change or incident ticket."); return
        self.dismiss({"action": self.preview.action_id, "args": dict(self.preview.args), "reason": reason, "ticket": ticket, "typed_confirmation": typed_confirmation, "preview_hash": self.preview.preview_hash, "output_type": self.command.get("output_type")})

    @on(Button.Pressed, "#action-cancel")
    def cancel_pressed(self) -> None:
        self.dismiss(None)


class HelpScreen(ModalScreen[None]):
    def compose(self) -> ComposeResult:
        with Vertical(id="help-dialog"):
            yield Label("NetOps Operator Console", id="action-heading")
            yield Static("The console opens on the searchable action hub. Use / to search actions, Enter to open the selected action, F for Functions, A to return to Actions, J for Jobs, I for the Inspector, L for Activity, D for result details, R to refresh, E to export, and ? for this panel.\n\nOpening the console performs local reads only. Active diagnostics show an exact preview and require an operator reason. Configuration actions remain guarded by their typed workflow and confirmation policy.\n\nEvery timestamp is rendered in ISO 8601 UTC. [OK], [WARN], [FAIL], and [STALE] remain meaningful without color.")
            yield Button("Close", id="help-close", variant="primary")

    @on(Button.Pressed, "#help-close")
    def close_pressed(self) -> None:
        self.dismiss(None)


class FunctionScreen(ModalScreen[str | None]):
    """Compact launcher for data and configuration workspaces."""

    BINDINGS = [("escape", "cancel", "Close")]

    def __init__(self, functions: list[tuple[str, str, str]]):
        super().__init__()
        self.functions = functions

    def compose(self) -> ComposeResult:
        with Vertical(id="function-dialog"):
            yield Label("Functions", id="action-heading")
            yield Static("Open a workspace when you need its recorded state, tools, or configuration.", id="function-description")
            yield ListView(
                *(
                    ListItem(
                        Vertical(
                            Label(label, classes="function-title"),
                            Label(hint, classes="function-hint"),
                            classes="function-copy",
                        ),
                        id=f"function-{view_id}",
                    )
                    for view_id, label, hint in self.functions
                ),
                id="function-list",
            )
            yield Button("Close", id="function-close")

    def on_mount(self) -> None:
        function_list = self.query_one("#function-list", ListView)
        function_list.index = 0
        function_list.focus()

    @on(ListView.Selected, "#function-list")
    def function_selected(self, event: ListView.Selected) -> None:
        item_id = event.item.id or ""
        if item_id.startswith("function-"):
            self.dismiss(item_id.removeprefix("function-"))

    @on(Button.Pressed, "#function-close")
    def close_pressed(self) -> None:
        self.dismiss(None)

    def action_cancel(self) -> None:
        self.dismiss(None)


class ConfirmScreen(ModalScreen[bool]):
    def __init__(self, heading: str, message: str, confirm_label: str = "Confirm"):
        super().__init__()
        self.heading = heading
        self.message = message
        self.confirm_label = confirm_label

    def compose(self) -> ComposeResult:
        with Vertical(id="help-dialog"):
            yield Label(self.heading, id="action-heading")
            yield Static(self.message)
            with Horizontal(id="action-buttons"):
                yield Button("Back", id="confirm-back")
                yield Button(self.confirm_label, id="confirm-accept", variant="error")

    @on(Button.Pressed)
    def choice_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "confirm-accept")


class ExitScreen(ModalScreen[str | None]):
    def __init__(self, active_jobs: int):
        super().__init__()
        self.active_jobs = active_jobs

    def compose(self) -> ComposeResult:
        with Vertical(id="help-dialog"):
            yield Label("Active operations", id="action-heading")
            yield Static(f"{self.active_jobs} operation(s) are still running. Stay in the console to let them finish, or explicitly cancel them before exiting.")
            with Horizontal(id="action-buttons"):
                yield Button("Stay", id="exit-stay")
                yield Button("Open jobs", id="exit-wait", variant="primary")
                yield Button("Cancel jobs and exit", id="exit-cancel", variant="error")

    @on(Button.Pressed)
    def choice_pressed(self, event: Button.Pressed) -> None:
        choice = {"exit-stay": None, "exit-wait": "wait", "exit-cancel": "cancel"}.get(event.button.id or "")
        self.dismiss(choice)
