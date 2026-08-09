"""Reusable industrial workbench widgets."""

from __future__ import annotations

import json
from collections import defaultdict, deque
from typing import Any

from rich.markup import escape
from rich.table import Table
from rich.text import Text
from textual import on
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.message import Message
from textual.widgets import Button, DataTable, Input, Label, RichLog, Select, Static, TabbedContent, TabPane, Tree

from netops_platform.core import fmt_time
from netops_platform.contracts import ColumnSpec, DatasetV1, ResultEnvelopeV1


STATUS_STYLES = {
    "ONLINE": ("[OK]", "bold"), "UP": ("[OK]", "bold"),
    "HEALTHY": ("[OK]", "bold"), "SUCCESS": ("[OK]", "bold"),
    "COMPLETED": ("[OK]", "bold"), "OFFLINE": ("[FAIL]", "bold"),
    "DOWN": ("[FAIL]", "bold"), "FAILED": ("[FAIL]", "bold"),
    "ERROR": ("[FAIL]", "bold"), "CRITICAL": ("[FAIL]", "bold"),
    "WARNING": ("[WARN]", "bold"), "ATTENTION": ("[WARN]", "bold"),
    "PARTIAL": ("[WARN]", "bold"), "STALE": ("[STALE]", "bold"),
    "RUNNING": ("[RUN]", "bold"), "QUEUED": ("[WAIT]", "bold"),
    "CANCELLING": ("[STOP]", "bold"), "CANCELLED": ("[STOP]", "dim"),
    "UNKNOWN": ("[?]", "dim"),
}


def display_value(value: Any, column: ColumnSpec | None = None) -> Text | str:
    if value is None:
        return ""
    if column and column.kind == "timestamp":
        return fmt_time(value) or str(value)
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, (list, tuple, set)):
        return ", ".join(str(item) for item in value)
    if isinstance(value, dict):
        return json.dumps(value, sort_keys=True, default=str)
    text = str(value)
    if column and column.kind == "status":
        prefix, style = STATUS_STYLES.get(text.strip().upper(), ("", ""))
        return Text(f"{prefix} {text}".strip(), style=style)
    return text


class MetricStrip(Horizontal):
    def compose(self) -> ComposeResult:
        for index in range(6):
            with Vertical(classes="metric", id=f"metric-{index}"):
                yield Label("-", classes="metric-label", id=f"metric-label-{index}")
                yield Label("-", classes="metric-value", id=f"metric-value-{index}")

    def update_metrics(self, metrics: dict[str, Any]) -> None:
        items = list(metrics.items())[:6]
        for index in range(6):
            label = self.query_one(f"#metric-label-{index}", Label)
            value = self.query_one(f"#metric-value-{index}", Label)
            if index < len(items):
                key, metric = items[index]
                label.update(key.replace("_", " ").upper())
                value.update(str(metric))
            else:
                label.update("-")
                value.update("-")


class IndustrialDataTable(DataTable):
    class RowFocused(Message):
        def __init__(self, row: dict[str, Any]):
            super().__init__()
            self.row = row

    class RowActivated(Message):
        def __init__(self, row: dict[str, Any]):
            super().__init__()
            self.row = row

    def __init__(self, **kwargs: Any):
        super().__init__(zebra_stripes=True, cursor_type="row", fixed_rows=0, **kwargs)
        self.dataset: DatasetV1 | None = None
        self.filtered_rows: list[dict[str, Any]] = []
        self.visible_columns: list[ColumnSpec] = []
        self.filter_text = ""
        self.sort_key = ""
        self.sort_reverse = False

    def load_dataset(self, dataset: DatasetV1, preserve_key: str = "") -> None:
        self.dataset = dataset
        self.visible_columns = [column for column in dataset.columns if not column.hidden] or list(dataset.columns[:12])
        self._rebuild(preserve_key)

    def set_filter(self, value: str) -> None:
        self.filter_text = value.strip().lower()
        self._rebuild()

    def _materialized_rows(self) -> list[dict[str, Any]]:
        rows = list(self.dataset.rows if self.dataset else [])
        if self.filter_text:
            rows = [row for row in rows if self.filter_text in json.dumps(row, default=str).lower()]
        if self.sort_key:
            column = next((item for item in self.visible_columns if item.key == self.sort_key), None)

            def sort_value(row: dict[str, Any]) -> tuple[bool, Any]:
                value = row.get(self.sort_key)
                if column and column.kind in {"number", "timestamp"}:
                    try:
                        return value is None, float(value)
                    except (TypeError, ValueError):
                        return True, 0.0
                return value is None, str(value or "").casefold()

            rows.sort(key=sort_value, reverse=self.sort_reverse)
        return rows

    def _rebuild(self, preserve_key: str = "") -> None:
        self.clear(columns=True)
        self.filtered_rows = self._materialized_rows()
        if not self.visible_columns:
            return
        for column in self.visible_columns:
            self.add_column(column.label, key=column.key)
        wanted_index = 0
        for index, row in enumerate(self.filtered_rows):
            stable = str(row.get((self.dataset.row_key if self.dataset else "") or "") or index)
            self.add_row(*(display_value(row.get(column.key), column) for column in self.visible_columns), key=f"{stable}:{index}")
            if preserve_key and stable == preserve_key:
                wanted_index = index
        if self.filtered_rows:
            self.move_cursor(row=wanted_index, column=0, animate=False)

    def selected_row(self) -> dict[str, Any] | None:
        if not self.filtered_rows:
            return None
        return self.filtered_rows[max(0, min(self.cursor_row, len(self.filtered_rows) - 1))]

    @on(DataTable.HeaderSelected)
    def sort_selected_column(self, event: DataTable.HeaderSelected) -> None:
        key = str(event.column_key.value)
        self.sort_reverse = not self.sort_reverse if self.sort_key == key else False
        self.sort_key = key
        self._rebuild()

    @on(DataTable.RowHighlighted)
    def publish_highlighted_row(self, _: DataTable.RowHighlighted) -> None:
        row = self.selected_row()
        if row is not None:
            self.post_message(self.RowFocused(row))

    @on(DataTable.RowSelected)
    def publish_selected_row(self, _: DataTable.RowSelected) -> None:
        row = self.selected_row()
        if row is not None:
            self.post_message(self.RowFocused(row))
            self.post_message(self.RowActivated(row))


class ResultWorkbench(Vertical):
    class RefreshRequested(Message):
        pass

    class ExportRequested(Message):
        def __init__(self, dataset: DatasetV1):
            super().__init__()
            self.dataset = dataset

    class RowFocused(Message):
        def __init__(self, row: dict[str, Any], dataset_id: str):
            super().__init__()
            self.row = row
            self.dataset_id = dataset_id

    class RowActivated(Message):
        def __init__(self, row: dict[str, Any], dataset_id: str):
            super().__init__()
            self.row = row
            self.dataset_id = dataset_id

    class FilterChanged(Message):
        def __init__(self, dataset_id: str, value: str):
            super().__init__()
            self.dataset_id = dataset_id
            self.value = value

    def __init__(self, **kwargs: Any):
        super().__init__(**kwargs)
        self.envelope: ResultEnvelopeV1 | None = None
        self.active_dataset: DatasetV1 | None = None
        self.filter_values: dict[str, str] = {}

    def set_filter_values(self, values: dict[str, Any]) -> None:
        self.filter_values = {str(key): str(value) for key, value in values.items() if isinstance(value, str)}

    def compose(self) -> ComposeResult:
        yield MetricStrip(id="metric-strip")
        with Horizontal(id="workbench-toolbar"):
            yield Input(placeholder="Filter visible results  /", id="result-filter")
            yield Select([], prompt="Dataset", allow_blank=True, id="dataset-select", compact=True)
            yield Button("Details", id="toggle-details", variant="default", compact=True)
            yield Button("Refresh", id="refresh-view", variant="default", compact=True)
            yield Button("Export", id="export-view", variant="default", compact=True)
            yield Static("No observation", id="freshness")
        with TabbedContent(id="result-tabs"):
            with TabPane("Data", id="data-tab"):
                yield IndustrialDataTable(id="result-table")
            with TabPane("Topology", id="topology-tab"):
                yield Tree("Topology has no recorded links", id="topology-tree")
            with TabPane("Findings", id="findings-tab"):
                yield RichLog(id="findings-log", wrap=True, markup=True)
            with TabPane("Evidence", id="evidence-tab"):
                yield Static("No evidence loaded.", id="evidence-view", expand=True)
            with TabPane("Raw", id="raw-tab"):
                yield Static("{}", id="raw-view", expand=True)

    def show_envelope(self, envelope: ResultEnvelopeV1) -> None:
        previous_dataset_id = self.active_dataset.id if self.active_dataset else ""
        self.envelope = envelope
        self.query_one(MetricStrip).update_metrics(envelope.metrics)
        select = self.query_one("#dataset-select", Select)
        options = [(dataset.title, dataset.id) for dataset in envelope.datasets]
        select.set_options(options or [("No data", "")])
        if envelope.datasets:
            selected = next((item for item in envelope.datasets if item.id == previous_dataset_id), envelope.datasets[0])
            select.value = selected.id
            self.show_dataset(selected)
        else:
            self.active_dataset = None
            self.query_one(IndustrialDataTable).clear(columns=True)
        freshness = envelope.provenance.freshness.upper()
        observed = envelope.provenance.observed_at_iso or "not recorded"
        self.query_one("#freshness", Static).update(f"[{freshness}] {observed}")
        findings = self.query_one("#findings-log", RichLog)
        findings.clear()
        if envelope.findings:
            for item in envelope.findings:
                marker = "FAIL" if item.severity in {"error", "critical", "danger"} else "WARN" if item.severity == "warning" else "INFO"
                findings.write(f"[bold][{marker}] {escape(item.code)}[/] {escape(item.message)}")
        else:
            findings.write("[bold][OK][/] No current findings in this view.")
        evidence = {"summary": envelope.summary, "metrics": envelope.metrics, "provenance": envelope.provenance.to_dict()}
        self.query_one("#evidence-view", Static).update(json.dumps(evidence, indent=2, sort_keys=True, default=str))
        self.query_one("#raw-view", Static).update(json.dumps(envelope.raw, indent=2, sort_keys=True, default=str))
        self._build_topology(envelope.raw)

    def show_dataset(self, dataset: DatasetV1) -> None:
        filter_input = self.query_one("#result-filter", Input)
        if self.active_dataset is not None:
            self.filter_values[self.active_dataset.id] = filter_input.value
        self.active_dataset = dataset
        filter_input.placeholder = "Search actions by name, function, or purpose" if dataset.id == "commands" else "Filter visible results"
        filter_input.value = self.filter_values.get(dataset.id, "")
        table = self.query_one(IndustrialDataTable)
        selected = table.selected_row() or {}
        preserve = str(selected.get((table.dataset.row_key if table.dataset else "") or "") or "")
        table.load_dataset(dataset, preserve)
        table.set_filter(filter_input.value)

    def select_dataset(self, dataset_id: str) -> bool:
        if self.envelope is None:
            return False
        dataset = next((item for item in self.envelope.datasets if item.id == dataset_id), None)
        if dataset is None:
            return False
        self.query_one("#dataset-select", Select).value = dataset.id
        self.show_dataset(dataset)
        return True

    def _build_topology(self, raw: dict[str, Any]) -> None:
        tree = self.query_one("#topology-tree", Tree)
        nodes = {str(item.get("id")): item for item in raw.get("nodes") or [] if item.get("id")}
        edges = raw.get("edges") or []
        if not nodes or not edges:
            tree.reset("Topology has no recorded links")
            return
        adjacency: dict[str, list[tuple[str, dict[str, Any]]]] = defaultdict(list)
        for edge in edges:
            source, target = str(edge.get("source") or ""), str(edge.get("target") or "")
            if source and target:
                adjacency[source].append((target, edge)); adjacency[target].append((source, edge))
        root_id = str(raw.get("root") or next(iter(nodes)))
        root_info = nodes.get(root_id, {"label": root_id})
        tree.reset(str(root_info.get("label") or root_id), data=root_info)
        queue: deque[tuple[str, Any, int]] = deque([(root_id, tree.root, 0)])
        visited = {root_id}
        while queue:
            current, parent, depth = queue.popleft()
            if depth >= 8:
                parent.add_leaf("[depth limit]", data={"kind": "limit"}); continue
            for neighbor, edge in sorted(adjacency.get(current, []), key=lambda item: str(nodes.get(item[0], {}).get("label") or item[0])):
                label = str(nodes.get(neighbor, {}).get("label") or neighbor)
                port = edge.get("local_port") if current == edge.get("source") else edge.get("remote_port")
                if neighbor in visited:
                    parent.add_leaf(f"{label} via {port or '?'} [cycle]", data={**nodes.get(neighbor, {}), "edge": edge, "cycle": True}); continue
                visited.add(neighbor)
                child = parent.add(f"{label} via {port or '?'}", data={**nodes.get(neighbor, {}), "edge": edge}, expand=depth < 2)
                queue.append((neighbor, child, depth + 1))
        tree.root.expand()

    @on(Input.Changed, "#result-filter")
    def filter_changed(self, event: Input.Changed) -> None:
        self.query_one(IndustrialDataTable).set_filter(event.value)
        if self.active_dataset:
            self.filter_values[self.active_dataset.id] = event.value
            self.post_message(self.FilterChanged(self.active_dataset.id, event.value))

    @on(Select.Changed, "#dataset-select")
    def dataset_changed(self, event: Select.Changed) -> None:
        if self.envelope is None:
            return
        dataset = next((item for item in self.envelope.datasets if item.id == str(event.value)), None)
        if dataset:
            self.show_dataset(dataset)

    @on(Button.Pressed, "#refresh-view")
    def refresh_pressed(self) -> None:
        self.post_message(self.RefreshRequested())

    @on(Button.Pressed, "#toggle-details")
    def details_pressed(self) -> None:
        self.set_details(not self.has_class("details-open"))

    def set_details(self, visible: bool) -> None:
        self.set_class(visible, "details-open")
        self.query_one("#toggle-details", Button).label = "Less" if visible else "Details"
        if not visible:
            self.query_one("#result-tabs", TabbedContent).active = "data-tab"

    @on(Button.Pressed, "#export-view")
    def export_pressed(self) -> None:
        visible = self.current_export_dataset()
        if visible:
            self.post_message(self.ExportRequested(visible))

    def current_export_dataset(self) -> DatasetV1 | None:
        if self.active_dataset:
            table = self.query_one(IndustrialDataTable)
            return DatasetV1(
                id=self.active_dataset.id,
                title=self.active_dataset.title,
                rows=list(table.filtered_rows),
                columns=list(table.visible_columns),
                row_key=self.active_dataset.row_key,
                default_sort=table.sort_key,
                default_descending=table.sort_reverse,
                row_actions=list(self.active_dataset.row_actions),
            )
        return None

    @on(IndustrialDataTable.RowFocused)
    def row_focused(self, event: IndustrialDataTable.RowFocused) -> None:
        self.post_message(self.RowFocused(event.row, self.active_dataset.id if self.active_dataset else ""))

    @on(IndustrialDataTable.RowActivated)
    def row_activated(self, event: IndustrialDataTable.RowActivated) -> None:
        self.post_message(self.RowActivated(event.row, self.active_dataset.id if self.active_dataset else ""))

    @on(Tree.NodeSelected, "#topology-tree")
    def topology_node_selected(self, event: Tree.NodeSelected) -> None:
        if isinstance(event.node.data, dict):
            self.post_message(self.RowFocused(dict(event.node.data), "topology"))


def inspector_table(row: dict[str, Any]) -> Table:
    table = Table.grid(padding=(0, 1), expand=True)
    table.add_column(style="dim", no_wrap=True); table.add_column(overflow="fold")
    priority = ("status", "kind", "name", "hostname", "ip", "mac", "platform", "model", "switch_name", "switch_port", "created_at", "last_seen")
    keys = [key for key in priority if key in row] + [key for key in row if key not in priority and not key.endswith("_iso") and key not in {"raw_json", "attrs_json"}]
    for key in keys:
        value = row.get(key)
        if key.endswith(("_at", "_seen", "_failed")):
            value = fmt_time(value) or value
        if isinstance(value, (dict, list)):
            value = json.dumps(value, sort_keys=True, default=str)
        table.add_row(key.replace("_", " ").title(), str(value if value is not None else ""))
    return table
