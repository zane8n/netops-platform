"""Correlate an operator's own Excel workbooks with Netrune's inventory.

An operator keeps a sheet of switches; Netrune's scans are fresher. This reads
the workbook, finds each sheet's header row, works out which column holds which
field, matches every data row to exactly one switch, and writes Netrune's values
into the cells that are empty or out of date -- leaving every other cell, sheet,
style, and formula as the operator built it.

Nothing here touches a switch or Netrune's database. The CLI layer
(`excel_cli.py`) owns the preview/backup/apply/verify/audit lifecycle; this
module is the pure planning and workbook mechanics so it can be tested without
an App.
"""

from __future__ import annotations

import copy
import datetime as dt
import ipaddress
import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from netops_platform.identity import _host_label, normalize_mac
from netops_platform.inventory_ingest import _meaningful_model


FIELDS = ("hostname", "ip", "model", "serial", "mac", "platform", "status", "last_seen")
IDENTITY_FIELDS = ("serial", "mac", "ip", "hostname")
# Status and Last Seen are opt-in (--fields): an asset sheet's "Status" is
# usually lifecycle ("In stock", "Decommissioned"), not reachability.
DEFAULT_FIELDS = ("hostname", "ip", "model", "serial", "mac", "platform")
FIELD_LABELS = {
    "hostname": "Hostname", "ip": "IP Address", "model": "Model", "serial": "Serial Number",
    "mac": "Base MAC", "platform": "Platform", "status": "Status", "last_seen": "Last Seen",
}

# Normalized header text (lowercase letters and digits only) to field.
HEADER_SYNONYMS: Dict[str, Set[str]] = {
    "hostname": {"hostname", "host", "name", "devicename", "switchname", "switch", "device", "sysname",
                 "systemname", "nodename", "node", "switchhostname", "devicehostname"},
    "ip": {"ip", "ipaddress", "ipaddr", "mgmtip", "managementip", "mgmtipaddress", "managementipaddress",
           "ipv4", "ipv4address", "switchip", "deviceip", "mgmtaddress", "managementaddress"},
    "mac": {"mac", "macaddress", "basemac", "basemacaddress", "basemacaddr", "baseethernetmac",
            "baseethernetmacaddress", "systemmac", "chassismac", "switchmac"},
    "serial": {"serial", "serialnumber", "serialno", "serialnum", "sn", "sno", "systemserial",
               "systemserialnumber", "chassisserial", "motherboardserial", "motherboardserialnumber"},
    "model": {"model", "modelnumber", "modelno", "devicemodel", "switchmodel", "hardwaremodel",
              "hardware", "pid", "productmodel"},
    "platform": {"platform", "vendor", "os", "manufacturer", "make", "devicetype"},
    "status": {"status", "state", "reachability", "onlinestatus", "netrunestatus"},
    "last_seen": {"lastseen", "lastpolled", "lastcontact", "lastupdated", "lastchecked"},
}

# Parts of a workbook openpyxl does not carry through a load/save round trip.
FEATURES_LOST_ON_SAVE = {
    "xl/charts/": "charts",
    "xl/drawings/": "drawings, shapes, or images",
    "xl/media/": "embedded images",
    "xl/pivotTables/": "pivot tables",
    "xl/slicers/": "slicers",
    "xl/timelines/": "timelines",
    "xl/metadata.xml": "dynamic-array (spill) formulas",
    "xl/externalLinks/": "external workbook links",
}

PLACEHOLDERS = {"", "n/a", "na", "none", "null", "unknown", "-", "--", "tbd", "?"}
IPV4 = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")


class ExcelError(Exception):
    """A workbook problem the operator can act on."""


def require_openpyxl() -> Any:
    try:
        import openpyxl  # noqa: F401
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise ExcelError(
            "Excel support needs openpyxl, which is not installed for this Python. "
            "On Arch: sudo pacman -S python-openpyxl  (or: pip install 'netrune[excel]')"
        ) from exc
    return openpyxl


# --------------------------------------------------------------------------
# Value normalization


def _blank(value: Any) -> bool:
    return value is None or str(value).strip().lower() in PLACEHOLDERS


def header_key(value: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value or "").lower())


def header_field(value: Any) -> str:
    key = header_key(value)
    if not key:
        return ""
    for name, synonyms in HEADER_SYNONYMS.items():
        if key in synonyms:
            return name
    # Looser forms such as "Switch Base MAC (Netrune)" or "Mgmt IPv4 addr".
    if "mac" in key and "machine" not in key:
        return "mac"
    if "serial" in key:
        return "serial"
    if "model" in key:
        return "model"
    if "hostname" in key or key.endswith("devicename") or key.endswith("switchname"):
        return "hostname"
    if key.endswith("ip") or "ipaddress" in key or "ipv4" in key:
        return "ip"
    return ""


def name_key(value: Any) -> str:
    return re.sub(r"[^A-Z0-9]", "", _host_label(value).upper())


def ip_key(value: Any) -> str:
    match = IPV4.search(str(value or ""))
    if not match:
        return ""
    try:
        return str(ipaddress.IPv4Address(match.group(1)))
    except ValueError:
        return ""


def serial_key(value: Any) -> str:
    text = re.sub(r"[^A-Z0-9-]", "", str(value or "").upper())
    return "" if text.lower() in PLACEHOLDERS or text in {"NA", "NOTAVAIL", "NOTAVAILABLE"} else text


def identity_key(field_name: str, value: Any) -> str:
    if _blank(value):
        return ""
    if field_name == "hostname":
        return name_key(value)
    if field_name == "ip":
        return ip_key(value)
    if field_name == "mac":
        return normalize_mac(value)
    if field_name == "serial":
        return serial_key(value)
    return str(value).strip().upper()


def mac_style(samples: Iterable[Any]) -> Tuple[str, bool]:
    """The MAC notation a column already uses, so new values match it."""
    counts: Dict[str, int] = {}
    upper = lower = 0
    for sample in samples:
        text = str(sample or "").strip()
        if not normalize_mac(text):
            continue
        if re.fullmatch(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", text):
            style = "colon"
        elif re.fullmatch(r"(?:[0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}", text):
            style = "hyphen"
        elif re.fullmatch(r"[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}", text):
            style = "dotted"
        elif re.fullmatch(r"[0-9A-Fa-f]{6}-[0-9A-Fa-f]{6}", text):
            style = "hyphen-six"
        else:
            style = "bare"
        counts[style] = counts.get(style, 0) + 1
        letters = re.sub(r"[^A-Fa-f]", "", text)
        upper += letters.isupper() and bool(letters)
        lower += letters.islower() and bool(letters)
    style = max(counts, key=counts.get) if counts else "colon"
    return style, upper > lower


def format_mac_as(value: Any, style: str, upper: bool) -> str:
    clean = normalize_mac(value)
    if not clean:
        return ""
    if style == "dotted":
        text = ".".join(clean[i:i + 4] for i in range(0, 12, 4))
    elif style == "hyphen-six":
        text = f"{clean[:6]}-{clean[6:]}"
    elif style == "hyphen":
        text = "-".join(clean[i:i + 2] for i in range(0, 12, 2))
    elif style == "bare":
        text = clean
    else:
        text = ":".join(clean[i:i + 2] for i in range(0, 12, 2))
    return text.upper() if upper else text


# --------------------------------------------------------------------------
# Netrune side


@dataclass
class DeviceIndex:
    devices: List[Dict[str, Any]]
    keys: Dict[str, Dict[str, Set[int]]] = field(default_factory=dict)

    @classmethod
    def build(cls, devices: Sequence[Mapping[str, Any]]) -> "DeviceIndex":
        index = cls([dict(device) for device in devices], {name: {} for name in IDENTITY_FIELDS})
        for position, device in enumerate(index.devices):
            values = {
                "ip": [device.get("ip"), *(device.get("addresses") or [])],
                "mac": [device.get("mac"), *(device.get("macs") or [])],
                "serial": [device.get("serial"), *(device.get("serials") or [])],
                "hostname": [device.get("hostname"), device.get("name"), *(device.get("aliases") or [])],
            }
            for kind, items in values.items():
                for item in items:
                    key = identity_key(kind, item)
                    if key:
                        index.keys[kind].setdefault(key, set()).add(position)
        return index

    def lookup(self, kind: str, value: Any) -> Set[int]:
        key = identity_key(kind, value)
        return set(self.keys.get(kind, {}).get(key, set())) if key else set()


def device_value(device: Mapping[str, Any], field_name: str) -> Any:
    if field_name == "last_seen":
        try:
            seconds = int(device.get("last_seen") or 0)
        except (TypeError, ValueError):
            return None
        # Naive local time: Excel has no time zones, and an operator reads the
        # sheet in the time the box reports.
        return dt.datetime.fromtimestamp(seconds).replace(microsecond=0) if seconds > 0 else None
    value = device.get(field_name)
    if field_name == "hostname":
        value = device.get("hostname") or device.get("name")
    if _blank(value):
        return None
    if field_name == "mac":
        return normalize_mac(value) or None
    if field_name == "model" and not _meaningful_model(value):
        return None
    return str(value).strip()


# --------------------------------------------------------------------------
# Workbook side


@dataclass
class SheetLayout:
    title: str
    header_row: int
    columns: Dict[str, int]
    headers: Dict[int, str]
    first_row: int
    last_row: int
    hostname_fqdn: bool = False
    mac_format: Tuple[str, bool] = ("colon", False)

    def as_dict(self) -> Dict[str, Any]:
        from openpyxl.utils import get_column_letter
        return {
            "sheet": self.title,
            "header_row": self.header_row,
            "data_rows": max(0, self.last_row - self.first_row + 1),
            "columns": {name: f"{get_column_letter(col)} ({self.headers.get(col, '')})" for name, col in sorted(self.columns.items(), key=lambda item: item[1])},
        }


def parse_column_map(spec: str) -> Dict[str, str]:
    """`--map "Mgmt Addr=ip,F=mac"`: header text or column letter to field."""
    mapping: Dict[str, str] = {}
    for part in [item for item in (spec or "").split(",") if item.strip()]:
        if "=" not in part:
            raise ExcelError(f"--map entry '{part}' must look like 'Header=field' or 'C=field'.")
        left, _, right = part.rpartition("=")
        target = right.strip().lower().replace("-", "_")
        if target not in FIELDS:
            raise ExcelError(f"--map field '{right.strip()}' is not one of: {', '.join(FIELDS)}.")
        mapping[left.strip()] = target
    return mapping


def detect_layout(ws: Any, overrides: Optional[Mapping[str, str]] = None, scan_rows: int = 30) -> Optional[SheetLayout]:
    """Find the header row: the first of the top rows naming the most fields."""
    from openpyxl.utils import column_index_from_string
    overrides = dict(overrides or {})
    best: Optional[Tuple[int, Dict[str, int], Dict[int, str]]] = None
    max_column = ws.max_column or 0
    for row in range(1, min(scan_rows, ws.max_row or 0) + 1):
        columns: Dict[str, int] = {}
        headers: Dict[int, str] = {}
        for col in range(1, max_column + 1):
            value = ws.cell(row=row, column=col).value
            if value is None or not isinstance(value, str):
                continue
            headers[col] = value.strip()
            name = header_field(value)
            if name and name not in columns:
                columns[name] = col
        for key, target in overrides.items():
            col = 0
            if re.fullmatch(r"[A-Za-z]{1,3}", key):
                col = column_index_from_string(key.upper())
            elif key.isdigit():
                col = int(key)
            else:
                col = next((c for c, text in headers.items() if header_key(text) == header_key(key)), 0)
            if col:
                columns = {name: c for name, c in columns.items() if c != col}
                columns[target] = col
        if not any(name in columns for name in IDENTITY_FIELDS) or len(columns) < 2:
            continue
        if best is None or len(columns) > len(best[1]):
            best = (row, columns, headers)
    if best is None:
        return None
    header_row, columns, headers = best
    last_row = header_row
    for row in range(header_row + 1, (ws.max_row or header_row) + 1):
        if any(not _blank(ws.cell(row=row, column=col).value) for col in columns.values()):
            last_row = row
    layout = SheetLayout(ws.title, header_row, columns, headers, header_row + 1, last_row)
    if "hostname" in columns:
        names = [ws.cell(row=r, column=columns["hostname"]).value for r in range(layout.first_row, last_row + 1)]
        names = [str(n).strip() for n in names if not _blank(n)]
        dotted = sum(1 for n in names if "." in n and not ip_key(n))
        layout.hostname_fqdn = bool(names) and dotted * 2 > len(names)
    if "mac" in columns:
        layout.mac_format = mac_style(ws.cell(row=r, column=columns["mac"]).value for r in range(layout.first_row, last_row + 1))
    return layout


def workbook_features(path: Path) -> List[str]:
    try:
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()
    except zipfile.BadZipFile as exc:
        raise ExcelError(f"{path} is not an .xlsx/.xlsm workbook (not a zip container).") from exc
    found = []
    for prefix, label in FEATURES_LOST_ON_SAVE.items():
        if any(name.startswith(prefix) for name in names) and label not in found:
            found.append(label)
    return found


def excel_lock_file(path: Path) -> Optional[Path]:
    """Excel's `~$name.xlsx` owner file: the workbook is open somewhere."""
    for candidate in (path.with_name("~$" + path.name), path.with_name("~$" + path.name[2:])):
        if candidate.exists() and candidate != path:
            return candidate
    return None


def load_workbook(path: Path) -> Any:
    openpyxl = require_openpyxl()
    suffix = path.suffix.lower()
    if suffix not in {".xlsx", ".xlsm"}:
        raise ExcelError(f"{path.name}: only .xlsx and .xlsm workbooks are supported"
                         + (" (save .xls files as .xlsx first)." if suffix == ".xls" else "."))
    if not path.is_file():
        raise ExcelError(f"{path} does not exist.")
    try:
        return openpyxl.load_workbook(path, keep_vba=suffix == ".xlsm", rich_text=True)
    except (OSError, ValueError, KeyError, zipfile.BadZipFile) as exc:
        raise ExcelError(f"Could not read {path.name}: {exc}") from exc


# --------------------------------------------------------------------------
# Planning


@dataclass
class CellChange:
    sheet: str
    row: int
    column: int
    header: str
    field: str
    old: Any
    new: Any
    matched_by: str
    device: str
    kind: str = "update"  # update | fill | add

    def as_dict(self) -> Dict[str, Any]:
        from openpyxl.utils import get_column_letter
        return {
            "sheet": self.sheet, "cell": f"{get_column_letter(self.column)}{self.row}", "row": self.row,
            "column": self.header, "field": self.field, "old": _display(self.old), "new": _display(self.new),
            "matched_by": self.matched_by, "device": self.device, "kind": self.kind,
        }


@dataclass
class SheetPlan:
    layout: SheetLayout
    changes: List[CellChange] = field(default_factory=list)
    matched_rows: int = 0
    unmatched: List[Dict[str, Any]] = field(default_factory=list)
    conflicts: List[Dict[str, Any]] = field(default_factory=list)
    kept: List[Dict[str, Any]] = field(default_factory=list)
    duplicates: List[Dict[str, Any]] = field(default_factory=list)
    matched_devices: Set[int] = field(default_factory=set)
    additions: List[Dict[str, Any]] = field(default_factory=list)


def _display(value: Any) -> str:
    if isinstance(value, dt.datetime):
        return value.strftime("%Y-%m-%d %H:%M")
    return "" if value is None else str(value)


def _equivalent(field_name: str, current: Any, desired: Any) -> bool:
    if _blank(current):
        return False
    if field_name in IDENTITY_FIELDS:
        return identity_key(field_name, current) == identity_key(field_name, desired)
    if field_name == "last_seen":
        if isinstance(current, dt.datetime) and isinstance(desired, dt.datetime):
            return abs((current - desired).total_seconds()) < 60
        return False
    have, want = str(current).strip().lower(), str(desired).strip().lower()
    if field_name == "platform":
        # "Cisco" in a Vendor column already agrees with "Cisco IOS".
        return have in want or want in have
    return have == want


def _cell_text_for(layout: SheetLayout, field_name: str, value: Any) -> Any:
    if field_name == "mac":
        style, upper = layout.mac_format
        return format_mac_as(value, style, upper)
    if field_name == "hostname" and not layout.hostname_fqdn:
        return _host_label(value)
    return value


def plan_sheet(
    ws: Any,
    layout: SheetLayout,
    index: DeviceIndex,
    *,
    fields: Sequence[str] = DEFAULT_FIELDS,
    fill_only: bool = False,
    prefer: str = "",
    add_missing: bool = False,
) -> SheetPlan:
    from openpyxl.cell.cell import MergedCell
    plan = SheetPlan(layout)
    writable = [name for name in FIELDS if name in layout.columns and name in fields]
    owners: Dict[int, List[int]] = {}
    for row in range(layout.first_row, layout.last_row + 1):
        cells = {name: ws.cell(row=row, column=col).value for name, col in layout.columns.items()}
        if all(_blank(cells.get(name)) for name in IDENTITY_FIELDS):
            continue
        votes: Dict[str, int] = {}
        ambiguous: List[str] = []
        for kind in IDENTITY_FIELDS:
            if kind not in layout.columns or _blank(cells.get(kind)):
                continue
            hits = index.lookup(kind, cells[kind])
            if len(hits) == 1:
                votes[kind] = next(iter(hits))
            elif len(hits) > 1:
                ambiguous.append(kind)
        label = next((str(cells[k]) for k in ("hostname", "ip", "serial", "mac") if not _blank(cells.get(k))), f"row {row}")
        distinct = set(votes.values())
        if not distinct:
            plan.unmatched.append({"sheet": layout.title, "row": row, "row_label": label,
                                   "reason": "ambiguous " + "/".join(ambiguous) if ambiguous else "no Netrune device has these values"})
            continue
        if len(distinct) > 1:
            if prefer and prefer in votes:
                distinct = {votes[prefer]}
            else:
                plan.conflicts.append({
                    "sheet": layout.title, "row": row, "row_label": label,
                    "points_to": ", ".join(f"{kind}->{_device_label(index.devices[pos])}" for kind, pos in votes.items()),
                })
                continue
        position = next(iter(distinct))
        device = index.devices[position]
        matched_by = "+".join(kind for kind, pos in votes.items() if pos == position)
        plan.matched_rows += 1
        plan.matched_devices.add(position)
        owners.setdefault(position, []).append(row)
        for name in writable:
            desired = device_value(device, name)
            if desired is None:
                continue
            column = layout.columns[name]
            cell = ws.cell(row=row, column=column)
            if isinstance(cell, MergedCell):
                continue
            current = cell.value
            if cell.data_type == "f" or (isinstance(current, str) and current.startswith("=")):
                if not _equivalent(name, current, desired):
                    plan.kept.append({"sheet": layout.title, "row": row, "column": layout.headers.get(column, name), "reason": "formula cell left as-is"})
                continue
            if _equivalent(name, current, desired):
                continue
            if fill_only and not _blank(current):
                plan.kept.append({"sheet": layout.title, "row": row, "column": layout.headers.get(column, name),
                                  "reason": f"--fill-only kept '{_display(current)}' (Netrune: '{_display(_cell_text_for(layout, name, desired))}')"})
                continue
            plan.changes.append(CellChange(
                layout.title, row, column, layout.headers.get(column, name), name, current,
                _cell_text_for(layout, name, desired), matched_by, _device_label(device),
                "fill" if _blank(current) else "update",
            ))
    for position, rows in owners.items():
        if len(rows) > 1:
            plan.duplicates.append({"sheet": layout.title, "device": _device_label(index.devices[position]), "rows": ", ".join(map(str, rows))})
    if add_missing:
        next_row = layout.last_row + 1
        for position, device in enumerate(index.devices):
            if position in plan.matched_devices:
                continue
            values = {name: device_value(device, name) for name in writable}
            if not any(values.get(name) is not None for name in IDENTITY_FIELDS):
                continue
            plan.additions.append({"row": next_row, "device": _device_label(device)})
            for name in writable:
                if values.get(name) is None:
                    continue
                column = layout.columns[name]
                plan.changes.append(CellChange(
                    layout.title, next_row, column, layout.headers.get(column, name), name, None,
                    _cell_text_for(layout, name, values[name]), "not in sheet", _device_label(device), "add",
                ))
            next_row += 1
    return plan


def _device_label(device: Mapping[str, Any]) -> str:
    name = _host_label(device.get("hostname") or device.get("name") or "")
    return f"{name} ({device.get('ip')})" if name else str(device.get("ip") or "?")


# --------------------------------------------------------------------------
# Applying


def apply_plans(wb: Any, plans: Sequence[SheetPlan], *, comments: bool = True, highlight: bool = False,
                stamp: str = "") -> int:
    from openpyxl.comments import Comment
    from openpyxl.formula.translate import Translator
    from openpyxl.styles import PatternFill
    from openpyxl.utils import get_column_letter
    fill = PatternFill(start_color="FFF2CC", end_color="FFF2CC", fill_type="solid")
    stamp = stamp or dt.datetime.now().strftime("%Y-%m-%d %H:%M")
    applied = 0
    for plan in plans:
        ws = wb[plan.layout.title]
        template_row = plan.layout.last_row
        added_rows = sorted({change.row for change in plan.changes if change.kind == "add"})
        for row in added_rows:
            # A new row looks and calculates like the one above it: same
            # styles, and that row's formulas re-pointed at this row.
            for col in range(1, (ws.max_column or 0) + 1):
                source = ws.cell(row=template_row, column=col)
                target = ws.cell(row=row, column=col)
                if source.has_style:
                    target._style = copy.copy(source._style)
                if source.data_type == "f" and isinstance(source.value, str):
                    origin = f"{get_column_letter(col)}{template_row}"
                    target.value = Translator(source.value, origin=origin).translate_formula(f"{get_column_letter(col)}{row}")
        for change in plan.changes:
            cell = ws.cell(row=change.row, column=change.column)
            cell.value = change.new
            if isinstance(change.new, dt.datetime) and cell.number_format in {"General", ""}:
                cell.number_format = "yyyy-mm-dd hh:mm"
            if comments:
                note = (f"Netrune {stamp}: added {change.device}" if change.kind == "add"
                        else f"Netrune {stamp}: was '{_display(change.old)}'" if change.kind == "update"
                        else f"Netrune {stamp}: filled from {change.device}")
                cell.comment = Comment(note, "Netrune", width=260, height=60)
            if highlight:
                cell.fill = fill
            applied += 1
        if added_rows:
            last = max(added_rows)
            for table in ws.tables.values():
                start, _, end = table.ref.partition(":")
                end_row = int(re.sub(r"[A-Z]", "", end))
                start_row = int(re.sub(r"[A-Z]", "", start))
                if start_row <= plan.layout.header_row <= end_row and end_row >= plan.layout.last_row:
                    table.ref = f"{start}:{re.sub(r'[0-9]', '', end)}{last}"
                    if table.autoFilter is not None:
                        table.autoFilter.ref = table.ref
    return applied


def verify_saved(path: Path, plans: Sequence[SheetPlan]) -> List[str]:
    """Reopen what was written and confirm every planned cell holds its value."""
    wb = load_workbook(path)
    problems = []
    for plan in plans:
        ws = wb[plan.layout.title]
        for change in plan.changes:
            value = ws.cell(row=change.row, column=change.column).value
            if isinstance(change.new, dt.datetime):
                ok = isinstance(value, dt.datetime) and abs((value - change.new).total_seconds()) < 1
            else:
                ok = str(value) == str(change.new)
            if not ok:
                problems.append(f"{change.sheet}!{change.as_dict()['cell']}: expected '{_display(change.new)}', found '{_display(value)}'")
    return problems


# --------------------------------------------------------------------------
# A fresh tracker workbook


TRACKER_STATUSES = ("Not started", "Planned", "In progress", "Blocked", "Done", "Cancelled")
TRACKER_CHANGES = ("Hardware swap", "Firmware upgrade", "VLAN change", "Readdress", "Port change",
                   "Decommission", "New install", "Other")


def build_tracker(devices: Sequence[Mapping[str, Any]], path: Path, *, generated: str = "",
                  migration_rows: int = 300) -> Dict[str, Any]:
    """Asset inventory, live summary, and a migration/change tracker in one workbook.

    Everything after the data is formulas (COUNTIFS, INDEX/MATCH, TODAY), so
    the summary and tracker keep calculating as the operator edits statuses,
    owners, and dates -- and `netrune excel sync` can refresh the Inventory
    sheet later without disturbing them.
    """
    openpyxl = require_openpyxl()
    from openpyxl.chart import BarChart, Reference
    from openpyxl.formatting.rule import CellIsRule, FormulaRule
    from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
    from openpyxl.utils import get_column_letter
    from openpyxl.worksheet.datavalidation import DataValidation
    from openpyxl.worksheet.table import Table, TableStyleInfo

    generated = generated or dt.datetime.now().strftime("%Y-%m-%d %H:%M")
    header_font = Font(bold=True, color="FFFFFF")
    header_fill = PatternFill(start_color="1F3864", end_color="1F3864", fill_type="solid")
    title_font = Font(bold=True, size=14, color="1F3864")
    muted = Font(italic=True, color="595959")
    red = PatternFill(start_color="F8CBAD", end_color="F8CBAD", fill_type="solid")
    amber = PatternFill(start_color="FFE699", end_color="FFE699", fill_type="solid")
    green = PatternFill(start_color="C6E0B4", end_color="C6E0B4", fill_type="solid")
    grey = PatternFill(start_color="D9D9D9", end_color="D9D9D9", fill_type="solid")
    thin = Side(style="thin", color="BFBFBF")

    wb = openpyxl.Workbook()
    inv = wb.active
    inv.title = "Inventory"
    columns = ["Hostname", "IP Address", "Platform", "Model", "Serial Number", "Base MAC", "Status",
               "Last Seen", "Days Since Seen", "Site", "Owner", "Notes"]
    inv.append(columns)
    rows = sorted(devices, key=lambda d: (_host_label(d.get("hostname") or d.get("name") or "").lower(), str(d.get("ip") or "")))
    for number, device in enumerate(rows, start=2):
        inv.append([
            _host_label(device.get("hostname") or device.get("name") or "") or None,
            device.get("ip") or None,
            device_value(device, "platform"),
            device_value(device, "model"),
            device_value(device, "serial"),
            format_mac_as(device.get("mac"), "colon", False) or None,
            device_value(device, "status"),
            device_value(device, "last_seen"),
            f'=IF(H{number}="","",INT(TODAY()-H{number}))',
            None, None, None,
        ])
        inv.cell(row=number, column=8).number_format = "yyyy-mm-dd hh:mm"
    last = max(2, len(rows) + 1)
    table = Table(displayName="Inventory", ref=f"A1:{get_column_letter(len(columns))}{last}")
    table.tableStyleInfo = TableStyleInfo(name="TableStyleMedium2", showRowStripes=True)
    inv.add_table(table)
    inv.freeze_panes = "B2"
    for col, width in zip("ABCDEFGHIJKL", (30, 15, 14, 24, 16, 19, 10, 17, 10, 16, 14, 40)):
        inv.column_dimensions[col].width = width
    inv.conditional_formatting.add(f"G2:G{last}", CellIsRule(operator="equal", formula=['"OFFLINE"'], fill=red))
    inv.conditional_formatting.add(f"G2:G{last}", CellIsRule(operator="equal", formula=['"ONLINE"'], fill=green))
    inv.conditional_formatting.add(f"I2:I{last}", FormulaRule(formula=[f'AND(ISNUMBER(I2),I2>7)'], fill=amber))

    summary = wb.create_sheet("Summary", 0)
    summary["A1"] = "Network inventory summary"
    summary["A1"].font = title_font
    summary["A2"] = f"Generated by Netrune {generated}. Counts are live formulas over the Inventory sheet."
    summary["A2"].font = muted
    rng = lambda col: f"Inventory!${col}$2:${col}${last}"  # noqa: E731
    kpis = [
        ("Devices", f'=COUNTA({rng("A")})'),
        ("Online", f'=COUNTIF({rng("G")},"ONLINE")'),
        ("Offline", f'=COUNTIF({rng("G")},"OFFLINE")'),
        ("Online %", "=IF(B4=0,0,B5/B4)"),
        ("Not seen for 7+ days", f'=COUNTIF({rng("I")},">7")'),
        ("Missing serial", f'=COUNTBLANK({rng("E")})'),
        ("Missing base MAC", f'=COUNTBLANK({rng("F")})'),
    ]
    for offset, (label, formula) in enumerate(kpis, start=4):
        summary.cell(row=offset, column=1, value=label).font = Font(bold=True)
        summary.cell(row=offset, column=2, value=formula)
    summary["B7"].number_format = "0.0%"
    models = sorted({str(device_value(d, "model")) for d in rows if device_value(d, "model")})
    platforms = sorted({str(d.get("platform")) for d in rows if not _blank(d.get("platform"))})
    start = 13
    for col, title in ((1, "Model"), (2, "Devices"), (3, "Online"), (4, "Offline")):
        cell = summary.cell(row=start - 1, column=col, value=title)
        cell.font, cell.fill = header_font, header_fill
    for offset, model in enumerate(models):
        row = start + offset
        summary.cell(row=row, column=1, value=model)
        summary.cell(row=row, column=2, value=f"=COUNTIF({rng('D')},A{row})")
        summary.cell(row=row, column=3, value=f'=COUNTIFS({rng("D")},A{row},{rng("G")},"ONLINE")')
        summary.cell(row=row, column=4, value=f'=COUNTIFS({rng("D")},A{row},{rng("G")},"OFFLINE")')
    if models:
        chart = BarChart()
        chart.type = "bar"
        chart.title = "Devices by model"
        chart.style = 10
        chart.height = max(7.5, 0.5 * len(models) + 3)
        chart.width = 16
        data = Reference(summary, min_col=2, min_row=start - 1, max_row=start + len(models) - 1)
        cats = Reference(summary, min_col=1, min_row=start, max_row=start + len(models) - 1)
        chart.add_data(data, titles_from_data=True)
        chart.set_categories(cats)
        chart.legend = None
        summary.add_chart(chart, "F4")
    prow = start + len(models) + 2
    for col, title in ((1, "Platform"), (2, "Devices")):
        cell = summary.cell(row=prow, column=col, value=title)
        cell.font, cell.fill = header_font, header_fill
    for offset, platform in enumerate(platforms, start=1):
        summary.cell(row=prow + offset, column=1, value=platform)
        summary.cell(row=prow + offset, column=2, value=f"=COUNTIF({rng('C')},A{prow + offset})")
    summary.column_dimensions["A"].width = 30
    summary.column_dimensions["B"].width = 12

    mig = wb.create_sheet("Migration Tracker")
    mig_columns = ["Device", "IP Address", "Current Model", "Change Type", "Target / Details", "Owner",
                   "Planned Date", "Status", "Completed Date", "Days Overdue", "Notes"]
    mig.append(mig_columns)
    end = migration_rows + 1
    for row in range(2, end + 1):
        lookup = f"MATCH(A{row},Inventory!$A$2:$A${last},0)"
        mig.cell(row=row, column=2, value=f'=IF(A{row}="","",IFERROR(INDEX(Inventory!$B$2:$B${last},{lookup}),"not in inventory"))')
        mig.cell(row=row, column=3, value=f'=IF(A{row}="","",IFERROR(INDEX(Inventory!$D$2:$D${last},{lookup}),""))')
        mig.cell(row=row, column=10, value=f'=IF(OR(G{row}="",H{row}="Done",H{row}="Cancelled"),"",MAX(0,INT(TODAY()-G{row})))')
        mig.cell(row=row, column=7).number_format = "yyyy-mm-dd"
        mig.cell(row=row, column=9).number_format = "yyyy-mm-dd"
    mig_table = Table(displayName="MigrationTracker", ref=f"A1:{get_column_letter(len(mig_columns))}{end}")
    mig_table.tableStyleInfo = TableStyleInfo(name="TableStyleMedium4", showRowStripes=True)
    mig.add_table(mig_table)
    mig.freeze_panes = "B2"
    for col, width in zip("ABCDEFGHIJK", (30, 15, 22, 18, 36, 14, 13, 13, 15, 12, 40)):
        mig.column_dimensions[col].width = width
    device_list = DataValidation(type="list", formula1=f"=Inventory!$A$2:$A${last}", allow_blank=True,
                                 showErrorMessage=False)
    status_list = DataValidation(type="list", formula1='"' + ",".join(TRACKER_STATUSES) + '"', allow_blank=True)
    change_list = DataValidation(type="list", formula1='"' + ",".join(TRACKER_CHANGES) + '"', allow_blank=True)
    dates = DataValidation(type="date", operator="greaterThan", formula1="36526", allow_blank=True)
    for validation, cells in ((device_list, f"A2:A{end}"), (change_list, f"D2:D{end}"),
                              (status_list, f"H2:H{end}"), (dates, f"G2:G{end}"), (dates, f"I2:I{end}")):
        if validation not in mig.data_validations.dataValidation:
            mig.add_data_validation(validation)
        validation.add(cells)
    mig.conditional_formatting.add(f"A2:K{end}", FormulaRule(formula=['$H2="Done"'], fill=green))
    mig.conditional_formatting.add(f"A2:K{end}", FormulaRule(formula=['$H2="Blocked"'], fill=red))
    mig.conditional_formatting.add(f"A2:K{end}", FormulaRule(formula=['$H2="Cancelled"'], fill=grey))
    mig.conditional_formatting.add(f"J2:J{end}", FormulaRule(formula=['AND(ISNUMBER(J2),J2>0)'], fill=amber))
    mig.conditional_formatting.add(f"B2:B{end}", CellIsRule(operator="equal", formula=['"not in inventory"'], fill=red))

    trow = prow + len(platforms) + 3
    summary.cell(row=trow, column=1, value="Migration progress").font = title_font
    for col, title in ((1, "Status"), (2, "Changes")):
        cell = summary.cell(row=trow + 1, column=col, value=title)
        cell.font, cell.fill = header_font, header_fill
    for offset, status in enumerate(TRACKER_STATUSES, start=2):
        summary.cell(row=trow + offset, column=1, value=status)
        summary.cell(row=trow + offset, column=2, value=f"=COUNTIF('Migration Tracker'!$H$2:$H${end},A{trow + offset})")
    done_row = trow + len(TRACKER_STATUSES) + 2
    summary.cell(row=done_row, column=1, value="Complete %").font = Font(bold=True)
    summary.cell(row=done_row, column=2, value=(
        f"=IFERROR(COUNTIF('Migration Tracker'!$H$2:$H${end},\"Done\")/"
        f"(COUNTA('Migration Tracker'!$H$2:$H${end})-COUNTIF('Migration Tracker'!$H$2:$H${end},\"Cancelled\")),0)"))
    summary.cell(row=done_row, column=2).number_format = "0.0%"
    summary.cell(row=done_row + 1, column=1, value="Overdue").font = Font(bold=True)
    summary.cell(row=done_row + 1, column=2, value=f"=COUNTIF('Migration Tracker'!$J$2:$J${end},\">0\")")
    for row in summary.iter_rows(min_row=start - 1, max_row=start + len(models) - 1, max_col=4):
        for cell in row:
            cell.border = Border(bottom=thin)
            cell.alignment = Alignment(vertical="center")

    wb.properties.creator = "Netrune"
    wb.properties.title = "Network inventory and migration tracker"
    wb.save(path)
    return {"devices": len(rows), "models": len(models), "migration_rows": migration_rows,
            "sheets": [ws.title for ws in wb.worksheets]}
