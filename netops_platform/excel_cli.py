"""Command surface for the excel domain.

A free-function module like path_cli.py: cmd_excel has one caller boundary
(App.dispatch), so nothing here needs to sit on the App's MRO. The workbook
planning and mechanics live in excel.py; this module owns the guarded
preview/backup/apply/verify/audit lifecycle around them (ADR 0005), applied to
a local file rather than a switch.
"""

from __future__ import annotations

import concurrent.futures
import datetime as dt
import errno
import json
import os
import select
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from netops_platform import excel


SYNC_USAGE = ("netrune excel sync <workbook.xlsx> [--sheet NAME|N[,...]] [--map 'Header=field,...'] [--fields LIST] "
              "[--refresh LIST|all] [--remarks] [--free-ips [--accept-free IPS|all] [--reject-free IPS|all]] [--fill-only] [--add-missing] [--prefer serial|mac|ip|hostname] [--output PATH] "
              "[--no-shade] [--comments] [--ignore-lock] [--allow-feature-loss] (--dry-run | --confirm)")
INSPECT_USAGE = ("netrune excel inspect <workbook.xlsx> [--sheet NAME|N[,...]] [--map 'Header=field,...'] [--fields LIST] "
                 "[--refresh LIST|all] [--remarks] [--free-ips]")
EXPORT_USAGE = "netrune excel export <tracker.xlsx> [--migration-rows N] [--confirm]"
REPORT_USAGE = "netrune excel report <reports.xlsx> [--report LIST] [--since 30d|12w|6m|YYYY-MM-DD|all] [--confirm]"

VALUE_OPTIONS = {"--sheet", "--map", "--fields", "--refresh", "--prefer", "--output", "--migration-rows",
                 "--accept-free", "--reject-free", "--report", "--since"}
# --highlight and --no-comments describe what is now the default (shading,
# no notes); they stay accepted so older scripts keep working.
FLAG_OPTIONS = {"--fill-only", "--add-missing", "--comments", "--no-shade", "--highlight", "--no-comments",
                "--ignore-lock", "--allow-feature-loss", "--remarks", "--free-ips"}

# A host that drops ping usually still answers one of these, if only with a
# refusal: remote access, Windows, cameras, printers, web. Plain TCP connects,
# no OT protocols (Modbus, S7, EtherNet/IP).
PROBE_PORTS = (22, 23, 80, 135, 139, 443, 445, 554, 3389, 8080, 8443, 9100)
# Documentation ranges (RFC 5737): nothing real lives there, so whatever
# "answers" for them is a proxy or NAT on this machine's own path.
UNREACHABLE_PROBES = ("192.0.2.1", "198.51.100.1")
MAX_FREE_IP_CHECKS = 4096


def _parse(rest: List[str]) -> Tuple[List[str], Dict[str, Any]]:
    positional: List[str] = []
    options: Dict[str, Any] = {}
    index = 0
    while index < len(rest):
        item = rest[index]
        key, has_value, inline = item.partition("=") if item.startswith("--") else (item, "", "")
        if key in VALUE_OPTIONS:
            if has_value:
                options[key] = inline
                index += 1
                continue
            if index + 1 >= len(rest):
                raise excel.ExcelError(f"{key} needs a value.")
            options[key] = rest[index + 1]
            index += 2
            continue
        if item in FLAG_OPTIONS:
            options[item] = True
            index += 1
            continue
        if item.startswith("--"):
            raise excel.ExcelError(f"Unknown excel option: {item}")
        positional.append(item)
        index += 1
    return positional, options


def _workbook_path(positional: List[str]) -> Path:
    if len(positional) != 1:
        raise excel.ExcelError("Give exactly one workbook path.")
    return Path(os.path.expanduser(positional[0])).resolve()


def _devices(app: Any) -> List[Dict[str, Any]]:
    from netops_platform.core import GlobalOptions
    return [row for row in app.inventory_rows("", GlobalOptions(limit=1_000_000)) if row.get("kind") == "device"]


def _field_list(options: Dict[str, Any], option: str) -> Tuple[str, ...]:
    raw = str(options.get(option) or "").strip()
    chosen = tuple(item.strip().lower().replace("-", "_") for item in raw.split(",") if item.strip())
    if option == "--refresh" and chosen == ("all",):
        return excel.FIELDS
    unknown = [item for item in chosen if item not in excel.FIELDS]
    if unknown:
        raise excel.ExcelError(f"{option}: unknown field(s) {', '.join(unknown)}; choose from {', '.join(excel.FIELDS)}"
                               + (", or all." if option == "--refresh" else "."))
    return chosen


def _fields(options: Dict[str, Any]) -> Tuple[str, ...]:
    """The fields written: --fields (or the defaults) plus whatever --refresh names."""
    chosen = _field_list(options, "--fields") or excel.DEFAULT_FIELDS
    return chosen + tuple(name for name in _field_list(options, "--refresh") if name not in chosen)


def _layouts(wb: Any, options: Dict[str, Any]) -> List[Tuple[Any, excel.SheetLayout]]:
    overrides = excel.parse_column_map(str(options.get("--map") or ""))
    wanted = options.get("--sheet")
    if wanted:
        sheets = [wb[name] for name in excel.select_sheets(wb.sheetnames, str(wanted))]
    else:
        sheets = list(wb.worksheets)
    found = []
    for ws in sheets:
        layout = excel.detect_layout(ws, overrides)
        if layout:
            found.append((ws, layout))
        elif wanted:
            raise excel.ExcelError(
                f"Sheet '{ws.title}' has no header row naming a hostname, IP, serial, or MAC column plus one more field. "
                "Point at the columns with --map, e.g. --map 'Device=hostname,Mgmt=ip'.")
    if not found:
        raise excel.ExcelError("No sheet has a recognizable header row (hostname/IP/serial/MAC plus one more field). "
                               "Use --sheet and --map to point at the columns.")
    return found


def _pings(ip: str) -> bool:
    try:
        return subprocess.run(["ping", "-c", "2", "-i", "0.3", "-W", "1", ip], stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, timeout=6).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _tcp_answers(ip: str, ports: Tuple[int, ...], timeout: float = 1.0, *, first: bool = True) -> List[int]:
    """Ports where a host accepted or refused a connect (either way, something is there)."""
    sockets: Dict[socket.socket, int] = {}
    answered: List[int] = []
    try:
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setblocking(False)
            sockets[sock] = port
            if sock.connect_ex((ip, port)) in (0, errno.ECONNREFUSED):
                answered.append(port)
                if first:
                    return answered
        pending = {sock for sock, port in sockets.items() if port not in answered}
        deadline = time.monotonic() + timeout
        while pending and (left := deadline - time.monotonic()) > 0:
            _, ready, _ = select.select([], list(pending), [], left)
            for sock in ready:
                pending.discard(sock)
                if sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) in (0, errno.ECONNREFUSED):
                    answered.append(sockets[sock])
                    if first:
                        return answered
    except OSError:
        pass
    finally:
        for sock in sockets:
            sock.close()
    return sorted(answered)


def _probe_ip(ip: str, ports: Tuple[int, ...] = PROBE_PORTS) -> str:
    """What answers on an address: "answers ping", "answers on port N", or ""."""
    if _pings(ip):
        return "answers ping"
    answered = _tcp_answers(ip, ports)
    return f"answers on port {answered[0]}" if answered else ""


def _probe_calibration() -> Tuple[bool, List[int]]:
    """Does this machine get ping replies, and which ports, from addresses that cannot exist?"""
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(UNREACHABLE_PROBES) * 2) as pool:
        pings = list(pool.map(_pings, UNREACHABLE_PROBES))
        ports = list(pool.map(lambda ip: _tcp_answers(ip, PROBE_PORTS, first=False), UNREACHABLE_PROBES))
    return any(pings), sorted({port for answered in ports for port in answered})


def _ip_usage(app: Any) -> Tuple[Dict[str, str], Dict[str, Tuple[str, int]], Dict[str, Dict[str, Any]]]:
    """Every address Netrune holds now (with the device's name and MAC), and
    the last thing it ever saw on each address."""
    from netops_platform.core import GlobalOptions
    known: Dict[str, str] = {}
    details: Dict[str, Dict[str, Any]] = {}
    for row in app.inventory_rows("", GlobalOptions(limit=1_000_000)):
        name = excel._host_label(row.get("name") or row.get("hostname") or row.get("ip"))
        label = ("switch " if row.get("kind") == "device" else "AP ") + name
        for address in [row.get("ip"), *(row.get("addresses") or [])]:
            if excel.ip_key(address):
                known.setdefault(excel.ip_key(address), label)
                details.setdefault(excel.ip_key(address), {"hostname": name if not excel.normalize_mac(name) else "",
                                                           "mac": row.get("mac") or "", "last_seen": row.get("last_seen")})
    for row in app.state.rows("SELECT remote_ip, remote_name FROM neighbors WHERE COALESCE(remote_ip,'')<>''"):
        if excel.ip_key(row["remote_ip"]):
            known.setdefault(excel.ip_key(row["remote_ip"]), "device " + excel._host_label(row.get("remote_name") or row["remote_ip"]))
    history: Dict[str, Tuple[str, int]] = {}
    for row in app.state.rows("SELECT ip, name, last_seen FROM inventory_identity_state WHERE COALESCE(ip,'')<>'' AND last_seen>0"):
        key = excel.ip_key(row["ip"])
        if key and int(row["last_seen"]) > history.get(key, ("", 0))[1]:
            history[key] = (excel._host_label(row.get("name") or key), int(row["last_seen"]))
    return known, history, details


def _ip_list(options: Dict[str, Any], option: str) -> Any:
    raw = str(options.get(option) or "").strip()
    if raw.lower() == "all":
        return "all"
    chosen = {excel.ip_key(item) for item in raw.split(",") if item.strip()}
    if "" in chosen:
        raise excel.ExcelError(f"{option} takes IP addresses separated by commas, or all.")
    return chosen


def _interactive(opts: Any) -> bool:
    """Questions are only asked while applying, in a real terminal, without --json."""
    return bool(opts.confirm and not opts.json and sys.stdin.isatty() and sys.stdout.isatty())


def _ask_free(candidate: Dict[str, Any]) -> str:
    """One terminal question about an old entry: y/n/Enter, or a for all / q to stop."""
    question = (f"  {candidate['sheet']} row {candidate['row']}: {candidate['ip']} '{candidate['label']}' -- Netrune never saw it "
                "and nothing answers. Free to use? [y]es / [n]o, allocated / Enter skip / [a]ll yes / [q] skip the rest: ")
    try:
        answer = input(question).strip().lower()
    except EOFError:
        return "q"
    return answer[:1]


def _free_ip_findings(app: Any, layouts: List[Tuple[Any, excel.SheetLayout]], index: excel.DeviceIndex, opts: Any,
                      options: Dict[str, Any], *, interactive: bool = False,
                      answers: Optional[Dict[str, Dict[str, Any]]] = None) -> Tuple[Dict[str, Dict[int, excel.IpFinding]], str]:
    """Each sheet's rows -> what the free-IP rule says about their address.

    Empty rows are judged from Netrune's memory alone. Rows naming something
    Netrune never saw are probed; a silent one is free only once the operator
    agrees: --accept-free/--reject-free, the answer kept in its remark from a
    previous run, an answer given in `health review`, or (interactive
    --confirm) a question per row.
    """
    candidates = [row for ws, layout in layouts for row in excel.ip_candidates(ws, layout, index)]
    if not candidates:
        return {}, ""
    known, history, details = _ip_usage(app)
    now = time.time()
    # Every address Netrune does not already hold is probed, empty rows
    # included: something answering is in use whatever the sheet says.
    to_probe = sorted({row["ip"] for row in candidates if row["ip"] not in known})
    if len(to_probe) > MAX_FREE_IP_CHECKS:
        raise excel.ExcelError(f"--free-ips would probe {len(to_probe)} addresses (limit {MAX_FREE_IP_CHECKS}); "
                               "narrow it with --sheet.")
    replies: Dict[str, str] = {}
    note = ""
    if to_probe:
        if sys.stderr.isatty() and not getattr(opts, "json", False):
            print(f"Checking {len(to_probe)} address(es) Netrune holds no device for...", file=sys.stderr, flush=True)
        fake_ping, intercepted = _probe_calibration()
        if fake_ping:
            raise excel.ExcelError("This machine gets ping replies from addresses that do not exist (a NAT or VPN answers "
                                   "for them), so it cannot tell a free address from a used one. Run --free-ips from a "
                                   "machine on the plant network.")
        ports = tuple(port for port in PROBE_PORTS if port not in intercepted)
        if intercepted:
            note = (f"Ports {', '.join(map(str, intercepted))} answer for addresses that do not exist from this machine "
                    "(a proxy on the path), so they were not counted as a sign of use.")
        workers = min(64, max(32, int(getattr(opts, "workers", 0) or 0)), len(to_probe))
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers, thread_name_prefix="excel-free-ip") as pool:
            replies = dict(zip(to_probe, pool.map(lambda ip: _probe_ip(ip, ports), to_probe)))
    accept, reject = _ip_list(options, "--accept-free"), _ip_list(options, "--reject-free")

    def decide(row: Dict[str, Any], answer_all: str = "") -> str:
        if accept == "all" or row["ip"] in accept:
            return "accepted"
        if reject == "all" or row["ip"] in reject:
            return "rejected"
        return (excel.prior_decision(row["remark"])
                or str(((answers or {}).get(row["sheet"]) or {}).get("free", {}).get(row["ip"]) or "")
                or answer_all)

    def classify(row: Dict[str, Any], decision: str) -> excel.IpFinding:
        return excel.classify_ip(row["ip"], empty=row["empty"], known=known, history=history,
                                 reply=replies.get(row["ip"], ""), now=now, decision=decision, details=details)

    findings: Dict[str, Dict[int, excel.IpFinding]] = {}
    pending = []
    for row in candidates:
        finding = classify(row, decide(row))
        findings.setdefault(row["sheet"], {})[row["row"]] = finding
        if finding.state == "unconfirmed":
            pending.append(row)
    if pending and interactive:
        print(f"{len(pending)} row(s) name something Netrune has never seen, and nothing answers on the address:", file=sys.stderr)
        answer_all = ""
        for row in pending:
            answer = "y" if answer_all == "a" else _ask_free(row) if answer_all != "q" else ""
            if answer in {"a", "q"}:
                answer_all = answer
                answer = "y" if answer == "a" else ""
            decision = {"y": "accepted", "n": "rejected"}.get(answer, "")
            findings[row["sheet"]][row["row"]] = classify(row, decision)
    return findings, note


def _plans(app: Any, wb: Any, options: Dict[str, Any], *, fields: Tuple[str, ...], opts: Any = None,
           interactive: bool = False, source: Optional[Path] = None) -> Tuple[List[excel.SheetPlan], excel.DeviceIndex]:
    prefer = str(options.get("--prefer") or "").strip().lower()
    if prefer and prefer not in excel.IDENTITY_FIELDS:
        raise excel.ExcelError("--prefer must be serial, mac, ip, or hostname.")
    layouts = _layouts(wb, options)
    if options.get("--add-missing") and len(layouts) > 1:
        raise excel.ExcelError("--add-missing needs --sheet: name the one sheet new rows belong on.")
    index = excel.DeviceIndex.build(_devices(app))
    refresh = _field_list(options, "--refresh")
    answers = review_answers(app, source) if source else {}
    findings, note = (_free_ip_findings(app, layouts, index, opts, options, interactive=interactive, answers=answers)
                      if options.get("--free-ips") else (None, ""))
    plans = [excel.plan_sheet(ws, layout, index, fields=fields, fill_only=bool(options.get("--fill-only")),
                              prefer=prefer, add_missing=bool(options.get("--add-missing")), refresh=refresh,
                              remarks=bool(options.get("--remarks") or options.get("--free-ips")),
                              ip_findings=None if findings is None else findings.get(layout.title, {}),
                              row_prefer={int(row): choice for row, choice in
                                          ((answers.get(layout.title) or {}).get("prefer") or {}).items()})
             for ws, layout in layouts]
    for plan in plans:
        plan.probe_note = note
    if source:
        _record_pending(app, source, plans)
    return plans, index


# What a workbook still needs the operator to decide, and what they decided,
# so `health review` can ask in the morning and the next sync can act on it.
# Both live in markers keyed by the workbook's resolved path, per sheet.
REVIEW_MARKER = "excel_review"
ANSWERS_MARKER = "excel_answers"


def _marker(app: Any, key: str) -> Dict[str, Any]:
    try:
        value = json.loads(app.state.get_marker(key) or "{}")
    except (TypeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def review_answers(app: Any, source: Path) -> Dict[str, Dict[str, Any]]:
    return _marker(app, ANSWERS_MARKER).get(str(Path(source).resolve()), {})


def record_answer(app: Any, workbook: str, sheet: str, kind: str, key: str, value: Any) -> None:
    """One `health review` answer: kind `free` (key an address, value
    accepted/rejected) or `prefer` (key a row number, value {kind, label})."""
    answers = _marker(app, ANSWERS_MARKER)
    answers.setdefault(workbook, {}).setdefault(sheet, {}).setdefault(kind, {})[str(key)] = value
    app.state.set_marker(ANSWERS_MARKER, json.dumps(answers, sort_keys=True))
    # The answered question leaves the queue now, not at the next sync.
    pending = _marker(app, REVIEW_MARKER)
    sheets = (pending.get(workbook) or {}).get("sheets") or {}
    if sheet in sheets:
        field, wanted = ("ip", key) if kind == "free" else ("row", int(key))
        sheets[sheet] = [item for item in sheets[sheet] if not (item["kind"] == f"excel-{kind if kind == 'free' else 'conflict'}"
                                                                and item.get(field) == wanted)]
        app.state.set_marker(REVIEW_MARKER, json.dumps(pending, sort_keys=True))


def _record_pending(app: Any, source: Path, plans: List[excel.SheetPlan]) -> None:
    workbook = str(Path(source).resolve())
    pending = _marker(app, REVIEW_MARKER)
    entry = pending.setdefault(workbook, {"sheets": {}})
    entry["at"] = int(time.time())
    for plan in plans:
        items = [{"kind": "excel-free", "sheet": plan.layout.title, "row": check["row"], "ip": check["ip"],
                  "named": check.get("named", "")}
                 for check in plan.ip_checks if check.get("state") == "unconfirmed"]
        items += [{"kind": "excel-conflict", "sheet": plan.layout.title, "row": conflict["row"],
                   "label": conflict.get("row_label", ""), "votes": conflict.get("votes") or {}}
                  for conflict in plan.conflicts if conflict.get("votes")]
        entry.setdefault("sheets", {})[plan.layout.title] = items
    entry["sheets"] = {sheet: items for sheet, items in entry["sheets"].items() if items}
    if not entry["sheets"]:
        pending.pop(workbook, None)
    app.state.set_marker(REVIEW_MARKER, json.dumps(pending, sort_keys=True))


def pending_review(app: Any) -> List[Dict[str, Any]]:
    """Every workbook question waiting for `health review`, oldest workbook first."""
    out = []
    for workbook, entry in sorted(_marker(app, REVIEW_MARKER).items(), key=lambda kv: kv[1].get("at", 0)):
        for sheet, items in sorted((entry.get("sheets") or {}).items()):
            out.extend({**item, "workbook": workbook, "recorded_at": entry.get("at", 0)} for item in items)
    return out


def _clear_answers(app: Any, source: Path, sheets: Sequence[str]) -> None:
    """Answers written into the sheet by a sync are the sheet's now (its
    remarks, its corrected cells): drop them so they cannot outlive the rows."""
    answers = _marker(app, ANSWERS_MARKER)
    workbook = str(Path(source).resolve())
    if workbook in answers:
        for sheet in sheets:
            answers[workbook].pop(sheet, None)
        if not answers[workbook]:
            answers.pop(workbook)
        app.state.set_marker(ANSWERS_MARKER, json.dumps(answers, sort_keys=True))


def _shade_legend() -> str:
    return ", ".join(f"{excel.CONFIDENCE_SHADES[level]} ({level})" for level in reversed(excel.CONFIDENCE_LEVELS))


def _summary_rows(plans: List[excel.SheetPlan], index: excel.DeviceIndex) -> List[Dict[str, Any]]:
    rows = []
    for plan in plans:
        data_rows = plan.matched_rows + len(plan.unmatched) + len(plan.conflicts)
        rows.append({
            "sheet": plan.layout.title,
            "header_row": plan.layout.header_row,
            "rows": data_rows,
            "matched": plan.matched_rows,
            "unmatched": len(plan.unmatched),
            "conflicts": len(plan.conflicts),
            "cell_changes": len([c for c in plan.changes if c.kind != "add"]),
            "new_rows": len(plan.additions),
            **{level: len([c for c in plan.changes if c.confidence == level]) for level in reversed(excel.CONFIDENCE_LEVELS)},
            "free_ips": len([check for check in plan.ip_checks if check["state"] == "free"]),
            "devices_not_in_sheet": len(index.devices) - len(plan.matched_devices),
        })
    return rows


def _report(app: Any, plans: List[excel.SheetPlan], index: excel.DeviceIndex, opts: Any,
            features: List[str], lock: Optional[Path], heading: str) -> Tuple[Dict[str, Any], str]:
    changes = [change.as_dict() for plan in plans for change in plan.changes]
    unmatched = [row for plan in plans for row in plan.unmatched]
    conflicts = [row for plan in plans for row in plan.conflicts]
    kept = [row for plan in plans for row in plan.kept]
    duplicates = [row for plan in plans for row in plan.duplicates]
    ip_checks = [row for plan in plans for row in plan.ip_checks]
    summary = _summary_rows(plans, index)
    payload = {
        "ok": True, "summary": summary, "layouts": [plan.layout.as_dict() for plan in plans],
        "changes": changes, "unmatched": unmatched, "conflicts": conflicts, "kept": kept,
        "duplicates": duplicates, "ip_checks": ip_checks, "probe_note": plans[0].probe_note if plans else "", "features_lost_on_save": features, "lock_file": str(lock or ""),
    }
    limit = max(1, int(getattr(opts, "limit", 100) or 100))
    parts = [heading, ""]
    for layout in payload["layouts"]:
        mapped = ", ".join(f"{name}={where}" for name, where in layout["columns"].items())
        parts.append(f"Sheet '{layout['sheet']}': header row {layout['header_row']}, {layout['data_rows']} data row(s); columns {mapped}")
    parts += ["", app.render_table(summary, ["sheet", "rows", "matched", "unmatched", "conflicts", "cell_changes", "new_rows", "devices_not_in_sheet"])]
    if changes:
        # Least certain first: those are the cells worth reading.
        ordered = sorted(changes, key=lambda change: excel.CONFIDENCE_LEVELS.index(change["confidence"]))
        parts += ["", f"Cell changes ({len(changes)}, least certain first" + (f"; first {limit} shown" if len(changes) > limit else "") + ")",
                  app.render_table(ordered[:limit], ["sheet", "cell", "column", "old", "new", "kind", "confidence", "why"]),
                  "Confidence: " + ", ".join(f"{sum(row[level] for row in summary)} {level}" for level in reversed(excel.CONFIDENCE_LEVELS))
                  + ". Written cells are shaded " + _shade_legend() + "."]
    for plan in plans:
        if plan.remarks_column:
            from openpyxl.utils import get_column_letter
            parts += ["", f"Sheet '{plan.layout.title}' has no Remarks/Comments/Notes column: adding 'Remarks' as column "
                          f"{get_column_letter(plan.remarks_column)}."]
    if ip_checks:
        order = ("free", "unconfirmed", "allocated", "recent", "reserved", "in_use")
        counts = {state: len([row for row in ip_checks if row["state"] == state]) for state in order}
        parts += ["", f"Addresses checked ({len(ip_checks)}): {counts['free']} free, {counts['unconfirmed']} awaiting you, "
                      f"{counts['allocated']} allocated offline, {counts['recent']} recently used, "
                      f"{counts['reserved']} reserved in remarks, {counts['in_use']} in use"]
        free = sorted((row for row in ip_checks if row["state"] == "free"),
                      key=lambda row: (row["priority"], tuple(int(part) for part in row["ip"].split("."))))
        if free:
            parts += ["Suggested for allocation (empty rows first, then long-unused, then confirmed old entries)",
                      app.render_table(free[:limit], ["sheet", "row", "ip", "remark", "why"])]
        waiting = [row for row in ip_checks if row["state"] == "unconfirmed"]
        if waiting:
            parts += [f"Rows naming something Netrune never saw, with nothing answering ({len(waiting)}): left as they are until you decide",
                      app.render_table(waiting[:limit], ["sheet", "row", "ip", "named"]),
                      "Answer them with --confirm in a terminal (one question per row), or pass "
                      "--accept-free IP,... (free to use) / --reject-free IP,... (allocated, offline); 'all' for every one."]
        others = [row for row in ip_checks if row["state"] not in {"free", "unconfirmed"}]
        if others:
            parts += ["Not free", app.render_table(sorted(others, key=lambda row: order.index(row["state"]))[:limit],
                                                    ["sheet", "row", "ip", "remark", "why"])]
        if plans[0].probe_note:
            parts.append(plans[0].probe_note)
    if conflicts:
        parts += ["", "Rows left alone: their keys point at different switches (resolve with --prefer KEY)",
                  app.render_table(conflicts[:limit], ["sheet", "row", "row_label", "points_to"])]
    if unmatched:
        parts += ["", f"Rows with no Netrune match ({len(unmatched)})",
                  app.render_table(unmatched[:limit], ["sheet", "row", "row_label", "reason"])]
    if duplicates:
        parts += ["", "One switch on several rows (each row is updated)",
                  app.render_table(duplicates[:limit], ["sheet", "device", "rows"])]
    if kept:
        parts += ["", f"Cells kept as they are ({len(kept)})", app.render_table(kept[:limit], ["sheet", "row", "column", "reason"])]
    if features:
        parts += ["", "Warning: this workbook contains " + ", ".join(features) + ", which openpyxl does not preserve "
                  "when it saves. Write to a new file with --output, or accept the loss with --allow-feature-loss."]
    if lock:
        parts += ["", f"Warning: {lock.name} exists, so the workbook looks open in Excel. Close it first; saving "
                  "from Excel afterwards would overwrite these changes (--ignore-lock to proceed anyway)."]
    return payload, "\n".join(parts)


def _file_mode(destination: Path) -> int:
    # mkstemp creates 0600; a replaced workbook keeps the mode it had, and a
    # new one gets what the operator's umask would have given it.
    if destination.exists():
        return destination.stat().st_mode & 0o777
    umask = os.umask(0)
    os.umask(umask)
    return 0o666 & ~umask


def _atomic_save(wb: Any, destination: Path, build: Any = None) -> Any:
    destination.parent.mkdir(parents=True, exist_ok=True)
    mode = _file_mode(destination)
    handle, temporary = tempfile.mkstemp(prefix=".netrune-", suffix=destination.suffix, dir=str(destination.parent))
    os.close(handle)
    try:
        result = build(Path(temporary)) if build else wb.save(temporary)
        os.chmod(temporary, mode)
        os.replace(temporary, destination)
        return result
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _backup(app: Any, source: Path) -> Path:
    folder = app.paths.data_dir / "excel-backups"
    folder.mkdir(parents=True, exist_ok=True)
    target = folder / f"{source.stem}-{dt.datetime.now().strftime('%Y%m%d-%H%M%S')}{source.suffix}"
    shutil.copy2(source, target)
    return target


def _sync(app: Any, rest: List[str], opts: Any) -> int:
    from netops_platform.core import CONFIRM_REQUIRED, INTERNAL, SUCCESS
    positional, options = _parse(rest)
    source = _workbook_path(positional)
    destination = Path(os.path.expanduser(str(options["--output"]))).resolve() if options.get("--output") else source
    fields = _fields(options)
    wb = excel.load_workbook(source)
    plans, index = _plans(app, wb, options, fields=fields, opts=opts, interactive=_interactive(opts), source=source)
    features = excel.workbook_features(source)
    lock = excel.excel_lock_file(source) or (excel.excel_lock_file(destination) if destination.exists() else None)
    pending = sum(len(plan.changes) for plan in plans)
    if not opts.confirm:
        payload, text = _report(app, plans, index, opts, features, lock,
                                f"Preview of Netrune -> {source.name}" + (f" (writing {destination})" if destination != source else ""))
        payload.update({"requires_confirm": bool(pending), "source": str(source), "destination": str(destination), "fields": list(fields)})
        if pending:
            text += f"\n\nNothing written. Re-run with --confirm to apply {pending} cell change(s)" + (
                f" to {destination}." if destination != source else "; the original is backed up first.")
        else:
            text += "\n\nThe workbook already agrees with Netrune; nothing to change."
        app.emit(payload, opts, text)
        return SUCCESS if (opts.dry_run or not pending) else CONFIRM_REQUIRED
    if not pending:
        app.emit({"ok": True, "applied": 0, "source": str(source)}, opts, f"{source.name} already agrees with Netrune; nothing written.")
        return SUCCESS
    if lock and not options.get("--ignore-lock"):
        raise excel.ExcelError(f"{lock.name} exists: {source.name} looks open in Excel. Close it, or pass --ignore-lock.")
    if features and destination == source and not options.get("--allow-feature-loss"):
        raise excel.ExcelError(f"{source.name} contains {', '.join(features)}, which would be lost on save. "
                               "Write a copy with --output, or pass --allow-feature-loss.")
    backup = _backup(app, source) if destination == source or destination.exists() else None
    applied = excel.apply_plans(wb, plans, shade=not options.get("--no-shade"), comments=bool(options.get("--comments")))
    _atomic_save(wb, destination)
    problems = excel.verify_saved(destination, plans)
    detail = {"source": str(source), "destination": str(destination), "backup": str(backup or ""),
              "applied": applied, "fields": list(fields), "verify_problems": problems[:20],
              "sheets": _summary_rows(plans, index)}
    app.state.record_audit_event("excel", "excel-sync", target=str(destination),
                                 result="success" if not problems else "verify-failed", detail=detail)
    if not problems and destination == source:
        _clear_answers(app, source, [plan.layout.title for plan in plans])
    levels = {level: sum(row[level] for row in detail["sheets"]) for level in reversed(excel.CONFIDENCE_LEVELS)}
    lines = [f"Wrote {applied} cell(s) to {destination}: " + ", ".join(f"{count} {level}" for level, count in levels.items())
             + ("." if options.get("--no-shade") else "; shaded " + _shade_legend() + ".")]
    from openpyxl.utils import get_column_letter
    for plan in plans:
        if plan.remarks_column:
            lines.append(f"Added a Remarks column ({get_column_letter(plan.remarks_column)}) to '{plan.layout.title}'.")
    free = [check for plan in plans for check in plan.ip_checks if check["state"] == "free"]
    if any(plan.ip_checks for plan in plans):
        lines.append(f"{len(free)} address(es) marked free to use.")
    if backup:
        lines.append(f"Original backed up to {backup}.")
    lines.append("Read back and verified." if not problems else "Verification found differences:\n  " + "\n  ".join(problems[:20]))
    app.emit({"ok": not problems, **detail}, opts, "\n".join(lines))
    return SUCCESS if not problems else INTERNAL


def _inspect(app: Any, rest: List[str], opts: Any) -> int:
    from netops_platform.core import SUCCESS
    positional, options = _parse(rest)
    source = _workbook_path(positional)
    wb = excel.load_workbook(source)
    fields = _fields(options)
    plans, index = _plans(app, wb, options, fields=fields, opts=opts, source=source)
    features = excel.workbook_features(source)
    payload, text = _report(app, plans, index, opts, features, excel.excel_lock_file(source),
                            f"{source.name}: {len(wb.sheetnames)} sheet(s) ("
                            + ", ".join(f"{number}={name}" for number, name in enumerate(wb.sheetnames, start=1)) + "); "
                            f"compared with {len(index.devices)} Netrune switch(es)")
    payload.update({"sheets": wb.sheetnames, "fields": list(fields)})
    text += "\n\nFields compared: " + ", ".join(fields) + ". Status and last_seen are only written when --fields names them."
    app.emit(payload, opts, text)
    return SUCCESS


def _export(app: Any, rest: List[str], opts: Any) -> int:
    from netops_platform.core import CONFIRM_REQUIRED, SUCCESS
    positional, options = _parse(rest)
    destination = _workbook_path(positional)
    if destination.suffix.lower() != ".xlsx":
        raise excel.ExcelError("Export writes an .xlsx workbook; give a path ending in .xlsx.")
    try:
        migration_rows = int(options.get("--migration-rows") or 300)
    except ValueError:
        raise excel.ExcelError("--migration-rows must be a number.")
    if not 1 <= migration_rows <= 5000:
        raise excel.ExcelError("--migration-rows must be between 1 and 5000.")
    devices = _devices(app)
    if destination.exists() and not opts.confirm:
        app.emit({"ok": False, "requires_confirm": True, "destination": str(destination)}, opts,
                 f"{destination} already exists. Re-run with --confirm to replace it (the current file is backed up first).")
        return CONFIRM_REQUIRED
    if opts.dry_run:
        app.emit({"ok": True, "destination": str(destination), "devices": len(devices)}, opts,
                 f"Would write a tracker for {len(devices)} switch(es) to {destination}.")
        return SUCCESS
    excel.require_openpyxl()
    backup = _backup(app, destination) if destination.exists() else None
    result = _atomic_save(None, destination, build=lambda path: excel.build_tracker(devices, path, migration_rows=migration_rows))
    excel.load_workbook(destination)  # read back: a file Excel cannot open is not a success
    app.state.record_audit_event("excel", "excel-export", target=str(destination), result="success",
                                 detail={**result, "backup": str(backup or "")})
    lines = [f"Wrote {destination}: {result['devices']} switch(es), {result['models']} model(s), "
             f"sheets {', '.join(result['sheets'])}."]
    if backup:
        lines.append(f"Previous file backed up to {backup}.")
    lines.append(f"Keep it current with: netrune excel sync {destination} --sheet Inventory --add-missing --fields "
                 "hostname,ip,manufacturer,platform,model,serial,mac,status,last_seen --confirm")
    app.emit({"ok": True, "destination": str(destination), "backup": str(backup or ""), **result}, opts, "\n".join(lines))
    return SUCCESS


def _write_reports(app: Any, rest: List[str], opts: Any) -> int:
    from netops_platform import excel_reports
    from netops_platform.core import CONFIRM_REQUIRED, SUCCESS
    positional, options = _parse(rest)
    destination = _workbook_path(positional)
    if destination.suffix.lower() != ".xlsx":
        raise excel.ExcelError("Reports are written as an .xlsx workbook; give a path ending in .xlsx.")
    chosen = [item.strip().lower() for item in str(options.get("--report") or "").split(",") if item.strip()]
    names = list(excel_reports.REPORTS) if not chosen or chosen == ["all"] else chosen
    unknown = [name for name in names if name not in excel_reports.REPORTS]
    if unknown:
        raise excel.ExcelError(f"--report: unknown report(s) {', '.join(unknown)}; choose from {', '.join(excel_reports.REPORTS)}, or all.")
    # --since is a global flag, so it arrives on opts rather than in `rest`.
    since, period = excel_reports.parse_since(str(getattr(opts, "since", "") or options.get("--since") or ""), time.time())
    if destination.exists() and not opts.confirm:
        app.emit({"ok": False, "requires_confirm": True, "destination": str(destination)}, opts,
                 f"{destination} already exists. Re-run with --confirm to replace it (the current file is backed up first).")
        return CONFIRM_REQUIRED
    data = excel_reports.collect(app, since)
    summary = [{"report": name, "sheet": excel_reports.REPORTS[name].sheet, "rows": len(data[name])} for name in names]
    if opts.dry_run:
        app.emit({"ok": True, "destination": str(destination), "period": period, "reports": summary}, opts,
                 f"Would write {destination} covering {period}:\n" + app.render_table(summary, ["report", "sheet", "rows"]))
        return SUCCESS
    excel.require_openpyxl()
    backup = _backup(app, destination) if destination.exists() else None
    result = _atomic_save(None, destination, build=lambda path: excel_reports.build(data, path, names, period=period))
    excel.load_workbook(destination)  # read back: a file Excel cannot open is not a success
    app.state.record_audit_event("excel", "excel-report", target=str(destination), result="success",
                                 detail={**result, "period": period, "backup": str(backup or "")})
    lines = [f"Wrote {destination} covering {period}:", app.render_table(summary, ["report", "sheet", "rows"])]
    if data["_notes"].get("switch_rows_in_ap_inventory"):
        lines.append(f"{data['_notes']['switch_rows_in_ap_inventory']} row(s) in the AP inventory are switches seen as neighbours "
                     "and were left out of the AP sheets.")
    if backup:
        lines.append(f"Previous file backed up to {backup}.")
    lines.append("Each report's definition is on the Report Info sheet.")
    app.emit({"ok": True, "destination": str(destination), "backup": str(backup or ""), "period": period,
              "reports": summary}, opts, "\n".join(lines))
    return SUCCESS


def dispatch(app: Any, args: List[str], opts: Any) -> int:
    from netops_platform.core import SUCCESS, VALIDATION
    if app.handle_help("excel", args, opts):
        return SUCCESS
    verb = args[0] if args else "inspect"
    rest = args[1:]
    handlers = {"inspect": (_inspect, INSPECT_USAGE), "sync": (_sync, SYNC_USAGE), "export": (_export, EXPORT_USAGE),
                "report": (_write_reports, REPORT_USAGE)}
    if verb not in handlers:
        return app.usage_error("excel", verb, opts, f"Unknown excel action: {verb}", "netrune excel <inspect|sync|export|report>", VALIDATION)
    handler, usage = handlers[verb]
    try:
        return handler(app, rest, opts)
    except excel.ExcelError as exc:
        return app.usage_error("excel", verb, opts, str(exc), usage, VALIDATION)
