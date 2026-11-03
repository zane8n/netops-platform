"""Command surface for the map domain: the operator's network map.

A free-function module like excel_cli.py: cmd_map has one caller boundary
(App.dispatch). The map's format, importers, correlation, and edit planning
live in netmap.py; this module gathers the evidence from the database and
owns the guarded preview/backup/apply/verify/audit lifecycle (ADR 0005)
around every write to the map file.

The map file is the operator's own text, in the profile's configuration
directory. Netrune adds to it (marked with a dated comment) and fills blanks;
it never removes or reorders what the operator wrote.
"""

from __future__ import annotations

import datetime as dt
import difflib
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from netops_platform import netmap

USAGE = "netrune map <show|check|update|import|init|edit|export|path>"
CHECK_USAGE = "netrune map check [device] [--file PATH] [--all]"
UPDATE_USAGE = "netrune map update [--add-new] [--attachments] [--overwrite] (--dry-run | --confirm)"
IMPORT_USAGE = "netrune map import <file.txt|.csv|.xlsx|.drawio|.vsdx> [--sheet NAME] [--overwrite] [--replace] (--dry-run | --confirm)"
INIT_USAGE = "netrune map init [--from-network] [--attachments] [--confirm]"
EXPORT_USAGE = "netrune map export <file.csv|.txt|.drawio> [--confirm]"
SHOW_USAGE = "netrune map show [device] [--file PATH]"

VALUE_OPTIONS = {"--file", "--sheet", "--format"}
FLAG_OPTIONS = {"--add-new", "--attachments", "--overwrite", "--replace", "--from-network"}
STALE_STP_SECONDS = 30 * 86400


def map_path(app: Any) -> Path:
    return Path(app.paths.config_dir) / "network-map.txt"


def _parse(rest: Sequence[str]) -> Tuple[List[str], Dict[str, Any]]:
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
                raise netmap.MapError(f"{key} needs a value.")
            options[key] = rest[index + 1]
            index += 2
            continue
        if item in FLAG_OPTIONS:
            options[item] = True
            index += 1
            continue
        if item.startswith("--"):
            raise netmap.MapError(f"Unknown map option: {item}")
        positional.append(item)
        index += 1
    return positional, options


def _load(app: Any, options: Dict[str, Any], *, required: bool = True) -> Tuple[Optional[netmap.NetMap], Path]:
    path = Path(os.path.expanduser(options["--file"])).resolve() if options.get("--file") else map_path(app)
    if not path.is_file():
        if required and options.get("--file"):
            raise netmap.MapError(f"{path} does not exist.")
        return None, path
    return netmap.read_any(path, sheet=str(options.get("--sheet") or "")), path


def _no_map_text(path: Path) -> str:
    return (f"No network map yet ({path}).\n"
            "Start one of these ways:\n"
            "  netrune map init --from-network --dry-run   draft it from what Netrune already discovered\n"
            "  netrune map import ~/my-map.vsdx --dry-run  bring in a Visio, draw.io, Excel/CSV, or text map\n"
            "  netrune map init                            an empty template to type into (netrune map edit)")


# --------------------------------------------------------------------------
# Evidence


def evidence(app: Any) -> Tuple[netmap.Inventory, List[netmap.Seen], Dict[str, Any]]:
    from netops_platform.core import GlobalOptions
    inventory = netmap.Inventory(app.inventory_rows("", GlobalOptions(limit=1_000_000)))
    current = app.state.rows("SELECT local_ip,local_name,local_port,remote_name,remote_port,remote_ip FROM neighbors")
    history: List[Dict[str, Any]] = []
    stp: List[Dict[str, Any]] = []
    latest = 0
    for row in app.state.rows("SELECT rel_type,switch_ip,switch_name,switch_port,object_id,status,last_seen,attrs_json "
                              "FROM relationships_current WHERE rel_type IN ('neighbor_link','stp_link')"):
        try:
            attrs = json.loads(row.get("attrs_json") or "{}")
        except json.JSONDecodeError:
            attrs = {}
        item = {"local_ip": row.get("switch_ip"), "local_name": row.get("switch_name"), "local_port": row.get("switch_port"),
                "remote_name": attrs.get("remote_name") or "", "remote_ip": attrs.get("remote_ip") or row.get("object_id") or "",
                "remote_port": attrs.get("remote_port") or "", "last_seen": int(row.get("last_seen") or 0)}
        if row["rel_type"] == "neighbor_link":
            history.append(item)
            if row.get("status") == "active":
                latest = max(latest, item["last_seen"])
        elif row.get("status") == "active" and item["last_seen"] >= time.time() - STALE_STP_SECONDS:
            stp.append(item)
    seen = netmap.build_seen(inventory, current, history, stp)
    about = {"current_links": len(current), "topology_as_of": latest,
             "switches_with_current_data": len({item.a for item in seen if item.current})}
    return inventory, seen, about


def _as_of(about: Dict[str, Any]) -> str:
    when = about.get("topology_as_of")
    stamp = dt.datetime.fromtimestamp(when).strftime("%Y-%m-%d %H:%M") if when else "never"
    note = (f"topology: {about['current_links']} LLDP/CDP link(s) from {about['switches_with_current_data']} switch(es), last scan {stamp}")
    if not about.get("current_links"):
        note += " -- run 'netrune topology scan' on the site network for current evidence"
    return note


# --------------------------------------------------------------------------
# Guarded writes


def _write(app: Any, path: Path, text: str, action: str, detail: Dict[str, Any]) -> Dict[str, Any]:
    """Back up, write atomically, read back, audit."""
    backup = ""
    if path.exists():
        folder = Path(app.paths.data_dir) / "map-backups"
        folder.mkdir(parents=True, exist_ok=True)
        target = folder / f"{path.stem}-{dt.datetime.now().strftime('%Y%m%d-%H%M%S')}{path.suffix}"
        shutil.copy2(path, target)
        backup = str(target)
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(prefix=".netrune-", suffix=path.suffix, dir=str(path.parent))
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            stream.write(text)
        # The map names the organisation's devices and rooms: private, like
        # the rest of the profile.
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    written = path.read_text(encoding="utf-8")
    problems = [] if written == text else ["the file read back differs from what was written"]
    if path.suffix.lower() in {".txt", ".map", ""} and not problems:
        problems = [problem for problem in netmap.parse_map(written).problems if "already described" not in problem][:5]
    app.state.record_audit_event("map", action, target=str(path), result="success" if not problems else "verify-failed",
                                 detail={**detail, "backup": backup, "verify_problems": problems})
    return {"backup": backup, "verify_problems": problems}


def _diff(before: str, after: str, path: Path) -> str:
    lines = list(difflib.unified_diff(before.splitlines(), after.splitlines(), f"{path.name} (now)", f"{path.name} (after)", lineterm="", n=1))
    return "\n".join(lines)


def _preview_or_apply(app: Any, opts: Any, path: Path, before: str, after: str, action: str,
                      changes: List[Dict[str, str]], summary: str) -> int:
    from netops_platform.core import CONFIRM_REQUIRED, INTERNAL, SUCCESS
    payload: Dict[str, Any] = {"ok": True, "path": str(path), "changes": changes, "summary": summary}
    if before == after:
        app.emit({**payload, "applied": 0}, opts, f"{summary}\nThe map already has all of it; nothing to change.")
        return SUCCESS
    if not opts.confirm:
        diff = _diff(before, after, path)
        payload.update({"requires_confirm": True, "diff": diff})
        command = shlex.join(["netrune", *sys.argv[1:]]) if sys.argv[1:2] == ["map"] else f"netrune map {action.removeprefix('map-')}"
        command = command.replace(" --dry-run", "")
        app.emit(payload, opts, "\n".join([summary, "", diff, "",
                                           f"Nothing written. Re-run with --confirm to apply {len(changes)} change(s) to {path}"
                                           + ("; the current map is backed up first." if before else ".")
                                           + f"\n  {command} --confirm"]))
        return SUCCESS if opts.dry_run else CONFIRM_REQUIRED
    result = _write(app, path, after, action, {"changes": changes[:200], "summary": summary})
    payload.update({"applied": len(changes), **result, "ok": not result["verify_problems"]})
    lines = [summary, f"Wrote {len(changes)} change(s) to {path}."]
    if result["backup"]:
        lines.append(f"Previous map backed up to {result['backup']}.")
    lines.append("Read back and verified." if not result["verify_problems"] else "Verification found: " + "; ".join(result["verify_problems"]))
    app.emit(payload, opts, "\n".join(lines))
    return SUCCESS if not result["verify_problems"] else INTERNAL


# --------------------------------------------------------------------------
# Verbs


def _check(app: Any, rest: List[str], opts: Any) -> int:
    from netops_platform.core import PARTIAL, SUCCESS
    positional, options = _parse(rest)
    current, path = _load(app, options)
    if current is None:
        app.emit({"ok": True, "path": str(path), "configured": False, "summary": "no network map yet"}, opts, _no_map_text(path))
        return SUCCESS
    inventory, seen, about = evidence(app)
    result = netmap.check(current, inventory, seen)
    findings = result.findings
    if positional:
        wanted = netmap.name_key(positional[0])
        findings = [item for item in findings if netmap.name_key(item["switch"]) == wanted
                    or wanted in netmap.name_key(item["subject"]).split()]
    counts = {status: sum(1 for item in findings if item["status"] == status) for status in netmap.STATUS_ORDER}
    counts = {status: count for status, count in counts.items() if count}
    attention = sum(counts.get(status, 0) for status in netmap.ATTENTION_STATUSES)
    headline = (f"Network map check: {attention} item(s) disagree with the network | "
                + " | ".join(f"{status} {count}" for status, count in counts.items()))
    summary = headline + f"\n{len(current.nodes)} device(s), {len(current.links)} link(s), {len(current.attachments)} attachment(s) on the map ({path})\n{_as_of(about)}"
    payload = {"ok": True, "path": str(path), "status": "ATTENTION" if attention else "SUCCESS", "summary": headline,
               "counts": counts, "attention": attention, "findings": findings, "about": about,
               "map": current.counts(), "parse_problems": current.problems}
    if not positional and path == map_path(app):
        app.state.set_marker("map_check_last", json.dumps({
            "at": int(time.time()), "counts": counts, "attention": attention,
            "items": [item for item in findings if item["status"] in netmap.ATTENTION_STATUSES][:20]}))
    shown = findings if opts.all else [item for item in findings if item["status"] != "OK"]
    lines = [summary]
    if current.problems:
        lines += ["", "Map file problems (fix with: netrune map edit):"] + [f"  {problem}" for problem in current.problems[:20]]
    status = ""
    headings = {"INFO": "INFO  on the network next to mapped devices, not on the map",
                "NOT ON MAP": "NOT ON MAP  links between two mapped devices that the map lacks"}
    for item in shown:
        if item["status"] != status:
            status = item["status"]
            lines += ["", headings.get(status, status)]
        if status == "INFO" and not item["line"]:
            lines.append(f"  {item['network'] if item['kind'] == 'device' else item['subject']}  ({item['hint']})")
            continue
        where = f"line {item['line']}" if item["line"] else "network"
        lines.append(f"  {where:<9} {item['subject']}")
        if item["network"] and item["network"] != item["subject"]:
            lines.append(f"            network: {item['network']}")
        if item["hint"]:
            lines.append(f"            {item['hint']}")
    hidden = len(findings) - len(shown)
    if hidden:
        lines += ["", f"{hidden} item(s) agree (--all lists them)."]
    if result.discovered_links or result.endpoints or result.unmapped_neighbors:
        lines += ["", "To write what the network shows into the map: netrune map update --dry-run"
                  + (" --add-new" if result.unmapped_neighbors else "") + (" --attachments" if result.endpoints else "")]
    app.emit(payload, opts, "\n".join(lines))
    return PARTIAL if attention else SUCCESS


def _update(app: Any, rest: List[str], opts: Any) -> int:
    from netops_platform.core import SUCCESS
    positional, options = _parse(rest)
    if positional:
        raise netmap.MapError("map update takes no device; it updates the whole map.")
    path = map_path(app)
    if not path.is_file():
        app.emit({"ok": False, "path": str(path), "configured": False}, opts, _no_map_text(path))
        return SUCCESS
    current = netmap.parse_map(path.read_text(encoding="utf-8"))
    inventory, seen, about = evidence(app)
    result = netmap.check(current, inventory, seen)
    edits = netmap.plan_update(current, result, add_new=bool(options.get("--add-new")), attachments=bool(options.get("--attachments")),
                               overwrite=bool(options.get("--overwrite")))
    section = f"# --- Added by netrune map update, {netmap.today()}: seen on the network ---"
    after = netmap.apply_edits(current, edits, section=section)
    changes = netmap.describe_edits(edits, current)
    if options.get("--add-new") and edits:
        # The switches just added get the same treatment as the rest (their
        # links to each other, their APs and phones with --attachments) in
        # this run, without reaching another hop further out.
        grown = netmap.parse_map(after)
        second = netmap.plan_update(grown, netmap.check(grown, inventory, seen), attachments=bool(options.get("--attachments")),
                                    overwrite=bool(options.get("--overwrite")))
        if second:
            after = netmap.apply_edits(grown, second, section=section)
            changes += netmap.describe_edits(second, grown)
    summary = f"Map update from the network ({_as_of(about)})"
    if changes:
        summary += "\n" + app.render_table(changes, ["device", "change", "detail"])
    skipped = []
    if result.unmapped_neighbors and not options.get("--add-new"):
        skipped.append(f"{len(result.unmapped_neighbors)} neighbouring switch(es) not on the map (--add-new adds them)")
    if result.endpoints and not options.get("--attachments"):
        skipped.append(f"{len(result.endpoints)} AP/phone port(s) not on the map (--attachments adds them)")
    if skipped:
        summary += "\nNot included: " + "; ".join(skipped) + "."
    return _preview_or_apply(app, opts, path, path.read_text(encoding="utf-8"), after, "map-update", changes, summary)


def _import(app: Any, rest: List[str], opts: Any) -> int:
    positional, options = _parse(rest)
    if len(positional) != 1:
        raise netmap.MapError("Give exactly one file to import.")
    source = Path(os.path.expanduser(positional[0])).resolve()
    incoming = netmap.read_any(source, sheet=str(options.get("--sheet") or ""))
    if not incoming.nodes:
        raise netmap.MapError(f"Found no devices in {source.name}." + (f" ({'; '.join(incoming.problems[:3])})" if incoming.problems else ""))
    path = map_path(app)
    before = path.read_text(encoding="utf-8") if path.is_file() else ""
    if not before or options.get("--replace"):
        after = netmap.render_map(incoming, header=netmap.TEMPLATE + f"#\n# Imported from {source.name} on {netmap.today()}.\n")
        changes = [{"device": node.name, "change": "new device", "detail": netmap.render_header(node), "why": f"from {source.name}"}
                   for node in incoming.nodes.values()]
    else:
        current = netmap.parse_map(before)
        edits = netmap.plan_merge(current, incoming, overwrite=bool(options.get("--overwrite")), stamp=f"netrune import {netmap.today()}")
        after = netmap.apply_edits(current, edits, section=f"# --- Imported from {source.name}, {netmap.today()} ---")
        changes = netmap.describe_edits(edits, current)
    counts = incoming.counts()
    summary = (f"Read {source.name}: {counts['devices']} device(s), {counts['links']} link(s), {counts['attachments']} attachment(s)"
               + ("" if before and not options.get("--replace") else " -> a new map")
               + ("" if not incoming.problems else "\n  " + "\n  ".join(incoming.problems[:10])))
    if changes and before and not options.get("--replace"):
        summary += "\n" + app.render_table(changes, ["device", "change", "detail"])
    return _preview_or_apply(app, opts, path, before, after, "map-import", changes, summary)


def _seed_from_network(app: Any, attachments: bool) -> Tuple[netmap.NetMap, Dict[str, Any]]:
    inventory, seen, about = evidence(app)
    draft = netmap.NetMap()
    switches = [row for row in inventory.rows if row.get("kind") == "device"]
    for row in sorted(switches, key=lambda row: str(row.get("name") or row.get("ip") or "").lower()):
        name = str(row.get("name") or row.get("ip") or "").strip()
        if not name:
            continue
        node = draft.ensure_node(name)
        node.ip = str(row.get("ip") or "")
        for key in ("model", "serial"):
            value = str(row.get(key) or "").strip()
            if value and value.upper() not in {"N/A", "UNKNOWN"}:
                node.fields[key] = value
    # LLDP/CDP first; a spanning-tree link only where LLDP/CDP shows none
    # between the same two switches (it knows no far-end port).
    cables: set = set()
    pairs: set = set()
    for item in sorted((item for item in seen if item.current and item.b and item.a != item.b),
                       key=lambda item: item.source == "spanning-tree"):
        a_row, b_row = inventory.by_ident.get(item.a), inventory.by_ident.get(item.b)
        if not a_row or not b_row or a_row.get("kind") != "device" or b_row.get("kind") != "device":
            continue
        cable = tuple(sorted(((item.a, netmap.port_key(item.a_port)), (item.b, netmap.port_key(item.b_port)))))
        pair = tuple(sorted((item.a, item.b)))
        if cable in cables or (item.source == "spanning-tree" and pair in pairs):
            continue
        cables.add(cable)
        pairs.add(pair)
        a_name, b_name = str(a_row.get("name") or a_row.get("ip")).strip(), str(b_row.get("name") or b_row.get("ip")).strip()
        draft.links.append(netmap.Link(a_name, item.a_port, b_name, item.b_port))
    if attachments:
        result = netmap.check(draft, inventory, seen)
        for entry in result.endpoints:
            draft.attachments.append(netmap.Attachment(entry["switch"], entry["port"], entry["kind"], entry["label"]))
    # Each cable once, under the switch nearer the core (more links).
    degree: Dict[str, int] = {}
    for link in draft.links:
        for name in (link.a, link.b):
            degree[netmap.name_key(name)] = degree.get(netmap.name_key(name), 0) + 1
    unique: Dict[Tuple[str, str], netmap.Link] = {}
    for link in draft.links:
        a, b = netmap.name_key(link.a), netmap.name_key(link.b)
        if (degree.get(b, 0), b) > (degree.get(a, 0), a):
            link = netmap.Link(link.b, link.b_port, link.a, link.a_port)
        key = (netmap.name_key(link.a) + "|" + netmap.port_key(link.a_port), netmap.name_key(link.b) + "|" + netmap.port_key(link.b_port))
        unique.setdefault(key, link)
    draft.links = list(unique.values())
    return draft, about


def _init(app: Any, rest: List[str], opts: Any) -> int:
    from netops_platform.core import CONFIRM_REQUIRED, SUCCESS
    positional, options = _parse(rest)
    if positional:
        raise netmap.MapError("map init takes no arguments besides its options.")
    path = map_path(app)
    if options.get("--from-network"):
        draft, about = _seed_from_network(app, bool(options.get("--attachments")))
        counts = draft.counts()
        text = netmap.render_map(draft, header=netmap.TEMPLATE + f"#\n# Drafted from Netrune's discovery on {netmap.today()}: "
                                 "add @locations, fix names, delete what is not yours.\n")
        summary = (f"Draft from the network: {counts['devices']} switch(es), {counts['links']} link(s), "
                   f"{counts['attachments']} attachment(s); {_as_of(about)}")
    else:
        text = netmap.TEMPLATE + "\n# Your devices start here.\n"
        summary = "An empty map with the format guide at the top."
    if path.exists() and not opts.confirm:
        app.emit({"ok": False, "requires_confirm": True, "path": str(path)}, opts,
                 f"{path} already exists. 'netrune map edit' opens it; 'netrune map import FILE' adds to it.\n"
                 "Re-run with --confirm to replace it (it is backed up first).")
        return CONFIRM_REQUIRED
    if opts.dry_run:
        app.emit({"ok": True, "dry_run": True, "path": str(path), "text": text, "summary": summary}, opts,
                 f"{summary}\nWould write {path}:\n\n{text}")
        return SUCCESS
    result = _write(app, path, text, "map-init", {"summary": summary})
    lines = [summary, f"Wrote {path}."]
    if result["backup"]:
        lines.append(f"Previous map backed up to {result['backup']}.")
    lines.append("Next: netrune map edit   (then: netrune map check)")
    app.emit({"ok": True, "path": str(path), **result, "summary": summary}, opts, "\n".join(lines))
    return SUCCESS


def _edit(app: Any, rest: List[str], opts: Any) -> int:
    from netops_platform.core import SUCCESS, VALIDATION
    path = map_path(app)
    if not path.exists():
        _write(app, path, netmap.TEMPLATE + "\n# Your devices start here.\n", "map-init", {"summary": "template for map edit"})
    before = path.read_text(encoding="utf-8")
    editor = os.environ.get("VISUAL") or os.environ.get("EDITOR") or next(
        (name for name in ("nano", "vim", "vi") if shutil.which(name)), "")
    if opts.json or not sys.stdin.isatty() or not editor:
        app.emit({"ok": True, "path": str(path)}, opts, f"Edit {path} in any editor, then run: netrune map check")
        return SUCCESS
    subprocess.run([*shlex.split(editor), str(path)], check=False)
    after = path.read_text(encoding="utf-8")
    parsed = netmap.parse_map(after)
    if after != before:
        app.state.record_audit_event("map", "map-edit", target=str(path), result="success",
                                     detail={"map": parsed.counts(), "problems": parsed.problems[:20]})
    counts = parsed.counts()
    lines = [f"{path}: {counts['devices']} device(s), {counts['links']} link(s), {counts['attachments']} attachment(s)."]
    if parsed.problems:
        lines += ["Problems:"] + [f"  {problem}" for problem in parsed.problems[:20]] + ["Run 'netrune map edit' again to fix them."]
    else:
        lines.append("Next: netrune map check")
    app.emit({"ok": not parsed.problems, "path": str(path), "map": counts, "problems": parsed.problems}, opts, "\n".join(lines))
    return SUCCESS if not parsed.problems else VALIDATION


def _show(app: Any, rest: List[str], opts: Any) -> int:
    from netops_platform.core import SUCCESS, VALIDATION
    positional, options = _parse(rest)
    current, path = _load(app, options)
    if current is None:
        app.emit({"ok": True, "path": str(path), "configured": False}, opts, _no_map_text(path))
        return SUCCESS
    counts = current.counts()
    if not positional:
        locations: Dict[str, int] = {}
        for node in current.nodes.values():
            locations[node.location or "(no location)"] = locations.get(node.location or "(no location)", 0) + 1
        rows = [{"location": location, "devices": count} for location, count in sorted(locations.items())]
        last = json.loads(app.state.get_marker("map_check_last") or "{}") if path == map_path(app) else {}
        lines = [f"Network map {path}",
                 ", ".join(f"{count} {name}" for name, count in counts.items()),
                 app.render_table(rows, ["location", "devices"])]
        if last:
            when = dt.datetime.fromtimestamp(last["at"]).strftime("%Y-%m-%d %H:%M")
            lines.append(f"Last check {when}: {last.get('attention', 0)} item(s) disagreed with the network ("
                         + ", ".join(f"{status} {count}" for status, count in (last.get("counts") or {}).items()) + ").")
        if current.problems:
            lines += ["Problems:"] + [f"  {problem}" for problem in current.problems[:10]]
        lines.append("netrune map show <device> prints one device; netrune map check compares the map with the network.")
        app.emit({"ok": True, "path": str(path), "map": counts, "locations": rows, "last_check": last,
                  "problems": current.problems}, opts, "\n".join(lines))
        return SUCCESS
    node = current.node(positional[0])
    if node is None:
        close = difflib.get_close_matches(netmap.name_key(positional[0]), list(current.nodes), n=3, cutoff=0.6)
        hint = f" Did you mean: {', '.join(current.nodes[key].name for key in close)}?" if close else ""
        app.emit({"ok": False, "error": f"{positional[0]} is not on the map."}, opts, f"{positional[0]} is not on the map.{hint}")
        return VALIDATION
    own = [link for link in current.links if netmap.name_key(link.a) == node.key]
    incoming = [link for link in current.links if netmap.name_key(link.b) == node.key]
    plugged = [item for item in current.attachments if netmap.name_key(item.switch) == node.key]
    lines = [netmap.render_header(node)]
    lines += [netmap.render_port_line(item) for item in netmap._compress_ranges(
        sorted(own + plugged, key=lambda item: netmap._port_sort(item.a_port if isinstance(item, netmap.Link) else item.port)))]
    if incoming:
        lines += ["", "Linked from:"] + [f"  {link.a} {link.a_port} -> {link.b_port or '?'}".rstrip() for link in incoming]
    if node.line >= 0:
        lines += ["", f"(line {node.line + 1} of {path})"]
    app.emit({"ok": True, "node": node.__dict__, "links": [link.__dict__ for link in own + incoming],
              "attachments": [item.__dict__ for item in plugged]}, opts, "\n".join(lines))
    return SUCCESS


def _export(app: Any, rest: List[str], opts: Any) -> int:
    from netops_platform.core import CONFIRM_REQUIRED, SUCCESS
    positional, options = _parse(rest)
    if len(positional) != 1:
        raise netmap.MapError("Give the file to write: .csv (spreadsheet), .txt (the map), or .drawio (a diagram).")
    destination = Path(os.path.expanduser(positional[0])).resolve()
    fmt = str(options.get("--format") or destination.suffix.lstrip(".") or "txt").lower()
    if fmt not in {"csv", "txt", "drawio", "xml"}:
        raise netmap.MapError(f"Cannot export as {fmt}: use .csv, .txt, or .drawio.")
    current, path = _load(app, {})
    if current is None:
        app.emit({"ok": False, "path": str(path)}, opts, _no_map_text(path))
        return SUCCESS
    if fmt == "csv":
        text = netmap.to_csv(current)
    elif fmt == "txt":
        text = path.read_text(encoding="utf-8")
    else:
        inventory, seen, _ = evidence(app)
        text = netmap.to_drawio(current, netmap.check(current, inventory, seen))
    if destination.exists() and not opts.confirm:
        app.emit({"ok": False, "requires_confirm": True, "destination": str(destination)}, opts,
                 f"{destination} already exists. Re-run with --confirm to replace it (it is backed up first).")
        return CONFIRM_REQUIRED
    if opts.dry_run:
        app.emit({"ok": True, "dry_run": True, "destination": str(destination), "bytes": len(text)}, opts,
                 f"Would write {destination} ({len(text)} bytes, {fmt}).")
        return SUCCESS
    result = _write(app, destination, text, "map-export", {"format": fmt, "source": str(path)})
    note = {"csv": "Edit it in Excel and bring changes back with: netrune map import FILE --dry-run",
            "drawio": "Open it in draw.io (diagrams.net): green agrees with the network, red is not seen, orange differs, "
                      "dashed blue is on the network but not the map, grey has no evidence yet.",
            "txt": "A copy of the map file.", "xml": ""}[fmt]
    app.emit({"ok": True, "destination": str(destination), "format": fmt, **result}, opts,
             f"Wrote {destination}." + (f" Previous file backed up to {result['backup']}." if result["backup"] else "") + f"\n{note}")
    return SUCCESS


def _path(app: Any, rest: List[str], opts: Any) -> int:
    from netops_platform.core import SUCCESS
    path = map_path(app)
    app.emit({"ok": True, "path": str(path), "exists": path.is_file()}, opts, str(path))
    return SUCCESS


HANDLERS = {"show": (_show, SHOW_USAGE), "check": (_check, CHECK_USAGE), "update": (_update, UPDATE_USAGE),
            "import": (_import, IMPORT_USAGE), "init": (_init, INIT_USAGE), "edit": (_edit, "netrune map edit"),
            "export": (_export, EXPORT_USAGE), "path": (_path, "netrune map path")}


def attention_item(app: Any) -> Optional[Dict[str, Any]]:
    """The attention queue's line for the last map check, when it disagreed."""
    last = json.loads(app.state.get_marker("map_check_last") or "{}")
    if not last.get("attention"):
        return None
    counts = ", ".join(f"{status} {count}" for status, count in (last.get("counts") or {}).items()
                       if status in netmap.ATTENTION_STATUSES)
    when = dt.datetime.fromtimestamp(last["at"]).strftime("%Y-%m-%d")
    return {"kind": "map", "level": "warning", "title": "network map",
            "text": f"{last['attention']} item(s) disagree with the network ({counts}) as of {when}; run: netrune map check",
            "row": last}


def dispatch(app: Any, args: List[str], opts: Any) -> int:
    from netops_platform.core import SUCCESS, VALIDATION
    if app.handle_help("map", args, opts):
        return SUCCESS
    verb = args[0] if args else "show"
    rest = args[1:]
    if verb not in HANDLERS:
        return app.usage_error("map", verb, opts, f"Unknown map action: {verb}", USAGE, VALIDATION)
    handler, usage = HANDLERS[verb]
    try:
        return handler(app, rest, opts)
    except netmap.MapError as exc:
        return app.usage_error("map", verb, opts, str(exc), usage, VALIDATION)
