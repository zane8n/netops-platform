"""Command surface for the excel domain.

A free-function module like path_cli.py: cmd_excel has one caller boundary
(App.dispatch), so nothing here needs to sit on the App's MRO. The workbook
planning and mechanics live in excel.py; this module owns the guarded
preview/backup/apply/verify/audit lifecycle around them (ADR 0005), applied to
a local file rather than a switch.
"""

from __future__ import annotations

import datetime as dt
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from netops_platform import excel


SYNC_USAGE = ("netrune excel sync <workbook.xlsx> [--sheet NAME] [--map 'Header=field,...'] [--fields LIST] "
              "[--fill-only] [--add-missing] [--prefer serial|mac|ip|hostname] [--output PATH] "
              "[--highlight] [--no-comments] [--ignore-lock] [--allow-feature-loss] (--dry-run | --confirm)")
INSPECT_USAGE = "netrune excel inspect <workbook.xlsx> [--sheet NAME] [--map 'Header=field,...'] [--fields LIST]"
EXPORT_USAGE = "netrune excel export <tracker.xlsx> [--migration-rows N] [--confirm]"

VALUE_OPTIONS = {"--sheet", "--map", "--fields", "--prefer", "--output", "--migration-rows"}
FLAG_OPTIONS = {"--fill-only", "--add-missing", "--highlight", "--no-comments", "--ignore-lock", "--allow-feature-loss"}


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


def _fields(options: Dict[str, Any]) -> Tuple[str, ...]:
    raw = str(options.get("--fields") or "").strip()
    if not raw:
        return excel.DEFAULT_FIELDS
    chosen = tuple(item.strip().lower().replace("-", "_") for item in raw.split(",") if item.strip())
    unknown = [item for item in chosen if item not in excel.FIELDS]
    if unknown:
        raise excel.ExcelError(f"--fields: unknown field(s) {', '.join(unknown)}; choose from {', '.join(excel.FIELDS)}.")
    return chosen


def _layouts(wb: Any, options: Dict[str, Any]) -> List[Tuple[Any, excel.SheetLayout]]:
    overrides = excel.parse_column_map(str(options.get("--map") or ""))
    wanted = options.get("--sheet")
    if wanted:
        if wanted not in wb.sheetnames:
            raise excel.ExcelError(f"No sheet named '{wanted}'. Sheets: {', '.join(wb.sheetnames)}")
        sheets = [wb[wanted]]
    else:
        sheets = list(wb.worksheets)
    found = []
    for ws in sheets:
        layout = excel.detect_layout(ws, overrides)
        if layout:
            found.append((ws, layout))
        elif wanted:
            raise excel.ExcelError(
                f"Sheet '{wanted}' has no header row naming a hostname, IP, serial, or MAC column plus one more field. "
                "Point at the columns with --map, e.g. --map 'Device=hostname,Mgmt=ip'.")
    if not found:
        raise excel.ExcelError("No sheet has a recognizable header row (hostname/IP/serial/MAC plus one more field). "
                               "Use --sheet and --map to point at the columns.")
    return found


def _plans(app: Any, wb: Any, options: Dict[str, Any], *, fields: Tuple[str, ...]) -> Tuple[List[excel.SheetPlan], excel.DeviceIndex]:
    prefer = str(options.get("--prefer") or "").strip().lower()
    if prefer and prefer not in excel.IDENTITY_FIELDS:
        raise excel.ExcelError("--prefer must be serial, mac, ip, or hostname.")
    layouts = _layouts(wb, options)
    if options.get("--add-missing") and len(layouts) > 1:
        raise excel.ExcelError("--add-missing needs --sheet: name the one sheet new rows belong on.")
    index = excel.DeviceIndex.build(_devices(app))
    plans = [excel.plan_sheet(ws, layout, index, fields=fields, fill_only=bool(options.get("--fill-only")),
                              prefer=prefer, add_missing=bool(options.get("--add-missing")))
             for ws, layout in layouts]
    return plans, index


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
    summary = _summary_rows(plans, index)
    payload = {
        "ok": True, "summary": summary, "layouts": [plan.layout.as_dict() for plan in plans],
        "changes": changes, "unmatched": unmatched, "conflicts": conflicts, "kept": kept,
        "duplicates": duplicates, "features_lost_on_save": features, "lock_file": str(lock or ""),
    }
    limit = max(1, int(getattr(opts, "limit", 100) or 100))
    parts = [heading, ""]
    for layout in payload["layouts"]:
        mapped = ", ".join(f"{name}={where}" for name, where in layout["columns"].items())
        parts.append(f"Sheet '{layout['sheet']}': header row {layout['header_row']}, {layout['data_rows']} data row(s); columns {mapped}")
    parts += ["", app.render_table(summary, ["sheet", "rows", "matched", "unmatched", "conflicts", "cell_changes", "new_rows", "devices_not_in_sheet"])]
    if changes:
        parts += ["", f"Cell changes ({len(changes)}" + (f", first {limit} shown" if len(changes) > limit else "") + ")",
                  app.render_table(changes[:limit], ["sheet", "cell", "column", "old", "new", "matched_by", "kind"])]
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
    plans, index = _plans(app, wb, options, fields=fields)
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
    applied = excel.apply_plans(wb, plans, comments=not options.get("--no-comments"), highlight=bool(options.get("--highlight")))
    _atomic_save(wb, destination)
    problems = excel.verify_saved(destination, plans)
    detail = {"source": str(source), "destination": str(destination), "backup": str(backup or ""),
              "applied": applied, "fields": list(fields), "verify_problems": problems[:20],
              "sheets": _summary_rows(plans, index)}
    app.state.record_audit_event("excel", "excel-sync", target=str(destination),
                                 result="success" if not problems else "verify-failed", detail=detail)
    lines = [f"Wrote {applied} cell(s) to {destination}."]
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
    plans, index = _plans(app, wb, options, fields=fields)
    features = excel.workbook_features(source)
    payload, text = _report(app, plans, index, opts, features, excel.excel_lock_file(source),
                            f"{source.name}: {len(wb.sheetnames)} sheet(s) ({', '.join(wb.sheetnames)}); "
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
                 "hostname,ip,platform,model,serial,mac,status,last_seen --confirm")
    app.emit({"ok": True, "destination": str(destination), "backup": str(backup or ""), **result}, opts, "\n".join(lines))
    return SUCCESS


def dispatch(app: Any, args: List[str], opts: Any) -> int:
    from netops_platform.core import SUCCESS, VALIDATION
    if app.handle_help("excel", args, opts):
        return SUCCESS
    verb = args[0] if args else "inspect"
    rest = args[1:]
    handlers = {"inspect": (_inspect, INSPECT_USAGE), "sync": (_sync, SYNC_USAGE), "export": (_export, EXPORT_USAGE)}
    if verb not in handlers:
        return app.usage_error("excel", verb, opts, f"Unknown excel action: {verb}", "netrune excel <inspect|sync|export>", VALIDATION)
    handler, usage = handlers[verb]
    try:
        return handler(app, rest, opts)
    except excel.ExcelError as exc:
        return app.usage_error("excel", verb, opts, str(exc), usage, VALIDATION)
