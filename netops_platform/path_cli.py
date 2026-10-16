"""Command surface for the path domain.

Kept out of core.py as a free function, matching traffic_cli.py's and
setup_cli.py's pattern: cmd_path has no callers outside its own dispatch,
verified by grep across the tree before moving anything. It delegates
almost all of its real work to PathInspector (netops_platform/path_inspector.py),
an already-independent module.
"""

from __future__ import annotations

from typing import Any, List

from netops_platform.contracts import PathRequestV1

def dispatch(app: Any, args: List[str], opts: GlobalOptions) -> int:
    from netops_platform.core import CHRONOLOGY, PARTIAL, SUCCESS, TIME_FORMAT, UNREACHABLE, VALIDATION, fmt_time, now, timestamp_rows
    if app.handle_help("path", args, opts): return SUCCESS
    verb = args[0] if args else "history"
    rest = args[1:]
    if verb == "findings":
        # path_findings and path_hops were written on every run and never
        # read; every lookup went through the run's JSON blob. Querying
        # them across runs is what the normalised tables are for.
        severity = ""
        index = 0
        while index < len(rest):
            if rest[index] == "--severity" and index + 1 < len(rest):
                severity = str(rest[index + 1]).lower()
                if severity not in {"critical", "error", "warning", "info"}:
                    return app.usage_error("path", "findings", opts, "--severity must be critical, error, warning, or info.", "netrune path findings --severity critical", VALIDATION)
                index += 2
                continue
            return app.usage_error("path", "findings", opts, f"Unknown path findings option: {rest[index]}", "netrune path findings [--severity LEVEL]", VALIDATION)
        clauses = []
        params: List[Any] = []
        if severity:
            clauses.append("f.severity=?")
            params.append(severity)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(opts.limit)
        rows = app.state.rows(
            "SELECT f.code,f.severity,f.device_id,f.interface,f.message,f.confidence,"
            "       r.endpoint,r.vlan,r.status,r.started_at "
            "FROM path_findings f JOIN path_runs r ON r.run_id=f.run_id "
            f"{where} ORDER BY r.started_at DESC,f.id DESC LIMIT ?",
            tuple(params),
        )
        counts = app.state.rows(
            "SELECT code,severity,COUNT(*) AS occurrences FROM path_findings "
            "GROUP BY code,severity ORDER BY occurrences DESC LIMIT 20"
        )
        payload = {"ok": True, "rows": timestamp_rows(rows), "count": len(rows), "by_code": counts}
        text = (
            f"Path findings ({len(rows)} shown)\n"
            + app.render_table(timestamp_rows(rows), ["severity", "code", "device_id", "interface", "endpoint", "vlan", "started_at"])
            + "\n\nMost frequent\n"
            + app.render_table(counts, ["severity", "code", "occurrences"])
        )
        app.emit(payload, opts, text)
        return SUCCESS if rows else PARTIAL
    if verb == "history":
        endpoint = ""; vlan = 0; index = 0
        while index < len(rest):
            value = rest[index]
            if value == "--vlan" and index + 1 < len(rest):
                try: vlan = int(rest[index + 1])
                except ValueError: return app.usage_error("path", "history", opts, "--vlan must be an integer.", "netrune help path history", VALIDATION)
                if not 1 <= vlan <= 4094: return app.usage_error("path", "history", opts, "--vlan must be between 1 and 4094.", "netrune help path history", VALIDATION)
                index += 2
            elif value.startswith("-"):
                return app.usage_error("path", "history", opts, f"Unknown path history option: {value}", "netrune help path history", VALIDATION)
            elif not endpoint: endpoint = value; index += 1
            else: return app.usage_error("path", "history", opts, f"Unexpected argument: {value}", "netrune help path history", VALIDATION)
        rows = timestamp_rows(app.path_inspector.history(endpoint, vlan, opts.limit))
        app.emit({"ok": True, "rows": rows, "chronology": CHRONOLOGY, "time_format": TIME_FORMAT}, opts, app.render_table(rows, ["started_at", "status", "endpoint", "vlan", "source", "destination", "mode", "confidence", "run_ref"]))
        return SUCCESS
    if verb in {"show", "hshow"}:
        if not rest: return app.usage_error("path", "show", opts, "Missing path run id.", "netrune path history", VALIDATION)
        reference = rest[0]; vlan = 0; index = 1
        while index < len(rest):
            value = rest[index]
            if value == "--vlan" and index + 1 < len(rest):
                try: vlan = int(rest[index + 1])
                except ValueError: return app.usage_error("path", "show", opts, "--vlan must be an integer.", "netrune help path show", VALIDATION)
                if not 1 <= vlan <= 4094: return app.usage_error("path", "show", opts, "--vlan must be between 1 and 4094.", "netrune help path show", VALIDATION)
                index += 2
            else: return app.usage_error("path", "show", opts, f"Unknown or incomplete option: {value}", "netrune help path show", VALIDATION)
        try:
            payload = app.path_inspector.show(reference, vlan)
        except ValueError as exc:
            return app.usage_error("path", "show", opts, str(exc), "netrune path history", VALIDATION)
        if payload is None: return app.usage_error("path", "show", opts, f"Path run not found: {rest[0]}", "netrune path history", VALIDATION)
        hops = payload.get("hops") or []; findings = payload.get("findings") or []
        request = payload.get("request") or {}
        text = (
            f"{payload.get('status')}: {payload.get('summary')}\n"
            f"Confidence: {payload.get('confidence')}% | VLAN: {request.get('vlan')} | Recorded: {fmt_time(payload.get('finished_at'))} | Run: {payload.get('run_id')}\n\n"
            + app.render_table(hops, ["sequence", "device_name", "management_ip", "ingress_interface", "egress_interface", "layer", "vlan_state", "forwarding_state", "confidence"])
            + "\n\nFindings\n" + app.render_findings(findings)
        )
        app.emit({"ok": True, **payload}, opts, text)
        return SUCCESS
    if verb != "inspect": return app.unknown_action("path", verb, opts)
    endpoint = ""; vlan = 0; source = ""; destination = ""; mode = "hybrid"; explain = False; refresh = False
    index = 0
    while index < len(rest):
        value = rest[index]
        if value == "--vlan" and index + 1 < len(rest): vlan = int(rest[index + 1]); index += 2
        elif value == "--from" and index + 1 < len(rest): source = rest[index + 1]; index += 2
        elif value == "--to" and index + 1 < len(rest): destination = rest[index + 1]; index += 2
        elif value == "--cached": mode = "cached"; index += 1
        elif value == "--refresh": mode = "hybrid"; refresh = True; index += 1
        elif value == "--hybrid": mode = "hybrid"; index += 1
        elif value == "--live": mode = "live"; index += 1
        elif value == "--explain": explain = True; index += 1
        elif value.startswith("-"): return app.usage_error("path", "inspect", opts, f"Unknown path option: {value}", "netrune help path inspect", VALIDATION)
        elif not endpoint: endpoint = value; index += 1
        elif not vlan and value.isdigit(): vlan = int(value); index += 1
        else: return app.usage_error("path", "inspect", opts, f"Unexpected argument: {value}", "netrune help path inspect", VALIDATION)
    if not endpoint or not vlan:
        return app.usage_error("path", "inspect", opts, "Endpoint and --vlan are required.", "netrune path inspect 02:00:00:00:00:25 --vlan 120", VALIDATION)
    if opts.dry_run: mode = "cached"
    if refresh and mode != "cached": opts.refresh_neighbors = True
    try:
        request = PathRequestV1(endpoint, vlan, source, destination, opts.depth or 8, opts.max_nodes, mode, explain, now())
    except ValueError as exc:
        return app.usage_error("path", "inspect", opts, str(exc), "netrune help path inspect", VALIDATION)
    # A path inspection reads several devices: the forwarding walk, VLAN
    # inspection, spanning tree, capability collection and possibly a
    # switch-wide search. Holding the vault once covers all of them instead
    # of prompting for each read.
    if mode in {"live", "hybrid"}:
        with app.vault_session_scope(opts, minutes=30):
            result = app.path_inspector.inspect(request, opts)
    else:
        result = app.path_inspector.inspect(request, opts)
    payload = result.to_dict()
    hops = payload["hops"]; findings = payload["findings"]
    text = (
        f"{result.status}: {result.summary}\n"
        f"Confidence: {result.confidence}% | VLAN: {vlan} | Mode: {mode} | Recorded: {fmt_time(result.finished_at)} | Run: {result.run_id}\n\n"
        "Hop path\n" + app.render_table(hops, ["sequence", "device_name", "management_ip", "ingress_interface", "egress_interface", "layer", "vlan_state", "forwarding_state", "confidence"])
        + "\n\nFindings\n" + app.render_findings(findings, "No blockers or evidence warnings found.")
    )
    if explain:
        text += "\n\nEvidence\nCached topology plans the path; hybrid mode then validates VLAN and forwarding evidence on each bounded hop. Unsupported policy semantics remain unknown."
    app.emit({"ok": result.status in {"COMPLETE", "PARTIAL"}, **payload}, opts, text)
    return SUCCESS if result.status == "COMPLETE" else (UNREACHABLE if result.status == "BLOCKED" else PARTIAL)
