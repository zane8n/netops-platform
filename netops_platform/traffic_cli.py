"""Command surface for the traffic domain.

Kept out of core.py because the domain owns a collector daemon, an exposition
endpoint, and a provisioning generator, none of which the rest of the CLI needs
to know about. `App.cmd_traffic` delegates here.
"""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import subprocess
import sys
import urllib.parse
from pathlib import Path
import re
import time
from typing import Any, Dict, List, Mapping, Optional

from netops_platform.traffic import (
    TrafficMonitor,
    humanize_bps,
    SERIES_COLORS,
    parse_interface_index,
    parse_rate,
    resolve_color,
)

WINDOW_RE = re.compile(r"(\d+)\s*([smhd]?)")
WINDOW_SCALE = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}


def window_seconds(value: Any, fallback: int = 3600) -> Optional[int]:
    """Seconds from a --since value written as 900, 15m, 6h, or 2d."""
    text = str(value or "").strip().lower()
    if not text:
        return fallback
    match = WINDOW_RE.fullmatch(text)
    if not match:
        return None
    return max(60, min(int(match.group(1)) * WINDOW_SCALE[match.group(2)], 90 * 86400))


def _split_push_credentials(url: str) -> "tuple[str, str]":
    """Pull user:pass@ out of a storage URL into a Basic-Auth header.

    urllib does not turn embedded userinfo into an Authorization header on
    its own -- 'user:pass@host' would be sent to the resolver as the
    hostname -- and echoing the URL as typed would print the token in every
    dry-run and error message, so it is separated once here and the
    credential-free URL is what ever gets shown to the operator.

    Returns (credential_free_url, authorization_header_or_empty_string).
    """
    parsed = urllib.parse.urlsplit(url)
    if not parsed.username:
        return url, ""
    import base64
    credentials = parsed.username + (f":{parsed.password}" if parsed.password else "")
    header = "Basic " + base64.b64encode(credentials.encode("utf-8")).decode("ascii")
    netloc = parsed.hostname or ""
    if parsed.port:
        netloc += f":{parsed.port}"
    return urllib.parse.urlunsplit(parsed._replace(netloc=netloc)), header


def _flag(rest: List[str], name: str) -> tuple[List[str], Optional[str]]:
    """Pull `--name value` out of the argument list."""
    if name not in rest:
        return rest, None
    position = rest.index(name)
    if position + 1 >= len(rest):
        return rest, ""
    return rest[:position] + rest[position + 2:], rest[position + 1]


def _is_address(text: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(text.strip())
    except ValueError:
        return False
    return True


def _resolves_in_dns(text: str) -> bool:
    import socket
    try:
        socket.getaddrinfo(text.strip(), None)
    except OSError:
        return False
    return True


def _duration(seconds: Optional[float]) -> str:
    """An uptime the way an operator says it out loud."""
    if seconds is None:
        return "-"
    total = int(seconds)
    days, remainder = divmod(total, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes = remainder // 60
    if days:
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


#: What systemctl says when there is no user manager to talk to. The message
#: names a bus and a missing file, neither of which is the problem.
_NO_USER_BUS = ("Failed to connect to user scope bus", "Failed to connect to bus")


def user_manager_problem() -> str:
    """Why `systemctl --user` cannot work here, in terms of the actual cause.

    Every user service lives inside a per-user systemd manager. When that
    manager is not running, each command fails with a message about a bus and a
    missing socket -- which describes the symptom and not the cause, and sends
    people to look at permissions. The manager itself can fail to start at boot
    on a machine where logind and the session race, and it stays down until
    something starts it: linger being enabled is not the same as the manager
    having started.
    """
    state = _run(["systemctl", "is-active", "user@%d.service" % os.getuid()], timeout=15)[1].strip()
    if state == "active":
        return ""
    lingering = _run(["loginctl", "show-user", os.environ.get("USER", ""),
                      "-p", "Linger", "--value"], timeout=15)[1].strip() == "yes"
    detail = "" if lingering else (
        "\nLinger is also off, so it would not come back after a reboot either:"
        "\n    sudo loginctl enable-linger \"$USER\"")
    return ("The per-user systemd manager is not running, so no user service can be. "
            f"user@{os.getuid()}.service is '{state or 'unknown'}'. "
            "Start it with:\n"
            f"    sudo systemctl start user@{os.getuid()}.service\n"
            "Everything enabled here comes up with it." + detail)


def _snmp_system_name(app: Any, address: str, opts: Any) -> str:
    """What the device calls itself, so a watch added by address still reads.

    One extra SNMP read, and only the first time an unknown address is watched.
    Without it every chart and table for that switch is labelled by its address,
    which is the thing nobody recognises.
    """
    from netops_platform.core import clean_display_name
    from netops_platform.traffic import parse_device_health
    rc, out, err = app.capture(
        app.legacy_cmd("netrune-control", "snmp-health", address),
        min(int(getattr(opts, "timeout", 0) or 30), 60))
    name = parse_device_health((out or "") + (err or "")).get("info", {}).get("sysName", "")
    # sysName is usually fully qualified; the short form is what an operator says.
    return clean_display_name(str(name).split(".")[0]) if name else ""



def _dashboard_keep(app: Any, opts: Any, action: str, rest: List[str],
                    grapher: Any, base: str, usage) -> int:
    """Keep a dashboard edited in the browser, or go back to the generated one.

    Dashboards are generated because a generator can keep five of them
    consistent and a person editing JSON cannot. But an operator who has
    arranged a board the way they read it should not have to choose between
    that and every other thing regeneration does, so a kept dashboard is
    written verbatim in place of the generated one.
    """
    import json as _json
    import urllib.error
    import urllib.request
    from netops_platform.core import PARTIAL, SUCCESS, VALIDATION
    from netops_platform.traffic_stack import kept_dashboard_dir

    root = Path(app.paths.state_dir) / "metrics-stack"
    directory = kept_dashboard_dir(root)
    uids = [u for u in rest if not u.startswith("-")]

    if action in {"revert", "regenerate"}:
        if not uids:
            return usage("Which dashboard? Or --all to go back to the generated set.",
                         "netrune traffic dashboard revert netrune-overview")
        removed = []
        for uid in (sorted(p.stem for p in directory.glob("*.json")) if uids == ["--all"] else uids):
            path = directory / f"{uid}.json"
            if path.is_file():
                path.unlink()
                removed.append(uid)
        app.emit({"ok": True, "reverted": removed}, opts,
                 (f"Reverted {len(removed)} dashboard(s) to the generated version: "
                  + ", ".join(removed) if removed else "Nothing was being kept.")
                 + "\nRun 'netrune traffic stack init' to write them out.")
        return SUCCESS

    # save
    def fetch(uid: str) -> Optional[Dict[str, Any]]:
        try:
            with urllib.request.urlopen(f"{base}/api/dashboards/uid/{uid}", timeout=10) as response:
                return _json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, OSError, ValueError):
            return None

    if not uids or uids == ["--all"]:
        from netops_platform.traffic_dashboards import all_dashboards
        uids = [d.uid for d in all_dashboards()]
    directory.mkdir(parents=True, exist_ok=True)
    saved, missing = [], []
    for uid in uids:
        payload = fetch(uid)
        board = (payload or {}).get("dashboard")
        if not board:
            missing.append(uid)
            continue
        # The provisioner supplies id and version; carrying the browser's copies
        # back makes it refuse the file as a stale write.
        board.pop("id", None)
        board.pop("version", None)
        board["uid"] = uid
        (directory / f"{uid}.json").write_text(_json.dumps(board, indent=2) + "\n", encoding="utf-8")
        saved.append(uid)
    lines = []
    if saved:
        lines.append(f"Kept {len(saved)} dashboard(s) as edited: " + ", ".join(saved))
        lines.append(f"  {directory}")
        lines.append("These are now written in place of the generated ones, and survive "
                     "'netrune traffic stack init'.")
        lines.append("Go back with 'netrune traffic dashboard revert <uid>'.")
    if missing:
        lines.append(f"Could not read {len(missing)}: " + ", ".join(missing)
                     + f". Is the grapher answering at {base}?")
    app.emit({"ok": bool(saved), "saved": saved, "missing": missing,
              "directory": str(directory)}, opts, "\n".join(lines) or "Nothing to save.")
    return SUCCESS if saved and not missing else PARTIAL


def _http_ok(url: str, timeout: int = 5) -> bool:
    import urllib.error
    import urllib.request
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            return 200 <= response.status < 400
    except (urllib.error.URLError, OSError, ValueError):
        return False


def _snmp_failure(output: str) -> str:
    """What to tell an operator when an SNMP read came back empty.

    The helper distinguishes a device that did not answer from a profile with
    no credentials to ask with, because those lead somewhere very different.
    Reporting both as "check the community" sends an operator to look at a
    switch that was answering the whole time.
    """
    for line in str(output or "").splitlines():
        line = line.strip()
        if line.startswith("ERROR:") and "credentials are configured" in line:
            return line[len("ERROR:"):].strip()
    return ("SNMP returned no interface list for that device. Check the community or v3 "
            "credentials, and that this host is permitted by the device's SNMP ACL.")


def _label(watch: Mapping[str, Any]) -> str:
    """How a target is named in output.

    A remote poller can watch the same interface this machine does -- that is a
    normal thing to want, from two vantage points -- so the collector that took
    the reading is part of the name whenever it is not this one. Two identical
    labels for two different measurements is worse than a longer label.
    """
    if watch.get("kind") == "icmp":
        base = str(watch.get("target") or watch.get("label") or watch.get("watch_id"))
    else:
        device = str(watch.get("device_name") or watch.get("device_ip") or "")
        base = f"{device} {watch.get('interface_name') or ''}".strip()
    owner = str(watch.get("owner") or "")
    return f"{base}  @{owner}" if owner else base


def collector_pidfile(app: Any) -> Path:
    return Path(app.paths.state_dir) / "traffic-collector.json"


def running_collector(app: Any) -> Dict[str, Any]:
    """The live collector's record, or an empty dict when none is running."""
    path = collector_pidfile(app)
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
        pid = int(record.get("pid") or 0)
    except (OSError, ValueError, TypeError):
        return {}
    if pid <= 0:
        return {}
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        # A stale record from a collector that was killed rather than stopped.
        path.unlink(missing_ok=True)
        return {}
    except PermissionError:
        pass
    if not _is_collector_process(pid):
        # The pid outlived its collector -- a reboot or a kill -9 -- and now
        # belongs to something else. Trusting it refuses every restart forever.
        path.unlink(missing_ok=True)
        return {}
    return record


def _is_collector_process(pid: int) -> bool:
    """Whether a live pid is still a traffic collector, where the OS can say.

    os.kill() also accepts a thread id, so after a reboot a recorded pid can be
    "alive" as a thread of an unrelated program. Linux names both the thread
    group and the command line; elsewhere the signal probe is all there is.
    """
    proc = Path("/proc") / str(pid)
    if not Path("/proc/self").is_dir():
        return True
    try:
        status = (proc / "status").read_text(encoding="utf-8", errors="replace")
        argv = (proc / "cmdline").read_bytes().split(b"\0")
    except FileNotFoundError:
        return False
    except OSError:
        return True
    tgid = re.search(r"^Tgid:\s*(\d+)", status, re.MULTILINE)
    if tgid and int(tgid.group(1)) != pid:
        return False
    return b"traffic" in argv and b"daemon" in argv


def dispatch(app: Any, args: List[str], opts: Any) -> int:
    from netops_platform.core import PARTIAL, SUCCESS, VALIDATION, clean_display_name, eprint

    if app.handle_help("traffic", args, opts):
        return SUCCESS
    verb = args[0] if args else "list"
    rest = list(args[1:])
    monitor: TrafficMonitor = app.traffic
    actor = os.environ.get("SUDO_USER") or os.environ.get("USER") or ""

    def usage(message: str, example: str) -> int:
        return app.usage_error("traffic", verb, opts, message, example, VALIDATION)

    def resolve_window() -> Optional[int]:
        return window_seconds(opts.since)

    # ---- watchlist ---------------------------------------------------------

    def _cmd_list():
        nonlocal rest
        rows = monitor.list_watches()
        headline = {"interface": "out_bps", "icmp": "rtt_ms", "device": "cpu_percent"}
        for row in rows:
            kind = str(row["kind"])
            summary = monitor.summarize(str(row["watch_id"]), headline.get(kind, "out_bps"), 3600)
            row["state"] = "active" if row.get("enabled") else "paused"
            row["collector"] = row.get("owner") or "(local)"
            row["samples"] = summary["samples"]
            if summary["latest"] is None:
                row["latest"] = "-"
            elif kind == "interface":
                row["latest"] = humanize_bps(summary["latest"])
            elif kind == "icmp":
                row["latest"] = f"{summary['latest']:.1f} ms"
            else:
                row["latest"] = f"{summary['latest']:.0f}% cpu"
            row["recent"] = summary["spark"]
            row["name"] = monitor.display_name(row) if row.get("display_name") else ""
        app.emit(
            {"ok": True, "rows": rows, "count": len(rows)}, opts,
            app.render_table(rows, ["watch_id", "kind", "device_name", "interface_name", "name",
                                    "target", "collector", "interval_seconds", "state", "samples",
                                    "latest", "recent"])
            if rows else "No targets are being monitored. Add one with 'netrune traffic watch <device> <interface>'.")
        return SUCCESS if rows else PARTIAL

    def _cmd_watch():
        nonlocal rest
        rest, interval_arg = _flag(rest, "--interval")
        interval = 60
        if interval_arg is not None:
            if not str(interval_arg).isdigit():
                return usage("--interval requires seconds.", "netrune traffic watch SW01 Gi1/0/16 --interval 30")
            interval = int(interval_arg)
        if not rest:
            return usage("A device and interface are required.", "netrune traffic watch SITE-A-SW01 Gi1/0/16")
        device, choices = app.resolve_device_record(rest[0])
        if not device and _is_address(rest[0]):
            # An address needs no inventory. Reading counters over SNMP needs a
            # community and nothing else -- no scan, no platform detection, no
            # SSH -- and requiring a device record first is what made a machine
            # whose whole job is polling need the configuration of one that
            # does everything.
            device = {"ip": rest[0], "hostname": _snmp_system_name(app, rest[0], opts)}
        if not device:
            labels = ", ".join(str(row.get("hostname") or row.get("ip")) for row in choices[:8])
            return usage(
                f"'{rest[0]}' did not resolve to one device."
                + (f" Candidates: {labels}" if labels else "")
                + " An address is accepted directly, with no inventory.",
                "netrune traffic watch 198.51.100.10 Gi1/0/16")
        if len(rest) < 2:
            return usage("At least one interface name is required.", "netrune traffic watch SITE-A-SW01 Gi1/0/16")

        # One name may contain spaces ("gi 1/0/16"); several are comma separated.
        tail = " ".join(rest[1:])
        wanted = [name.strip() for name in tail.split(",") if name.strip()] if "," in tail else [tail.strip()]
        device_ip = str(device.get("ip") or "")
        device_name = clean_display_name(device.get("hostname") or "")

        if opts.dry_run:
            app.emit({"ok": True, "dry_run": True, "device": device_ip, "interfaces": wanted,
                      "interval_seconds": interval}, opts,
                     f"Would monitor {len(wanted)} interface(s) on {device_name or device_ip} every {interval}s: "
                     + ", ".join(wanted))
            return SUCCESS

        # One index walk serves every name in the batch.
        rc, out, err = app.capture(
            app.legacy_cmd("netrune-control", "snmp-index", device_ip), opts.timeout or 60)
        combined = (out or "") + (err or "")
        available = parse_interface_index(combined)
        if not available:
            return usage(_snmp_failure(combined), "netrune traffic interfaces <device>")

        added, existing, missing = [], [], []
        for name in wanted:
            resolved = monitor.match_interface(available, name)
            if not resolved:
                missing.append(name)
                continue
            before = monitor.find_watch("interface", device_ip=device_ip, interface_name=resolved["name"])
            watch = monitor.add_watch(
                "interface", device_ip=device_ip, device_name=device_name,
                interface_name=resolved["name"], interval_seconds=interval, actor=actor,
                ifindex=str(resolved["ifindex"]))
            (existing if before else added).append(watch)

        lines = []
        if added:
            lines.append(f"Watching {len(added)} new interface(s) on {device_name or device_ip} every {interval}s:")
            lines.extend(f"  {w['interface_name']:<16} SNMP index {w['ifindex']}" for w in added)
        if existing:
            lines.append(f"Already watched: " + ", ".join(str(w["interface_name"]) for w in existing))
        if missing:
            seen = ", ".join(row["name"] for row in available[:12])
            lines.append(f"Not found on the device: {', '.join(missing)}. Seen: {seen}")
        # The switch behind a watched port is worth reading for as long as the
        # port is, and only for as long as it is. Deriving that rather than
        # asking for it separately is what keeps the two from drifting apart.
        health = monitor.sync_device_watches(actor)
        if health["added"]:
            lines.append(f"Also collecting switch health for {', '.join(health['added'])}: "
                         f"uptime, CPU, memory, temperature, and rejected management access, "
                         f"every {monitor.device_health_interval()}s.")
        if added:
            lines.append("Collect with 'netrune traffic poll' or run 'netrune traffic daemon'.")
        app.emit({"ok": bool(added or existing), "added": added, "already_watched": existing,
                  "not_found": missing, "device_health": health}, opts, "\n".join(lines))
        if missing and not added:
            return VALIDATION
        return SUCCESS

    def _cmd_ping():
        nonlocal rest
        if not rest:
            return usage("A target address is required.", "netrune traffic ping 198.51.100.10")
        rest, interval_arg = _flag(rest, "--interval")
        interval = int(interval_arg) if str(interval_arg or "").isdigit() else 60
        asked = " ".join(rest).strip()

        # A switch's hostname is a name netrune knows and DNS usually does not,
        # so a watch stored under it can never succeed -- it reports the device
        # as down forever, which is the most misleading thing this tool could
        # say. Resolve it here, and keep the name as the label so the chart
        # still reads the way the operator typed it.
        target, label = asked, asked
        if not _is_address(asked):
            device, _ = app.resolve_device_record(asked)
            if device and device.get("ip"):
                target = str(device["ip"])
                label = clean_display_name(device.get("hostname") or "") or asked
            elif not _resolves_in_dns(asked):
                return usage(
                    f"'{asked}' is not an address, is not a device netrune knows, and does not "
                    "resolve in DNS. A watch on it would report it unreachable forever.",
                    "netrune traffic ping 198.51.100.10")

        if opts.dry_run:
            app.emit({"ok": True, "dry_run": True, "target": target, "label": label}, opts,
                     f"Would monitor ICMP reachability for {label} ({target}).")
            return SUCCESS
        watch = monitor.add_watch("icmp", target=target, label=label,
                                  interval_seconds=interval, actor=actor)
        detail = f"{label} ({target})" if label != target else target
        app.emit({"ok": True, "watch": watch}, opts,
                 f"Watching ICMP reachability for {detail} every "
                 f"{watch.get('interval_seconds')}s.")
        return SUCCESS

    def _cmd_watch_control():
        nonlocal rest
        if not rest:
            return usage(f"A watch id, device, or interface is required.",
                         f"netrune traffic {verb} SITE-A-SW01" + (" 30" if verb == "interval" else ""))
        seconds = 0
        if verb == "interval":
            if len(rest) < 2 or not rest[-1].isdigit():
                return usage("An interval in seconds is required.", "netrune traffic interval Gi1/0/16 30")
            seconds = int(rest[-1])
            rest = rest[:-1]
        needle = " ".join(rest)
        matched = monitor.match_watches(needle)
        if not matched:
            app.emit({"ok": False, "matched": 0, "query": needle}, opts,
                     f"No monitored target matched '{needle}'. Run 'netrune traffic list' to see the watchlist.")
            return VALIDATION
        if verb in {"unwatch", "remove"} and len(matched) > 1 and not opts.confirm:
            listing = "\n".join(f"  {w['watch_id']}  {_label(w)}" for w in matched)
            app.emit({"ok": False, "matched": len(matched), "watches": matched, "requires_confirm": True}, opts,
                     f"'{needle}' matches {len(matched)} targets and removing them discards their samples:\n"
                     f"{listing}\nRe-run with --confirm to remove all of them.")
            return VALIDATION

        changed = []
        for watch in matched:
            watch_id = str(watch["watch_id"])
            if verb == "pause":
                monitor.set_enabled(watch_id, False)
            elif verb == "resume":
                monitor.set_enabled(watch_id, True)
            elif verb == "interval":
                monitor.set_interval(watch_id, seconds)
            else:
                monitor.remove_watch(watch_id)
            changed.append(watch)

        verbs = {"pause": "Paused", "resume": "Resumed", "interval": "Re-timed",
                 "unwatch": "Stopped monitoring", "remove": "Stopped monitoring"}
        detail = f" to every {seconds}s" if verb == "interval" else ""
        lines = [f"{verbs[verb]} {len(changed)} target(s){detail}:"]
        lines.extend(f"  {_label(w)}" for w in changed)
        health = {"added": [], "removed": []}
        if verb in {"unwatch", "remove"}:
            # A switch nobody watches a port on stops being collected. Its
            # history stays until retention removes it, so the graphs of what
            # happened while it was watched do not lose their context.
            health = monitor.sync_device_watches(actor)
            if health["removed"]:
                lines.append(f"Stopped collecting switch health for {', '.join(health['removed'])}: "
                             "no watched ports remain on it.")
        if running_collector(app) and verb != "interval":
            lines.append("The running collector picks this up on its next tick.")
        app.emit({"ok": True, "action": verb, "changed": changed, "count": len(changed),
                  "device_health": health}, opts, "\n".join(lines))
        return SUCCESS

    def _cmd_name():
        nonlocal rest
        if not rest:
            return usage("A target and a name are required.",
                         'netrune traffic name Gi1/0/16 "Warehouse uplink" --color teal')
        rest, _ = _flag(rest, "--name")
        rest, color_arg = _flag(rest, "--color")
        if color_arg is None:
            rest, color_arg = _flag(rest, "--colour")
        # `traffic color <target> <colour>` is the same operation with the
        # colour where the name would be.
        if verb in {"color", "colour"} and color_arg is None and len(rest) >= 2:
            color_arg = rest[-1]
            rest = rest[:-1]
        color = None
        if color_arg is not None:
            color = resolve_color(color_arg)
            if color is None:
                names = ", ".join(sorted(SERIES_COLORS))
                return usage(
                    f"'{color_arg}' is not a colour. Use one of {names}, or an explicit "
                    "#rrggbb. Those four were checked together for separation, lightness, "
                    "and colour-blind readability; a fifth of your own is not.",
                    "netrune traffic name Gi1/0/12 AFRIX --color teal")
        clearing = "--clear" in rest
        rest = [item for item in rest if item != "--clear"]
        naming = clearing or len(rest) >= 2
        if not naming and color is None:
            return usage("A name is required. Use --clear to remove one, or --color on its own "
                         "to recolour without renaming.",
                         'netrune traffic name Gi1/0/16 "Warehouse uplink" --color teal')
        # The name is everything after the target, so it needs no quoting to
        # contain spaces -- which every name worth giving does.
        needle, chosen = (rest[0], "") if clearing else (rest[0], " ".join(rest[1:]))
        matched = monitor.match_watches(needle)
        if not matched:
            app.emit({"ok": False, "matched": 0, "query": needle}, opts,
                     f"No monitored target matched '{needle}'. Run 'netrune traffic list'.")
            return VALIDATION
        if len(matched) > 1 and not opts.confirm:
            listing = "\n".join(f"  {w['watch_id']}  {_label(w)}" for w in matched)
            app.emit({"ok": False, "matched": len(matched), "watches": matched,
                      "requires_confirm": True}, opts,
                     f"'{needle}' matches {len(matched)} targets, and one name for several ports "
                     f"would make them indistinguishable:\n{listing}\n"
                     "Use the watch id from the left column to name exactly one, or re-run with "
                     "--confirm to give them all this name.")
            return VALIDATION
        for watch in matched:
            if naming:
                monitor.set_display_name(str(watch["watch_id"]), chosen)
            if color is not None or clearing:
                monitor.set_display_color(str(watch["watch_id"]), "" if clearing else color)
        renamed = [monitor.get_watch(str(w["watch_id"])) or {} for w in matched]
        if clearing:
            lines = [f"Cleared the name on {len(renamed)} target(s). They show as the device "
                     "calls them again:"]
        elif naming:
            lines = [f"Named {len(renamed)} target(s):"]
        else:
            lines = [f"Recoloured {len(renamed)} target(s):"]
        lines += [f"  {_label(w)}  ->  {monitor.display_name(w)}"
                  + (f"  {w.get('display_color')}" if w.get("display_color") else "")
                  for w in renamed]
        if color is not None:
            lines.append("Regenerate the dashboards to apply it: "
                         "'netrune traffic stack init'.")
        lines.append("Dashboards pick this up on their next refresh; history is unaffected, "
                     "because the name is not part of a series' identity.")
        app.emit({"ok": True, "renamed": renamed, "name": chosen}, opts, "\n".join(lines))
        return SUCCESS

    def _cmd_subscribe():
        nonlocal rest
        rest, down_arg = _flag(rest, "--down")
        rest, up_arg = _flag(rest, "--up")
        rest, facing_arg = _flag(rest, "--facing")
        clearing = "--clear" in rest
        rest = [item for item in rest if item != "--clear"]
        if not rest:
            return usage("A target is required.",
                         "netrune traffic subscribe Gi1/0/12 --down 100M --up 20M")
        if not clearing and down_arg is None and up_arg is None:
            return usage("Give --down, --up, or both. Use --clear to remove a subscription.",
                         "netrune traffic subscribe Gi1/0/12 --down 100M --up 20M")
        facing = str(facing_arg or "isp").strip().lower()
        if facing not in {"isp", "lan"}:
            return usage("--facing takes 'isp' (the port reaching the provider) or 'lan'.",
                         "netrune traffic subscribe Gi1/0/12 --down 100M --facing isp")
        down = up = None
        if not clearing:
            for label, raw in (("--down", down_arg), ("--up", up_arg)):
                if raw is None:
                    continue
                parsed = parse_rate(raw)
                if parsed is None:
                    return usage(f"'{raw}' is not a rate. Write it as 100M, 20 Mbps, or 1.5G.",
                                 "netrune traffic subscribe Gi1/0/12 --down 100M --up 20M")
                if label == "--down":
                    down = parsed
                else:
                    up = parsed

        needle = " ".join(rest)
        matched = [w for w in monitor.match_watches(needle) if w.get("kind") == "interface"]
        if not matched:
            app.emit({"ok": False, "matched": 0, "query": needle}, opts,
                     f"No monitored interface matched '{needle}'. Run 'netrune traffic list'.")
            return VALIDATION
        if len(matched) > 1 and not opts.confirm:
            listing = "\n".join(f"  {w['watch_id']}  {_label(w)}" for w in matched)
            app.emit({"ok": False, "matched": len(matched), "watches": matched,
                      "requires_confirm": True}, opts,
                     f"'{needle}' matches {len(matched)} ports, and a subscription belongs to "
                     f"one link:\n{listing}\n"
                     "Name the switch and the port together, or use the watch id from the left "
                     "column -- that is exactly one target however many switches share a port "
                     "name.")
            return VALIDATION
        for watch in matched:
            monitor.set_subscription(str(watch["watch_id"]), down, up,
                                     faces_lan=None if clearing else (facing == "lan"))
        updated = [monitor.get_watch(str(w["watch_id"])) or {} for w in matched]
        if clearing:
            lines = [f"Cleared the subscription on {len(updated)} link(s). They are drawn against "
                     "the port's line rate again."]
        else:
            lines = [f"Recorded the subscription on {len(updated)} link(s):"]
            for watch in updated:
                plan = monitor.subscription(watch)
                lines.append(
                    f"  {_label(watch)}"
                    f"  down {humanize_bps(plan.get('down_bps')) if plan.get('down_bps') else '-'}"
                    f"  up {humanize_bps(plan.get('up_bps')) if plan.get('up_bps') else '-'}"
                    f"  ({'facing the LAN' if plan.get('faces_lan') else 'facing the provider'})")
            lines.append("These are soft limits: nothing is enforced, and they are what the WAN "
                         "bars on the overview are drawn against.")
        app.emit({"ok": True, "links": updated}, opts, "\n".join(lines))
        return SUCCESS

    def _cmd_push():
        nonlocal rest
        from netops_platform.traffic_metrics import MetricsExporter
        from netops_platform.traffic_stack import DEFAULT_VM_URL
        import urllib.error
        import urllib.request

        rest, to_arg = _flag(rest, "--to")
        target = (to_arg or app.config.public.get("traffic_push_url") or "").rstrip("/")
        if not target:
            return usage("Where to? A storage URL is required.",
                         "netrune traffic push --to http://198.51.100.5:8428")
        target, push_auth_header = _split_push_credentials(target)
        # Where a previous push got to, so a collector that was cut off sends
        # what the other end missed rather than only what is true now. Sending
        # only the present would leave the outage as a hole in the graph, which
        # is the one thing a poller running through it should prevent.
        marker = f"push:{target}"
        window = resolve_window()
        if window is None:
            return usage(f"'{opts.since}' is not a window. Use seconds or 15m, 6h, 2d.",
                         "netrune traffic push --to http://198.51.100.5:8428 --since 24h")
        last = int(app.state.get_marker(marker) or 0) if hasattr(app.state, "get_marker") else 0
        if opts.since:
            since = int(time.time()) - window
        elif last:
            since = last
        else:
            since = 0
        now_at = int(time.time())

        exporter = MetricsExporter(monitor)
        body = exporter.render_replay(since, now_at) if since else exporter.render()
        replaying = bool(since)
        if not body.strip():
            # Nothing new since the last push is the normal steady state once
            # the timer is running, not a problem.
            body = exporter.render()
            replaying = False
        families = len([line for line in body.splitlines() if line.startswith("# TYPE ")])
        series = len([line for line in body.splitlines()
                      if line and not line.startswith("#")])
        if not series:
            app.emit({"ok": False, "series": 0}, opts,
                     "Nothing collected yet, so there is nothing to send.")
            return PARTIAL
        # The same labels storage attaches when it scrapes. Without them the
        # pushed readings become a second series for every port, identical
        # except for scrape plumbing -- and a vector match on the labels that
        # identify a port then finds two candidates and refuses, which takes
        # every chart on the board out at once.
        from netops_platform.traffic_stack import SCRAPE_INSTANCE, SCRAPE_JOB, SCRAPE_SOURCE
        stamps = urllib.parse.urlencode(
            [("extra_label", f"job={SCRAPE_JOB}"),
             ("extra_label", f"instance={SCRAPE_INSTANCE}"),
             ("extra_label", f"source={SCRAPE_SOURCE}")])
        url = f"{target}/api/v1/import/prometheus?{stamps}"
        if opts.dry_run:
            app.emit({"ok": True, "dry_run": True, "url": url, "series": series}, opts,
                     f"Would send {series} series in {families} families to {url}.")
            return SUCCESS
        headers = {"Content-Type": "text/plain; charset=utf-8"}
        if push_auth_header:
            headers["Authorization"] = push_auth_header
        request = urllib.request.Request(
            url, data=body.encode("utf-8"), method="POST", headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=min(int(opts.timeout or 30), 300)) as response:
                status = response.status
        except urllib.error.HTTPError as exc:
            app.emit({"ok": False, "url": url, "status": exc.code}, opts,
                     f"Storage refused the readings: HTTP {exc.code} from {url}. "
                     f"{exc.read().decode('utf-8', 'replace')[:200]}")
            return PARTIAL
        except (urllib.error.URLError, OSError) as exc:
            app.emit({"ok": False, "url": url, "error": str(exc)}, opts,
                     f"Could not reach {url}. {exc}\n"
                     "Storage binds to loopback unless told otherwise; the machine running it "
                     "needs 'netrune setup local --accept-push --confirm'.")
            return PARTIAL
        if hasattr(app.state, "set_marker"):
            app.state.set_marker(marker, str(now_at))
        gap = ""
        if replaying and since:
            minutes = max(1, (now_at - since) // 60)
            gap = (f"\nThese carry the time each reading was taken, covering the "
                   f"{minutes} minute(s) since the last successful push -- so an outage at "
                   "the far end is drawn as the traffic that happened, not as a hole.")
        app.emit({"ok": True, "url": url, "series": series, "families": families,
                  "status": status, "replayed_since": since if replaying else 0}, opts,
                 f"Sent {series} reading(s) in {families} families to {url}." + gap
                 + "\nThey carry this collector's id, so they stay distinguishable from the "
                 "receiving machine's own readings and every dashboard reads them unchanged.")
        return SUCCESS

    def _cmd_dashboard():
        nonlocal rest
        from netops_platform.traffic_dashboards import all_dashboards
        from netops_platform.traffic_graphers import get_grapher
        rest, port_arg = _flag(rest, "--port")
        opening = "--open" in rest
        grapher = get_grapher(app.config.public.get("traffic_grapher") or "grafana")
        if grapher is None:
            return usage("No grapher is configured.", "netrune traffic stack graphers")
        port = int(port_arg) if str(port_arg or "").isdigit() else grapher.default_port
        base = f"http://127.0.0.1:{port}"

        unit = f"netrune-{grapher.name}.service"
        rc, unit_output = _run(["systemctl", "--user", "is-active", unit], timeout=20)
        running = "" if any(m in unit_output for m in _NO_USER_BUS) else unit_output.strip()
        answering = _http_ok(base + grapher.health_path())

        action = rest[0] if rest and not rest[0].startswith("-") else ""
        if action in {"save", "keep", "revert", "regenerate"}:
            return _dashboard_keep(app, opts, action, rest[1:], grapher, base, usage)

        boards = [{"dashboard": d.title.split("/")[-1].strip(),
                   "url": grapher.dashboard_url(base, d)}
                  for d in all_dashboards(monitor.series_colors(), monitor.service_links())]
        lines = [f"{grapher.display_name} is "
                 + ("answering" if answering else f"not answering") + f" at {base}"
                 + (f"  (unit {unit}: {running})" if running else "")]
        if not answering:
            # The reasons it is not up read identically from a browser and lead
            # somewhere quite different.
            lines.append("")
            problem = user_manager_problem()
            if problem:
                lines.append(problem)
            elif running == "active":
                lines.append("The unit is running but the port is not answering yet; give it a "
                             f"few seconds, or read 'journalctl --user -u {unit}'.")
            else:
                lines.append("Start it with:   netrune traffic stack up")
        lines.append("")
        lines += [f"  {b['dashboard']:<14} {b['url']}" for b in boards]
        if opening and answering:
            overview = next((b for b in boards if "Overview" in b["dashboard"]), boards[0])
            with contextlib.suppress(Exception):
                subprocess.Popen(["xdg-open", overview["url"]],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            lines.append("")
            lines.append(f"Opening {overview['url']}")
        app.emit({"ok": bool(answering), "grapher": grapher.name, "url": base,
                  "unit": unit, "unit_state": running, "answering": bool(answering),
                  "dashboards": boards}, opts, "\n".join(lines))
        return SUCCESS if answering else PARTIAL

    def _cmd_health():
        nonlocal rest
        wanted = ""
        if rest:
            device, choices = app.resolve_device_record(" ".join(rest))
            if not device:
                labels = ", ".join(str(row.get("hostname") or row.get("ip")) for row in choices[:8])
                return usage(f"'{' '.join(rest)}' did not resolve to one device."
                             + (f" Candidates: {labels}" if labels else ""),
                             "netrune inventory list <target>")
            wanted = str(device.get("ip") or "")
        watches = [w for w in monitor.list_watches()
                   if w.get("kind") == "device" and (not wanted or w.get("device_ip") == wanted)]
        if not watches:
            app.emit({"ok": False, "rows": []}, opts,
                     "No switch health is being collected. It is added automatically when you "
                     "watch an interface: 'netrune traffic watch SITE-A-SW01 Gi1/0/16'.")
            return PARTIAL
        window = resolve_window() or 21600
        rows = []
        for watch in watches:
            row = {"switch": watch.get("device_name") or watch.get("device_ip"),
                   "address": watch.get("device_ip"),
                   "state": "active" if watch.get("enabled") else "paused"}
            for metric, column, render in (
                ("uptime_seconds", "uptime", lambda v: _duration(v)),
                ("cpu_percent", "cpu", lambda v: f"{v:.0f}%"),
                ("memory_percent", "memory", lambda v: f"{v:.0f}%"),
                ("temperature_celsius", "temp", lambda v: f"{v:.0f}C"),
                ("logged_in_users", "sessions", lambda v: f"{v:.0f}"),
            ):
                summary = monitor.summarize(str(watch["watch_id"]), metric, window)
                row[column] = render(summary["latest"]) if summary["latest"] is not None else "-"
            row["cpu_trend"] = monitor.summarize(
                str(watch["watch_id"]), "cpu_percent", window)["spark"]
            rows.append(row)
        notes = ["Collected automatically for every switch with a watched port.",
                 "A dash means the switch does not answer that OID over SNMP; nothing is wrong.",
                 "Failed SSH logins are not in any standard MIB -- read the switch's syslog for those."]
        app.emit({"ok": True, "rows": rows, "count": len(rows)}, opts,
                 app.render_table(rows, ["switch", "address", "state", "uptime", "cpu", "memory",
                                         "temp", "sessions", "cpu_trend"])
                 + "\n\n" + "\n".join(notes))
        return SUCCESS

    def _cmd_interfaces():
        nonlocal rest
        if not rest:
            return usage("A device is required.", "netrune traffic interfaces SITE-A-SW01")
        device, _ = app.resolve_device_record(rest[0])
        if not device:
            return usage(f"'{rest[0]}' did not resolve to one device.", "netrune inventory list <target>")
        rc, out, err = app.capture(
            app.legacy_cmd("netrune-control", "snmp-index", str(device.get("ip") or "")), opts.timeout or 60)
        combined = (out or "") + (err or "")
        rows = parse_interface_index(combined)
        watched = {
            str(w.get("interface_name") or "").lower()
            for w in monitor.list_watches() if w.get("device_ip") == device.get("ip")
        }
        for row in rows:
            row["watched"] = "yes" if row["name"].lower() in watched else ""
        app.emit({"ok": bool(rows), "rows": rows, "count": len(rows)}, opts,
                 app.render_table(rows, ["ifindex", "name", "alias", "watched"]) if rows
                 else _snmp_failure(combined))
        return SUCCESS if rows else PARTIAL

    # ---- collection --------------------------------------------------------

    def _cmd_poll():
        nonlocal rest
        # Device-health watches are derived from the interface watchlist, so the
        # collector reconciles them before collecting rather than trusting that
        # whatever last edited the list remembered to. It also means an install
        # that predates switch health picks it up on its next round.
        monitor.sync_device_watches(actor)
        payload = monitor.poll(opts=opts)
        lines = [f"Collected {payload['samples_recorded']} sample(s) from {payload['watches']} "
                 f"watch(es) as '{payload['collector']}'."]
        for failure in payload["errors"][:5]:
            lines.append(f"  {failure.get('device') or failure.get('target')}: {failure['error']}")
        app.emit(payload, opts, "\n".join(lines))
        return SUCCESS if payload["ok"] else PARTIAL

    def _cmd_daemon():
        nonlocal rest
        rest, interval_arg = _flag(rest, "--interval")
        override = 0
        if interval_arg is not None:
            if not str(interval_arg).isdigit():
                return usage("--interval requires seconds.", "netrune traffic daemon --interval 30")
            override = max(10, min(int(interval_arg), 3600))
        # Same reconciliation the one-shot poll does. The daemon is the thing
        # that runs for weeks, so it is the one that most needs its derived
        # watchlist current rather than as it was when it started.
        monitor.sync_device_watches(actor)
        running = running_collector(app)
        if running:
            return usage(f"A collector is already running as pid {running.get('pid')} "
                         f"(collector '{running.get('collector')}').", "netrune traffic status")
        if not monitor.list_watches(enabled_only=True):
            return usage("Nothing is being monitored yet.", "netrune traffic watch <device> <interface>")
        return _run_daemon(app, monitor, opts, override)

    def _cmd_status():
        nonlocal rest
        running = running_collector(app)
        watches = monitor.list_watches()
        now = int(time.time())
        rows = []
        for watch in watches:
            metric = "out_bps" if watch["kind"] == "interface" else "rtt_ms"
            summary = monitor.summarize(str(watch["watch_id"]), metric, 86400)
            last = summary.get("last_at")
            interval = int(watch.get("interval_seconds") or 60)
            age = now - int(last) if last else None
            rows.append({
                "target": _label(watch),
                "state": "active" if watch.get("enabled") else "paused",
                "every": f"{interval}s",
                "last_sample": f"{age}s ago" if age is not None else "never",
                "next_poll": _next_poll(watch, age, interval, bool(running)),
                "health": _health(watch, age, interval),
            })
        header = (f"Collector '{running.get('collector')}' running as pid {running.get('pid')} since "
                  f"{time.strftime('%H:%M:%S', time.localtime(int(running.get('started_at') or now)))}."
                  if running else
                  "No collector is running. Start one with 'netrune traffic daemon', or collect once with "
                  "'netrune traffic poll'.")
        app.emit({"ok": True, "collector": running, "running": bool(running), "rows": rows}, opts,
                 header + ("\n\n" + app.render_table(rows, ["target", "state", "every", "last_sample", "next_poll", "health"])
                           if rows else "\n\nNothing is being monitored yet."))
        return SUCCESS

    # ---- reading -----------------------------------------------------------

    def _cmd_show():
        nonlocal rest
        window = resolve_window()
        if window is None:
            return usage(f"'{opts.since}' is not a window. Use seconds or 15m, 6h, 2d.",
                         "netrune traffic show --since 6h")
        watches = monitor.match_watches(" ".join(rest)) if rest else monitor.list_watches()
        if not watches:
            app.emit({"ok": False, "rows": []}, opts, "No monitored target matched.")
            return PARTIAL
        blocks: List[str] = []
        payload_rows: List[Dict[str, Any]] = []
        for watch in watches:
            metrics = (("in_bps", "out_bps") if watch["kind"] == "interface"
                       else ("rtt_ms", "packet_loss_pct"))
            block = [f"{_label(watch)}  [{watch['watch_id']}]"
                     + ("" if watch.get("enabled") else "  (paused)")]
            for metric in metrics:
                summary = monitor.summarize(str(watch["watch_id"]), metric, window)
                payload_rows.append({"watch_id": watch["watch_id"], "metric": metric, **summary})
                if not summary["samples"]:
                    block.append(f"  {metric:<18} no samples yet")
                    continue
                render = humanize_bps if metric.endswith("_bps") else (lambda v: f"{v:.1f}")
                block.append(f"  {metric:<18} {summary['spark']}  now {render(summary['latest'])}"
                             f"  peak {render(summary['peak'])}")
            blocks.append("\n".join(block))
        app.emit({"ok": True, "window_seconds": window, "series": payload_rows}, opts, "\n\n".join(blocks))
        return SUCCESS

    def _cmd_report():
        nonlocal rest
        from netops_platform.traffic_report import render_report
        window = resolve_window()
        if window is None:
            return usage(f"'{opts.since}' is not a window. Use seconds or 15m, 6h, 2d.",
                         "netrune traffic report --since 6h")
        rest, out_arg = _flag(rest, "--out")
        if out_arg == "":
            return usage("--out requires a file path.", "netrune traffic report --out ~/traffic.html")
        watches = monitor.match_watches(" ".join(rest)) if rest else monitor.list_watches()
        cards: List[Dict[str, Any]] = []
        for watch in watches:
            metrics = (("in_bps", "out_bps", "in_utilization_pct", "out_utilization_pct")
                       if watch["kind"] == "interface" else ("rtt_ms", "jitter_ms", "packet_loss_pct"))
            readings = {m: monitor.summarize(str(watch["watch_id"]), m, window) for m in metrics}
            series = {m: monitor.series(str(watch["watch_id"]), m, window) for m in metrics}
            speed = 0
            for row in series.get("in_bps", []) or series.get("out_bps", []):
                speed = int(json.loads(row.get("raw_json") or "{}").get("speed_bps") or 0) or speed
            cards.append({"watch": watch, "readings": readings, "series": series, "speed_bps": speed,
                          "collectors": sorted({c for r in readings.values() for c in r.get("collectors", [])})})
        payload = {"window_seconds": window, "generated_at": int(time.time()),
                   "collector": monitor.collector_id(), "cards": cards}
        path = (Path(os.path.expanduser(out_arg)) if out_arg
                else Path(app.paths.state_dir) / "reports" / f"traffic-{int(time.time())}.html")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(render_report(payload), encoding="utf-8")
        os.chmod(path, 0o600)
        app.emit({"ok": True, "path": str(path), "targets": len(cards), "window_seconds": window}, opts,
                 f"Wrote a traffic report for {len(cards)} target(s) covering the last "
                 f"{window // 60} minute(s):\n{path}")
        return SUCCESS

    # ---- metrics stack -----------------------------------------------------

    def _cmd_exporter():
        nonlocal rest
        from netops_platform.traffic_exporter import is_loopback, serve_forever, split_bind
        rest, bind_arg = _flag(rest, "--bind")
        once = "--once" in rest
        try:
            host, port = split_bind(bind_arg or "127.0.0.1:9713")
        except ValueError as exc:
            return usage(str(exc), "netrune traffic exporter --bind 127.0.0.1:9713")
        if once:
            from netops_platform.traffic_metrics import MetricsExporter
            body = MetricsExporter(monitor).render()
            print(body, end="")
            return SUCCESS
        if not is_loopback(host) and not opts.confirm:
            from netops_platform.traffic_exporter import is_tailnet
            reach = ("Anyone on the same tailnet can read it." if is_tailnet(host)
                     else "Anyone who can reach that address can read it.")
            return usage(
                f"'{host}' is not a loopback address. The exposition has no authentication of its own, "
                f"so binding it there publishes your topology. {reach} Re-run with --confirm if that "
                "is the intent.",
                "netrune traffic exporter --bind 127.0.0.1:9713")
        try:
            server = serve_forever(monitor, host, port, logger=None)
        except OSError as exc:
            return usage(f"Could not bind {host}:{port}: {exc}", "netrune traffic exporter --bind 127.0.0.1:9714")
        actual = server.server_address[1]
        _stop_on_sigterm()
        eprint(f"Exposition on http://{host}:{actual}/metrics for VictoriaMetrics to scrape. Ctrl+C stops it.")
        eprint("This publishes readings the collector already took. It talks to no device and runs no command.")
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            server.shutdown()
            eprint("Exposition stopped.")
            return SUCCESS

    def _cmd_backfill():
        nonlocal rest
        from netops_platform.traffic_metrics import escape_label
        rest, url_arg = _flag(rest, "--url")
        window = resolve_window()
        if window is None:
            return usage(f"'{opts.since}' is not a window. Use seconds or 15m, 6h, 2d.",
                         "netrune traffic backfill --since 30d")
        window = window if opts.since else 30 * 86400
        target = (url_arg or app.config.public.get("traffic_victoriametrics_url")
                  or "http://127.0.0.1:8428").rstrip("/")
        lines = _backfill_body(monitor, window, escape_label)
        if not lines:
            app.emit({"ok": False, "samples": 0}, opts,
                     "No stored history in that window, so there is nothing to import.")
            return PARTIAL
        if opts.dry_run:
            app.emit({"ok": True, "dry_run": True, "samples": len(lines), "url": target}, opts,
                     f"Would import {len(lines)} historical sample(s) into {target}.\n"
                     + "\n".join(lines[:5]) + ("\n..." if len(lines) > 5 else ""))
            return SUCCESS
        import urllib.error
        import urllib.request
        body = ("\n".join(lines) + "\n").encode("utf-8")
        request = urllib.request.Request(
            f"{target}/api/v1/import/prometheus", data=body,
            headers={"Content-Type": "text/plain"}, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=min(int(opts.timeout or 60), 300)) as response:
                code = response.status
        except urllib.error.URLError as exc:
            return usage(f"Could not reach VictoriaMetrics at {target}: {exc}",
                         "netrune traffic backfill --url http://127.0.0.1:8428")
        # Query results are cached per time range, and a range that was already
        # queried before the import keeps returning its old empty answer. Only
        # backfilled data hits this, because only backfilled data lands behind
        # ranges that have already been asked about.
        cache_reset = True
        try:
            urllib.request.urlopen(
                urllib.request.Request(f"{target}/internal/resetRollupResultCache", method="POST"),
                timeout=30).close()
        except urllib.error.URLError:
            cache_reset = False
        note = ("" if cache_reset else
                "\nThe rollup result cache could not be reset, so a range you already queried may keep "
                f"returning its old answer. POST {target}/internal/resetRollupResultCache to clear it.")
        app.emit({"ok": True, "samples": len(lines), "url": target, "status": code,
                  "cache_reset": cache_reset}, opts,
                 f"Imported {len(lines)} historical sample(s) into {target}.\n"
                 "These are the rates Netrune computed before the stack existed, published as gauges "
                 "named netrune_history_*. Live series use raw counters and are named differently on "
                 "purpose, so a derived value is never mistaken for a measured one.\n"
                 "Imported points are older than an instant query looks back, so query them over a "
                 "range rather than at a moment." + note)
        return SUCCESS

    def _cmd_stack():
        nonlocal rest
        from netops_platform.traffic_graphers import get_grapher, grapher_names
        from netops_platform.traffic_stack import (
            DEFAULT_EXPORTER_BIND, DEFAULT_VM_URL, ROLE_COLLECTOR, ROLE_FULL, ROLES,
            stack_files)
        action = rest[0] if rest else "init"
        rest = rest[1:]
        if action == "graphers":
            from netops_platform.traffic_graphers import GRAPHERS
            selected = app.config.public.get("traffic_grapher") or "grafana"
            rows = [{"grapher": g.name, "name": g.display_name,
                     "deployment": g.image or "built into VictoriaMetrics",
                     "port": g.default_port, "selected": "yes" if g.name == selected else ""}
                    for g in sorted(GRAPHERS.values(), key=lambda g: g.name)]
            app.emit({"ok": True, "rows": rows, "selected": selected}, opts,
                     app.render_table(rows, ["grapher", "name", "deployment", "port", "selected"])
                     + "\n\nSelect one with 'netrune traffic stack init --grapher <name>', or set it "
                       "for good with 'netrune config set traffic_grapher <name>'.\n"
                       "Every grapher reads the same VictoriaMetrics; only the dashboard files differ.")
            return SUCCESS
        if action in {"up", "down", "restart", "status", "install"}:
            return _stack_service(app, opts, action, usage)
        if action not in {"init", "show"}:
            return usage(f"Unknown stack action '{action}'.", "netrune traffic stack init")
        rest, dir_arg = _flag(rest, "--dir")
        rest, url_arg = _flag(rest, "--url")
        rest, bind_arg = _flag(rest, "--bind")
        rest, retention_arg = _flag(rest, "--retention")
        rest, interval_arg = _flag(rest, "--scrape-interval")
        rest, unit_arg = _flag(rest, "--unit-dir")
        rest, grapher_arg = _flag(rest, "--grapher")
        rest, port_arg = _flag(rest, "--grapher-port")
        rest, role_arg = _flag(rest, "--role")
        rest, publish_arg = _flag(rest, "--publish")
        accept_push = "--accept-push" in rest
        rest = [item for item in rest if item != "--accept-push"]
        if publish_arg:
            # One flag for "serve this beyond loopback", because splitting it
            # per component invites getting half of it right.
            bind_arg = f"{publish_arg}:{(bind_arg or DEFAULT_EXPORTER_BIND).rsplit(':', 1)[-1]}"
        role = str(role_arg or ROLE_FULL).strip().lower()
        if role not in ROLES:
            return usage(f"Unknown role '{role}'. Choose from {', '.join(ROLES)}.",
                         "netrune traffic stack init --role collector")
        grapher_name = (grapher_arg or app.config.public.get("traffic_grapher") or "grafana")
        if get_grapher(grapher_name) is None:
            return usage(f"Unknown grapher '{grapher_name}'. Available: {', '.join(grapher_names())}.",
                         "netrune traffic stack graphers")
        grapher_port = int(port_arg) if str(port_arg or "").isdigit() else 0
        root = Path(os.path.expanduser(dir_arg)) if dir_arg else Path(app.paths.state_dir) / "metrics-stack"
        bind = bind_arg or DEFAULT_EXPORTER_BIND
        from netops_platform.traffic_exporter import is_loopback, is_tailnet, split_bind
        try:
            bind_host, _ = split_bind(bind)
        except ValueError as exc:
            return usage(str(exc), "netrune traffic stack init --bind 127.0.0.1:9713")
        # `netrune setup` enforces this same rule at its own level (and
        # hardcodes --confirm onto the stack_args it forwards here when it
        # does), so it never reaches this check. If a new way to expose data
        # beyond loopback is added here, mirror it in cmd_setup too.
        if accept_push and not opts.confirm:
            return usage(
                "--accept-push lets anything that can reach this machine write readings into "
                "its store. Publishing dashboards is read-only; this is not, so confirm it.",
                "netrune traffic stack init --accept-push --confirm")
        if role == ROLE_COLLECTOR:
            # A collector generates no exposition, so there is nothing to
            # publish and nothing to consent to.
            bind_host = "127.0.0.1"
        if not is_loopback(bind_host) and not opts.confirm:
            reach = ("Anyone on the same tailnet could read it." if is_tailnet(bind_host)
                     else "Anyone who can reach that address could read it.")
            return usage(
                f"--bind {bind} would generate a service that publishes the exposition beyond this "
                f"host. {reach} A service cannot be asked to confirm at start time, so confirm here.",
                f"netrune traffic stack init --bind {bind} --confirm")
        url = (url_arg or DEFAULT_VM_URL).rstrip("/")
        retention = retention_arg or "90d"
        scrape = int(interval_arg) if str(interval_arg or "").isdigit() else _suggested_scrape(monitor)
        binaries = {name: shutil.which(name) or name
                    for name in ("netrune", "victoria-metrics", "vmalert")}
        # Only a real path counts as "installed"; the fallbacks above are names.
        for name in ("grafana", "grafana-server"):
            found = shutil.which(name)
            if found:
                binaries[name] = found
        rest, native_arg = _flag(rest, "--grapher-deploy")
        grapher_native = str(native_arg or "auto").lower() != "container"
        unit_dir = Path(os.path.expanduser(unit_arg)) if unit_arg else None
        # A poller hands its readings over on a timer: pushed straight into
        # storage where there is a path to it, written to a file where there is
        # not. Neither is generated unless configured.
        #
        # Publishing dashboards is read-only exposure. Accepting a push means
        # anything that can reach the address can write readings into the
        # store, so it is a separate thing to ask for.
        storage_bind = f"{publish_arg or '0.0.0.0'}:{url.rsplit(':', 1)[-1]}" if accept_push else ""
        files = stack_files(bind, url, scrape, retention, root, role=role,
                            export_path=str(app.config.public.get("traffic_export_path") or ""),
                            push_url=str(app.config.public.get("traffic_push_url") or ""),
                            series_colors=monitor.series_colors(),
                            links=monitor.service_links(),
                            org=str(app.config.public.get("traffic_grafana_org") or ""),
                            grapher_bind=publish_arg or "",
                            storage_bind=storage_bind,
                            grapher_name=grapher_name, grapher_port=grapher_port,
                            unit_dir=unit_dir, binaries=binaries,
                            grapher_native=grapher_native,
                            confirmed_bind=not is_loopback(bind_host))
        if action == "show":
            app.emit({"ok": True, "files": {str(k): v for k, v in files.items()}}, opts,
                     "\n\n".join(f"# {path}\n{body}" for path, body in files.items()))
            return SUCCESS
        from netops_platform.traffic_stack import VM_CREDENTIAL_FILE, VM_CREDENTIAL_USER
        credential_path = root / VM_CREDENTIAL_FILE
        for path, body in files.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(body, encoding="utf-8")
            if path == credential_path:
                path.chmod(0o600)
        # Switching graphers leaves the previous one's unit behind, and a unit
        # left on disk is a service something later starts. Only what this stack
        # generates stays.
        generated = {path.name for path in files}
        retired = [path for path in (root / "systemd").glob("netrune-*.service")
                   if path.name not in generated] if (root / "systemd").is_dir() else []
        for path in retired:
            path.unlink()
        listing = "\n".join(f"  {path}" for path in sorted(files))
        # A tile averages over a minute. A link polled more slowly than that
        # leaves the counter flat for several scrapes and then jumps, and the
        # tile reads the jump as one interval's traffic -- six times the real
        # number on a link polled every minute. The line-rate bound in the
        # queries keeps it from rendering something impossible, but the honest
        # fix is to poll the link at least as often as the window needs.
        from netops_platform.traffic_dashboards import TILE_RATE_WINDOW
        needed = max(10, (window_seconds(TILE_RATE_WINDOW) or 60) // 4)
        slow = [w for w in monitor.subscribed_watches()
                if int(w.get("interval_seconds") or 60) > needed]
        if slow:
            names = ", ".join(f"{monitor.display_name(w)} ({w['interval_seconds']}s)" for w in slow)
            eprint(f"Warning: {len(slow)} service link(s) are polled more slowly than the "
                   f"overview tiles average over, so their tiles will lag and can overstate: "
                   f"{names}. Poll them at {needed}s or faster: "
                   f"'netrune traffic interval <link> {needed}'.")
        if role == ROLE_COLLECTOR:
            app.emit({"ok": True, "root": str(root), "role": role,
                      "files": [str(p) for p in sorted(files)]}, opts,
                     f"Wrote the collector stack to {root}:\n{listing}\n\n"
                     "This machine collects and nothing else: no exposition, no storage, no "
                     "dashboards. Whatever pulls from it keeps the readings.\n"
                     "Install and start it with 'netrune traffic stack up'.")
            return SUCCESS
        (root / "storage").mkdir(parents=True, exist_ok=True)
        grapher = get_grapher(grapher_name)
        port = grapher_port or grapher.default_port
        push_note = ""
        if accept_push:
            token = files.get(credential_path, "")
            push_note = (
                f"\nAccepting pushes on {storage_bind}, gated by the token in "
                f"{credential_path} (mode 0600). Give the remote poller:\n"
                f"  netrune config set traffic_push_url http://{VM_CREDENTIAL_USER}:{token}@{storage_bind}\n")
        app.emit({"ok": True, "root": str(root), "files": [str(p) for p in sorted(files)],
                  "scrape_interval": scrape, "grapher": grapher_name}, opts,
                 f"Wrote the metrics stack to {root}:\n{listing}\n\n"
                 f"Grapher: {grapher.display_name}"
                 + (f" on http://127.0.0.1:{port}" if grapher.image else "") + ".\n"
                 f"Scrape interval set to {scrape}s to stay inside the shortest watch interval.\n"
                 f"Read {root / 'README.md'} for the order to start things in.\n"
                 + push_note)
        return SUCCESS

    def _cmd_verify():
        nonlocal rest
        from netops_platform.traffic_graphers import get_grapher
        from netops_platform.traffic_stack import DEFAULT_VM_URL
        rest, url_arg = _flag(rest, "--url")
        rest, bind_arg = _flag(rest, "--bind")
        rest, grapher_arg = _flag(rest, "--grapher")
        rest, port_arg = _flag(rest, "--grapher-port")
        vm_url = (url_arg or app.config.public.get("traffic_victoriametrics_url")
                  or DEFAULT_VM_URL).rstrip("/")
        bind = bind_arg or "127.0.0.1:9713"
        grapher = get_grapher(grapher_arg or app.config.public.get("traffic_grapher") or "grafana")
        port = int(port_arg) if str(port_arg or "").isdigit() else (grapher.default_port if grapher else 0)
        # A collector-role machine has no exposition, storage, or dashboards by
        # design. Checking for them there reports four failures for four things
        # deliberately absent, which trains an operator to ignore the output.
        stack_units = Path(app.paths.state_dir) / "metrics-stack" / "systemd"
        collector_only = (stack_units.is_dir()
                          and not (stack_units / "netrune-exporter.service").is_file())
        checks = _verify_chain(app, monitor, vm_url, bind, grapher, port,
                               collector_only=collector_only)
        failed = [c for c in checks if c["state"] == "fail"]
        warned = [c for c in checks if c["state"] == "warn"]
        lines = [f"  {'ok  ' if c['state']=='pass' else ('WARN' if c['state']=='warn' else 'FAIL')}  "
                 f"{c['check']:<34} {c['detail']}" for c in checks]
        summary = (f"{len(checks) - len(failed) - len(warned)}/{len(checks)} checks passed"
                   + (f", {len(warned)} warning(s)" if warned else "")
                   + (f", {len(failed)} failure(s)" if failed else "."))
        if failed:
            # Every component here is a user service. When the manager they all
            # live in is down they each fail separately, and a column of
            # failures reads as several problems rather than one.
            problem = user_manager_problem()
            if problem:
                summary += "\n\nAll of these have one cause.\n" + problem
        app.emit({"ok": not failed, "checks": checks, "failed": len(failed),
                  "warnings": len(warned)}, opts, "\n".join(lines) + "\n\n" + summary)
        return SUCCESS if not failed else PARTIAL

    # ---- remote pollers ----------------------------------------------------

    def _cmd_export():
        nonlocal rest
        # Read-only, and deliberately plain on stdout: this is what a puller on
        # the other end of an SSH pipe consumes.
        from netops_platform.traffic_sync import export_rows, render_jsonl
        window = resolve_window()
        if window is None:
            return usage(f"'{opts.since}' is not a window. Use seconds or 15m, 6h, 2d.",
                         "netrune traffic export --since 24h")
        since = int(time.time()) - (window if opts.since else 86400)
        rows = list(export_rows(monitor, since=since))
        for line in render_jsonl(rows):
            print(line)
        return SUCCESS

    def _cmd_pull():
        nonlocal rest
        from netops_platform.traffic_sync import (
            RemoteError, RemoteStore, merge_export, parse_jsonl, run_remote)
        rest, remote_arg = _flag(rest, "--remote")
        rest, file_arg = _flag(rest, "--file")
        store = RemoteStore(app.state)

        # Merging is not tied to how the readings arrived. SSH is the tidiest
        # way to fetch them and needs nothing standing between the two machines,
        # but it is not always permitted between two subnets, and a firewall
        # rule is not a reason to be unable to read your own data. An export is
        # a file; anything that can move a file will do -- a share, a USB stick,
        # whatever is already allowed.
        name = remote_arg or ("" if file_arg else (rest[0] if rest else ""))
        remote = store.get(name) if name else None
        if not file_arg:
            if not name:
                return usage("A remote or a file is required.",
                             "netrune traffic pull --remote poller1")
            if not remote:
                known = ", ".join(r["name"] for r in store.list()) or "none yet"
                return usage(f"No remote called '{name}'. Known: {known}.",
                             "netrune traffic remote add poller1 --host 198.51.100.5")
        elif name and not remote:
            return usage(f"No remote called '{name}' to record this pull against.",
                         f"netrune traffic pull --file {file_arg}")

        window = resolve_window()
        if window is None:
            return usage(f"'{opts.since}' is not a window. Use seconds or 15m, 6h, 2d.",
                         "netrune traffic pull --remote poller1 --since 24h")

        try:
            if file_arg:
                # Whatever the file holds is what there is to merge; a window
                # would silently drop readings the operator already carried
                # across. Merging is idempotent, so re-reading a file is safe.
                if file_arg == "-":
                    body = sys.stdin.read()
                else:
                    path = Path(os.path.expanduser(file_arg))
                    if not path.is_file():
                        return usage(f"No such export file: {path}",
                                     "netrune traffic pull --file ./poller.jsonl")
                    body = path.read_text(encoding="utf-8")
            else:
                # Without an explicit window, resume from the newest sample
                # already merged, so a repeated pull carries only what is new.
                if opts.since:
                    since = int(time.time()) - window
                else:
                    last = int((remote or {}).get("last_sample_at") or 0)
                    since = last if last else int(time.time()) - 86400
                body = run_remote(
                    remote, ["traffic", "export", "--since", f"{max(60, int(time.time()) - since)}s"],
                    timeout=min(int(opts.timeout or 120), 900))
            rows = parse_jsonl(body)
            summary = merge_export(monitor, rows, dry_run=opts.dry_run)
        except RemoteError as exc:
            app.emit({"ok": False, "remote": name, "error": str(exc)}, opts, f"Pull failed. {exc}")
            return PARTIAL
        except OSError as exc:
            app.emit({"ok": False, "file": file_arg, "error": str(exc)}, opts,
                     f"Could not read the export. {exc}")
            return PARTIAL
        if not opts.dry_run and name:
            store.record_pull(name, summary["collector"], summary["newest_sample_at"])
        lines = [
            f"{'Would merge' if opts.dry_run else 'Merged'} {summary['merged']} new sample(s) from "
            f"'{summary['collector']}' via {name or file_arg}."]
        if summary["already_present"]:
            lines.append(f"  {summary['already_present']} sample(s) were already here; a repeated "
                         "pull carries them but does not duplicate them.")
        lines.append(f"  {summary['watches']} watch(es) and {summary['counters']} counter baseline(s).")
        if summary["newest_sample_at"]:
            lines.append("  Newest reading "
                         + time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(summary["newest_sample_at"]))
                         + ".")
        if summary["merged"] and not opts.dry_run:
            lines.append("Its interfaces now appear in 'netrune traffic show' and 'traffic report'.")
        app.emit({"ok": True, "remote": name, "file": file_arg or None,
                  "dry_run": opts.dry_run, **summary}, opts, "\n".join(lines))
        return SUCCESS

    def _cmd_remote():
        nonlocal rest
        from netops_platform.traffic_sync import RemoteError, RemoteStore, remote_netrune, run_remote
        store = RemoteStore(app.state)
        action = rest[0] if rest else "list"
        rest = rest[1:]

        if action == "list":
            rows = []
            for remote in store.list():
                last = int(remote.get("last_pull_at") or 0)
                rows.append({
                    "remote": remote["name"],
                    "host": remote.get("host"),
                    "ssh_user": remote.get("ssh_user") or "-",
                    "profile": remote.get("profile") or "-",
                    "collector": remote.get("collector_id") or "(not pulled yet)",
                    "last_pull": time.strftime("%Y-%m-%d %H:%M", time.localtime(last)) if last else "never",
                })
            app.emit({"ok": True, "rows": rows, "count": len(rows)}, opts,
                     app.render_table(rows, ["remote", "host", "ssh_user", "profile", "collector", "last_pull"])
                     if rows else "No remote pollers are configured. Add one with "
                                  "'netrune traffic remote add <name> --host <address>'.")
            return SUCCESS if rows else PARTIAL

        if action == "add":
            rest, host_arg = _flag(rest, "--host")
            rest, user_arg = _flag(rest, "--ssh-user")
            rest, port_arg = _flag(rest, "--ssh-port")
            rest, profile_arg = _flag(rest, "--profile-name")
            if not rest:
                return usage("A name for the remote is required.",
                             "netrune traffic remote add poller1 --host 100.64.0.5")
            if not host_arg:
                return usage("--host is required.",
                             "netrune traffic remote add poller1 --host 100.64.0.5 --ssh-user netrune")
            try:
                remote = store.add(rest[0], host_arg, ssh_user=user_arg or "",
                                   ssh_port=int(port_arg) if str(port_arg or "").isdigit() else 0,
                                   profile=profile_arg or "poller", actor=actor)
            except ValueError as exc:
                return usage(str(exc), "netrune traffic remote add poller1 --host 100.64.0.5")
            app.emit({"ok": True, "remote": remote}, opts,
                     f"Remote '{remote['name']}' is {remote.get('ssh_user') or '<current user>'}@"
                     f"{remote['host']}, profile '{remote.get('profile')}'.\n"
                     f"Check it with 'netrune traffic remote {remote['name']} status', then pull with "
                     f"'netrune traffic pull --remote {remote['name']}'.")
            return SUCCESS

        if action in {"remove", "forget"}:
            if not rest:
                return usage("A remote name is required.", "netrune traffic remote remove poller1")
            removed = store.remove(rest[0])
            app.emit({"ok": removed, "remote": rest[0]}, opts,
                     f"Forgot remote '{rest[0]}'. Its pulled samples stay; remove them with "
                     f"'netrune traffic unwatch'." if removed else f"No remote called '{rest[0]}'.")
            return SUCCESS if removed else VALIDATION

        # Anything else is a netrune command for the remote to run. This wrapper
        # deliberately does not know what those verbs mean: the real CLI on the
        # other end validates them, and teaching this side their grammar would
        # mean two implementations to keep in step.
        remote = store.get(action)
        if not remote:
            known = ", ".join(r["name"] for r in store.list()) or "none yet"
            return usage(f"No remote called '{action}'. Known: {known}.",
                         "netrune traffic remote list")
        if not rest:
            return usage(f"A command for '{action}' to run is required.",
                         f"netrune traffic remote {action} list")
        forwarded = ["traffic", *rest]
        if opts.confirm and "--confirm" not in forwarded:
            forwarded.append("--confirm")
        if opts.json and "--json" not in forwarded:
            forwarded.append("--json")
        if opts.dry_run:
            command = remote_netrune(remote, forwarded)
            app.emit({"ok": True, "dry_run": True, "command": command}, opts,
                     "Would run: " + " ".join(command))
            return SUCCESS
        try:
            output = run_remote(remote, forwarded, timeout=min(int(opts.timeout or 300), 900))
        except RemoteError as exc:
            app.emit({"ok": False, "remote": action, "error": str(exc)}, opts, str(exc))
            return PARTIAL
        print(output, end="" if output.endswith("\n") else "\n")
        return SUCCESS

    handlers = {
        "list": _cmd_list,
        "watches": _cmd_list,
        "watch": _cmd_watch,
        "ping": _cmd_ping,
        "pause": _cmd_watch_control,
        "resume": _cmd_watch_control,
        "unwatch": _cmd_watch_control,
        "remove": _cmd_watch_control,
        "interval": _cmd_watch_control,
        "name": _cmd_name,
        "rename": _cmd_name,
        "label": _cmd_name,
        "color": _cmd_name,
        "colour": _cmd_name,
        "subscribe": _cmd_subscribe,
        "service": _cmd_subscribe,
        "push": _cmd_push,
        "dashboard": _cmd_dashboard,
        "dashboards": _cmd_dashboard,
        "open": _cmd_dashboard,
        "health": _cmd_health,
        "switches": _cmd_health,
        "interfaces": _cmd_interfaces,
        "poll": _cmd_poll,
        "daemon": _cmd_daemon,
        "status": _cmd_status,
        "show": _cmd_show,
        "graph": _cmd_show,
        "report": _cmd_report,
        "exporter": _cmd_exporter,
        "backfill": _cmd_backfill,
        "stack": _cmd_stack,
        "verify": _cmd_verify,
        "export": _cmd_export,
        "pull": _cmd_pull,
        "remote": _cmd_remote,
    }
    handler = handlers.get(verb)
    return handler() if handler else app.unknown_action("traffic", verb, opts)


def _next_poll(watch: Mapping[str, Any], age: Optional[int], interval: int,
               collector_running: bool) -> str:
    """When this target is next due, in the terms an operator asked in.

    The collector wakes every few seconds and polls whatever has reached its own
    interval, so "next tick" for a given target is its interval minus however
    long ago it was last read.
    """
    if watch.get("owner"):
        return "on next pull"
    if not watch.get("enabled"):
        return "paused"
    if not collector_running:
        return "no collector"
    if age is None:
        return "now"
    remaining = interval - age
    return "now" if remaining <= 0 else f"in {remaining}s"


def _health(watch: Mapping[str, Any], age: Optional[int], interval: int) -> str:
    if watch.get("owner"):
        # Freshness here is a function of when this machine last pulled, not of
        # whether the poller is collecting. Its own verify answers that.
        return "remote" if age is None else f"pulled {age}s ago"
    if not watch.get("enabled"):
        return "paused"
    if age is None:
        return "no data yet"
    # Two missed intervals is the point at which a gap stops looking like jitter.
    return "ok" if age <= interval * 2 + 15 else "stale"


def _run_daemon(app: Any, monitor: TrafficMonitor, opts: Any, override: int) -> int:
    from netops_platform.core import SUCCESS, eprint

    watches = monitor.list_watches(enabled_only=True)
    cadence = (f"every {override}s" if override
               else f"on each target's own interval, from "
                    f"{min(int(w.get('interval_seconds') or 60) for w in watches)}s")
    record = {"pid": os.getpid(), "collector": monitor.collector_id(),
              "started_at": int(time.time()), "override_interval": override}
    path = collector_pidfile(app)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(record), encoding="utf-8")
    os.chmod(path, 0o600)
    _stop_on_sigterm()
    eprint(f"Traffic collector '{record['collector']}' is collecting {cadence}. Ctrl+C stops it.")
    eprint("The watchlist is re-read every tick, so watch, pause, resume, and unwatch take effect "
           "without restarting this process.")

    attempts: Dict[str, float] = {}
    rounds = collected = 0
    try:
        while True:
            started = time.monotonic()
            due = monitor.due_watches(attempts, override_interval=override)
            if due:
                payload = monitor.poll(due, opts=opts)
                rounds += 1
                collected += payload["samples_recorded"]
                for failure in payload["errors"][:2]:
                    eprint(f"  {failure.get('device') or failure.get('target')}: {failure['error']}")
            app._progress_update(
                f"traffic collector | {rounds} round(s) | {collected} sample(s) | "
                f"{len(monitor.list_watches(enabled_only=True))} active target(s) | Ctrl+C stops", opts)
            # A short tick keeps every target close to its own interval without
            # waking for the ones that are not due yet.
            time.sleep(max(0.5, 5.0 - (time.monotonic() - started)))
    except KeyboardInterrupt:
        app._progress_clear(opts)
        eprint(f"Collector stopped after {rounds} round(s) and {collected} sample(s).")
        return SUCCESS
    finally:
        path.unlink(missing_ok=True)


def _suggested_scrape(monitor: TrafficMonitor) -> int:
    """A scrape interval that cannot outrun the collector, or alias against it.

    Scraping more slowly than the collector polls discards readings that were
    actually taken. Scraping at exactly the poll interval is worse than it
    looks: the two drift against each other, so some scrapes land between two
    polls and see nothing while the next sees two polls' worth, and a rate over
    a short window reads that doubled step as real traffic -- a gigabit port
    reporting 1.2 Gb/s. Half the shortest interval keeps every poll observed on
    its own.
    """
    watches = monitor.list_watches(enabled_only=True)
    if not watches:
        return 30
    shortest = min(int(w.get("interval_seconds") or 60) for w in watches)
    return max(5, min(shortest // 2 or shortest, 300))


def _backfill_body(monitor: TrafficMonitor, window: int, escape) -> List[str]:
    """Stored history as Prometheus exposition lines with explicit timestamps.

    The history is rates Netrune already computed; the raw counters behind them
    were never retained. Re-deriving a counter by integrating those rates would
    invent readings nobody took, so the history is published under its own
    gauge names and left honest about what it is.
    """
    metric_names = {
        "in_bps": "netrune_history_interface_receive_bits_per_second",
        "out_bps": "netrune_history_interface_transmit_bits_per_second",
        "in_utilization_pct": "netrune_history_interface_receive_utilization_percent",
        "out_utilization_pct": "netrune_history_interface_transmit_utilization_percent",
        "rtt_ms": "netrune_history_icmp_rtt_seconds",
        "packet_loss_pct": "netrune_history_icmp_loss_ratio",
    }
    scales = {"rtt_ms": 0.001, "packet_loss_pct": 0.01}
    watches = {str(w["watch_id"]): w for w in monitor.list_watches()}
    cutoff = int(time.time()) - window
    lines: List[str] = []
    for row in monitor.state.rows(
        "SELECT watch_id,metric,value,observed_at,collector FROM traffic_samples"
        " WHERE observed_at>=? AND metric IN (%s) ORDER BY observed_at"
        % ",".join("?" * len(metric_names)),
        (cutoff, *metric_names),
    ):
        watch = watches.get(str(row["watch_id"]))
        if not watch or row["value"] is None:
            continue
        name = metric_names[str(row["metric"])]
        value = float(row["value"]) * scales.get(str(row["metric"]), 1.0)
        if watch.get("kind") == "interface":
            labels = {
                "device": watch.get("device_name") or watch.get("device_ip") or "",
                "device_ip": watch.get("device_ip") or "",
                "interface": watch.get("interface_name") or "",
                "ifindex": watch.get("ifindex") or "",
                "collector": row["collector"],
            }
        else:
            labels = {"target": watch.get("target") or "", "collector": row["collector"]}
        rendered = ",".join(f'{k}="{escape(v)}"' for k, v in labels.items() if v not in (None, ""))
        # Prometheus exposition timestamps are milliseconds.
        lines.append(f"{name}{{{rendered}}} {value} {int(row['observed_at']) * 1000}")
    return lines


class _Stopped(KeyboardInterrupt):
    """Raised when a service manager asks the process to stop."""


def _stop_on_sigterm():
    """Make SIGTERM behave like Ctrl+C so shutdown runs the same cleanup.

    Under systemd a plain SIGTERM would kill the process between statements,
    leaving the collector's pidfile behind to claim it is still running.
    """
    import signal

    def handler(signum, frame):
        raise _Stopped()

    try:
        signal.signal(signal.SIGTERM, handler)
    except ValueError:
        # Not on the main thread; the caller is embedded and owns its signals.
        pass


def _verify_chain(app: Any, monitor: TrafficMonitor, vm_url: str, bind: str,
                  grapher: Any, port: int,
                  collector_only: bool = False) -> List[Dict[str, Any]]:
    """Walk the pipeline link by link and report where it breaks.

    Each check answers one question an operator would otherwise answer by hand,
    in the order the data actually flows, so the first failure is the cause
    rather than a symptom of something upstream.

    On a collector-role machine the pipeline ends at the collector: there is no
    exposition, no storage, and no dashboard, and reporting their absence as
    failures would teach an operator to stop reading this.
    """
    import urllib.error
    import urllib.request

    checks: List[Dict[str, Any]] = []

    def record(name: str, state: str, detail: str) -> None:
        checks.append({"check": name, "state": state, "detail": detail})

    def fetch(url: str, timeout: int = 8) -> Optional[str]:
        try:
            with urllib.request.urlopen(url, timeout=timeout) as response:
                return response.read().decode("utf-8", "replace")
        except (urllib.error.URLError, OSError, ValueError):
            return None

    # 1. Is anything being collected at all?
    watches = monitor.list_watches()
    active = [w for w in watches if w.get("enabled")]
    if not watches:
        record("watchlist", "fail", "nothing is being monitored; run 'netrune traffic watch'")
    elif not active:
        record("watchlist", "warn", f"{len(watches)} target(s), all paused")
    else:
        record("watchlist", "pass", f"{len(active)} active of {len(watches)} target(s)")

    # 2. Is the collector running and recent?
    running = running_collector(app)
    newest = 0
    for watch in watches:
        metric = "out_bps" if watch["kind"] == "interface" else "rtt_ms"
        last = monitor.summarize(str(watch["watch_id"]), metric, 86400).get("last_at") or 0
        newest = max(newest, int(last))
    age = int(time.time()) - newest if newest else None
    if running:
        record("collector", "pass", f"running as pid {running.get('pid')}")
    elif age is not None and age < 900:
        record("collector", "warn", f"not running; newest sample is {age}s old")
    else:
        record("collector", "fail", "not running; start 'netrune traffic daemon'")

    if collector_only:
        # The chain ends here by design. Saying so is the useful answer; the
        # alternative is four failures for four things deliberately absent.
        record("role", "pass",
               "collector only: no exposition, storage, or dashboards on this machine")
        pulled = [w for w in watches if w.get("owner")]
        if pulled:
            record("ownership", "warn",
                   f"{len(pulled)} watch(es) belong to another collector and are not polled here")
        return checks

    # 3. Is the exposition being served?
    body = fetch(f"http://{bind}/metrics")
    if body is None:
        record("exposition", "fail", f"nothing answering on http://{bind}/metrics")
    else:
        families = len({line.split()[2] for line in body.splitlines() if line.startswith("# TYPE ")})
        record("exposition", "pass" if families else "warn",
               f"{families} metric families on http://{bind}")

    # 4. Is VictoriaMetrics up, and scraping?
    if fetch(f"{vm_url}/health") is None:
        record("victoriametrics", "fail", f"not answering at {vm_url}")
        record("scrape", "fail", "skipped; storage is unreachable")
    else:
        record("victoriametrics", "pass", vm_url)
        scraped = fetch(f"{vm_url}/api/v1/query?query=up")
        value = ""
        try:
            result = json.loads(scraped or "{}").get("data", {}).get("result") or []
            value = str(result[0]["value"][1]) if result else ""
        except (ValueError, KeyError, IndexError):
            value = ""
        if value == "1":
            record("scrape", "pass", "VictoriaMetrics is scraping the exposition")
        elif value == "0":
            record("scrape", "fail", "target is down; check the exposition bind and scrape config")
        else:
            record("scrape", "fail", "no 'up' series; is promscrape.config pointed at the exposition?")

        # 5. Do the dashboard queries return anything?
        probe = ("8 * rate(netrune_interface_receive_bytes_total[2m])")
        answered = fetch(f"{vm_url}/api/v1/query?query={urllib.parse.quote(probe)}")
        try:
            rows = json.loads(answered or "{}").get("data", {}).get("result") or []
        except ValueError:
            rows = []
        if rows:
            record("rate derivation", "pass", f"{len(rows)} interface series resolve to a rate")
        else:
            record("rate derivation", "warn",
                   "no rate yet; a counter needs two scrapes before it has one")

    # 6. Is the grapher up, and does it know about the datasource?
    if grapher is None or not grapher.image:
        record("grapher", "pass", "vmui, built into VictoriaMetrics")
    else:
        base = f"http://127.0.0.1:{port}"
        if fetch(base + grapher.health_path()) is None:
            record("grapher", "fail", f"{grapher.display_name} not answering at {base}")
        else:
            record("grapher", "pass", f"{grapher.display_name} at {base}")

    return checks


#: The units the stack installs, in the order a cold start needs them.
STACK_UNITS = ("netrune-exporter.service", "netrune-collector.service",
               "netrune-victoriametrics.service", "netrune-vmalert.service")
STACK_TARGET = "netrune-metrics.target"


def _systemd_user_dir() -> Path:
    return Path(os.path.expanduser("~/.config/systemd/user"))


def _run(command: List[str], timeout: int = 120) -> tuple[int, str]:
    try:
        finished = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        return 127, f"{command[0]} is not installed"
    except subprocess.TimeoutExpired:
        return 124, f"{' '.join(command)} timed out"
    return finished.returncode, (finished.stdout or "") + (finished.stderr or "")


def _installed_units(root: Path) -> List[str]:
    source = root / "systemd"
    if not source.is_dir():
        return []
    # Timers too: a unit the generator wrote and the installer skipped is a
    # feature that silently does not exist.
    return (sorted(path.name for path in source.glob("*.service"))
            + sorted(path.name for path in source.glob("*.timer"))
            + sorted(path.name for path in source.glob("*.target")))


def _stack_service(app: Any, opts: Any, action: str, usage) -> int:
    """Drive the generated units, so the stack is a command rather than a ritual.

    Copying unit files and remembering the systemctl incantation is the part
    people get wrong or skip, and a stack that is never started is the same as
    one that was never generated.
    """
    from netops_platform.core import PARTIAL, SUCCESS

    root = Path(app.paths.state_dir) / "metrics-stack"
    if not (root / "systemd").is_dir():
        return usage(f"No generated units at {root / 'systemd'}.", "netrune traffic stack init")

    if action in {"install", "up"}:
        destination = _systemd_user_dir()
        destination.mkdir(parents=True, exist_ok=True)
        copied = []
        for name in _installed_units(root):
            body = (root / "systemd" / name).read_text(encoding="utf-8")
            target = destination / name
            if not target.is_file() or target.read_text(encoding="utf-8") != body:
                target.write_text(body, encoding="utf-8")
                copied.append(name)
        # An installed unit the stack no longer generates -- a grapher that was
        # swapped out -- would keep running and keep its port.
        wanted = set(_installed_units(root))
        retired = []
        for path in sorted(destination.glob("netrune-*.service")):
            if path.name in wanted:
                continue
            _run(["systemctl", "--user", "disable", "--now", path.name], timeout=120)
            path.unlink()
            retired.append(path.name)
        rc, output = _run(["systemctl", "--user", "daemon-reload"])
        if rc != 0:
            problem = user_manager_problem() if any(m in output for m in _NO_USER_BUS) else ""
            return usage(problem or f"systemd is not usable here: {output.strip()[:200]}",
                         "netrune traffic stack status")
        lines = [f"Installed {len(copied)} changed unit(s) into {destination}." if copied
                 else f"Units in {destination} are already current."]
        if retired:
            lines.append(f"Stopped and removed {len(retired)} unit(s) this stack no longer "
                         f"generates: {', '.join(retired)}")

        if action == "install":
            lines.append("Start them with 'netrune traffic stack up'.")
            app.emit({"ok": True, "installed": copied, "unit_dir": str(destination)}, opts,
                     "\n".join(lines))
            return SUCCESS

        rc, output = _run(["systemctl", "--user", "enable", "--now", STACK_TARGET], timeout=180)
        if rc != 0:
            app.emit({"ok": False, "error": output.strip()}, opts,
                     "\n".join(lines) + f"\nCould not start {STACK_TARGET}: {output.strip()[:300]}")
            return PARTIAL
        # Enabling the target starts what it wants, but a unit added after the
        # target was first enabled has no symlink yet and would stay stopped.
        for name in _installed_units(root):
            # A oneshot driven by a timer must not be enabled itself, or it
            # runs at boot and then never again on its own schedule.
            if name.endswith(".timer") or (
                    name.endswith(".service")
                    and f"{name[:-len('.service')]}.timer" not in _installed_units(root)):
                _run(["systemctl", "--user", "enable", "--now", name], timeout=120)
        linger = _run(["loginctl", "show-user", os.environ.get("USER", ""), "-p", "Linger", "--value"])[1].strip()
        lines.append(f"Started {STACK_TARGET}.")
        if linger != "yes":
            lines.append("Linger is off, so these stop when your last session closes. "
                         "Enable it with: loginctl enable-linger \"$USER\"")
        lines.append("Check with 'netrune traffic stack status' or 'netrune traffic verify'.")
        app.emit({"ok": True, "installed": copied, "retired": retired,
                  "linger": linger == "yes"}, opts, "\n".join(lines))
        return SUCCESS

    if action in {"down", "restart"}:
        verb = "stop" if action == "down" else "restart"
        rc, output = _run(["systemctl", "--user", verb, STACK_TARGET], timeout=180)
        units = [name for name in _installed_units(root) if name.endswith(".service")]
        # PartOf= carries stop and restart down to the services, but a unit the
        # target does not know about would be left behind.
        for name in units:
            _run(["systemctl", "--user", verb, name], timeout=120)
        app.emit({"ok": rc == 0, "action": verb, "units": units}, opts,
                 f"{verb.capitalize()}ed the stack ({len(units)} service(s))."
                 if rc == 0 else f"systemctl {verb} failed: {output.strip()[:300]}")
        return SUCCESS if rc == 0 else PARTIAL

    # status
    problem = user_manager_problem()
    if problem:
        app.emit({"ok": False, "user_manager": False, "detail": problem}, opts, problem)
        return PARTIAL
    rows = []
    for name in _installed_units(root):
        if not name.endswith(".service"):
            continue
        active = _run(["systemctl", "--user", "is-active", name], timeout=20)[1].strip()
        enabled = _run(["systemctl", "--user", "is-enabled", name], timeout=20)[1].strip()
        installed = (_systemd_user_dir() / name).is_file()
        current = installed and (_systemd_user_dir() / name).read_text(encoding="utf-8") == \
            (root / "systemd" / name).read_text(encoding="utf-8")
        rows.append({
            "unit": name.replace("netrune-", "").replace(".service", ""),
            "active": active or "unknown",
            "enabled": enabled or "unknown",
            "installed": "yes" if installed else "no",
            "current": "yes" if current else ("stale" if installed else "-"),
        })
    linger = _run(["loginctl", "show-user", os.environ.get("USER", ""), "-p", "Linger", "--value"])[1].strip()
    stale = [row["unit"] for row in rows if row["current"] == "stale"]
    notes = []
    if stale:
        notes.append(f"{len(stale)} unit(s) differ from the generated copy: {', '.join(stale)}. "
                     "Run 'netrune traffic stack up' to install them.")
    if linger != "yes":
        notes.append("Linger is off: user services stop when your last session closes.")
    app.emit({"ok": True, "rows": rows, "linger": linger == "yes", "stale": stale}, opts,
             (app.render_table(rows, ["unit", "active", "enabled", "installed", "current"])
              if rows else "No units are generated yet. Run 'netrune traffic stack init'.")
             + ("\n\n" + "\n".join(notes) if notes else ""))
    return SUCCESS
