"""Command surface for the setup domain.

Kept out of core.py as a free function, matching traffic_cli.py's pattern,
because cmd_setup has no callers outside its own dispatch -- unlike
vlan/topology/lookup/diagnose, nothing else in the codebase calls into it,
so there's no MRO-resolution reason to use a mixin here. write_snmp_community
keeps a public module-level name (rather than becoming private like
_dispatch_quietly/_user_is_lingering) because tests call it directly via
`self.app.write_snmp_community(...)`; core.py keeps a matching 2-line
delegate method so that call site keeps working.
"""

from __future__ import annotations

import contextlib
import io
import os
import socket
import subprocess
from pathlib import Path
from typing import Any, Dict, List

#: What a machine is being set up to be, and what that actually requires.
SETUP_ROLES = {
    "poller": "Collects and nothing else. No exposition, no storage, no dashboards.",
    "local": "Collects, stores, and draws. The machine you look at.",
}


def dispatch(app: Any, args: List[str], opts: GlobalOptions) -> int:
    from netops_platform.core import PARTIAL, SUCCESS, VALIDATION, _take_flag
    """Everything a working install needs, from the few facts that differ.

    Standing this up by hand was around twenty commands: create a profile,
    select it, set an identity, set a retention, migrate, write a
    credentials file, generate units, install units, reload, enable, enable
    linger. Every one of those is mechanism. The facts that actually differ
    between two installs are the SNMP community, what this machine is for,
    and what it should watch -- so those are the arguments, and the rest is
    this command's job rather than the operator's.
    """
    if app.handle_help("setup", args, opts):
        return SUCCESS
    role = (args[0] if args and not args[0].startswith("-") else "").lower()
    rest = list(args[1:] if role else args)
    if role not in SETUP_ROLES:
        listing = "\n".join(f"  {name:<8} {why}" for name, why in SETUP_ROLES.items())
        return app.usage_error(
            "setup", "", opts,
            (f"Unknown role '{role}'." if role else "A role is required.") + "\n" + listing,
            "netrune setup poller --community <community>", VALIDATION)

    rest, community = _take_flag(rest, "--community")
    rest, collector = _take_flag(rest, "--collector-id")
    rest, profile_name = _take_flag(rest, "--profile-name")
    rest, retention = _take_flag(rest, "--retention")
    rest, publish = _take_flag(rest, "--publish")
    rest, export_to = _take_flag(rest, "--export-to")
    rest, push_to = _take_flag(rest, "--push-to")
    accept_push = "--accept-push" in rest
    rest = [item for item in rest if item != "--accept-push"]
    watches: List[str] = []
    while True:
        rest, target = _take_flag(rest, "--watch")
        if target is None:
            break
        watches.append(target)

    # This machine's own gate on the same rule traffic_cli.py's `stack init`
    # enforces (non-loopback exposure needs --confirm): setup hardcodes
    # --confirm onto the stack_args it forwards below, so stack init's own
    # check never fires here and this is the only enforcement point for
    # this command. If stack init ever grows a new way to expose data
    # beyond loopback, mirror it here too.
    if (publish or accept_push) and not opts.confirm:
        return app.usage_error(
            "setup", "", opts,
            (f"--publish {publish} serves this machine's readings and dashboards to anything "
             "that can reach that address, rather than to this machine only."
             if publish else "")
            + ("\n--accept-push lets anything that can reach this machine write readings into "
               "its store, which is not read-only exposure." if accept_push else "")
            + "\nThat is a deliberate choice, so confirm it here.",
            f"netrune setup {role}"
            + (f" --publish {publish}" if publish else "")
            + (" --accept-push" if accept_push else "") + " --confirm", VALIDATION)

    profile = profile_name or role
    steps: List[Dict[str, Any]] = []

    def step(name: str, ok: bool, detail: str = "") -> None:
        steps.append({"step": name, "ok": bool(ok), "detail": detail})

    if opts.dry_run:
        plan = [f"profile '{profile}'", "collector identity",
                "SNMP community" if community else "SNMP community (not given)",
                "database", f"{role} stack", "services", "linger"]
        plan += [f"watch {t}" for t in watches]
        app.emit({"ok": True, "dry_run": True, "role": role, "profile": profile,
                   "plan": plan}, opts,
                  f"Would set this machine up as a {role}:\n"
                  + "\n".join(f"  {item}" for item in plan))
        return SUCCESS

    # 1. A profile of its own, so this install's state is never entangled
    #    with another's on the same machine.
    existing = {row.get("name") for row in app.profile_rows()} if hasattr(app, "profile_rows") else set()
    _dispatch_quietly(app, ["profile", "create", profile])
    _dispatch_quietly(app, ["profile", "use", profile])
    step("profile", True, profile)

    # 2. Identity. Two collectors with the same id produce one series that
    #    is neither, and a pull between them is refused outright.
    identity = collector or socket.gethostname().split(".")[0].lower()
    app._write_profile_config_value("traffic_collector_id", identity)
    app._write_profile_config_value(
        "traffic_retention_days", str(retention or (365 if role == "poller" else 180)))
    if export_to:
        app._write_profile_config_value("traffic_export_path", export_to)
    if push_to:
        app._write_profile_config_value("traffic_push_url", push_to.rstrip("/"))
    step("identity", True, identity)

    # 3. The one credential that is genuinely required.
    if community:
        written = write_snmp_community(app, community)
        step("snmp community", True, str(written))
    else:
        step("snmp community", False,
             "not given; nothing can be read until one is set with --community")

    app.state.init_db()
    step("database", True, "")

    # 4. Generate and start. Both, because a generated stack nobody started
    #    is the same as one that was never generated.
    stack_args = ["traffic", "stack", "init"]
    if role == "poller":
        stack_args += ["--role", "collector"]
    if publish:
        stack_args += ["--publish", publish, "--confirm"]
    if accept_push:
        stack_args += ["--accept-push", "--confirm"]
    code = _dispatch_quietly(app, stack_args)
    step("stack", code == SUCCESS, "generated")
    code = _dispatch_quietly(app, ["traffic", "stack", "up"])
    step("services", code == SUCCESS, "installed and started" if code == SUCCESS else "see 'traffic stack status'")

    # 5. Linger, which decides whether any of it survives a reboot.
    lingering = _user_is_lingering(app)
    step("survives reboot", lingering,
         "linger is on" if lingering else
         'linger is OFF; run: sudo loginctl enable-linger "$USER"')

    for target in watches:
        address, _, interface = target.partition(":")
        if not interface:
            step(f"watch {target}", False, "expected ADDRESS:INTERFACE")
            continue
        code = _dispatch_quietly(app, ["traffic", "watch", address, interface])
        step(f"watch {target}", code == SUCCESS, "" if code == SUCCESS else "see the error above")

    done = [s for s in steps if s["ok"]]
    lines = [f"{len(done)}/{len(steps)} steps done."]
    lines += [f"  {'ok  ' if s['ok'] else 'TODO'}  {s['step']:<18} {s['detail']}" for s in steps]
    lines.append("")
    if role == "poller":
        lines.append("This machine collects only; whatever pulls from it keeps the readings.")
        if not watches:
            lines.append("Give it something to watch:")
            lines.append("  netrune traffic watch <switch-address> <interface>")
        lines.append("Hand its readings over with either:")
        lines.append("  netrune traffic export --since 24h > somewhere-the-other-machine-can-read")
        lines.append("  ...or, where SSH between the two is permitted, let it pull.")
    else:
        if not watches:
            lines.append("Watch something:")
            lines.append("  netrune traffic watch <switch-address> <interface>")
        lines.append("Then look at it:  netrune traffic dashboard")
    if not community:
        lines.append("")
        lines.append("Nothing can be read until an SNMP community is set. Re-run with "
                     "--community, or write it to " + str(Path(app.paths.config_dir) / ".env"))
    app.emit({"ok": all(s["ok"] for s in steps), "role": role, "profile": profile,
               "steps": steps}, opts, "\n".join(lines))
    return SUCCESS if all(s["ok"] for s in steps) else PARTIAL

def _dispatch_quietly(app: Any, args: List[str]) -> int:
    from netops_platform.core import INTERNAL
    """Run one of our own commands without its output becoming ours."""
    buffer = io.StringIO()
    try:
        with contextlib.redirect_stdout(buffer), contextlib.redirect_stderr(buffer):
            return app.dispatch([*args, "--plain", "--no-color"])
    except SystemExit as exc:
        return int(exc.code or 0)
    except Exception:
        return INTERNAL

def _user_is_lingering(app: Any) -> bool:
    try:
        finished = subprocess.run(
            ["loginctl", "show-user", os.environ.get("USER", ""), "-p", "Linger", "--value"],
            capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.SubprocessError):
        return False
    return finished.stdout.strip() == "yes"

def write_snmp_community(app: Any, community: str) -> Path:
    """Put the community where the SNMP helpers read it, at mode 600.

    Hand-writing this file was a step in the install guide, which is a step
    too many for the one thing every install needs.
    """
    path = Path(app.paths.config_dir) / ".env"
    path.parent.mkdir(parents=True, exist_ok=True)
    existing = path.read_text(encoding="utf-8") if path.is_file() else ""
    kept = [line for line in existing.splitlines()
            if not line.strip().startswith(("communities=", "snmp_version="))]
    body = "\n".join(kept + [f'communities="{community}"', 'snmp_version="v2c"']).strip() + "\n"
    path.write_text(body, encoding="utf-8")
    path.chmod(0o600)
    return path

