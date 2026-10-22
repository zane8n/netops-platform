"""`netrune check`: memorable names for the checks an operator reaches for.

Netrune has ~170 registered commands; most days need two dozen of them. This
is a fixed catalogue of those, grouped by the question they answer, each with
a short name that says what it does (`pulse`, `down`, `links`, `vlan-trace`,
`find-mac`, `db`). A name is only shorthand: `netrune check <name> [args]` is
rewritten into the real command line before global flags are parsed
(`expand_argv`, called from `App.dispatch`), so `--json`, `--dry-run`,
`--all`, and `--limit` behave exactly as on the command it stands for, and the
command itself does all the work.

A free-function module like path_cli.py: `dispatch(app, args, opts)` only
lists the catalogue and explains one name; running a name never reaches it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple


@dataclass(frozen=True)
class Check:
    name: str
    group: str
    argv: Tuple[str, ...]  # "{1}", "{2}": the check's own positional arguments
    args: str  # how to call it, e.g. "<switch> <vlan>"
    tells: str  # what it answers, in a line
    reach: str  # none (memory only) | ping | SNMP | SSH | Internet
    speed: str  # instant | seconds | minutes
    writes: bool = False  # changes Netrune's own state (never a switch)


GROUPS = (
    ("routine", "Routines"),
    ("up", "What is up or down"),
    ("links", "Links and topology"),
    ("aps", "Access points"),
    ("where", "Where is it"),
    ("vlan", "VLANs and paths"),
    ("port", "Ports, cables, and the Internet"),
    ("identity", "Inventory and identity"),
    ("db", "Netrune's own database"),
    ("backup", "Backups"),
    ("setup", "Netrune itself"),
)

CHECKS: Tuple[Check, ...] = (
    Check("morning", "routine", ("workflow", "morning-check"), "",
          "The daily routine: reachability, topology, realign memory, database health, filtering, the attention queue.", "ping+SNMP", "minutes", True),
    Check("weekly", "routine", ("workflow", "weekly"), "",
          "Every long scan, SSH reads of every switch (hardware, AP ports, spanning tree), backups.", "SNMP+SSH", "minutes", True),
    Check("weekly-resume", "routine", ("workflow", "weekly", "--resume"), "",
          "Run only the weekly SSH steps that waited for the vault.", "SSH", "minutes", True),
    Check("attention", "routine", ("health", "attention"), "",
          "Everything that wants a look: outages, flapping, link changes, AP moves, failed backups, merge candidates.", "none", "instant"),

    Check("pulse", "up", ("health", "check"), "[target]",
          "Ping every known switch and AP (or one target) and record who is up or down now.", "ping", "seconds", True),
    Check("down", "up", ("health", "offline"), "",
          "What is down right now, from the last pulse.", "none", "instant"),
    Check("alive", "up", ("inventory", "activity"), "<device[,...]> [more]",
          "Ping just these devices now and say which answer.", "ping", "seconds"),
    Check("status", "up", ("health", "status"), "",
          "Up/down state, flaps, and outage start for everything.", "none", "instant"),
    Check("uptime", "up", ("health", "timeline"), "",
          "Up/down changes, newest first: when things went down and came back.", "none", "instant"),

    Check("links", "links", ("topology", "links"), "",
          "Quick: switch-to-switch links Netrune knows, with how sure it is of each.", "none", "instant"),
    Check("link-changes", "links", ("topology", "changes"), "",
          "Links that appeared or disappeared, newest first.", "none", "instant"),
    Check("neighbours", "links", ("topology", "show"), "[switch]",
          "What one switch sees on each port (LLDP/CDP).", "none", "instant"),
    Check("uplinks", "links", ("topology", "stp", "{1}"), "<switch>",
          "Live spanning tree on a switch: root, blocked ports, which ports are uplinks.", "SSH", "seconds"),
    Check("topology-refresh", "links", ("topology", "scan"), "",
          "Re-read LLDP/CDP neighbours from every switch.", "SNMP", "minutes", True),

    Check("aps-on", "aps", ("ap", "on-switch", "{1}"), "<switch>",
          "Which APs hang off a switch, and on which ports.", "none", "instant"),
    Check("ap-ports", "aps", ("ap", "neighbors"), "<switch[,...]> (or --all)",
          "Live: read CDP/LLDP and the MAC table to confirm which port each AP is on.", "SSH", "seconds", True),
    Check("ap-moves", "aps", ("ap", "moves"), "",
          "APs that changed switch or port, newest first.", "none", "instant"),
    Check("ap-history", "aps", ("ap", "timeline", "{1}"), "<ap>",
          "Where one AP has been attached over time.", "none", "instant"),
    Check("ap-unjoined", "aps", ("ap", "unjoined"), "",
          "APs the controller lists as not joined.", "none", "instant"),
    Check("ap-refresh", "aps", ("ap", "scan"), "",
          "Re-read APs from the controllers and switches.", "SNMP", "minutes", True),

    Check("find", "where", ("inventory", "list"), "[text]",
          "Find a switch or AP by any part of its name, IP, MAC, serial, or model.", "none", "instant"),
    Check("find-mac", "where", ("lookup", "mac", "all", "{1}"), "<mac>",
          "Live: which switch port a MAC is on now (access port, not the uplinks it crosses).", "SSH", "seconds"),
    Check("find-ip", "where", ("lookup", "core", "{1}"), "<ip|mac>",
          "Ask the core switch's ARP/MAC tables who an IP or MAC is.", "SSH", "seconds"),
    Check("mac-history", "where", ("lookup", "mac", "history", "{1}"), "<mac>",
          "Every port and identity a MAC has had, newest first.", "none", "instant"),
    Check("ip-history", "where", ("memory", "ip", "{1}"), "<ip>",
          "Who has held an IP over time.", "none", "instant"),
    Check("port-history", "where", ("memory", "port", "{1}", "{2}"), "<switch> <port>",
          "What has been plugged into one switch port over time.", "none", "instant"),

    Check("vlan-where", "vlan", ("vlan", "locate", "{1}", "{2}"), "<switch> <vlan>",
          "Live: where a VLAN exists, starting from a switch.", "SSH", "seconds"),
    Check("vlan-trace", "vlan", ("vlan", "propagation", "{1}", "{2}"), "<switch> <vlan>",
          "Live: follow a VLAN switch by switch from a root and show where it stops.", "SSH", "minutes"),
    Check("path", "vlan", ("path", "inspect", "{1}", "--vlan", "{2}"), "<endpoint> <vlan>",
          "The L2/L3 path to an endpoint on a VLAN, hop by hop, with findings.", "SSH", "seconds"),

    Check("port-health", "port", ("diagnose", "port-health", "{1}", "on", "{2}"), "<switch> <port>",
          "Live: speed/duplex negotiation and error-counter growth on one port.", "SSH", "seconds"),
    Check("cable", "port", ("diagnose", "cable", "{1}", "on", "{2}"), "<switch> <port>",
          "The last recorded cable (TDR) result for a port; starts no test.", "none", "instant"),
    Check("latency", "port", ("diagnose", "latency", "{1}"), "<target>",
          "Round-trip time, jitter, and loss to a target.", "ping", "seconds"),
    Check("internet", "port", ("diagnose", "filtering", "google.com"), "",
          "Is the Internet reachable and unfiltered: DNS, TLS, and filtering checks.", "Internet", "seconds"),
    Check("speed", "port", ("diagnose", "speed"), "",
          "This machine's Internet speed.", "Internet", "minutes"),

    Check("device", "identity", ("memory", "device", "{1}"), "<name|ip>",
          "Everything Netrune knows about one device: identity, history, relationships.", "none", "instant"),
    Check("same", "identity", ("device", "identity", "{1}", "{2}"), "<device> <device>",
          "Are these two records the same switch? Evidence and conflicts.", "none", "instant"),
    Check("support", "identity", ("device", "support", "{1}"), "<device>",
          "Manufacturer, model, driver, and what Netrune can safely do on it.", "none", "instant"),
    Check("merges", "identity", ("inventory", "merges"), "",
          "Manual device merges in force.", "none", "instant"),
    Check("hardware", "identity", ("device", "inventory"), "<device> (or --all)",
          "Live: re-read model, Motherboard serial, and base MAC over SSH.", "SSH", "seconds", True),

    Check("db", "db", ("db", "coherence"), "",
          "Quick database health: storage, references, labels, identities, merges, caches, stuck jobs.", "none", "seconds"),
    Check("db-fix", "db", ("db", "coherence", "--realign"), "",
          "The same, and fix what has one right answer (re-apply merges, relabel, drop switches filed as APs).", "none", "seconds", True),
    Check("db-deep", "db", ("db", "integrity"), "",
          "Full SQLite integrity check (slower).", "none", "seconds"),
    Check("db-size", "db", ("db", "status"), "",
          "Where the database is, its size, schema, and record counts.", "none", "instant"),

    Check("backups", "backup", ("backup", "history", "{1}"), "<device>",
          "Backup history for a device.", "none", "instant"),
    Check("config-diff", "backup", ("backup", "diff", "{1}"), "<device>",
          "What changed between a device's last two different configs.", "none", "instant"),
    Check("backup-all", "backup", ("backup", "run", "--all", "--skip-recent"), "",
          "Back up every online device whose config changed.", "SSH", "minutes", True),

    Check("doctor", "setup", ("diagnose", "doctor"), "",
          "Is this machine set up right: tools, routes, trust, core settings.", "none", "seconds"),
    Check("vault", "setup", ("vault", "status"), "",
          "Is the SSH vault locked or open, and until when.", "none", "instant"),
)

BY_NAME: Dict[str, Check] = {check.name: check for check in CHECKS}
USAGE = "netrune check [<name> [args] [--show]]"


def needed(check: Check) -> int:
    return max((int(match) for part in check.argv for match in re.findall(r"\{(\d+)\}", part)), default=0)


def expand_argv(argv: Sequence[str]) -> Optional[List[str]]:
    """`check <name> [args]` -> the real command line, every other token kept in order.

    The check's own arguments are the words straight after its name; flags
    and their values (`--limit 5`, `--depth 3`) stay exactly where they were.
    Returns None when argv is not a runnable check (no name, an unknown
    name, `--show`/`--help`, or too few arguments): `cmd_check` then lists,
    explains, or reports usage.
    """
    tokens = list(argv)
    if "check" not in tokens:
        return None
    at = tokens.index("check")
    if any(not token.startswith("-") for token in tokens[:at]) or at + 1 >= len(tokens):
        return None
    check = BY_NAME.get(tokens[at + 1])
    if not check or any(token in {"--show", "--help", "-h"} for token in tokens):
        return None
    end = at + 2
    while end < len(tokens) and not tokens[end].startswith("-"):
        end += 1
    given = tokens[at + 2:end]
    count = needed(check)
    if len(given) < count:
        return None
    expanded = [part.format(*([""] + given)) if "{" in part else part for part in check.argv]
    return tokens[:at] + expanded + given[count:] + tokens[end:]


def command_line(check: Check) -> str:
    names = check.args.split()
    def label(match: "re.Match[str]") -> str:
        index = int(match.group(1)) - 1
        return names[index] if index < len(names) else f"<arg{index + 1}>"
    return "netrune " + " ".join(re.sub(r"\{(\d+)\}", label, part) for part in check.argv)


def rows() -> List[Dict[str, Any]]:
    titles = dict(GROUPS)
    return [{"group": titles[check.group], "check": check.name, "args": check.args, "tells": check.tells,
             "reach": check.reach, "speed": check.speed, "writes": check.writes, "runs": command_line(check)}
            for check in CHECKS]


def help_topic() -> Dict[str, Any]:
    actions = {check.name: {"usage": f"netrune check {check.name} {check.args}".rstrip(),
                            "about": f"{check.tells} Runs: {command_line(check)} ({check.reach}, {check.speed}).",
                            "examples": [f"netrune check {check.name} {check.args}".rstrip()]}
               for check in CHECKS}
    return {"summary": "Memorable names for everyday checks, grouped by the question they answer.",
            "usage": USAGE, "actions": actions}


def dispatch(app: Any, args: List[str], opts: Any) -> int:
    from netops_platform.core import SUCCESS, VALIDATION
    names = [arg for arg in args if not arg.startswith("-")]
    if not names or names[0] in {"list", "all"}:
        payload = {"ok": True, "checks": rows()}
        if opts.json:
            app.emit(payload, opts, "")
            return SUCCESS
        parts = ["netrune check <name> [args]   (add --show to see the command a name runs)", ""]
        for key, title in GROUPS:
            group = [row for row in payload["checks"] if row["group"] == title]
            parts.append(title)
            for row in group:
                call = f"{row['check']} {row['args']}".rstrip()
                marks = f"[{row['reach']}, {row['speed']}{', writes' if row['writes'] else ''}]"
                parts.append(f"  {call:<34} {row['tells']} {marks}")
            parts.append("")
        parts.append("reach: none = Netrune's memory only; ping/SNMP/SSH = talks to the network; writes = updates Netrune's own records.")
        app.emit(payload, opts, "\n".join(parts))
        return SUCCESS
    check = BY_NAME.get(names[0])
    if not check:
        close = sorted(BY_NAME, key=lambda name: (not name.startswith(names[0][:2]), name))[:5]
        return app.usage_error("check", names[0], opts, f"No check called '{names[0]}'. Try: {', '.join(close)}", USAGE, VALIDATION)
    payload = {"ok": True, **next(row for row in rows() if row["check"] == check.name)}
    text = (f"{check.name}: {check.tells}\nRuns:  {command_line(check)}" + (f"\nUsage: netrune check {check.name} {check.args}" if check.args else "")
            + f"\nReach: {check.reach} | {check.speed}" + (" | updates Netrune's records" if check.writes else ""))
    app.emit(payload, opts, text)
    # Reached with a runnable name only when arguments were missing.
    return SUCCESS if "--show" in args or len(names) - 1 >= needed(check) else VALIDATION
