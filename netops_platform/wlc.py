"""What the wireless controllers say about their APs.

`netops-discovery` walks a controller's AP table with one `snmpbulkwalk -On`
and hands the raw output here; this module turns it into the AP pipe rows
`ap_merge` consumes and into the controller sidecar (`ap_controller.db`) that
carries what the pipe format has no room for: model, serial, firmware, the
controller's own status, uptime, and when the AP was polled.

Read from the live controllers on 2026-10-22, not only from the MIBs:

- Ruckus SmartZone answers on the legacy RUCKUS-SZ-WLAN-MIB `ruckusSZAPTable`
  (5.2.x has no RUCKUS-CTRL-MIB `ruckusCtrlApTable`). Its index is the AP MAC,
  length-prefixed (`6.a.b.c.d.e.f`). Disconnected APs stay in the table with
  their last IP and uptime, so uptime is only meaningful while connected.
- net-snmp prints a MAC as `STRING: " Xi5Rp"` when all six bytes happen to be
  printable, so the MAC comes from the index, never from the column's text.
- Uptime is TimeTicks (hundredths of a second): APs that never rebooted match
  the controller's own sysUpTime.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Mapping, Optional, Sequence

RUCKUS_AP_TABLE = ".1.3.6.1.4.1.25053.1.4.2.1.1.2.2.1"
# ruckusSZSystemStatsNumAP: the controller's own count, to tell a complete
# walk from a cut-off one.
RUCKUS_AP_COUNT = ".1.3.6.1.4.1.25053.1.4.1.1.1.15.1.0"
RUCKUS_COLUMNS = {1: "mac", 2: "group", 5: "name", 6: "uptime", 7: "firmware", 8: "model",
                  9: "serial", 10: "ip", 16: "connection", 17: "registration"}

# Cisco WLC (AireOS and Catalyst 9800): AIRESPACE-WIRELESS-MIB bsnAPTable for
# identity, CISCO-LWAPP-AP-MIB cLApTable for uptime. Both index by the AP's
# radio MAC as six bare sub-identifiers. Read live from a 9800 on 17.15:
# bsnApIpAddress (.19) is the address (.28, the static one, mirrors it);
# bsnAPEthernetMacAddress (.33) is the MAC switches see, while
# cLApIfMacAddress returns the radio MAC despite its description.
CISCO_AP_TABLE = ".1.3.6.1.4.1.14179.2.2.1.1"
CISCO_LWAPP_TABLE = ".1.3.6.1.4.1.9.9.513.1.1.1.1"
CISCO_COLUMNS = {3: "name", 6: "operation", 8: "firmware", 16: "model", 17: "serial", 19: "ip", 33: "ethernet_mac"}
CISCO_LWAPP_COLUMNS = {6: "uptime", 7: "join_uptime"}
# Walked one column at a time: the whole bsnAPTable is ~37 columns per AP.
CISCO_WALK_OIDS = tuple(f"{CISCO_AP_TABLE}.{column}" for column in CISCO_COLUMNS) + tuple(
    f"{CISCO_LWAPP_TABLE}.{column}" for column in CISCO_LWAPP_COLUMNS)
# bsnAPOperationStatus: associated(1), disassociating(2), downloading(3).
CISCO_OPERATION = {"1": "", "2": "disassociating", "3": "downloading image"}
# The join-statistics command: Catalyst 9800 first, AireOS as the fallback.
CISCO_JOIN_COMMANDS = ("show wireless stats ap join summary", "show ap join stats summary all")

CONTROLLER_FIELDS = ("mac", "controller_ip", "controller", "name", "ip", "model", "serial", "firmware",
                     "status", "uptime_s", "join_uptime_s", "polled_at", "detail")

_LINE = re.compile(r"^(\.[0-9.]+) = (.*)$")


@dataclass
class ControllerAP:
    mac: str
    name: str
    ip: str
    model: str = ""
    serial: str = ""
    firmware: str = ""
    status: str = "ONLINE"
    uptime_s: Optional[int] = None
    join_uptime_s: Optional[int] = None
    detail: str = ""


def parse_walk(text: str, table: str) -> Dict[str, Dict[int, str]]:
    """`snmpbulkwalk -On` output under `table`, as {row index: {column: raw value}}.

    A value net-snmp wraps onto further lines (a long Hex-STRING) is joined
    back to the line it started on.
    """
    rows: Dict[str, Dict[int, str]] = {}
    prefix = table.rstrip(".") + "."
    last: Optional[Dict[int, str]] = None
    last_col = 0
    for line in (text or "").splitlines():
        match = _LINE.match(line)
        if not match:
            if last is not None and line.strip():
                last[last_col] += " " + line.strip()
            continue
        oid, value = match.groups()
        last = None
        if not oid.startswith(prefix):
            continue
        column, _, index = oid[len(prefix):].partition(".")
        if not column.isdigit() or not index:
            continue
        last, last_col = rows.setdefault(index, {}), int(column)
        last[last_col] = value
    return rows


def value(raw: Optional[str]) -> str:
    """The value without net-snmp's type label: `STRING: "x"` -> `x`, `Timeticks: (5) ...` -> `5`."""
    raw = (raw or "").strip()
    if raw.startswith("Timeticks:"):
        match = re.search(r"\((\d+)\)", raw)
        return match.group(1) if match else ""
    raw = re.sub(r"^[A-Za-z0-9-]+: ?", "", raw, count=1) if re.match(r"^[A-Za-z0-9-]+:( |$)", raw) else raw
    if raw.startswith("No Such") or raw.startswith("No more"):
        return ""
    return raw[1:-1] if len(raw) >= 2 and raw[0] == raw[-1] == '"' else raw


def index_mac(index: str) -> str:
    """The MAC a table index encodes: six octets, optionally length-prefixed."""
    parts = index.split(".")
    if len(parts) == 7 and parts[0] == "6":
        parts = parts[1:]
    if len(parts) != 6 or not all(part.isdigit() and int(part) < 256 for part in parts):
        return ""
    return ":".join(f"{int(part):02x}" for part in parts)


def ticks_seconds(raw: Optional[str]) -> Optional[int]:
    ticks = value(raw)
    return int(ticks) // 100 if ticks.isdigit() else None


def _ipv4(text: str) -> str:
    return text if re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", text or "") and text != "0.0.0.0" else ""


def ruckus_aps(text: str) -> List[ControllerAP]:
    """Every AP in a SmartZone `ruckusSZAPTable` walk."""
    aps = []
    for index, row in parse_walk(text, RUCKUS_AP_TABLE).items():
        mac = index_mac(index)
        if not mac:
            continue
        connection = value(row.get(16))
        registration = value(row.get(17))
        connected = connection.lower() == "connect"
        notes = [] if connected else [connection or "no connection state"]
        if registration and registration.lower() != "approved":
            notes.append(f"registration {registration}")
        aps.append(ControllerAP(
            mac=mac, name=value(row.get(5)), ip=_ipv4(value(row.get(10))), model=value(row.get(8)),
            serial=value(row.get(9)), firmware=value(row.get(7)), status="ONLINE" if connected else "OFFLINE",
            uptime_s=ticks_seconds(row.get(6)) if connected else None, detail="; ".join(notes),
        ))
    return sorted(aps, key=lambda ap: (ap.name.lower(), ap.mac))


def octets_mac(raw: Optional[str]) -> str:
    """A MacAddress column's value: Hex-STRING octets, or the six characters
    net-snmp printed instead when every byte happened to be printable."""
    text = (raw or "").strip()
    if text.startswith("Hex-STRING:"):
        octets = text.split(":", 1)[1].split()
        if len(octets) == 6 and all(re.fullmatch(r"[0-9A-Fa-f]{2}", octet) for octet in octets):
            return ":".join(octet.lower() for octet in octets)
        return ""
    chars = value(text)
    if text.startswith("STRING:") and len(chars) == 6:
        return ":".join(f"{ord(char):02x}" for char in chars)
    return ""


def cisco_aps(text: str) -> List[ControllerAP]:
    """Every AP joined to a Cisco WLC, from walks of `CISCO_WALK_OIDS`."""
    identity = parse_walk(text, CISCO_AP_TABLE)
    lwapp = parse_walk(text, CISCO_LWAPP_TABLE)
    aps = []
    for index, row in identity.items():
        radio = index_mac(index)
        if not radio:
            continue
        times = lwapp.get(index, {})
        operation = value(row.get(6))
        aps.append(ControllerAP(
            mac=octets_mac(row.get(33)) or radio, name=value(row.get(3)), ip=_ipv4(value(row.get(19))),
            model=value(row.get(16)), serial=value(row.get(17)), firmware=value(row.get(8)), status="ONLINE",
            uptime_s=ticks_seconds(times.get(6)), join_uptime_s=ticks_seconds(times.get(7)),
            detail=CISCO_OPERATION.get(operation, f"operation status {operation}" if operation else ""),
        ))
    return sorted(aps, key=lambda ap: (ap.name.lower(), ap.mac))


def dotted_mac(text: str) -> str:
    """`0c75.bd12.3456`, `0c:75:bd:12:34:56`, or bare hex as `0c:75:bd:12:34:56`; anything else empty."""
    digits = re.sub(r"[^0-9a-f]", "", (text or "").lower())
    return ":".join(digits[i:i + 2] for i in range(0, 12, 2)) if len(digits) == 12 and re.fullmatch(r"[0-9a-f.:-]+", text.lower()) else ""


def join_rejected(output: str) -> bool:
    """The controller refused the command (a 9800 given the AireOS one, or the reverse)."""
    return bool(re.search(r"invalid autocommand|Invalid input detected|Incorrect usage|Unknown command", output or "", re.I))


def parse_join_summary(output: str) -> List[Dict[str, str]]:
    """Rows of a join-statistics table, by the header's own column positions.

    Catalyst 9800 `show wireless stats ap join summary`:
    `Base MAC  Ethernet MAC  AP Name  IP Address  Status  Last Failure Phase  Last Disconnect Reason`;
    AireOS `show ap join stats summary all`: `Base Mac  AP EthernetMac  AP Name  IP Address  Status`.
    A row is kept only when its first column is a MAC, so banners, prompts,
    and error text (`Line has invalid autocommand ...`) never become APs.
    """
    lines = (output or "").replace("\r", "").splitlines()
    header = next((i for i, line in enumerate(lines) if re.match(r"\s*Base Mac\b", line, re.I)), None)
    if header is None:
        return []
    head = lines[header]
    names = [match.group(0) for match in re.finditer(r"\S+(?: \S+)*", head)]
    starts = [match.start() for match in re.finditer(r"\S+(?: \S+)*", head)]
    canonical = {"base mac": "base_mac", "ethernet mac": "ethernet_mac", "ap ethernetmac": "ethernet_mac", "ap name": "name",
                 "ip address": "ip", "status": "status", "last failure phase": "failure_phase",
                 "last disconnect reason": "disconnect_reason"}
    keys = [canonical.get(name.lower(), name.lower()) for name in names]
    rows = []
    for line in lines[header + 1:]:
        if not line.strip() or re.fullmatch(r"[-\s]+", line):
            continue
        cells = {key: line[start:(starts[k + 1] if k + 1 < len(starts) else None)].strip() for k, (key, start) in enumerate(zip(keys, starts))}
        if not dotted_mac(cells.get("base_mac", "")):
            continue
        rows.append(cells)
    return rows


def unjoined_aps(join_rows: Sequence[Mapping[str, str]], joined: Sequence[ControllerAP]) -> List[ControllerAP]:
    """The APs join statistics list as not joined, minus what is joined now.

    A not-joined row whose MAC is joined, or whose name a joined AP carries
    (the old hardware of a replaced AP), is history rather than an AP that
    cannot join. The row's IP is where the AP last was, often reused by
    another AP since, so it goes in `detail`, not in the AP's address.
    """
    joined_macs = {ap.mac for ap in joined}
    joined_names = {ap.name.lower() for ap in joined if ap.name}
    out = []
    for row in join_rows:
        if row.get("status", "").lower() == "joined":
            continue
        mac = dotted_mac(row.get("ethernet_mac", "")) or dotted_mac(row.get("base_mac", ""))
        radio = dotted_mac(row.get("base_mac", ""))
        name = row.get("name", "")
        if not mac or mac in joined_macs or radio in joined_macs or name.lower() in joined_names:
            continue
        failure = " ".join(part for part in (row.get("failure_phase", ""), row.get("disconnect_reason", "")) if part)
        last_ip = _ipv4(row.get("ip", ""))
        notes = [row.get("status") or "not joined"] + ([f"last failure {failure}"] if failure else []) + ([f"last IP {last_ip}"] if last_ip else [])
        out.append(ControllerAP(mac=mac, name=name, ip="", status="OFFLINE", detail="; ".join(notes)))
    return sorted(out, key=lambda ap: (ap.name.lower(), ap.mac))


def joined_count(join_rows: Sequence[Mapping[str, str]]) -> Optional[int]:
    """How many APs the join statistics call joined: the SNMP walk should hold as many."""
    return sum(1 for row in join_rows if row.get("status", "").lower() == "joined") if join_rows else None


def in_scope(ap: ControllerAP, *, ip_prefixes: Sequence[str] = (), name_prefixes: Sequence[str] = (),
             name_contains: Sequence[str] = (), last_ip: str = "") -> bool:
    """Whether an AP on a shared controller is this site's: its address
    starts with an IP prefix, OR its name starts with a name prefix or
    contains a name substring. No filter configured keeps every AP. An
    unjoined AP is judged by the address it last had."""
    if not (ip_prefixes or name_prefixes or name_contains):
        return True
    address = ap.ip or last_ip
    name = (ap.name or "").upper()
    return (any(address.startswith(prefix) for prefix in ip_prefixes if prefix)
            or any(name.startswith(prefix.upper()) for prefix in name_prefixes if prefix)
            or any(token.upper() in name for token in name_contains if token))


def last_ip(ap: ControllerAP) -> str:
    match = re.search(r"last IP (\S+)", ap.detail or "")
    return match.group(1) if match else ""


def completeness(found: int, expected: Optional[int]) -> str:
    """Empty when the walk holds every AP the controller counts; otherwise why not."""
    if expected is None or found >= expected:
        return ""
    return f"walk returned {found} of the {expected} AP(s) the controller counts"


def pipe_rows(aps: Sequence[ControllerAP], *, controller_ip: str, controller: str, vendor: str, now: int) -> str:
    """AP pipe rows (`ap_merge.AP_FIELDS`) for the scan's controller file.

    The platform names the model ("Ruckus R610") so `ap_merge.pick_platform`
    prefers it over a switch's generic description. An AP with no address is
    keyed by its MAC, as the unjoined Cisco rows already are.
    """
    lines = []
    for ap in aps:
        key = ap.ip or "wlc:" + ap.mac.replace(":", "")
        platform = f"{vendor} {ap.model}" if ap.model else f"{vendor}-AP"
        # An AP the controller knows but has not joined has no attachment at
        # all; `ap unjoined` lists these.
        port = "not-joined" if not ap.ip and ap.status == "OFFLINE" and vendor == "Cisco" else "wireless"
        # Bare hex MAC, the AP cache's own form.
        fields = (key, ap.name or f"{vendor}-AP", platform, controller_ip, controller, port, ap.mac.replace(":", ""), str(now), ap.status)
        lines.append("|".join(_clean(field) for field in fields))
    return "".join(line + "\n" for line in lines)


def sidecar_rows(aps: Sequence[ControllerAP], *, controller_ip: str, controller: str, now: int) -> List[Dict[str, str]]:
    return [{
        "mac": ap.mac, "controller_ip": controller_ip, "controller": controller, "name": ap.name, "ip": ap.ip,
        "model": ap.model, "serial": ap.serial, "firmware": ap.firmware, "status": ap.status,
        "uptime_s": "" if ap.uptime_s is None else str(ap.uptime_s),
        "join_uptime_s": "" if ap.join_uptime_s is None else str(ap.join_uptime_s),
        "polled_at": str(now), "detail": ap.detail,
    } for ap in aps]


def parse_sidecar(text: str) -> List[Dict[str, str]]:
    rows = []
    for line in (text or "").splitlines():
        if not line.strip():
            continue
        parts = line.split("|") + [""] * len(CONTROLLER_FIELDS)
        rows.append(dict(zip(CONTROLLER_FIELDS, parts[:len(CONTROLLER_FIELDS)])))
    return rows


def render_sidecar(rows: Sequence[Mapping[str, str]]) -> str:
    return "".join("|".join(_clean(str(row.get(field, ""))) for field in CONTROLLER_FIELDS) + "\n" for row in rows)


def replace_controller(existing: Sequence[Mapping[str, str]], controller_ip: str,
                       fresh: Sequence[Mapping[str, str]]) -> List[Dict[str, str]]:
    """The sidecar after one controller's poll: its rows replaced, other controllers' kept."""
    kept = [dict(row) for row in existing if row.get("controller_ip") != controller_ip]
    return sorted(kept + [dict(row) for row in fresh], key=lambda row: (row["controller_ip"], row["name"].lower(), row["mac"]))


def _clean(text: str) -> str:
    return re.sub(r"[|\r\n]", " ", text or "").strip()
