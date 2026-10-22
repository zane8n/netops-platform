#!/usr/bin/env python3
"""Pure parsers and normalizers for network-read Netrune workflows."""

from __future__ import annotations

import contextlib
import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional

from netops_platform.identity import normalize_mac


ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
MAC_TOKEN_RE = re.compile(
    r"(?i)(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}|"
    r"[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}|"
    r"[0-9a-f]{6}-[0-9a-f]{6}|[0-9a-f]{12}"
)


def clean_network_output(value: Any) -> str:
    text = str(value or "").replace("\r", "")
    return ANSI_RE.sub("", text).replace("\x00", "")


def normalize_interface(value: Any) -> str:
    """Return a comparison key for common Cisco/Aruba interface spellings."""
    text = re.sub(r"\s+", "", str(value or "").strip().lower())
    replacements = (
        ("twentyfivegigabitethernet", "twe"),
        ("fortygigabitethernet", "fo"),
        ("hundredgigabitethernet", "hu"),
        ("tengigabitethernet", "te"),
        ("gigabitethernet", "gi"),
        ("fastethernet", "fa"),
        ("port-channel", "po"),
        ("portchannel", "po"),
        ("ethernet", "eth"),
        ("trunk", "trk"),
    )
    for long_name, short_name in replacements:
        if text.startswith(long_name):
            text = short_name + text[len(long_name):]
            break
    return text.rstrip(",;:")


def interface_matches(left: Any, right: Any) -> bool:
    a, b = normalize_interface(left), normalize_interface(right)
    return bool(a and b and a == b)


def _split_ports(value: Any) -> List[str]:
    text = str(value or "").strip()
    if not text or text.lower() == "none":
        return []
    return [item.strip() for item in re.split(r"\s*,\s*|\s+", text) if item.strip()]


def parse_vlan_control_output(value: Any, mode: str = "propagation") -> Dict[str, Any]:
    """Parse the stable, human-readable netrune-control VLAN reports."""
    text = clean_network_output(value)
    lower = text.lower()
    result: Dict[str, Any] = {
        "defined": None,
        "access_ports": [],
        "trunks": [],
        "device_name": "",
        "device_ip": "",
        "error": "",
    }
    if re.search(r"\b(?:ssh|connection|authentication).*(?:failed|denied|timed out)|no targets resolved|platform unknown", lower):
        result["error"] = "device inspection failed"

    header = re.search(r"Propagation Map for:\s*(.+?)\s*\(([^)]+)\)", text, re.I)
    if header:
        result["device_name"] = header.group(1).strip()
        result["device_ip"] = header.group(2).strip()
    locate_header = re.search(r"\[([^]]+)\]\s+(.+?)\s+->\s+(DEFINED|NOT DEFINED)", text, re.I)
    if locate_header:
        result["device_ip"] = locate_header.group(1).strip()
        result["device_name"] = locate_header.group(2).strip()
        result["defined"] = locate_header.group(3).upper() == "DEFINED"

    status = re.search(r"Target VLAN:\s*\d+\s*\|\s*Status:\s*(DEFINED|NOT DEFINED)", text, re.I)
    if status:
        result["defined"] = status.group(1).upper() == "DEFINED"
    elif re.search(r"\bNOT DEFINED\b", text, re.I):
        result["defined"] = False

    access = re.search(r"Access Ports:\s*([^\n]+)", text, re.I)
    if access:
        result["access_ports"] = _split_ports(access.group(1))
    located_trunks = re.search(r"Trunk Ports:\s*([^\n]+)", text, re.I)
    if located_trunks:
        result["trunks"] = [
            {"port": port, "carries_vlan": True, "neighbor_name": "", "neighbor_ip": ""}
            for port in _split_ports(located_trunks.group(1))
        ]

    if mode == "propagation" or "Propagation Map" in text:
        trunks: List[Dict[str, Any]] = []
        pattern = re.compile(
            r"^\s*-\s*([^:\s]+)\s*:\s*(PROPAGATED|MISSING)"
            r"(?:\s*->\s*(?:Adj Switch:\s*)?([^\n(]+?)?(?:\s*\(([^)]+)\))?)?\s*$",
            re.I | re.M,
        )
        for match in pattern.finditer(text):
            trunks.append({
                "port": match.group(1).strip(),
                "carries_vlan": match.group(2).upper() == "PROPAGATED",
                "neighbor_name": (match.group(3) or "").strip(),
                "neighbor_ip": (match.group(4) or "").strip(),
            })
        if trunks:
            result["trunks"] = trunks
    return result


def parse_vlan_table_output(value: Any) -> Dict[str, Any]:
    """Parse a switch-wide `show vlan` table.

    Covers the Aruba AOS-S "Status and Counters" table, the AOS-CX and Cisco
    column tables, and FastIron's stanza listing. The management VLAN is
    reported only when the device states it: AOS-S prints the field but leaves
    it blank when unset, and treating a blank as "no management VLAN" is
    correct where guessing from a VLAN name is not.
    """
    text = clean_network_output(value)
    result: Dict[str, Any] = {
        "vlans": [],
        "primary_vlan": "",
        "management_vlan": None,
        "max_vlans": None,
        "parsed": False,
        "unsupported": False,
    }
    if _is_unsupported_command(text):
        result["unsupported"] = True
        return result

    # Horizontal-only whitespace: `\s` spans newlines, which lets a field the
    # device prints empty swallow the next lines of the report.
    primary = re.search(r"^[ \t]*Primary VLAN[ \t]*:[ \t]*(\S.*?)[ \t]*$", text, re.I | re.M)
    if primary:
        result["primary_vlan"] = primary.group(1).strip()
    maximum = re.search(r"^[ \t]*Maximum VLANs to support[ \t]*:[ \t]*(\d+)", text, re.I | re.M)
    if maximum:
        result["max_vlans"] = int(maximum.group(1))
    management = re.search(r"^[ \t]*Management VLAN[ \t]*:[ \t]*(\S.*?)?[ \t]*$", text, re.I | re.M)
    if management and management.group(1):
        result["management_vlan"] = management.group(1).strip()

    seen: Dict[int, Dict[str, Any]] = {}
    for line in text.splitlines():
        if "|" in line:
            # AOS-S: "  4   Management-of-Switch-Range  | Port-based No    No"
            left, _, right = line.partition("|")
            head = left.split()
            if not head or not head[0].isdigit():
                continue
            tail = right.split()
            entry = {
                "vlan": int(head[0]),
                "name": " ".join(head[1:]),
                "status": tail[0] if tail else "",
                "voice": _yes_no(tail[1]) if len(tail) > 1 else None,
                "jumbo": _yes_no(tail[2]) if len(tail) > 2 else None,
                "interfaces": [],
            }
            seen.setdefault(entry["vlan"], entry)
            continue
        fields = line.split()
        if len(fields) < 2 or not fields[0].isdigit():
            continue
        if re.match(r"^\s*(?:VLAN|----)", line, re.I):
            continue
        # AOS-CX: "4  MGMT  up  ok  static  1/1/3"  |  Cisco: "4  MGMT  active  Gi1/0/3, Gi1/0/4"
        vlan_id = int(fields[0])
        status_index = next(
            (index for index, token in enumerate(fields[1:], start=1)
             if token.lower() in {"up", "down", "active", "act/lshut", "suspended"}),
            0,
        )
        if not status_index:
            continue
        entry = {
            "vlan": vlan_id,
            "name": " ".join(fields[1:status_index]),
            "status": fields[status_index],
            "voice": None,
            "jumbo": None,
            # AOS-CX puts Reason and Type between the status and the port list;
            # Cisco puts the ports there directly. Every port name carries a
            # digit, while "ok", "default", and "static" do not.
            "interfaces": [
                port for port in _split_ports(" ".join(fields[status_index + 1:]).replace(",", " "))
                if any(character.isdigit() for character in port)
            ],
        }
        seen.setdefault(vlan_id, entry)

    result["vlans"] = [seen[key] for key in sorted(seen)]
    result["parsed"] = bool(result["vlans"])
    return result


# Capability letters as printed by the compact CDP neighbour table.
CDP_CAPABILITY_NAMES = {
    "R": "router", "S": "switch", "H": "host", "I": "igmp",
    "r": "repeater", "P": "phone", "M": "remote-management",
    "B": "bridge", "T": "trans-bridge", "W": "wlan-ap",
}
# Media keywords that indicate an optical port. Fibre on an access switch is
# almost always an uplink, so it corroborates the other signals.
FIBER_MEDIA_RE = re.compile(
    r"(?i)\b(?:\d+)?(?:base)?(?:LX|SX|LR|SR|ER|ZR|LH|LX4|CX4|CWDM|DWDM)\b|\bSFP\b|\bXFP\b|\bQSFP\b|\bfiber\b|\bfibre\b"
)


def parse_cdp_neighbors_table(value: Any) -> List[Dict[str, Any]]:
    """Parse the compact `show cdp neighbors` table used by Aruba AOS-S.

    Rows look like::

        1      90 3a 72 07 8e d0   | Ruckus R610 Multimedia Ho... R S
        19     40 f4 9f 60 6a 00   | Cisco IOS Software [Dubli... S

    The capability letters sit at the end of the right-hand column, so they are
    read from the right and the remainder is the platform string.
    """
    text = clean_network_output(value)
    rows: List[Dict[str, Any]] = []
    if _is_unsupported_command(text):
        return rows
    for line in text.splitlines():
        if "|" not in line or set(line.strip()) <= set("-+| "):
            continue
        left, _, right = line.partition("|")
        head = left.split()
        if not head or not re.fullmatch(r"[A-Za-z]*\d[\w/.-]*", head[0]):
            continue
        if head[0].lower() in {"port", "local"}:
            continue
        tail = right.split()
        capabilities: List[str] = []
        while tail and len(tail[-1]) == 1 and tail[-1].isalpha():
            capabilities.insert(0, tail.pop())
        rows.append({
            "port": head[0],
            "device_id": " ".join(head[1:]),
            "platform": " ".join(tail),
            "capabilities": capabilities,
            "capability_names": [CDP_CAPABILITY_NAMES.get(item, item) for item in capabilities],
            # A neighbour advertising switch and nothing else is infrastructure.
            # Access points add R, phones add P/H/M, so those are not uplinks.
            "switch_only": capabilities == ["S"],
        })
    return rows


def expand_vlan_list(value: Any) -> List[int]:
    """Expand a Cisco VLAN list such as `4-5,15,40,104` into individual ids."""
    vlans: List[int] = []
    text = re.sub(r"\s+", "", str(value or ""))
    if not text or text.lower() in {"none", "all"}:
        return [0] if text.lower() == "all" else []
    for chunk in text.split(","):
        if not chunk:
            continue
        if "-" in chunk:
            start, _, end = chunk.partition("-")
            if start.isdigit() and end.isdigit() and int(start) <= int(end):
                vlans.extend(range(int(start), min(int(end), 4094) + 1))
        elif chunk.isdigit():
            vlans.append(int(chunk))
    return sorted(set(vlans))


def parse_trunk_summary(value: Any) -> Dict[str, Dict[str, Any]]:
    """Parse Cisco `show interfaces trunk` into per-port trunk facts.

    The command prints the same ports under four headings. Mode, status and
    native VLAN come from the first; the allowed and forwarding VLAN lists come
    from the later ones, which is what distinguishes an uplink carrying the
    whole VLAN range from an access-layer trunk carrying a handful.
    """
    text = clean_network_output(value)
    ports: Dict[str, Dict[str, Any]] = {}
    section = ""
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or set(stripped) <= set("-"):
            continue
        lowered = stripped.lower()
        if lowered.startswith("port"):
            if "vlans allowed on trunk" in lowered:
                section = "allowed"
            elif "vlans allowed and active" in lowered:
                section = "active"
            elif "forwarding state" in lowered:
                section = "forwarding"
            elif "mode" in lowered and "encapsulation" in lowered:
                section = "status"
            else:
                section = ""
            continue
        fields = stripped.split()
        if len(fields) < 2 or not re.match(r"^[A-Za-z]+[0-9]", fields[0]):
            continue
        entry = ports.setdefault(fields[0], {
            "port": fields[0], "mode": "", "encapsulation": "", "status": "",
            "native_vlan": 0, "allowed_vlans": [], "active_vlans": [], "forwarding_vlans": [],
        })
        if section == "status" and len(fields) >= 5:
            entry["mode"] = fields[1]
            entry["encapsulation"] = fields[2]
            entry["status"] = fields[3]
            entry["native_vlan"] = int(fields[4]) if fields[4].isdigit() else 0
        elif section in {"allowed", "active", "forwarding"}:
            entry[f"{section}_vlans"] = expand_vlan_list(fields[1])
    return ports


def classify_uplink_ports(
    stp_ports: Optional[Iterable[Mapping[str, Any]]] = None,
    cdp_rows: Optional[Iterable[Mapping[str, Any]]] = None,
    trunks: Optional[Mapping[str, Mapping[str, Any]]] = None,
    management_vlan: int = 0,
) -> Dict[str, Dict[str, Any]]:
    """Decide which ports face other switches, and say why.

    Spanning tree alone is not enough. A port whose neighbour also runs STP is
    marked `Edge No`, but a switch that does not participate in this region's
    spanning tree still leaves the port looking like an edge port. A CDP
    neighbour advertising the switch capability and nothing else settles it,
    and optical media corroborates.
    """
    verdicts: Dict[str, Dict[str, Any]] = {}

    def record(port: Any, reason: str, confidence: int, evidence: Optional[Dict[str, Any]] = None) -> None:
        key = str(port or "").strip()
        if not key:
            return
        entry = verdicts.setdefault(key, {"port": key, "reasons": [], "confidence": 0, "evidence": {}})
        if reason not in entry["reasons"]:
            entry["reasons"].append(reason)
        entry["confidence"] = max(entry["confidence"], confidence)
        entry["evidence"].update(evidence or {})

    for row in cdp_rows or ():
        if row.get("switch_only"):
            record(row.get("port"), "cdp-switch-only", 95, {
                "cdp_device": row.get("device_id") or "",
                "cdp_platform": row.get("platform") or "",
            })

    for row in stp_ports or ():
        state = str(row.get("state") or "").lower()
        if state != "forwarding":
            continue
        media = str(row.get("type") or row.get("media") or "")
        if not row.get("edge"):
            record(row.get("port"), "stp-forwarding-non-edge", 90, {"stp_role": row.get("role") or ""})
        if media and FIBER_MEDIA_RE.search(media):
            # On its own this is a hint, not proof: fibre can serve a server.
            record(row.get("port"), "fiber-media", 70, {"media": media})

    # A Cisco trunk carrying the management VLAN reaches the rest of the
    # infrastructure; an access-layer trunk to a phone or AP carries only its
    # own few VLANs and does not. This is what separates Te1/1/3 from Gi1/0/1.
    for port_name, trunk in (trunks or {}).items():
        if str(trunk.get("status") or "").lower() not in {"trunking", "", "up"}:
            continue
        allowed = list(trunk.get("allowed_vlans") or [])
        carries_management = bool(management_vlan) and management_vlan in allowed
        if carries_management:
            record(port_name, "trunk-carries-management-vlan", 92, {
                "allowed_vlan_count": len(allowed),
                "native_vlan": trunk.get("native_vlan") or 0,
            })
        elif len(allowed) >= 10:
            # No management VLAN known: a broad trunk is still infrastructure,
            # but say so with lower confidence than a positive VLAN match.
            record(port_name, "trunk-carries-many-vlans", 85, {"allowed_vlan_count": len(allowed)})

    for entry in verdicts.values():
        entry["uplink"] = entry["confidence"] >= 90
    return verdicts


STP_FORWARDING_STATES = {"forwarding", "fwd", "learning", "lrn"}
STP_BLOCKED_STATES = {"blocking", "blk", "discarding", "dis", "disabled", "listening", "lis", "broken", "bkn"}


def _stp_state(value: Any) -> str:
    """Map a vendor state token onto forwarding/blocking/disabled/unknown."""
    text = str(value or "").strip().lower()
    if text in {"disabled", "dis", "down"}:
        return "disabled"
    if text in {"forwarding", "fwd"}:
        return "forwarding"
    if text in {"learning", "lrn", "listening", "lis"}:
        return "transitioning"
    if text in STP_BLOCKED_STATES:
        return "blocking"
    return "unknown"


def _stp_role(value: Any) -> str:
    text = str(value or "").strip().lower()
    return {
        "root": "root", "desg": "designated", "designated": "designated",
        "altn": "alternate", "alternate": "alternate", "back": "backup",
        "backup": "backup", "disabled": "disabled", "dsbl": "disabled",
    }.get(text, text)


def parse_spanning_tree_output(value: Any) -> Dict[str, Any]:
    """Parse `show spanning-tree` from Aruba AOS-S, Aruba AOS-CX, and Cisco IOS.

    AOS-S in MSTP mode prints a pipe-delimited port table and states the role
    only indirectly, so the role is derived: the CST root port is the path
    toward the root bridge, a port whose designated bridge is this switch is
    downstream, and an explicit `Edge Yes` marks a host-facing port. AOS-CX and
    Cisco state the role directly and are taken at their word.
    """
    text = clean_network_output(value)
    result: Dict[str, Any] = {
        "mode": "",
        "enabled": None,
        "switch_mac": "",
        "switch_priority": None,
        "root_mac": "",
        "root_priority": None,
        "root_port": "",
        "root_path_cost": None,
        "regional_root_mac": "",
        "is_root": False,
        "topology_changes": None,
        "ports": [],
        "parsed": False,
        "unsupported": False,
    }
    if _is_unsupported_command(text):
        result["unsupported"] = True
        return result

    def field(*patterns: str) -> str:
        for pattern in patterns:
            match = re.search(pattern, text, re.I | re.M)
            if match:
                return match.group(1).strip()
        return ""

    enabled = field(r"^[ \t]*STP Enabled[ \t]*:[ \t]*(\S+)", r"^[ \t]*Spanning tree status[ \t]*:[ \t]*(\S+)")
    if enabled:
        result["enabled"] = enabled.lower() in {"yes", "enabled", "true"}
    # Read the mode from the fields that declare it. Scanning the whole report
    # would match AOS-S's "PVST Protected Ports" list and misreport MSTP.
    force_version = field(r"^[ \t]*Force Version[ \t]*:[ \t]*(\S+)")
    protocol = field(r"Spanning tree enabled protocol[ \t]+(\S+)", r"^[ \t]*Spanning Tree Mode[ \t]*:[ \t]*(\S+)")
    banner = field(r"^[ \t]*(Multiple Spanning Tree|Rapid Spanning Tree|Rapid Per-VLAN Spanning Tree)")
    evidence = f"{force_version} {protocol} {banner}".lower()
    for token, mode in (("mstp", "mstp"), ("multiple spanning tree", "mstp"),
                        ("rapid-pvst", "rpvst"), ("rpvst", "rpvst"),
                        ("rapid per-vlan", "rpvst"), ("pvst", "pvst"),
                        ("rstp", "rstp"), ("rapid spanning tree", "rstp"), ("stp", "stp")):
        if token in evidence:
            result["mode"] = mode
            break

    result["switch_mac"] = normalize_mac(field(
        r"^[ \t]*Switch MAC Address[ \t]*:[ \t]*(\S+)",
        r"^[ \t]*Bridge ID\s+Priority\s*:.*?\n\s*MAC-Address[ \t]*:[ \t]*(\S+)",
        r"^[ \t]*Bridge ID\s+Priority\s+\d+[^\n]*\n[ \t]*Address\s+(\S+)",
    ))
    result["root_mac"] = normalize_mac(field(
        r"^[ \t]*CST Root MAC Address[ \t]*:[ \t]*(\S+)",
        r"^[ \t]*Root ID\s+Priority\s*:.*?\n\s*MAC-Address[ \t]*:[ \t]*(\S+)",
        r"^[ \t]*Root ID\s+Priority\s+\d+[^\n]*\n[ \t]*Address\s+(\S+)",
    ))
    result["regional_root_mac"] = normalize_mac(field(r"^[ \t]*IST Regional Root MAC Address[ \t]*:[ \t]*(\S+)"))
    result["root_port"] = field(r"^[ \t]*CST Root Port[ \t]*:[ \t]*(\S+)", r"^[ \t]*Port\s+(\d+)\s*\(")
    for key, pattern in (
        ("switch_priority", r"^[ \t]*Switch Priority[ \t]*:[ \t]*(\d+)"),
        ("root_priority", r"^[ \t]*CST Root Priority[ \t]*:[ \t]*(\d+)"),
        ("root_path_cost", r"^[ \t]*CST Root Path Cost[ \t]*:[ \t]*(\d+)"),
        ("topology_changes", r"^[ \t]*Topology Change Count[ \t]*:[ \t]*([\d,]+)"),
    ):
        raw = field(pattern)
        if raw:
            result[key] = int(raw.replace(",", ""))
    result["is_root"] = bool(
        re.search(r"This bridge is the root|We are the root", text, re.I)
        or (result["switch_mac"] and result["switch_mac"] == result["root_mac"])
    )

    ports: List[Dict[str, Any]] = []
    current_vlan = 0
    for line in text.splitlines():
        instance = re.match(r"^\s*(?:VLAN|MST)0*(\d+)\s*$", line, re.I)
        if instance:
            current_vlan = int(instance.group(1))
            continue
        row = _parse_aos_s_stp_row(line) if line.count("|") >= 2 else _parse_columnar_stp_row(line)
        if row:
            row["vlan"] = current_vlan
            ports.append(row)
    ports = [port for port in ports if port]

    root_port = normalize_interface(result["root_port"])
    for port in ports:
        if not port.get("role"):
            if port["state"] == "disabled":
                port["role"] = "disabled"
            elif port["edge"]:
                port["role"] = "edge"
            elif root_port and normalize_interface(port["port"]) == root_port:
                port["role"] = "root"
            elif port["designated_bridge"] and port["designated_bridge"] == result["switch_mac"]:
                port["role"] = "designated"
            elif port["designated_bridge"] and port["state"] == "blocking":
                # Not forwarding, not this switch's segment: a redundant link
                # held down by spanning tree.
                port["role"] = "alternate"
            elif port["state"] == "forwarding":
                port["role"] = "network"
        port["forwarding"] = port["state"] == "forwarding"
        # A forwarding, non-edge port faces other infrastructure, which is what
        # makes it a candidate uplink for topology and VLAN propagation.
        port["network_facing"] = bool(port["forwarding"] and not port["edge"] and port["role"] != "edge")

    result["ports"] = ports
    result["parsed"] = bool(ports or result["switch_mac"] or result["enabled"] is not None)
    return result


def _parse_aos_s_stp_row(line: str) -> Optional[Dict[str, Any]]:
    """Parse one Aruba AOS-S MSTP port row.

    The row is `Port Type | Cost Prio State | DesignatedBridge Hello PtP Edge`.
    Both the type and the designated bridge are blank on unused ports, so each
    pipe-delimited segment is read from the end where its columns are fixed.
    """
    left, middle, right = (segment.strip() for segment in line.split("|", 2))
    head = left.split()
    if not head or not re.fullmatch(r"[A-Za-z]*\d[\w/.-]*", head[0]):
        return None
    center = middle.split()
    if len(center) < 3:
        return None
    tail = right.split()
    if len(tail) < 3:
        return None
    return {
        "port": head[0],
        "type": " ".join(head[1:]),
        "cost": center[0],
        "priority": center[1],
        "state": _stp_state(center[2]),
        "state_text": center[2],
        "designated_bridge": normalize_mac(tail[-4]) if len(tail) >= 4 else "",
        "hello_time": tail[-3],
        "point_to_point": _yes_no(tail[-2]),
        "edge": _yes_no(tail[-1]) is True,
        "role": "",
    }


def _parse_columnar_stp_row(line: str) -> Optional[Dict[str, Any]]:
    """Parse one Cisco IOS or Aruba AOS-CX spanning-tree port row."""
    fields = line.split()
    if len(fields) < 4 or not re.fullmatch(r"[A-Za-z]*\d[\w/.-]*", fields[0]):
        return None
    role = _stp_role(fields[1])
    if role not in {"root", "designated", "alternate", "backup", "disabled"}:
        return None
    state = _stp_state(fields[2])
    if state == "unknown":
        return None
    remainder = " ".join(fields[3:]).lower()
    return {
        "port": fields[0],
        "type": " ".join(fields[5:]) if len(fields) > 5 else "",
        "cost": fields[3] if len(fields) > 3 else "",
        "priority": fields[4] if len(fields) > 4 else "",
        "state": state,
        "state_text": fields[2],
        "designated_bridge": "",
        "hello_time": "",
        "point_to_point": "p2p" in remainder or "point_to_point" in remainder,
        "edge": "edge" in remainder,
        "role": role,
    }


def _yes_no(value: Any) -> Optional[bool]:
    text = str(value or "").strip().lower()
    if text in {"yes", "y", "true", "enabled"}:
        return True
    if text in {"no", "n", "false", "disabled"}:
        return False
    return None


def _is_unsupported_command(text: str) -> bool:
    return bool(re.search(
        r"(?im)^\s*(?:%\s*)?(?:invalid input|unknown command|unrecognized command|command not found|"
        r"(?:command|feature).{0,40}not supported|not supported.{0,40}(?:command|feature))\b",
        text,
    ))


def _neighbor_block_value(block: str, patterns: Iterable[str]) -> str:
    for pattern in patterns:
        match = re.search(pattern, block, re.I | re.M)
        if match:
            return match.group(1).strip().strip('"')
    return ""


def parse_neighbor_detail_output(value: Any) -> List[Dict[str, Any]]:
    """Parse common Cisco CDP/LLDP and Aruba LLDP detail output."""
    text = clean_network_output(value)
    records: List[Dict[str, Any]] = []

    # CDP detail blocks begin with Device ID and include the local interface.
    # Cisco writes "Interface: Gi1/0/5,  Port ID (outgoing port): ..."; AOS-S
    # indents its fields and writes "Port : 5" and "Device Port : ...".
    # AOS-S heads each entry "CDP neighbors information for port N" and lists
    # "Port : N" before the Device ID, so its entries split on that header.
    boundary = (r"(?=^[ \t]*CDP neighbors information for port\b)" if re.search(r"^[ \t]*CDP neighbors information for port\b", text, re.I | re.M)
                else r"(?=^[ \t]*Device ID\s*:)")
    for block in re.split(boundary, text, flags=re.I | re.M):
        if not re.search(r"^[ \t]*Device ID\s*:", block, re.I | re.M):
            continue
        name = _neighbor_block_value(block, [r"^[ \t]*Device ID\s*:\s*(.+)$"])
        local = _neighbor_block_value(block, [r"^Interface\s*:\s*([^,]+)", r"^[ \t]*Port\s*:\s*(\S+)\s*$"])
        remote_port = _neighbor_block_value(block, [r"Port ID \(outgoing port\)\s*:\s*(.+)$", r"^[ \t]*Device Port\s*:\s*(.+)$"])
        platform = _neighbor_block_value(block, [r"^[ \t]*Platform\s*:\s*([^,\n]+)"])
        capabilities = _neighbor_block_value(block, [r"Capabilities\s*:\s*(.+)$", r"^[ \t]*Capability\s*:\s*(.+)$"])
        ips = IP_RE.findall(block)
        records.append({
            "protocol": "cdp",
            "local_port": local,
            "remote_name": name,
            "remote_port": remote_port,
            "remote_ip": ips[0] if ips else "",
            "platform": platform,
            "capabilities": capabilities,
        })

    # LLDP detail output varies, but Local Intf/Port and System Name are stable.
    lldp_starts = list(re.finditer(r"^[ \t]*(?:Local (?:Intf|Port id|Port)|LocalPort)[ \t]*:[ \t]*", text, re.I | re.M))
    for index, start in enumerate(lldp_starts):
        end = lldp_starts[index + 1].start() if index + 1 < len(lldp_starts) else len(text)
        block = text[start.start():end]
        local = _neighbor_block_value(block, [r"^[ \t]*Local (?:Intf|Port id|Port)[ \t]*:[ \t]*(.+)$", r"^[ \t]*LocalPort[ \t]*:[ \t]*(.+)$"])
        name = _neighbor_block_value(block, [r"^[ \t]*System Name[ \t]*:[ \t]*(.+)$", r"^[ \t]*SysName[ \t]*:[ \t]*(.+)$"])
        remote_port = _neighbor_block_value(block, [r"^[ \t]*Port ?[Ii]d[ \t]*:[ \t]*(.+)$", r"^[ \t]*Port ?Desc(?:ription|r)[ \t]*:[ \t]*(.+)$"])
        platform = _neighbor_block_value(block, [r"^[ \t]*System Descr(?:iption)?[ \t]*:[ \t]*(.+)$"])
        if not platform:
            # Cisco IOS puts the description on the line after its label.
            following = re.search(r"^[ \t]*System Description[ \t]*:[ \t]*\n[ \t]*(\S.*)$", block, re.I | re.M)
            platform = following.group(1).strip() if following else ""
        capabilities = _neighbor_block_value(block, [r"^[ \t]*System Capabilities Enabled[ \t]*:[ \t]*(.+)$", r"^[ \t]*Enabled Capabilities[ \t]*:[ \t]*(.+)$", r"^[ \t]*System Capabilities(?: Supported)?[ \t]*:[ \t]*(.+)$"])
        # The management address, not an address that only appears in the
        # description or a VLAN name, is the neighbour's own.
        managed = re.search(r"Management Address(?:es)?.*?((?:\d{1,3}\.){3}\d{1,3})", block, re.I | re.S)
        ips = [managed.group(1)] if managed else IP_RE.findall(block)
        chassis = _neighbor_block_value(block, [r"^[ \t]*ChassisId[ \t]*:[ \t]*(.+)$", r"^[ \t]*Chassis id[ \t]*:[ \t]*(.+)$"])
        if local and (name or remote_port or ips):
            records.append({
                "protocol": "lldp",
                "local_port": local,
                "remote_mac": normalize_mac(chassis),
                "remote_name": name,
                "remote_port": remote_port,
                "remote_ip": ips[0] if ips else "",
                "platform": platform,
                "capabilities": capabilities,
            })

    # Aruba AOS-S uses a pipe-separated LLDP summary when no port is supplied.
    for line in text.splitlines():
        match = re.match(
            r"^\s*(\S+)\s*\|\s*((?:[0-9A-Fa-f]{2}[ :.-]+){5}[0-9A-Fa-f]{2}|\S+)\s+(\S+)\s+(\S+)\s+(.+?)\s*$",
            line,
        )
        if not match or match.group(1).lower() in {"localport", "port"}:
            continue
        records.append({
            "protocol": "lldp",
            "local_port": match.group(1),
            "remote_name": match.group(5).strip(),
            "remote_port": match.group(3),
            "remote_ip": "",
            "platform": "",
            "capabilities": "",
        })

    # AOS-CX and newer switch families commonly provide a fixed-column table.
    for line in text.splitlines():
        match = re.match(
            r"^\s*(\S+)\s+([0-9A-Fa-f][0-9A-Fa-f:.-]{10,})\s+(\S+)\s+(\S+)\s+(\d+)\s+(.+?)\s*$",
            line,
        )
        if not match or match.group(1).upper() in {"LOCAL-PORT", "PORT"}:
            continue
        records.append({
            "protocol": "lldp",
            "local_port": match.group(1),
            "remote_name": match.group(6).strip(),
            "remote_port": match.group(3),
            "remote_ip": "",
            "platform": "",
            "capabilities": "",
        })

    unique: Dict[tuple, Dict[str, Any]] = {}
    for row in records:
        key = (normalize_interface(row.get("local_port")), str(row.get("remote_name") or "").lower(), row.get("remote_ip"))
        if key[0] and (key[1] or key[2]):
            unique[key] = row
    return list(unique.values())


def _looks_like_interface(value: str) -> bool:
    token = value.strip().strip(",;()")
    if not token or token.lower() in {"yes", "no", "learn", "forward", "dynamic", "static", "secure", "self"}:
        return False
    return bool(re.match(r"(?i)^(?:gi|gig|te|ten|fa|eth|et|twe|fo|hu|po|port-channel|trk|lag|vlan|ve|[a-z]?\d)[a-z0-9./:_-]*$", token))


def parse_mac_table_output(value: Any, requested_mac: Any) -> List[Dict[str, Any]]:
    """Extract MAC, VLAN, entry type, and port from Cisco/Aruba FDB output."""
    wanted = normalize_mac(requested_mac)
    if not wanted:
        return []
    hits: List[Dict[str, Any]] = []
    for raw in clean_network_output(value).splitlines():
        match = MAC_TOKEN_RE.search(raw)
        if not match or normalize_mac(match.group(0)) != wanted:
            continue
        before = raw[:match.start()].strip().split()
        after = raw[match.end():].strip().split()
        # Ignore command echo and wrapper text.
        if "show" in {item.lower() for item in before[-2:]} or re.search(r"(?i)mac (?:address-table|address)\s*\|", raw):
            continue
        vlan = ""
        for token in reversed(before):
            if re.fullmatch(r"\d{1,4}", token):
                vlan = token
                break
        if not vlan:
            for token in after:
                if re.fullmatch(r"\d{1,4}", token):
                    vlan = token
                    break
        entry_type = next((token.upper() for token in after if token.lower() in {"dynamic", "static", "secure", "self", "learned"}), "")
        port = next((token.strip(",;()") for token in reversed(after) if _looks_like_interface(token)), "")
        if port == vlan and len(after) > 1:
            port = next((token.strip(",;()") for token in reversed(after[1:]) if _looks_like_interface(token) and token != vlan), port)
        if not port and after:
            candidate = after[-1].strip(",;()")
            if candidate and candidate != vlan:
                port = candidate
        if not port:
            # A forwarding-table entry always names a port. A line carrying the
            # address with nothing after it is a command echo or a summary
            # line, and treating it as a location puts the device on every
            # switch that was merely asked about it.
            continue
        hits.append({
            "mac": wanted,
            "mac_dotted": f"{wanted[:4]}.{wanted[4:8]}.{wanted[8:]}",
            "vlan": vlan,
            "entry_type": entry_type,
            "port": port,
            "raw_line": raw.strip(),
        })
    unique: Dict[tuple, Dict[str, Any]] = {}
    for row in hits:
        unique[(row["vlan"], normalize_interface(row["port"]), row["entry_type"])] = row
    return list(unique.values())


def parse_svi_output(value: Any, vlan: int) -> Dict[str, Any]:
    """Parse common Cisco, Aruba, and FastIron VLAN-interface state output.

    The parser is deliberately conservative: an interface is only reported as
    up or down when the device output states that explicitly. Merely finding a
    VLAN number does not prove Layer 3 termination.
    """
    text = clean_network_output(value)
    compact = " ".join(text.split())[:1200]
    result: Dict[str, Any] = {
        "vlan": int(vlan),
        "interface": "",
        "exists": None,
        "state": "unknown",
        "parsed": False,
        "unsupported": False,
        "raw_excerpt": compact,
    }
    interface_patterns = (
        rf"(?i)\b((?:vlan|ve|virtual\s+ethernet)\s*0*{int(vlan)})\s+is\s+"
        r"(administratively\s+down|up|down)(?:\s*,?\s*line\s+protocol\s+is\s+(up|down))?",
        rf"(?i)\b((?:vlan|ve)\s*0*{int(vlan)})\s+.*?\b(up|down|disabled)\b(?:\s|$)",
    )
    for pattern in interface_patterns:
        match = re.search(pattern, text)
        if not match:
            continue
        interface = re.sub(r"\s+", "", match.group(1))
        administrative = str(match.group(2) or "").lower()
        protocol = str(match.group(3) or "").lower() if match.lastindex and match.lastindex >= 3 else ""
        if "administratively" in administrative or administrative == "disabled":
            state = "administratively-down"
        elif administrative == "up" and protocol != "down":
            state = "up"
        else:
            state = "down"
        result.update({"interface": interface, "exists": True, "state": state, "parsed": True})
        return result

    absent = re.search(
        rf"(?i)(?:vlan|ve|virtual\s+ethernet)\s*0*{int(vlan)}\b.*(?:does not exist|not found|not configured)",
        text,
    )
    if absent:
        result.update({"exists": False, "state": "absent", "parsed": True})
        return result
    if re.search(
        r"(?im)^\s*(?:%\s*)?(?:invalid input|unknown command|unrecognized command|command not found|"
        r"(?:command|feature).{0,40}not supported|not supported.{0,40}(?:command|feature))\b",
        text,
    ):
        result["unsupported"] = True
    return result


def parse_lag_output(value: Any) -> Dict[str, Any]:
    """Parse Cisco `show etherchannel summary` and Aruba `show trunks`.

    Reports per-member-interface bundle membership and whether that bundle is
    in use, which is what a forwarding decision needs.
    """
    text = clean_network_output(value)
    result: Dict[str, Any] = {"groups": [], "interfaces": {}, "parsed": False, "unsupported": False}
    if _is_unsupported_command(text):
        result["unsupported"] = True
        return result
    for line in text.splitlines():
        # Cisco: "1      Po1(SU)      LACP      Gi1/0/1(P) Gi1/0/2(P)"
        cisco = re.match(r"^\s*(\d+)\s+(\S+?)\(([A-Za-z]+)\)\s+(\S*)\s*(.*)$", line)
        if cisco:
            flags = cisco.group(3).upper()
            members = re.findall(r"(\S+?)\(([A-Za-z]+)\)", cisco.group(5))
            group = {
                "group": cisco.group(1),
                "name": cisco.group(2),
                "protocol": cisco.group(4),
                # U = in use. D = down.
                "operational": "U" in flags and "D" not in flags,
                "members": [name for name, _ in members],
            }
            result["groups"].append(group)
            for name, member_flags in members:
                result["interfaces"][normalize_interface(name)] = {
                    "interface": name, "group": group["name"],
                    # P = bundled in port-channel.
                    "operational": group["operational"] and "P" in member_flags.upper(),
                }
            continue
        # Aruba: "  1    |  100/1000T   | Trk1   LACP"
        if line.count("|") >= 2:
            left, _, right = line.split("|", 2)
            head = left.split()
            tail = right.split()
            if head and re.fullmatch(r"[A-Za-z]*\d[\w/.-]*", head[0]) and tail:
                group_name = tail[0]
                if re.fullmatch(r"(?i)trk\d+|dyn\d+|lacp\d+", group_name):
                    result["interfaces"][normalize_interface(head[0])] = {
                        "interface": head[0], "group": group_name, "operational": True,
                    }
                    if group_name not in [g["name"] for g in result["groups"]]:
                        result["groups"].append({
                            "group": group_name, "name": group_name,
                            "protocol": tail[1] if len(tail) > 1 else "",
                            "operational": True, "members": [],
                        })
    result["parsed"] = bool(result["groups"] or result["interfaces"])
    return result


def parse_route_output(value: Any, destination: Any = "") -> Dict[str, Any]:
    """Decide whether a device holds a route for a destination."""
    text = clean_network_output(value)
    result: Dict[str, Any] = {
        "destination": str(destination or ""), "route_present": None,
        "via": "", "parsed": False, "unsupported": False,
    }
    if _is_unsupported_command(text):
        result["unsupported"] = True
        return result
    if re.search(r"(?im)^\s*%?\s*(?:network )?not (?:in table|found)|^\s*%\s*Network not in table", text):
        result.update({"route_present": False, "parsed": True})
        return result
    match = re.search(r"(?im)^\s*(?:Routing entry for|[A-Z*]{1,3}\s+)(\d{1,3}(?:\.\d{1,3}){3}[/\d]*)", text)
    via = re.search(r"(?i)\bvia\s+(\d{1,3}(?:\.\d{1,3}){3})", text)
    if match or via or re.search(r"(?i)directly connected", text):
        result.update({
            "route_present": True, "parsed": True,
            "via": via.group(1) if via else "directly connected",
        })
    return result


def parse_vrf_output(value: Any) -> Dict[str, Any]:
    """List the VRFs a device knows and the interfaces bound to each."""
    text = clean_network_output(value)
    result: Dict[str, Any] = {"vrfs": [], "parsed": False, "unsupported": False}
    if _is_unsupported_command(text):
        result["unsupported"] = True
        return result
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 2 or fields[0].lower() in {"name", "vrf", "----"}:
            continue
        if not re.fullmatch(r"[A-Za-z0-9][\w.:-]*", fields[0]):
            continue
        interfaces = [
            item.strip(",") for item in fields[1:]
            if _looks_like_interface(item.strip(","))
            and not re.fullmatch(r"\d+:\d+", item.strip(","))
        ]
        result["vrfs"].append({"name": fields[0], "interfaces": interfaces})
    result["parsed"] = bool(result["vrfs"])
    return result


def parse_arp_output(value: Any, requested: Any = "") -> List[Dict[str, Any]]:
    """Extract vendor-neutral IP/MAC pairs from common switch ARP tables."""
    text = clean_network_output(value)
    requested_text = str(requested or "").strip()
    requested_mac = normalize_mac(requested_text)
    requested_ip = requested_text if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", requested_text) else ""
    rows: List[Dict[str, Any]] = []
    for raw in text.splitlines():
        mac_match = MAC_TOKEN_RE.search(raw)
        ips = IP_RE.findall(raw)
        if not mac_match or not ips:
            continue
        mac = normalize_mac(mac_match.group(0))
        if not mac:
            continue
        ip = ips[0]
        if requested_mac and mac != requested_mac:
            continue
        if requested_ip and ip != requested_ip:
            continue
        after = raw[mac_match.end():].strip().split()
        interface = next((token.strip(",;()") for token in reversed(after) if _looks_like_interface(token)), "")
        rows.append({
            "ip": ip,
            "mac": mac,
            "mac_dotted": f"{mac[:4]}.{mac[4:8]}.{mac[8:]}",
            "interface": interface,
            "raw_line": raw.strip(),
        })
    unique: Dict[tuple, Dict[str, Any]] = {}
    for row in rows:
        unique[(row["ip"], row["mac"])] = row
    return list(unique.values())


def parse_ping_output(value: Any, expected_count: int = 0) -> Dict[str, Any]:
    """Parse Cisco IOS and Unix/Aruba-style ping summaries."""
    text = clean_network_output(value)
    sent = received = 0
    loss: Optional[float] = None
    minimum = average = maximum = None

    cisco = re.search(r"Success rate is\s+(\d+(?:\.\d+)?)\s+percent\s*\((\d+)\s*/\s*(\d+)\)", text, re.I)
    if cisco:
        success = float(cisco.group(1))
        received, sent = int(cisco.group(2)), int(cisco.group(3))
        loss = max(0.0, 100.0 - success)
    unix = re.search(r"(\d+)\s+packets transmitted,\s*(\d+)\s+(?:packets )?received,\s*(\d+(?:\.\d+)?)%\s+packet loss", text, re.I)
    if unix:
        sent, received, loss = int(unix.group(1)), int(unix.group(2)), float(unix.group(3))
    aruba = re.search(r"(\d+)\s+packets transmitted,\s*(\d+)\s+packets received", text, re.I)
    if aruba and not unix:
        sent, received = int(aruba.group(1)), int(aruba.group(2))
        loss = (100.0 * (sent - received) / sent) if sent else None

    rtt = re.search(r"(?:round-trip min/avg/max(?:/[a-z]+)?\s*=|min/avg/max(?:/[a-z]+)?\s*=)\s*([0-9.]+)\s*/\s*([0-9.]+)\s*/\s*([0-9.]+)", text, re.I)
    if rtt:
        minimum, average, maximum = map(float, rtt.groups())
    reply_marks = re.search(r"(?m)^\s*([!.]+)\s*$", text)
    if not sent and reply_marks:
        marks = reply_marks.group(1)
        sent = expected_count or len(marks)
        received = marks[:sent].count("!")
        loss = 100.0 * (sent - received) / sent

    parsed = bool(sent or received or loss is not None or average is not None)
    if not parsed:
        status = "ERROR"
    elif received <= 0:
        status = "UNREACHABLE"
    elif loss and loss > 0:
        status = "DEGRADED"
    else:
        status = "REACHABLE"
    return {
        "parsed": parsed,
        "status": status,
        "transmitted": sent,
        "received": received,
        "packet_loss_pct": loss,
        "min_ms": minimum,
        "avg_ms": average,
        "max_ms": maximum,
    }


def _counter(text: str, patterns: Iterable[str]) -> Optional[int]:
    for pattern in patterns:
        match = re.search(pattern, text, re.I | re.M)
        if match:
            with contextlib.suppress(ValueError):
                return int(match.group(1).replace(",", ""))
    return None


def parse_interface_health_output(value: Any) -> Dict[str, Any]:
    """Parse link state, negotiation, rates, and cumulative error counters.

    Supports stable Cisco IOS/IOS-XE, Aruba AOS-S, Aruba AOS-CX, and Ruckus
    FastIron fields. Missing fields remain null instead of being presented as
    zero.
    """
    text = clean_network_output(value)
    result: Dict[str, Any] = {
        "parsed": False,
        "interface": "",
        "admin_status": "UNKNOWN",
        "oper_status": "UNKNOWN",
        "line_protocol": "UNKNOWN",
        "speed_mbps": None,
        "duplex": "UNKNOWN",
        "media": "",
        "input_bps": None,
        "output_bps": None,
        "counters": {},
    }

    cisco = re.search(
        r"^\s*([^\s,]+)\s+is\s+([^,\n]+),\s*line protocol is\s+([^\s(\n]+)(?:\s*\(([^)]+)\))?",
        text,
        re.I | re.M,
    )
    if cisco:
        state = cisco.group(2).strip().lower()
        result["interface"] = cisco.group(1).strip()
        result["admin_status"] = "DOWN" if "administratively" in state else "UP"
        result["oper_status"] = "UP" if state == "up" else "DOWN"
        result["line_protocol"] = cisco.group(3).strip().upper()
        if cisco.group(4):
            result["link_reason"] = cisco.group(4).strip()

    aos_cx = re.search(r"^\s*Interface\s+(\S+)\s+is\s+(up|down)(?:\s+\(([^)]+)\))?", text, re.I | re.M)
    if aos_cx:
        result["interface"] = aos_cx.group(1).strip()
        result["oper_status"] = aos_cx.group(2).upper()
        result["line_protocol"] = result["oper_status"]
        if aos_cx.group(3):
            result["link_reason"] = aos_cx.group(3).strip()
    aos_cx_admin = re.search(r"^\s*Admin state is\s+(up|down)\b", text, re.I | re.M)
    if aos_cx_admin:
        result["admin_status"] = aos_cx_admin.group(1).upper()
    aos_cx_state = re.search(r"^\s*State information\s*:\s*([^\n]+)", text, re.I | re.M)
    if aos_cx_state:
        result["link_reason"] = aos_cx_state.group(1).strip()

    aruba_link = re.search(r"^\s*Link Status\s*:\s*([^\n]+)", text, re.I | re.M)
    aruba_enabled = re.search(r"^\s*Port Enabled\s*:\s*([^\n]+)", text, re.I | re.M)
    if aruba_link:
        status = aruba_link.group(1).strip().lower()
        result["oper_status"] = "UP" if status.startswith("up") else "DOWN"
        result["line_protocol"] = result["oper_status"]
    if aruba_enabled:
        result["admin_status"] = "UP" if aruba_enabled.group(1).strip().lower() in {"yes", "true", "enabled", "up"} else "DOWN"

    aruba_brief = re.search(
        r"^\s*([A-Za-z]?\d+(?:/\d+)*)\s+(\S+)\s+\|\s+\S+\s+(Yes|No)\s+(Up|Down)\s+([0-9]+)(FDx|HDx)\b",
        text,
        re.I | re.M,
    )
    if aruba_brief:
        result["interface"] = aruba_brief.group(1)
        result["media"] = aruba_brief.group(2)
        result["admin_status"] = "UP" if aruba_brief.group(3).lower() == "yes" else "DOWN"
        result["oper_status"] = aruba_brief.group(4).upper()
        result["line_protocol"] = result["oper_status"]
        result["speed_mbps"] = float(aruba_brief.group(5))
        result["duplex"] = "FULL" if aruba_brief.group(6).lower().startswith("f") else "HALF"

    negotiation = re.search(r"\b(Full|Half|Auto)-duplex\s*,\s*([^,\n]+)", text, re.I)
    if negotiation:
        result["duplex"] = negotiation.group(1).upper()
        speed_text = negotiation.group(2)
        speed = re.search(r"([0-9.]+)\s*([KMG])?b/s", speed_text, re.I)
        if speed:
            amount = float(speed.group(1))
            unit = (speed.group(2) or "M").upper()
            result["speed_mbps"] = round(amount * {"K": 0.001, "M": 1.0, "G": 1000.0}[unit], 3)

    explicit_duplex = re.search(r"^\s*(Full|Half)-duplex\s*$", text, re.I | re.M)
    if explicit_duplex:
        result["duplex"] = explicit_duplex.group(1).upper()
    explicit_speed = re.search(r"^\s*Speed\s+([0-9.]+)\s*([KMG])?b/s\b", text, re.I | re.M)
    if explicit_speed:
        amount = float(explicit_speed.group(1))
        unit = (explicit_speed.group(2) or "M").upper()
        result["speed_mbps"] = round(amount * {"K": 0.001, "M": 1.0, "G": 1000.0}[unit], 3)
    fastiron_speed = re.search(r"\bactual\s+([0-9.]+)\s*([KMG])?(?:bit|b/s)\b", text, re.I)
    if fastiron_speed and result["speed_mbps"] is None:
        amount = float(fastiron_speed.group(1))
        unit = (fastiron_speed.group(2) or "M").upper()
        result["speed_mbps"] = round(amount * {"K": 0.001, "M": 1.0, "G": 1000.0}[unit], 3)
    fastiron_duplex = re.search(r"\bactual duplex\s+(full|half)\b|\bactual\s+(full|half)-duplex\b", text, re.I)
    if fastiron_duplex and result["duplex"] == "UNKNOWN":
        result["duplex"] = (fastiron_duplex.group(1) or fastiron_duplex.group(2)).upper()

    mode = re.search(r"^\s*(?:Mode|Port Mode)\s*:\s*([0-9]+)(FDx|HDx)", text, re.I | re.M)
    if mode:
        result["speed_mbps"] = float(mode.group(1))
        result["duplex"] = "FULL" if mode.group(2).lower().startswith("f") else "HALF"

    media = re.search(r"(?:media type is|Media Type\s*:)\s*([^\n,]+)", text, re.I)
    if media:
        result["media"] = media.group(1).strip()
    aos_cx_media = re.search(r"^\s*Type\s+([^\n]+)", text, re.I | re.M)
    if aos_cx_media:
        result["media"] = aos_cx_media.group(1).strip()

    input_rate = re.search(r"5 minute input rate\s*(?:(?:is|:)\s*)?([\d,]+)\s*(?:bits/sec|bps)", text, re.I)
    output_rate = re.search(r"5 minute output rate\s*(?:(?:is|:)\s*)?([\d,]+)\s*(?:bits/sec|bps)", text, re.I)
    if input_rate:
        result["input_bps"] = int(input_rate.group(1).replace(",", ""))
    if output_rate:
        result["output_bps"] = int(output_rate.group(1).replace(",", ""))
    interval_input_rate = re.search(r"(?:30|300)\s+second input rate\s*:?[ \t]*([\d,]+)\s*(?:bits/sec|bps)", text, re.I)
    interval_output_rate = re.search(r"(?:30|300)\s+second output rate\s*:?[ \t]*([\d,]+)\s*(?:bits/sec|bps)", text, re.I)
    if interval_input_rate:
        result["input_bps"] = int(interval_input_rate.group(1).replace(",", ""))
    if interval_output_rate:
        result["output_bps"] = int(interval_output_rate.group(1).replace(",", ""))
    aruba_input_rate = re.search(r"^\s*Total Rx \(bps\)\s*:\s*([\d,]+)", text, re.I | re.M)
    aruba_output_rate = re.search(r"\bTotal Tx \(bps\)\s*:\s*([\d,]+)", text, re.I)
    if aruba_input_rate:
        result["input_bps"] = int(aruba_input_rate.group(1).replace(",", ""))
    if aruba_output_rate:
        result["output_bps"] = int(aruba_output_rate.group(1).replace(",", ""))

    # AOS-CX reports receive/transmit rates as columns rather than labels.
    cx_rates = re.search(
        r"^\s*([KMGT]?)bits\s*/\s*sec\s+([0-9.]+)\s+([0-9.]+)(?:\s+[0-9.]+)?\s*$",
        text,
        re.I | re.M,
    )
    if cx_rates:
        multiplier = {"": 1.0, "K": 1_000.0, "M": 1_000_000.0, "G": 1_000_000_000.0, "T": 1_000_000_000_000.0}[(cx_rates.group(1) or "").upper()]
        result["input_bps"] = int(float(cx_rates.group(2)) * multiplier)
        result["output_bps"] = int(float(cx_rates.group(3)) * multiplier)

    counter_patterns = {
        "input_errors": [r"([\d,]+)\s+input errors\b"],
        "crc_errors": [r"([\d,]+)\s+CRC\b", r"^\s*FCS Rx\s*:\s*([\d,]+)"],
        "frame_errors": [r"([\d,]+)\s+frame\b", r"^\s*Alignment Rx\s*:\s*([\d,]+)"],
        "overruns": [r"([\d,]+)\s+overrun\b"],
        "ignored": [r"([\d,]+)\s+ignored\b"],
        "output_errors": [r"([\d,]+)\s+output errors\b"],
        "collisions": [r"([\d,]+)\s+collisions\b", r"^\s*Collisions Tx\s*:\s*([\d,]+)"],
        "interface_resets": [r"([\d,]+)\s+interface resets\b"],
        "output_drops": [r"Total output drops:\s*([\d,]+)", r"^\s*Drops Tx\s*:\s*([\d,]+)"],
        "runts": [r"^\s*Runts(?: Rx)?\s*:\s*([\d,]+)"],
        "giants": [r"^\s*Giants(?: Rx)?\s*:\s*([\d,]+)"],
        "rx_errors": [r"^\s*Total Rx Errors\s*:\s*([\d,]+)"],
        "late_collisions": [r"^\s*Late Colln(?: Tx)?\s*:\s*([\d,]+)"],
        "excessive_collisions": [r"^\s*Excessive Colln\s*:\s*([\d,]+)"],
        "deferred": [r"^\s*Deferred(?: Tx)?\s*:\s*([\d,]+)"],
        "rx_discards": [r"^\s*Discard Rx\s*:\s*([\d,]+)"],
    }
    result["counters"] = {
        key: found
        for key, patterns in counter_patterns.items()
        if (found := _counter(text, patterns)) is not None
    }

    def cx_pair(label: str) -> tuple[Optional[int], Optional[int]]:
        match = re.search(
            rf"^\s*{label}\s+([\d,]+|n/a)\s+([\d,]+|n/a)(?:\s+[\d,]+|\s+n/a)?\s*$",
            text,
            re.I | re.M,
        )
        if not match:
            return None, None
        values: List[Optional[int]] = []
        for value in match.groups()[:2]:
            values.append(None if value.lower() == "n/a" else int(value.replace(",", "")))
        return values[0], values[1]

    errors_rx, errors_tx = cx_pair("Errors")
    crc_rx, _ = cx_pair(r"CRC/FCS")
    _, collision_tx = cx_pair("Collision")
    runts_rx, _ = cx_pair("Runts")
    giants_rx, _ = cx_pair("Giants")
    dropped_rx, dropped_tx = cx_pair("Dropped")
    for key, found in {
        "input_errors": errors_rx,
        "output_errors": errors_tx,
        "crc_errors": crc_rx,
        "collisions": collision_tx,
        "runts": runts_rx,
        "giants": giants_rx,
        "rx_discards": dropped_rx,
        "output_drops": dropped_tx,
    }.items():
        if found is not None:
            result["counters"][key] = found
    result["parsed"] = bool(cisco or aos_cx or aruba_link or aruba_enabled or aruba_brief or result["counters"])
    return result


def parse_cable_diagnostics_output(value: Any) -> Dict[str, Any]:
    """Parse Cisco, Aruba, and Ruckus/FastIron copper diagnostics."""
    text = clean_network_output(value)
    lower = text.lower()
    result: Dict[str, Any] = {
        "parsed": False,
        "status": "UNKNOWN",
        "healthy": None,
        "pairs": [],
        "message": "Cable diagnostic output was not recognized.",
    }
    if re.search(r"never (?:been )?run|no results to show|no (?:tdr|cable diagnostic) results", lower):
        result.update({"parsed": True, "status": "NOT_RUN", "message": "No previous cable diagnostic result is available."})
        return result
    if re.search(r"not supported|unsupported|invalid input.*cable|only supported on.*copper", lower):
        result.update({"parsed": True, "status": "UNSUPPORTED", "message": "Cable diagnostics are not supported on this interface or platform."})
        return result
    if re.search(r"in progress|running.*(?:tdr|cable)", lower):
        result.update({"parsed": True, "status": "IN_PROGRESS", "message": "Cable diagnostics are still running."})
        return result

    pair_rows: List[Dict[str, Any]] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or not re.search(r"\b(?:Pair\s*[A-D]|[1-8]\s*[-/]\s*[1-8])\b", line, re.I):
            continue
        pair_match = re.search(r"\b(Pair\s*[A-D]|[1-8]\s*[-/]\s*[1-8])\b", line, re.I)
        status_match = re.search(r"\b(Normal|Good|OK|Terminated|Open|Short(?:ed)?|Impedance Mismatch|ImpedMis|Crossed|Unknown|Fail(?:ed)?)\b", line, re.I)
        if not pair_match or not status_match:
            continue
        distance = re.search(r"(\d+(?:\.\d+)?)\s*(?:\+/-\s*\d+(?:\.\d+)?\s*)?(m|meters?|ft|feet)\b", line, re.I)
        distance_m: Optional[float] = None
        if distance:
            distance_m = float(distance.group(1))
            if distance.group(2).lower() in {"ft", "feet"}:
                distance_m *= 0.3048
            distance_m = round(distance_m, 2)
        pair_rows.append({
            "pair": re.sub(r"\s+", " ", pair_match.group(1).upper().replace("PAIR", "Pair")).strip(),
            "status": status_match.group(1).upper().replace("FAILED", "FAIL").replace("SHORTED", "SHORT").replace("IMPEDMIS", "IMPEDANCE MISMATCH"),
            "distance_m": distance_m,
            "raw_line": line,
        })

    if pair_rows:
        good = {"NORMAL", "GOOD", "OK", "TERMINATED"}
        healthy = all(row["status"] in good for row in pair_rows)
        result.update({
            "parsed": True,
            "status": "HEALTHY" if healthy else "FAULT",
            "healthy": healthy,
            "pairs": pair_rows,
            "message": "All reported pairs are healthy." if healthy else "One or more copper pairs report a fault.",
        })
        return result
    return result


def parse_iperf3_output(value: Any) -> Dict[str, Any]:
    """Parse iperf3 JSON, using receiver goodput as the primary result."""
    try:
        payload = value if isinstance(value, dict) else json.loads(str(value or "{}"))
    except (TypeError, ValueError, json.JSONDecodeError):
        return {"parsed": False, "ok": False, "error": "invalid iperf3 JSON"}
    if payload.get("error"):
        return {"parsed": True, "ok": False, "error": str(payload.get("error"))}
    start = payload.get("start") or {}
    end = payload.get("end") or {}
    test = start.get("test_start") or {}
    protocol = str(test.get("protocol") or "TCP").upper()
    receiver = end.get("sum_received") or end.get("sum") or {}
    sender = end.get("sum_sent") or end.get("sum") or {}
    bits = receiver.get("bits_per_second")
    if bits is None:
        return {"parsed": False, "ok": False, "error": "iperf3 summary is missing receiver throughput"}
    reverse = bool(test.get("reverse"))
    result: Dict[str, Any] = {
        "parsed": True,
        "ok": True,
        "protocol": protocol,
        "reverse": reverse,
        "direction": "download" if reverse else "upload",
        "seconds": round(float(receiver.get("seconds") or test.get("duration") or 0), 3),
        "bytes": int(receiver.get("bytes") or 0),
        "bits_per_second": round(float(bits), 3),
        "megabits_per_second": round(float(bits) / 1_000_000, 3),
        "retransmits": int(sender.get("retransmits") or 0),
        "streams": int(test.get("num_streams") or len(end.get("streams") or []) or 1),
    }
    if receiver.get("jitter_ms") is not None:
        result["jitter_ms"] = round(float(receiver.get("jitter_ms") or 0), 3)
    if receiver.get("lost_percent") is not None:
        result["lost_percent"] = round(float(receiver.get("lost_percent") or 0), 3)
    remote = (start.get("connected") or [{}])[0]
    result["local_host"] = remote.get("local_host") or ""
    result["remote_host"] = remote.get("remote_host") or ""
    return result


def extract_ip_candidates(value: Any) -> List[str]:
    output: List[str] = []
    for candidate in IP_RE.findall(clean_network_output(value)):
        parts = candidate.split(".")
        if len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts) and candidate not in output:
            output.append(candidate)
    return output


@lru_cache(maxsize=32)
def _read_oui_file(path_value: str) -> Dict[str, str]:
    path = Path(path_value)
    if not path.is_file():
        return {}
    rows: Dict[str, str] = {}
    with contextlib.suppress(OSError):
        for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            match = re.match(r"^([0-9A-Fa-f]{6,12})\s+(.+)$", line)
            if match:
                rows[match.group(1).upper()] = match.group(2).strip()
    return rows


def lookup_oui(value: Any, paths: Optional[Iterable[Path]] = None) -> Dict[str, str]:
    mac = normalize_mac(value)
    if not mac:
        return {"prefix": "", "vendor": "", "source": ""}
    candidates = list(paths or (
        Path("/usr/share/nmap/nmap-mac-prefixes"),
        Path("/usr/share/ieee-data/oui.txt"),
        Path("/usr/share/misc/oui.txt"),
    ))
    upper = mac.upper()
    for path in candidates:
        table = _read_oui_file(str(path))
        for length in range(min(12, len(upper)), 5, -1):
            prefix = upper[:length]
            if prefix in table:
                return {"prefix": prefix, "vendor": table[prefix], "source": str(path)}
    return {"prefix": upper[:6], "vendor": "Unknown", "source": ""}
