#!/usr/bin/env python3
"""Pure parsers and normalizers for network-read NetOps workflows."""

from __future__ import annotations

import contextlib
import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

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
    """Parse the stable, human-readable netops-control VLAN reports."""
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
    for block in re.split(r"(?=^Device ID\s*:)", text, flags=re.I | re.M):
        if not re.search(r"^Device ID\s*:", block, re.I | re.M):
            continue
        name = _neighbor_block_value(block, [r"^Device ID\s*:\s*(.+)$"])
        local = _neighbor_block_value(block, [r"^Interface\s*:\s*([^,]+)"])
        remote_port = _neighbor_block_value(block, [r"Port ID \(outgoing port\)\s*:\s*(.+)$"])
        platform = _neighbor_block_value(block, [r"^Platform\s*:\s*([^,]+)"])
        capabilities = _neighbor_block_value(block, [r"Capabilities\s*:\s*(.+)$"])
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
    lldp_starts = list(re.finditer(r"^(?:Local (?:Intf|Port id|Port)|LocalPort)\s*:\s*", text, re.I | re.M))
    for index, start in enumerate(lldp_starts):
        end = lldp_starts[index + 1].start() if index + 1 < len(lldp_starts) else len(text)
        block = text[start.start():end]
        local = _neighbor_block_value(block, [r"^Local (?:Intf|Port id|Port)\s*:\s*(.+)$", r"^LocalPort\s*:\s*(.+)$"])
        name = _neighbor_block_value(block, [r"^System Name\s*:\s*(.+)$", r"^SysName\s*:\s*(.+)$"])
        remote_port = _neighbor_block_value(block, [r"^Port id\s*:\s*(.+)$", r"^Port Description\s*:\s*(.+)$"])
        platform = _neighbor_block_value(block, [r"^System Description\s*:\s*(.+)$"])
        capabilities = _neighbor_block_value(block, [r"^Enabled Capabilities\s*:\s*(.+)$", r"^System Capabilities\s*:\s*(.+)$"])
        ips = IP_RE.findall(block)
        if local and (name or remote_port or ips):
            records.append({
                "protocol": "lldp",
                "local_port": local,
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
    return bool(re.match(r"(?i)^(?:gi|gig|te|ten|fa|eth|et|twe|fo|hu|po|port-channel|trk|lag|[a-z]?\d)[a-z0-9./:_-]*$", token))


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
