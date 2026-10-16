#!/usr/bin/env python3
"""Normalized inventory-ingest boundary for shell, SNMP, and future providers."""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from netops_platform.devices import detect_device_family
from netops_platform.identity import normalize_mac


DEVICE_FIELDS = ("ip", "hostname", "platform", "model", "serial", "mac", "source", "last_seen", "status")
ABSENT = {"", "n/a", "na", "none", "null", "unknown", "not available"}
PLATFORM_LABELS = {
    "cisco-ios": "Cisco IOS",
    "aruba-aos-switch": "Aruba AOS-S",
    "aruba-aos-cx": "Aruba AOS-CX",
    "ruckus-fastiron": "Ruckus FastIron",
    "ruckus-smartzone": "Ruckus SmartZone",
    "ruckus-ap": "Ruckus AP",
}


def _text(value: Any) -> str:
    return str(value or "").replace("\r", " ").replace("\n", " ").replace("|", " ").strip().strip('"')


def _meaningful(value: Any) -> bool:
    return _text(value).lower() not in ABSENT


def _timestamp(value: Any, default: Optional[int] = None) -> int:
    try:
        result = int(value)
        return result if result > 0 else int(default or time.time())
    except (TypeError, ValueError):
        return int(default or time.time())


def _status(value: Any) -> str:
    text = _text(value).upper()
    return text if text in {"ONLINE", "OFFLINE", "UNKNOWN"} else "UNKNOWN"


def _meaningful_model(value: Any) -> bool:
    # Quotes, brackets, and colons only reach the model field when a parser
    # captured an error message or a whole log line instead of a model.
    return _meaningful(value) and not re.search(r'["():\\]', _text(value))


# HPE product numbers: J9851A, JL258A, and the CX-era R8N88A style.
_ARUBA_PRODUCT_NUMBER = r"(?:J[A-Z]?\d{3,4}|[A-Z]\d[A-Z]\d{2})[A-Z]{1,2}"


def aruba_model_name(text: Any, *, require_product_number: bool = False) -> str:
    """Return the model name an Aruba describes itself with, e.g.
    `2930F-8G-PoE+-2SFP+` from `Aruba JL258A 2930F-8G-PoE+-2SFP+ Switch`.

    The same canonicalization serves SNMP's entPhysicalDescr/sysDescr and the
    CLI's `show modules` Chassis line, so the two sources store one string
    instead of overwriting each other on alternate scans. Free text such as
    sysDescr only counts when it carries an HPE product number; a labelled CLI
    field (Chassis, Product Name) is a model by definition.
    """
    value = re.split(r",", _text(text), maxsplit=1)[0]
    value = re.sub(r"^(?:Aruba|HPE?|ProCurve|Hewlett[ -]Packard(?: Enterprise)?)\s+", "", value, flags=re.I)
    if require_product_number and not re.search(rf"\b{_ARUBA_PRODUCT_NUMBER}\b", value):
        return ""
    value = re.sub(rf"\b{_ARUBA_PRODUCT_NUMBER}\b", " ", value)
    # AOS-CX product names run straight into the firmware: "... Swch FL.10.08.1010".
    value = re.sub(r"\s+[A-Z]{2}\.\d+\.\d+\S*\s*$", "", value)
    value = re.sub(r"\b(?:Switch|Swch)\b", " ", value, flags=re.I)
    value = " ".join(value.split())
    return value if _meaningful_model(value) else ""


def _first_match(text: str, patterns: Sequence[str]) -> str:
    for pattern in patterns:
        match = re.search(pattern, text, re.I | re.M)
        if match:
            return match.group(1).strip().rstrip(",")
    return ""


def _serial_value(value: str) -> str:
    return value if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{3,39}", value or "") and _meaningful(value) else ""


def parse_cli_hardware(text: Any, family: str) -> Dict[str, str]:
    """Extract model, serial, and base MAC from labelled CLI output only.

    Missing fields come back empty, never guessed: this runs after every SSH
    job, and an unlabelled MAC-shaped token in `show interfaces` or a MAC
    table is some other device's address, not this switch's base MAC.
    """
    raw = str(text or "").replace("\r", "")
    model = serial = mac = ""
    if family == "cisco-ios":
        model = _first_match(raw, (
            r"^[ \t]*Model Number[ \t]*:[ \t]*(\S+)",
            # `show inventory`: the first entry is the chassis (or the stack,
            # whose PID still names the switch model).
            r"^[ \t]*PID:[ \t]*([^\s,]+)",
        ))
        serial = _serial_value(_first_match(raw, (
            r"^[ \t]*Motherboard Serial Number[ \t]*:[ \t]*(\S+)",
            r"^[ \t]*System Serial Number[ \t]*:[ \t]*(\S+)",
            r"^[ \t]*PID:[^\n]*\bSN:[ \t]*([A-Za-z0-9-]+)",
            r"^[ \t]*Processor board ID[ \t]+(\S+)",
        )))
        mac = _first_match(raw, (r"^[ \t]*Base Ethernet MAC Address[ \t]*:[ \t]*(\S+)",))
    elif family in {"aruba-aos-switch", "aruba-aos-cx"}:
        # AOS-S `show system` is two columns, so Serial Number and Base MAC
        # Addr sit mid-line after the left column's value.
        chassis = _first_match(raw, (r"^[ \t]*Chassis[ \t]*:[ \t]*(.+?)(?:\s+Serial Number\b.*)?$",))
        product = _first_match(raw, (r"^[ \t]*Product Name[ \t]*:[ \t]*(.+?)\s*$",))
        model = aruba_model_name(chassis) or aruba_model_name(product)
        serial = _serial_value(_first_match(raw, (
            r"^[ \t]*Chassis[ \t]*:.*?\bSerial Number[ \t]*:[ \t]*([A-Za-z0-9-]+)",
            r"(?:^|\s)Chassis Serial (?:Nbr|Number)[ \t]*:[ \t]*([A-Za-z0-9-]+)",
            r"(?:^|\s)Serial Number[ \t]*:[ \t]*([A-Za-z0-9-]+)",
        )))
        mac = _first_match(raw, (r"(?:^|\s)(?:Base MAC Addr(?:ess)?|System MAC Address)[ \t]*:[ \t]*([0-9A-Fa-f][0-9A-Fa-f:.-]{11,16})",))
    return {
        "model": model if _meaningful_model(model) else "",
        "serial": serial,
        "mac": normalize_mac(mac),
    }


_ENTITY_COLUMNS = {"2": "descr", "5": "class", "11": "serial", "13": "model"}
_ENTITY_NAMES = {"entPhysicalDescr": "descr", "entPhysicalClass": "class", "entPhysicalSerialNum": "serial", "entPhysicalModelName": "model"}


def parse_entity_varbinds(lines: Iterable[str]) -> Dict[int, Dict[str, str]]:
    """Group `OID<TAB>value` ENTITY-MIB lines by entPhysicalIndex."""
    entities: Dict[int, Dict[str, str]] = {}
    for line in lines:
        oid, _, value = str(line).rstrip("\r\n").partition("\t")
        match = re.search(r"(?:47\.1\.1\.1\.1\.(\d+)|(entPhysical[A-Za-z]+))\.(\d+)$", oid.strip())
        if not match:
            continue
        column = _ENTITY_COLUMNS.get(match.group(1) or "") or _ENTITY_NAMES.get(match.group(2) or "")
        value = value.strip().strip('"').strip()
        if not column or re.match(r"no such (?:instance|object)|not avail", value, re.I):
            continue
        if column == "class":
            value = "3" if re.match(r"(?:chassis|3)\b", value, re.I) else value
        entities.setdefault(int(match.group(3)), {})[column] = value
    return entities


def parse_snmp_hardware(family: str, lines: Iterable[str], *, sysdescr: Any = "", bridge_mac: Any = "") -> Dict[str, str]:
    """Model and serial from the ENTITY-MIB chassis entity, base MAC from the bridge.

    The chassis is the lowest-indexed class-3 entity, not index 1: Catalyst 9000
    puts a "c92xx Stack" container at 1 and the switch at 1000, and 2960/3560CX
    and stackable Arubas start their table at 1001.
    """
    entities = parse_entity_varbinds(lines)
    chassis = next((entities[index] for index in sorted(entities) if entities[index].get("class") == "3"), {})
    model = ""
    if family in {"aruba-aos-switch", "aruba-aos-cx"}:
        model = (aruba_model_name(chassis.get("descr"), require_product_number=True)
                 or aruba_model_name(sysdescr, require_product_number=True))
    elif family == "cisco-ios":
        # sysDescr names the software image (C2960S-UNIVERSALK9-M), not the
        # hardware, and IOS-XE's CAT9K_LITE_IOSXE names none at all.
        model = chassis.get("model", "")
    serial = _serial_value(chassis.get("serial", ""))
    return {
        "model": model if _meaningful_model(model) else "",
        "serial": serial,
        "mac": normalize_mac(bridge_mac),
    }


def normalize_device_observation(raw: Mapping[str, Any], observed_at: Optional[int] = None) -> Dict[str, Any]:
    row = {key: _text(raw.get(key)) for key in DEVICE_FIELDS}
    sysdescr = _text(raw.get("sysdescr"))
    detection = detect_device_family(
        platform=row["platform"],
        model=row["model"],
        sysdescr=sysdescr,
        hostname=row["hostname"],
        device_kind=raw.get("device_kind"),
    )
    if detection.family != "unknown":
        row["platform"] = PLATFORM_LABELS[detection.family]
    elif not _meaningful(row["platform"]):
        row["platform"] = "Unknown"
    row["hostname"] = row["hostname"] if _meaningful(row["hostname"]) else "N/A"
    row["model"] = row["model"] if _meaningful_model(row["model"]) else "N/A"
    row["serial"] = row["serial"] if _meaningful(row["serial"]) else "N/A"
    row["mac"] = normalize_mac(row["mac"]) or "N/A"
    row["source"] = row["source"] if _meaningful(row["source"]) else "unknown"
    row["last_seen"] = _timestamp(raw.get("last_seen"), observed_at)
    row["status"] = _status(raw.get("status"))
    row["driver_family"] = detection.family
    row["driver_confidence"] = detection.confidence
    return row


def _source_union(left: Any, right: Any) -> str:
    values: List[str] = []
    for raw in (left, right):
        for token in re.split(r"[+,]", _text(raw)):
            token = token.strip()
            if _meaningful(token) and token not in values:
                values.append(token)
    return "+".join(values) or "unknown"


def merge_device_observations(
    existing: Mapping[str, Any],
    incoming: Mapping[str, Any],
    observed_at: Optional[int] = None,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Merge per field so fresh status/name data cannot erase richer inventory."""
    old = normalize_device_observation(existing, observed_at)
    new = normalize_device_observation(incoming, observed_at)
    if old["ip"] and new["ip"] and old["ip"] != new["ip"]:
        raise ValueError("cannot merge observations for different IP addresses")
    merged = dict(old)
    changed: List[str] = []
    # A current non-placeholder hostname is authoritative regardless of whether
    # a previous detailed observation came from SSH.
    # Cisco's SNMP chassis serial is the System serial; the device serial is
    # the Motherboard serial from `show version`, and on 2960/3560CX the two
    # differ. Once SSH has recorded one, an SNMP-only scan of the same model
    # must not flip it; a different model is different hardware, so it may.
    keep_cli_serial = (
        new["driver_family"] == "cisco-ios"
        and _text(incoming.get("source")).upper() == "SNMP"
        and "SSH" in _text(old.get("source")).upper()
        and _meaningful(old.get("model"))
        and old.get("model") == new.get("model")
    )
    for field in ("hostname", "platform", "model", "serial", "mac"):
        if field == "serial" and keep_cli_serial and _meaningful(old.get(field)):
            continue
        if _meaningful(new.get(field)) and new.get(field) != old.get(field):
            merged[field] = new[field]
            changed.append(field)
    merged["ip"] = new.get("ip") or old.get("ip")
    merged["status"] = new["status"]
    merged["last_seen"] = new["last_seen"]
    merged["source"] = _source_union(old.get("source"), new.get("source"))
    merged["driver_family"] = new["driver_family"] if new["driver_family"] != "unknown" else old["driver_family"]
    merged["driver_confidence"] = max(int(old.get("driver_confidence") or 0), int(new.get("driver_confidence") or 0))
    for field in ("status", "source"):
        if merged[field] != old[field] and field not in changed:
            changed.append(field)
    return merged, {
        "changed": bool(changed),
        "changed_fields": changed,
        "hostname_changed": "hostname" in changed,
        "driver_family": merged["driver_family"],
        "driver_confidence": merged["driver_confidence"],
    }


def parse_device_pipe(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    if not path.is_file():
        return rows
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        parts = raw.split("|")
        if len(parts) < len(DEVICE_FIELDS):
            continue
        rows.append(dict(zip(DEVICE_FIELDS, parts[:len(DEVICE_FIELDS)])))
    return rows


def render_device_pipe(rows: Iterable[Mapping[str, Any]]) -> str:
    lines = []
    for raw in rows:
        row = normalize_device_observation(raw)
        lines.append("|".join(str(row.get(field) or "") for field in DEVICE_FIELDS))
    return "\n".join(lines) + ("\n" if lines else "")


def merge_scan_files(
    inventory_path: Path,
    targets_path: Path,
    observations_path: Path,
    *,
    observed_at: Optional[int] = None,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    observed = int(observed_at or time.time())
    targets = {
        line.strip() for line in targets_path.read_text(encoding="utf-8", errors="replace").splitlines()
        if line.strip()
    }
    existing = {row["ip"]: row for row in parse_device_pipe(inventory_path) if row.get("ip")}
    incoming = {row["ip"]: row for row in parse_device_pipe(observations_path) if row.get("ip")}
    output: Dict[str, Dict[str, Any]] = {}
    changed_fields: Dict[str, List[str]] = {}
    for ip, old in existing.items():
        if ip in incoming:
            merged, detail = merge_device_observations(old, incoming.pop(ip), observed)
            output[ip] = merged
            if detail["changed_fields"]:
                changed_fields[ip] = detail["changed_fields"]
        elif ip in targets:
            row = normalize_device_observation(old, observed)
            row["status"] = "OFFLINE"
            row["last_seen"] = observed
            output[ip] = row
            if str(old.get("status") or "").upper() != "OFFLINE":
                changed_fields[ip] = ["status"]
        else:
            output[ip] = normalize_device_observation(old, observed)
    for ip, row in incoming.items():
        output[ip] = normalize_device_observation(row, observed)
        changed_fields[ip] = ["first_seen"]
    rows = [output[ip] for ip in sorted(output, key=lambda value: tuple(int(part) if part.isdigit() else 0 for part in value.split(".")))]
    return rows, {
        "ok": True,
        "targets": len(targets),
        "observed": sum(1 for ip in targets if ip in output and output[ip]["status"] == "ONLINE"),
        "offline": sum(1 for ip in targets if ip in output and output[ip]["status"] == "OFFLINE"),
        "inventory_rows": len(rows),
        "changed_devices": len(changed_fields),
        "changes": changed_fields,
        "observed_at": observed,
    }


def merge_device_record(
    inventory_path: Path,
    record: str,
    *,
    observed_at: Optional[int] = None,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Merge one provider observation through the same boundary as a scan."""
    parts = str(record or "").split("|")
    if len(parts) < len(DEVICE_FIELDS):
        raise ValueError(f"device record requires {len(DEVICE_FIELDS)} pipe-delimited fields")
    incoming = dict(zip(DEVICE_FIELDS, parts[:len(DEVICE_FIELDS)]))
    ip = _text(incoming.get("ip"))
    if not ip:
        raise ValueError("device record requires an IP address")
    observed = int(observed_at or time.time())
    incoming["last_seen"] = _timestamp(incoming.get("last_seen"), observed)
    existing = {row["ip"]: row for row in parse_device_pipe(inventory_path) if row.get("ip")}
    if ip in existing:
        merged, detail = merge_device_observations(existing[ip], incoming, observed)
    else:
        merged = normalize_device_observation(incoming, observed)
        detail = {
            "changed": True,
            "changed_fields": ["first_seen"],
            "hostname_changed": False,
            "driver_family": merged["driver_family"],
            "driver_confidence": merged["driver_confidence"],
        }
    existing[ip] = merged
    rows = [
        existing[address]
        for address in sorted(
            existing,
            key=lambda value: tuple(int(part) if part.isdigit() else 0 for part in value.split(".")),
        )
    ]
    return rows, {
        "ok": True,
        "ip": ip,
        "changed": detail["changed"],
        "changed_fields": detail["changed_fields"],
        "hostname_changed": detail["hostname_changed"],
        "driver_family": detail["driver_family"],
        "driver_confidence": detail["driver_confidence"],
        "observed_at": observed,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Netrune normalized inventory ingest")
    subparsers = parser.add_subparsers(dest="operation", required=True)
    merge = subparsers.add_parser("merge-device-scan")
    merge.add_argument("--inventory", type=Path, required=True)
    merge.add_argument("--targets", type=Path, required=True)
    merge.add_argument("--observations", type=Path, required=True)
    merge.add_argument("--output", type=Path, required=True)
    merge.add_argument("--observed-at", type=int, default=0)
    merge.add_argument("--summary", type=Path)
    record = subparsers.add_parser("merge-device-record")
    record.add_argument("--inventory", type=Path, required=True)
    record.add_argument("--record", required=True)
    record.add_argument("--output", type=Path, required=True)
    record.add_argument("--observed-at", type=int, default=0)
    record.add_argument("--summary", type=Path)
    cli_hardware = subparsers.add_parser("parse-cli-hardware", help="Read CLI output on stdin; print model|serial|mac.")
    cli_hardware.add_argument("--family", required=True)
    snmp_hardware = subparsers.add_parser("parse-snmp-hardware", help="Read ENTITY-MIB OID<TAB>value lines on stdin; print model|serial|mac.")
    snmp_hardware.add_argument("--family", required=True)
    snmp_hardware.add_argument("--sysdescr", default="")
    snmp_hardware.add_argument("--bridge-mac", default="")
    args = parser.parse_args(argv)
    if args.operation in {"parse-cli-hardware", "parse-snmp-hardware"}:
        text = sys.stdin.read()
        if args.operation == "parse-cli-hardware":
            hardware = parse_cli_hardware(text, args.family)
        else:
            hardware = parse_snmp_hardware(args.family, text.splitlines(), sysdescr=args.sysdescr, bridge_mac=args.bridge_mac)
        print("|".join(hardware[field] or "N/A" for field in ("model", "serial", "mac")))
        return 0
    if args.operation == "merge-device-scan":
        rows, detail = merge_scan_files(
            args.inventory,
            args.targets,
            args.observations,
            observed_at=args.observed_at or None,
        )
        args.output.write_text(render_device_pipe(rows), encoding="utf-8")
        if args.summary:
            args.summary.write_text(json.dumps(detail, sort_keys=True) + "\n", encoding="utf-8")
        return 0
    if args.operation == "merge-device-record":
        try:
            rows, detail = merge_device_record(
                args.inventory,
                args.record,
                observed_at=args.observed_at or None,
            )
        except ValueError as exc:
            parser.error(str(exc))
        args.output.write_text(render_device_pipe(rows), encoding="utf-8")
        if args.summary:
            args.summary.write_text(json.dumps(detail, sort_keys=True) + "\n", encoding="utf-8")
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
