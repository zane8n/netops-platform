#!/usr/bin/env python3
"""Normalized inventory-ingest boundary for shell, SNMP, and future providers."""

from __future__ import annotations

import argparse
import json
import re
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
    row["model"] = row["model"] if _meaningful(row["model"]) else "N/A"
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
    for field in ("hostname", "platform", "model", "serial", "mac"):
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
    parser = argparse.ArgumentParser(description="NetOps normalized inventory ingest")
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
    args = parser.parse_args(argv)
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
