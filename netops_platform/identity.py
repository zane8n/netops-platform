#!/usr/bin/env python3
"""Deterministic identity reconciliation for NetOps inventory."""

from __future__ import annotations

import difflib
import functools
import ipaddress
import os
import re
from typing import Any, Dict, List, Sequence, Tuple


def normalize_mac(value: Any) -> str:
    """Return a canonical physical unicast MAC, or an empty string if invalid."""
    text = re.sub(r"[^0-9a-f]", "", str(value or "").lower())
    if len(text) != 12 or text in {"000000000000", "ffffffffffff"}:
        return ""
    # Inventory identities must be physical unicast addresses. An all-zero OUI
    # is also a common SNMP/parser placeholder rather than a device identity.
    if text.startswith("000000") or int(text[:2], 16) & 1:
        return ""
    return text


@functools.lru_cache(maxsize=32)
def _configured_prefixes(configuration: str) -> Tuple[str, ...]:
    return tuple(
        prefix
        for prefix in (
            re.sub(r"[^A-Z0-9]", "", item.upper())
            for item in configuration.split(",")
        )
        if prefix
    )


def _strip_org_prefixes(value: str, configuration: str | None = None) -> str:
    text = value
    prefixes = _configured_prefixes(
        os.environ.get("NETOPS_IDENTITY_STRIP_PREFIXES", "")
        if configuration is None else configuration
    )
    changed = True
    while changed:
        changed = False
        for prefix in prefixes:
            if text.startswith(prefix) and len(text) > len(prefix):
                text = text[len(prefix):]
                changed = True
                break
    return text


@functools.lru_cache(maxsize=4096)
def _normalize_location_text(raw: str, prefixes: str) -> str:
    text = re.sub(r"[^A-Z0-9]", "", raw.upper())
    text = _strip_org_prefixes(text, prefixes)
    replacements = (
        (r"SQUARE0*(\d+)", r"SQ\1"),
        (r"HOUSE0*(\d+)", r"H\1"),
        (r"(?:BUILDING|BLDG|BLD)0*(\d+)", r"BLDG\1"),
        (r"CAMP", "CMP"),
        (r"ENGINEERING", "ENGG"),
        (r"OFFICE", "OFC"),
    )
    for pattern, replacement in replacements:
        text = re.sub(pattern, replacement, text)
    return text


def normalize_location_label(value: Any) -> str:
    """Normalize common site words while retaining meaningful qualifiers."""
    return _normalize_location_text(
        str(value or ""),
        os.environ.get("NETOPS_IDENTITY_STRIP_PREFIXES", ""),
    )


def ap_name_evidence(name: Any) -> Dict[str, Any]:
    raw = str(name or "").strip()
    compact = re.sub(r"[^A-Z0-9]", "", raw.upper())
    matches = list(re.finditer(r"AP0*(\d{1,5})(?!\d)", compact))
    if not matches:
        return {"raw": raw, "name_key": compact, "ap_number": "", "location_key": "", "signature": ""}
    match = matches[-1]
    ap_number = str(int(match.group(1)))
    location = normalize_location_label(compact[:match.start()])
    signature = f"{location}:AP{ap_number}" if location else ""
    return {
        "raw": raw,
        "name_key": compact,
        "ap_number": ap_number,
        "location_key": location,
        "signature": signature,
    }


@functools.lru_cache(maxsize=8192)
def _normalize_asset_text(raw: str, prefixes: str) -> str:
    text = re.sub(r"[^A-Z0-9]", "", raw.upper())
    text = _strip_org_prefixes(text, prefixes)
    replacements = (
        (r"PLANT", "PLNT"),
        (r"PLAN(?=AP|SW|\d|$)", "PLN"),
        (r"SQUARE0*(\d+)", r"SQ\1"),
        (r"HOUSE0*(\d+)", r"H\1"),
        (r"(?:BUILDING|BLDG|BLD)0*(\d+)", r"BLDG\1"),
        (r"CAMP", "CMP"),
        (r"ENGINEERING", "ENGG"),
        (r"OFFICE", "OFC"),
        (r"SWITCH", "SW"),
        (r"ACCESSPOINT", "AP"),
    )
    for pattern, replacement in replacements:
        text = re.sub(pattern, replacement, text)
    return text


def normalize_asset_name(value: Any) -> str:
    """Normalize naming variants while preserving role and asset ID."""
    return _normalize_asset_text(
        str(value or ""),
        os.environ.get("NETOPS_IDENTITY_STRIP_PREFIXES", ""),
    )


def _asset_role_number(value: Any) -> Tuple[str, str]:
    text = normalize_asset_name(value)
    match = re.search(r"(AP|SW)0*(\d{1,5})(?!\d)", text)
    if not match:
        return "", ""
    return match.group(1), str(int(match.group(2)))


def _meaningful_serial(value: Any) -> str:
    text = re.sub(r"[^A-Z0-9]", "", str(value or "").upper())
    return "" if text in {"", "NA", "NONE", "NULL", "UNKNOWN", "NOTAVAILABLE"} else text


def identity_match_evidence(
    left: Dict[str, Any],
    right: Dict[str, Any],
    entity_type: str,
) -> Dict[str, Any]:
    """Score two observations using names plus physical and attachment evidence.

    Names create candidates at profile-configured similarity thresholds.
    Conflicting physical identifiers always block an automatic merge.
    """
    kind = "ap" if str(entity_type).lower() in {"ap", "access-point", "access_point"} else "switch"
    key = "NETOPS_AP_SIMILARITY_THRESHOLD" if kind == "ap" else "NETOPS_SWITCH_SIMILARITY_THRESHOLD"
    default = 85 if kind == "ap" else 75
    try:
        threshold = max(50, min(100, int(os.environ.get(key, default))))
    except (TypeError, ValueError):
        threshold = default
    left_name = left.get("name") or left.get("hostname") or ""
    right_name = right.get("name") or right.get("hostname") or ""
    left_key = normalize_asset_name(left_name)
    right_key = normalize_asset_name(right_name)
    similarity = int(round(difflib.SequenceMatcher(None, left_key, right_key).ratio() * 100)) if left_key and right_key else 0
    left_mac, right_mac = normalize_mac(left.get("mac")), normalize_mac(right.get("mac"))
    left_serial, right_serial = _meaningful_serial(left.get("serial")), _meaningful_serial(right.get("serial"))
    left_ip = str(left.get("ip") or "").strip() if _valid_ip(left.get("ip")) else ""
    right_ip = str(right.get("ip") or "").strip() if _valid_ip(right.get("ip")) else ""
    left_role, left_number = _asset_role_number(left_name)
    right_role, right_number = _asset_role_number(right_name)
    same_asset_number = bool(left_role and left_role == right_role and left_number and left_number == right_number)
    role_number_conflict = bool(left_role and right_role and left_role == right_role and left_number and right_number and left_number != right_number)
    same_attachment = bool(
        kind == "ap"
        and str(left.get("switch_ip") or left.get("switch_name") or "").strip().lower()
        == str(right.get("switch_ip") or right.get("switch_name") or "").strip().lower()
        and str(left.get("switch_ip") or left.get("switch_name") or "").strip()
        and str(left.get("switch_port") or "").strip().lower()
        == str(right.get("switch_port") or "").strip().lower()
        and str(left.get("switch_port") or "").strip().lower() not in {"", "n/a", "wireless", "not-joined"}
    )
    conflicts: List[str] = []
    if left_mac and right_mac and left_mac != right_mac:
        conflicts.append("mac")
    if left_serial and right_serial and left_serial != right_serial:
        conflicts.append("serial")
    if role_number_conflict:
        conflicts.append("asset-number")

    signals: Dict[str, Any] = {
        "name_similarity": similarity,
        "name_threshold": threshold,
        "same_mac": bool(left_mac and left_mac == right_mac),
        "same_serial": bool(left_serial and left_serial == right_serial),
        "same_ip": bool(left_ip and left_ip == right_ip),
        "same_attachment": same_attachment,
        "same_asset_number": same_asset_number,
        "same_model": bool(left.get("model") and str(left.get("model")).lower() == str(right.get("model") or "").lower()),
    }
    score = 0
    score += 100 if signals["same_mac"] else 0
    score += 95 if signals["same_serial"] else 0
    score += 80 if signals["same_ip"] else 0
    score += 75 if signals["same_attachment"] else 0
    score += 20 if signals["same_asset_number"] else 0
    score += 10 if signals["same_model"] else 0
    if similarity >= threshold:
        score += 45 if kind == "ap" else 40
    elif similarity:
        score += int(similarity * 0.25)
    strong_identity = any(signals[key] for key in ("same_mac", "same_serial", "same_ip", "same_attachment"))
    name_identity = similarity >= threshold and (
        left_key == right_key
        or (same_asset_number and signals["same_model"])
    )
    same_device = not conflicts and (strong_identity or name_identity)
    confidence = min(100, max(threshold, score) if same_device else min(score, 74))
    return {
        "same_device": same_device,
        "candidate": not conflicts and similarity >= threshold,
        "confidence": confidence,
        "entity_type": kind,
        "signals": signals,
        "conflicts": conflicts,
        "left_normalized_name": left_key,
        "right_normalized_name": right_key,
    }


@functools.lru_cache(maxsize=8192)
def _valid_ip_text(value: str) -> bool:
    try:
        return str(ipaddress.ip_address(value.strip())) != "0.0.0.0"
    except ValueError:
        return False


def _valid_ip(value: Any) -> bool:
    return _valid_ip_text(str(value or ""))


def _anchor_pairs(indexes: Sequence[int]) -> set[Tuple[int, int]]:
    """Return the minimum pair set needed to connect one equality bucket."""
    if len(indexes) < 2:
        return set()
    first = indexes[0]
    return {(min(first, item), max(first, item)) for item in indexes[1:]}


def _all_pairs(indexes: Sequence[int]) -> set[Tuple[int, int]]:
    return {
        (left, right)
        for offset, left in enumerate(indexes)
        for right in indexes[offset + 1:]
    }


def _row_score(row: Dict[str, Any]) -> Tuple[int, int, int, int, int, int]:
    status = str(row.get("status") or "").upper()
    attached = bool(
        (row.get("switch_ip") or row.get("switch_name"))
        and str(row.get("switch_port") or "").lower() not in {"", "n/a", "not-joined", "wireless"}
    )
    try:
        seen = int(row.get("last_seen") or 0)
    except (TypeError, ValueError):
        seen = 0
    return (
        1 if status == "ONLINE" else 0,
        1 if _valid_ip(row.get("ip")) else 0,
        1 if attached else 0,
        1 if normalize_mac(row.get("mac")) else 0,
        1 if row.get("platform") else 0,
        seen,
    )


def reconcile_ap_rows(rows: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Collapse aliases without merging records carrying conflicting valid MACs."""
    source: List[Dict[str, Any]] = []
    generic_names = {"", "N/A", "UNKNOWN", "NONE", "NULL", "CISCO-AP", "RUCKUS-AP", "AP"}
    for raw in rows:
        if not isinstance(raw, dict):
            continue
        row = dict(raw)
        name = str(row.get("name") or "").strip()
        inferred_mac = normalize_mac(row.get("mac"))
        if not inferred_mac and re.fullmatch(r"[0-9A-Fa-f:\-. ]{12,24}", name):
            inferred_mac = normalize_mac(name)
        valid_ip = _valid_ip(row.get("ip"))
        meaningful_name = name.upper() not in generic_names
        if not valid_ip and not inferred_mac and not meaningful_name:
            continue
        row["mac"] = inferred_mac
        source.append(row)
    if not source:
        return []

    evidence = []
    for row in source:
        item = ap_name_evidence(row.get("name"))
        item["mac_key"] = normalize_mac(row.get("mac"))
        item["ip_key"] = str(row.get("ip") or "").strip() if _valid_ip(row.get("ip")) else ""
        evidence.append(item)

    parent = list(range(len(source)))
    group_macs = [{item["mac_key"]} if item["mac_key"] else set() for item in evidence]

    def find(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    def union(left: int, right: int) -> bool:
        a, b = find(left), find(right)
        if a == b:
            return True
        combined_macs = group_macs[a] | group_macs[b]
        if len(combined_macs) > 1:
            return False
        parent[b] = a
        group_macs[a] = combined_macs
        return True

    buckets: Dict[Tuple[str, str], List[int]] = {}
    for index, item in enumerate(evidence):
        keys = []
        if item["mac_key"]:
            keys.append(("mac", item["mac_key"]))
        if item["signature"]:
            keys.append(("signature", item["signature"]))
        if item["name_key"]:
            keys.append(("name", item["name_key"]))
        if item["ip_key"]:
            keys.append(("ip", item["ip_key"]))
        for key in keys:
            buckets.setdefault(key, []).append(index)

    candidate_pairs: set[Tuple[int, int]] = set()
    for indexes in buckets.values():
        candidate_pairs.update(_anchor_pairs(indexes))
        first = indexes[0]
        for right in indexes[1:]:
            union(first, right)

    # Similarity is only capable of merging rows that also share a physical,
    # attachment, or role/model signal. Build those candidate blocks instead
    # of comparing every AP with every other AP.
    scored_buckets: Dict[Tuple[str, ...], List[int]] = {}
    for index, row in enumerate(source):
        serial = _meaningful_serial(row.get("serial"))
        if serial:
            scored_buckets.setdefault(("serial", serial), []).append(index)
        switch = str(row.get("switch_ip") or row.get("switch_name") or "").strip().lower()
        port = str(row.get("switch_port") or "").strip().lower()
        if switch and port not in {"", "n/a", "wireless", "not-joined"}:
            scored_buckets.setdefault(("attachment", switch, port), []).append(index)
        role, number = _asset_role_number(row.get("name"))
        model = str(row.get("model") or "").strip().lower()
        if role and number and model:
            scored_buckets.setdefault(("role-model", role, number, model), []).append(index)
    for indexes in scored_buckets.values():
        candidate_pairs.update(_all_pairs(indexes))

    pair_confidence: Dict[Tuple[int, int], int] = {}
    for left, right in sorted(candidate_pairs):
        assessment = identity_match_evidence(source[left], source[right], "ap")
        pair_confidence[(left, right)] = int(assessment["confidence"])
        if assessment["same_device"]:
            union(left, right)

    groups: Dict[int, List[int]] = {}
    for index in range(len(source)):
        groups.setdefault(find(index), []).append(index)

    reconciled: List[Dict[str, Any]] = []
    for indexes in groups.values():
        members = [source[index] for index in indexes]
        member_evidence = [evidence[index] for index in indexes]
        best = max(members, key=_row_score)
        row = dict(best)
        aliases = sorted({str(item.get("name") or "").strip() for item in members if item.get("name")})
        addresses = sorted({str(item.get("ip") or "").strip() for item in members if _valid_ip(item.get("ip"))})
        if addresses and not _valid_ip(row.get("ip")):
            row["ip"] = addresses[0]
        elif not addresses and not _valid_ip(row.get("ip")):
            row["ip"] = ""
        macs = sorted({normalize_mac(item.get("mac")) for item in members if normalize_mac(item.get("mac"))})
        signatures = sorted({item["signature"] for item in member_evidence if item["signature"]})
        online = any(str(item.get("status") or "").upper() == "ONLINE" for item in members)
        offline = all(str(item.get("status") or "").upper() == "OFFLINE" for item in members)
        if online:
            row["status"] = "ONLINE"
        elif offline:
            row["status"] = "OFFLINE"
        else:
            row["status"] = "UNKNOWN"
        row["last_seen"] = max((int(item.get("last_seen") or 0) for item in members), default=0)
        assessed_confidence = max(
            (pair_confidence.get((min(left, right), max(left, right)), 0) for left in indexes for right in indexes if left < right),
            default=0,
        )
        if macs:
            canonical_id = "mac:" + macs[0]
            confidence = 100
        elif signatures:
            canonical_id = "ap:" + signatures[0].lower()
            confidence = max(92, assessed_confidence)
        else:
            canonical_id = "row:" + str(row.get("ip") or row.get("name") or len(reconciled)).lower()
            confidence = max(60, assessed_confidence)
        row.update(
            {
                "canonical_id": canonical_id,
                "identity_confidence": confidence,
                "identity_conflict": len(macs) > 1,
                "merged_records": len(members),
                "aliases": aliases,
                "alias_names": ", ".join(aliases),
                "addresses": addresses,
                "macs": macs,
                "identity_signature": signatures[0] if signatures else "",
            }
        )
        reconciled.append(row)

    reconciled.sort(
        key=lambda row: (
            0 if str(row.get("status") or "").upper() == "OFFLINE" else 1,
            str(row.get("name") or row.get("ip") or "").lower(),
        )
    )
    return reconciled


def reconcile_device_rows(rows: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Build canonical switch/device rows while retaining aliases and addresses."""
    source: List[Dict[str, Any]] = []
    for raw in rows:
        if not isinstance(raw, dict):
            continue
        row = dict(raw)
        row["name"] = str(row.get("name") or row.get("hostname") or "").strip()
        row["hostname"] = row["name"]
        row["mac"] = normalize_mac(row.get("mac"))
        if not (_valid_ip(row.get("ip")) or row["mac"] or _meaningful_serial(row.get("serial")) or row["name"]):
            continue
        source.append(row)
    if not source:
        return []

    parent = list(range(len(source)))
    group_macs = [{row["mac"]} if row["mac"] else set() for row in source]
    group_serials = [{_meaningful_serial(row.get("serial"))} if _meaningful_serial(row.get("serial")) else set() for row in source]

    def find(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    def union(left: int, right: int) -> bool:
        a, b = find(left), find(right)
        if a == b:
            return True
        macs = group_macs[a] | group_macs[b]
        serials = group_serials[a] | group_serials[b]
        if len(macs) > 1 or len(serials) > 1:
            return False
        parent[b] = a
        group_macs[a] = macs
        group_serials[a] = serials
        return True

    buckets: Dict[Tuple[str, str], List[int]] = {}
    for index, row in enumerate(source):
        values = {
            "ip": str(row.get("ip") or "").strip() if _valid_ip(row.get("ip")) else "",
            "mac": row["mac"],
            "serial": _meaningful_serial(row.get("serial")),
            "name": normalize_asset_name(row.get("name")),
        }
        for kind, value in values.items():
            if value:
                buckets.setdefault((kind, value), []).append(index)
    candidate_pairs: set[Tuple[int, int]] = set()
    for indexes in buckets.values():
        candidate_pairs.update(_anchor_pairs(indexes))
        first = indexes[0]
        for right in indexes[1:]:
            union(first, right)

    fuzzy_buckets: Dict[Tuple[str, str, str], List[int]] = {}
    for index, row in enumerate(source):
        role, number = _asset_role_number(row.get("name"))
        model = str(row.get("model") or "").strip().lower()
        if role and number and model:
            fuzzy_buckets.setdefault((role, number, model), []).append(index)
    for indexes in fuzzy_buckets.values():
        candidate_pairs.update(_all_pairs(indexes))

    pair_assessments: Dict[Tuple[int, int], Dict[str, Any]] = {}
    for left, right in sorted(candidate_pairs):
        assessment = identity_match_evidence(source[left], source[right], "switch")
        pair_assessments[(left, right)] = assessment
        if assessment["same_device"]:
            union(left, right)

    groups: Dict[int, List[int]] = {}
    for index in range(len(source)):
        groups.setdefault(find(index), []).append(index)

    def score(row: Dict[str, Any]) -> Tuple[int, int, int, int, int, int]:
        try:
            seen = int(row.get("last_seen") or 0)
        except (TypeError, ValueError):
            seen = 0
        return (
            1 if str(row.get("status") or "").upper() == "ONLINE" else 0,
            1 if _valid_ip(row.get("ip")) else 0,
            1 if normalize_mac(row.get("mac")) else 0,
            1 if _meaningful_serial(row.get("serial")) else 0,
            1 if row.get("model") else 0,
            seen,
        )

    reconciled: List[Dict[str, Any]] = []
    for indexes in groups.values():
        members = [source[index] for index in indexes]
        row = dict(max(members, key=score))
        aliases = sorted({str(item.get("name") or item.get("hostname") or "").strip() for item in members if item.get("name") or item.get("hostname")})
        addresses = sorted({str(item.get("ip") or "").strip() for item in members if _valid_ip(item.get("ip"))})
        macs = sorted({normalize_mac(item.get("mac")) for item in members if normalize_mac(item.get("mac"))})
        serials = sorted({_meaningful_serial(item.get("serial")) for item in members if _meaningful_serial(item.get("serial"))})
        if any(str(item.get("status") or "").upper() == "ONLINE" for item in members):
            row["status"] = "ONLINE"
        elif all(str(item.get("status") or "").upper() == "OFFLINE" for item in members):
            row["status"] = "OFFLINE"
        else:
            row["status"] = "UNKNOWN"
        row["last_seen"] = max((int(item.get("last_seen") or 0) for item in members), default=0)
        assessed_confidence = max(
            (
                int(pair_assessments.get((min(left, right), max(left, right)), {}).get("confidence") or 0)
                for left in indexes for right in indexes if left < right
            ),
            default=0,
        )
        if macs:
            canonical_id, confidence = "mac:" + macs[0], 100
        elif serials:
            canonical_id, confidence = "serial:" + serials[0].lower(), 98
        elif aliases:
            canonical_id = "switch:" + normalize_asset_name(aliases[0]).lower()
            confidence = max(75, assessed_confidence) if len(members) > 1 else 65
        else:
            canonical_id, confidence = "ip:" + str(row.get("ip") or "unknown"), 60
        row.update({
            "name": row.get("name") or row.get("hostname") or "",
            "hostname": row.get("hostname") or row.get("name") or "",
            "canonical_id": canonical_id,
            "identity_confidence": confidence,
            "identity_conflict": len(macs) > 1 or len(serials) > 1,
            "merged_records": len(members),
            "aliases": aliases,
            "alias_names": ", ".join(aliases),
            "addresses": addresses,
            "macs": macs,
            "serials": serials,
        })
        reconciled.append(row)
    reconciled.sort(key=lambda row: (0 if str(row.get("status") or "").upper() == "OFFLINE" else 1, str(row.get("hostname") or row.get("ip") or "").lower()))
    return reconciled


def ap_rows_match(row: Dict[str, Any], query: Any) -> bool:
    needle = re.sub(r"[^A-Z0-9]", "", str(query or "").upper())
    if not needle:
        return True
    values = [
        row.get("name"), row.get("ip"), row.get("platform"), row.get("switch_name"),
        row.get("switch_port"), row.get("canonical_id"), row.get("identity_signature"),
    ]
    values.extend(row.get("aliases") or [])
    values.extend(row.get("addresses") or [])
    return any(needle in re.sub(r"[^A-Z0-9]", "", str(value or "").upper()) for value in values)
