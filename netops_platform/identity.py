#!/usr/bin/env python3
"""Deterministic identity reconciliation for Netrune inventory."""

from __future__ import annotations

import difflib
import functools
import ipaddress
import os
import re
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from netops_platform.devices import device_manufacturer


def _environment(primary: str, legacy: str, default: Any = "") -> Any:
    return os.environ.get(primary, os.environ.get(legacy, default))


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
        _environment("NETRUNE_IDENTITY_STRIP_PREFIXES", "NETOPS_IDENTITY_STRIP_PREFIXES", "")
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
        _environment("NETRUNE_IDENTITY_STRIP_PREFIXES", "NETOPS_IDENTITY_STRIP_PREFIXES", ""),
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
        _environment("NETRUNE_IDENTITY_STRIP_PREFIXES", "NETOPS_IDENTITY_STRIP_PREFIXES", ""),
    )


def _asset_role_number(value: Any) -> Tuple[str, str]:
    text = normalize_asset_name(value)
    match = re.search(r"(AP|SW)0*(\d{1,5})(?!\d)", text)
    if not match:
        return "", ""
    return match.group(1), str(int(match.group(2)))


def _asset_location_prefix(value: Any) -> str:
    """Return the location portion of a name, the device-side analog of
    `ap_name_evidence`'s `location_key` -- everything before the role+number.
    """
    text = normalize_asset_name(value)
    match = re.search(r"(AP|SW)0*(\d{1,5})(?!\d)", text)
    if not match:
        return ""
    return normalize_location_label(text[:match.start()])


def name_key(value: Any) -> str:
    """The one key every module matches device names by (ADR 0008): the host
    label without its DNS domain, upper-cased, letters and digits only, so
    `sw-01.site.example.com`, `SW_01`, and `SW01` meet. Fuzzy identity scoring
    uses `normalize_asset_name` instead, which also strips configured prefixes."""
    return re.sub(r"[^A-Z0-9]", "", _host_label(value).upper())


def _host_label(value: Any) -> str:
    """Drop a DNS domain suffix so names are compared on the host label alone.

    Every switch in one site shares a long suffix like `.example.corp.com`,
    which on its own lifts two unrelated `*-SW01` names over the similarity
    threshold. Only a trailing all-alphabetic TLD counts as a domain, so a
    dotted name like `SITE.OFC.AP12` keeps its meaningful segments.
    """
    text = str(value or "").strip().rstrip(".")
    host, _, domain = text.partition(".")
    if host and domain and not _valid_ip(text) and re.fullmatch(r"[A-Za-z]{2,63}", domain.rsplit(".", 1)[-1]):
        return host
    return text


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
    key = "NETRUNE_AP_SIMILARITY_THRESHOLD" if kind == "ap" else "NETRUNE_SWITCH_SIMILARITY_THRESHOLD"
    legacy_key = key.replace("NETRUNE_", "NETOPS_", 1)
    default = 85 if kind == "ap" else 75
    try:
        threshold = max(50, min(100, int(_environment(key, legacy_key, default))))
    except (TypeError, ValueError):
        threshold = default
    left_name = left.get("name") or left.get("hostname") or ""
    right_name = right.get("name") or right.get("hostname") or ""
    left_key = normalize_asset_name(_host_label(left_name))
    right_key = normalize_asset_name(_host_label(right_name))
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
    if kind == "switch" and not (left_mac and left_mac == right_mac) and concurrently_distinct(left, right):
        conflicts.append("concurrent-addresses")

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


def continuity_match_evidence(
    old: Dict[str, Any],
    new: Dict[str, Any],
    entity_type: str,
    *,
    window_days: int = 14,
    port_swap: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Score whether `new` plausibly continues `old`'s identity after a swap.

    `port_swap` is the neighbour-port evidence for this exact pair (see
    neighbor_port_transitions): structural on its own, and with the rest of
    the neighbouring switch unchanged the strongest signal there is.

    This is deliberately not `identity_match_evidence`: there, a MAC/serial
    difference blocks a match outright, because that function answers "is
    this the same observation of one device." Here a MAC/serial difference is
    the expected case -- the whole point is a hardware swap -- so it is never
    scored as a conflict, just left unscored.

    Temporal proximity alone can never produce a candidate: at least one
    structural signal (attachment continuity, or a location+role match, or a
    bare role-number match) must hold first, so two unrelated devices that
    happen to churn on the same day never pair up on coincidence alone.
    """
    kind = "ap" if str(entity_type).lower() in {"ap", "access-point", "access_point"} else "switch"
    old_role, old_number = _asset_role_number(old.get("name"))
    new_role, new_number = _asset_role_number(new.get("name"))
    old_location = _asset_location_prefix(old.get("name"))
    new_location = _asset_location_prefix(new.get("name"))
    same_role_number = bool(old_role and old_role == new_role and old_number and old_number == new_number)
    same_location_and_role = bool(same_role_number and old_location and old_location == new_location)
    same_role_number_only = bool(same_role_number and not same_location_and_role)
    same_attachment_transition = bool(
        kind == "ap"
        and switch_learned_attachment(old)
        and switch_learned_attachment(new)
        and str(old.get("switch_ip") or old.get("switch_name") or "").strip().lower()
        == str(new.get("switch_ip") or new.get("switch_name") or "").strip().lower()
        and str(old.get("switch_port") or "").strip().lower() == str(new.get("switch_port") or "").strip().lower()
    )
    same_model = bool(old.get("model") and str(old.get("model")).lower() == str(new.get("model") or "").lower())
    signals: Dict[str, Any] = {
        "same_attachment_transition": same_attachment_transition,
        "same_location_and_role_number": same_location_and_role,
        "same_role_number_only": same_role_number_only,
        "same_model": same_model,
        "same_neighbor_port_transition": bool(port_swap),
    }
    if port_swap:
        signals["neighbor_port"] = f"{port_swap.get('local_ip')} {port_swap.get('local_port')}"
        signals["neighbor_port_confidence"] = int(port_swap.get("confidence") or 0)
        signals["neighbor_other_link_changes"] = int(port_swap.get("other_link_changes") or 0)
    structural = same_attachment_transition or same_location_and_role or same_role_number_only or bool(port_swap)
    score = 0
    if structural:
        score += round(int(port_swap.get("confidence") or 0) * 0.7) if port_swap else 0
        score += 45 if same_attachment_transition else 0
        score += 35 if same_location_and_role else 0
        score += 15 if same_role_number_only else 0
        score += 10 if same_model else 0
        try:
            old_last_seen = int(old.get("last_seen") or 0)
            new_first_seen = int(new.get("first_seen") or new.get("last_seen") or 0)
        except (TypeError, ValueError):
            old_last_seen = new_first_seen = 0
        gap_days = max(0.0, (new_first_seen - old_last_seen) / 86400.0) if (old_last_seen and new_first_seen) else float(window_days)
        proximity = max(0.0, 1.0 - (gap_days / window_days)) if window_days > 0 else 0.0
        signals["temporal_gap_days"] = round(gap_days, 2)
        score += round(20 * proximity)
    return {
        "candidate": structural,
        "confidence": min(100, score) if structural else 0,
        "entity_type": kind,
        "signals": signals,
    }


PORT_TRANSITION_SCAN_SECONDS = 600
PORT_TRANSITION_GAP_DAYS = 3


def neighbor_port_transitions(events: Sequence[Mapping[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """What the neighbour tables say happened to devices, from topology link events.

    swaps: on one local switch port, the link to A went and a link to B came
    (one scan, or B within PORT_TRANSITION_GAP_DAYS with nothing in between):
    B now stands where A stood -- a replacement, or A renamed B. Confidence
    rests on how still the rest of that switch was: no other link changing
    on it in that scan is the strongest case there is.

    moves: one neighbour name left one port and appeared on another.

    `events` are topology_events rows (created_at, event_type link_added /
    link_removed, local_ip, local_port, remote_name, remote_ip), any order.
    """
    def key(name: Any) -> str:
        text = str(name or "").strip()
        # Not a device that can stand in a switch or AP position: a host with
        # no LLDP name (reported by its address), or an IP phone.
        if _valid_ip(text) or re.fullmatch(r"SEP[0-9A-F]{12}", text, re.I):
            return ""
        return normalize_asset_name(_host_label(name))

    ordered = sorted((dict(event) for event in events), key=lambda event: (int(event.get("created_at") or 0), event.get("event_type") != "link_removed"))
    churn: Dict[Tuple[str, int], int] = {}
    port_adds: Dict[Tuple[str, str, int], int] = {}
    for event in ordered:
        bucket = (str(event.get("local_ip") or ""), int(event.get("created_at") or 0) // PORT_TRANSITION_SCAN_SECONDS)
        churn[bucket] = churn.get(bucket, 0) + 1
        if event.get("event_type") == "link_added":
            port = (bucket[0], str(event.get("local_port") or ""), bucket[1])
            port_adds[port] = port_adds.get(port, 0) + 1
    # A port that sees several neighbours at once (a shared uplink, a hub, a
    # media converter) is not one position; a change there says nothing about
    # who replaced whom.
    present: Dict[Tuple[str, str], set] = {}
    removed: Dict[Tuple[str, str], Dict[str, Any]] = {}
    gone: Dict[str, Dict[str, Any]] = {}
    swaps: List[Dict[str, Any]] = []
    moves: List[Dict[str, Any]] = []
    for event in ordered:
        local = (str(event.get("local_ip") or ""), str(event.get("local_port") or ""))
        name = key(event.get("remote_name"))
        if not local[0] or not local[1] or not name:
            continue
        when = int(event.get("created_at") or 0)
        if event.get("event_type") == "link_removed":
            present.setdefault(local, set()).discard(name)
            removed[local] = event
            gone[name] = event
            continue
        if event.get("event_type") != "link_added":
            continue
        before = removed.pop(local, None)
        alone = not present.get(local) and port_adds.get((local[0], local[1], when // PORT_TRANSITION_SCAN_SECONDS), 0) == 1
        present.setdefault(local, set()).add(name)
        if before and alone and key(before.get("remote_name")) != name:
            gap = when - int(before.get("created_at") or 0)
            if gap <= PORT_TRANSITION_GAP_DAYS * 86400:
                bucket = (local[0], when // PORT_TRANSITION_SCAN_SECONDS)
                others = churn.get(bucket, 0) - (2 if gap < PORT_TRANSITION_SCAN_SECONDS else 1)
                confidence = (90 if others <= 0 else 75 if others <= 2 else 55) - (15 if gap >= PORT_TRANSITION_SCAN_SECONDS else 0)
                swaps.append({
                    "old_name": _host_label(before.get("remote_name")), "new_name": _host_label(event.get("remote_name")),
                    "old_key": key(before.get("remote_name")), "new_key": name,
                    "old_ip": str(before.get("remote_ip") or ""), "new_ip": str(event.get("remote_ip") or ""),
                    "local_ip": local[0], "local_port": local[1], "when": when, "gap_seconds": gap,
                    "other_link_changes": max(0, others), "confidence": confidence,
                })
        earlier = gone.pop(name, None)
        if earlier and (str(earlier.get("local_ip") or ""), str(earlier.get("local_port") or "")) != local \
                and when - int(earlier.get("created_at") or 0) <= PORT_TRANSITION_GAP_DAYS * 86400:
            moves.append({
                "name": _host_label(event.get("remote_name")), "key": name, "when": when,
                "from": f"{earlier.get('local_ip')} {earlier.get('local_port')}", "to": f"{local[0]} {local[1]}",
            })
    # A port that goes A -> B and later B -> A sees two devices in turn (a
    # flapping link, a redundant path), not a replacement: drop both.
    flapping = {
        index for index, swap in enumerate(swaps) for later in swaps[index + 1:]
        if (later["local_ip"], later["local_port"], later["old_key"], later["new_key"])
        == (swap["local_ip"], swap["local_port"], swap["new_key"], swap["old_key"])
    }
    flapping |= {
        index for index, swap in enumerate(swaps) for earlier in swaps[:index]
        if (earlier["local_ip"], earlier["local_port"], earlier["old_key"], earlier["new_key"])
        == (swap["local_ip"], swap["local_port"], swap["new_key"], swap["old_key"])
    }
    return {"swaps": [swap for index, swap in enumerate(swaps) if index not in flapping], "moves": moves}


def identity_continuity_candidates(
    old_pool: Sequence[Dict[str, Any]],
    new_pool: Sequence[Dict[str, Any]],
    entity_type: str,
    *,
    window_days: int = 14,
    port_swaps: Sequence[Mapping[str, Any]] = (),
) -> List[Dict[str, Any]]:
    """Pair disappeared identities against newly-appeared ones.

    Bucketed by shared attachment / location+role / role-only keys first
    (mirroring `reconcile_ap_rows`'s own strategy) so this stays proportional
    to what actually shares a signal rather than comparing every pair.
    `port_swaps` (neighbor_port_transitions' swaps) pair an old and a new
    name directly: a neighbour port that saw the old device now sees the new.
    """
    if not old_pool or not new_pool:
        return []
    kind = "ap" if str(entity_type).lower() in {"ap", "access-point", "access_point"} else "switch"

    def buckets(rows: Sequence[Dict[str, Any]]) -> Tuple[Dict[Any, List[int]], Dict[Any, List[int]], Dict[Any, List[int]]]:
        attachment: Dict[Any, List[int]] = {}
        location_role: Dict[Any, List[int]] = {}
        role_only: Dict[Any, List[int]] = {}
        for index, row in enumerate(rows):
            if kind == "ap" and switch_learned_attachment(row):
                key = (str(row.get("switch_ip") or row.get("switch_name") or "").strip().lower(),
                       str(row.get("switch_port") or "").strip().lower())
                attachment.setdefault(key, []).append(index)
            role, number = _asset_role_number(row.get("name"))
            if role and number:
                location = _asset_location_prefix(row.get("name"))
                if location:
                    location_role.setdefault((location, role, number), []).append(index)
                role_only.setdefault((role, number), []).append(index)
        return attachment, location_role, role_only

    old_attachment, old_location_role, old_role_only = buckets(old_pool)
    new_attachment, new_location_role, new_role_only = buckets(new_pool)
    pairs: set[Tuple[int, int]] = set()
    for old_buckets, new_buckets in ((old_attachment, new_attachment), (old_location_role, new_location_role), (old_role_only, new_role_only)):
        for key, old_indexes in old_buckets.items():
            for new_index in new_buckets.get(key, []):
                for old_index in old_indexes:
                    pairs.add((old_index, new_index))
    by_pair: Dict[Tuple[str, str], Mapping[str, Any]] = {}
    for swap in port_swaps:
        pair_key = (swap["old_key"], swap["new_key"])
        if pair_key not in by_pair or swap["confidence"] > by_pair[pair_key]["confidence"]:
            by_pair[pair_key] = swap
    if by_pair:
        def names(rows: Sequence[Dict[str, Any]]) -> Dict[str, List[int]]:
            found: Dict[str, List[int]] = {}
            for index, row in enumerate(rows):
                found.setdefault(normalize_asset_name(_host_label(row.get("name"))), []).append(index)
            return found
        old_names, new_names = names(old_pool), names(new_pool)
        for old_key, new_key in by_pair:
            for old_index in old_names.get(old_key, []):
                for new_index in new_names.get(new_key, []):
                    pairs.add((old_index, new_index))

    results: List[Dict[str, Any]] = []
    for old_index, new_index in sorted(pairs):
        old_row, new_row = old_pool[old_index], new_pool[new_index]
        swap = by_pair.get((normalize_asset_name(_host_label(old_row.get("name"))), normalize_asset_name(_host_label(new_row.get("name")))))
        assessment = continuity_match_evidence(old_row, new_row, kind, window_days=window_days, port_swap=swap)
        if not assessment["candidate"]:
            continue
        results.append({
            "old": old_pool[old_index],
            "new": new_pool[new_index],
            "confidence": assessment["confidence"],
            "signals": assessment["signals"],
            "entity_type": kind,
        })
    results.sort(key=lambda item: -item["confidence"])
    return results


def cluster_rename_candidates(
    candidate_rows: Sequence[Dict[str, Any]],
    *,
    min_members: int = 3,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Group candidates that share an old->new location mapping and asset number.

    A whole-site rename shows up as many candidates that all preserve the same
    role+number but move from one location prefix to another; collapsing those
    into one cluster is what lets an operator confirm a pattern once instead of
    reviewing N unrelated-looking rows. Pairs that don't cluster pass through
    unchanged as singles. Returns (clusters, singles).
    """
    groups: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
    singles: List[Dict[str, Any]] = []
    for row in candidate_rows:
        old = row.get("old") or {}
        new = row.get("new") or {}
        old_role, old_number = _asset_role_number(old.get("name"))
        new_role, new_number = _asset_role_number(new.get("name"))
        old_prefix = _asset_location_prefix(old.get("name"))
        new_prefix = _asset_location_prefix(new.get("name"))
        same_asset = bool(old_role and old_role == new_role and old_number and old_number == new_number)
        if old_prefix and new_prefix and old_prefix != new_prefix and same_asset:
            groups.setdefault((old_prefix, new_prefix), []).append(row)
        else:
            singles.append(row)
    clusters: List[Dict[str, Any]] = []
    for (old_prefix, new_prefix), members in groups.items():
        if len(members) >= min_members:
            clusters.append({
                "old_location_prefix": old_prefix,
                "new_location_prefix": new_prefix,
                "member_count": len(members),
                "members": members,
            })
        else:
            singles.extend(members)
    return clusters, singles


@functools.lru_cache(maxsize=8192)
def _valid_ip_text(value: str) -> bool:
    try:
        return str(ipaddress.ip_address(value.strip())) != "0.0.0.0"
    except ValueError:
        return False


def _valid_ip(value: Any) -> bool:
    return _valid_ip_text(str(value or ""))


CONCURRENT_SECONDS = 900


def concurrently_distinct(left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
    """Two switch records that cannot be one box: different management IPs,
    both online, both seen in the same scan. Whatever their names share is
    coincidence, not identity. Fuzzy name matching once fused four C2960S
    switches named `...-SW01`, none with a MAC or serial yet, into one record
    for a week (similar names, same role/number, same model), and a real
    replacement's serial then spread to all four."""
    left_ip = str(left.get("ip") or "").strip() if _valid_ip(left.get("ip")) else ""
    right_ip = str(right.get("ip") or "").strip() if _valid_ip(right.get("ip")) else ""
    if not (left_ip and right_ip and left_ip != right_ip):
        return False
    if any(str(row.get("status") or "").upper() != "ONLINE" for row in (left, right)):
        return False
    try:
        seen = int(left.get("last_seen") or 0), int(right.get("last_seen") or 0)
    except (TypeError, ValueError):
        return False
    return all(seen) and abs(seen[0] - seen[1]) <= CONCURRENT_SECONDS


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


def switch_learned_attachment(row: Dict[str, Any]) -> bool:
    """Report whether a row names a real switch port rather than a controller."""
    return bool(
        (row.get("switch_ip") or row.get("switch_name"))
        and str(row.get("switch_port") or "").strip().lower()
        not in {"", "n/a", "wireless", "not-joined", "not joined", "unjoined", "nonjoined"}
    )


def _attachment_score(row: Dict[str, Any]) -> Tuple[int, int]:
    try:
        seen = int(row.get("last_seen") or 0)
    except (TypeError, ValueError):
        seen = 0
    return (1 if switch_learned_attachment(row) else 0, seen)


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
        # Attachment is a different fact from identity. A wireless controller
        # knows an AP's address and name but reports its port as "wireless";
        # only the switch knows the physical port. Take the port from whichever
        # member actually learned it rather than from whichever row won on
        # identity, so a controller record can no longer erase it.
        attachment = max(members, key=_attachment_score)
        if switch_learned_attachment(attachment):
            row["switch_ip"] = attachment.get("switch_ip") or ""
            row["switch_name"] = attachment.get("switch_name") or ""
            row["switch_port"] = attachment.get("switch_port") or ""
            row["attachment_source"] = "switch"
        elif switch_learned_attachment(row):
            row["attachment_source"] = "switch"
        elif row.get("switch_ip") or row.get("switch_name"):
            row["attachment_source"] = "controller"
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
                "manufacturer": device_manufacturer(platform=row.get("platform"), model=row.get("model")),
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
    for (kind, _), indexes in buckets.items():
        candidate_pairs.update(_anchor_pairs(indexes))
        first = indexes[0]
        for right in indexes[1:]:
            if kind == "name" and concurrently_distinct(source[first], source[right]):
                continue
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
            "manufacturer": device_manufacturer(platform=row.get("platform"), model=row.get("model")),
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
