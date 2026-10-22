"""The AP scan's merge: controller readings, switch readings, and what was there.

This replaces the awk merge that lived inside `netops-discovery`'s
`discover_aps` (ADR 0008 phase 2): the shell still collects, and Python now
judges. The rules, in one place:

- what an AP is and what it is called come from the controller; where it is
  plugged in comes from the switch; the platform is whichever names a model,
  the controller first (`pick_platform`);
- a switch reading joins the controller record by MAC, then hostname, then
  address (Cisco controllers report the radio MAC, LLDP the Ethernet MAC);
  when both have one, the controller's MAC is kept: the switch's is a MAC
  table guess that is sometimes a client's;
- an AP recorded without a MAC joins its fresh controller record by name,
  then address, so the first poll that reports MACs does not duplicate it;
  one recorded under the same name with a MAC within two of the
  controller's (a switch's port MAC for the AP) joins it too;
  a row with no MAC, no usable name, and no address is dropped;
- an AP in the previous file that neither source saw stays, OFFLINE; one a
  shared controller recorded for another site (outside `scope`) is dropped;
- an AP only its controller saw keeps its last switch port: the controller
  says it is up, not where it is plugged in;
- a port `ap neighbors` confirmed against the switch's MAC table
  (`ap_attachments.db`) beats an SNMP reading of another port on the same
  switch: SNMP resolves LLDP's local port number through ifIndex, which is
  the weak step. A reading on a different switch is newer evidence of a
  move and wins.

Rows are the AP pipe format: ip|name|platform|switch_ip|switch_name|switch_port|mac|last_seen|status.
"""

from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Callable, Dict, List, Mapping, Optional, Sequence, Tuple

AP_FIELDS = ("ip", "name", "platform", "switch_ip", "switch_name", "switch_port", "mac", "last_seen", "status")
ATTACHMENT_FIELDS = ("mac", "name", "ip", "switch_ip", "switch_name", "switch_port", "verdict", "observed_at")
CONFIRMED_DAYS = 14
_MODEL = re.compile(r"(^|[^A-Z0-9])(CW?9[0-9]{3}[A-Z]*|AIR-[A-Z0-9]|[RTH][0-9]{3}[A-Z]?|UAP-|U6-|ROCKET)")


def _blank(value: str) -> bool:
    return value in {"", "N/A"}


def valid_ip(ip: str) -> bool:
    return bool(re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+", ip or "")) and ip != "0.0.0.0"


def norm_name(name: str) -> str:
    return (name or "").strip().lower()


def good_name(name: str) -> bool:
    return norm_name(name) not in {"", "n/a", "cisco-ap", "ruckus-ap"}


def ap_key(row: Mapping[str, str]) -> str:
    if not _blank(row["mac"]):
        # Bare hex: the cache holds 903a72078fd0 where a controller says 90:3a:72:07:8f:d0.
        return "mac:" + (re.sub(r"[^0-9a-f]", "", row["mac"].lower()) or row["mac"].lower())
    if good_name(row["name"]):
        return "name:" + norm_name(row["name"])
    if valid_ip(row["ip"]):
        return "ip:" + row["ip"]
    return f"switch:{row['switch_ip']}|port:{row['switch_port']}"


def pick(primary: str, fallback: str) -> str:
    return primary if not _blank(primary) else fallback


def has_model(platform: str) -> bool:
    return bool(_MODEL.search((platform or "").upper()))


def pick_platform(controller: str, switch: str) -> str:
    if has_model(controller):
        return controller
    if has_model(switch):
        return switch
    return pick(controller, switch)


def _mac_int(mac: str) -> Optional[int]:
    digits = re.sub(r"[^0-9a-f]", "", (mac or "").lower())
    return int(digits, 16) if len(digits) == 12 else None


def near_mac(left: str, right: str) -> bool:
    """Two MACs of one AP: its base Ethernet MAC, and the port MAC a switch's
    neighbour table reported a step or two above it."""
    a, b = _mac_int(left), _mac_int(right)
    return a is not None and b is not None and a != b and a >> 8 == b >> 8 and abs(a - b) <= 2


def _attached(row: Mapping[str, str]) -> bool:
    return not _blank(row.get("switch_ip", "")) and norm_name(row.get("switch_port", "")) not in {"", "n/a", "wireless", "not-joined"}


def short_switch_name(name: str) -> str:
    name = re.sub(r'[\r\n"]', "", name or "")
    if _blank(name):
        return name
    return name.split(".", 1)[0][:32]


def parse(text: str, fields: Sequence[str] = AP_FIELDS) -> List[Dict[str, str]]:
    rows = []
    for line in (text or "").splitlines():
        if not line.strip():
            continue
        parts = line.split("|")
        parts += [""] * (len(fields) - len(parts))
        rows.append(dict(zip(fields, parts[:len(fields)])))
    return rows


def render(rows: Sequence[Mapping[str, str]]) -> str:
    return "".join("|".join(str(row.get(field, "")) for field in AP_FIELDS) + "\n" for row in rows)


def _confirmed_index(attachments: Sequence[Mapping[str, str]], now: float) -> Dict[str, Mapping[str, str]]:
    index: Dict[str, Mapping[str, str]] = {}
    for row in attachments:
        try:
            seen = int(row.get("observed_at") or 0)
        except ValueError:
            continue
        if row.get("verdict") not in {"confirmed", "learned", "clients"} or now - seen > CONFIRMED_DAYS * 86400:
            continue
        for key in (("mac:" + row["mac"].lower()) if row.get("mac") else "",
                    ("name:" + norm_name(row["name"])) if good_name(row.get("name", "")) else "",
                    ("ip:" + row["ip"]) if valid_ip(row.get("ip", "")) else ""):
            if key and int(index.get(key, {}).get("observed_at") or 0) <= seen:
                index[key] = row
    return index


def apply_confirmed(row: Dict[str, str], confirmed: Mapping[str, Mapping[str, str]]) -> Dict[str, str]:
    """Keep an MAC-table-confirmed port over an SNMP reading of the same switch."""
    found = None
    for key in (("mac:" + row["mac"].lower()) if not _blank(row["mac"]) else "",
                ("name:" + norm_name(row["name"])) if good_name(row["name"]) else "",
                ("ip:" + row["ip"]) if valid_ip(row["ip"]) else ""):
        if key and key in confirmed:
            found = confirmed[key]
            break
    if not found or row.get("status") != "ONLINE":
        return row
    attached = not _blank(row["switch_ip"]) and norm_name(row["switch_port"]) not in {"", "n/a", "wireless", "not-joined"}
    if not attached or row["switch_ip"] == found["switch_ip"]:
        row = dict(row)
        row.update({"switch_ip": found["switch_ip"], "switch_name": short_switch_name(found["switch_name"]),
                    "switch_port": found["switch_port"]})
        if _blank(row["mac"]) and found.get("mac"):
            row["mac"] = found["mac"]
    return row


def merge_ap_scan(controller: Sequence[Mapping[str, str]], switch: Sequence[Mapping[str, str]],
                  existing: Sequence[Mapping[str, str]], attachments: Sequence[Mapping[str, str]] = (),
                  now: Optional[float] = None,
                  scope: Optional[Tuple[str, Callable[[Mapping[str, str]], bool]]] = None) -> List[Dict[str, str]]:
    now = time.time() if now is None else now
    ctrl: Dict[str, Dict[str, str]] = {}
    by_name: Dict[str, str] = {}
    by_ip: Dict[str, str] = {}
    order: List[str] = []
    for row in controller:
        key = ap_key(row)
        ctrl[key] = dict(row)
        if key not in order:
            order.append(key)
        if good_name(row["name"]):
            by_name[norm_name(row["name"])] = key
        if valid_ip(row["ip"]):
            by_ip[row["ip"]] = key
    sw: Dict[str, Dict[str, str]] = {}
    # A switch reading joined to a controller record by name or address
    # carried a MAC the controller disowns (often a client's, from the MAC
    # table): a stored row under that MAC is this AP, not other hardware.
    joined: Dict[str, str] = {}
    for row in switch:
        key = ap_key(row)
        if key not in ctrl:
            own = key
            if good_name(row["name"]) and norm_name(row["name"]) in by_name:
                key = by_name[norm_name(row["name"])]
            elif valid_ip(row["ip"]) and row["ip"] in by_ip:
                key = by_ip[row["ip"]]
            if key != own:
                joined[own] = key
        sw[key] = dict(row)
        if key not in order:
            order.append(key)
    fresh = set(order)
    confirmed = _confirmed_index(attachments, now)

    def emit(key: str, previous: Optional[Mapping[str, str]] = None) -> Dict[str, str]:
        s, c = sw.get(key), ctrl.get(key)
        if s and c:
            row = {"ip": pick(s["ip"], c["ip"]), "name": c["name"] if good_name(c["name"]) else pick(s["name"], c["name"]),
                   "platform": pick_platform(c["platform"], s["platform"]), "switch_ip": pick(s["switch_ip"], c["switch_ip"]),
                   "switch_name": short_switch_name(pick(s["switch_name"], c["switch_name"])),
                   "switch_port": pick(s["switch_port"], c["switch_port"]), "mac": pick(c["mac"], s["mac"]),
                   "last_seen": pick(s["last_seen"], c["last_seen"]), "status": "ONLINE"}
        else:
            row = dict(s or c or {})
            if c and not s and previous and _attached(previous):
                # Only the controller saw it this scan: it says the AP is up,
                # not that it was unplugged, so the last port stands until a
                # switch reports another.
                row["switch_ip"], row["switch_name"], row["switch_port"] = (
                    previous["switch_ip"], previous["switch_name"], previous["switch_port"])
            row["switch_name"] = short_switch_name(row.get("switch_name", ""))
        return apply_confirmed(row, confirmed)

    out: List[Dict[str, str]] = []
    emitted = set()
    for row in existing:
        if _blank(row["mac"]) and not good_name(row["name"]) and not valid_ip(row["ip"]):
            # Nothing says which AP this was (a parse that put an OID where
            # the address belongs): no reading can ever match it again.
            continue
        if scope and row["switch_name"] == scope[0] and not scope[1](row):
            # A shared controller's AP of another site, recorded before the
            # filter was set: it is not this inventory's, online or not.
            continue
        key = ap_key(row)
        key = joined.get(key, key)
        if key not in fresh and _blank(row["mac"]):
            # Recorded before its controller reported MACs: the same AP by
            # name, then address. A row that has a MAC is not re-keyed, so a
            # replaced AP's old hardware stays its own record ...
            if good_name(row["name"]) and norm_name(row["name"]) in by_name:
                key = by_name[norm_name(row["name"])]
            elif valid_ip(row["ip"]) and row["ip"] in by_ip:
                key = by_ip[row["ip"]]
        elif key not in fresh and good_name(row["name"]) and norm_name(row["name"]) in by_name:
            # ... unless it carries the controller record's name and a MAC a
            # step or two from the controller's: a switch's port MAC for it.
            fresh_key = by_name[norm_name(row["name"])]
            if near_mac(row["mac"], ctrl[fresh_key]["mac"]):
                key = fresh_key
        if key in emitted:
            continue
        if key in fresh:
            out.append(emit(key, row))
            fresh.discard(key)
        else:
            old = dict(row)
            old["switch_name"] = short_switch_name(old["switch_name"])
            old["status"] = "OFFLINE"
            out.append(old)
        emitted.add(key)
    for key in order:
        if key in fresh and key not in emitted:
            out.append(emit(key))
            emitted.add(key)
    return out


def merge_files(controller: Path, switch: Path, existing: Path, attachments: Optional[Path] = None,
                scope: Optional[Tuple[str, Callable[[Mapping[str, str]], bool]]] = None) -> List[Dict[str, str]]:
    def read(path: Optional[Path], fields: Sequence[str] = AP_FIELDS) -> List[Dict[str, str]]:
        return parse(path.read_text(encoding="utf-8", errors="replace"), fields) if path and path.is_file() else []
    return merge_ap_scan(read(controller), read(switch), read(existing), read(attachments, ATTACHMENT_FIELDS), scope=scope)


def write_attachments(path: Path, entries: Sequence[Mapping[str, str]]) -> int:
    """Record `ap neighbors` readings, newest per AP, for the next AP scan to honour."""
    rows = parse(path.read_text(encoding="utf-8", errors="replace"), ATTACHMENT_FIELDS) if path.is_file() else []
    def ident(row: Mapping[str, str]) -> str:
        return row.get("mac") or norm_name(row.get("name", "")) or row.get("ip", "")
    kept = {ident(row): row for row in rows if ident(row)}
    for entry in entries:
        if ident(entry):
            kept[ident(entry)] = {field: str(entry.get(field) or "") for field in ATTACHMENT_FIELDS}
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text("".join("|".join(row.get(field, "") for field in ATTACHMENT_FIELDS) + "\n" for row in kept.values()),
                         encoding="utf-8")
    temporary.replace(path)
    return len(kept)
