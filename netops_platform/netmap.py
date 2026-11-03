"""The operator's network map: what the network is meant to look like.

Everything else in Netrune is *discovered*: LLDP/CDP neighbours, spanning
tree, controller polls. The map is *declared*: the operator's own picture of
which switch hangs off which, where each one lives, and what is plugged into
its ports (phones, APs, printers). Each is evidence about the other, so this
module keeps the two apart and compares them:

- ``parse_map`` reads the map's plain-text format (see ``TEMPLATE``), which is
  meant to be typed by hand, many switches at a time, and to stay readable;
- ``read_any`` brings a map in from what the operator already has: the text
  format, a CSV/Excel sheet of links, a draw.io diagram, or a Visio drawing;
- ``check`` correlates the map with the inventory and topology evidence and
  says, item by item, what agrees, what differs, and what the network shows
  that the map does not;
- ``plan_update``/``plan_merge`` turn discoveries (or an imported map) into
  edits, and ``apply_edits`` writes them into the operator's file without
  disturbing their layout, order, or comments. Nothing is ever removed.

No database access here: map_cli.py gathers the evidence and owns the guarded
preview/backup/apply/verify/audit lifecycle (ADR 0005) around writes.
"""

from __future__ import annotations

import base64
import csv
import datetime as dt
import html
import io
import ipaddress
import re
import shlex
import urllib.parse
import xml.etree.ElementTree as ET
import zipfile
import zlib
import contextlib
from collections import defaultdict
from dataclasses import dataclass, field
from difflib import get_close_matches
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from netops_platform.network import normalize_interface


class MapError(ValueError):
    """A map that cannot be read, or a request that cannot be applied."""


# --------------------------------------------------------------------------
# Vocabulary

NODE_KINDS = ("switch", "router", "firewall", "controller", "server", "ap", "phone", "printer", "camera", "pc", "other")
# Things plugged into a port rather than network devices with ports of their own.
ENDPOINT_KINDS = ("phone", "ap", "printer", "camera", "pc", "server", "other")
LEAF_KINDS = ("phone", "ap", "printer", "camera", "pc")
KIND_ALIASES = {
    "phones": "phone", "ipphone": "phone", "ip-phone": "phone", "voip": "phone", "telephone": "phone", "handset": "phone",
    "wap": "ap", "wifi": "ap", "wireless": "ap", "accesspoint": "ap", "access-point": "ap", "aps": "ap",
    "printers": "printer", "mfp": "printer", "copier": "printer",
    "cam": "camera", "cctv": "camera", "cameras": "camera",
    "computer": "pc", "workstation": "pc", "laptop": "pc", "desktop": "pc", "pcs": "pc",
    "sw": "switch", "switches": "switch", "stack": "switch",
    "fw": "firewall", "rtr": "router", "wlc": "controller", "vsz": "controller",
    "device": "other", "endpoint": "other",
}
FIELD_ALIASES = {
    "loc": "location", "site": "location", "building": "location", "room": "location", "where": "location",
    "address": "ip", "mgmt": "ip", "mgmt_ip": "ip", "ipaddress": "ip",
    "type": "kind", "role": "kind",
    "sn": "serial", "serial_number": "serial", "serialnumber": "serial",
    "basemac": "mac", "base_mac": "mac",
    "note": "notes", "comment": "notes", "description": "notes",
    "extension": "ext",
}
FIELD_ORDER = ("model", "serial", "mac")
ARROWS = {"->", "-->", "=>", "<->", "<-->", "--", "→", "↔"}

IPV4 = re.compile(r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b")
_PORT_IN_TEXT = re.compile(
    r"(?i)\b(?:twentyfivegigabitethernet|twentyfivegige|twe|hundredgigabitethernet|hu|fortygigabitethernet|fo|"
    r"tengigabitethernet|tengig|te|gigabitethernet|gig|gi|ge|fastethernet|fa|ethernet|eth|et|port-channel|po|trk)"
    r"\s?\d+(?:[/.:]\d+)*\b|\b\d+/\d+(?:/\d+)?\b|\bport\s?\d+\b")
_AP_NAME = re.compile(r"(?i)(?:^|[-_\s])(?:w?ap)[-_]?\d+$|ap\d+$|(?:^|[-_\s])ap(?:$|[-_\s])")
_SEP_NAME = re.compile(r"(?i)^sep([0-9a-f]{12})$")
_RANGE = re.compile(r"^(.*?)(\d+)-(\d+)$")

STATUS_ORDER = ("DIFFERENT", "NOT SEEN", "NO MATCH", "NOT ON MAP", "STALE", "UNKNOWN", "INFO", "OK")
# What a weekly run should raise: the map and the network disagree about
# something the map claims. UNKNOWN (no evidence either way) and an unmapped
# neighbour (the map may cover only part of the site) are information.
ATTENTION_STATUSES = ("DIFFERENT", "NOT SEEN", "NO MATCH", "NOT ON MAP")


def today() -> str:
    return dt.date.today().isoformat()


def name_key(value: Any) -> str:
    """Comparison key for a device name: case-folded, domain dropped."""
    text = " ".join(str(value or "").strip().strip('"').split())
    if not text:
        return ""
    if IPV4.fullmatch(text):
        return text
    return text.split(".")[0].lower()


def mac_key(value: Any) -> str:
    text = re.sub(r"[\s:.\-]", "", str(value or "")).lower()
    match = _SEP_NAME.match(text)
    if match:
        return match.group(1)
    return text if re.fullmatch(r"[0-9a-f]{12}", text) and text != "0" * 12 else ""


def port_key(value: Any) -> str:
    """Comparison key for a port, across Cisco/Aruba spellings and LLDP's
    habit of describing a port as '"SWITCH port 9"'."""
    text = str(value or "").strip().strip('"').strip()
    match = re.search(r"(?i)\bport\s+(\S+)$", text)
    if match:
        text = match.group(1)
    return normalize_interface(text)


_SHORT_PORTS = (("twentyfivegigabitethernet", "Twe"), ("twentyfivegige", "Twe"), ("hundredgigabitethernet", "Hu"),
                ("hundredgige", "Hu"), ("fortygigabitethernet", "Fo"), ("tengigabitethernet", "Te"),
                ("gigabitethernet", "Gi"), ("fastethernet", "Fa"), ("port-channel", "Po"))


def short_port(value: Any) -> str:
    """A port as an operator writes it: 'Gi1/0/48', '49' -- from LLDP's
    'GigabitEthernet1/0/48' or '"SWITCH port 49"'."""
    # The shell scan hands Aruba's port descriptions over still escaped:
    # '\"SWITCH port 9\"'.
    text = str(value or "").replace('\\"', '"').strip().strip('"\\').strip()
    match = re.search(r"(?i)\bport\s+(\S+)$", text)
    if match:
        text = match.group(1).strip('"\\')
    lowered = text.lower()
    for long_name, short_name in _SHORT_PORTS:
        if lowered.startswith(long_name) and text[len(long_name):len(long_name) + 1].isdigit():
            return short_name + text[len(long_name):]
    return text


def canonical_kind(value: Any, default: str = "") -> str:
    text = str(value or "").strip().lower()
    text = KIND_ALIASES.get(text.replace(" ", ""), KIND_ALIASES.get(text, text))
    return text if text in NODE_KINDS else default


def guess_endpoint_kind(label: Any) -> str:
    """What a port's free-text label most likely describes."""
    text = str(label or "").strip()
    lowered = text.lower()
    if not text:
        return "other"
    if _SEP_NAME.match(text.split()[0]) or re.search(r"\b(phone|voip|handset|ext\.?\s*\d+)\b", lowered):
        return "phone"
    if re.search(r"\b(printer|mfp|copier|plotter)\b", lowered):
        return "printer"
    if re.search(r"\b(camera|cctv|cam\d*|nvr)\b", lowered):
        return "camera"
    if re.search(r"\b(access point|wap|wifi)\b", lowered) or _AP_NAME.search(text.split()[0]):
        return "ap"
    if re.search(r"\b(pc|laptop|desktop|workstation|computer)\b", lowered):
        return "pc"
    if re.search(r"\bserver\b", lowered):
        return "server"
    return "other"


def is_ip(value: Any) -> bool:
    try:
        ipaddress.ip_address(str(value or "").strip())
        return True
    except ValueError:
        return False


def expand_ports(spec: str) -> List[str]:
    """`Gi1/0/1-24` -> 24 ports; `1-8,10` -> 9; anything else -> itself."""
    ports: List[str] = []
    for part in [item for item in spec.split(",") if item]:
        match = _RANGE.match(part)
        if match and (not match.group(1) or not match.group(1)[-1].isdigit()):
            prefix, start, end = match.group(1), int(match.group(2)), int(match.group(3))
            if start < end and end - start < 512:
                ports.extend(f"{prefix}{number}" for number in range(start, end + 1))
                continue
        ports.append(part)
    return ports


# --------------------------------------------------------------------------
# Model


@dataclass
class Node:
    name: str
    kind: str = "switch"
    ip: str = ""
    location: str = ""
    fields: Dict[str, str] = field(default_factory=dict)
    line: int = -1          # header line index in the file; -1 = not written yet
    end: int = -1           # last line index of its block
    implicit: bool = False  # only named by a link, never described

    @property
    def key(self) -> str:
        return name_key(self.name)


@dataclass
class Link:
    a: str
    a_port: str = ""
    b: str = ""
    b_port: str = ""
    note: str = ""
    line: int = -1
    top_level: bool = False

    def pair(self) -> Tuple[str, str]:
        return tuple(sorted((name_key(self.a), name_key(self.b))))  # type: ignore[return-value]


@dataclass
class Attachment:
    switch: str
    port: str = ""
    kind: str = "other"
    label: str = ""
    fields: Dict[str, str] = field(default_factory=dict)
    line: int = -1


@dataclass
class NetMap:
    nodes: Dict[str, Node] = field(default_factory=dict)
    links: List[Link] = field(default_factory=list)
    attachments: List[Attachment] = field(default_factory=list)
    problems: List[str] = field(default_factory=list)
    lines: List[str] = field(default_factory=list)

    def node(self, name: str) -> Optional[Node]:
        return self.nodes.get(name_key(name))

    def ensure_node(self, name: str, **values: Any) -> Node:
        key = name_key(name)
        node = self.nodes.get(key)
        if node is None:
            node = Node(name=name.strip(), **values)
            self.nodes[key] = node
        return node

    def counts(self) -> Dict[str, int]:
        kinds: Dict[str, int] = defaultdict(int)
        for item in self.attachments:
            kinds[item.kind] += 1
        return {"devices": len(self.nodes), "links": len(self.links), "attachments": len(self.attachments),
                **{f"{kind}s": count for kind, count in sorted(kinds.items())}}


# --------------------------------------------------------------------------
# The text format

TEMPLATE = """\
# Netrune network map -- your picture of the network, checked against it.
#
#   netrune map check     compare this map with what Netrune discovered
#   netrune map update    write discoveries back in (preview first, --confirm)
#   netrune map edit      open this file in your editor and validate it
#
# A device is a line starting at the left margin:
#     NAME  [kind]  [IP]  [model=..] [serial=..] [mac=..]  [@location]
#   kind is switch unless you say router, firewall, controller, server, ...
#   @location may be several words; quote names that contain spaces.
#
# Its ports are the indented lines below it:
#     PORT  ->  OTHER-DEVICE  [ITS-PORT]     a cable to another device
#     PORT  phone|ap|printer|camera|pc  [label]   something plugged in
#     PORT  any description                   kind guessed from the words
#   A range covers many ports at once:  Gi1/0/1-24 phone
#   A link with an unknown local port:  -> CORE-SW01
#
# A link on its own line works too:   SW-A Gi1/0/49 -> SW-B Te1/1/1
# [Building or room]  on its own line sets @location for the devices below it.
# Everything after # is a comment. Netrune never deletes your lines; what it
# adds is marked with a "# netrune <date>" comment.
"""


def _strip_comment(line: str) -> Tuple[str, str]:
    match = re.search(r"(^|\s)#", line)
    if not match:
        return line.rstrip(), ""
    return line[:match.start()].rstrip(), line[match.start():].strip()


def _tokens(text: str) -> List[str]:
    try:
        return shlex.split(text, posix=True)
    except ValueError:  # an apostrophe in a label: "Joe's office"
        return text.split()


def _kv(token: str) -> Optional[Tuple[str, str]]:
    if "=" not in token or token.startswith("=") or token in ARROWS:
        return None
    key, _, value = token.partition("=")
    key = key.strip().lower()
    if not re.fullmatch(r"[a-z][a-z0-9_\-]*", key):
        return None
    return FIELD_ALIASES.get(key, key), value.strip()


def _apply_node_tokens(node: Node, tokens: Sequence[str], *, explicit_kind: bool = True) -> None:
    location: List[str] = []
    notes: List[str] = []
    in_location = False
    for token in tokens:
        pair = _kv(token)
        if pair:
            key, value = pair
            if key == "ip":
                node.ip = value
            elif key == "kind":
                node.kind = canonical_kind(value, node.kind)
            elif key == "location":
                node.location = value
            elif value:
                node.fields[key] = value
            in_location = False
            continue
        if token.startswith("@"):
            in_location = True
            if token[1:]:
                location.append(token[1:])
            continue
        if in_location:
            location.append(token)
            continue
        if not node.ip and is_ip(token):
            node.ip = token
            continue
        kind = canonical_kind(token)
        if kind and explicit_kind and node.kind == "switch" and kind != "other":
            node.kind = kind
            continue
        notes.append(token)
    if location:
        node.location = " ".join(location)
    if notes and "notes" not in node.fields:
        node.fields["notes"] = " ".join(notes)


def _link_side(tokens: Sequence[str]) -> Tuple[str, str, str]:
    """`NAME [PORT] [note...]` -> (name, port, note)."""
    plain = [token for token in tokens if not _kv(token)]
    if not plain:
        return "", "", ""
    return plain[0], plain[1] if len(plain) > 1 else "", " ".join(plain[2:])


def parse_map(text: str) -> NetMap:
    netmap = NetMap(lines=text.splitlines())
    current: Optional[Node] = None
    section_location = ""
    for index, raw in enumerate(netmap.lines):
        body, comment = _strip_comment(raw)
        if not body.strip():
            continue
        indented = raw[:1].isspace()
        stripped = body.strip()
        if not indented and re.fullmatch(r"\[[^\]]*\]", stripped):
            section_location = stripped[1:-1].strip()
            current = None
            continue
        tokens = _tokens(stripped)
        if not tokens:
            continue
        arrow = next((i for i, token in enumerate(tokens) if token in ARROWS), -1)
        if not indented:
            if arrow > 0:
                a, a_port, _ = _link_side(tokens[:arrow])
                b, b_port, note = _link_side(tokens[arrow + 1:])
                if not a or not b:
                    netmap.problems.append(f"line {index + 1}: a link needs a device on both sides of '{tokens[arrow]}'")
                    continue
                for name in (a, b):
                    if not netmap.node(name):
                        netmap.ensure_node(name, implicit=True, location=section_location)
                netmap.links.append(Link(a, a_port, b, b_port, note or comment.lstrip("# "), line=index, top_level=True))
                current = None
                continue
            existing = netmap.node(tokens[0])
            if existing and not existing.implicit:
                netmap.problems.append(f"line {index + 1}: {tokens[0]} is already described on line {existing.line + 1}; "
                                       "its ports below are added to that one")
                current = existing
                continue
            node = existing or Node(name=tokens[0])
            node.implicit, node.line, node.end = False, index, index
            node.location = node.location or section_location
            _apply_node_tokens(node, tokens[1:])
            if not node.location:
                node.location = section_location
            netmap.nodes[node.key] = node
            current = node
            continue
        # An indented line: one of the current device's ports.
        if current is None:
            netmap.problems.append(f"line {index + 1}: an indented port line needs a device line above it")
            continue
        current.end = index
        if arrow == 0:
            b, b_port, note = _link_side(tokens[1:])
            if b:
                if not netmap.node(b):
                    netmap.ensure_node(b, implicit=True)
                netmap.links.append(Link(current.name, "", b, b_port, note or comment.lstrip("# "), line=index))
            else:
                netmap.problems.append(f"line {index + 1}: '->' needs the device it leads to")
            continue
        port_spec = tokens[0].rstrip(":")
        ports = expand_ports(port_spec)
        if arrow == 1:
            b, b_port, note = _link_side(tokens[2:])
            if not b:
                netmap.problems.append(f"line {index + 1}: '{tokens[1]}' needs the device it leads to")
                continue
            if not netmap.node(b):
                netmap.ensure_node(b, implicit=True)
            for port in ports:
                netmap.links.append(Link(current.name, port, b, b_port, note or comment.lstrip("# "), line=index))
            continue
        rest = tokens[1:]
        kind = canonical_kind(rest[0]) if rest else ""
        if kind and kind in ENDPOINT_KINDS:
            rest = rest[1:]
        fields = {}
        words = []
        for token in rest:
            pair = _kv(token)
            if pair:
                fields[pair[0]] = pair[1]
            else:
                words.append(token)
        label = " ".join(words)
        if not kind or kind not in ENDPOINT_KINDS:
            kind = guess_endpoint_kind(label) if label else "other"
        for port in ports:
            netmap.attachments.append(Attachment(current.name, port, kind, label, dict(fields), line=index))
    _fold_leaf_links(netmap)
    return netmap


def _fold_leaf_links(netmap: NetMap) -> None:
    """A link to a phone or AP is that endpoint plugged into the port: the
    check judges it as an attachment, and the endpoint is not a device of
    the map in its own right unless the operator described it."""
    kept: List[Link] = []
    for link in netmap.links:
        for near, near_port, far in ((link.a, link.a_port, link.b), (link.b, link.b_port, link.a)):
            node = netmap.node(far)
            far_kind = node.kind if node and not node.implicit else ""
            if not far_kind and _SEP_NAME.match(name_key(far)):
                far_kind = "phone"
            if far_kind in LEAF_KINDS and (netmap.node(near) is None or netmap.node(near).kind not in LEAF_KINDS):
                netmap.attachments.append(Attachment(near, near_port, far_kind, far, {}, line=link.line))
                if node and node.implicit:
                    netmap.nodes.pop(node.key, None)
                break
        else:
            kept.append(link)
    netmap.links = kept


def _quote(value: str) -> str:
    return f'"{value}"' if re.search(r"[\s#'\"]", value) and '"' not in value else value


def render_header(node: Node, *, with_location: bool = True) -> str:
    parts = [_quote(node.name)]
    if node.kind and node.kind != "switch":
        parts.append(node.kind)
    if node.ip:
        parts.append(node.ip)
    for key in FIELD_ORDER + tuple(sorted(k for k in node.fields if k not in FIELD_ORDER)):
        value = node.fields.get(key)
        if value:
            parts.append(f"{key}={_quote(value)}")
    if with_location and node.location:
        parts.append("@" + _quote(node.location))
    return " ".join(parts)


def render_port_line(item: Any, *, indent: str = "  ", stamp: str = "") -> str:
    if isinstance(item, Link):
        text = f"{item.a_port:<11} -> {_quote(item.b)}" if item.a_port else f"-> {_quote(item.b)}"
        if item.b_port:
            text += f" {item.b_port}"
        if item.note and not stamp:
            text += f"  # {item.note}"
    else:
        text = f"{item.port or '?':<11} {item.kind}"
        if item.label:
            text += f" {item.label}"
        for key, value in sorted(item.fields.items()):
            text += f" {key}={_quote(value)}"
    text = indent + text.rstrip()
    if stamp:
        text = f"{text}  # {stamp}"
    return text


def render_map(netmap: NetMap, *, header: str = TEMPLATE) -> str:
    """The whole map in canonical form, grouped by location."""
    by_switch: Dict[str, List[Any]] = defaultdict(list)
    for link in netmap.links:
        by_switch[name_key(link.a)].append(link)
    for item in netmap.attachments:
        by_switch[name_key(item.switch)].append(item)
    groups: Dict[str, List[Node]] = defaultdict(list)
    for node in netmap.nodes.values():
        groups[node.location].append(node)
    out = [header.rstrip(), ""]
    for location in sorted(groups, key=lambda value: (value != "", value.lower())):
        if location:
            out += [f"[{location}]", ""]
        for node in groups[location]:
            out.append(render_header(node, with_location=False))
            items = sorted(by_switch.get(node.key, []), key=lambda item: _port_sort(item.a_port if isinstance(item, Link) else item.port))
            out += [render_port_line(item) for item in _compress_ranges(items)]
            out.append("")
    return "\n".join(out).rstrip() + "\n"


def _compress_ranges(items: Sequence[Any]) -> List[Any]:
    """Gi1/0/1..24 all `phone` with no label -> one `Gi1/0/1-24 phone` line."""
    out: List[Any] = []
    run: List[Attachment] = []

    def flush() -> None:
        if len(run) >= 3:
            first = re.match(r"^(.*?)(\d+)$", run[0].port)
            last = re.match(r"^(.*?)(\d+)$", run[-1].port)
            out.append(Attachment(run[0].switch, f"{run[0].port}-{last.group(2)}" if first and last else run[0].port, run[0].kind))
        else:
            out.extend(run)
        run.clear()

    for item in items:
        match = re.match(r"^(.*?)(\d+)$", item.port) if isinstance(item, Attachment) and not item.label and not item.fields else None
        if match and run:
            previous = re.match(r"^(.*?)(\d+)$", run[-1].port)
            if previous and previous.group(1) == match.group(1) and int(previous.group(2)) + 1 == int(match.group(2)) and run[-1].kind == item.kind:
                run.append(item)
                continue
        flush()
        if match:
            run.append(item)
        else:
            out.append(item)
    flush()
    return out


def _port_sort(port: str) -> Tuple[Any, ...]:
    return tuple(int(part) if part.isdigit() else part for part in re.split(r"(\d+)", port_key(port)))


# --------------------------------------------------------------------------
# Bringing a map in from what the operator already has


def read_any(path: Path, *, sheet: str = "") -> NetMap:
    suffix = path.suffix.lower()
    if not path.is_file():
        raise MapError(f"{path} does not exist.")
    if suffix in {".csv", ".tsv"}:
        return from_rows(_csv_rows(path))
    if suffix in {".xlsx", ".xlsm"}:
        return from_rows(_xlsx_rows(path, sheet))
    if suffix in {".drawio", ".dio"} or (suffix == ".xml" and any(
            marker in path.read_bytes()[:200000] for marker in (b"<mxfile", b"<mxGraphModel"))):
        return from_drawio(path.read_text(encoding="utf-8", errors="replace"))
    if suffix == ".vsdx":
        return from_vsdx(path)
    if suffix in {".vsd", ".pdf", ".png", ".jpg", ".jpeg", ".gif", ".svg"}:
        raise MapError(f"{path.name}: a {suffix} picture has no machine-readable links. Save the drawing as .vsdx or "
                       ".drawio, export its links as CSV, or have it transcribed into the map's text format "
                       "(netrune map init writes a template).")
    return parse_map(path.read_text(encoding="utf-8", errors="replace"))


ROW_COLUMNS = {
    "device": ("device", "switch", "switchname", "name", "hostname", "node", "localdevice", "localswitch",
               "sourcedevice", "fromdevice", "from", "source", "devicename"),
    "ip": ("ip", "ipaddress", "mgmtip", "managementip", "mgmt", "address", "switchip", "deviceip"),
    "kind": ("kind", "type", "role", "devicetype", "deviceclass"),
    "location": ("location", "site", "building", "room", "area", "closet", "idf", "rack", "cabinet"),
    "model": ("model", "modelnumber", "hardware", "platform"),
    "serial": ("serial", "serialnumber", "sn", "serialno"),
    "mac": ("mac", "macaddress", "basemac"),
    "port": ("port", "localport", "interface", "localinterface", "sourceport", "fromport", "switchport", "portnumber"),
    "remote": ("connectsto", "connectedto", "neighbor", "neighbour", "remote", "remotedevice", "to", "target",
               "uplinkto", "uplink", "peer", "destination", "todevice", "remoteswitch", "neighbordevice", "neighbourdevice"),
    "remote_port": ("remoteport", "neighborport", "neighbourport", "toport", "targetport", "peerport",
                    "destinationport", "remoteinterface", "uplinkport"),
    "endpoint": ("endpoint", "endpointtype", "connected", "connectedtype", "pluggedin", "attached", "what"),
    "label": ("label", "description", "desc", "notes", "note", "comment", "comments", "user", "extension", "ext", "remarks"),
}


def _header_key(value: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value or "").lower())


def map_columns(header: Sequence[Any]) -> Dict[str, int]:
    keys = [_header_key(cell) for cell in header]
    found: Dict[str, int] = {}
    for field_name, aliases in ROW_COLUMNS.items():
        for alias in aliases:
            if alias in keys and keys.index(alias) not in found.values():
                found[field_name] = keys.index(alias)
                break
    return found


def _csv_rows(path: Path) -> List[List[str]]:
    text = path.read_text(encoding="utf-8-sig", errors="replace")
    dialect = csv.excel_tab if path.suffix.lower() == ".tsv" else csv.excel
    with contextlib.suppress(csv.Error):
        dialect = csv.Sniffer().sniff(text[:4096], delimiters=",;\t|")
    return [row for row in csv.reader(io.StringIO(text), dialect)]


def _xlsx_rows(path: Path, sheet: str) -> List[List[str]]:
    try:
        from openpyxl import load_workbook
    except ImportError as exc:
        raise MapError("Reading .xlsx needs openpyxl (pip install 'netrune[excel]'); or save the sheet as CSV.") from exc
    workbook = load_workbook(path, read_only=True, data_only=True)
    candidates = [workbook[sheet]] if sheet and sheet in workbook.sheetnames else list(workbook.worksheets)
    if sheet and sheet not in workbook.sheetnames:
        raise MapError(f"{path.name} has no sheet '{sheet}' (it has: {', '.join(workbook.sheetnames)}).")
    for ws in candidates:
        rows = [["" if cell is None else str(cell).strip() for cell in row] for row in ws.iter_rows(values_only=True)]
        if _find_header(rows) is not None:
            return rows
    raise MapError(f"No sheet of {path.name} has a header row naming a device/switch column; name it with --sheet.")


def _find_header(rows: Sequence[Sequence[str]]) -> Optional[int]:
    for index, row in enumerate(rows[:30]):
        columns = map_columns(row)
        if "device" in columns and len(columns) >= 2:
            return index
    return None


def from_rows(rows: Sequence[Sequence[Any]]) -> NetMap:
    """A sheet of links/devices -> map. One row is a device (no port), a
    link (a port and what it connects to), or something plugged into a port.
    A blank device cell repeats the one above, as in a sheet whose device is
    written once per group of rows."""
    header_index = _find_header(rows)
    if header_index is None:
        raise MapError("No header row names a device/switch column plus one more (port, connects to, IP, ...).")
    columns = map_columns(rows[header_index])
    netmap = NetMap()
    last_device = ""
    for offset, row in enumerate(rows[header_index + 1:], start=header_index + 2):
        cells = {name: str(row[index]).strip() if index < len(row) and row[index] is not None else ""
                 for name, index in columns.items()}
        if not any(cells.values()):
            continue
        device = cells.get("device") or last_device
        if not device:
            netmap.problems.append(f"row {offset}: no device named and none above it")
            continue
        last_device = device
        port, remote = cells.get("port", ""), cells.get("remote", "")
        node = netmap.ensure_node(device)
        node.implicit = False
        kind_cell = canonical_kind(cells.get("kind"))
        endpoint_kind = canonical_kind(cells.get("endpoint")) or (kind_cell if port and not remote and kind_cell in ENDPOINT_KINDS else "")
        if kind_cell and not endpoint_kind and not (port and not remote):
            node.kind = kind_cell
        if not (port or remote):
            for key in ("ip", "location"):
                if cells.get(key):
                    setattr(node, key, cells[key])
            for key in FIELD_ORDER:
                if cells.get(key):
                    node.fields[key] = cells[key]
            if cells.get("label"):
                node.fields.setdefault("notes", cells["label"])
            continue
        if cells.get("ip") and not node.ip and remote and not endpoint_kind:
            node.ip = cells["ip"]  # a sheet of each switch's links, its IP repeated per row
        if cells.get("location") and not node.location:
            node.location = cells["location"]
        if remote and not endpoint_kind:
            if not netmap.node(remote):
                netmap.ensure_node(remote, implicit=True)
            for single in expand_ports(port) or [""]:
                netmap.links.append(Link(device, single, remote, cells.get("remote_port", ""), cells.get("label", "")))
            continue
        label = remote or cells.get("label", "")
        kind = endpoint_kind or guess_endpoint_kind(label)
        for single in expand_ports(port) or [""]:
            netmap.attachments.append(Attachment(device, single, kind, label))
    _fold_leaf_links(netmap)
    return netmap


# draw.io ------------------------------------------------------------------

_SHAPE_KINDS = (
    ("phone", ("phone", "telephone", "handset", "voip")),
    ("ap", ("access_point", "accesspoint", "wireless", "wifi", "antenna", "wap")),
    ("printer", ("printer",)),
    ("camera", ("camera", "cctv")),
    ("firewall", ("firewall", "asa")),
    ("router", ("router",)),
    ("controller", ("wlc", "wireless_lan_controller", "controller")),
    ("server", ("server", "rack_server")),
    ("pc", ("pc", "workstation", "laptop", "desktop", "computer", "terminal")),
    ("switch", ("switch", "layer_3", "multilayer", "hub", "stack")),
)


def _kind_from_text(*texts: str) -> str:
    joined = " ".join(texts).lower().replace(" ", "_")
    for kind, words in _SHAPE_KINDS:
        if any(word in joined for word in words):
            return kind
    return ""


def _label_lines(value: str) -> List[str]:
    text = re.sub(r"(?i)<br\s*/?>|</div>|</p>|</li>", "\n", value or "")
    text = html.unescape(re.sub(r"<[^>]+>", "", text))
    return [" ".join(line.split()) for line in text.splitlines() if line.strip()]


def _ports_in(text: str) -> List[str]:
    found = []
    for match in _PORT_IN_TEXT.finditer(text or ""):
        token = match.group(0)
        token = re.sub(r"(?i)^port\s?", "", token)
        found.append(token.replace(" ", ""))
    return found


def _drawio_models(text: str) -> List[ET.Element]:
    root = ET.fromstring(text)
    if root.tag == "mxGraphModel":
        return [root]
    models = []
    for diagram in root.iter("diagram"):
        inner = diagram.find("mxGraphModel")
        if inner is not None:
            models.append(inner)
            continue
        payload = (diagram.text or "").strip()
        if not payload:
            continue
        try:
            raw = zlib.decompress(base64.b64decode(payload), -15)
            models.append(ET.fromstring(urllib.parse.unquote(raw.decode("utf-8"))))
        except (ValueError, zlib.error, ET.ParseError) as exc:
            raise MapError(f"A page of this draw.io file could not be decoded: {exc}") from exc
    return models


@dataclass
class _Shape:
    id: str
    lines: List[str]
    kind: str
    parent: str
    attrs: Dict[str, str]
    container: bool = False


def _end_port(texts: Sequence[str]) -> str:
    """The port named by a label at one end of a cable: a recognisable port,
    else the label itself when it is one short token (Aruba's '49', 'A1')."""
    found = _ports_in(" ".join(texts))
    if found:
        return found[0]
    words = " ".join(texts).split()
    return words[0] if len(words) == 1 and len(words[0]) <= 24 else ""


def _graph_to_map(shapes: Dict[str, _Shape], edges: List[Tuple[str, str, List[str], List[str], List[str]]]) -> NetMap:
    """Shared by draw.io and Visio: shapes + (source, target, labels at the
    source end, labels at the target end, labels for the whole cable) -> map."""
    netmap = NetMap()
    connected = {edge[0] for edge in edges} | {edge[1] for edge in edges}

    def location_of(shape: _Shape) -> str:
        seen = set()
        parent = shapes.get(shape.parent)
        while parent is not None and parent.id not in seen:
            seen.add(parent.id)
            if parent.container and parent.lines:
                return parent.lines[0]
            parent = shapes.get(parent.parent)
        return ""

    def device_of(shape: _Shape) -> Optional[Node]:
        if not shape.lines and not shape.attrs.get("label"):
            return None
        lines = list(shape.lines)
        ip = shape.attrs.get("ip") or next((m.group(0) for line in lines for m in [IPV4.search(line)] if m), "")
        name_line = next((line for line in lines if not IPV4.fullmatch(line.strip())), "")
        name = (shape.attrs.get("name") or shape.attrs.get("hostname") or name_line or ip).strip()
        if not name:
            return None
        if IPV4.search(name) and not IPV4.fullmatch(name):
            name = IPV4.sub("", name).strip(" -:()") or ip
        kind = canonical_kind(shape.attrs.get("kind") or shape.attrs.get("type")) or shape.kind or _kind_from_text(name) or "switch"
        node = Node(name=name, kind=kind, ip=ip, location=shape.attrs.get("location") or location_of(shape))
        for key in FIELD_ORDER:
            if shape.attrs.get(key):
                node.fields[key] = shape.attrs[key]
        extra = [line for line in lines if line != name_line and not IPV4.fullmatch(line.strip())]
        if extra:
            node.fields["notes"] = "; ".join(extra)
        return node

    devices: Dict[str, Node] = {}
    for shape in shapes.values():
        if shape.container or shape.id not in connected:
            continue
        node = device_of(shape)
        if node is not None:
            devices[shape.id] = node
    for node in devices.values():
        if node.kind not in LEAF_KINDS:
            existing = netmap.ensure_node(node.name)
            if existing.kind == "switch":
                existing.kind = node.kind
            existing.ip = existing.ip or node.ip
            existing.location = existing.location or node.location
            existing.fields.update({k: v for k, v in node.fields.items() if v})
    for source, target, near, far, whole in edges:
        a, b = devices.get(source), devices.get(target)
        if a is None or b is None or a.name == b.name:
            continue
        a_port, b_port = _end_port(near), _end_port(far)
        both = _ports_in(" ".join(whole))  # one label "Gi1/0/1 - Gi1/0/49" for the whole cable
        a_port, b_port = a_port or (both[0] if both else ""), b_port or (both[1] if len(both) > 1 else "")
        if a.kind in LEAF_KINDS and b.kind in LEAF_KINDS:
            continue
        if b.kind in LEAF_KINDS:
            netmap.attachments.append(Attachment(a.name, a_port, b.kind, b.name, {k: v for k, v in {"ip": b.ip}.items() if v}))
        elif a.kind in LEAF_KINDS:
            netmap.attachments.append(Attachment(b.name, b_port, a.kind, a.name, {k: v for k, v in {"ip": a.ip}.items() if v}))
        else:
            netmap.links.append(Link(a.name, a_port, b.name, b_port))
    return netmap


def from_drawio(text: str) -> NetMap:
    shapes: Dict[str, _Shape] = {}
    edges: List[Tuple[str, str, List[str], List[str], List[str]]] = []
    edge_labels: Dict[str, List[Tuple[float, str]]] = defaultdict(list)
    raw_edges: List[Tuple[str, str, str, str]] = []
    for model in _drawio_models(text):
        for element in model.iter():
            if element.tag not in {"mxCell", "object", "UserObject"}:
                continue
            cell = element if element.tag == "mxCell" else element.find("mxCell")
            if cell is None:
                continue
            if element.tag == "mxCell" and element.get("id") is None:
                continue
            ident = element.get("id") or ""
            value = element.get("label") if element.tag != "mxCell" else cell.get("value")
            style = cell.get("style") or ""
            attrs = {key.lower(): str(val) for key, val in element.attrib.items()
                     if element.tag != "mxCell" and key not in {"id", "label", "placeholders"}}
            parent = cell.get("parent") or ""
            if cell.get("edge") == "1":
                raw_edges.append((ident, cell.get("source") or "", cell.get("target") or "", value or ""))
            elif cell.get("vertex") == "1":
                if parent and "edgeLabel" in style or (cell.get("connectable") == "0" and parent):
                    geometry = cell.find("mxGeometry")
                    position = float(geometry.get("x") or 0) if geometry is not None and geometry.get("relative") == "1" else 0.0
                    edge_labels[parent].append((position, " ".join(_label_lines(value or ""))))
                    continue
                container = "container=1" in style or "swimlane" in style or style.startswith("group")
                shapes[ident] = _Shape(ident, _label_lines(value or ""), _kind_from_text(style), parent, attrs, container)
    for ident, source, target, value in raw_edges:
        near: List[str] = []
        far: List[str] = []
        whole = [_strip_html(value)] if value else []
        for position, label in edge_labels.get(ident, []):
            (near if position < 0 else far if position > 0 else whole).append(label)
        edges.append((source, target, near, far, whole))
    return _graph_to_map(shapes, edges)


def _strip_html(value: str) -> str:
    return " ".join(_label_lines(value))


# Visio --------------------------------------------------------------------

_VISIO_NS = "{http://schemas.microsoft.com/office/visio/2012/main}"


def from_vsdx(path: Path) -> NetMap:
    try:
        archive = zipfile.ZipFile(path)
    except zipfile.BadZipFile as exc:
        raise MapError(f"{path.name} is not a .vsdx drawing (an older .vsd must be re-saved as .vsdx).") from exc
    with archive:
        names = archive.namelist()
        masters: Dict[str, str] = {}
        if "visio/masters/masters.xml" in names:
            for master in ET.fromstring(archive.read("visio/masters/masters.xml")).iter(f"{_VISIO_NS}Master"):
                masters[master.get("ID") or ""] = f"{master.get('NameU') or ''} {master.get('Name') or ''}"
        pages = sorted(name for name in names if re.fullmatch(r"visio/pages/page\d+\.xml", name))
        if not pages:
            raise MapError(f"{path.name} has no drawing pages.")
        shapes: Dict[str, _Shape] = {}
        edges: List[Tuple[str, str, List[str], List[str], List[str]]] = []
        for page_number, page in enumerate(pages):
            root = ET.fromstring(archive.read(page))
            prefix = f"p{page_number}:"
            top: Dict[str, str] = {}
            texts: Dict[str, str] = {}

            def walk(element: ET.Element, owner: str, parent: str, master: str) -> None:
                for shape in element.findall(f"{_VISIO_NS}Shape"):
                    ident = shape.get("ID") or ""
                    own_master = masters.get(shape.get("Master") or "", master)
                    text_element = shape.find(f"{_VISIO_NS}Text")
                    text = "\n".join(part.strip() for part in text_element.itertext() if part.strip()) if text_element is not None else ""
                    props = {}
                    # Shape Data (Section N="Property"): the network stencils'
                    # IP Address, Network Name, Serial Number, ... fields.
                    for section in shape.findall(f"{_VISIO_NS}Section"):
                        if section.get("N") != "Property":
                            continue
                        for row in section.findall(f"{_VISIO_NS}Row"):
                            value = next((cell.get("V") for cell in row.findall(f"{_VISIO_NS}Cell") if cell.get("N") == "Value"), "")
                            label = re.sub(r"[^a-z0-9]", "", (row.get("N") or "").lower())
                            mapped = {"ipaddress": "ip", "ip": "ip", "networkname": "name", "hostname": "name",
                                      "serialnumber": "serial", "macaddress": "mac", "location": "location",
                                      "building": "location", "productnumber": "model", "model": "model"}.get(label)
                            if mapped and value:
                                props[mapped] = value
                    root_owner = owner or ident
                    top[ident] = root_owner
                    if text:
                        texts[ident] = text
                    if root_owner == ident:
                        container = "container" in own_master.lower()
                        shapes[prefix + ident] = _Shape(prefix + ident, [], _kind_from_text(own_master), parent, props, container)
                    else:
                        owner_shape = shapes.get(prefix + root_owner)
                        if owner_shape is not None:
                            for key, value in props.items():
                                owner_shape.attrs.setdefault(key, value)
                    children = shape.find(f"{_VISIO_NS}Shapes")
                    if children is not None:
                        walk(children, root_owner, parent, own_master)

            for shapes_element in root.findall(f"{_VISIO_NS}Shapes"):
                walk(shapes_element, "", "", "")
            # A group's text may sit on a sub-shape; the group is the device.
            for ident, text in texts.items():
                owner = shapes.get(prefix + top.get(ident, ident))
                if owner is not None and not owner.lines:
                    owner.lines = _label_lines(text.replace("\n", "<br>"))
            ends: Dict[str, Dict[str, str]] = defaultdict(dict)
            for connect in root.iter(f"{_VISIO_NS}Connect"):
                connector, cell, target = connect.get("FromSheet") or "", connect.get("FromCell") or "", connect.get("ToSheet") or ""
                end = "begin" if cell.startswith("Begin") else "end" if cell.startswith("End") else ""
                if end:
                    ends[connector][end] = prefix + top.get(target, target)
            for connector, both in ends.items():
                if "begin" in both and "end" in both:
                    shape = shapes.pop(prefix + connector, None)
                    label = " ".join(shape.lines) if shape else ""
                    edges.append((both["begin"], both["end"], [], [], [label] if label else []))
        return _graph_to_map(shapes, edges)


# --------------------------------------------------------------------------
# Correlation


class Inventory:
    """Netrune's inventory rows, indexed every way a map can name a device."""

    def __init__(self, rows: Iterable[Mapping[str, Any]]):
        self.rows = [dict(row) for row in rows]
        self.by_name: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self.by_ip: Dict[str, Dict[str, Any]] = {}
        self.by_mac: Dict[str, Dict[str, Any]] = {}
        self.by_serial: Dict[str, Dict[str, Any]] = {}
        self.by_ident: Dict[str, Dict[str, Any]] = {}
        self.aps_on: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for row in self.rows:
            self.by_ident.setdefault(self.ident(row), row)
            if row.get("kind") == "ap":
                for switch in {str(row.get("switch_ip") or ""), name_key(row.get("switch_name"))} - {""}:
                    self.aps_on[switch].append(row)
            names = {name_key(row.get("name")), *(name_key(alias) for alias in row.get("aliases") or [])}
            for key in names - {""}:
                if not any(existing is row for existing in self.by_name[key]):
                    self.by_name[key].append(row)
            for ip in [row.get("ip"), *(row.get("addresses") or [])]:
                if is_ip(ip):
                    self.by_ip.setdefault(str(ip), row)
            for mac in [row.get("mac"), *(row.get("macs") or [])]:
                if mac_key(mac):
                    self.by_mac.setdefault(mac_key(mac), row)
            serial = str(row.get("serial") or "").strip().upper()
            if serial and serial not in {"N/A", "UNKNOWN", "NONE"}:
                self.by_serial.setdefault(serial, row)

    @staticmethod
    def ident(row: Optional[Mapping[str, Any]]) -> str:
        if not row:
            return ""
        return str(row.get("canonical_id") or row.get("ip") or name_key(row.get("name")))

    def by_name_one(self, name: str, prefer_kind: str = "") -> Optional[Dict[str, Any]]:
        rows = self.by_name.get(name_key(name)) or []
        if prefer_kind:
            rows = [row for row in rows if row.get("kind") == prefer_kind] or rows
        return rows[0] if rows else None

    def resolve(self, name: str = "", ip: str = "", mac: str = "", serial: str = "",
                prefer_kind: str = "") -> Tuple[Optional[Dict[str, Any]], str, str]:
        """(row, how it matched, conflict note)."""
        # Hardware identity first; then the name, which the operator chose
        # and which is rarely mistyped into another real switch's name; the
        # IP last, the field most often stale or mistyped on a drawing.
        candidates = []
        if serial and serial.strip().upper() in self.by_serial:
            candidates.append(("serial", self.by_serial[serial.strip().upper()]))
        if mac_key(mac) in self.by_mac:
            candidates.append(("MAC", self.by_mac[mac_key(mac)]))
        named = self.by_name_one(name, prefer_kind) if name else None
        if not named and name and mac_key(name) in self.by_mac:
            named = self.by_mac[mac_key(name)]
        if named:
            candidates.append(("name", named))
        if is_ip(ip) and ip in self.by_ip:
            candidates.append(("IP", self.by_ip[ip]))
        if not candidates:
            return None, "", ""
        how, row = candidates[0]
        conflict = ""
        others = [(other_how, other) for other_how, other in candidates[1:] if self.ident(other) != self.ident(row)]
        if others:
            other_how, other = others[0]
            conflict = (f"matched by {how}; the map's {other_how} belongs to {str(other.get('name') or other.get('ip')).strip()}")
        return row, how, conflict

    def suggest(self, name: str) -> str:
        close = get_close_matches(name_key(name), list(self.by_name), n=1, cutoff=0.75)
        if not close:
            return ""
        row = self.by_name[close[0]][0]
        return str(row.get("name") or close[0]).strip()


@dataclass
class Seen:
    """One link the network showed: from a switch port to a neighbour."""
    a: str
    a_name: str
    a_port: str
    b: str
    b_name: str
    b_port: str
    source: str
    current: bool
    last_seen: int = 0


def _port_quality(port: str) -> int:
    if re.fullmatch(r"[A-Za-z][A-Za-z\-]*\d+(?:[/.:]\d+)*", port or ""):
        return 3
    if re.fullmatch(r"\d+(?:/\d+)+|[A-L]\d{1,2}", port or ""):
        return 2
    return 1 if port else 0


def build_seen(inventory: Inventory, current: Iterable[Mapping[str, Any]],
               history: Iterable[Mapping[str, Any]] = (), stp: Iterable[Mapping[str, Any]] = ()) -> List[Seen]:
    """Normalise LLDP/CDP rows (current scan), neighbour-link history, and
    spanning-tree links into one list keyed by inventory identity."""
    out: List[Seen] = []

    def remote_row(name: Any, ip: Any) -> Optional[Dict[str, Any]]:
        if is_ip(ip) and str(ip) in inventory.by_ip:
            return inventory.by_ip[str(ip)]
        key = name_key(name)
        return inventory.by_name_one(key) or (inventory.by_mac.get(mac_key(name)) if mac_key(name) else None)

    def add(row: Mapping[str, Any], source: str, is_current: bool, last_seen: int = 0) -> None:
        local = inventory.by_ip.get(str(row.get("local_ip") or "")) or inventory.by_name_one(row.get("local_name") or "")
        if local is None:
            return
        remote = remote_row(row.get("remote_name"), row.get("remote_ip"))
        out.append(Seen(Inventory.ident(local), str(local.get("name") or local.get("ip") or "").strip(),
                        short_port(row.get("local_port")), Inventory.ident(remote),
                        str((remote or {}).get("name") or row.get("remote_name") or "").strip(),
                        short_port(row.get("remote_port")), source, is_current, int(last_seen or 0)))

    for row in current:
        add(row, "lldp/cdp", True)
    # Aruba's LLDP table lists a Cisco neighbour twice on one port: by name
    # with its interface (Gi1/1/1), and by chassis MAC with a port
    # description ('8'). Keep the interface.
    best: Dict[Tuple[str, str, str], Seen] = {}
    for item in out:
        if not item.b:
            continue
        key = (item.a, port_key(item.a_port), item.b)
        if key not in best or _port_quality(item.b_port) > _port_quality(best[key].b_port):
            best[key] = item
    out = [item for item in out if not item.b or best[(item.a, port_key(item.a_port), item.b)] is item]
    for row in history:
        add(row, "lldp/cdp history", False, int(row.get("last_seen") or 0))
    for row in stp:
        add(row, "spanning-tree", True, int(row.get("last_seen") or 0))
    return out


@dataclass
class CheckResult:
    findings: List[Dict[str, Any]]
    counts: Dict[str, int]
    matched: Dict[str, Dict[str, Any]]       # map node key -> inventory row
    seen: List[Seen]
    discovered_links: List[Dict[str, Any]]   # NOT ON MAP links between mapped devices
    unmapped_neighbors: List[Dict[str, Any]]  # switches next to mapped ones, not on the map
    endpoints: List[Dict[str, Any]]          # APs/phones seen on mapped switches' ports, not on the map

    @property
    def attention(self) -> int:
        return sum(self.counts.get(status, 0) for status in ATTENTION_STATUSES)


def _finding(status: str, kind: str, subject: str, map_says: str, network: str, hint: str = "",
             line: int = -1, switch: str = "") -> Dict[str, Any]:
    return {"status": status, "kind": kind, "subject": subject, "map": map_says, "network": network,
            "hint": hint, "line": line + 1 if line >= 0 else None, "switch": switch}


def _date(epoch: int) -> str:
    return dt.datetime.fromtimestamp(epoch).strftime("%Y-%m-%d") if epoch else "?"


def _model_differs(declared: str, found: str) -> bool:
    a, b = re.sub(r"[^a-z0-9]", "", declared.lower()), re.sub(r"[^a-z0-9]", "", found.lower())
    return bool(a and b and a not in b and b not in a)


def check(netmap: NetMap, inventory: Inventory, seen: Sequence[Seen]) -> CheckResult:
    findings: List[Dict[str, Any]] = []
    matched: Dict[str, Dict[str, Any]] = {}
    ident_to_node: Dict[str, str] = {}

    # Devices --------------------------------------------------------------
    for node in netmap.nodes.values():
        prefer = "ap" if node.kind == "ap" else "device" if node.kind not in LEAF_KINDS else ""
        row, how, conflict = inventory.resolve(node.name, node.ip, node.fields.get("mac", ""), node.fields.get("serial", ""), prefer)
        label = render_header(node) if node.line >= 0 else node.name
        if row is None:
            suggestion = inventory.suggest(node.name)
            hint = f"did you mean {suggestion}?" if suggestion else ("never discovered; check the name or IP" if not node.implicit
                                                                       else "only named by a link; add a line for it with its IP")
            findings.append(_finding("NO MATCH", "device", node.name, label, "not in the inventory", hint, node.line, node.name))
            continue
        twin = ident_to_node.get(Inventory.ident(row))
        if twin is not None:
            findings.append(_finding("DIFFERENT", "device", node.name, label, str(row.get("name") or "").strip(),
                                     f"the same device as {netmap.nodes[twin].name} on the map: one of the two is a duplicate",
                                     node.line, node.name))
            continue
        matched[node.key] = row
        ident_to_node[Inventory.ident(row)] = node.key
        found_name = str(row.get("name") or "").strip()
        network = f"{found_name} {row.get('ip') or ''}".strip()
        if str(row.get("status") or "").upper() == "OFFLINE":
            network += f" (offline, last seen {_date(int(row.get('last_seen') or 0))})"
        differences = []
        if conflict and "the map's IP" not in conflict:
            differences.append(conflict)
        if node.ip and is_ip(node.ip) and node.ip not in {row.get("ip"), *(row.get("addresses") or [])}:
            owner = inventory.by_ip.get(node.ip)
            owner_note = f" (that address is {str(owner.get('name') or '').strip()})" if owner is not None else ""
            differences.append(f"IP {node.ip} on the map{owner_note}, {row.get('ip')} found")
        serial = str(row.get("serial") or "").strip()
        if node.fields.get("serial") and serial and node.fields["serial"].strip().upper() != serial.upper():
            differences.append(f"serial {node.fields['serial']} on the map, {serial} found (replaced?)")
        if node.fields.get("model") and row.get("model") and _model_differs(node.fields["model"], str(row["model"])):
            differences.append(f"model {node.fields['model']} on the map, {row['model']} found")
        if how != "name" and name_key(node.name) != name_key(found_name) and found_name:
            differences.append(f"named {found_name} on the network (matched by {how})")
        if differences:
            findings.append(_finding("DIFFERENT", "device", node.name, label, network, "; ".join(differences), node.line, node.name))
        else:
            findings.append(_finding("OK", "device", node.name, label, network, f"matched by {how}", node.line, node.name))

    current_from: Set[str] = {item.a for item in seen if item.current}
    by_pair: Dict[Tuple[str, str], List[Seen]] = defaultdict(list)
    by_port: Dict[Tuple[str, str], List[Seen]] = defaultdict(list)
    for item in seen:
        if item.b:
            by_pair[(item.a, item.b)].append(item)
        by_port[(item.a, port_key(item.a_port))].append(item)

    # Links ----------------------------------------------------------------
    mapped_pairs: Set[Tuple[str, str]] = set()
    for link in netmap.links:
        a_row, b_row = matched.get(name_key(link.a)), matched.get(name_key(link.b))
        subject = f"{link.a} {link.a_port}".strip() + f" -> {link.b} {link.b_port}".rstrip()
        if a_row is None or b_row is None:
            missing = link.a if a_row is None else link.b
            findings.append(_finding("UNKNOWN", "link", subject, subject, "", f"{missing} is not matched to a discovered device", link.line, link.a))
            continue
        a, b = Inventory.ident(a_row), Inventory.ident(b_row)
        mapped_pairs.add(tuple(sorted((a, b))))  # type: ignore[arg-type]
        evidence = [(item, False) for item in by_pair.get((a, b), [])] + [(item, True) for item in by_pair.get((b, a), [])]

        def ports_agree(item: Seen, flipped: bool) -> bool:
            near, far = (item.b_port, item.a_port) if flipped else (item.a_port, item.b_port)
            return ((not link.a_port or not near or port_key(link.a_port) == port_key(near))
                    and (not link.b_port or not far or port_key(link.b_port) == port_key(far)))

        def shown(item: Seen, flipped: bool) -> str:
            near, far = (item.b_port, item.a_port) if flipped else (item.a_port, item.b_port)
            return f"{link.a} {near or '?'} -> {link.b} {far or '?'} ({item.source})"

        def contradicts(item: Seen, flipped: bool) -> bool:
            near, far = (item.b_port, item.a_port) if flipped else (item.a_port, item.b_port)
            return bool((link.a_port and near and port_key(link.a_port) != port_key(near))
                        or (link.b_port and far and port_key(link.b_port) != port_key(far)))

        def confirms(item: Seen, flipped: bool) -> bool:
            near, far = (item.b_port, item.a_port) if flipped else (item.a_port, item.b_port)
            return bool((not link.a_port or (near and port_key(link.a_port) == port_key(near)))
                        and (not link.b_port or (far and port_key(link.b_port) == port_key(far))))

        # LLDP/CDP names both ports; spanning tree knows only its own side,
        # so it speaks only when LLDP/CDP says nothing about these two.
        current = [(item, flipped) for item, flipped in evidence if item.current]
        pool = [pair for pair in current if pair[0].source != "spanning-tree"] or current
        confirmed = [pair for pair in pool if confirms(*pair)]
        against = [pair for pair in pool if contradicts(*pair)]
        if confirmed:
            item, flipped = confirmed[0]
            findings.append(_finding("OK", "link", subject, subject, shown(item, flipped), "", link.line, link.a))
            continue
        if against:
            item, flipped = max(against, key=lambda pair: _port_quality(pair[0].a_port) + _port_quality(pair[0].b_port))
            findings.append(_finding("DIFFERENT", "link", subject, subject, shown(item, flipped),
                                     "same two devices, different port(s): moved cable or a map typo", link.line, link.a))
            continue
        if pool:
            item, flipped = pool[0]
            findings.append(_finding("OK", "link", subject, subject, shown(item, flipped),
                                     "the two are linked; the network does not name the port(s) to confirm them", link.line, link.a))
            continue
        on_port = [item for item in by_port.get((a, port_key(link.a_port)), []) if item.current and item.b != b] if link.a_port else []
        past = sorted((item for item, _ in evidence if not item.current), key=lambda item: -item.last_seen)
        if on_port:
            other = on_port[0]
            findings.append(_finding("DIFFERENT", "link", subject, subject,
                                     f"{link.a} {link.a_port} -> {other.b_name or '?'} {other.b_port}".rstrip() + f" ({other.source})",
                                     "that port leads somewhere else now", link.line, link.a))
        elif a in current_from or b in current_from:
            hint = f"last seen {_date(past[0].last_seen)}" if past else "neither switch reports it over LLDP/CDP"
            findings.append(_finding("NOT SEEN", "link", subject, subject, "", hint, link.line, link.a))
        elif past:
            findings.append(_finding("STALE", "link", subject, subject, shown(past[0], False),
                                     f"last seen {_date(past[0].last_seen)}; no current scan of either switch", link.line, link.a))
        else:
            findings.append(_finding("UNKNOWN", "link", subject, subject, "", "no LLDP/CDP data from either switch yet", link.line, link.a))

    # Attachments ----------------------------------------------------------
    declared_ports: Dict[str, Set[str]] = defaultdict(set)
    for item in netmap.attachments:
        switch_row = matched.get(name_key(item.switch))
        subject = f"{item.switch} {item.port or '(port?)'} {item.kind}" + (f" {item.label}" if item.label else "")
        if switch_row is None:
            findings.append(_finding("UNKNOWN", "attachment", subject, subject, "", f"{item.switch} is not matched to a discovered device", item.line, item.switch))
            continue
        switch = Inventory.ident(switch_row)
        if item.port:
            declared_ports[switch].add(port_key(item.port))
        here = [s for s in (by_port.get((switch, port_key(item.port)), []) if item.port else [s for s in seen if s.a == switch]) if s.current]
        candidates = {id(row): row for key in (str(switch_row.get("ip") or ""), name_key(switch_row.get("name")))
                      for row in inventory.aps_on.get(key, [])}.values()
        aps_here = [row for row in candidates if not item.port or port_key(row.get("switch_port")) == port_key(item.port)]
        label_key = name_key(item.label)
        if item.kind == "ap":
            names = [str(row.get("name") or "").strip() for row in aps_here] + [s.b_name for s in here if _looks_ap(s, inventory)]
            names = [name for name in names if name]
            if not names:
                status = "NOT SEEN" if switch in current_from else "UNKNOWN"
                findings.append(_finding(status, "attachment", subject, subject, "",
                                         "no AP found there" if status == "NOT SEEN" else "no LLDP/CDP data from this switch yet",
                                         item.line, item.switch))
            elif not label_key or any(name_key(name) == label_key or label_key in name_key(name) for name in names):
                findings.append(_finding("OK", "attachment", subject, subject, f"AP {names[0]}", "", item.line, item.switch))
            else:
                findings.append(_finding("DIFFERENT", "attachment", subject, subject, f"AP {names[0]}", "a different AP is there", item.line, item.switch))
            continue
        if item.kind == "phone":
            phones = [s for s in here if _looks_phone(s.b_name)]
            if phones:
                wanted = mac_key(item.label) or mac_key(item.fields.get("mac", ""))
                if wanted and not any(mac_key(s.b_name) == wanted for s in phones):
                    findings.append(_finding("DIFFERENT", "attachment", subject, subject, f"phone {phones[0].b_name}", "a different phone is there", item.line, item.switch))
                else:
                    findings.append(_finding("OK", "attachment", subject, subject, f"phone {phones[0].b_name}", "", item.line, item.switch))
            elif switch in current_from:
                findings.append(_finding("NOT SEEN", "attachment", subject, subject, "", "no phone announced itself there over CDP/LLDP (a phone without CDP/LLDP stays invisible here)", item.line, item.switch))
            else:
                findings.append(_finding("UNKNOWN", "attachment", subject, subject, "", "no LLDP/CDP data from this switch yet", item.line, item.switch))
            continue
        if here:
            findings.append(_finding("INFO", "attachment", subject, subject, f"{here[0].b_name} {here[0].b_port}".strip(), "LLDP/CDP sees this there", item.line, item.switch))
        else:
            findings.append(_finding("UNKNOWN", "attachment", subject, subject, "",
                                     f"a {item.kind} rarely speaks LLDP/CDP; 'netrune lookup mac' finds it by MAC", item.line, item.switch))

    # What the network shows that the map does not -------------------------
    discovered: Dict[Tuple[str, ...], Dict[str, Any]] = {}
    unmapped: Dict[str, Dict[str, Any]] = {}
    endpoints: Dict[Tuple[str, str], Dict[str, Any]] = {}
    # A port that leads to another switch is an uplink: an AP the AP scan
    # placed there was seen through the trunk, not plugged in.
    uplinks = {(item.a, port_key(item.a_port)) for item in seen
               if item.current and (inventory.by_ident.get(item.b) or {}).get("kind") == "device"}
    # Spanning tree repeats what LLDP/CDP already shows, without the far port.
    lldp_pairs = {frozenset((item.a, item.b)) for item in seen if item.current and item.b and item.source != "spanning-tree"}
    for item in seen:
        if not item.current or item.a not in ident_to_node:
            continue
        if item.source == "spanning-tree" and frozenset((item.a, item.b)) in lldp_pairs:
            continue
        a_node = netmap.nodes[ident_to_node[item.a]]
        if item.b in ident_to_node:
            pair = tuple(sorted((item.a, item.b)))
            if pair in mapped_pairs or item.a == item.b:
                continue
            b_node = netmap.nodes[ident_to_node[item.b]]
            key = tuple(sorted(((item.a, port_key(item.a_port)), (item.b, port_key(item.b_port)))))
            discovered.setdefault(key, {"a": a_node.name, "a_port": item.a_port, "b": b_node.name, "b_port": item.b_port, "source": item.source})
            continue
        remote = inventory.by_ident.get(item.b) if item.b else None
        if remote is not None and remote.get("kind") == "device":
            entry = unmapped.setdefault(item.b, {"name": item.b_name, "ip": remote.get("ip"), "model": remote.get("model") or "",
                                                 "serial": remote.get("serial") or "", "mac": remote.get("mac") or "", "links": []})
            entry["links"].append({"a": a_node.name, "a_port": item.a_port, "b_port": item.b_port})
            continue
        if port_key(item.a_port) in declared_ports.get(item.a, set()) or (item.a, port_key(item.a_port)) in uplinks:
            continue
        kind = "ap" if (remote is not None and remote.get("kind") == "ap") or _looks_ap(item, inventory) else "phone" if _looks_phone(item.b_name) else ""
        if kind:
            endpoints.setdefault((item.a, port_key(item.a_port)), {"switch": a_node.name, "port": item.a_port, "kind": kind, "label": item.b_name})
    for row in inventory.rows:
        if row.get("kind") != "ap":
            continue
        switch_row = inventory.by_ip.get(str(row.get("switch_ip") or "")) or inventory.by_name_one(row.get("switch_name") or "", "device")
        switch = Inventory.ident(switch_row)
        if switch in ident_to_node and row.get("switch_port") and port_key(row.get("switch_port")) not in declared_ports.get(switch, set()) \
                and (switch, port_key(row.get("switch_port"))) not in uplinks:
            endpoints.setdefault((switch, port_key(row.get("switch_port"))), {
                "switch": netmap.nodes[ident_to_node[switch]].name, "port": short_port(row.get("switch_port")), "kind": "ap",
                "label": str(row.get("name") or "").strip()})
    for entry in discovered.values():
        subject = f"{entry['a']} {entry['a_port']} -> {entry['b']} {entry['b_port']}".strip()
        findings.append(_finding("NOT ON MAP", "link", subject, "", f"{subject} ({entry['source']})",
                                 "both devices are on the map; 'map update' adds the link", -1, entry["a"]))
    for entry in unmapped.values():
        where = ", ".join(dict.fromkeys(f"{link['a']} {link['a_port']}".strip() for link in entry["links"]))
        findings.append(_finding("INFO", "device", entry["name"], "", f"{entry['name']} {entry['ip'] or ''}".strip(),
                                 f"next to {where}", -1, entry["links"][0]["a"]))
    per_switch: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for entry in endpoints.values():
        per_switch[entry["switch"]][entry["kind"]] += 1
    for switch, kinds in per_switch.items():
        text = ", ".join(f"{count} {kind}{'s' if count != 1 else ''}" for kind, count in sorted(kinds.items()))
        findings.append(_finding("INFO", "attachment", f"{switch}: {text}", "", text,
                                 "on ports the map does not describe", -1, switch))

    counts: Dict[str, int] = defaultdict(int)
    for item in findings:
        counts[item["status"]] += 1
    findings.sort(key=lambda item: (STATUS_ORDER.index(item["status"]), item["switch"].lower(), item["line"] or 10**9))
    return CheckResult(findings, dict(counts), matched, list(seen), list(discovered.values()), list(unmapped.values()),
                       sorted(endpoints.values(), key=lambda entry: (entry["switch"].lower(), _port_sort(entry["port"]))))


def _looks_phone(name: str) -> bool:
    return bool(_SEP_NAME.match(name_key(name)) or re.search(r"(?i)phone", name or ""))


def _looks_ap(item: Seen, inventory: Inventory) -> bool:
    if item.b:
        row = next((row for row in inventory.by_name.get(name_key(item.b_name), []) if row.get("kind") == "ap"), None)
        if row is not None:
            return True
    return bool(_AP_NAME.search(name_key(item.b_name)) and not _looks_phone(item.b_name))


# --------------------------------------------------------------------------
# Writing back: edits that keep the operator's file as they wrote it


@dataclass
class Edit:
    """`fields`: set on a node's line; `add`: port lines under a node;
    `node`: a whole new device block; `replace`: one line rewritten."""
    action: str
    node: str = ""
    values: Dict[str, str] = field(default_factory=dict)
    lines: List[str] = field(default_factory=list)
    line: int = -1
    text: str = ""
    why: str = ""
    new_node: Optional[Node] = None


def _node_fills(node: Node, row: Mapping[str, Any], overwrite: bool) -> Dict[str, str]:
    values: Dict[str, str] = {}
    found = {"ip": str(row.get("ip") or ""), "model": str(row.get("model") or ""), "serial": str(row.get("serial") or ""),
             "mac": str(row.get("mac") or "")}
    for key, value in found.items():
        value = value.strip()
        if not value or value.upper() in {"N/A", "UNKNOWN"} or (key == "ip" and not is_ip(value)):
            continue
        have = node.ip if key == "ip" else node.fields.get(key, "")
        if key == "mac":
            value = ":".join(mac_key(value)[i:i + 2] for i in range(0, 12, 2)) if mac_key(value) else ""
            if not value or (have and mac_key(have) == mac_key(value)):
                continue
        if not have or (overwrite and have.strip().upper() != value.upper()
                        and not (key == "ip" and have in {row.get("ip"), *(row.get("addresses") or [])})
                        and not (key == "model" and not _model_differs(have, value))):
            values[key] = value
    return values


def plan_update(netmap: NetMap, result: CheckResult, *, add_new: bool = False, attachments: bool = False,
                overwrite: bool = False, stamp: str = "") -> List[Edit]:
    stamp = stamp or f"netrune {today()}"
    edits: List[Edit] = []
    for key, row in result.matched.items():
        node = netmap.nodes[key]
        values = _node_fills(node, row, overwrite)
        if node.kind in LEAF_KINDS:
            values.pop("model", None)
        if values:
            edits.append(Edit("fields", node=key, values=values, why="filled from the inventory"))
    # Ports the map left blank on a link, where the network shows exactly one cable.
    for link in netmap.links:
        if link.line < 0 or (link.a_port and link.b_port):
            continue
        a_row, b_row = result.matched.get(name_key(link.a)), result.matched.get(name_key(link.b))
        if a_row is None or b_row is None:
            continue
        a, b = Inventory.ident(a_row), Inventory.ident(b_row)
        options = {(item.a_port if item.a == a else item.b_port, item.b_port if item.a == a else item.a_port)
                   for item in result.seen if item.current and {item.a, item.b} == {a, b}}
        options = {pair for pair in options if (not link.a_port or port_key(pair[0]) == port_key(link.a_port))
                   and (not link.b_port or port_key(pair[1]) == port_key(link.b_port))}
        if len(options) == 1:
            a_port, b_port = next(iter(options))
            filled = Link(link.a, link.a_port or a_port, link.b, link.b_port or b_port, link.note, link.line, link.top_level)
            edits.append(Edit("replace", line=link.line, text=_rewrite_link_line(netmap.lines[link.line], filled, link), why="ports filled from LLDP/CDP"))
    for entry in result.discovered_links:
        edits.append(Edit("add", node=name_key(entry["a"]), lines=[render_port_line(Link(entry["a"], entry["a_port"], entry["b"], entry["b_port"]), stamp=stamp)],
                          why=f"link seen by {entry['source']}"))
    if add_new:
        for entry in result.unmapped_neighbors:
            node = Node(name=entry["name"])
            fills = _node_fills(node, entry, False)
            node.ip = fills.pop("ip", "")
            node.fields.update(fills)
            lines = [render_header(node) + f"  # {stamp}: next to " + ", ".join(sorted({link['a'] for link in entry["links"]}))]
            lines += [render_port_line(Link(node.name, link["b_port"], link["a"], link["a_port"])) for link in entry["links"]]
            edits.append(Edit("node", node=node.key, lines=lines, new_node=node, why="switch seen next to mapped ones"))
    if attachments:
        for entry in result.endpoints:
            edits.append(Edit("add", node=name_key(entry["switch"]),
                              lines=[render_port_line(Attachment(entry["switch"], entry["port"], entry["kind"], entry["label"]), stamp=stamp)],
                              why=f"{entry['kind']} seen on the port"))
    return edits


_ARROW_RE = r"(?:<-->|<->|-->|->|=>|--|\u2192|\u2194)"
_NAME_RE = r"(?:\"[^\"]+\"|'[^']+'|\S+)"


def _rewrite_link_line(original: str, filled: Link, before: Link) -> str:
    """Fill a link line's blank ports in place: the operator's spacing,
    names, and comment stay exactly as written."""
    body, comment = original, ""
    match = re.search(r"(^|\s)#", original)
    if match:
        body, comment = original[:match.start()], original[match.start():]
    if filled.b_port and not before.b_port:
        body = re.sub(rf"(\s{_ARROW_RE}\s+{_NAME_RE})", lambda m: f"{m.group(1)} {filled.b_port}", body, count=1)
    if filled.a_port and not before.a_port:
        if before.top_level:
            body = re.sub(rf"^(\s*{_NAME_RE})", lambda m: f"{m.group(1)} {filled.a_port}", body, count=1)
        else:
            body = re.sub(rf"^(\s*)({_ARROW_RE})", lambda m: f"{m.group(1)}{filled.a_port} {m.group(2)}", body, count=1)
    return body + comment


def plan_merge(current: NetMap, incoming: NetMap, *, overwrite: bool = False, stamp: str = "") -> List[Edit]:
    """Edits that bring an imported map into the operator's map: new devices,
    new links and attachments, blank fields filled (and differing ones
    replaced with `overwrite`). Nothing already there is removed."""
    stamp = stamp or f"netrune import {today()}"
    edits: List[Edit] = []
    have_links = {(link.pair(), port_key(link.a_port) if name_key(link.a) <= name_key(link.b) else port_key(link.b_port),
                   port_key(link.b_port) if name_key(link.a) <= name_key(link.b) else port_key(link.a_port)) for link in current.links}
    have_pairs = {link.pair() for link in current.links}
    have_ports = {(name_key(item.switch), port_key(item.port)) for item in current.attachments if item.port}
    have_ports |= {(name_key(link.a), port_key(link.a_port)) for link in current.links if link.a_port}
    have_ports |= {(name_key(link.b), port_key(link.b_port)) for link in current.links if link.b_port}
    new_blocks: Dict[str, Edit] = {}
    for node in incoming.nodes.values():
        if node.implicit:  # only named by a link: nothing to describe
            continue
        existing = current.node(node.name)
        if existing is None or existing.line < 0:
            fresh = Node(node.name, node.kind, node.ip, node.location, dict(node.fields))
            if existing is not None:  # named by a link only: give it a line now
                fresh.location = fresh.location or existing.location
            edit = Edit("node", node=node.key, lines=[render_header(fresh) + f"  # {stamp}"], new_node=fresh, why="new device")
            new_blocks[node.key] = edit
            edits.append(edit)
            continue
        values = {}
        for key in ("ip", "location", *FIELD_ORDER):
            value = getattr(node, key) if key in {"ip", "location"} else node.fields.get(key, "")
            have = getattr(existing, key) if key in {"ip", "location"} else existing.fields.get(key, "")
            if value and (not have or (overwrite and have != value)):
                values[key] = value
        if node.kind != "switch" and existing.kind == "switch":
            values["kind"] = node.kind
        if values:
            edits.append(Edit("fields", node=existing.key, values=values, why="from the imported map"))

    def add_line(owner: str, line: str, why: str) -> None:
        key = name_key(owner)
        if key in new_blocks:
            new_blocks[key].lines.append(line)
        else:
            edits.append(Edit("add", node=key, lines=[line], why=why))

    for link in incoming.links:
        a, b = sorted((name_key(link.a), name_key(link.b)))
        ports = (port_key(link.a_port), port_key(link.b_port)) if name_key(link.a) == a else (port_key(link.b_port), port_key(link.a_port))
        if (link.pair(), *ports) in have_links:
            continue
        if link.pair() in have_pairs and not (link.a_port or link.b_port):
            continue
        if (name_key(link.a), port_key(link.a_port)) in have_ports and link.a_port:
            continue
        # The line sits under its first device, which needs a line of its own
        # (with what the import knows about it) if the map has none yet.
        owner = current.node(link.a)
        if (owner is None or owner.line < 0) and name_key(link.a) not in new_blocks:
            known = incoming.node(link.a) or Node(name=link.a)
            fresh = Node(known.name, known.kind, known.ip, known.location, dict(known.fields))
            new_blocks[name_key(link.a)] = Edit("node", node=name_key(link.a), lines=[render_header(fresh) + f"  # {stamp}"], new_node=fresh, why="new device")
            edits.append(new_blocks[name_key(link.a)])
        add_line(link.a, render_port_line(link, stamp="" if name_key(link.a) in new_blocks else stamp), "link from the imported map")
        have_links.add((link.pair(), *ports))
    for item in incoming.attachments:
        if item.port and (name_key(item.switch), port_key(item.port)) in have_ports:
            continue
        owner = current.node(item.switch)
        if (owner is None or owner.line < 0) and name_key(item.switch) not in new_blocks:
            fresh = Node(name=item.switch)
            new_blocks[name_key(item.switch)] = Edit("node", node=name_key(item.switch), lines=[render_header(fresh) + f"  # {stamp}"], new_node=fresh, why="new device")
            edits.append(new_blocks[name_key(item.switch)])
        add_line(item.switch, render_port_line(item, stamp="" if name_key(item.switch) in new_blocks else stamp), "from the imported map")
        if item.port:
            have_ports.add((name_key(item.switch), port_key(item.port)))
    return edits


def _set_header_values(line: str, node: Node, values: Mapping[str, str]) -> str:
    body, comment = _strip_comment(line)
    for key, value in values.items():
        if key == "ip":
            body = body.replace(node.ip, value, 1) if node.ip and node.ip in body else f"{body} {value}"
        elif key == "location":
            body = re.sub(r"@\"[^\"]*\"|@'[^']*'|@\S.*$", "", body).rstrip() + f" @{_quote(value)}"
        elif key == "kind":
            tokens = body.split(maxsplit=1)
            body = f"{tokens[0]} {value}" + (f" {tokens[1]}" if len(tokens) > 1 else "")
        else:
            pattern = re.compile(rf"(?i)(?<!\S){re.escape(key)}=(\"[^\"]*\"|'[^']*'|\S+)")
            if pattern.search(body):
                body = pattern.sub(f"{key}={_quote(value)}", body, count=1)
            else:
                location = re.search(r"\s@", body)
                insert = f" {key}={_quote(value)}"
                body = body[:location.start()] + insert + body[location.start():] if location else body + insert
    return body + (f"  {comment}" if comment else "")


def apply_edits(netmap: NetMap, edits: Sequence[Edit], *, section: str = "") -> str:
    """The operator's file with `edits` applied: lines rewritten in place,
    port lines added at the end of their device's block, new devices
    appended in one marked section. Nothing is removed."""
    lines = list(netmap.lines)
    inserts: Dict[int, List[str]] = defaultdict(list)
    appended: List[str] = []
    new_nodes: Dict[str, List[str]] = {}
    for edit in edits:
        if edit.action == "replace" and 0 <= edit.line < len(lines):
            lines[edit.line] = edit.text
        elif edit.action == "fields":
            node = netmap.nodes.get(edit.node)
            if node is None:
                continue
            if node.line >= 0:
                lines[node.line] = _set_header_values(lines[node.line], node, edit.values)
            else:
                fresh = Node(node.name, node.kind, edit.values.get("ip", node.ip), edit.values.get("location", node.location),
                             {**node.fields, **{k: v for k, v in edit.values.items() if k not in {"ip", "location", "kind"}}})
                new_nodes.setdefault(edit.node, [render_header(fresh)])
        elif edit.action == "add":
            node = netmap.nodes.get(edit.node)
            if node is not None and node.line >= 0:
                inserts[node.end].extend(edit.lines)
            elif edit.node in new_nodes:
                new_nodes[edit.node].extend(edit.lines)
            elif node is not None:
                new_nodes[edit.node] = [render_header(node)] + list(edit.lines)
        elif edit.action == "node":
            if edit.node in new_nodes:
                new_nodes[edit.node] = edit.lines[:1] + new_nodes[edit.node][1:] + edit.lines[1:]
            else:
                new_nodes[edit.node] = list(edit.lines)
    for block in new_nodes.values():
        appended += block + [""]
    out: List[str] = []
    for index, line in enumerate(lines):
        out.append(line)
        if index in inserts:
            indent = _block_indent(lines, netmap, index)
            out.extend(indent + item.lstrip() for item in inserts[index])
    while out and not out[-1].strip():
        out.pop()
    if appended:
        out += ["", section or f"# --- Added by netrune, {today()} ---"] + appended
    return "\n".join(out).rstrip() + "\n"


def _block_indent(lines: Sequence[str], netmap: NetMap, end: int) -> str:
    for node in netmap.nodes.values():
        if node.end == end and node.line >= 0:
            for index in range(node.line + 1, node.end + 1):
                match = re.match(r"(\s+)\S", lines[index])
                if match:
                    return match.group(1)
    return "  "


def describe_edits(edits: Sequence[Edit], netmap: NetMap) -> List[Dict[str, str]]:
    rows = []
    for edit in edits:
        node = netmap.nodes.get(edit.node)
        name = node.name if node else (edit.new_node.name if edit.new_node else edit.node)
        if edit.action == "fields":
            change = ", ".join(f"{key}={value}" for key, value in edit.values.items())
        elif edit.action == "replace":
            change = edit.text.strip()
        else:
            change = " | ".join(line.strip() for line in edit.lines)
        rows.append({"device": name, "change": {"fields": "set", "add": "add", "node": "new device", "replace": "fill ports"}[edit.action],
                     "detail": change, "why": edit.why})
    return rows


# --------------------------------------------------------------------------
# Out


CSV_COLUMNS = ("device", "kind", "ip", "location", "model", "serial", "mac", "port", "connects_to", "remote_port", "endpoint", "label")


def to_rows(netmap: NetMap) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    for node in netmap.nodes.values():
        rows.append({"device": node.name, "kind": node.kind, "ip": node.ip, "location": node.location,
                     **{key: node.fields.get(key, "") for key in FIELD_ORDER}, "label": node.fields.get("notes", "")})
    for link in netmap.links:
        rows.append({"device": link.a, "port": link.a_port, "connects_to": link.b, "remote_port": link.b_port, "label": link.note})
    for item in netmap.attachments:
        rows.append({"device": item.switch, "port": item.port, "endpoint": item.kind, "label": item.label})
    return [{column: row.get(column, "") for column in CSV_COLUMNS} for row in rows]


def to_csv(netmap: NetMap) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=CSV_COLUMNS, lineterminator="\n")
    writer.writeheader()
    writer.writerows(to_rows(netmap))
    return buffer.getvalue()


_STATUS_COLOURS = {"OK": ("#d5e8d4", "#82b366"), "DIFFERENT": ("#ffe6cc", "#d79b00"), "NOT SEEN": ("#f8cecc", "#b85450"),
                   "NO MATCH": ("#f8cecc", "#b85450"), "STALE": ("#fff2cc", "#d6b656"), "UNKNOWN": ("#f5f5f5", "#999999"),
                   "NOT ON MAP": ("#dae8fc", "#6c8ebf")}


def to_drawio(netmap: NetMap, result: Optional[CheckResult] = None) -> str:
    """A draw.io diagram of the map: devices in layers by hops from the most
    connected one, cables labelled with both ports, everything coloured by
    the last check when one is given (green agrees, red not seen, orange
    different, blue on the network but not the map, grey unknown)."""
    node_status: Dict[str, str] = {}
    link_status: Dict[Tuple[str, str, str], str] = {}
    if result is not None:
        for item in result.findings:
            if item["kind"] == "device" and item["map"]:
                node_status[name_key(item["subject"])] = item["status"]
    for link in netmap.links:
        link_status[(name_key(link.a), port_key(link.a_port), name_key(link.b))] = "UNKNOWN"
    if result is not None:
        lookup = {(f"{link.a} {link.a_port}".strip() + f" -> {link.b} {link.b_port}".rstrip()): link for link in netmap.links}
        for item in result.findings:
            link = lookup.get(item["subject"]) if item["kind"] == "link" else None
            if link is not None:
                link_status[(name_key(link.a), port_key(link.a_port), name_key(link.b))] = item["status"]
    extra_links = [Link(entry["a"], entry["a_port"], entry["b"], entry["b_port"]) for entry in (result.discovered_links if result else [])]
    neighbours: Dict[str, Set[str]] = defaultdict(set)
    for link in netmap.links + extra_links:
        neighbours[name_key(link.a)].add(name_key(link.b))
        neighbours[name_key(link.b)].add(name_key(link.a))
    order = list(netmap.nodes)
    layer: Dict[str, int] = {}
    for start in sorted(order, key=lambda key: -len(neighbours[key])):
        if start in layer:
            continue
        base = max(layer.values(), default=-1) + 1
        layer[start] = base
        queue = [start]
        while queue:
            key = queue.pop(0)
            for other in sorted(neighbours[key]):
                if other not in layer and other in netmap.nodes:
                    layer[other] = layer[key] + 1
                    queue.append(other)
    rows: Dict[int, List[str]] = defaultdict(list)
    for key in order:
        rows[layer.get(key, 0)].append(key)
    ends: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for item in netmap.attachments:
        ends[name_key(item.switch)][item.kind] += 1
    cells = ['<mxCell id="0"/>', '<mxCell id="1" parent="0"/>']
    ids: Dict[str, str] = {}
    for depth, keys in sorted(rows.items()):
        for position, key in enumerate(keys):
            node = netmap.nodes[key]
            ident = f"n{len(ids) + 1}"
            ids[key] = ident
            fill, stroke = _STATUS_COLOURS.get(node_status.get(key, "UNKNOWN" if result else ""), ("#ffffff", "#000000"))
            label = [f"<b>{html.escape(node.name)}</b>"]
            if node.ip:
                label.append(html.escape(node.ip))
            if node.location:
                label.append(f"<i>{html.escape(node.location)}</i>")
            if ends.get(key):
                label.append(html.escape(", ".join(f"{count} {kind}" for kind, count in sorted(ends[key].items()))))
            value = html.escape("<br>".join(label), quote=True)
            cells.append(f'<mxCell id="{ident}" value="{value}" style="rounded=1;whiteSpace=wrap;html=1;fillColor={fill};strokeColor={stroke};" '
                         f'vertex="1" parent="1"><mxGeometry x="{40 + position * 230}" y="{40 + depth * 170}" width="190" height="80" as="geometry"/></mxCell>')
    for index, link in enumerate(netmap.links + extra_links, start=1):
        source, target = ids.get(name_key(link.a)), ids.get(name_key(link.b))
        if not source or not target:
            continue
        status = link_status.get((name_key(link.a), port_key(link.a_port), name_key(link.b)), "NOT ON MAP" if link in extra_links else "")
        _, stroke = _STATUS_COLOURS.get(status, ("", "#000000"))
        dashed = "dashed=1;" if status in {"NOT ON MAP", "UNKNOWN", "STALE"} else ""
        cells.append(f'<mxCell id="e{index}" value="" style="endArrow=none;html=1;strokeColor={stroke};{dashed}" edge="1" '
                     f'parent="1" source="{source}" target="{target}"><mxGeometry relative="1" as="geometry"/></mxCell>')
        for end, port in (("-0.7", link.a_port), ("0.7", link.b_port)):
            if port:
                side = "a" if end.startswith("-") else "b"
                cells.append(f'<mxCell id="e{index}{side}" value="{html.escape(port, quote=True)}" '
                             'style="edgeLabel;html=1;fontSize=9;" vertex="1" connectable="0" '
                             f'parent="e{index}"><mxGeometry x="{end}" relative="1" as="geometry"/></mxCell>')
    body = "".join(cells)
    return ('<mxfile host="netrune"><diagram name="Network map" id="netrune-map"><mxGraphModel grid="1" gridSize="10" '
            f'pageWidth="1600" pageHeight="1200"><root>{body}</root></mxGraphModel></diagram></mxfile>\n')
