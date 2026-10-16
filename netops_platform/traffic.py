#!/usr/bin/env python3
"""Interface and reachability monitoring.

Collection is watchlist driven: the poller only ever touches targets that were
explicitly named, so adding a switch to inventory never silently adds load.

Samples carry the identity of the collector that produced them. That costs
nothing here and is what allows a remote poller — reached over a tunnel — to
merge its history with a laptop's without the two becoming indistinguishable.

Signals are keyed by metric name rather than fixed columns, so adding a new
kind of measurement is a collector plus a row type, not a schema migration.
"""

from __future__ import annotations

import concurrent.futures

import contextlib
import json
import re
import socket
import time
import uuid
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

# 64-bit interface counters wrap here; the 32-bit ones wrap far sooner, which
# is why the collector prefers ifHCInOctets and records which width it saw.
#: Concurrent probes per round. Bounded so a large watchlist cannot open
#: an unbounded number of sockets or SNMP sessions at once.
POLL_WORKERS = 8

COUNTER_WIDTH_64 = 1 << 64
COUNTER_WIDTH_32 = 1 << 32

# An absolute backstop for a computed rate. Nothing on a copper access estate
# approaches this, so anything above it came from a counter reset or a
# re-indexed interface rather than from traffic.
MAX_PLAUSIBLE_BPS = 800_000_000_000

#: What a link is assumed to carry when the device does not report its speed.
#: A rate above the line rate did not happen -- the counter reset, or the
#: ifIndex now answers for a different port -- and without a reported speed
#: there is nothing else to judge it against. An estate with faster links than
#: this sets traffic_link_ceiling_bps.
DEFAULT_LINK_CEILING_BPS = 1_000_000_000

#: Two counter reads are never exactly an interval apart, so a port running at
#: line rate computes slightly above it. Past this the overshoot is not timing.
RATE_TOLERANCE = 1.05

#: ifSpeed is a 32-bit gauge and reports this when the real speed does not fit.
#: Believing it would divide utilisation by 4.29 Gbps and report every port as
#: idle, which is worse than reporting no utilisation at all.
IFSPEED_UNKNOWN = 4_294_967_295

WATCH_KINDS = ("interface", "icmp", "device")

#: Device health changes on the scale of minutes, not seconds. Polling it at
#: the interface cadence would multiply SNMP load for readings that would be
#: identical.
DEVICE_HEALTH_INTERVAL = 300

#: How often a raw counter is written to the replay log, regardless of how
#: often it is polled. A collector cut off from storage replays this log to
#: fill the gap, and a rate is derived over minutes -- so logging every ten
#: second poll would multiply the rows for resolution nothing reads.
COUNTER_LOG_INTERVAL = 60

SPARK_LEVELS = "▁▂▃▄▅▆▇█"

#: Units for the device-health readings, for the terminal views.
_HEALTH_UNITS = {
    "cpu_percent": "pct", "memory_used_bytes": "bytes", "memory_total_bytes": "bytes",
    "temperature_celsius": "C", "tcp_established": "count", "logged_in_users": "count",
    "interfaces": "count",
}


def sparkline(values: Sequence[Optional[float]], width: int = 0) -> str:
    """Render a series as a single line of block characters.

    Gaps are real information — a poller that missed a window should not look
    like a period of zero traffic — so a missing sample renders as a space.
    """
    series = list(values)
    if width and len(series) > width:
        # Keep the most recent window rather than averaging history away.
        series = series[-width:]
    present = [value for value in series if value is not None]
    if not present:
        return ""
    ceiling = max(present)
    floor = min(present)
    span = ceiling - floor
    out = []
    for value in series:
        if value is None:
            out.append(" ")
            continue
        if span <= 0:
            out.append(SPARK_LEVELS[0] if ceiling == 0 else SPARK_LEVELS[len(SPARK_LEVELS) // 2])
            continue
        step = int((value - floor) / span * (len(SPARK_LEVELS) - 1))
        out.append(SPARK_LEVELS[max(0, min(step, len(SPARK_LEVELS) - 1))])
    return "".join(out)


#: Colours for telling one link from another on a chart.
#:
#: These four were checked together, not chosen by eye: every pair separates
#: for normal vision and under deuteranopia, all four sit in one lightness band
#: so none shouts louder than the others, and all four hold contrast against a
#: dark chart surface. Adding a fifth to this set breaks it -- six hues will not
#: fit the band without two of them colliding -- so anything past these four is
#: given as an explicit hex and is nobody's guarantee but the person choosing.
#:
#: Colour is never the only thing carrying identity here: every series is named
#: in a legend, a bar, or a table row as well.
SERIES_COLORS = {
    "teal":   "#149084",
    "orange": "#B54D15",
    "green":  "#79A632",
    "violet": "#7A5AF0",
}

HEX_COLOR_RE = re.compile(r"^#[0-9a-fA-F]{6}$")


def resolve_color(value: Any) -> Optional[str]:
    """A colour from the checked set, or an explicit hex the caller vouches for."""
    text = str(value or "").strip().lower()
    if not text:
        return None
    if text in SERIES_COLORS:
        return SERIES_COLORS[text]
    if HEX_COLOR_RE.match(text):
        return text
    return None


RATE_SUFFIXES = {"k": 1e3, "m": 1e6, "g": 1e9, "t": 1e12}


def parse_rate(text: Any) -> Optional[int]:
    """Read a subscribed rate the way a contract writes it.

    "100M", "100 Mbps", "1.5G", and "100000000" all mean the same thing, and an
    operator copying a number off an invoice should not have to convert it.
    Decimal multiples throughout, because that is what a service is sold in --
    a 100M service is 100,000,000 bits per second, not 104,857,600.
    """
    raw = str(text or "").strip().lower().replace(" ", "")
    if not raw:
        return None
    for tail in ("bit/s", "bits/s", "bps", "b/s", "b"):
        if raw.endswith(tail):
            raw = raw[: -len(tail)]
            break
    scale = 1.0
    if raw and raw[-1] in RATE_SUFFIXES:
        scale = RATE_SUFFIXES[raw[-1]]
        raw = raw[:-1]
    try:
        value = float(raw)
    except ValueError:
        return None
    if value <= 0:
        return None
    return int(round(value * scale))


def humanize_bps(value: Optional[float]) -> str:
    """Format a bit rate the way an operator reads it."""
    if value is None:
        return "-"
    magnitude = float(value)
    for unit, scale in (("Tbps", 1e12), ("Gbps", 1e9), ("Mbps", 1e6), ("kbps", 1e3)):
        if magnitude >= scale:
            return f"{magnitude / scale:.2f} {unit}"
    return f"{magnitude:.0f} bps"


def parse_timeticks(value: Any) -> int:
    """Convert an SNMP uptime to whole seconds.

    net-snmp prints either raw ticks or a `days:hours:minutes:seconds.frac`
    string depending on the output flags, and both reach this code.
    """
    text = str(value or "").strip()
    if not text:
        return 0
    if re.fullmatch(r"\d+", text):
        return int(text) // 100
    match = re.search(r"(?:(\d+):)?(\d{1,2}):(\d{2}):(\d{2})(?:\.\d+)?", text)
    if not match:
        return 0
    days, hours, minutes, seconds = match.groups()
    return int(days or 0) * 86400 + int(hours) * 3600 + int(minutes) * 60 + int(seconds)


def parse_interface_index(text: Any) -> List[Dict[str, str]]:
    """Parse `ifIndex|ifName|ifAlias` lines from the SNMP helper."""
    rows: List[Dict[str, str]] = []
    for line in str(text or "").splitlines():
        parts = line.strip().split("|")
        if len(parts) < 2 or not parts[0].isdigit():
            continue
        rows.append({
            "ifindex": parts[0],
            "name": parts[1].strip(),
            "alias": parts[2].strip() if len(parts) > 2 else "",
        })
    return rows


def parse_interface_counters(text: Any) -> Dict[str, Any]:
    """Parse counter lines plus the device uptime from the SNMP helper."""
    result: Dict[str, Any] = {"uptime_seconds": 0, "interfaces": {}}
    for line in str(text or "").splitlines():
        parts = line.strip().split("|")
        if len(parts) < 2:
            continue
        if parts[0] == "sysUpTime":
            result["uptime_seconds"] = parse_timeticks(parts[1])
            continue
        if not parts[0].isdigit() or len(parts) < 5:
            continue

        def number(value: str) -> Optional[int]:
            cleaned = re.sub(r"[^0-9]", "", value or "")
            return int(cleaned) if cleaned else None

        def field(position: int) -> str:
            return (parts[position] if len(parts) > position else "").strip()

        speed = number(parts[3])
        if speed is not None and (speed <= 0 or speed >= IFSPEED_UNKNOWN):
            speed = None

        result["interfaces"][parts[0]] = {
            "in_octets": number(parts[1]),
            "out_octets": number(parts[2]),
            "speed_bps": speed,
            "oper_status": (parts[4] or "").strip().lower(),
            "name": field(5),
            "in_errors": number(field(6)),
            "out_errors": number(field(7)),
            "in_discards": number(field(8)),
            "out_discards": number(field(9)),
            "admin_status": field(10).lower(),
            # Which octet counter answered. None from a collector too old to
            # report it, which means "do not check" rather than "64".
            "counter_width": number(field(11)),
        }
    return result


def plausible_rate(
    rate: float,
    speed_bps: Optional[int],
    ceiling_bps: int = DEFAULT_LINK_CEILING_BPS,
) -> Optional[float]:
    """The rate to record, or None when the link could not have carried it.

    A port cannot pass more than its line rate, so a reading above it is not a
    measurement of traffic -- it is a counter that reset between reads, or an
    ifIndex that has come to answer for a different port. Recording it draws a
    spike that never happened, and one such spike rescales every other line on
    the chart into a flat row along the bottom.

    Where the device reports no speed the estate ceiling stands in, which is
    what keeps an unknown port from admitting an impossible number.
    """
    if rate < 0:
        return None
    limit = min(float(speed_bps or ceiling_bps) * RATE_TOLERANCE, float(MAX_PLAUSIBLE_BPS))
    return rate if rate <= limit else None


DEVICE_HEALTH_COUNTERS = (
    "bad_community", "bad_community_use", "bad_version", "asn_parse_errors",
    "tcp_opens_in", "tcp_opens_out", "tcp_attempt_fails",
)

DEVICE_HEALTH_GAUGES = (
    "cpu_percent", "memory_used_bytes", "memory_total_bytes",
    "temperature_celsius", "tcp_established", "logged_in_users", "interfaces",
)

DEVICE_HEALTH_INFO = ("sysName", "sysDescr", "sysLocation", "sysContact")


def parse_device_health(text: Any) -> Dict[str, Any]:
    """Parse `key|value` lines from the device-health SNMP helper.

    Absence is the normal case for most keys: an agent that does not implement
    a MIB emits no line for it, and a reading that is missing must stay missing
    rather than become a zero. A zero CPU reading and no CPU reading look the
    same on a chart and mean opposite things.
    """
    result: Dict[str, Any] = {"uptime_seconds": 0, "counters": {}, "gauges": {}, "info": {}}
    for line in str(text or "").splitlines():
        key, separator, value = line.strip().partition("|")
        if not separator:
            continue
        key = key.strip()
        value = value.strip()
        if not value:
            continue
        if key == "sysUpTime":
            result["uptime_seconds"] = parse_timeticks(value)
        elif key in DEVICE_HEALTH_INFO:
            result["info"][key] = value[:200]
        elif key in DEVICE_HEALTH_COUNTERS or key in DEVICE_HEALTH_GAUGES:
            digits = re.sub(r"[^0-9.\-]", "", value)
            if not digits or digits in {"-", ".", "-."}:
                continue
            with contextlib.suppress(ValueError):
                number = float(digits)
                bucket = "counters" if key in DEVICE_HEALTH_COUNTERS else "gauges"
                result[bucket][key] = number
    return result


def _word_matches(word: str, haystack: str) -> bool:
    """One word of an operator's phrase, spelled the way they spell it.

    Normalising both sides is what lets "gi 1/0/16" and "Gi1/0/16" be the same
    port, which is how people actually type an interface name.
    """
    if word in haystack:
        return True
    normalized = _normalize(word)
    return bool(normalized) and normalized in _normalize(haystack)


def counter_delta(previous: int, current: int, width: int = COUNTER_WIDTH_64) -> Optional[int]:
    """Difference between two counter readings, accounting for wrap.

    A counter that went backwards has either wrapped or been reset. Wrap is
    recoverable; a reset is not, and guessing would invent a spike, so the
    caller is told to discard the interval instead.
    """
    if current >= previous:
        return current - previous
    wrapped = current + width - previous
    # A wrap moves the counter by less than one full width. A jump larger than
    # half the width is far more likely a reset than a genuine wrap.
    if wrapped < width // 2:
        return wrapped
    return None


class TrafficMonitor:
    """Watchlist, collectors, and series access for traffic monitoring."""

    def __init__(self, app: Any):
        self.app = app
        self.state = app.state
        #: Interfaces whose octet counter changed width during a round. Collected
        #: per poll so a persistent mismatch surfaces instead of silently
        #: draining a series to nothing.
        self._width_mismatches: List[Dict[str, Any]] = []

    # ---- collector identity -------------------------------------------------

    def link_ceiling_bps(self) -> int:
        """The fastest link this estate has, used where a device reports none."""
        configured = str(self.app.config.public.get("traffic_link_ceiling_bps") or "").strip()
        if configured.isdigit() and int(configured) > 0:
            return int(configured)
        return DEFAULT_LINK_CEILING_BPS

    def collector_id(self) -> str:
        """Identify the host that produced a sample.

        Configurable so a cloud poller can name itself something meaningful
        rather than reporting an opaque container hostname.
        """
        configured = str(self.app.config.public.get("traffic_collector_id") or "").strip()
        if configured:
            return configured[:64]
        with contextlib.suppress(Exception):
            return (socket.gethostname() or "local")[:64]
        return "local"

    # ---- watchlist ----------------------------------------------------------

    def add_watch(
        self,
        kind: str,
        *,
        device_ip: str = "",
        device_name: str = "",
        interface_name: str = "",
        target: str = "",
        label: str = "",
        interval_seconds: int = 60,
        actor: str = "",
        ifindex: str = "",
    ) -> Dict[str, Any]:
        kind = str(kind or "").strip().lower()
        if kind not in WATCH_KINDS:
            raise ValueError(f"watch kind must be one of {', '.join(WATCH_KINDS)}")
        if kind == "interface" and not (device_ip and interface_name):
            raise ValueError("an interface watch needs a device and an interface name")
        if kind == "icmp" and not (target or device_ip):
            raise ValueError("an ICMP watch needs a target address")
        if kind == "device" and not device_ip:
            raise ValueError("a device watch needs a device address")
        interval = max(10, min(int(interval_seconds or 60), 3600))
        existing = self.find_watch(kind, device_ip=device_ip, interface_name=interface_name, target=target)
        if existing:
            return existing
        watch_id = "wch-" + uuid.uuid4().hex[:16]
        self.state.execute(
            "INSERT INTO traffic_watch(watch_id,kind,device_ip,device_name,interface_name,target,label,"
            "interval_seconds,enabled,added_at,added_by,notes) VALUES(?,?,?,?,?,?,?,?,1,?,?,'')",
            (watch_id, kind, device_ip, device_name, interface_name, target,
             label or interface_name or target or device_ip, interval, int(time.time()), actor or ""),
        )
        if ifindex:
            self._remember_index(watch_id, str(ifindex), interface_name)
        return self.get_watch(watch_id) or {}

    def find_watch(self, kind: str, *, device_ip: str = "", interface_name: str = "", target: str = "") -> Optional[Dict[str, Any]]:
        if kind == "interface":
            return self.state.one(
                "SELECT * FROM traffic_watch WHERE kind='interface' AND device_ip=? AND lower(interface_name)=lower(?)",
                (device_ip, interface_name),
            )
        if kind == "device":
            return self.state.one(
                "SELECT * FROM traffic_watch WHERE kind='device' AND device_ip=?", (device_ip,))
        return self.state.one("SELECT * FROM traffic_watch WHERE kind='icmp' AND target=?", (target,))

    def get_watch(self, watch_id: str) -> Optional[Dict[str, Any]]:
        return self.state.one("SELECT * FROM traffic_watch WHERE watch_id=?", (watch_id,))

    def list_watches(self, enabled_only: bool = False,
                     owned_only: bool = False) -> List[Dict[str, Any]]:
        """Every watch, or only the ones this collector is responsible for.

        A watch pulled from a remote poller carries that poller's collector id
        as its owner. This collector must never poll it: the device sits on the
        remote's network, and trying would produce failures that read as the
        device being down.
        """
        clauses = []
        if enabled_only:
            clauses.append("enabled=1")
        if owned_only:
            clauses.append("(owner IS NULL OR owner='' OR owner=?)")
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        arguments = (self.collector_id(),) if owned_only else ()
        return self.state.rows(
            f"SELECT * FROM traffic_watch{where}"
            " ORDER BY kind,device_name,device_ip,interface_name,target", arguments)

    def sync_device_watches(self, actor: str = "") -> Dict[str, List[str]]:
        """Keep one switch-health watch beside every switch with a watched port.

        Switch health matters exactly when somebody is already watching a port
        on that switch, and it is what makes the port readable: throughput that
        fell to nothing means one thing if the switch rebooted, another if its
        CPU is pinned, and another if the link is simply quiet. Reading those
        from three separate places is how the wrong conclusion gets drawn.

        The list is derived rather than maintained. An operator who had to
        remember to add and remove a second watch alongside the first would
        eventually be graphing a switch nobody watches and missing one they do.

        A paused interface watch still keeps its switch's health watch: a pause
        is temporary, and the history is worth more unbroken.
        """
        added: List[str] = []
        removed: List[str] = []
        wanted: Dict[str, Dict[str, str]] = {}
        for watch in self.list_watches():
            if watch.get("kind") != "interface":
                continue
            address = str(watch.get("device_ip") or "")
            if not address:
                continue
            wanted.setdefault(address, {
                "device_name": str(watch.get("device_name") or ""),
                # The health watch must belong to whoever owns the ports, or a
                # laptop would poll a switch that only the remote poller can
                # reach and record the failure as the switch being down.
                "owner": str(watch.get("owner") or ""),
            })

        existing = {str(watch.get("device_ip") or ""): watch
                    for watch in self.list_watches() if watch.get("kind") == "device"}

        for address, details in wanted.items():
            watch = existing.get(address)
            if watch:
                if str(watch.get("owner") or "") != details["owner"]:
                    self.set_owner(str(watch["watch_id"]), details["owner"])
                continue
            created = self.add_watch(
                "device", device_ip=address, device_name=details["device_name"],
                label=f"{details['device_name'] or address} health",
                interval_seconds=self.device_health_interval(), actor=actor or "auto")
            if created:
                if details["owner"]:
                    self.set_owner(str(created["watch_id"]), details["owner"])
                added.append(address)

        for address, watch in existing.items():
            if address not in wanted:
                self.remove_watch(str(watch["watch_id"]))
                removed.append(address)
        return {"added": added, "removed": removed}

    def device_health_interval(self) -> int:
        configured = str(self.app.config.public.get("traffic_device_interval") or "").strip()
        if configured.isdigit() and int(configured) >= 30:
            return min(int(configured), 3600)
        return DEVICE_HEALTH_INTERVAL

    def owns(self, watch: Mapping[str, Any]) -> bool:
        owner = str(watch.get("owner") or "")
        return not owner or owner == self.collector_id()

    def set_owner(self, watch_id: str, owner: str) -> None:
        self.state.execute("UPDATE traffic_watch SET owner=? WHERE watch_id=?", (owner, watch_id))

    def remove_watch(self, watch_id: str) -> bool:
        if not self.get_watch(watch_id):
            return False
        self.state.execute("DELETE FROM traffic_watch WHERE watch_id=?", (watch_id,))
        return True

    def set_enabled(self, watch_id: str, enabled: bool) -> bool:
        if not self.get_watch(watch_id):
            return False
        self.state.execute("UPDATE traffic_watch SET enabled=? WHERE watch_id=?", (1 if enabled else 0, watch_id))
        return True

    def set_display_name(self, watch_id: str, name: str) -> bool:
        """Give a watch a name a human chose, or clear it with an empty string.

        The name never becomes part of a series' identity -- it travels on a
        separate info metric that the dashboards join against. Naming a port
        that has been collected for weeks would otherwise start a new series
        and leave its history stranded under the old one, which is a steep
        price for a label.
        """
        if not self.get_watch(watch_id):
            return False
        cleaned = " ".join(str(name or "").split())[:64]
        self.state.execute(
            "UPDATE traffic_watch SET display_name=? WHERE watch_id=?",
            (cleaned or None, watch_id))
        return True

    def display_name(self, watch: Mapping[str, Any]) -> str:
        """What to call this target on a chart.

        Falls back to what the device calls the port, so a legend always reads
        as something rather than as a blank.
        """
        chosen = str(watch.get("display_name") or "").strip()
        if chosen:
            return chosen
        if watch.get("kind") == "icmp":
            return str(watch.get("target") or watch.get("label") or "")
        return str(watch.get("interface_name") or watch.get("device_name")
                   or watch.get("device_ip") or "")

    def set_display_color(self, watch_id: str, color: str) -> bool:
        """Pin a colour to a link, so it is the same colour on every chart.

        A grapher assigns colours by the order series happen to arrive, which
        means a link changes colour when another one goes quiet and drops out
        of a topk. Pinning it makes the colour mean the link rather than its
        current rank.
        """
        if not self.get_watch(watch_id):
            return False
        resolved = resolve_color(color) if color else None
        self.state.execute(
            "UPDATE traffic_watch SET display_color=? WHERE watch_id=?", (resolved, watch_id))
        return True

    #: The combined line is not a watch, so its colour cannot come from one.
    #: Violet because it has to stand apart from every link colour at once.
    WAN_SERIES_NAME = "WAN"

    def series_colors(self) -> Dict[str, str]:
        """Chosen colours keyed by the name each link is drawn under."""
        colors: Dict[str, str] = {}
        for watch in self.list_watches():
            chosen = str(watch.get("display_color") or "").strip()
            if chosen:
                colors[self.display_name(watch)] = chosen
        if colors:
            configured = resolve_color(self.app.config.public.get("traffic_wan_color"))
            colors[self.WAN_SERIES_NAME] = configured or SERIES_COLORS["violet"]
        return colors

    def set_subscription(self, watch_id: str, down_bps: Optional[int],
                         up_bps: Optional[int], faces_lan: Optional[bool] = None) -> bool:
        """Record what this link is sold as, so utilisation can mean something.

        A port's line rate says what the hardware can carry; a service link's
        subscribed rate says what you are entitled to. On a gigabit port
        carrying a 100M service, utilisation against the line rate reads 10% at
        the exact moment the service is full, which is the opposite of useful.

        These are soft limits. Nothing is enforced and nothing is discarded for
        exceeding them -- they are what the bars are drawn against.
        """
        watch = self.get_watch(watch_id)
        if not watch:
            return False
        assignments = ["subscribed_down_bps=?", "subscribed_up_bps=?"]
        values: List[Any] = [down_bps or None, up_bps or None]
        if faces_lan is not None:
            assignments.append("faces_lan=?")
            values.append(1 if faces_lan else 0)
        values.append(watch_id)
        self.state.execute(
            f"UPDATE traffic_watch SET {','.join(assignments)} WHERE watch_id=?", tuple(values))
        return True

    def subscription(self, watch: Mapping[str, Any]) -> Dict[str, Any]:
        """The subscribed rates resolved onto the counters they constrain.

        Which counter carries "download" depends on which way the port faces. On
        the port that reaches the provider, what the switch receives came from
        the internet, so receive is download. On the port facing the LAN it is
        the other way round, and reading one as the other would show a full
        upload as a quiet download.
        """
        down = int(watch.get("subscribed_down_bps") or 0)
        up = int(watch.get("subscribed_up_bps") or 0)
        if not (down or up):
            return {}
        faces_lan = bool(watch.get("faces_lan"))
        return {
            "down_bps": down,
            "up_bps": up,
            "faces_lan": faces_lan,
            # What the receive counter is capped by, and what to call it.
            "receive_bps": up if faces_lan else down,
            "transmit_bps": down if faces_lan else up,
            "downlink": "transmit" if faces_lan else "receive",
        }

    def service_links(self) -> List[Any]:
        """The purchased links, named and coloured, for the overview to draw.

        Which links exist is a property of the estate, so the dashboard is
        generated from the watchlist rather than carrying a fixed list that
        would be wrong the first time one is added.
        """
        from netops_platform.traffic_dashboards import ServiceLink
        return [ServiceLink(name=self.display_name(watch),
                            color=str(watch.get("display_color") or ""),
                            down_bps=int(watch.get("subscribed_down_bps") or 0),
                            up_bps=int(watch.get("subscribed_up_bps") or 0))
                for watch in self.subscribed_watches()]

    def subscribed_watches(self) -> List[Dict[str, Any]]:
        """Watches that carry a purchased service, which is what "WAN" means here."""
        return [watch for watch in self.list_watches()
                if watch.get("subscribed_down_bps") or watch.get("subscribed_up_bps")]

    def set_interval(self, watch_id: str, seconds: int) -> bool:
        if not self.get_watch(watch_id):
            return False
        self.state.execute(
            "UPDATE traffic_watch SET interval_seconds=? WHERE watch_id=?",
            (max(10, min(int(seconds), 3600)), watch_id),
        )
        return True

    def match_watches(self, needle: str, enabled_only: bool = False) -> List[Dict[str, Any]]:
        """Watches an operator's phrase refers to.

        An exact watch id wins outright, and is the way to name one target with
        no ambiguity at all -- `netrune traffic list` prints them.

        Otherwise every word has to match, against any of the fields an operator
        would use to name a target. So `Gi1/1/1` reaches that port on every
        switch, `SITE-A-SW01` reaches every port on that switch, and
        `SITE-A-SW01 Gi1/1/1` reaches exactly one. Requiring every word rather
        than the whole phrase is what makes the last of those work: the fields
        are searched together, and a device and its port are not adjacent in
        that text.
        """
        text = str(needle or "").strip().lower()
        if not text:
            return []
        exact = self.get_watch(needle.strip())
        if exact and (not enabled_only or exact.get("enabled")):
            return [exact]
        fields = ("watch_id", "device_name", "device_ip", "interface_name", "target",
                  "label", "display_name")
        words = text.split()
        matched: List[Dict[str, Any]] = []
        for watch in self.list_watches(enabled_only=enabled_only):
            haystack = " ".join(str(watch.get(field) or "") for field in fields).lower()
            if all(_word_matches(word, haystack) for word in words):
                matched.append(watch)
        return matched

    # ---- interface index resolution ----------------------------------------

    @staticmethod
    def match_interface(rows: Sequence[Mapping[str, Any]], interface_name: str) -> Optional[Dict[str, Any]]:
        """The row an operator's spelling of an interface name refers to."""
        wanted = _normalize(interface_name)
        for row in rows:
            if _normalize(row.get("name")) == wanted:
                return dict(row)
        return None

    def resolve_interface_index(self, device_ip: str, interface_name: str, opts: Any = None) -> Dict[str, Any]:
        """Map an interface name to its SNMP index.

        The index is not stable across a reload on some platforms, so it is
        resolved rather than stored, and the caller re-resolves when a counter
        read stops matching.
        """
        timeout = min(int(getattr(opts, "timeout", 0) or 60), 120)
        rc, out, err = self.app.capture(
            self.app.legacy_cmd("netrune-control", "snmp-index", device_ip), timeout
        )
        rows = parse_interface_index((out or "") + (err or ""))
        if not rows:
            return {"ok": False, "error": "SNMP returned no interface list", "exit_code": rc}
        wanted = _normalize(interface_name)
        for row in rows:
            if _normalize(row["name"]) == wanted:
                return {"ok": True, **row}
        return {
            "ok": False,
            "error": f"{interface_name} was not found among {len(rows)} interfaces",
            "candidates": [row["name"] for row in rows[:12]],
        }

    # ---- collection ---------------------------------------------------------

    def due_watches(
        self,
        attempts: Dict[str, float],
        now: Optional[float] = None,
        override_interval: int = 0,
    ) -> List[Dict[str, Any]]:
        """Enabled watches whose own interval has elapsed since the last attempt.

        `attempts` is the caller's record of when each watch was last tried, and
        is updated in place. A watch that has never been tried is due, so a
        collector starting up takes one reading from everything before settling
        into each watch's cadence.
        """
        moment = time.time() if now is None else float(now)
        due: List[Dict[str, Any]] = []
        for watch in self.list_watches(enabled_only=True, owned_only=True):
            watch_id = str(watch["watch_id"])
            interval = int(override_interval or watch.get("interval_seconds") or 60)
            last = attempts.get(watch_id)
            if last is None or moment - last >= interval:
                attempts[watch_id] = moment
                due.append(watch)
        for stale in set(attempts) - {str(w["watch_id"]) for w in self.list_watches()}:
            attempts.pop(stale, None)
        return due

    def poll(self, watches: Optional[Sequence[Mapping[str, Any]]] = None, opts: Any = None) -> Dict[str, Any]:
        """Collect one round for the given watches, or all enabled ones."""
        selected = list(watches if watches is not None else self.list_watches(enabled_only=True))
        self._width_mismatches = []
        observed_at = int(time.time())
        collector = self.collector_id()
        recorded = 0
        errors: List[Dict[str, Any]] = []

        by_device: Dict[str, List[Mapping[str, Any]]] = {}
        icmp_watches: List[Mapping[str, Any]] = []
        device_watches: List[Mapping[str, Any]] = []
        for watch in selected:
            if watch.get("kind") == "interface":
                by_device.setdefault(str(watch.get("device_ip") or ""), []).append(watch)
            elif watch.get("kind") == "icmp":
                icmp_watches.append(watch)
            elif watch.get("kind") == "device":
                device_watches.append(watch)

        # Every unit of work below is a network round trip against a different
        # address, so they wait on each other for no reason if run in turn. A
        # ping is roughly three seconds of mostly waiting; a dozen targets in
        # sequence would outlast the interval they were asked to keep.
        jobs: List[Tuple[str, Any, Any]] = [
            ("device", device_ip,
             lambda ip=device_ip, group=device_watches:
                 self._poll_device_interfaces(ip, group, observed_at, collector, opts))
            for device_ip, device_watches in by_device.items()
        ] + [
            ("target", watch.get("target"),
             lambda w=watch: self._poll_icmp(w, observed_at, collector, opts))
            for watch in icmp_watches
        ] + [
            ("device", watch.get("device_ip"),
             lambda w=watch: self._poll_device_health(w, observed_at, collector, opts))
            for watch in device_watches
        ]
        if len(jobs) == 1:
            label, subject, work = jobs[0]
            try:
                recorded += work()
            except Exception as exc:
                errors.append({label: subject, "error": str(exc)})
        elif jobs:
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=min(POLL_WORKERS, len(jobs)), thread_name_prefix="netrune-poll"
            ) as pool:
                pending = {pool.submit(work): (label, subject) for label, subject, work in jobs}
                for future in concurrent.futures.as_completed(pending):
                    label, subject = pending[future]
                    try:
                        recorded += future.result()
                    except Exception as exc:
                        errors.append({label: subject, "error": str(exc)})

        for mismatch in self._width_mismatches:
            watch = self.get_watch(str(mismatch["watch_id"])) or {}
            errors.append({
                "device": watch.get("device_name") or watch.get("device_ip"),
                "interface": watch.get("interface_name"),
                "error": (f"the switch answered with the {mismatch['got']}-bit octet counter "
                          f"where it had been answering the {mismatch['expected']}-bit one; "
                          "the reading was discarded rather than mixed into the series"),
            })

        return {
            "ok": not errors or recorded > 0,
            "observed_at": observed_at,
            "collector": collector,
            "watches": len(selected),
            "samples_recorded": recorded,
            "errors": errors,
            "counter_width_mismatches": len(self._width_mismatches),
        }

    def _poll_device_interfaces(
        self,
        device_ip: str,
        watches: Sequence[Mapping[str, Any]],
        observed_at: int,
        collector: str,
        opts: Any,
    ) -> int:
        if not device_ip:
            return 0
        # The ifIndex is resolved once at watch time and reused, because walking
        # the whole IF-MIB on every round costs far more than the counter read
        # itself. Drift is caught below rather than assumed away.
        index_of: Dict[str, str] = {}
        unresolved: List[Mapping[str, Any]] = []
        for watch in watches:
            cached = str(watch.get("ifindex") or "").strip()
            if cached.isdigit():
                index_of[str(watch["watch_id"])] = cached
            else:
                unresolved.append(watch)
        for watch in unresolved:
            resolved = self.resolve_interface_index(device_ip, str(watch.get("interface_name") or ""), opts)
            if resolved.get("ok"):
                index_of[str(watch["watch_id"])] = str(resolved["ifindex"])
                self._remember_index(str(watch["watch_id"]), str(resolved["ifindex"]), str(resolved.get("name") or ""))
        if not index_of:
            return 0

        reading = self._read_counters(device_ip, sorted(set(index_of.values()), key=int), opts)
        if not reading["interfaces"]:
            return 0

        recorded = 0
        stale: List[Mapping[str, Any]] = []
        for watch in watches:
            watch_id = str(watch["watch_id"])
            ifindex = index_of.get(watch_id)
            counters = reading["interfaces"].get(ifindex or "")
            expected = str(watch.get("interface_name") or "")
            # An ifIndex that now answers for a different port would graph the
            # wrong link silently, which is worse than a gap in the series.
            if counters and counters.get("name") and expected and _normalize(counters["name"]) != _normalize(expected):
                counters = None
            if not counters:
                if watch.get("ifindex"):
                    stale.append(watch)
                continue
            recorded += self._record_interface_sample(
                watch_id, counters, reading["uptime_seconds"], observed_at, collector
            )

        for watch in stale:
            resolved = self.resolve_interface_index(device_ip, str(watch.get("interface_name") or ""), opts)
            if not resolved.get("ok"):
                self._remember_index(str(watch["watch_id"]), "", "")
                continue
            self._remember_index(str(watch["watch_id"]), str(resolved["ifindex"]), str(resolved.get("name") or ""))
            retry = self._read_counters(device_ip, [str(resolved["ifindex"])], opts)
            counters = retry["interfaces"].get(str(resolved["ifindex"]))
            if counters:
                recorded += self._record_interface_sample(
                    str(watch["watch_id"]), counters, retry["uptime_seconds"], observed_at, collector
                )
        return recorded

    def _read_counters(self, device_ip: str, indexes: Sequence[str], opts: Any) -> Dict[str, Any]:
        timeout = min(int(getattr(opts, "timeout", 0) or 60), 120)
        rc, out, err = self.app.capture(
            self.app.legacy_cmd("netrune-control", "snmp-counters", device_ip, ",".join(indexes)), timeout
        )
        return parse_interface_counters((out or "") + (err or ""))

    def _remember_index(self, watch_id: str, ifindex: str, name: str) -> None:
        self.state.execute(
            "UPDATE traffic_watch SET ifindex=?, ifname=? WHERE watch_id=?",
            (ifindex, name, watch_id),
        )

    def _record_interface_sample(
        self,
        watch_id: str,
        counters: Mapping[str, Any],
        uptime_seconds: int,
        observed_at: int,
        collector: str,
    ) -> int:
        speed = counters.get("speed_bps") or 0
        status = str(counters.get("oper_status") or "")
        rates: Dict[str, Optional[float]] = {"in_bps": None, "out_bps": None}

        previous = {
            str(row["counter"]): row
            for row in self.state.rows(
                "SELECT counter,observed_at,value FROM traffic_counters WHERE watch_id=? AND collector=?",
                (watch_id, collector),
            )
        }
        # A device that restarted has counters starting from zero again, so the
        # interval spanning the restart is not a measurement.
        restarted = False
        uptime_row = previous.get("uptime")
        if uptime_row and uptime_seconds and int(uptime_row["value"]) > uptime_seconds:
            restarted = True

        def remember(name: str, value: Any) -> None:
            if value is None:
                return
            self.state.execute(
                "INSERT OR REPLACE INTO traffic_counters(watch_id,counter,observed_at,value,collector)"
                " VALUES(?,?,?,?,?)",
                (watch_id, name, observed_at, int(value), collector),
            )
            self._log_counter(watch_id, name, observed_at, value, collector, previous)

        # ifHCInOctets and ifInOctets are different counters, not two spellings
        # of one. A poll that misses the 64-bit varbind falls back to the 32-bit
        # one, which substitutes a value orders of magnitude smaller into the
        # middle of the same series. The reading after it then looks like the
        # link carried the entire counter in one interval -- which is how a
        # 10 Gb port comes to report tens of terabits per second.
        #
        # A reading of the wrong width is discarded rather than stored. A gap is
        # the truth, and the exposition holding its last value for one interval
        # is already how a missed read looks.
        width = counters.get("counter_width")
        stored = previous.get("counter_width")
        previous_width = int(stored["value"]) if stored else None
        mismatched = bool(width and previous_width and width != previous_width)
        if mismatched:
            seen = previous.get("counter_width_seen")
            # Two rounds running is a device that really did change which
            # counter it answers, rather than one varbind going missing. Adopt
            # the new width and drop the old baseline, so no delta is ever
            # computed between two different counters.
            if seen is not None and int(seen["value"]) == width:
                self.state.execute(
                    "DELETE FROM traffic_counters WHERE watch_id=? AND collector=?"
                    " AND counter IN ('in_octets','out_octets')", (watch_id, collector))
                previous.pop("in_octets", None)
                previous.pop("out_octets", None)
                mismatched = False
        if width:
            remember("counter_width_seen", width)
            if not mismatched:
                remember("counter_width", width)

        for counter_name, metric in (("in_octets", "in_bps"), ("out_octets", "out_bps")):
            if mismatched:
                break
            current = counters.get(counter_name)
            if current is None:
                continue
            prior = previous.get(counter_name)
            if prior and not restarted:
                elapsed = observed_at - int(prior["observed_at"])
                delta = counter_delta(int(prior["value"]), int(current))
                if elapsed > 0 and delta is not None:
                    rates[metric] = plausible_rate(
                        delta * 8 / elapsed, speed, self.link_ceiling_bps())
            remember(counter_name, current)

        # Error and discard counters are stored raw and never differenced here.
        # A time-series database derives their rate at query time, and keeping
        # the monotonic value is what makes that possible.
        for name in ("in_errors", "out_errors", "in_discards", "out_discards"):
            remember(name, counters.get(name))
        remember("speed_bps", speed or None)
        remember("oper_up", 1 if status == "up" else 0)
        admin = str(counters.get("admin_status") or "")
        if admin:
            remember("admin_up", 1 if admin == "up" else 0)
        if uptime_seconds:
            remember("uptime", uptime_seconds)

        if mismatched:
            # Said plainly so a persistent mismatch is visible rather than
            # quietly draining the series to nothing.
            self._width_mismatches.append(
                {"watch_id": watch_id, "expected": previous_width, "got": width})

        written = 0
        for metric, value in rates.items():
            if value is None:
                continue
            self._write_sample(watch_id, observed_at, metric, value, "bps", status, collector,
                               {"speed_bps": speed})
            written += 1
        if speed and rates.get("in_bps") is not None:
            self._write_sample(watch_id, observed_at, "in_utilization_pct",
                               min(100.0, rates["in_bps"] / speed * 100), "pct", status, collector, {})
            written += 1
        if speed and rates.get("out_bps") is not None:
            self._write_sample(watch_id, observed_at, "out_utilization_pct",
                               min(100.0, rates["out_bps"] / speed * 100), "pct", status, collector, {})
            written += 1
        # Link state is worth recording even on the first read, when no rate
        # can exist yet.
        self._write_sample(watch_id, observed_at, "oper_up", 1.0 if status == "up" else 0.0,
                           "bool", status, collector, {"speed_bps": speed})
        return written + 1

    def _poll_device_health(
        self, watch: Mapping[str, Any], observed_at: int, collector: str, opts: Any
    ) -> int:
        """Read the switch behind a watched port: uptime, load, and who is knocking."""
        device_ip = str(watch.get("device_ip") or "")
        if not device_ip:
            return 0
        timeout = min(int(getattr(opts, "timeout", 0) or 60), 120)
        rc, out, err = self.app.capture(
            self.app.legacy_cmd("netrune-control", "snmp-health", device_ip), timeout)
        reading = parse_device_health((out or "") + (err or ""))
        if not (reading["counters"] or reading["gauges"] or reading["uptime_seconds"]):
            return 0

        watch_id = str(watch["watch_id"])
        known = {str(row["counter"]): row for row in self.state.rows(
            "SELECT counter,observed_at,value FROM traffic_counters WHERE watch_id=? AND collector=?",
            (watch_id, collector))}
        for name, value in sorted(reading["counters"].items()):
            self.state.execute(
                "INSERT OR REPLACE INTO traffic_counters(watch_id,counter,observed_at,value,collector)"
                " VALUES(?,?,?,?,?)", (watch_id, name, observed_at, int(value), collector))
            self._log_counter(watch_id, name, observed_at, value, collector, known)
        if reading["uptime_seconds"]:
            self.state.execute(
                "INSERT OR REPLACE INTO traffic_counters(watch_id,counter,observed_at,value,collector)"
                " VALUES(?,?,?,?,?)", (watch_id, "uptime", observed_at,
                                       int(reading["uptime_seconds"]), collector))

        written = 0
        # Gauges also land in traffic_counters, which is what the exposition
        # reads. They are published as gauges there; the table's name describes
        # where a reading is kept, not what kind of number it is.
        for name, value in sorted(reading["gauges"].items()):
            self.state.execute(
                "INSERT OR REPLACE INTO traffic_counters(watch_id,counter,observed_at,value,collector)"
                " VALUES(?,?,?,?,?)", (watch_id, name, observed_at, int(value), collector))
            self._log_counter(watch_id, name, observed_at, value, collector, known)
            self._write_sample(watch_id, observed_at, name, float(value),
                               _HEALTH_UNITS.get(name, ""), "up", collector, {})
            written += 1
        if reading["uptime_seconds"]:
            self._write_sample(watch_id, observed_at, "uptime_seconds",
                               float(reading["uptime_seconds"]), "s", "up", collector, {})
            written += 1
        if reading["gauges"].get("memory_total_bytes") and reading["gauges"].get("memory_used_bytes"):
            share = (reading["gauges"]["memory_used_bytes"]
                     / reading["gauges"]["memory_total_bytes"] * 100)
            self._write_sample(watch_id, observed_at, "memory_percent",
                               min(100.0, share), "pct", "up", collector, {})
            written += 1
        if reading["info"]:
            # Identity is one row per poll rather than a sample series: it is a
            # label, and a label that changes is news rather than a measurement.
            self.state.execute(
                "INSERT OR REPLACE INTO traffic_counters(watch_id,counter,observed_at,value,collector)"
                " VALUES(?,?,?,?,?)", (watch_id, "info_seen", observed_at, 1, collector))
            self._write_sample(watch_id, observed_at, "device_info", 1.0, "", "up",
                               collector, reading["info"])
            written += 1
        return written

    #: Counters worth replaying. The rest are state, not a series, and a gap in
    #: them is not something a chart draws.
    REPLAYABLE = ("in_octets", "out_octets", "in_errors", "out_errors",
                  "in_discards", "out_discards", "speed_bps", "oper_up", "admin_up",
                  "uptime", "cpu_percent", "memory_used_bytes", "memory_total_bytes",
                  "temperature_celsius", "bad_community", "tcp_opens_in", "tcp_attempt_fails")

    def _log_counter(self, watch_id: str, name: str, observed_at: int, value: Any,
                     collector: str, previous: Mapping[str, Any]) -> None:
        """Keep a reading for replay, at a cadence a rate can actually use.

        The latest value alone is enough to publish now, and nothing more is
        needed while storage is reachable. It stops being enough the moment it
        is not: a collector that was cut off for a day has one number to offer
        for that day, and one number draws no line.
        """
        if name not in self.REPLAYABLE:
            return
        prior = previous.get(name)
        if prior and observed_at - int(prior["observed_at"]) < COUNTER_LOG_INTERVAL:
            return
        self.state.execute(
            "INSERT OR REPLACE INTO traffic_counter_log(watch_id,counter,observed_at,value,collector)"
            " VALUES(?,?,?,?,?)", (watch_id, name, observed_at, int(value), collector))

    def _poll_icmp(self, watch: Mapping[str, Any], observed_at: int, collector: str, opts: Any) -> int:
        target = str(watch.get("target") or watch.get("device_ip") or "")
        if not target:
            return 0
        payload = self.app.icmp_probe(target, opts)
        written = 0
        for metric, key, unit in (
            ("rtt_ms", "avg_ms", "ms"),
            ("packet_loss_pct", "packet_loss_pct", "pct"),
            ("jitter_ms", "jitter_ms", "ms"),
        ):
            value = payload.get(key)
            if value is None:
                continue
            self._write_sample(str(watch["watch_id"]), observed_at, metric, float(value), unit,
                               "up" if not payload.get("unreachable") else "down", collector, {})
            written += 1
        self._write_sample(str(watch["watch_id"]), observed_at, "reachable",
                           0.0 if payload.get("unreachable") else 1.0, "bool",
                           "down" if payload.get("unreachable") else "up", collector, {})
        return written + 1

    def _write_sample(
        self,
        watch_id: str,
        observed_at: int,
        metric: str,
        value: float,
        unit: str,
        status: str,
        collector: str,
        raw: Mapping[str, Any],
    ) -> None:
        self.state.execute(
            "INSERT INTO traffic_samples(watch_id,observed_at,metric,value,unit,status,collector,raw_json) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (watch_id, observed_at, metric, float(value), unit, status, collector,
             json.dumps(dict(raw), sort_keys=True) if raw else None),
        )

    # ---- series -------------------------------------------------------------

    def series(
        self,
        watch_id: str,
        metric: str,
        since_seconds: int = 3600,
        collector: str = "",
    ) -> List[Dict[str, Any]]:
        cutoff = int(time.time()) - max(60, int(since_seconds))
        clauses = ["watch_id=?", "metric=?", "observed_at>=?"]
        params: List[Any] = [watch_id, metric, cutoff]
        if collector:
            clauses.append("collector=?")
            params.append(collector)
        return self.state.rows(
            "SELECT observed_at,value,unit,status,collector FROM traffic_samples "
            f"WHERE {' AND '.join(clauses)} ORDER BY observed_at",
            tuple(params),
        )

    def summarize(self, watch_id: str, metric: str, since_seconds: int = 3600) -> Dict[str, Any]:
        rows = self.series(watch_id, metric, since_seconds)
        values = [float(row["value"]) for row in rows if row["value"] is not None]
        if not values:
            return {"samples": 0, "latest": None, "peak": None, "mean": None, "spark": ""}
        return {
            "samples": len(values),
            "latest": values[-1],
            "peak": max(values),
            "mean": sum(values) / len(values),
            "first_at": rows[0]["observed_at"],
            "last_at": rows[-1]["observed_at"],
            "collectors": sorted({str(row["collector"]) for row in rows}),
            "spark": sparkline(values, 48),
        }


def _normalize(value: Any) -> str:
    """Compare interface names without punctuation or vendor abbreviation."""
    text = re.sub(r"[^a-z0-9/]", "", str(value or "").lower())
    for long_name, short in (
        ("tengigabitethernet", "te"), ("gigabitethernet", "gi"), ("fastethernet", "fa"),
        ("twentyfivegige", "twe"), ("fortygigabitethernet", "fo"), ("hundredgige", "hu"),
        ("ethernet", "eth"), ("port-channel", "po"),
    ):
        if text.startswith(long_name):
            return short + text[len(long_name):]
    return text
