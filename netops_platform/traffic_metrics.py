"""Prometheus exposition for collected traffic readings.

Counters are published raw and monotonic. Netrune deliberately does not compute
rates here: a time-series database derives them at query time, handles counter
resets as part of that derivation, and does not need a second opinion. The
per-sample rates Netrune keeps in SQLite exist for the terminal views and the
offline report, not for this endpoint.

Cardinality is bounded by the watchlist. Nothing is published for a device that
nobody asked to monitor.
"""

from __future__ import annotations

import json
import re
import time
from typing import Any, Dict, List, Mapping, Sequence, Tuple

# Prometheus label values are quoted strings; only these three characters need
# escaping, and switch hostnames occasionally contain backslashes.
_ESCAPES = {"\\": "\\\\", '"': '\\"', "\n": "\\n"}
LABEL_SAFE_RE = re.compile(r"[\\\"\n]")

INTERFACE_COUNTERS: Tuple[Tuple[str, str, str], ...] = (
    ("in_octets", "netrune_interface_receive_bytes_total", "Bytes received on the interface since the counter last reset."),
    ("out_octets", "netrune_interface_transmit_bytes_total", "Bytes transmitted on the interface since the counter last reset."),
    ("in_errors", "netrune_interface_receive_errors_total", "Inbound packets that contained errors."),
    ("out_errors", "netrune_interface_transmit_errors_total", "Outbound packets that could not be transmitted because of errors."),
    ("in_discards", "netrune_interface_receive_drops_total", "Inbound packets discarded despite containing no errors."),
    ("out_discards", "netrune_interface_transmit_drops_total", "Outbound packets discarded despite containing no errors."),
)

INTERFACE_GAUGES: Tuple[Tuple[str, str, str], ...] = (
    ("speed_bps", "netrune_interface_speed_bits", "Interface speed in bits per second as the device reports it."),
    ("oper_up", "netrune_interface_up", "1 when ifOperStatus is up."),
    ("admin_up", "netrune_interface_admin_up", "1 when ifAdminStatus is up."),
)

#: Switch-level readings, published beside the ports they give context to.
#: A port that went quiet is read differently depending on whether the switch
#: rebooted, is out of CPU, or is simply idle, and none of that is in IF-MIB.
DEVICE_COUNTERS: Tuple[Tuple[str, str, str], ...] = (
    ("bad_community", "netrune_device_snmp_rejected_community_total",
     "SNMP requests refused because the community string was wrong. A rising count is somebody probing the management plane."),
    ("bad_community_use", "netrune_device_snmp_refused_operation_total",
     "SNMP requests refused because the community was not permitted that operation."),
    ("bad_version", "netrune_device_snmp_bad_version_total",
     "SNMP requests arriving with an unsupported protocol version."),
    ("asn_parse_errors", "netrune_device_snmp_malformed_total",
     "SNMP requests the agent could not parse."),
    ("tcp_opens_in", "netrune_device_tcp_accepted_total",
     "Inbound TCP connections the device accepted, management sessions among them."),
    ("tcp_opens_out", "netrune_device_tcp_initiated_total",
     "TCP connections the device opened itself."),
    ("tcp_attempt_fails", "netrune_device_tcp_refused_total",
     "TCP connection attempts that failed. Sustained growth alongside rejected communities is a scan."),
)

DEVICE_GAUGES: Tuple[Tuple[str, str, str], ...] = (
    ("cpu_percent", "netrune_device_cpu_percent",
     "Control-plane CPU as the device reports it. A pinned CPU delays SNMP replies and makes every other reading late."),
    ("memory_used_bytes", "netrune_device_memory_used_bytes", "Memory in use on the device."),
    ("memory_total_bytes", "netrune_device_memory_bytes", "Memory the device reports having."),
    ("temperature_celsius", "netrune_device_temperature_celsius",
     "The warmest sensor the device exposes."),
    ("tcp_established", "netrune_device_tcp_established",
     "TCP connections open right now."),
    ("logged_in_users", "netrune_device_logged_in_users",
     "Sessions the device counts as logged in. No standard MIB reports failed logins; the device's syslog is where those are recorded."),
    ("interfaces", "netrune_device_interfaces",
     "Interfaces the device has, watched or not."),
)

ICMP_GAUGES: Tuple[Tuple[str, str, str, float], ...] = (
    ("rtt_ms", "netrune_icmp_rtt_seconds", "Round-trip time from the collector to the target.", 0.001),
    ("jitter_ms", "netrune_icmp_jitter_seconds", "Round-trip time variation from the collector to the target.", 0.001),
    ("packet_loss_pct", "netrune_icmp_loss_ratio", "Fraction of probes lost, from 0 to 1.", 0.01),
    ("reachable", "netrune_icmp_up", "1 when the target answered the last probe.", 1.0),
)


#: A reading this much older than the watch's own interval is not published as
#: a counter any more. The exposition otherwise serves its last value forever,
#: so a stopped collector draws a flat line rather than an empty one -- and when
#: collection resumes, the counter jumps by everything that accumulated while
#: nobody was reading it. A rate derived across that gap attributes hours of
#: traffic to a single interval, which is how a 10 Gb port comes to report
#: hundreds of gigabits per second.
#:
#: Letting the series go absent instead makes the storage record a gap, and a
#: rate is never derived across a gap. The freshness and watch_enabled gauges
#: keep being published throughout, because those are what say a gap is a
#: stopped collector rather than an idle link.
STALE_AFTER_INTERVALS = 5
STALE_AFTER_SECONDS_MIN = 300


def stale_horizon(watch: Mapping[str, Any]) -> int:
    """How old a reading may be before its counters stop being published."""
    interval = int(watch.get("interval_seconds") or 60)
    return max(STALE_AFTER_INTERVALS * interval, STALE_AFTER_SECONDS_MIN)


def escape_label(value: Any) -> str:
    text = str(value if value is not None else "")
    return LABEL_SAFE_RE.sub(lambda match: _ESCAPES[match.group(0)], text)


def render_labels(labels: Mapping[str, Any]) -> str:
    pairs = [f'{name}="{escape_label(value)}"' for name, value in labels.items() if value not in (None, "")]
    return "{" + ",".join(pairs) + "}" if pairs else ""


def render_metric(name: str, help_text: str, kind: str, samples: Sequence[Tuple[Mapping[str, Any], float]]) -> List[str]:
    """One metric family, omitted entirely when it has no samples."""
    if not samples:
        return []
    lines = [f"# HELP {name} {help_text}", f"# TYPE {name} {kind}"]
    for labels, value in samples:
        lines.append(f"{name}{render_labels(labels)} {format_value(value)}")
    return lines


def format_value(value: Any) -> str:
    number = float(value)
    if number.is_integer() and abs(number) < 2 ** 53:
        return str(int(number))
    return repr(number)


class MetricsExporter:
    """Builds the exposition body from the latest stored readings."""

    def __init__(self, monitor: Any) -> None:
        self.monitor = monitor
        self.state = monitor.state

    def latest_readings(self) -> Dict[str, Dict[str, Dict[str, Any]]]:
        """Latest raw value per watch, counter name, and collector."""
        readings: Dict[str, Dict[str, Dict[str, Any]]] = {}
        for row in self.state.rows(
            "SELECT watch_id,counter,observed_at,value,collector FROM traffic_counters"
        ):
            readings.setdefault(str(row["watch_id"]), {}).setdefault(str(row["collector"]), {})[
                str(row["counter"])
            ] = {"value": row["value"], "observed_at": row["observed_at"]}
        return readings

    @staticmethod
    def _sample_series(con: Any) -> List[Tuple[str, str]]:
        """Every (collector, watch) pair that has stored samples.

        Walks the identity index one distinct key at a time. traffic_samples
        grows by the minute and this endpoint is scraped every few seconds, so
        a scan of it here is a cost that only ever grows -- it once outran the
        scrape interval and piled up a thread per scrape.
        """
        pairs: List[Tuple[str, str]] = []
        collectors = [row[0] for row in con.execute(
            "WITH RECURSIVE c(name) AS ("
            " SELECT MIN(collector) FROM traffic_samples"
            " UNION ALL"
            " SELECT (SELECT MIN(collector) FROM traffic_samples WHERE collector > c.name)"
            " FROM c WHERE c.name IS NOT NULL)"
            " SELECT name FROM c WHERE name IS NOT NULL")]
        for collector in collectors:
            pairs.extend((collector, row[0]) for row in con.execute(
                "WITH RECURSIVE w(id) AS ("
                " SELECT MIN(watch_id) FROM traffic_samples WHERE collector=?1"
                " UNION ALL"
                " SELECT (SELECT MIN(watch_id) FROM traffic_samples WHERE collector=?1 AND watch_id > w.id)"
                " FROM w WHERE w.id IS NOT NULL)"
                " SELECT id FROM w WHERE id IS NOT NULL", (collector,)))
        return pairs

    def latest_icmp(self) -> Dict[str, Dict[str, Dict[str, Any]]]:
        """Newest sample per watch, metric, and collector for probe results."""
        newest: Dict[str, Dict[str, Dict[str, Any]]] = {}
        with self.state.connect() as con:
            for collector, watch_id in self._sample_series(con):
                for metric in ("rtt_ms", "jitter_ms", "packet_loss_pct", "reachable"):
                    row = con.execute(
                        "SELECT value,observed_at FROM traffic_samples"
                        " WHERE collector=? AND watch_id=? AND metric=?"
                        " ORDER BY observed_at DESC LIMIT 1", (collector, watch_id, metric)).fetchone()
                    if row is not None:
                        newest.setdefault(str(watch_id), {}).setdefault(str(collector), {})[metric] = {
                            "value": row["value"], "observed_at": row["observed_at"]}
        return newest

    def latest_device_info(self) -> Dict[str, Dict[str, Any]]:
        """What each device last said it is, from the newest `device_info` sample."""
        facts: Dict[str, Dict[str, Any]] = {}
        taken_at: Dict[str, int] = {}
        with self.state.connect() as con:
            for collector, watch_id in self._sample_series(con):
                # Newest first, stopping at the first reading that parses: an
                # empty or garbled one is skipped in favour of the one before.
                for row in con.execute(
                    "SELECT raw_json,observed_at FROM traffic_samples"
                    " WHERE collector=? AND watch_id=? AND metric='device_info'"
                    " ORDER BY observed_at DESC", (collector, watch_id)):
                    if not row["raw_json"]:
                        continue
                    try:
                        payload = json.loads(str(row["raw_json"]))
                    except (TypeError, ValueError):
                        continue
                    if isinstance(payload, dict):
                        key = str(watch_id)
                        if key not in taken_at or int(row["observed_at"]) > taken_at[key]:
                            facts[key], taken_at[key] = payload, int(row["observed_at"])
                        break
        return facts

    def render_replay(self, since: int, until: int = 0) -> str:
        """Stored readings as exposition carrying their own timestamps.

        The live exposition says what is true now, and storage stamps it on
        arrival -- which is right while it is arriving. It is exactly wrong for
        filling a gap: readings taken yesterday would all land at the moment
        they were finally sent, drawn as a vertical wall rather than as the day
        they describe. Every line here carries the time the reading was
        actually taken.

        Only what a collector measured itself. A poller does not replay what it
        pulled from somewhere else, or two of them would each insist on the
        other's history.
        """
        ceiling = int(until or time.time())
        watches = {str(row["watch_id"]): row
                   for row in self.monitor.list_watches(owned_only=True)}
        by_name: Dict[str, List[str]] = {}
        # Each table is (stored name, metric name, help), so the first two.
        counters = {key: metric for key, metric, _ in INTERFACE_COUNTERS + DEVICE_COUNTERS}
        gauges = {key: metric for key, metric, _ in INTERFACE_GAUGES + DEVICE_GAUGES}
        gauges["uptime"] = "netrune_device_uptime_seconds"
        device_keys = {key for key, _, _ in DEVICE_COUNTERS + DEVICE_GAUGES} | {"uptime"}

        for row in self.state.rows(
            "SELECT watch_id,counter,observed_at,value,collector FROM traffic_counter_log"
            " WHERE observed_at > ? AND observed_at <= ? ORDER BY observed_at ASC",
            (int(since), ceiling),
        ):
            watch = watches.get(str(row["watch_id"]))
            if not watch or row["value"] is None:
                continue
            name = str(row["counter"])
            metric = counters.get(name) or gauges.get(name)
            if not metric:
                continue
            if watch.get("kind") == "device" or name in device_keys:
                labels = {"device": str(watch.get("device_name") or watch.get("device_ip") or ""),
                          "device_ip": str(watch.get("device_ip") or ""),
                          "collector": str(row["collector"])}
            else:
                labels = self.interface_labels(watch, str(row["collector"]))
            by_name.setdefault(metric, []).append(
                f"{metric}{render_labels(labels)} {format_value(row['value'])}"
                f" {int(row['observed_at']) * 1000}")

        blocks: List[str] = []
        for metric, lines in sorted(by_name.items()):
            kind = "counter" if metric in set(counters.values()) else "gauge"
            blocks.append(f"# TYPE {metric} {kind}")
            blocks.extend(lines)
        return ("\n".join(blocks) + "\n") if blocks else ""

    def render(self) -> str:
        # Only what this collector is responsible for. Readings pulled from a
        # remote poller are that poller's to publish: republishing its counters
        # under this host's scrape would hold them still between pulls, and a
        # held counter reads as zero traffic rather than as no data.
        watches = {str(row["watch_id"]): row
                   for row in self.monitor.list_watches(owned_only=True)}
        readings = self.latest_readings()
        probes = self.latest_icmp()
        blocks: List[str] = []

        collectors = {
            collector
            for per_watch in list(readings.values()) + list(probes.values())
            for collector in per_watch
        } or {self.monitor.collector_id()}
        blocks.extend(render_metric(
            "netrune_collector_info", "Collectors that have written readings to this store.", "gauge",
            [({"collector": name}, 1) for name in sorted(collectors)],
        ))

        # ---- interfaces ----------------------------------------------------
        interface_watches = [w for w in watches.values() if w.get("kind") == "interface"]
        counter_samples: Dict[str, List[Tuple[Dict[str, Any], float]]] = {}
        gauge_samples: Dict[str, List[Tuple[Dict[str, Any], float]]] = {}
        freshness: List[Tuple[Dict[str, Any], float]] = []
        # The chosen name rides a metric of its own rather than a label on the
        # counters. A label would make the name part of the series' identity,
        # so naming a port that has been collected for weeks would start a new
        # series and strand its history under the old one -- a steep price for
        # something that exists to make a legend readable.
        identity_samples: List[Tuple[Dict[str, Any], float]] = []
        subscribed: List[Tuple[Dict[str, Any], float]] = []
        uptimes: List[Tuple[Dict[str, Any], float]] = []
        enabled: List[Tuple[Dict[str, Any], float]] = []

        now = time.time()
        for watch in interface_watches:
            watch_id = str(watch["watch_id"])
            horizon = stale_horizon(watch)
            for collector, values in sorted(readings.get(watch_id, {}).items()):
                labels = self.interface_labels(watch, collector)
                enabled.append((dict(labels), 1 if watch.get("enabled") else 0))
                observed = max((r["observed_at"] for r in values.values() if r.get("observed_at")),
                               default=0)
                if observed:
                    freshness.append((dict(labels), float(observed)))
                plan = self.monitor.subscription(watch)
                chosen_name = self.monitor.display_name(watch)
                identity_samples.append((
                    {**labels,
                     "name": chosen_name,
                     # One label naming the link outright. A table needs a
                     # single column to join its queries on, and device plus
                     # port is two -- which is how a four-column table ends up
                     # as four one-column rows.
                     "link": f"{labels['device']} {chosen_name}".strip(),
                     # Which counter carries download on this port. A dashboard
                     # that guessed would show a full upload as a quiet
                     # download on any port facing the LAN.
                     "downlink": plan.get("downlink", "receive"),
                     "service": "yes" if plan else ""},
                    1.0))
                # The rate the link is sold at, labelled the way a contract
                # states it rather than by which counter measures it. A gigabit
                # port carrying a 100M service reads 10% against its line rate
                # at the moment the service is full, which is the opposite of
                # useful; the `downlink` label above is what lets a dashboard
                # find the counter that carries each direction.
                for direction, rate in (("down", plan.get("down_bps")),
                                        ("up", plan.get("up_bps"))):
                    if rate:
                        subscribed.append(({**labels, "direction": direction}, float(rate)))
                if observed and now - observed > horizon:
                    # Stale. The freshness gauge above still says so; the
                    # counters go absent so no rate is derived across the gap.
                    # The name keeps being published: a gap on a chart should
                    # still say which port it belongs to.
                    continue
                if not watch.get("enabled"):
                    # A paused watch keeps its last counter forever. Publishing
                    # it would hold the value still, and a still counter has a
                    # rate of zero -- which reads as a quiet port rather than as
                    # a port nobody is measuring. Letting the series go stale
                    # draws the gap that actually happened. The enabled gauge
                    # above still says the pause was deliberate.
                    continue
                for key, metric, _ in INTERFACE_COUNTERS:
                    reading = values.get(key)
                    if reading is not None and reading["value"] is not None:
                        counter_samples.setdefault(metric, []).append((dict(labels), float(reading["value"])))
                for key, metric, _ in INTERFACE_GAUGES:
                    reading = values.get(key)
                    if reading is not None and reading["value"] is not None:
                        gauge_samples.setdefault(metric, []).append((dict(labels), float(reading["value"])))
                uptime = values.get("uptime")
                if uptime is not None and uptime["value"] is not None:
                    uptimes.append((
                        {"device": labels["device"], "device_ip": labels["device_ip"], "collector": collector},
                        float(uptime["value"]),
                    ))

        for _, metric, help_text in INTERFACE_COUNTERS:
            blocks.extend(render_metric(metric, help_text, "counter", counter_samples.get(metric, [])))
        for _, metric, help_text in INTERFACE_GAUGES:
            blocks.extend(render_metric(metric, help_text, "gauge", gauge_samples.get(metric, [])))
        blocks.extend(render_metric(
            "netrune_interface_subscribed_bits",
            "Bits per second this link is sold at. A soft limit: nothing enforces it.",
            "gauge", subscribed))
        blocks.extend(render_metric(
            "netrune_interface_info",
            "Always 1. Carries the name a person gave this port, for dashboards to join against.",
            "gauge", identity_samples))
        blocks.extend(render_metric(
            "netrune_interface_last_poll_timestamp_seconds",
            "When the collector last read this interface. Alert on this to notice a stopped collector.",
            "gauge", freshness))
        blocks.extend(render_metric(
            "netrune_interface_watch_enabled",
            "1 when this interface is being collected, 0 when it is paused.", "gauge", enabled))
        # ---- switch health --------------------------------------------------
        # These come from a watch of their own, derived from the interface
        # watchlist. The interface poll happens to see sysUpTime as a side
        # effect and it is kept, but a switch whose health watch is answering
        # is the better source and is appended last so it wins the collapse.
        device_counters: Dict[str, List[Tuple[Dict[str, Any], float]]] = {}
        device_gauges: Dict[str, List[Tuple[Dict[str, Any], float]]] = {}
        device_freshness: List[Tuple[Dict[str, Any], float]] = []
        device_info: List[Tuple[Dict[str, Any], float]] = []
        identity = self.latest_device_info()

        for watch in watches.values():
            if watch.get("kind") != "device" or not watch.get("enabled"):
                continue
            watch_id = str(watch["watch_id"])
            horizon = stale_horizon(watch)
            for collector, values in sorted(readings.get(watch_id, {}).items()):
                labels = {
                    "device": str(watch.get("device_name") or watch.get("device_ip") or ""),
                    "device_ip": str(watch.get("device_ip") or ""),
                    "collector": collector,
                }
                observed = max((r["observed_at"] for r in values.values() if r.get("observed_at")),
                               default=0)
                if observed:
                    device_freshness.append((dict(labels), float(observed)))
                if observed and now - observed > horizon:
                    continue
                for key, metric, _ in DEVICE_COUNTERS:
                    reading = values.get(key)
                    if reading is not None and reading["value"] is not None:
                        device_counters.setdefault(metric, []).append(
                            (dict(labels), float(reading["value"])))
                for key, metric, _ in DEVICE_GAUGES:
                    reading = values.get(key)
                    if reading is not None and reading["value"] is not None:
                        device_gauges.setdefault(metric, []).append(
                            (dict(labels), float(reading["value"])))
                uptime = values.get("uptime")
                if uptime is not None and uptime["value"] is not None:
                    uptimes.append((dict(labels), float(uptime["value"])))
                facts = identity.get(watch_id) or {}
                if facts:
                    # sysDescr is a paragraph and would dominate every label
                    # set it appears in, so only the short identifying fields
                    # become labels.
                    device_info.append(({**labels,
                                         "name": str(facts.get("sysName") or ""),
                                         "location": str(facts.get("sysLocation") or ""),
                                         "contact": str(facts.get("sysContact") or "")}, 1.0))

        blocks.extend(render_metric(
            "netrune_device_uptime_seconds",
            "Device sysUpTime. A decrease means the device restarted and its counters did too.",
            "gauge", _deduplicate(uptimes)))
        for _, metric, help_text in DEVICE_COUNTERS:
            blocks.extend(render_metric(metric, help_text, "counter",
                                        _deduplicate(device_counters.get(metric, []))))
        for _, metric, help_text in DEVICE_GAUGES:
            blocks.extend(render_metric(metric, help_text, "gauge",
                                        _deduplicate(device_gauges.get(metric, []))))
        blocks.extend(render_metric(
            "netrune_device_last_poll_timestamp_seconds",
            "When the collector last read this device's health.", "gauge",
            _deduplicate(device_freshness)))
        blocks.extend(render_metric(
            "netrune_device_info",
            "Always 1. The labels carry what the device says it is.", "gauge",
            _deduplicate(device_info)))

        # ---- reachability --------------------------------------------------
        icmp_samples: Dict[str, List[Tuple[Dict[str, Any], float]]] = {}
        icmp_freshness: List[Tuple[Dict[str, Any], float]] = []
        for watch in watches.values():
            if watch.get("kind") != "icmp":
                continue
            watch_id = str(watch["watch_id"])
            horizon = stale_horizon(watch)
            for collector, metrics in sorted(probes.get(watch_id, {}).items()):
                labels = {
                    "target": str(watch.get("target") or ""),
                    "label": str(watch.get("label") or ""),
                    "collector": collector,
                }
                observed = max((r["observed_at"] for r in metrics.values() if r.get("observed_at")),
                               default=0)
                if observed:
                    icmp_freshness.append((dict(labels), float(observed)))
                if observed and now - observed > horizon:
                    # A held reachability reading is worse than a missing one:
                    # it reports a target as up long after anyone last checked.
                    continue
                for key, metric, _, scale in ICMP_GAUGES:
                    reading = metrics.get(key)
                    if reading is not None and reading["value"] is not None:
                        icmp_samples.setdefault(metric, []).append(
                            (dict(labels), float(reading["value"]) * scale))
        for _, metric, help_text, _ in ICMP_GAUGES:
            blocks.extend(render_metric(metric, help_text, "gauge", icmp_samples.get(metric, [])))
        blocks.extend(render_metric(
            "netrune_icmp_last_poll_timestamp_seconds",
            "When the collector last probed this target.", "gauge", icmp_freshness))

        blocks.extend(render_metric(
            "netrune_exposition_build_timestamp_seconds",
            "When this exposition was rendered.", "gauge", [({}, float(int(time.time())))]))
        return "\n".join(blocks) + "\n"

    def interface_labels(self, watch: Mapping[str, Any], collector: str) -> Dict[str, Any]:
        return {
            "device": str(watch.get("device_name") or watch.get("device_ip") or ""),
            "device_ip": str(watch.get("device_ip") or ""),
            "interface": str(watch.get("interface_name") or ""),
            "ifindex": str(watch.get("ifindex") or ""),
            "collector": collector,
        }


def _deduplicate(samples: Sequence[Tuple[Dict[str, Any], float]]) -> List[Tuple[Dict[str, Any], float]]:
    """Collapse repeated label sets, which device-level metrics produce per port."""
    seen: Dict[str, Tuple[Dict[str, Any], float]] = {}
    for labels, value in samples:
        seen[render_labels(labels)] = (labels, value)
    return list(seen.values())
