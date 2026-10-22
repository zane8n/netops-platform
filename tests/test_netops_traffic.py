import contextlib
import io
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
import sys

sys.path.insert(0, str(ROOT))

from netops_platform import core as netops
from netops_platform.traffic_report import render_report
from netops_platform import traffic
from netops_platform.traffic import (
    COUNTER_WIDTH_32,
    COUNTER_WIDTH_64,
    counter_delta,
    humanize_bps,
    parse_interface_counters,
    parse_interface_index,
    parse_timeticks,
    sparkline,
)

# Counter and uptime values captured verbatim from a Catalyst 9300, so the
# parsers are pinned to bytes a real switch produced rather than to bytes
# convenient for a test. Identifiers are replaced with documentation values.
LIVE_INDEX = """24|Gi1/0/16|
33|Gi1/1/1|SITE-A-CORE-01 Port Te1/1/4
9|Gi1/0/1|IT OFFICE AP
"""

LIVE_COUNTERS_FIRST = """sysUpTime|58:23:41:13.32
24|383297273186|3421470058072|1000000000|up|Gi1/0/16
33|251619808279714|91703180805335|1000000000|up|Gi1/1/1
"""

LIVE_COUNTERS_SECOND = """sysUpTime|58:23:42:12.40
24|383297275191|3421478034291|1000000000|up|Gi1/0/16
33|251620231594989|91703306526448|1000000000|up|Gi1/1/1
"""


class TrafficParsingTest(unittest.TestCase):
    def test_interface_index_parses_names_and_aliases(self):
        rows = parse_interface_index(LIVE_INDEX)
        self.assertEqual([row["ifindex"] for row in rows], ["24", "33", "9"])
        self.assertEqual(rows[1]["alias"], "SITE-A-CORE-01 Port Te1/1/4")
        self.assertEqual(rows[0]["alias"], "")

    def test_counters_carry_name_speed_and_status(self):
        reading = parse_interface_counters(LIVE_COUNTERS_FIRST)
        self.assertEqual(reading["uptime_seconds"], 5096473)
        port = reading["interfaces"]["24"]
        self.assertEqual(port["in_octets"], 383297273186)
        self.assertEqual(port["speed_bps"], 1000000000)
        self.assertEqual(port["oper_status"], "up")
        self.assertEqual(port["name"], "Gi1/0/16")

    def test_counters_tolerate_a_helper_without_the_name_field(self):
        reading = parse_interface_counters("sysUpTime|1000\n24|10|20|1000000000|up\n")
        self.assertEqual(reading["interfaces"]["24"]["name"], "")
        self.assertEqual(reading["interfaces"]["24"]["out_octets"], 20)

    def test_timeticks_accepts_both_raw_ticks_and_formatted_uptime(self):
        self.assertEqual(parse_timeticks("58:23:41:13.32"), 5096473)
        self.assertEqual(parse_timeticks("509647300"), 5096473)
        self.assertEqual(parse_timeticks(""), 0)

    def test_counter_delta_recovers_wrap_but_refuses_a_reset(self):
        self.assertEqual(counter_delta(100, 250), 150)
        self.assertEqual(counter_delta(COUNTER_WIDTH_64 - 50, 100, COUNTER_WIDTH_64), 150)
        self.assertEqual(counter_delta(COUNTER_WIDTH_32 - 50, 100, COUNTER_WIDTH_32), 150)
        # A counter that fell from a modest value has been reset, and inventing
        # the wrap distance there would draw a spike that never happened.
        self.assertIsNone(counter_delta(1_000_000, 10, COUNTER_WIDTH_64))

    def test_sparkline_renders_gaps_as_gaps(self):
        rendered = sparkline([1, None, 9])
        self.assertEqual(len(rendered), 3)
        self.assertEqual(rendered[1], " ")
        self.assertNotEqual(rendered[0], rendered[2])

    def test_sparkline_of_a_flat_series_does_not_invent_variation(self):
        self.assertEqual(len(set(sparkline([5, 5, 5, 5]))), 1)

    def test_humanize_bps_scales_and_keeps_zero_readable(self):
        self.assertEqual(humanize_bps(0), "0 bps")
        self.assertEqual(humanize_bps(118), "118 bps")
        self.assertTrue(humanize_bps(718840).endswith("kbps"))
        self.assertTrue(humanize_bps(5866936).endswith("Mbps"))


class TrafficMonitorTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        base = Path(self.temp.name)
        self.env = mock.patch.dict(
            os.environ,
            {
                "NETOPS_CONFIG_DIR": str(base / "config"),
                "NETOPS_CACHE_DIR": str(base / "cache"),
                "NETOPS_SQLITE_DB": str(base / "cache" / "netops.sqlite3"),
                "NETOPS_BACKUP_DIR": str(base / "backups"),
                "NETOPS_PROGRESS": "0",
            },
            clear=False,
        )
        self.env.start()
        self.app = netops.App(ROOT)
        self.monitor = self.app.traffic
        self.base = int(time.time()) - 300

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def add_device(self, ip="198.51.100.10", name="TEST-SW01"):
        self.app.state.execute(
            "INSERT INTO devices(ip,hostname,platform,model,serial,mac,source,last_seen,status)"
            " VALUES(?,?,?,?,?,?,?,?,?)",
            (ip, name, "Cisco", "C9300", "SERIAL-1", "", "test", 1000, "ONLINE"),
        )

    def watch_interface(self, ifindex="24", name="Gi1/0/16"):
        return self.monitor.add_watch(
            "interface", device_ip="198.51.100.10", device_name="TEST-SW01",
            interface_name=name, interval_seconds=30, ifindex=ifindex,
        )

    # ---- watchlist ---------------------------------------------------------

    def test_only_named_targets_are_collected(self):
        self.assertEqual(self.monitor.list_watches(), [])
        payload = self.monitor.poll()
        self.assertEqual(payload["watches"], 0)
        self.assertEqual(payload["samples_recorded"], 0)

    def test_adding_the_same_interface_twice_reuses_one_watch(self):
        first = self.watch_interface()
        second = self.watch_interface()
        self.assertEqual(first["watch_id"], second["watch_id"])
        self.assertEqual(len(self.monitor.list_watches()), 1)

    def test_an_interface_watch_needs_a_device_and_an_interface(self):
        with self.assertRaises(ValueError):
            self.monitor.add_watch("interface", device_ip="198.51.100.10")
        with self.assertRaises(ValueError):
            self.monitor.add_watch("nonsense", target="198.51.100.10")

    def test_removing_a_watch_discards_its_samples(self):
        watch = self.watch_interface()
        self.monitor._write_sample(watch["watch_id"], int(time.time()), "in_bps", 5.0, "bps", "up", "local", {})
        self.assertTrue(self.monitor.remove_watch(watch["watch_id"]))
        self.assertEqual(self.monitor.series(watch["watch_id"], "in_bps", 86400), [])
        self.assertFalse(self.monitor.remove_watch(watch["watch_id"]))

    # ---- collection --------------------------------------------------------

    def poll_with(self, output, observed_at):
        with mock.patch.object(self.app, "capture", return_value=(0, output, "")), \
                mock.patch("netops_platform.traffic.time.time", return_value=observed_at):
            return self.monitor.poll()

    def test_the_first_round_only_establishes_a_baseline(self):
        self.watch_interface()
        payload = self.poll_with(LIVE_COUNTERS_FIRST, self.base)
        self.assertEqual(self.monitor.series(self.monitor.list_watches()[0]["watch_id"], "in_bps", 86400), [])
        self.assertTrue(payload["ok"])

    def test_a_second_round_produces_a_rate_from_the_counter_delta(self):
        watch = self.watch_interface()
        self.poll_with(LIVE_COUNTERS_FIRST, self.base)
        self.poll_with(LIVE_COUNTERS_SECOND, self.base + 59)
        # 383297275191 - 383297273186 = 2005 octets over 59 seconds.
        rate = self.monitor.summarize(watch["watch_id"], "in_bps", 86400)
        self.assertEqual(rate["samples"], 1)
        self.assertAlmostEqual(rate["latest"], 2005 * 8 / 59, places=3)
        out = self.monitor.summarize(watch["watch_id"], "out_bps", 86400)
        self.assertAlmostEqual(out["latest"], (3421478034291 - 3421470058072) * 8 / 59, places=3)

    def test_utilization_is_recorded_against_the_reported_link_speed(self):
        watch = self.watch_interface(ifindex="33", name="Gi1/1/1")
        self.poll_with(LIVE_COUNTERS_FIRST, self.base)
        self.poll_with(LIVE_COUNTERS_SECOND, self.base + 59)
        util = self.monitor.summarize(watch["watch_id"], "in_utilization_pct", 86400)
        rate = self.monitor.summarize(watch["watch_id"], "in_bps", 86400)
        self.assertAlmostEqual(util["latest"], rate["latest"] / 1_000_000_000 * 100, places=6)

    def test_a_device_restart_discards_the_interval_rather_than_inventing_a_spike(self):
        watch = self.watch_interface()
        self.poll_with(LIVE_COUNTERS_SECOND, self.base)
        rebooted = "sysUpTime|0:00:01:00.00\n24|500|900|1000000000|up|Gi1/0/16\n"
        self.poll_with(rebooted, self.base + 60)
        self.assertEqual(self.monitor.summarize(watch["watch_id"], "in_bps", 86400)["samples"], 0)

    def test_a_reassigned_ifindex_is_re_resolved_instead_of_graphed_as_the_same_port(self):
        watch = self.watch_interface()
        moved = "sysUpTime|58:23:42:12.40\n24|1|2|1000000000|up|Gi1/0/44\n"
        index_output = "24|Gi1/0/44|\n41|Gi1/0/16|\n"
        counters_at_41 = "sysUpTime|58:23:42:12.40\n41|777|888|1000000000|up|Gi1/0/16\n"
        replies = [(0, moved, ""), (0, index_output, ""), (0, counters_at_41, "")]
        with mock.patch.object(self.app, "capture", side_effect=replies), \
                mock.patch("netops_platform.traffic.time.time", return_value=self.base):
            self.monitor.poll()
        refreshed = self.monitor.get_watch(watch["watch_id"])
        self.assertEqual(refreshed["ifindex"], "41")
        stored = self.app.state.rows(
            "SELECT value FROM traffic_counters WHERE watch_id=? AND counter='in_octets'", (watch["watch_id"],))
        self.assertEqual(int(stored[0]["value"]), 777)

    def test_a_watch_reuses_its_stored_ifindex_instead_of_walking_every_round(self):
        self.watch_interface()
        with mock.patch.object(self.app, "capture", return_value=(0, LIVE_COUNTERS_FIRST, "")) as capture:
            self.monitor.poll()
        self.assertEqual(capture.call_count, 1)
        self.assertIn("snmp-counters", capture.call_args[0][0])

    def test_one_snmp_call_serves_every_watch_on_the_same_device(self):
        self.watch_interface("24", "Gi1/0/16")
        self.watch_interface("33", "Gi1/1/1")
        with mock.patch.object(self.app, "capture", return_value=(0, LIVE_COUNTERS_FIRST, "")) as capture:
            self.monitor.poll()
        self.assertEqual(capture.call_count, 1)
        self.assertIn("24,33", capture.call_args[0][0])

    def test_icmp_watches_record_latency_and_loss(self):
        watch = self.monitor.add_watch("icmp", target="198.51.100.10", label="core")
        probe = {"ok": True, "unreachable": False, "packet_loss_pct": 0.0,
                 "avg_ms": 2.5, "min_ms": 2.0, "max_ms": 3.2, "jitter_ms": 0.4}
        with mock.patch.object(self.app, "icmp_probe", return_value=probe), \
                mock.patch("netops_platform.traffic.time.time", return_value=self.base):
            self.monitor.poll()
        self.assertEqual(self.monitor.summarize(watch["watch_id"], "rtt_ms", 86400)["latest"], 2.5)
        self.assertEqual(self.monitor.summarize(watch["watch_id"], "packet_loss_pct", 86400)["latest"], 0.0)

    def test_an_unreachable_target_records_the_loss_rather_than_nothing(self):
        watch = self.monitor.add_watch("icmp", target="198.51.100.99")
        probe = {"ok": False, "unreachable": True, "packet_loss_pct": 100.0, "avg_ms": None}
        with mock.patch.object(self.app, "icmp_probe", return_value=probe), \
                mock.patch("netops_platform.traffic.time.time", return_value=self.base):
            self.monitor.poll()
        self.assertEqual(self.monitor.summarize(watch["watch_id"], "packet_loss_pct", 86400)["latest"], 100.0)
        self.assertEqual(self.monitor.summarize(watch["watch_id"], "reachable", 86400)["latest"], 0.0)

    def test_one_unreachable_device_does_not_stop_the_others(self):
        self.watch_interface()
        self.monitor.add_watch("icmp", target="198.51.100.99")
        probe = {"ok": True, "unreachable": False, "packet_loss_pct": 0.0, "avg_ms": 1.0}
        with mock.patch.object(self.app, "capture", side_effect=RuntimeError("snmp timeout")), \
                mock.patch.object(self.app, "icmp_probe", return_value=probe):
            payload = self.monitor.poll()
        self.assertTrue(payload["errors"])
        self.assertGreater(payload["samples_recorded"], 0)
        self.assertTrue(payload["ok"])

    def test_probes_in_one_round_do_not_wait_on_each_other(self):
        """A round must not take the sum of its probes.

        A ping is about three seconds of waiting. Run in turn, a dozen targets
        would outlast the interval they were asked to keep, and the collector
        would silently stop honouring the cadence the operator set.
        """
        for index in range(8):
            self.monitor.add_watch("icmp", target=f"198.51.100.{index + 30}")

        def slow_probe(target, opts=None, count=3):
            time.sleep(0.25)
            return {"ok": True, "unreachable": False, "packet_loss_pct": 0.0, "avg_ms": 1.0}

        with mock.patch.object(self.app, "icmp_probe", side_effect=slow_probe):
            started = time.monotonic()
            payload = self.monitor.poll()
            elapsed = time.monotonic() - started

        self.assertEqual(payload["errors"], [])
        self.assertGreater(payload["samples_recorded"], 0)
        # Eight probes at a quarter second each is two seconds in sequence.
        self.assertLess(elapsed, 1.2, f"probes appear to be running in sequence ({elapsed:.2f}s)")

    def test_a_failing_probe_does_not_take_the_round_down_with_it(self):
        self.watch_interface()
        for index in range(3):
            self.monitor.add_watch("icmp", target=f"198.51.100.{index + 40}")

        def flaky(target, opts=None, count=3):
            if target.endswith(".41"):
                raise RuntimeError("network unreachable")
            return {"ok": True, "unreachable": False, "packet_loss_pct": 0.0, "avg_ms": 1.0}

        with mock.patch.object(self.app, "capture", return_value=(0, LIVE_COUNTERS_FIRST, "")), \
                mock.patch.object(self.app, "icmp_probe", side_effect=flaky):
            payload = self.monitor.poll()
        self.assertEqual(len(payload["errors"]), 1)
        self.assertIn("198.51.100.41", str(payload["errors"]))
        self.assertGreater(payload["samples_recorded"], 0)

    # ---- scheduling --------------------------------------------------------

    def test_every_watch_is_due_on_the_first_pass(self):
        self.watch_interface("24", "Gi1/0/16")
        self.monitor.add_watch("icmp", target="198.51.100.10")
        attempts = {}
        self.assertEqual(len(self.monitor.due_watches(attempts, now=1000.0)), 2)

    def test_a_watch_is_not_due_again_until_its_own_interval_has_passed(self):
        self.watch_interface("24", "Gi1/0/16")  # 30s
        self.monitor.add_watch("icmp", target="198.51.100.10", interval_seconds=120)
        attempts = {}
        self.monitor.due_watches(attempts, now=1000.0)
        self.assertEqual(self.monitor.due_watches(attempts, now=1010.0), [])
        due = self.monitor.due_watches(attempts, now=1035.0)
        self.assertEqual([w["kind"] for w in due], ["interface"])
        self.assertEqual(len(self.monitor.due_watches(attempts, now=1121.0)), 2)

    def test_an_interval_override_applies_to_every_watch(self):
        self.watch_interface("24", "Gi1/0/16")
        self.monitor.add_watch("icmp", target="198.51.100.10", interval_seconds=3600)
        attempts = {}
        self.monitor.due_watches(attempts, now=1000.0, override_interval=10)
        self.assertEqual(len(self.monitor.due_watches(attempts, now=1011.0, override_interval=10)), 2)

    def test_a_disabled_watch_is_never_due_and_a_removed_one_is_forgotten(self):
        watch = self.watch_interface()
        attempts = {}
        self.monitor.due_watches(attempts, now=1000.0)
        self.monitor.set_enabled(watch["watch_id"], False)
        self.assertEqual(self.monitor.due_watches(attempts, now=2000.0), [])
        self.monitor.remove_watch(watch["watch_id"])
        self.monitor.due_watches(attempts, now=3000.0)
        self.assertEqual(attempts, {})

    # ---- collector identity ------------------------------------------------

    def test_samples_are_attributed_to_the_collector_that_took_them(self):
        watch = self.watch_interface()
        self.app.config.public["traffic_collector_id"] = "cloud-poller-1"
        self.poll_with(LIVE_COUNTERS_FIRST, self.base)
        self.poll_with(LIVE_COUNTERS_SECOND, self.base + 59)
        rows = self.app.state.rows(
            "SELECT DISTINCT collector FROM traffic_samples WHERE watch_id=?", (watch["watch_id"],))
        self.assertEqual([row["collector"] for row in rows], ["cloud-poller-1"])
        self.assertEqual(self.monitor.summarize(watch["watch_id"], "in_bps", 86400, )["samples"], 1)

    def test_a_second_collector_keeps_its_own_counter_baseline(self):
        watch = self.watch_interface()
        self.app.config.public["traffic_collector_id"] = "laptop"
        self.poll_with(LIVE_COUNTERS_FIRST, self.base)
        self.app.config.public["traffic_collector_id"] = "cloud-poller-1"
        # The cloud poller has never read this interface, so its first round is
        # a baseline too rather than a delta against the laptop's reading.
        self.poll_with(LIVE_COUNTERS_SECOND, self.base + 59)
        self.assertEqual(self.monitor.summarize(watch["watch_id"], "in_bps", 86400)["samples"], 0)
        baselines = self.app.state.rows(
            "SELECT collector FROM traffic_counters WHERE watch_id=? AND counter='in_octets' ORDER BY collector",
            (watch["watch_id"],))
        self.assertEqual([row["collector"] for row in baselines], ["cloud-poller-1", "laptop"])


class TrafficCommandTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        base = Path(self.temp.name)
        self.env = mock.patch.dict(
            os.environ,
            {
                "NETOPS_CONFIG_DIR": str(base / "config"),
                "NETOPS_CACHE_DIR": str(base / "cache"),
                "NETOPS_SQLITE_DB": str(base / "cache" / "netops.sqlite3"),
                "NETOPS_BACKUP_DIR": str(base / "backups"),
                "NETOPS_PROGRESS": "0",
            },
            clear=False,
        )
        self.env.start()
        self.app = netops.App(ROOT)
        self.app.state.execute(
            "INSERT INTO devices(ip,hostname,platform,model,serial,mac,source,last_seen,status)"
            " VALUES(?,?,?,?,?,?,?,?,?)",
            ("198.51.100.10", "TEST-SW01", "Cisco", "C9300", "SERIAL-1", "", "test", 1000, "ONLINE"),
        )

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def dispatch(self, args, capture_output=""):
        buffer = io.StringIO()
        with mock.patch.object(self.app, "capture", return_value=(0, capture_output, "")), \
                contextlib.redirect_stdout(buffer), contextlib.redirect_stderr(io.StringIO()):
            code = self.app.dispatch([*args, "--plain", "--no-color"])
        return code, buffer.getvalue()

    def test_watching_an_interface_the_device_does_not_have_is_refused(self):
        code, _ = self.dispatch(["traffic", "watch", "TEST-SW01", "Gi9/9/9"], "24|Gi1/0/16|\n")
        self.assertEqual(code, netops.VALIDATION)
        self.assertEqual(self.app.traffic.list_watches(), [])

    def test_watching_an_interface_stores_the_resolved_index(self):
        code, _ = self.dispatch(["traffic", "watch", "TEST-SW01", "Gi1/0/16"], "24|Gi1/0/16|uplink\n")
        self.assertEqual(code, netops.SUCCESS)
        watch = next(w for w in self.app.traffic.list_watches() if w["kind"] == "interface")
        self.assertEqual(watch["ifindex"], "24")
        self.assertEqual(watch["interface_name"], "Gi1/0/16")

    def test_an_interface_name_is_matched_the_way_an_operator_types_it(self):
        code, _ = self.dispatch(["traffic", "watch", "TEST-SW01", "gi 1/0/16"], "24|Gi1/0/16|\n")
        self.assertEqual(code, netops.SUCCESS)
        interfaces = [w for w in self.app.traffic.list_watches() if w["kind"] == "interface"]
        self.assertEqual(interfaces[0]["interface_name"], "Gi1/0/16")

    def test_an_ambiguous_device_is_refused_before_any_snmp_call(self):
        self.app.state.execute(
            "INSERT INTO devices(ip,hostname,platform,model,serial,mac,source,last_seen,status)"
            " VALUES(?,?,?,?,?,?,?,?,?)",
            ("198.51.100.11", "TEST-SW02", "Cisco", "C9300", "SERIAL-2", "", "test", 1000, "ONLINE"),
        )
        code, _ = self.dispatch(["traffic", "watch", "TEST-SW", "Gi1/0/16"])
        self.assertEqual(code, netops.VALIDATION)

    def test_a_dry_run_never_touches_the_network_or_the_watchlist(self):
        buffer = io.StringIO()
        with mock.patch.object(self.app, "capture", side_effect=AssertionError("dry run must not poll")), \
                contextlib.redirect_stdout(buffer), contextlib.redirect_stderr(io.StringIO()):
            code = self.app.dispatch(["traffic", "watch", "TEST-SW01", "Gi1/0/16", "--dry-run", "--plain"])
        self.assertEqual(code, netops.SUCCESS)
        self.assertEqual(self.app.traffic.list_watches(), [])

    def test_list_reports_nothing_monitored_as_a_partial_result(self):
        code, output = self.dispatch(["traffic", "list"])
        self.assertEqual(code, netops.PARTIAL)
        self.assertIn("No targets are being monitored", output)

    def test_show_renders_a_sparkline_for_a_collected_series(self):
        watch = self.app.traffic.add_watch(
            "interface", device_ip="198.51.100.10", device_name="TEST-SW01",
            interface_name="Gi1/0/16", ifindex="24")
        base = int(time.time()) - 120
        for offset, value in enumerate((1000.0, 5000.0, 20000.0)):
            self.app.traffic._write_sample(
                watch["watch_id"], base + offset * 30, "out_bps", value, "bps", "up", "local", {})
        code, output = self.dispatch(["traffic", "show", "--since", "3600"])
        self.assertEqual(code, netops.SUCCESS)
        self.assertIn("Gi1/0/16", output)
        self.assertIn("out_bps", output)
        self.assertIn("20.00 kbps", output)

    def test_show_filters_to_the_named_target(self):
        for name, index in (("Gi1/0/16", "24"), ("Gi1/1/1", "33")):
            self.app.traffic.add_watch(
                "interface", device_ip="198.51.100.10", device_name="TEST-SW01",
                interface_name=name, ifindex=index)
        code, output = self.dispatch(["traffic", "show", "Gi1/1/1"])
        self.assertEqual(code, netops.SUCCESS)
        self.assertIn("Gi1/1/1", output)
        self.assertNotIn("Gi1/0/16", output)

    def test_an_unknown_verb_is_reported_rather_than_silently_ignored(self):
        code, _ = self.dispatch(["traffic", "sparkle"])
        self.assertNotEqual(code, netops.SUCCESS)


class TrafficReportTest(unittest.TestCase):
    """The HTML report must render without script and read correctly in both themes."""

    def setUp(self):
        self.now = int(time.time())
        self.watch = {"watch_id": "wch-1", "kind": "interface", "device_ip": "198.51.100.10",
                      "device_name": "TEST-SW01", "interface_name": "Gi1/0/16", "ifindex": "24",
                      "target": "", "label": "Gi1/0/16"}

    def series(self, metric, values, step=60):
        return [{"observed_at": self.now - (len(values) - i) * step, "value": v, "collector": "laptop"}
                for i, v in enumerate(values)]

    def payload(self, cards, window=3600):
        return {"window_seconds": window, "generated_at": self.now, "collector": "laptop", "cards": cards}

    def interface_card(self, in_values, out_values, speed=1_000_000_000, util_peak=None):
        readings = {
            "in_bps": {"samples": len(in_values), "latest": in_values[-1], "peak": max(in_values),
                       "collectors": ["laptop"]},
            "out_bps": {"samples": len(out_values), "latest": out_values[-1], "peak": max(out_values),
                        "collectors": ["laptop"]},
            "in_utilization_pct": {"samples": len(in_values), "latest": 1.0,
                                   "peak": util_peak if util_peak is not None else 1.0, "collectors": ["laptop"]},
            "out_utilization_pct": {"samples": len(out_values), "latest": 0.5, "peak": 0.5, "collectors": ["laptop"]},
        }
        return {"watch": self.watch, "readings": readings, "speed_bps": speed, "collectors": ["laptop"],
                "series": {"in_bps": self.series("in_bps", in_values),
                           "out_bps": self.series("out_bps", out_values)}}

    def test_the_page_is_self_contained_and_carries_no_script(self):
        page = render_report(self.payload([self.interface_card([100.0, 5000.0], [200.0, 900.0])]))
        self.assertNotIn("<script", page.lower())
        self.assertNotIn("http://", page)
        self.assertNotIn("https://", page)
        self.assertIn("<title>Traffic Watch</title>", page)

    def test_both_themes_are_defined_at_token_level(self):
        page = render_report(self.payload([self.interface_card([1.0, 2.0], [3.0, 4.0])]))
        self.assertIn('@media (prefers-color-scheme: dark)', page)
        self.assertIn(':root:not([data-theme="light"])', page)
        self.assertIn(':root[data-theme="dark"]', page)
        self.assertIn("body {", page)
        self.assertIn("background: var(--bg)", page)

    def test_a_series_is_drawn_as_a_path_with_an_emphasised_endpoint(self):
        page = render_report(self.payload([self.interface_card([100.0, 5000.0, 250.0], [10.0, 20.0, 30.0])]))
        self.assertIn('class="series-rx"', page)
        self.assertIn('class="series-tx"', page)
        self.assertIn('class="tip-rx"', page)
        self.assertIn("5.00 kbps", page)

    def test_a_gap_in_collection_breaks_the_line_rather_than_bridging_it(self):
        rows = [{"observed_at": self.now - 3000, "value": 10.0, "collector": "laptop"},
                {"observed_at": self.now - 60, "value": 20.0, "collector": "laptop"}]
        card = self.interface_card([10.0, 20.0], [1.0, 2.0])
        card["series"]["in_bps"] = rows
        page = render_report(self.payload([card]))
        drawn = page.split('class="series-rx" d="')[1].split('"')[0]
        self.assertEqual(drawn.count("M"), 2)

    def test_a_saturated_link_is_flagged_in_form_as_well_as_number(self):
        page = render_report(self.payload([self.interface_card([9e8], [1e6], util_peak=91.0)]))
        self.assertIn('class="chip crit"', page)
        self.assertIn("91% of link", page)

    def test_a_quiet_link_reads_as_normal(self):
        page = render_report(self.payload([self.interface_card([100.0], [50.0], util_peak=0.4)]))
        self.assertIn('class="chip ok"', page)

    def test_an_unreachable_icmp_target_is_flagged_critical(self):
        watch = {"watch_id": "wch-2", "kind": "icmp", "target": "198.51.100.99", "device_ip": "",
                 "device_name": "", "interface_name": "", "label": "edge"}
        readings = {"rtt_ms": {"samples": 0, "latest": None, "peak": None, "collectors": []},
                    "jitter_ms": {"samples": 0, "latest": None, "peak": None, "collectors": []},
                    "packet_loss_pct": {"samples": 3, "latest": 100.0, "peak": 100.0, "collectors": ["laptop"]}}
        card = {"watch": watch, "readings": readings, "collectors": ["laptop"],
                "series": {"rtt_ms": [], "packet_loss_pct": self.series("packet_loss_pct", [100.0])}}
        page = render_report(self.payload([card]))
        self.assertIn("unreachable", page)
        self.assertIn('class="chip crit"', page)

    def test_a_loss_blip_that_has_cleared_is_still_reported(self):
        watch = {"watch_id": "wch-3", "kind": "icmp", "target": "198.51.100.98", "device_ip": "",
                 "device_name": "", "interface_name": "", "label": "edge"}
        readings = {"rtt_ms": {"samples": 4, "latest": 1.7, "peak": 10.1, "collectors": ["laptop"]},
                    "jitter_ms": {"samples": 4, "latest": 0.2, "peak": 1.0, "collectors": ["laptop"]},
                    "packet_loss_pct": {"samples": 4, "latest": 0.0, "peak": 33.3, "collectors": ["laptop"]}}
        card = {"watch": watch, "readings": readings, "collectors": ["laptop"],
                "series": {"rtt_ms": self.series("rtt_ms", [1.5, 10.1, 1.7]),
                           "packet_loss_pct": self.series("packet_loss_pct", [0.0, 33.3, 0.0])}}
        page = render_report(self.payload([card]))
        self.assertIn('class="chip warn"', page)
        self.assertIn("peak 33% loss", page)
        # The dropped packets are drawn as an event, not as another level line.
        self.assertIn('class="loss-bar"', page)
        self.assertEqual(page.count('class="loss-bar"'), 1)

    def test_an_empty_watchlist_says_what_to_do_next(self):
        page = render_report(self.payload([]))
        self.assertIn("Nothing is being monitored yet", page)
        self.assertIn("netrune traffic watch", page)

    def test_device_and_interface_names_are_escaped(self):
        hostile = dict(self.watch, device_name='SW<script>alert(1)</script>')
        card = self.interface_card([1.0], [1.0])
        card["watch"] = hostile
        page = render_report(self.payload([card]))
        self.assertNotIn("<script>", page)
        self.assertIn("&lt;script&gt;", page)


class TrafficTransportTest(unittest.TestCase):
    """The collector must be runnable unattended, which the vault would break."""

    def test_snmp_modes_do_not_open_the_ssh_vault(self):
        # A collection round happens every few seconds. Prompting for, or even
        # reading, an SSH secret it will never use would put the vault in the
        # path of every poll for nothing.
        control = (ROOT / "netops-control").read_text()
        guard = next(line for line in control.splitlines()
                     if "get_password_from_store" not in line
                     and line.strip().startswith('if [[ "$MODE" != "snmp-'))
        for mode in ("snmp-index", "snmp-counters", "snmp-health"):
            self.assertIn(f'"$MODE" != "{mode}"', guard)
        self.assertEqual(control.count("get_password_from_store || exit $?"), 1)

    def test_a_recent_v2c_success_skips_a_blocked_v3_attempt(self):
        lib = (ROOT / "netops-lib.sh").read_text()
        self.assertIn("snmp_cache_version()", lib)
        # Every SNMP entry point pays the blocked-v3 timeout otherwise, so all
        # four carry the guard rather than only the ones used by one caller.
        entry_points = [name for name in ("netops_snmp_get()", "netops_snmp_walk()", "netops_snmp_get_many()",
                                          "netops_snmp_bulkwalk()") if name in lib]
        self.assertEqual(len(entry_points), 4)
        self.assertEqual(lib.count('"$(snmp_cache_version "$ip")" != "v2c"'), 4)

    def test_the_counter_read_asks_for_every_interface_field_in_one_request(self):
        control = (ROOT / "netops-control").read_text()
        for oid in ("ifHCInOctets", "ifHCOutOctets", "ifInErrors", "ifOutErrors",
                    "ifInDiscards", "ifOutDiscards", "ifAdminStatus", "ifOperStatus", "ifName"):
            self.assertIn(f"IF-MIB::{oid}.$index", control)
        # Ten OIDs per interface one at a time would turn one round trip into ten.
        self.assertIn("netops_snmp_get_many", control)


if __name__ == "__main__":
    unittest.main()


# Captured verbatim from a Catalyst 9000-lite. The absent keys are absent on the
# real switch too: it implements no HOST-RESOURCES table, so nothing reports how
# many sessions are logged in, and that must stay missing rather than become 0.
LIVE_HEALTH = """sysUpTime|267:10:11:14.61
sysName|SITE-A-SW01.example.net
sysDescr|Cisco IOS Software [IOSXE], Catalyst L3 Switch Software (CAT9K_LITE_IOSXE), Version 17.15.3
sysLocation|EXAMPLE SITE
sysContact|Example IT
interfaces|74
bad_community|6270
bad_community_use|0
bad_version|0
asn_parse_errors|28
tcp_established|0
tcp_opens_in|1759
tcp_opens_out|5
tcp_attempt_fails|4
cpu_percent|5
memory_used_bytes|111428852
memory_total_bytes|643027480
temperature_celsius|47
"""


class LinkCeilingTest(unittest.TestCase):
    """A port cannot pass more than its line rate, and a chart should say so."""

    def test_a_rate_above_the_line_rate_is_not_a_measurement(self):
        # Counters that reset between two reads produce an enormous delta, and
        # a single fabricated spike rescales every other line on the chart into
        # a flat row along the bottom.
        gigabit = 1_000_000_000
        self.assertIsNone(traffic.plausible_rate(4.0 * gigabit, gigabit))
        self.assertEqual(traffic.plausible_rate(0.4 * gigabit, gigabit), 0.4 * gigabit)

    def test_timing_jitter_does_not_discard_a_saturated_link(self):
        # Two reads are never exactly an interval apart, so a port genuinely at
        # line rate computes a little over it. Rejecting that would blank the
        # one port most worth watching.
        gigabit = 1_000_000_000
        self.assertEqual(traffic.plausible_rate(gigabit * 1.02, gigabit), gigabit * 1.02)
        self.assertIsNone(traffic.plausible_rate(gigabit * 1.5, gigabit))

    def test_a_link_of_unknown_speed_is_held_to_the_estate_ceiling(self):
        self.assertIsNone(traffic.plausible_rate(9_000_000_000, None))
        self.assertEqual(traffic.plausible_rate(500_000_000, None), 500_000_000)
        # An estate with faster links says so, and is then believed.
        self.assertEqual(traffic.plausible_rate(9_000_000_000, None, 10_000_000_000),
                         9_000_000_000)

    def test_the_ifspeed_sentinel_is_not_a_speed(self):
        """4294967295 means "does not fit in 32 bits", not 4.29 Gbps.

        Believing it would divide utilisation by the wrong number and report
        every port on the switch as idle, which is worse than reporting none.
        """
        parsed = parse_interface_counters(
            "sysUpTime|100\n24|1000|2000|4294967295|up|Gi1/0/16|0|0|0|0|up\n")
        self.assertIsNone(parsed["interfaces"]["24"]["speed_bps"])
        parsed = parse_interface_counters(
            "sysUpTime|100\n24|1000|2000|0|up|Gi1/0/16|0|0|0|0|up\n")
        self.assertIsNone(parsed["interfaces"]["24"]["speed_bps"])


class DeviceHealthParsingTest(unittest.TestCase):
    def test_a_live_switch_reading_parses_into_counters_gauges_and_identity(self):
        parsed = traffic.parse_device_health(LIVE_HEALTH)
        self.assertEqual(parsed["uptime_seconds"], 23105474)
        self.assertEqual(parsed["counters"]["bad_community"], 6270)
        self.assertEqual(parsed["counters"]["tcp_attempt_fails"], 4)
        self.assertEqual(parsed["gauges"]["cpu_percent"], 5)
        self.assertEqual(parsed["gauges"]["temperature_celsius"], 47)
        self.assertEqual(parsed["info"]["sysLocation"], "EXAMPLE SITE")

    def test_a_reading_the_switch_does_not_answer_stays_missing(self):
        """Absent and zero are different facts and must not be conflated.

        A switch reporting 0% CPU and a switch that does not implement the OID
        draw the same flat line at zero, and only one of them is information.
        """
        parsed = traffic.parse_device_health(LIVE_HEALTH)
        self.assertNotIn("logged_in_users", parsed["gauges"])
        self.assertNotIn("logged_in_users", parsed["counters"])

    def test_a_zero_reading_the_switch_does_answer_is_kept(self):
        parsed = traffic.parse_device_health(LIVE_HEALTH)
        self.assertEqual(parsed["counters"]["bad_version"], 0)
        self.assertEqual(parsed["gauges"]["tcp_established"], 0)

    def test_junk_and_unknown_keys_are_ignored_rather_than_recorded(self):
        parsed = traffic.parse_device_health(
            "cpu_percent|not a number\nsomething_else|4\nno pipe here\n")
        self.assertEqual(parsed["counters"], {})
        self.assertEqual(parsed["gauges"], {})
        self.assertEqual(parsed["info"], {})


class CounterWidthTest(unittest.TestCase):
    """ifHCInOctets and ifInOctets are different counters, not two spellings.

    Reproduces the failure that put 61.6 Tb/s on a 10 Gb port: one poll missed
    the 64-bit varbind, the collector fell back to the 32-bit one, and the
    reading after that looked like the link had carried the whole counter in a
    single interval.
    """

    #: Verbatim from the switch that produced the spike, at the moment it did.
    WIDE = "sysUpTime|100\n36|924298324411345|204918256063647|10000000000|up|Te1/1/4|0|0|0|0|up|64\n"
    NARROW = "sysUpTime|100\n36|201572196|198765432|10000000000|up|Te1/1/4|0|0|0|0|up|32\n"

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        base = Path(self.temp.name)
        self.env = mock.patch.dict(os.environ, {
            "NETOPS_CONFIG_DIR": str(base / "config"),
            "NETOPS_CACHE_DIR": str(base / "cache"),
            "NETOPS_SQLITE_DB": str(base / "cache" / "netops.sqlite3"),
            "NETOPS_BACKUP_DIR": str(base / "backups"),
            "NETOPS_PROGRESS": "0",
        }, clear=False)
        self.env.start()
        self.app = netops.App(ROOT)
        self.monitor = self.app.traffic
        self.watch = self.monitor.add_watch(
            "interface", device_ip="198.51.100.10", device_name="SITE-A-SW01",
            interface_name="Te1/1/4", ifindex="36")

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def read(self, output):
        # Each round gets its own second, or the link-state sample collides with
        # the previous round's on the one-per-second identity index.
        self.clock = getattr(self, "clock", 1_700_000_000) + 60
        with mock.patch.object(self.app, "capture", return_value=(0, output, "")), \
                mock.patch("netops_platform.traffic.time.time", return_value=self.clock):
            return self.monitor.poll([self.watch])

    def stored(self, name):
        row = self.app.state.one(
            "SELECT value FROM traffic_counters WHERE watch_id=? AND counter=?",
            (self.watch["watch_id"], name))
        return int(row["value"]) if row else None

    def test_the_width_a_switch_answers_with_is_recorded(self):
        self.read(self.WIDE)
        self.assertEqual(self.stored("counter_width"), 64)
        self.assertEqual(self.stored("in_octets"), 924298324411345)

    def test_a_narrow_reading_never_lands_in_a_wide_series(self):
        self.read(self.WIDE)
        result = self.read(self.NARROW)
        # The 64-bit value stands; the 32-bit one is discarded, not stored.
        self.assertEqual(self.stored("in_octets"), 924298324411345)
        self.assertEqual(self.stored("counter_width"), 64)
        self.assertEqual(result["counter_width_mismatches"], 1)
        self.assertIn("discarded", result["errors"][0]["error"])

    def test_the_series_recovers_without_a_fabricated_spike(self):
        """The spike came from the recovery, not from the dip.

        rate() reads a value returning to 924 trillion from 201 million as a
        genuine increase of the whole counter. With the dip never stored, the
        next wide reading differences against the previous wide one.
        """
        self.read(self.WIDE)
        self.read(self.NARROW)
        later = ("sysUpTime|400\n"
                 "36|924298325411345|204918257063647|10000000000|up|Te1/1/4|0|0|0|0|up|64\n")
        self.read(later)
        self.assertEqual(self.stored("in_octets"), 924298325411345)
        rates = [row["value"] for row in self.app.state.rows(
            "SELECT value FROM traffic_samples WHERE watch_id=? AND metric='in_bps'",
            (self.watch["watch_id"],))]
        # 1,000,000 bytes over the interval, nowhere near the line rate -- and
        # emphatically not the 61.6 Tb/s the mixed series produced.
        self.assertTrue(rates)
        self.assertLess(max(rates), 10_000_000_000)

    def test_a_switch_that_really_changed_counters_is_believed_eventually(self):
        """Two rounds running is a device that changed, not a missed varbind.

        The old baseline is dropped rather than differenced against, so no rate
        is ever computed between two different counters.
        """
        self.read(self.WIDE)
        self.read(self.NARROW)
        self.read(self.NARROW)
        self.assertEqual(self.stored("counter_width"), 32)
        self.assertEqual(self.stored("in_octets"), 201572196)

    def test_a_collector_too_old_to_report_width_still_works(self):
        legacy = "sysUpTime|100\n36|1000|2000|10000000000|up|Te1/1/4|0|0|0|0|up\n"
        self.read(legacy)
        self.assertIsNone(self.stored("counter_width"))
        self.assertEqual(self.stored("in_octets"), 1000)


class SnmpCredentialDiagnosticTest(unittest.TestCase):
    """"No response" and "nothing to send" must not read the same.

    A profile with no communities in it cannot even form a request, and saying
    "check the community" sends an operator to inspect a switch that was
    answering all along. The distinction is cheap to make and was the whole
    difference between a five-minute fix and a long hunt.
    """

    def test_a_missing_credential_is_reported_as_one(self):
        from netops_platform.traffic_cli import _snmp_failure
        message = _snmp_failure(
            'ERROR: no SNMP credentials are configured. 198.51.100.10 has no cached '
            'community and none are set for this profile. Add one to /x/.env as: '
            'communities="<community>"\n')
        self.assertIn("no SNMP credentials are configured", message)
        self.assertIn(".env", message)
        self.assertNotIn("Check the community", message)

    def test_a_device_that_did_not_answer_still_says_so(self):
        from netops_platform.traffic_cli import _snmp_failure
        message = _snmp_failure("ERROR: no SNMP response for ifName\n")
        self.assertIn("Check the community", message)
        # The ACL case is the one people forget, and it looks identical.
        self.assertIn("ACL", message)

    def test_the_shell_only_claims_a_gap_when_there_is_one(self):
        """Cached community, configured community, or v3 user each close it."""
        lib = (ROOT / "netops-lib.sh").read_text()
        body = lib[lib.index("netops_snmp_credential_gap() {"):]
        body = body[:body.index("\n}\n")]
        for closes_the_gap in ('snmp_cache_get "$ip"', '${CREDS[communities]}',
                               '${CREDS[snmpv3_user]}'):
            with self.subTest(source=closes_the_gap):
                self.assertIn(closes_the_gap, body)
        # The message has to name the file, or it is another dead end.
        self.assertIn("$ENV_FILE", body)

    def test_the_index_walk_asks_why_before_blaming_the_device(self):
        control = (ROOT / "netops-control").read_text()
        walk = control[control.index("snmp_interface_index() {"):]
        walk = walk[:walk.index("\nsnmp_interface_counters()")]
        self.assertIn("netops_snmp_credential_gap", walk)
        self.assertLess(walk.index("netops_snmp_credential_gap"),
                        walk.index("no SNMP response for ifName"),
                        "the specific reason must be preferred over the generic one")


class PingTargetTest(unittest.TestCase):
    """A watch on a name nothing can resolve reports the device down forever.

    Switch hostnames are names netrune knows and DNS usually does not, so the
    resolution has to happen here rather than being left to ping.
    """

    def test_an_address_is_taken_as_written(self):
        from netops_platform.traffic_cli import _is_address
        self.assertTrue(_is_address("198.51.100.10"))
        self.assertTrue(_is_address("2001:db8::1"))
        self.assertFalse(_is_address("SITE-A-SW01"))
        self.assertFalse(_is_address(""))

    def test_a_name_that_resolves_nowhere_is_refused(self):
        from netops_platform.traffic_cli import _resolves_in_dns
        self.assertFalse(_resolves_in_dns("no-such-host.invalid"))
