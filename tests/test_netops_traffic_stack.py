import contextlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
import urllib.request
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from netops_platform import core as netops
from netops_platform.traffic_exporter import build_server, is_loopback, split_bind
from netops_platform.traffic_metrics import MetricsExporter, escape_label, format_value, render_labels
from netops_platform.traffic_stack import (
    RATE_WINDOW,
    alert_rules,
    scrape_config,
    stack_files,
)

# Captured verbatim from a Catalyst 9300; identifiers are documentation values.
LIVE_COUNTERS = (
    "sysUpTime|59:1:16:26.37\n"
    "24|383297479033|3422178894117|1000000000|up|Gi1/0/16|136717|826|0|176580|up\n"
    "33|251652976088541|91715055730664|1000000000|up|Gi1/1/1|160|0|13510|63552|down\n"
)


class ExpositionFormatTest(unittest.TestCase):
    def test_label_values_are_escaped(self):
        self.assertEqual(escape_label('SW"01'), 'SW\\"01')
        self.assertEqual(escape_label("a\\b"), "a\\\\b")
        self.assertEqual(escape_label("line\nbreak"), "line\\nbreak")

    def test_empty_labels_are_dropped_rather_than_published_blank(self):
        self.assertEqual(render_labels({"device": "SW1", "ifindex": ""}), '{device="SW1"}')
        self.assertEqual(render_labels({}), "")

    def test_large_counters_keep_full_integer_precision(self):
        # A 10G port's byte counter passes 2^53 within weeks; float notation
        # there would quietly lose the low digits a rate is computed from.
        self.assertEqual(format_value(251652976088541), "251652976088541")
        self.assertEqual(format_value(0), "0")
        self.assertIn(".", format_value(1.5))


class ExpositionContentTest(unittest.TestCase):
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
        self.app.state.execute(
            "INSERT INTO devices(ip,hostname,platform,model,serial,mac,source,last_seen,status)"
            " VALUES(?,?,?,?,?,?,?,?,?)",
            ("198.51.100.10", "SITE-A-SW01", "Cisco", "C9300", "S1", "", "test", 1000, "ONLINE"))

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def collect(self, output=LIVE_COUNTERS):
        for index, name in (("24", "Gi1/0/16"), ("33", "Gi1/1/1")):
            self.monitor.add_watch("interface", device_ip="198.51.100.10", device_name="SITE-A-SW01",
                                   interface_name=name, ifindex=index, interval_seconds=30)
        with mock.patch.object(self.app, "capture", return_value=(0, output, "")):
            self.monitor.poll()

    def body(self):
        return MetricsExporter(self.monitor).render()

    def series(self, text, name):
        return [line for line in text.splitlines() if line.startswith(name + "{")]

    def test_counters_are_published_raw_and_typed_as_counters(self):
        self.collect()
        text = self.body()
        self.assertIn("# TYPE netrune_interface_receive_bytes_total counter", text)
        line = next(l for l in self.series(text, "netrune_interface_receive_bytes_total") if "Gi1/0/16" in l)
        self.assertTrue(line.endswith(" 383297479033"), line)

    def test_no_rate_is_published_because_the_database_derives_it(self):
        self.collect()
        text = self.body()
        for forbidden in ("_bps", "bits_per_second", "_rate"):
            self.assertNotIn(forbidden, text.replace("netrune_interface_speed_bits", ""))

    def test_errors_and_discards_are_separate_counters(self):
        self.collect()
        text = self.body()
        errors = next(l for l in self.series(text, "netrune_interface_receive_errors_total") if "Gi1/0/16" in l)
        drops = next(l for l in self.series(text, "netrune_interface_transmit_drops_total") if "Gi1/0/16" in l)
        self.assertTrue(errors.endswith(" 136717"), errors)
        self.assertTrue(drops.endswith(" 176580"), drops)

    def test_operational_and_administrative_status_are_distinguishable(self):
        self.collect()
        text = self.body()
        # A port that is admin down is an intention; a port that is oper down
        # while admin up is a fault. One gauge cannot say which.
        oper = {l.split("interface=\"")[1].split('"')[0]: l.rsplit(" ", 1)[1]
                for l in self.series(text, "netrune_interface_up")}
        admin = {l.split("interface=\"")[1].split('"')[0]: l.rsplit(" ", 1)[1]
                 for l in self.series(text, "netrune_interface_admin_up")}
        self.assertEqual(oper["Gi1/1/1"], "1")
        self.assertEqual(admin["Gi1/1/1"], "0")

    def test_a_staleness_signal_is_published_for_every_interface(self):
        self.collect()
        text = self.body()
        stamps = self.series(text, "netrune_interface_last_poll_timestamp_seconds")
        self.assertEqual(len(stamps), 2)
        self.assertGreater(float(stamps[0].rsplit(" ", 1)[1]), 1_600_000_000)

    def test_a_paused_interface_stops_publishing_but_says_it_was_paused(self):
        self.collect()
        watch = next(w for w in self.monitor.list_watches() if w["interface_name"] == "Gi1/0/16")
        self.monitor.set_enabled(watch["watch_id"], False)
        text = self.body()
        marks = {l.split("interface=\"")[1].split('"')[0]: l.rsplit(" ", 1)[1]
                 for l in self.series(text, "netrune_interface_watch_enabled")}
        self.assertEqual(marks["Gi1/0/16"], "0")
        self.assertEqual(marks["Gi1/1/1"], "1")
        # Its counter would otherwise be republished unchanged forever, and a
        # counter that never moves has a rate of zero -- a quiet port, not an
        # unmeasured one. The series has to go stale instead.
        counters = self.series(text, "netrune_interface_receive_bytes_total")
        self.assertNotIn("Gi1/0/16", " ".join(counters))
        self.assertIn("Gi1/1/1", " ".join(counters))

    def test_an_unwatched_interface_leaves_the_exposition_entirely(self):
        self.collect()
        watch = next(w for w in self.monitor.list_watches() if w["interface_name"] == "Gi1/0/16")
        self.monitor.remove_watch(watch["watch_id"])
        text = self.body()
        self.assertNotIn("Gi1/0/16", text)

    def test_device_uptime_is_published_once_per_device_not_once_per_port(self):
        self.collect()
        self.assertEqual(len(self.series(self.body(), "netrune_device_uptime_seconds")), 1)

    def test_nothing_is_published_for_a_device_nobody_asked_to_monitor(self):
        self.collect()
        text = self.body()
        self.assertNotIn("198.51.100.99", text)
        self.assertEqual(len(self.series(text, "netrune_interface_up")), 2)

    def test_an_empty_watchlist_produces_a_valid_but_bare_exposition(self):
        text = self.body()
        self.assertIn("netrune_collector_info", text)
        self.assertNotIn("netrune_interface_receive_bytes_total{", text)
        self.assertTrue(text.endswith("\n"))

    def test_icmp_readings_are_published_in_base_units(self):
        watch = self.monitor.add_watch("icmp", target="198.51.100.10", label="core")
        probe = {"ok": True, "unreachable": False, "packet_loss_pct": 25.0,
                 "avg_ms": 2.5, "jitter_ms": 0.4}
        with mock.patch.object(self.app, "icmp_probe", return_value=probe):
            self.monitor.poll()
        text = self.body()
        rtt = self.series(text, "netrune_icmp_rtt_seconds")[0]
        loss = self.series(text, "netrune_icmp_loss_ratio")[0]
        self.assertAlmostEqual(float(rtt.rsplit(" ", 1)[1]), 0.0025)
        self.assertAlmostEqual(float(loss.rsplit(" ", 1)[1]), 0.25)

    def test_each_collector_publishes_its_own_series(self):
        self.collect()
        self.app.config.public["traffic_collector_id"] = "cloud-poller-1"
        with mock.patch.object(self.app, "capture", return_value=(0, LIVE_COUNTERS, "")):
            self.monitor.poll()
        collectors = {line.split('collector="')[1].split('"')[0]
                      for line in self.series(self.body(), "netrune_interface_receive_bytes_total")}
        self.assertEqual(len(collectors), 2)


class ExporterEndpointTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        base = Path(self.temp.name)
        self.env = mock.patch.dict(os.environ, {
            "NETOPS_CONFIG_DIR": str(base / "config"),
            "NETOPS_CACHE_DIR": str(base / "cache"),
            "NETOPS_SQLITE_DB": str(base / "cache" / "netops.sqlite3"),
            "NETOPS_PROGRESS": "0",
        }, clear=False)
        self.env.start()
        self.app = netops.App(ROOT)
        self.server = build_server(self.app.traffic, "127.0.0.1", 0)
        import threading
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.base_url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.env.stop()
        self.temp.cleanup()

    def get(self, path, method="GET"):
        request = urllib.request.Request(self.base_url + path, method=method)
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return response.status, response.headers, response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            return exc.code, exc.headers, exc.read().decode("utf-8")

    def test_metrics_are_served_with_the_prometheus_content_type(self):
        status, headers, body = self.get("/metrics")
        self.assertEqual(status, 200)
        self.assertIn("text/plain", headers["Content-Type"])
        self.assertIn("version=0.0.4", headers["Content-Type"])
        self.assertIn("netrune_collector_info", body)

    def test_readings_are_never_cached_by_anything_in_between(self):
        _, headers, _ = self.get("/metrics")
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")

    def test_there_is_no_route_that_does_anything_but_read(self):
        for path in ("/api/jobs", "/api/health", "/commands", "/../etc/passwd"):
            with self.subTest(path=path):
                status, _, _ = self.get(path)
                self.assertEqual(status, 404)

    def test_write_methods_are_refused(self):
        for method in ("POST", "PUT", "DELETE", "PATCH"):
            with self.subTest(method=method):
                status, _, _ = self.get("/metrics", method=method)
                self.assertGreaterEqual(status, 400)

    def test_health_answers_without_touching_the_database(self):
        status, _, body = self.get("/health")
        self.assertEqual(status, 200)
        self.assertEqual(body.strip(), "ok")


class BindParsingTest(unittest.TestCase):
    def test_bind_forms_an_operator_would_type(self):
        self.assertEqual(split_bind(""), ("127.0.0.1", 9713))
        self.assertEqual(split_bind("9714"), ("127.0.0.1", 9714))
        self.assertEqual(split_bind("127.0.0.1:9714"), ("127.0.0.1", 9714))
        self.assertEqual(split_bind("[::1]:9714"), ("::1", 9714))
        self.assertEqual(split_bind("localhost"), ("localhost", 9713))

    def test_an_unclosed_ipv6_bracket_is_an_error_not_a_silent_guess(self):
        with self.assertRaises(ValueError):
            split_bind("[::1:9714")

    def test_loopback_detection_covers_the_whole_range(self):
        for host in ("127.0.0.1", "127.0.1.5", "::1", "localhost", "LOCALHOST"):
            self.assertTrue(is_loopback(host), host)
        for host in ("0.0.0.0", "198.51.100.5", "::", "example.com"):
            self.assertFalse(is_loopback(host), host)


class StackProvisioningTest(unittest.TestCase):
    def test_scrape_interval_is_carried_into_the_config(self):
        text = scrape_config("127.0.0.1:9713", 15)
        self.assertIn("scrape_interval: 15s", text)
        self.assertIn('targets: ["127.0.0.1:9713"]', text)

    def test_alert_rules_derive_rates_rather_than_reading_a_stored_rate(self):
        rules = alert_rules()
        self.assertIn(f"rate(netrune_interface_receive_bytes_total[{RATE_WINDOW}])", rules)
        self.assertNotIn("_bps", rules)

    def test_a_saturation_alert_uses_the_reported_link_speed(self):
        self.assertIn("netrune_interface_speed_bits", alert_rules())

    def test_an_administratively_down_port_does_not_alert_as_a_fault(self):
        self.assertIn("netrune_interface_up == 0 and netrune_interface_admin_up == 1", alert_rules())

    def test_a_stopped_collector_alerts_from_the_staleness_signal(self):
        self.assertIn("netrune_interface_last_poll_timestamp_seconds", alert_rules())

    def test_vmalert_is_given_a_notifier_because_it_refuses_to_start_without_one(self):
        # vmalert exits with "config contains alerting rules but neither
        # -notifier.url nor -notifier.config nor -notifier.blackhole aren't set".
        files = stack_files("127.0.0.1:9713", "http://127.0.0.1:8428", 15, "90d", Path("/tmp/x"))
        compose = next(v for k, v in files.items() if k.name == "docker-compose.yml")
        readme = next(v for k, v in files.items() if k.name == "README.md")
        self.assertIn("-notifier.blackhole", compose)
        self.assertIn("-notifier.blackhole", readme)

    def test_every_generated_unit_is_pulled_in_by_the_target(self):
        files = stack_files("127.0.0.1:9713", "http://127.0.0.1:8428", 15, "90d",
                            Path("/tmp/x"), unit_dir=Path("/tmp/x/systemd"))
        units = {k.name for k in files if k.name.endswith(".service")}
        target = next(v for k, v in files.items() if k.name == "netrune-metrics.target")
        wanted = {name for line in target.splitlines() if line.startswith("Wants=")
                  for name in line.removeprefix("Wants=").split()}
        # A unit the target does not want is a unit nobody starts.
        self.assertEqual(units, wanted)

    def test_units_reference_absolute_binaries_not_a_path_lookup(self):
        files = stack_files("127.0.0.1:9713", "http://127.0.0.1:8428", 15, "90d",
                            Path("/tmp/x"), unit_dir=Path("/tmp/x/systemd"),
                            binaries={"netrune": "/usr/local/bin/netrune",
                                      "victoria-metrics": "/usr/sbin/victoria-metrics",
                                      "vmalert": "/usr/sbin/vmalert"})
        collector = next(v for k, v in files.items() if k.name == "netrune-collector.service")
        self.assertIn("ExecStart=/usr/local/bin/netrune traffic daemon", collector)

    def test_the_exposition_starts_before_the_scraper(self):
        files = stack_files("127.0.0.1:9713", "http://127.0.0.1:8428", 15, "90d",
                            Path("/tmp/x"), unit_dir=Path("/tmp/x/systemd"))
        vm = next(v for k, v in files.items() if k.name == "netrune-victoriametrics.service")
        # Scraping an endpoint that is not listening yet records the collector
        # as down for as long as the first scrape interval.
        self.assertIn("After=netrune-exporter.service", vm)

    def test_every_generated_file_parses_as_what_it_claims_to_be(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "stack"
            files = stack_files("127.0.0.1:9713", "http://127.0.0.1:8428", 15, "90d", root)
            for path, body in files.items():
                with self.subTest(path=path.name):
                    self.assertTrue(body.strip())
                    if path.suffix == ".json":
                        parsed = json.loads(body)
                        # Every grapher names its resources somehow; which key
                        # it uses is the adapter's business, not this test's.
                        self.assertTrue({"kind", "uid", "apiVersion"} & set(parsed), parsed.keys())


class TrafficControlCommandTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        base = Path(self.temp.name)
        self.env = mock.patch.dict(os.environ, {
            "NETOPS_CONFIG_DIR": str(base / "config"),
            "NETOPS_CACHE_DIR": str(base / "cache"),
            "NETOPS_SQLITE_DB": str(base / "cache" / "netops.sqlite3"),
            "NETOPS_PROGRESS": "0",
        }, clear=False)
        self.env.start()
        self.app = netops.App(ROOT)
        self.app.state.execute(
            "INSERT INTO devices(ip,hostname,platform,model,serial,mac,source,last_seen,status)"
            " VALUES(?,?,?,?,?,?,?,?,?)",
            ("198.51.100.10", "SITE-A-SW01", "Cisco", "C9300", "S1", "", "test", 1000, "ONLINE"))
        self.app.state.execute(
            "INSERT INTO devices(ip,hostname,platform,model,serial,mac,source,last_seen,status)"
            " VALUES(?,?,?,?,?,?,?,?,?)",
            ("198.51.100.11", "SITE-B-SW01", "Cisco", "C9300", "S2", "", "test", 1000, "ONLINE"))
        for device_ip, device_name, name, index in (
            ("198.51.100.10", "SITE-A-SW01", "Gi1/0/16", "24"),
            ("198.51.100.10", "SITE-A-SW01", "Gi1/1/1", "33"),
            ("198.51.100.11", "SITE-B-SW01", "Gi1/1/1", "33"),
        ):
            self.app.traffic.add_watch("interface", device_ip=device_ip, device_name=device_name,
                                       interface_name=name, ifindex=index, interval_seconds=30)

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def run_cli(self, args, capture_output=""):
        buffer = io.StringIO()
        with mock.patch.object(self.app, "capture", return_value=(0, capture_output, "")), \
                contextlib.redirect_stdout(buffer), contextlib.redirect_stderr(io.StringIO()):
            code = self.app.dispatch([*args, "--plain", "--no-color"])
        return code, buffer.getvalue()

    def enabled(self, interface, device_ip="198.51.100.10"):
        watch = self.app.traffic.find_watch("interface", device_ip=device_ip, interface_name=interface)
        return bool(watch["enabled"])

    def test_pausing_a_device_pauses_every_port_on_it_and_nothing_else(self):
        code, _ = self.run_cli(["traffic", "pause", "SITE-A-SW01"])
        self.assertEqual(code, netops.SUCCESS)
        self.assertFalse(self.enabled("Gi1/0/16"))
        self.assertFalse(self.enabled("Gi1/1/1"))
        self.assertTrue(self.enabled("Gi1/1/1", "198.51.100.11"))

    def test_pausing_an_interface_name_reaches_that_port_on_every_switch(self):
        self.run_cli(["traffic", "pause", "Gi1/1/1"])
        self.assertFalse(self.enabled("Gi1/1/1"))
        self.assertFalse(self.enabled("Gi1/1/1", "198.51.100.11"))
        self.assertTrue(self.enabled("Gi1/0/16"))

    def test_pausing_keeps_the_history_a_removal_would_discard(self):
        watch = self.app.traffic.find_watch("interface", device_ip="198.51.100.10", interface_name="Gi1/0/16")
        self.app.traffic._write_sample(watch["watch_id"], int(time.time()), "in_bps", 5.0, "bps", "up", "local", {})
        self.run_cli(["traffic", "pause", "Gi1/0/16"])
        self.assertEqual(self.app.traffic.summarize(watch["watch_id"], "in_bps", 3600)["samples"], 1)

    def test_a_paused_target_is_not_due_for_collection(self):
        self.run_cli(["traffic", "pause", "SITE-A-SW01"])
        due = self.app.traffic.due_watches({}, now=time.time())
        self.assertEqual([w["device_ip"] for w in due], ["198.51.100.11"])

    def test_resume_puts_a_target_back_into_collection(self):
        self.run_cli(["traffic", "pause", "SITE-A-SW01"])
        self.run_cli(["traffic", "resume", "Gi1/0/16"])
        self.assertTrue(self.enabled("Gi1/0/16"))
        self.assertFalse(self.enabled("Gi1/1/1"))

    def test_changing_an_interval_is_clamped_to_a_sane_range(self):
        self.run_cli(["traffic", "interval", "Gi1/0/16", "5"])
        watch = self.app.traffic.find_watch("interface", device_ip="198.51.100.10", interface_name="Gi1/0/16")
        self.assertEqual(watch["interval_seconds"], 10)
        self.run_cli(["traffic", "interval", "Gi1/0/16", "999999"])
        watch = self.app.traffic.find_watch("interface", device_ip="198.51.100.10", interface_name="Gi1/0/16")
        self.assertEqual(watch["interval_seconds"], 3600)

    def kind_count(self, kind):
        return len([w for w in self.app.traffic.list_watches() if w["kind"] == kind])

    def interface_count(self):
        return self.kind_count("interface")

    def test_removing_several_targets_at_once_requires_confirmation(self):
        code, output = self.run_cli(["traffic", "unwatch", "SITE-A-SW01"])
        self.assertEqual(code, netops.VALIDATION)
        self.assertIn("--confirm", output)
        self.assertEqual(self.interface_count(), 3)
        code, _ = self.run_cli(["traffic", "unwatch", "SITE-A-SW01", "--confirm"])
        self.assertEqual(code, netops.SUCCESS)
        self.assertEqual(self.interface_count(), 1)
        # SITE-A-SW01 had a health watch only because ports on it were
        # watched. With the last one gone it stops being collected, while
        # SITE-B-SW01 keeps its own.
        self.assertEqual([w["device_ip"] for w in self.app.traffic.list_watches()
                          if w["kind"] == "device"], ["198.51.100.11"])

    def test_removing_one_target_by_id_needs_no_confirmation(self):
        watch = self.app.traffic.find_watch("interface", device_ip="198.51.100.10", interface_name="Gi1/0/16")
        code, _ = self.run_cli(["traffic", "unwatch", watch["watch_id"]])
        self.assertEqual(code, netops.SUCCESS)
        self.assertEqual(self.interface_count(), 2)
        # A port remains on that switch, so its health watch stays.
        self.assertIn("198.51.100.10", [w["device_ip"] for w in self.app.traffic.list_watches()
                                        if w["kind"] == "device"])

    def test_a_phrase_matching_nothing_says_so_rather_than_acting_broadly(self):
        code, output = self.run_cli(["traffic", "pause", "SITE-Z-SW99"])
        self.assertEqual(code, netops.VALIDATION)
        self.assertIn("No monitored target matched", output)
        self.assertTrue(self.enabled("Gi1/0/16"))

    def test_watching_several_interfaces_uses_one_index_walk(self):
        index = "24|Gi1/0/16|\n25|Gi1/0/17|\n26|Gi1/0/18|\n"
        buffer = io.StringIO()
        with mock.patch.object(self.app, "capture", return_value=(0, index, "")) as capture, \
                contextlib.redirect_stdout(buffer), contextlib.redirect_stderr(io.StringIO()):
            code = self.app.dispatch(
                ["traffic", "watch", "SITE-A-SW01", "Gi1/0/17,Gi1/0/18", "--plain", "--no-color"])
        self.assertEqual(code, netops.SUCCESS)
        self.assertEqual(capture.call_count, 1)
        self.assertEqual(self.interface_count(), 5)

    def test_a_batch_reports_the_names_the_device_does_not_have(self):
        index = "24|Gi1/0/16|\n25|Gi1/0/17|\n"
        code, output = self.run_cli(
            ["traffic", "watch", "SITE-A-SW01", "Gi1/0/17,Gi9/9/9"], index)
        self.assertEqual(code, netops.SUCCESS)
        self.assertIn("Gi9/9/9", output)
        self.assertIn("Not found", output)
        self.assertEqual(self.interface_count(), 4)

    def test_status_reports_no_collector_when_none_is_running(self):
        code, output = self.run_cli(["traffic", "status"])
        self.assertEqual(code, netops.SUCCESS)
        self.assertIn("No collector is running", output)
        self.assertIn("never", output)

    def test_status_flags_a_target_that_has_stopped_producing_samples(self):
        watch = self.app.traffic.find_watch("interface", device_ip="198.51.100.10", interface_name="Gi1/0/16")
        self.app.traffic._write_sample(
            watch["watch_id"], int(time.time()) - 4000, "out_bps", 1.0, "bps", "up", "local", {})
        _, output = self.run_cli(["traffic", "status"])
        self.assertIn("stale", output)

    def test_the_stack_generator_writes_a_complete_tree(self):
        destination = Path(self.temp.name) / "stack"
        code, output = self.run_cli(["traffic", "stack", "init", "--dir", str(destination)])
        self.assertEqual(code, netops.SUCCESS)
        for name in ("scrape.yml", "alerts.yml", "docker-compose.yml", "README.md"):
            self.assertTrue((destination / name).is_file(), name)
        for unit in ("netrune-collector.service", "netrune-metrics.target"):
            self.assertTrue((destination / "systemd" / unit).is_file(), unit)
        self.assertIn(str(destination), output)

    def test_each_grapher_writes_its_own_provisioning_and_no_other(self):
        for grapher, present, absent in (
            ("grafana", "grafana/dashboards/netrune-interfaces.json", "perses.yml"),
            ("perses", "perses/dashboard-netrune-interfaces.json", "grafana"),
        ):
            destination = Path(self.temp.name) / f"stack-{grapher}"
            code, _ = self.run_cli(
                ["traffic", "stack", "init", "--dir", str(destination), "--grapher", grapher])
            with self.subTest(grapher=grapher):
                self.assertEqual(code, netops.SUCCESS)
                self.assertTrue((destination / present).is_file(), present)
                self.assertFalse((destination / absent).exists(), absent)
                self.assertTrue((destination / "systemd" / f"netrune-{grapher}.service").is_file())

    def test_an_unknown_grapher_is_refused_with_the_available_names(self):
        destination = Path(self.temp.name) / "stack-bad"
        code, output = self.run_cli(
            ["traffic", "stack", "init", "--dir", str(destination), "--grapher", "chronograf"])
        self.assertEqual(code, netops.VALIDATION)
        self.assertFalse(destination.exists())

    def test_the_generated_scrape_interval_does_not_alias_against_the_collector(self):
        """Half the shortest poll, not equal to it.

        Equal is worse than it looks: the two drift, so some scrapes land
        between polls and see nothing while the next sees two polls' worth, and
        a rate over a short window reads that doubled step as real traffic.
        """
        self.run_cli(["traffic", "interval", "Gi1/0/16", "20"])
        destination = Path(self.temp.name) / "stack"
        self.run_cli(["traffic", "stack", "init", "--dir", str(destination)])
        self.assertIn("scrape_interval: 10s", (destination / "scrape.yml").read_text())

    def test_the_scrape_interval_never_outruns_the_collector(self):
        """Slower than the poll would discard readings that were taken."""
        from netops_platform.traffic_cli import _suggested_scrape
        for interval in (10, 20, 60, 300):
            with self.subTest(interval=interval):
                for watch in self.app.traffic.list_watches():
                    self.app.traffic.set_interval(str(watch["watch_id"]), interval)
                self.assertLessEqual(_suggested_scrape(self.app.traffic), interval)

    def test_backfill_publishes_history_under_its_own_gauge_names(self):
        watch = self.app.traffic.find_watch("interface", device_ip="198.51.100.10", interface_name="Gi1/0/16")
        self.app.traffic._write_sample(
            watch["watch_id"], int(time.time()) - 60, "in_bps", 1234.0, "bps", "up", "local", {})
        code, output = self.run_cli(["traffic", "backfill", "--dry-run"])
        self.assertEqual(code, netops.SUCCESS)
        # A derived rate must never be published under the live counter's name.
        self.assertIn("netrune_history_interface_receive_bits_per_second", output)
        self.assertNotIn("netrune_interface_receive_bytes_total", output)

    def test_backfill_with_no_history_reports_that_rather_than_posting_nothing(self):
        code, output = self.run_cli(["traffic", "backfill", "--dry-run"])
        self.assertEqual(code, netops.PARTIAL)
        self.assertIn("nothing to import", output)


if __name__ == "__main__":
    unittest.main()


LIVE_HEALTH = """sysUpTime|267:10:11:14.61
sysName|SITE-A-SW01.example.net
sysLocation|EXAMPLE SITE
interfaces|74
bad_community|6270
bad_version|0
tcp_established|0
tcp_attempt_fails|4
cpu_percent|5
memory_used_bytes|111428852
memory_total_bytes|643027480
temperature_celsius|47
"""


class DeviceHealthWatchTest(unittest.TestCase):
    """Switch health is derived from the interface watchlist, never maintained.

    An operator who had to remember to add and remove a second watch alongside
    the first would eventually be collecting a switch nobody watches and missing
    one they do. Deriving it means the two cannot drift apart.
    """

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

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def watch_interface(self, device_ip, name, index):
        return self.monitor.add_watch("interface", device_ip=device_ip, device_name="SW",
                                      interface_name=name, ifindex=index)

    def device_watches(self):
        return sorted(w["device_ip"] for w in self.monitor.list_watches()
                      if w["kind"] == "device")

    def test_watching_a_port_starts_collecting_the_switch_behind_it(self):
        self.watch_interface("198.51.100.10", "Gi1/0/16", "24")
        self.monitor.sync_device_watches()
        self.assertEqual(self.device_watches(), ["198.51.100.10"])

    def test_a_second_port_on_the_same_switch_adds_no_second_health_watch(self):
        self.watch_interface("198.51.100.10", "Gi1/0/16", "24")
        self.watch_interface("198.51.100.10", "Gi1/1/1", "33")
        self.monitor.sync_device_watches()
        self.monitor.sync_device_watches()
        self.assertEqual(self.device_watches(), ["198.51.100.10"])

    def test_the_last_port_leaving_stops_the_switch_being_collected(self):
        first = self.watch_interface("198.51.100.10", "Gi1/0/16", "24")
        second = self.watch_interface("198.51.100.10", "Gi1/1/1", "33")
        self.monitor.sync_device_watches()
        self.monitor.remove_watch(first["watch_id"])
        self.monitor.sync_device_watches()
        self.assertEqual(self.device_watches(), ["198.51.100.10"])
        self.monitor.remove_watch(second["watch_id"])
        result = self.monitor.sync_device_watches()
        self.assertEqual(self.device_watches(), [])
        self.assertEqual(result["removed"], ["198.51.100.10"])

    def test_a_paused_port_keeps_its_switch_being_collected(self):
        """A pause is temporary and the history is worth more unbroken."""
        watch = self.watch_interface("198.51.100.10", "Gi1/0/16", "24")
        self.monitor.sync_device_watches()
        self.monitor.set_enabled(watch["watch_id"], False)
        self.monitor.sync_device_watches()
        self.assertEqual(self.device_watches(), ["198.51.100.10"])

    def test_health_follows_the_collector_that_owns_the_ports(self):
        """A laptop must not poll a switch only the remote poller can reach.

        Trying would fail every round, and a failure to reach a switch is
        recorded and read as the switch being down.
        """
        watch = self.watch_interface("198.51.100.10", "Gi1/0/16", "24")
        self.monitor.set_owner(watch["watch_id"], "site-a-poller")
        self.monitor.sync_device_watches()
        health = next(w for w in self.monitor.list_watches() if w["kind"] == "device")
        self.assertEqual(health["owner"], "site-a-poller")
        self.assertFalse(self.monitor.owns(health))
        # And so it is absent from the list this collector would poll.
        owned = [w["watch_id"] for w in self.monitor.list_watches(owned_only=True)]
        self.assertNotIn(health["watch_id"], owned)

    def test_switch_readings_reach_the_exposition(self):
        self.watch_interface("198.51.100.10", "Gi1/0/16", "24")
        self.monitor.sync_device_watches()
        health = next(w for w in self.monitor.list_watches() if w["kind"] == "device")
        with mock.patch.object(self.app, "capture", return_value=(0, LIVE_HEALTH, "")):
            self.monitor._poll_device_health(health, int(time.time()), "test", None)
        text = MetricsExporter(self.monitor).render()
        self.assertIn("# TYPE netrune_device_snmp_rejected_community_total counter", text)
        self.assertIn("# TYPE netrune_device_cpu_percent gauge", text)
        self.assertIn("netrune_device_temperature_celsius", text)
        # Identity travels as labels on a constant, not as a series per field.
        info = next(l for l in text.splitlines() if l.startswith("netrune_device_info{"))
        self.assertIn('location="EXAMPLE SITE"', info)
        self.assertTrue(info.endswith(" 1"))

    def test_a_paused_switch_publishes_nothing(self):
        """The same rule the interface exposition follows, for the same reason.

        A paused watch keeps its last counter forever, and a counter held still
        has a rate of zero -- which reads as a quiet switch rather than one
        nobody is measuring.
        """
        self.watch_interface("198.51.100.10", "Gi1/0/16", "24")
        self.monitor.sync_device_watches()
        health = next(w for w in self.monitor.list_watches() if w["kind"] == "device")
        with mock.patch.object(self.app, "capture", return_value=(0, LIVE_HEALTH, "")):
            self.monitor._poll_device_health(health, int(time.time()), "test", None)
        self.monitor.set_enabled(health["watch_id"], False)
        self.assertNotIn("netrune_device_cpu_percent", MetricsExporter(self.monitor).render())


class StaleReadingTest(unittest.TestCase):
    """A held counter is worse than an absent one.

    The exposition serves the newest stored reading, so a stopped collector
    draws a flat line rather than an empty one. When collection resumes the
    counter jumps by everything that accumulated while nobody was reading, and
    a rate derived across that gap attributes hours of traffic to one interval
    -- which is how a 10 Gb port comes to report hundreds of gigabits.
    """

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
            interface_name="Gi1/0/16", ifindex="24", interval_seconds=30)

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def collect(self, age_seconds):
        observed = int(time.time()) - age_seconds
        for counter, value in (("in_octets", 1000), ("out_octets", 2000), ("speed_bps", 10**9)):
            self.app.state.execute(
                "INSERT OR REPLACE INTO traffic_counters(watch_id,counter,observed_at,value,collector)"
                " VALUES(?,?,?,?,?)", (self.watch["watch_id"], counter, observed, value, "test"))
        return MetricsExporter(self.monitor).render()

    def test_a_fresh_reading_is_published(self):
        self.assertIn("netrune_interface_receive_bytes_total", self.collect(10))

    def test_a_reading_older_than_the_horizon_is_not(self):
        text = self.collect(3600)
        self.assertNotIn("netrune_interface_receive_bytes_total", text)
        # But the gauge that explains the gap keeps being published, or the
        # absence would be indistinguishable from an interface nobody watches.
        self.assertIn("netrune_interface_last_poll_timestamp_seconds", text)
        self.assertIn("netrune_interface_watch_enabled", text)

    def test_the_horizon_follows_the_watch_interval(self):
        from netops_platform.traffic_metrics import stale_horizon
        # Never tighter than five minutes: a watch collected every ten seconds
        # would otherwise blank itself over a single missed round.
        self.assertEqual(stale_horizon({"interval_seconds": 10}), 300)
        self.assertEqual(stale_horizon({"interval_seconds": 300}), 1500)


class DisplayNameTest(unittest.TestCase):
    """A name a person chose, without it becoming part of what a series is.

    "Warehouse uplink" is what an operator recognises; Gi1/0/16 is what the
    switch calls it. Both belong on the chart, but only one of them may decide
    a series' identity -- naming a port collected for weeks must not start a
    new series and strand the history under the old one.
    """

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
            interface_name="Gi1/0/16", ifindex="24")

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def current(self):
        return self.monitor.get_watch(str(self.watch["watch_id"])) or {}

    def test_an_unnamed_port_is_called_what_the_device_calls_it(self):
        self.assertEqual(self.monitor.display_name(self.current()), "Gi1/0/16")

    def test_a_name_replaces_it_and_a_clear_brings_it_back(self):
        self.monitor.set_display_name(str(self.watch["watch_id"]), "Warehouse uplink")
        self.assertEqual(self.monitor.display_name(self.current()), "Warehouse uplink")
        self.monitor.set_display_name(str(self.watch["watch_id"]), "")
        self.assertEqual(self.monitor.display_name(self.current()), "Gi1/0/16")

    def test_naming_does_not_touch_the_counters_identity(self):
        """The whole point: the name rides its own metric, not the counters."""
        with mock.patch.object(self.app, "capture", return_value=(0, LIVE_COUNTERS, "")):
            self.monitor.poll()
        before = [l for l in MetricsExporter(self.monitor).render().splitlines()
                  if l.startswith("netrune_interface_receive_bytes_total{")]
        self.monitor.set_display_name(str(self.watch["watch_id"]), "Warehouse uplink")
        after = [l for l in MetricsExporter(self.monitor).render().splitlines()
                 if l.startswith("netrune_interface_receive_bytes_total{")]
        self.assertEqual(before, after, "naming a port must not change its counter series")

    def test_the_name_travels_on_an_info_metric(self):
        with mock.patch.object(self.app, "capture", return_value=(0, LIVE_COUNTERS, "")):
            self.monitor.poll()
        self.monitor.set_display_name(str(self.watch["watch_id"]), "Warehouse uplink")
        text = MetricsExporter(self.monitor).render()
        info = next(l for l in text.splitlines() if l.startswith("netrune_interface_info{"))
        self.assertIn('name="Warehouse uplink"', info)
        # Always 1: it exists to carry labels, not a measurement.
        self.assertTrue(info.endswith(" 1"))
        # And it must carry the labels the dashboards join on, or every panel
        # that uses a name renders empty.
        for label in ("device=", "interface=", "collector="):
            self.assertIn(label, info)

    def test_the_dashboards_join_on_labels_the_info_metric_actually_has(self):
        from netops_platform.traffic_dashboards import IDENTITY_LABELS
        with mock.patch.object(self.app, "capture", return_value=(0, LIVE_COUNTERS, "")):
            self.monitor.poll()
        self.monitor.set_display_name(str(self.watch["watch_id"]), "Warehouse uplink")
        info = next(l for l in MetricsExporter(self.monitor).render().splitlines()
                    if l.startswith("netrune_interface_info{"))
        for label in (name.strip() for name in IDENTITY_LABELS.split(",")):
            with self.subTest(label=label):
                self.assertIn(f'{label}="', info)

    def test_a_name_is_trimmed_and_bounded(self):
        self.monitor.set_display_name(str(self.watch["watch_id"]), "  Warehouse   uplink  ")
        self.assertEqual(self.monitor.display_name(self.current()), "Warehouse uplink")
        self.monitor.set_display_name(str(self.watch["watch_id"]), "x" * 200)
        self.assertEqual(len(self.monitor.display_name(self.current())), 64)

    def test_a_name_survives_being_pulled_from_a_poller(self):
        from netops_platform.traffic_sync import WATCH_COLUMNS
        self.assertIn("display_name", WATCH_COLUMNS)


class CollectorRoleTest(unittest.TestCase):
    """A poller collects. It does not store, serve, or draw.

    Putting a time-series database and an exposition on the monitored network
    means a second store to keep and patch, and a listener on a network the
    machine was placed on to observe rather than to serve. The puller keeps the
    readings once.
    """

    def units(self, role):
        from netops_platform.traffic_stack import systemd_units
        return systemd_units(Path("/x"), "127.0.0.1:9713", "http://127.0.0.1:8428", "180d",
                             "netrune", "victoria-metrics", "vmalert", role=role)

    def test_a_collector_gets_the_collector_and_nothing_that_listens(self):
        from netops_platform.traffic_stack import ROLE_COLLECTOR
        names = set(self.units(ROLE_COLLECTOR))
        self.assertIn("netrune-collector.service", names)
        for absent in ("netrune-exporter.service", "netrune-victoriametrics.service",
                       "netrune-vmalert.service"):
            with self.subTest(absent=absent):
                self.assertNotIn(absent, names)

    def test_the_collector_unit_is_the_same_one_either_way(self):
        """One definition, so the poller cannot drift from the laptop."""
        from netops_platform.traffic_stack import ROLE_COLLECTOR, ROLE_FULL
        self.assertEqual(self.units(ROLE_COLLECTOR)["netrune-collector.service"],
                         self.units(ROLE_FULL)["netrune-collector.service"])

    def test_a_collector_prunes_itself(self):
        """Nobody logs into a poller to tidy up, so the tidying is a unit."""
        from netops_platform.traffic_stack import ROLE_COLLECTOR
        units = self.units(ROLE_COLLECTOR)
        self.assertIn("netrune-prune.timer", units)
        # Persistent, or a machine that was off overnight waits a full day.
        self.assertIn("Persistent=true", units["netrune-prune.timer"])
        self.assertIn("WantedBy=timers.target", units["netrune-prune.timer"])
        # The oneshot must not be enabled on its own, or it runs once at boot
        # and never again.
        self.assertNotIn("[Install]", units["netrune-prune.service"])

    def test_an_unknown_role_is_refused_rather_than_guessed(self):
        with self.assertRaises(ValueError):
            self.units("poller")

    def test_a_collector_generates_no_scrape_config_or_dashboards(self):
        from netops_platform.traffic_stack import ROLE_COLLECTOR, stack_files
        files = stack_files("127.0.0.1:9713", "http://127.0.0.1:8428", 10, "180d",
                            Path("/x"), role=ROLE_COLLECTOR)
        # Generating them and leaving them unused only invites someone to start
        # them.
        for path in files:
            with self.subTest(path=path.name):
                self.assertNotIn(path.suffix, {".yml", ".yaml", ".json"})
        self.assertTrue(all(p.suffix in {".service", ".timer", ".target"} for p in files))


class SubscribedRateTest(unittest.TestCase):
    """A port's line rate says what the hardware can carry. A subscription says
    what you are entitled to, and those are usually not the same number.

    A gigabit port carrying a 100M service reads 10% utilised at the exact
    moment the service is full. That is not a rounding problem, it is the wrong
    question, and it is why the WAN bars are drawn against the contract.
    """

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
            interface_name="Gi1/0/16", ifindex="24")

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def current(self):
        return self.monitor.get_watch(str(self.watch["watch_id"])) or {}

    def subscribe(self, down=None, up=None, faces_lan=False):
        self.monitor.set_subscription(str(self.watch["watch_id"]), down, up, faces_lan=faces_lan)
        return self.monitor.subscription(self.current())

    def test_a_rate_reads_the_way_a_contract_states_it(self):
        from netops_platform.traffic import parse_rate
        # Decimal multiples: a 100M service is 100,000,000 bits, not 104,857,600.
        for text, expected in (("100M", 100_000_000), ("100 Mbps", 100_000_000),
                               ("1.5G", 1_500_000_000), ("512k", 512_000),
                               ("20m", 20_000_000), ("100000000", 100_000_000)):
            with self.subTest(text=text):
                self.assertEqual(parse_rate(text), expected)

    def test_nonsense_is_refused_rather_than_guessed(self):
        from netops_platform.traffic import parse_rate
        for text in ("", "bogus", "0", "-5M", None):
            with self.subTest(text=text):
                self.assertIsNone(parse_rate(text))

    def test_an_unsubscribed_link_carries_no_service(self):
        self.assertEqual(self.monitor.subscription(self.current()), {})
        self.assertEqual(self.monitor.subscribed_watches(), [])

    def test_the_provider_facing_port_receives_the_download(self):
        """What the switch receives on the port reaching the provider came from
        the internet, so receive is download."""
        plan = self.subscribe(down=100_000_000, up=20_000_000, faces_lan=False)
        self.assertEqual(plan["downlink"], "receive")
        self.assertEqual(plan["receive_bps"], 100_000_000)
        self.assertEqual(plan["transmit_bps"], 20_000_000)

    def test_the_lan_facing_port_transmits_it(self):
        """Reading one as the other shows a full upload as a quiet download."""
        plan = self.subscribe(down=100_000_000, up=20_000_000, faces_lan=True)
        self.assertEqual(plan["downlink"], "transmit")
        self.assertEqual(plan["receive_bps"], 20_000_000)
        self.assertEqual(plan["transmit_bps"], 100_000_000)

    def test_the_subscription_reaches_the_exposition_as_the_contract_states_it(self):
        self.subscribe(down=100_000_000, up=20_000_000)
        with mock.patch.object(self.app, "capture", return_value=(0, LIVE_COUNTERS, "")):
            self.monitor.poll()
        lines = [l for l in MetricsExporter(self.monitor).render().splitlines()
                 if l.startswith("netrune_interface_subscribed_bits{")]
        self.assertEqual(len(lines), 2)
        self.assertTrue(any('direction="down"' in l and l.endswith(" 100000000") for l in lines))
        self.assertTrue(any('direction="up"' in l and l.endswith(" 20000000") for l in lines))

    def test_the_info_metric_says_which_counter_carries_download(self):
        """The dashboards cannot resolve up and down without it."""
        self.subscribe(down=100_000_000, faces_lan=True)
        with mock.patch.object(self.app, "capture", return_value=(0, LIVE_COUNTERS, "")):
            self.monitor.poll()
        info = next(l for l in MetricsExporter(self.monitor).render().splitlines()
                    if l.startswith("netrune_interface_info{"))
        self.assertIn('downlink="transmit"', info)
        self.assertIn('service="yes"', info)

    def test_clearing_a_subscription_leaves_the_link_watched(self):
        self.subscribe(down=100_000_000)
        self.monitor.set_subscription(str(self.watch["watch_id"]), None, None)
        self.assertEqual(self.monitor.subscription(self.current()), {})
        self.assertIsNotNone(self.monitor.get_watch(str(self.watch["watch_id"])))


class TargetMatchingTest(unittest.TestCase):
    """Naming one target when several switches share a port name."""

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
        # The situation that makes this necessary: the same port name on two
        # switches.
        self.a = self.monitor.add_watch("interface", device_ip="198.51.100.10",
                                        device_name="SITE-A-SW01",
                                        interface_name="Gi1/0/12", ifindex="20")
        self.b = self.monitor.add_watch("interface", device_ip="198.51.100.11",
                                        device_name="SITE-B-SW01",
                                        interface_name="Gi1/0/12", ifindex="20")

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def names(self, needle):
        return sorted(f"{w['device_name']} {w['interface_name']}"
                      for w in self.monitor.match_watches(needle))

    def test_a_port_name_alone_still_reaches_every_switch_with_it(self):
        self.assertEqual(len(self.names("Gi1/0/12")), 2)

    def test_a_switch_and_a_port_together_reach_exactly_one(self):
        """The fields are searched as one text and the device and its port are
        not adjacent in it, so every word has to match rather than the phrase."""
        self.assertEqual(self.names("SITE-A-SW01 Gi1/0/12"), ["SITE-A-SW01 Gi1/0/12"])
        self.assertEqual(self.names("SITE-B-SW01 Gi1/0/12"), ["SITE-B-SW01 Gi1/0/12"])

    def test_the_watch_id_reaches_exactly_one_whatever_else_is_true(self):
        matched = self.monitor.match_watches(str(self.a["watch_id"]))
        self.assertEqual([w["watch_id"] for w in matched], [self.a["watch_id"]])

    def test_a_chosen_name_is_a_way_to_name_a_target_too(self):
        self.monitor.set_display_name(str(self.b["watch_id"]), "ORANGE")
        self.assertEqual(self.names("ORANGE"), ["SITE-B-SW01 Gi1/0/12"])

    def test_an_operators_spelling_of_a_port_still_matches(self):
        self.assertEqual(len(self.names("gi 1/0/12")), 2)

    def test_a_subscription_can_name_one_of_two_identical_ports(self):
        self.monitor.set_subscription(str(self.a["watch_id"]), 100_000_000, 20_000_000)
        self.assertEqual([w["device_name"] for w in self.monitor.subscribed_watches()],
                         ["SITE-A-SW01"])


class HelpBrevityTest(unittest.TestCase):
    """An action list is scanned to find one action, not read."""

    def test_the_index_line_is_a_line(self):
        from netops_platform.core import GIST_WIDTH, HELP_TOPICS, action_gist
        for domain, topic in HELP_TOPICS.items():
            for action, doc in topic.get("actions", {}).items():
                with self.subTest(domain=domain, action=action):
                    self.assertLessEqual(len(action_gist(doc)), GIST_WIDTH + 4)

    def test_the_full_paragraph_survives_on_the_actions_own_page(self):
        """Brevity in the index must not cost the detail anywhere."""
        from netops_platform.core import HELP_TOPICS, action_gist
        watch = HELP_TOPICS["traffic"]["actions"]["watch"]
        self.assertGreater(len(watch["about"]), len(action_gist(watch)))
        self.assertIn("SNMP walk", watch["about"])

    def test_a_gist_is_used_where_one_is_written(self):
        from netops_platform.core import action_gist
        self.assertEqual(action_gist({"gist": "Short.", "about": "Much longer prose."}), "Short.")

    def test_the_first_sentence_stands_in_where_none_is(self):
        from netops_platform.core import action_gist
        self.assertEqual(
            action_gist({"about": "Does the thing. Then explains at length why."}),
            "Does the thing.")

    def test_a_full_stop_inside_a_version_does_not_end_the_sentence(self):
        from netops_platform.core import action_gist
        self.assertEqual(action_gist({"about": "Needs Python 3.11 or newer. And more."}),
                         "Needs Python 3.11 or newer.")


class UserManagerDiagnosisTest(unittest.TestCase):
    """Every component of the stack is a user service.

    When the manager they all live in is down, each fails separately with a
    message about a bus and a missing socket -- which describes the symptom, not
    the cause, and sends people to look at permissions. Linger being enabled is
    not the same as the manager having started: it can fail at boot and stay
    down.
    """

    def test_nothing_is_reported_when_the_manager_is_running(self):
        from netops_platform import traffic_cli
        with mock.patch.object(traffic_cli, "_run", return_value=(0, "active\n")):
            self.assertEqual(traffic_cli.user_manager_problem(), "")

    def test_a_failed_manager_is_named_along_with_the_command_that_starts_it(self):
        from netops_platform import traffic_cli

        def fake(command, timeout=0):
            return (0, "yes\n") if command[0] == "loginctl" else (3, "failed\n")

        with mock.patch.object(traffic_cli, "_run", side_effect=fake):
            problem = traffic_cli.user_manager_problem()
        self.assertIn("per-user systemd manager is not running", problem)
        self.assertIn(f"sudo systemctl start user@{os.getuid()}.service", problem)
        self.assertNotIn("Linger is also off", problem)

    def test_linger_being_off_as_well_is_said_too(self):
        """Starting it by hand fixes now; linger is what fixes the next reboot."""
        from netops_platform import traffic_cli

        def fake(command, timeout=0):
            return (0, "no\n") if command[0] == "loginctl" else (3, "failed\n")

        with mock.patch.object(traffic_cli, "_run", side_effect=fake):
            problem = traffic_cli.user_manager_problem()
        self.assertIn("enable-linger", problem)

    def test_the_opaque_bus_message_is_what_triggers_the_lookup(self):
        from netops_platform.traffic_cli import _NO_USER_BUS
        self.assertTrue(any(
            m in "Failed to connect to user scope bus via local transport: No such file"
            for m in _NO_USER_BUS))


class PollerNeedsOnlyACommunityTest(unittest.TestCase):
    """A machine whose whole job is reading counters should need what that
    takes and nothing else.

    Reading an interface counter over SNMP needs a community. It does not need
    an inventory, a subnet list, a platform detection, or SSH credentials to the
    switch -- those belong to the machine that explores and configures the
    estate. Requiring them on a poller is asking for a full install to do a
    fraction of the work.
    """

    def test_snmp_modes_skip_platform_detection_entirely(self):
        """verify_target falls back to an SSH probe for an unknown address,
        which is what dragged SSH credentials into a counter read."""
        control = (ROOT / "netops-control").read_text()
        dispatch = next(line for line in control.splitlines()
                        if "verify_target \"$ip\"" in line and line.strip().startswith("if"))
        self.assertIn('"$MODE" == snmp-*', dispatch)

    def test_an_address_is_watchable_with_no_inventory(self):
        from netops_platform.traffic_cli import _is_address
        self.assertTrue(_is_address("198.51.100.10"))

    def test_device_health_falls_back_to_sysdescr_for_the_platform(self):
        """Otherwise CPU and memory silently report nothing on a poller, which
        has no inventory to name the platform."""
        control = (ROOT / "netops-control").read_text()
        health = control[control.index("snmp_device_health() {"):]
        health = health[:health.index("\nperform_task()")]
        derive = health.index("netops_platform_family \"$(_health_get 'sysDescr.0')\"")
        vendor = health.index("cisco-ios)")
        self.assertLess(derive, vendor, "the family must be settled before the OIDs are chosen")


class OneCommandSetupTest(unittest.TestCase):
    """A working install should take the facts that differ and nothing else.

    Standing a poller up by hand was around twenty commands. Every one of them
    was mechanism -- create a profile, select it, set an identity, migrate,
    write a credentials file, generate units, install them, reload, enable,
    enable linger. None of it was a decision only the operator could make. What
    genuinely differs between two installs is the community, what the machine is
    for, and what it should watch.
    """

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        base = Path(self.temp.name)
        self.env = mock.patch.dict(os.environ, {
            "NETOPS_CONFIG_DIR": str(base / "config"),
            "NETOPS_CACHE_DIR": str(base / "cache"),
            "NETOPS_SQLITE_DB": str(base / "cache" / "netops.sqlite3"),
            "NETOPS_BACKUP_DIR": str(base / "backups"),
            "NETOPS_STATE_DIR": str(base / "state"),
            "NETOPS_PROGRESS": "0",
        }, clear=False)
        self.env.start()
        self.app = netops.App(ROOT)

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def run_cli(self, args):
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer), contextlib.redirect_stderr(buffer):
            code = self.app.dispatch([*args, "--plain", "--no-color"])
        return code, buffer.getvalue()

    def test_a_role_is_required_and_the_choices_are_named(self):
        code, output = self.run_cli(["setup"])
        self.assertEqual(code, netops.VALIDATION)
        self.assertIn("poller", output)
        self.assertIn("local", output)

    def test_a_dry_run_says_what_it_would_do_and_does_none_of_it(self):
        code, output = self.run_cli(["setup", "poller", "--community", "x", "--dry-run"])
        self.assertEqual(code, netops.SUCCESS)
        self.assertIn("Would set this machine up", output)
        self.assertFalse((Path(self.app.paths.config_dir) / ".env").exists())

    def test_the_community_lands_where_the_snmp_helpers_read_it(self):
        """Hand-writing this file was a step in the guide, which is one step too
        many for the single thing every install needs."""
        written = self.app.write_snmp_community("s3cret")
        self.assertTrue(written.is_file())
        self.assertIn('communities="s3cret"', written.read_text())
        self.assertIn('snmp_version="v2c"', written.read_text())
        # It is a credential; it must not be world-readable.
        self.assertEqual(oct(written.stat().st_mode)[-3:], "600")

    def test_rewriting_the_community_keeps_other_settings(self):
        path = Path(self.app.paths.config_dir)
        path.mkdir(parents=True, exist_ok=True)
        (path / ".env").write_text('ssh_user="someone"\ncommunities="old"\n')
        self.app.write_snmp_community("new")
        body = (path / ".env").read_text()
        self.assertIn('ssh_user="someone"', body)
        self.assertIn('communities="new"', body)
        self.assertNotIn('"old"', body)

    def test_publishing_beyond_this_machine_needs_saying_so(self):
        """It serves readings and dashboards to anything that can reach the
        address, and there is no login in front of them."""
        code, output = self.run_cli(["setup", "local", "--community", "x", "--publish", "0.0.0.0"])
        self.assertEqual(code, netops.VALIDATION)
        self.assertIn("--confirm", output)

    def test_a_missing_community_is_reported_rather_than_assumed(self):
        code, output = self.run_cli(["setup", "poller", "--dry-run"])
        self.assertEqual(code, netops.SUCCESS)
        self.assertIn("not given", output)


class PublishBindingTest(unittest.TestCase):
    """Loopback unless an operator says otherwise, and then everywhere it needs."""

    def units(self, publish=""):
        from netops_platform.traffic_stack import stack_files
        with tempfile.TemporaryDirectory() as temp:
            files = stack_files(f"{publish or '127.0.0.1'}:9713", "http://127.0.0.1:8428", 10,
                                "90d", Path(temp), grapher_bind=publish)
            return {p.name: b for p, b in files.items()}

    def test_loopback_by_default(self):
        units = self.units()
        self.assertIn("--bind 127.0.0.1:9713", units["netrune-exporter.service"])
        self.assertIn("GF_SERVER_HTTP_ADDR=127.0.0.1", units["netrune-grafana.service"])

    def test_publishing_reaches_the_exposition_and_the_dashboards(self):
        units = self.units("0.0.0.0")
        self.assertIn("--bind 0.0.0.0:9713", units["netrune-exporter.service"])
        self.assertIn("GF_SERVER_HTTP_ADDR=0.0.0.0", units["netrune-grafana.service"])

    def test_storage_stays_on_loopback_either_way(self):
        """Grafana proxies its queries server-side, so nothing outside this
        machine has any reason to reach the database directly."""
        for publish in ("", "0.0.0.0"):
            with self.subTest(publish=publish or "loopback"):
                units = self.units(publish)
                self.assertIn("-httpListenAddr=127.0.0.1:8428",
                              units["netrune-victoriametrics.service"])


class ScheduledExportTest(unittest.TestCase):
    """A poller nobody can reach still has to hand its readings over."""

    def units(self, export_path=""):
        from netops_platform.traffic_stack import ROLE_COLLECTOR, systemd_units
        return systemd_units(Path("/x"), "127.0.0.1:9713", "http://127.0.0.1:8428", "180d",
                             "netrune", "", "", role=ROLE_COLLECTOR, export_path=export_path)

    def test_nothing_is_generated_unless_a_path_is_given(self):
        self.assertNotIn("netrune-export.timer", self.units())

    def test_a_path_produces_a_timer_and_the_export_it_runs(self):
        units = self.units("/srv/share/poller.jsonl")
        self.assertIn("netrune-export.timer", units)
        self.assertIn("traffic export", units["netrune-export.service"])
        self.assertIn("/srv/share/poller.jsonl", units["netrune-export.service"])
        self.assertIn("WantedBy=timers.target", units["netrune-export.timer"])

    def test_the_file_is_moved_into_place_rather_than_written_in_place(self):
        """Anything watching the directory copies the moment it changes, and a
        half-written export is worse than a slightly old one."""
        service = self.units("/srv/share/poller.jsonl")["netrune-export.service"]
        self.assertIn('.part"', service)
        self.assertIn("mv ", service)

    def test_the_export_window_outlasts_the_interval_between_runs(self):
        """Overlap costs only the time to re-read it, because merging is
        idempotent. A gap costs readings nobody can get back."""
        from netops_platform.traffic_stack import systemd_units
        from netops_platform.traffic_stack import ROLE_COLLECTOR
        units = systemd_units(Path("/x"), "127.0.0.1:9713", "http://127.0.0.1:8428", "180d",
                              "netrune", "", "", role=ROLE_COLLECTOR,
                              export_path="/tmp/x.jsonl", export_every="15min",
                              export_window="48h")
        self.assertIn("--since 48h", units["netrune-export.service"])
        self.assertIn("OnUnitActiveSec=15min", units["netrune-export.timer"])


class ConfigWriteVisibilityTest(unittest.TestCase):
    """A setting written and then acted on in the same process."""

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

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def test_a_written_setting_is_visible_without_reloading(self):
        """'setup' writes a setting and then runs the command that reads it.
        Reading the copy loaded at startup meant acting on the old value."""
        self.app._write_profile_config_value("traffic_export_path", "/srv/x.jsonl")
        self.assertEqual(self.app.config.public.get("traffic_export_path"), "/srv/x.jsonl")

    def test_unsetting_removes_it_from_the_copy_too(self):
        self.app._write_profile_config_value("traffic_export_path", "/srv/x.jsonl")
        self.app._write_profile_config_value("traffic_export_path", None)
        self.assertIsNone(self.app.config.public.get("traffic_export_path"))


class PushHandoffTest(unittest.TestCase):
    """The other direction a poller can hand its readings over.

    Pulling fetches them over SSH and needs a path inward. Pushing needs a path
    outward. A network usually permits one or the other, and until now only one
    was possible -- and pulled readings never reached storage at all, because
    the exposition deliberately publishes only what this collector owns.
    """

    def units(self, push_url="", export_path=""):
        from netops_platform.traffic_stack import ROLE_COLLECTOR, systemd_units
        return systemd_units(Path("/x"), "127.0.0.1:9713", "http://127.0.0.1:8428", "180d",
                             "netrune", "", "", role=ROLE_COLLECTOR,
                             push_url=push_url, export_path=export_path)

    def test_nothing_is_generated_unless_asked_for(self):
        units = self.units()
        self.assertNotIn("netrune-push.timer", units)
        self.assertNotIn("netrune-export.timer", units)

    def test_a_push_url_produces_a_timer_that_pushes(self):
        units = self.units(push_url="http://198.51.100.5:8428")
        self.assertIn("netrune-push.timer", units)
        self.assertIn("traffic push --to http://198.51.100.5:8428",
                      units["netrune-push.service"])

    def test_both_ways_can_be_configured_at_once(self):
        """A file for the record, a push for the dashboards; neither excludes
        the other."""
        units = self.units(push_url="http://198.51.100.5:8428", export_path="/srv/x.jsonl")
        self.assertIn("netrune-push.timer", units)
        self.assertIn("netrune-export.timer", units)

    def test_storage_stays_shut_until_told_otherwise(self):
        """Publishing dashboards is read-only exposure. Accepting a push lets
        anything that can reach the address write into the store."""
        from netops_platform.traffic_stack import systemd_units
        closed = systemd_units(Path("/x"), "127.0.0.1:9713", "http://127.0.0.1:8428",
                               "180d", "netrune", "vm", "vmalert")
        self.assertIn("-httpListenAddr=127.0.0.1:8428",
                      closed["netrune-victoriametrics.service"])
        opened = systemd_units(Path("/x"), "127.0.0.1:9713", "http://127.0.0.1:8428",
                               "180d", "netrune", "vm", "vmalert",
                               storage_bind="0.0.0.0:8428")
        self.assertIn("-httpListenAddr=0.0.0.0:8428",
                      opened["netrune-victoriametrics.service"])

    def test_accepting_a_push_requires_a_credential_loopback_does_not(self):
        """VictoriaMetrics has no auth of its own: opening it to the network
        without a credential would expose its full query/import/admin API to
        anything that can reach the address, not just the push it was opened
        for."""
        from netops_platform.traffic_stack import VM_CREDENTIAL_FILE, VM_CREDENTIAL_USER, systemd_units
        closed = systemd_units(Path("/x"), "127.0.0.1:9713", "http://127.0.0.1:8428",
                               "180d", "netrune", "vm", "vmalert")
        self.assertNotIn("-httpAuth", closed["netrune-victoriametrics.service"])
        root = Path("/stack-root")
        opened = systemd_units(root, "127.0.0.1:9713", "http://127.0.0.1:8428",
                               "180d", "netrune", "vm", "vmalert",
                               storage_bind="0.0.0.0:8428")
        unit = opened["netrune-victoriametrics.service"]
        self.assertIn(f"-httpAuth.username={VM_CREDENTIAL_USER}", unit)
        self.assertIn(f"-httpAuth.password=file://{root / VM_CREDENTIAL_FILE}", unit)

    def test_the_push_credential_is_generated_once_and_kept_across_regeneration(self):
        """Re-running `stack init` must not silently invalidate every remote
        poller's already-distributed push URL."""
        from netops_platform.traffic_stack import VM_CREDENTIAL_FILE, _victoriametrics_credential
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = _victoriametrics_credential(root)
            (root / VM_CREDENTIAL_FILE).write_text(first, encoding="utf-8")
            second = _victoriametrics_credential(root)
            self.assertEqual(first, second)
            self.assertTrue(first)


class ReplayAfterAnOutageTest(unittest.TestCase):
    """A poller kept polling while the other end was off.

    Sending only what is true now would draw the outage as a hole, which is the
    one thing a poller running through it should prevent. So a reading carries
    the time it was taken, and the collector remembers where it got to.
    """

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
            interface_name="Gi1/0/16", ifindex="24")

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def log(self, counter, at, value):
        self.app.state.execute(
            "INSERT OR REPLACE INTO traffic_counter_log"
            "(watch_id,counter,observed_at,value,collector) VALUES(?,?,?,?,?)",
            (self.watch["watch_id"], counter, at, value, "site-a-poller"))

    def test_a_replayed_reading_carries_the_time_it_was_taken(self):
        base = int(time.time()) - 3600
        for step in range(4):
            self.log("in_octets", base + step * 60, 1_000_000 * (step + 1))
        body = MetricsExporter(self.monitor).render_replay(base - 60)
        lines = [l for l in body.splitlines() if not l.startswith("#")]
        self.assertEqual(len(lines), 4)
        stamps = sorted(int(l.rsplit(" ", 1)[1]) for l in lines)
        # Milliseconds, and in the past -- not stamped on arrival.
        self.assertEqual(stamps[0], (base) * 1000)
        self.assertLess(stamps[-1], int(time.time()) * 1000)

    def test_only_readings_after_the_window_are_replayed(self):
        base = int(time.time()) - 3600
        self.log("in_octets", base, 1)
        self.log("in_octets", base + 600, 2)
        body = MetricsExporter(self.monitor).render_replay(base + 300)
        self.assertEqual(len([l for l in body.splitlines() if not l.startswith("#")]), 1)

    def test_nothing_to_replay_renders_nothing(self):
        self.assertEqual(MetricsExporter(self.monitor).render_replay(int(time.time())), "")

    def test_a_replayed_counter_is_still_typed_as_a_counter(self):
        """Otherwise rate() over the replayed span is meaningless."""
        self.log("in_octets", int(time.time()) - 120, 5)
        body = MetricsExporter(self.monitor).render_replay(int(time.time()) - 300)
        self.assertIn("# TYPE netrune_interface_receive_bytes_total counter", body)

    def test_a_pulled_watch_is_never_replayed(self):
        """Two collectors would otherwise each insist on the other's history."""
        self.monitor.set_owner(str(self.watch["watch_id"]), "someone-else")
        self.log("in_octets", int(time.time()) - 120, 5)
        self.assertEqual(MetricsExporter(self.monitor).render_replay(int(time.time()) - 300), "")

    def test_the_log_is_written_at_its_own_cadence(self):
        """A rate is derived over minutes, so logging every ten-second poll
        multiplies rows for resolution nothing reads."""
        from netops_platform.traffic import COUNTER_LOG_INTERVAL
        self.assertGreaterEqual(COUNTER_LOG_INTERVAL, 30)
        previous = {"in_octets": {"observed_at": 1000, "value": 1}}
        self.monitor._log_counter(str(self.watch["watch_id"]), "in_octets", 1010, 2,
                                  "local", previous)
        self.assertIsNone(self.app.state.one(
            "SELECT 1 AS hit FROM traffic_counter_log WHERE observed_at=1010"))
        self.monitor._log_counter(str(self.watch["watch_id"]), "in_octets",
                                  1000 + COUNTER_LOG_INTERVAL, 2, "local", previous)
        self.assertIsNotNone(self.app.state.one(
            "SELECT 1 AS hit FROM traffic_counter_log WHERE observed_at=?",
            (1000 + COUNTER_LOG_INTERVAL,)))

    def test_the_log_is_kept_only_long_enough_to_cover_an_outage(self):
        """Raw counters at polling resolution are the bulkiest thing stored,
        and their purpose is catching up, not being a history."""
        self.assertLessEqual(self.app.state.RETENTION_DEFAULTS["traffic_counter_log"], 31)
        self.assertGreater(self.app.state.RETENTION_DEFAULTS["traffic_samples"],
                           self.app.state.RETENTION_DEFAULTS["traffic_counter_log"])

    def test_a_marker_survives_between_runs(self):
        self.app.state.set_marker("push:http://x", "12345")
        self.assertEqual(self.app.state.get_marker("push:http://x"), "12345")
        self.assertEqual(self.app.state.get_marker("push:http://never"), "")


class PushCredentialTest(unittest.TestCase):
    """A credential-gated push URL is the one thing sent to urlopen() that
    must never be echoed back to the operator as typed."""

    def test_no_credentials_passes_the_url_through_unchanged(self):
        from netops_platform.traffic_cli import _split_push_credentials
        url, header = _split_push_credentials("http://198.51.100.5:8428")
        self.assertEqual(url, "http://198.51.100.5:8428")
        self.assertEqual(header, "")

    def test_embedded_credentials_become_a_basic_auth_header_not_a_hostname(self):
        # urllib would otherwise try to resolve 'netrune:s3cr3t@host' as a
        # hostname verbatim, which fails, so this has to be split out first.
        from netops_platform.traffic_cli import _split_push_credentials
        import base64
        url, header = _split_push_credentials("http://netrune:s3cr3t@198.51.100.5:8428")
        self.assertEqual(url, "http://198.51.100.5:8428")
        self.assertEqual(header, "Basic " + base64.b64encode(b"netrune:s3cr3t").decode("ascii"))


class PushLabelParityTest(unittest.TestCase):
    """A push has to produce the series a scrape would, not a parallel set.

    Storage attaches job, instance and source when it scrapes. Readings written
    by any other route and missing those become a second series for every port,
    identical except for scrape plumbing. A vector match on the labels that
    identify a port -- which every throughput query uses -- then finds two
    candidates and refuses to evaluate, and every chart on the board goes blank
    at once. Nothing in the exposition looks wrong; the query simply stops
    working.
    """

    def test_the_scrape_labels_are_named_once(self):
        from netops_platform.traffic_stack import (
            SCRAPE_INSTANCE, SCRAPE_JOB, SCRAPE_SOURCE, scrape_config)
        config = scrape_config("127.0.0.1:9713", 10)
        self.assertIn(f"job_name: {SCRAPE_JOB}", config)
        self.assertIn(f"instance: {SCRAPE_INSTANCE}", config)
        self.assertIn(f"source: {SCRAPE_SOURCE}", config)

    def test_push_stamps_every_label_the_scrape_adds(self):
        source = (ROOT / "netops_platform" / "traffic_cli.py").read_text()
        push = source[source.index("def _cmd_push():"):]
        push = push[:push.index("return SUCCESS")]
        for label in ("SCRAPE_JOB", "SCRAPE_INSTANCE", "SCRAPE_SOURCE"):
            with self.subTest(label=label):
                self.assertIn(label, push)
        self.assertIn("extra_label", push)

    def test_the_scrape_and_the_push_cannot_drift(self):
        """Both read the same constants, so a change to one moves the other."""
        stack = (ROOT / "netops_platform" / "traffic_stack.py").read_text()
        for constant in ("SCRAPE_JOB", "SCRAPE_INSTANCE", "SCRAPE_SOURCE"):
            with self.subTest(constant=constant):
                self.assertIn(f"{constant} = ", stack)
                # Used by the generator rather than repeated as a literal.
                self.assertIn("{" + constant + "}", stack)
