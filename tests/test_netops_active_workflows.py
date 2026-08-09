import contextlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

import netops_core as netops


ROOT = Path(__file__).resolve().parents[1]


class NetOpsActiveWorkflowTest(unittest.TestCase):
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

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def add_device(self, ip, name, platform="Cisco", model="C9300"):
        self.app.state.execute(
            "INSERT INTO devices(ip,hostname,platform,model,serial,mac,source,last_seen,status) VALUES(?,?,?,?,?,?,?,?,?)",
            (ip, name, platform, model, f"SERIAL-{ip}", "", "test", 1000, "ONLINE"),
        )

    def test_global_depth_and_node_budget_are_bounded(self):
        opts, rest = netops.parse_global(["vlan", "propagation", "SW1", "131", "--depth", "99", "--max-nodes", "999", "--refresh-neighbors"])
        self.assertEqual(rest, ["vlan", "propagation", "SW1", "131"])
        self.assertEqual(opts.depth, 16)
        self.assertEqual(opts.max_nodes, 256)
        self.assertTrue(opts.refresh_neighbors)

    def test_legacy_jobs_table_is_upgraded_without_losing_history(self):
        with self.app.state.connect() as con:
            con.execute("DROP TABLE jobs")
            con.execute(
                "CREATE TABLE jobs(id TEXT PRIMARY KEY,action TEXT NOT NULL,command TEXT NOT NULL,status TEXT NOT NULL,"
                "started_at INTEGER,finished_at INTEGER,exit_code INTEGER,read_only INTEGER NOT NULL DEFAULT 1)"
            )
            con.execute(
                "INSERT INTO jobs(id,action,command,status,started_at,finished_at,exit_code,read_only) VALUES(?,?,?,?,?,?,?,?)",
                ("legacy-job", "db-status", "netops db status", "completed", 1704067200, 1704067201, 0, 1),
            )
        repaired = netops.State(self.app.paths)
        columns = {row["name"] for row in repaired.rows("PRAGMA table_info(jobs)")}
        row = repaired.one("SELECT * FROM jobs WHERE id='legacy-job'")
        self.assertTrue({"created_at", "writes_local"}.issubset(columns))
        self.assertEqual(row["created_at"], 1704067200)
        self.assertEqual(row["writes_local"], 0)

    def test_job_sse_replays_once_and_closes_on_completion(self):
        created_at = 1704067200
        with self.app.state.connect() as con:
            con.execute(
                "INSERT INTO jobs(id,action,command,status,created_at,started_at,finished_at,exit_code,read_only,writes_local) VALUES(?,?,?,?,?,?,?,?,?,?)",
                ("sse-job", "db-status", "netops db status", "running", created_at, created_at, None, None, 1, 0),
            )
        self.app.add_job_log("sse-job", "system", "started: netops db status")
        self.app.add_job_log("sse-job", "stdout", "Schema: 9 (expected 9)")
        self.app.add_job_log("sse-job", "system", "finished with exit code 0")
        self.app.set_job_status("sse-job", "completed", 0)

        handler_type = self.app.make_handler()
        handler = handler_type.__new__(handler_type)
        handler.wfile = io.BytesIO()
        handler.close_connection = False
        handler.send_response = lambda status: None
        handler.send_header = lambda name, value: None
        handler.end_headers = lambda: None
        handler.send_events("sse-job", 0)
        stream = handler.wfile.getvalue().decode()
        detail = {
            "job": self.app.state.one("SELECT * FROM jobs WHERE id='sse-job'"),
            "logs": self.app.state.rows("SELECT id,created_at,stream,line FROM job_logs WHERE job_id='sse-job' ORDER BY id"),
        }
        events = [json.loads(line[6:]) for line in stream.splitlines() if line.startswith("data: ")]
        event_ids = [row["id"] for row in events if row.get("id")]
        self.assertEqual(detail["job"]["status"], "completed")
        self.assertEqual(detail["job"]["exit_code"], 0)
        self.assertEqual(event_ids, [row["id"] for row in detail["logs"]])
        self.assertEqual(len(event_ids), len(set(event_ids)))
        self.assertTrue(all(row.get("created_at_iso", "").endswith("Z") for row in events))
        self.assertEqual(events[-1]["line"], "finished with exit code 0")
        self.assertTrue(handler.close_connection)

        resumed = handler_type.__new__(handler_type)
        resumed.wfile = io.BytesIO()
        resumed.close_connection = False
        resumed.send_response = lambda status: None
        resumed.send_header = lambda name, value: None
        resumed.end_headers = lambda: None
        resumed.send_events("sse-job", max(event_ids))
        self.assertEqual(resumed.wfile.getvalue(), b"")
        self.assertTrue(resumed.close_connection)

    def test_queued_job_can_be_cancelled_before_a_process_is_spawned(self):
        marker = Path(self.temp.name) / "queued-job-ran"
        command = [sys.executable, "-c", f"from pathlib import Path; Path({str(marker)!r}).touch()"]
        spec = netops.CommandSpec("fixture", "Fixture", command, "test fixture")
        self.app.sem = threading.Semaphore(0)
        with mock.patch.object(self.app, "command_spec", return_value=spec), mock.patch.object(
            self.app, "command_for_action", return_value=(command, True, False)
        ):
            created = self.app.create_job("fixture", {})
        jid = created["id"]
        done = self.app.jobs[jid]["done"]
        cancelled, _ = self.app.cancel_job(jid)
        self.app.sem.release()
        self.assertTrue(done.wait(3), "queued worker did not finish after cancellation")
        row = self.app.state.one("SELECT status,exit_code FROM jobs WHERE id=?", (jid,))
        self.assertTrue(cancelled)
        self.assertEqual(row, {"status": "cancelled", "exit_code": 143})
        self.assertFalse(marker.exists())

    def test_running_job_cancellation_is_not_overwritten_as_failed(self):
        command = [sys.executable, "-c", "import time; print('ready', flush=True); time.sleep(30)"]
        spec = netops.CommandSpec("fixture", "Fixture", command, "test fixture")
        with mock.patch.object(self.app, "command_spec", return_value=spec), mock.patch.object(
            self.app, "command_for_action", return_value=(command, True, False)
        ):
            created = self.app.create_job("fixture", {})
        jid = created["id"]
        deadline = time.monotonic() + 3
        proc = None
        while time.monotonic() < deadline:
            with self.app.lock:
                proc = self.app.jobs[jid].get("process")
            if proc is not None:
                break
            time.sleep(0.02)
        self.assertIsNotNone(proc, "job process never started")
        cancelled, _ = self.app.cancel_job(jid)
        self.assertTrue(self.app.jobs[jid]["done"].wait(5), "cancelled worker did not finish")
        row = self.app.state.one("SELECT status,exit_code FROM jobs WHERE id=?", (jid,))
        logs = self.app.state.rows("SELECT stream,line FROM job_logs WHERE job_id=? ORDER BY id", (jid,))
        self.assertTrue(cancelled)
        self.assertEqual(row, {"status": "cancelled", "exit_code": 143})
        self.assertIsNotNone(proc.poll())
        self.assertTrue(any("cancelled by operator" in item["line"] for item in logs))
        self.assertFalse(any("finished with exit code" in item["line"] for item in logs))

    def test_shutdown_cancels_active_jobs_and_rejects_new_work(self):
        command = [sys.executable, "-c", "import time; time.sleep(30)"]
        spec = netops.CommandSpec("fixture", "Fixture", command, "test fixture")
        with mock.patch.object(self.app, "command_spec", return_value=spec), mock.patch.object(
            self.app, "command_for_action", return_value=(command, True, False)
        ):
            created = self.app.create_job("fixture", {})
            jid = created["id"]
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                with self.app.lock:
                    if self.app.jobs[jid].get("process") is not None:
                        break
                time.sleep(0.02)
            stopped = self.app.shutdown_jobs(wait=3)
            with self.assertRaisesRegex(RuntimeError, "stopping"):
                self.app.create_job("fixture", {})
        row = self.app.state.one("SELECT status,exit_code FROM jobs WHERE id=?", (jid,))
        self.assertEqual(stopped, 1)
        self.assertEqual(row, {"status": "cancelled", "exit_code": 143})

    def test_new_network_dry_runs_do_not_open_transports(self):
        self.add_device("192.0.2.1", "CORE01")
        self.app.config.public["core_switch_ip"] = "192.0.2.1"
        with mock.patch.object(self.app, "capture") as capture, mock.patch.object(self.app, "emit") as emit:
            vlan_rc = self.app.vlan_cascade("CORE01", 131, "propagation", netops.GlobalOptions(depth=3, dry_run=True))
            ping_rc = self.app.point_of_truth_ping("192.0.2.50", netops.GlobalOptions(dry_run=True), count=5)
            mac_rc = self.app.locate_mac_live("02:00:00:00:00:25", netops.GlobalOptions(dry_run=True), "CORE01")
        self.assertEqual((vlan_rc, ping_rc, mac_rc), (netops.SUCCESS, netops.SUCCESS, netops.SUCCESS))
        capture.assert_not_called()
        self.assertEqual(emit.call_count, 3)

    def test_diagnostic_dry_runs_and_cable_confirmation_gate(self):
        self.add_device("192.0.2.1", "SW1")
        with mock.patch.object(self.app, "capture") as capture, mock.patch.object(self.app, "emit"):
            throughput = self.app.throughput_diagnostic("192.0.2.20", 5201, 10, 1, "both", "", netops.GlobalOptions(dry_run=True))
            port = self.app.port_health_diagnostic("SW1", "Gi1/0/7", 5, 1000, netops.GlobalOptions(dry_run=True))
            cable_preview = self.app.cable_diagnostic("SW1", "Gi1/0/7", True, 8, netops.GlobalOptions(dry_run=True))
            cable_blocked = self.app.cable_diagnostic("SW1", "Gi1/0/7", True, 8, netops.GlobalOptions())
        self.assertEqual((throughput, port, cable_preview), (netops.SUCCESS, netops.SUCCESS, netops.SUCCESS))
        self.assertEqual(cable_blocked, netops.CONFIRM_REQUIRED)
        capture.assert_not_called()

    def test_port_health_records_only_active_counter_increases_as_findings(self):
        self.add_device("192.0.2.1", "SW1")
        baseline = "GigabitEthernet1/0/7 is up, line protocol is up (connected)\nFull-duplex, 1000Mb/s\n10 input errors, 2 CRC, 0 frame, 0 overrun, 0 ignored\n0 output errors, 0 collisions, 0 interface resets"
        current = "GigabitEthernet1/0/7 is up, line protocol is up (connected)\nFull-duplex, 1000Mb/s\n11 input errors, 4 CRC, 0 frame, 0 overrun, 0 ignored\n0 output errors, 0 collisions, 0 interface resets"
        with mock.patch.object(self.app, "capture", side_effect=[(0, baseline, ""), (0, current, "")]), mock.patch.object(self.app, "emit"):
            rc = self.app.port_health_diagnostic("SW1", "Gi1/0/7", 0, 1000, netops.GlobalOptions())
        self.assertEqual(rc, netops.PARTIAL)
        record = self.app.state.one("SELECT * FROM diagnostic_runs WHERE kind='port-health' ORDER BY id DESC LIMIT 1")
        payload = json.loads(record["raw_json"])
        self.assertEqual(payload["counter_deltas"]["crc_errors"], 2)
        self.assertTrue(any(row.get("counter") == "crc_errors" for row in payload["findings"]))
        self.assertTrue(record["created_at"] > 0)

    def test_port_health_skips_wait_when_baseline_cannot_be_parsed(self):
        self.add_device("192.0.2.1", "SW1")
        current = "GigabitEthernet1/0/7 is up, line protocol is up (connected)\nFull-duplex, 1000Mb/s\n0 input errors, 0 CRC\n0 output errors, 0 collisions"
        with mock.patch.object(self.app, "capture", side_effect=[(0, "unrecognized output", ""), (0, current, "")]), mock.patch.object(
            netops.time, "sleep"
        ) as sleep, mock.patch.object(self.app, "emit") as emit:
            rc = self.app.port_health_diagnostic("SW1", "Gi1/0/7", 30, 1000, netops.GlobalOptions())
        payload = emit.call_args.args[0]
        self.assertEqual(rc, netops.PARTIAL)
        sleep.assert_not_called()
        self.assertEqual(payload["sample_seconds"], 0)
        self.assertTrue(any(row["code"] == "BASELINE_UNAVAILABLE" for row in payload["findings"]))

    def test_port_health_accepts_parsed_report_from_nonzero_helper(self):
        self.add_device("192.0.2.1", "SW1")
        report = "GigabitEthernet1/0/7 is up, line protocol is up (connected)\nFull-duplex, 1000Mb/s\n0 input errors, 0 CRC\n0 output errors, 0 collisions"
        with mock.patch.object(self.app, "capture", side_effect=[(1, report, ""), (1, report, "")]), mock.patch.object(self.app, "emit") as emit:
            rc = self.app.port_health_diagnostic("SW1", "Gi1/0/7", 0, 1000, netops.GlobalOptions())
        payload = emit.call_args.args[0]
        self.assertEqual(rc, netops.SUCCESS)
        self.assertEqual(payload["status"], "HEALTHY")
        self.assertTrue(payload["helper_exit_ignored"])

    def test_active_cable_test_refuses_aruba_optical_port(self):
        self.add_device("192.0.2.2", "ARUBA1", platform="Aruba", model="JL258A")
        detailed = "Link Status : Up\nPort Enabled : Yes\nFCS Rx : 0"
        brief = "9 1000LX | No Yes Up 1000FDx NA off 0"
        with mock.patch.object(self.app, "capture", side_effect=[(0, detailed, ""), (0, brief, "")]) as capture, mock.patch.object(self.app, "emit"):
            rc = self.app.cable_diagnostic("ARUBA1", "9", True, 8, netops.GlobalOptions(confirm=True))
        self.assertEqual(rc, netops.UNSUPPORTED)
        self.assertEqual(capture.call_count, 2)

    def test_active_cable_test_stops_when_media_precheck_fails(self):
        self.add_device("192.0.2.1", "SW1")
        with mock.patch.object(self.app, "capture", return_value=(1, "", "connection timed out")) as capture, mock.patch.object(
            netops.time, "sleep"
        ) as sleep, mock.patch.object(self.app, "emit") as emit:
            rc = self.app.cable_diagnostic("SW1", "Gi1/0/7", True, 8, netops.GlobalOptions(confirm=True))
        payload = emit.call_args.args[0]
        self.assertEqual(rc, netops.PARTIAL)
        self.assertEqual(capture.call_count, 1)
        sleep.assert_not_called()
        self.assertIn("not started", payload["reason"])

    def test_cable_diagnostic_accepts_parsed_result_from_nonzero_helper(self):
        self.add_device("192.0.2.1", "SW1")
        report = "Pair A 12 +/- 1 meters Pair B Normal\nPair B 12 +/- 1 meters Pair A Good"
        with mock.patch.object(self.app, "capture", return_value=(1, report, "wrapper exited late")), mock.patch.object(self.app, "emit") as emit:
            rc = self.app.cable_diagnostic("SW1", "Gi1/0/7", False, 8, netops.GlobalOptions())
        payload = emit.call_args.args[0]
        self.assertEqual(rc, netops.SUCCESS)
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["helper_exit_ignored"])

    def test_throughput_rejects_success_json_from_failed_iperf_process(self):
        result = {
            "start": {"test_start": {"protocol": "TCP", "duration": 2, "num_streams": 1}, "connected": [{}]},
            "end": {"sum_sent": {"retransmits": 0}, "sum_received": {"seconds": 2, "bytes": 1000, "bits_per_second": 4000}},
        }
        with mock.patch.object(netops.shutil, "which", return_value="/usr/bin/iperf3"), mock.patch.object(
            self.app, "capture", return_value=(1, json.dumps(result), "")
        ), mock.patch.object(self.app, "emit") as emit:
            rc = self.app.throughput_diagnostic("192.0.2.20", 5201, 2, 1, "upload", "", netops.GlobalOptions())
        payload = emit.call_args.args[0]
        self.assertEqual(rc, netops.PARTIAL)
        self.assertFalse(payload["ok"])
        self.assertTrue(payload["results"][0]["backend_reported_ok"])

    def test_speed_result_is_persisted_with_standard_chronology(self):
        fixture = {"ok": True, "observed_at": 1704067200, "scope": "netops-host-to-internet", "path": {"interface": "eth0"}, "tls": {"verified": True, "trust_source": "test"}, "download_mbps": {"sustained": 100.0}, "upload_mbps": {"sustained": 40.0}, "latency_ms": {"idle": 2.0, "loaded_download": 8.0, "loaded_upload": 6.0}, "packet_loss_pct": 0.0, "reliability": {"rating": "high"}}
        with mock.patch.object(self.app, "capture_streamed", return_value=(0, json.dumps(fixture), "")) as capture, mock.patch.object(self.app, "emit"):
            rc = self.app.internet_speed_diagnostic(2, "", netops.GlobalOptions())
        self.assertEqual(rc, netops.SUCCESS)
        self.assertIn("--profile", capture.call_args.args[0])
        self.assertIn("balanced", capture.call_args.args[0])
        payload = self.app.diagnostics_payload()
        self.assertEqual(payload["summary"]["latest_speed"]["recorded_at_iso"], "2024-01-01T00:00:00Z")
        self.assertEqual(payload["diagnostic_runs"][0]["recorded_at_iso"], "2024-01-01T00:00:00Z")

    def test_diagnostics_doctor_flags_unsafe_scan_limit_and_secret_permissions(self):
        self.app.paths.env_file.write_text('ssh_user="admin"\n', encoding="utf-8")
        self.app.paths.env_file.chmod(0o644)
        self.app.config.public["scan_max_hosts"] = "999999"
        captures = [
            (0, "1 packets transmitted, 1 received, 0% packet loss", ""),
            (0, "", ""),
            (0, "1.1.1.1 via 192.0.2.1 dev eth0 src 192.0.2.2", ""),
        ]
        with mock.patch.object(netops.shutil, "which", side_effect=lambda command: f"/usr/bin/{command}"), mock.patch.object(
            self.app, "capture", side_effect=captures
        ), mock.patch.object(self.app, "emit") as emit:
            rc = self.app.diagnostics_doctor(False, netops.GlobalOptions())
        payload = emit.call_args.args[0]
        checks = {row["check"]: row for row in payload["checks"]}
        self.assertEqual(rc, netops.PARTIAL)
        self.assertEqual(checks["scan host limit"]["status"], "FAIL")
        self.assertEqual(checks["credential config permissions"]["status"], "FAIL")
        self.assertIn("0644", checks["credential config permissions"]["detail"])

    def test_vlan_inspection_accepts_usable_report_and_filters_endpoint_neighbors(self):
        self.add_device("192.0.2.1", "SW-A")
        self.add_device("192.0.2.2", "SW-B")
        with self.app.state.connect() as con:
            con.execute(
                "INSERT INTO neighbors(local_ip,local_name,local_port,remote_name,remote_port,remote_ip) VALUES(?,?,?,?,?,?)",
                ("192.0.2.1", "SW-A", "Gi1/0/48", "SW-B", "Gi1/0/48", "192.0.2.2"),
            )
            con.execute(
                "INSERT INTO neighbors(local_ip,local_name,local_port,remote_name,remote_port,remote_ip) VALUES(?,?,?,?,?,?)",
                ("192.0.2.1", "SW-A", "Gi1/0/7", "SEP6026AAA6A676", "Port 1", "192.0.2.90"),
            )
        report = (
            "Propagation Map for: SW-A (192.0.2.1)\n"
            "  Target VLAN: 131 | Status: DEFINED\n"
            "  Detected Uplinks:\n"
            "    - Gi1/0/48: PROPAGATED\n"
        )
        device = self.app.state.one("SELECT ip,hostname,platform,model,status,last_seen FROM devices WHERE ip='192.0.2.1'")
        with mock.patch.object(self.app, "capture", return_value=(1, report, "")), mock.patch.object(self.app, "live_switch_neighbors") as live:
            inspected = self.app.inspect_vlan_node(device, 131, "propagation", netops.GlobalOptions())
        self.assertEqual(inspected["state"], "OK")
        self.assertEqual(inspected["result"], "PRESENT")
        self.assertEqual(inspected["error"], "")
        self.assertTrue(inspected["helper_exit_ignored"])
        self.assertEqual(inspected["trunk_count"], 1)
        self.assertEqual([row["remote_name"] for row in inspected["neighbors"]], ["SW-B"])
        self.assertEqual(len(inspected["links"]), 1)
        live.assert_not_called()

    def test_registry_builds_recursive_vlan_core_ping_and_mac_commands(self):
        vlan, _, _ = self.app.command_for_action("vlan-propagation", {"target": "site-a-core", "vlan": "131", "depth": "5", "max_nodes": "40", "refresh_neighbors": True})
        core_ping, _, _ = self.app.command_for_action("diagnose-core-ping", {"target": "192.0.2.50", "core": "CORE01", "count": "5"})
        mac, _, writes = self.app.command_for_action("lookup-mac-profile", {"mac": "02:00:00:00:00:25", "scope": "ZONE34"})
        self.assertEqual(vlan[-5:], ["--depth", "5", "--max-nodes", "40", "--refresh-neighbors"])
        self.assertEqual(core_ping[-4:], ["192.0.2.50", "--core", "CORE01", "--count", "5"][-4:])
        self.assertEqual(mac[-3:], ["profile", "02:00:00:00:00:25", "ZONE34"])
        self.assertTrue(writes)

    def test_registry_builds_bounded_ghoster_command(self):
        command, _, writes_local = self.app.command_for_action(
            "path-inspect",
            {
                "endpoint": "02:00:00:00:00:25",
                "vlan": "120",
                "source": "SITE-A-CORE-01",
                "depth": "16",
                "max_nodes": "256",
                "mode": "hybrid",
                "explain": True,
            },
        )
        self.assertIn("--refresh", command)
        self.assertEqual(command[command.index("--depth") + 1], "16")
        self.assertEqual(command[command.index("--max-nodes") + 1], "256")
        self.assertTrue(writes_local)
        for values in ({"endpoint": "host", "vlan": "0"}, {"endpoint": "host", "vlan": "120", "depth": "17"}, {"endpoint": "host", "vlan": "120", "mode": "invented"}):
            with self.assertRaises(ValueError):
                self.app.command_for_action("path-inspect", values)

    def test_ghoster_refresh_requests_live_neighbor_evidence(self):
        result = mock.Mock(
            status="COMPLETE",
            summary="fixture path",
            confidence=100,
            finished_at=1_700_000_000,
            run_id="path-fixture",
        )
        result.to_dict.return_value = {"hops": [], "findings": []}
        options = netops.GlobalOptions()
        with mock.patch.object(self.app.path_inspector, "inspect", return_value=result), contextlib.redirect_stdout(io.StringIO()):
            code = self.app.cmd_path(["inspect", "02:00:00:00:00:25", "--vlan", "120", "--refresh"], options)
        self.assertEqual(code, netops.SUCCESS)
        self.assertTrue(options.refresh_neighbors)

    def test_application_driver_registry_is_profile_local(self):
        drivers = self.app.paths.config_dir / "drivers"
        drivers.mkdir(parents=True, exist_ok=True)
        (drivers / "fixture.toml").write_text(
            "schema_version = 1\n"
            "[driver]\nfamily = \"fixture-os\"\nvendor = \"Example Networks\"\n"
            "operating_system = \"FixtureOS\"\ndevice_kind = \"switch\"\n"
            "[match]\nplatform = [\"FixtureOS\"]\nconfidence = 90\n"
            "[commands]\ninventory = [\"show system\"]\n"
            "[capabilities]\ninventory = \"fixture\"\n",
            encoding="utf-8",
        )
        isolated = netops.App(ROOT)
        self.assertEqual(isolated.detect_device_family(platform="FixtureOS 1.0").family, "fixture-os")
        self.assertEqual(netops.DEVICE_DRIVERS.detect(platform="FixtureOS 1.0").family, "unknown")

    def test_flat_adapter_refreshes_emit_unified_builtin_observations(self):
        self.app.paths.devices_file.write_text(
            "192.0.2.10|SITE-A-ACCESS-10|Cisco IOS-XE|C9300|SERIAL-10|02:00:00:00:00:10|ssh|1700000000|ONLINE\n",
            encoding="utf-8",
        )
        self.app.paths.aps_file.write_text(
            "192.0.2.21|SITE-A-AP-21|Cisco C9136|192.0.2.10|SITE-A-ACCESS-10|Gi1/0/21|02:00:00:00:00:21|1700000000|ONLINE\n"
            "192.0.2.22|SITE-A-AP-22|RUCKUS R750|192.0.2.10|SITE-A-ACCESS-10|Gi1/0/22|02:00:00:00:00:22|1700000000|ONLINE\n",
            encoding="utf-8",
        )
        self.app.paths.neighbors_file.write_text(
            "192.0.2.10|SITE-A-ACCESS-10|Gi1/0/48|SITE-A-CORE-01|Gi1/0/1|192.0.2.1\n",
            encoding="utf-8",
        )
        refresh = self.app.import_flat_state(("device", "ap", "topology"), "fixture-refresh")
        self.assertEqual(refresh["imported"]["devices"], 1)
        self.assertEqual(len(refresh["ingest_runs"]), 4)
        channels = {row["channel"] for row in self.app.state.rows("SELECT channel FROM observations")}
        self.assertEqual(channels, {"built-in-ssh-scan", "built-in-cisco-wlc", "built-in-smartzone", "built-in-lldp-cdp"})

    def test_successful_materializing_ingest_refreshes_derived_identity_state(self):
        result = mock.Mock(status="completed", accepted=1, received=1, duplicates=0, rejected=0, channel="fixture", run_id="ing-fixture", finished_at=1_700_000_000, message="")
        result.to_dict.return_value = {
            "status": "completed", "accepted": 1, "received": 1, "duplicates": 0,
            "rejected": 0, "channel": "fixture", "run_id": "ing-fixture", "finished_at": 1_700_000_000,
        }
        with mock.patch.object(self.app.ingest_manager, "run", return_value=result), mock.patch.object(self.app.state, "sync_derived_state", return_value={"timestamp": 1_700_000_000}) as sync, mock.patch.object(self.app, "emit"):
            code = self.app.cmd_ingest(["run", "fixture"], netops.GlobalOptions())
        self.assertEqual(code, netops.SUCCESS)
        sync.assert_called_once_with()
        repeated = self.app.import_flat_state(("device", "ap", "topology"), "fixture-refresh")
        self.assertTrue(all(row["duplicates"] == row["received"] for row in repeated["ingest_runs"]))

    def test_registry_builds_new_diagnostic_commands_and_finite_interface_job(self):
        speed, _, _ = self.app.command_for_action("diagnose-speed", {"profile": "quick", "runs": "1"})
        throughput, _, _ = self.app.command_for_action("diagnose-throughput", {"target": "192.0.2.20", "direction": "download", "parallel": "2"})
        port, _, _ = self.app.command_for_action("diagnose-port-health", {"device": "SW1", "interface": "Gi1/0/7", "sample_seconds": "8", "expected_speed": "1000"})
        cable, _, _ = self.app.command_for_action("diagnose-cable", {"device": "SW1", "interface": "Gi1/0/7"})
        interface, _, _ = self.app.command_for_action("diagnose-interface", {"device": "SW1", "interface": "Gi1/0/7"})
        self.assertEqual(speed[-4:], ["--profile", "quick", "--runs", "1"])
        self.assertEqual(throughput[-4:], ["--parallel", "2", "--direction", "download"])
        self.assertIn("--sample-seconds", port)
        self.assertEqual(cable[-3:], ["SW1", "on", "Gi1/0/7"])
        self.assertEqual(interface[-1], "--once")

    def test_natural_ask_extracts_depth_core_and_mac_profile(self):
        vlan = self.app.ask_payload("Check VLAN propagation from site-a-core for VLAN 131 to depth 5", netops.GlobalOptions(), {"history": []})["command_plan"]
        core = self.app.ask_payload("Point-of-truth ping 192.0.2.50 from core CORE01 five times", netops.GlobalOptions(), {"history": []})["command_plan"]
        mac = self.app.ask_payload("Profile MAC 02:00:00:00:00:25", netops.GlobalOptions(), {"history": []})["command_plan"]
        self.assertEqual(vlan["action"], "vlan-propagation")
        self.assertEqual(vlan["args"], {"vlan": "131", "depth": "5", "target": "site-a-core"})
        self.assertEqual(core["action"], "diagnose-core-ping")
        self.assertEqual(core["args"], {"count": "5", "target": "192.0.2.50", "core": "CORE01"})
        self.assertEqual(mac["action"], "lookup-mac-profile")
        self.assertEqual(mac["args"]["mac"], "02:00:00:00:00:25")

    def test_natural_ask_extracts_diagnostic_server_device_and_interface(self):
        throughput = self.app.ask_payload(
            "Run iperf throughput to 192.0.2.20 in both directions",
            netops.GlobalOptions(),
            {"history": []},
        )["command_plan"]
        cable = self.app.ask_payload(
            "Show cable diagnostic on site-a-access Gi1/0/12",
            netops.GlobalOptions(),
            {"history": []},
        )["command_plan"]
        port = self.app.ask_payload(
            "Check port health on SW1 interface Gi1/0/7",
            netops.GlobalOptions(),
            {"history": []},
        )["command_plan"]
        speed = self.app.ask_payload(
            "Run a quick speed test",
            netops.GlobalOptions(),
            {"history": []},
        )["command_plan"]

        self.assertEqual(throughput["args"], {"target": "192.0.2.20", "direction": "both"})
        self.assertEqual(cable["args"], {"device": "site-a-access", "interface": "Gi1/0/12"})
        self.assertEqual(port["args"], {"device": "SW1", "interface": "Gi1/0/7"})
        self.assertEqual(speed["action"], "diagnose-speed")
        self.assertEqual(speed["args"], {"profile": "quick"})

    def test_vlan_cascade_walks_layers_suppresses_cycle_and_flags_missing_trunk(self):
        self.add_device("192.0.2.1", "SW-A")
        self.add_device("192.0.2.2", "SW-B")
        self.add_device("192.0.2.3", "SW-C")

        def neighbor(ip, name, local_port, remote_port):
            return {"local_port": local_port, "remote_ip": ip, "remote_name": name, "remote_port": remote_port, "source": "fixture"}

        def inspect(device, vlan, mode, opts):
            ip = device["ip"]
            if ip == "192.0.2.1":
                trunks = [{"port": "Gi1/0/48", "carries_vlan": True, "neighbor": neighbor("192.0.2.2", "SW-B", "Gi1/0/48", "Gi1/0/48")}]
            elif ip == "192.0.2.2":
                trunks = [
                    {"port": "Gi1/0/47", "carries_vlan": True, "neighbor": neighbor("192.0.2.1", "SW-A", "Gi1/0/47", "Gi1/0/48")},
                    {"port": "Gi1/0/48", "carries_vlan": False, "neighbor": neighbor("192.0.2.3", "SW-C", "Gi1/0/48", "Gi1/0/48")},
                ]
            else:
                trunks = [{"port": "Gi1/0/48", "carries_vlan": True, "neighbor": neighbor("192.0.2.2", "SW-B", "Gi1/0/48", "Gi1/0/48")}]
            return {
                "ip": ip,
                "name": device["hostname"],
                "platform": device["platform"],
                "vlan": vlan,
                "defined": True,
                "vlan_status": "defined",
                "access_ports": [],
                "access_port_count": 0,
                "trunks": trunks,
                "trunk_count": len(trunks),
                "trunks_carrying": sum(row["carries_vlan"] is True for row in trunks),
                "trunks_missing": sum(row["carries_vlan"] is False for row in trunks),
                "trunks_unknown": 0,
                "links": trunks,
                "neighbors": [row["neighbor"] for row in trunks],
                "state": "MISSING" if any(row["carries_vlan"] is False for row in trunks) else "OK",
                "result": "TRUNK GAP" if any(row["carries_vlan"] is False for row in trunks) else "PRESENT",
                "error": "",
                "helper_exit_code": 0,
                "helper_exit_ignored": False,
                "observed_at": 1704067200,
            }

        with mock.patch.object(self.app, "inspect_vlan_node", side_effect=inspect), mock.patch.object(self.app, "live_log"), mock.patch.object(self.app, "emit") as emit:
            rc = self.app.vlan_cascade("SW-A", 131, "propagation", netops.GlobalOptions(depth=2, max_nodes=10))
        payload = emit.call_args.args[0]
        self.assertEqual(rc, netops.SUCCESS)
        self.assertEqual(payload["counts"]["visited_nodes"], 3)
        self.assertEqual(payload["counts"]["critical_findings"], 1)
        self.assertFalse(payload["healthy"])
        self.assertTrue(any(row["code"] == "VLAN_MISSING_ON_TRUNK" and row["device"] == "SW-B" for row in payload["findings"]))
        self.assertTrue(any(row["traversal"] == "cycle-suppressed" for row in payload["edges"]))
        self.assertNotIn("STATE", emit.call_args.args[2])

    def test_vlan_scan_accepts_multiple_roots_ranges_and_builds_matrix(self):
        targets, vlans = self.app.parse_vlan_scan_request([
            "--target", "SW-A", "--target", "SW-B", "--vlan", "10,20-21"
        ])
        self.assertEqual(targets, ["SW-A", "SW-B"])
        self.assertEqual(vlans, [10, 20, 21])

        def cascade(target, vlan, mode, opts, collect=False):
            payload = {
                "ok": True,
                "healthy": True,
                "complete": True,
                "root": {"name": target, "ip": "192.0.2.1" if target == "SW-A" else "192.0.2.2"},
                "findings": [],
                "counts": {"visited_nodes": 2, "present_nodes": 2, "missing_nodes": 0, "trunk_gaps": 0, "critical_findings": 0, "inspection_errors": 0},
            }
            return (netops.SUCCESS, payload, "fixture") if collect else netops.SUCCESS

        with mock.patch.object(self.app, "vlan_cascade", side_effect=cascade) as runner, mock.patch.object(self.app, "live_log"), mock.patch.object(self.app, "emit") as emit:
            rc = self.app.vlan_cascade_many(targets, vlans, "propagation", netops.GlobalOptions(depth=2))
        payload = emit.call_args.args[0]
        self.assertEqual(rc, netops.SUCCESS)
        self.assertEqual(runner.call_count, 6)
        self.assertEqual(payload["counts"]["scans"], 6)
        self.assertEqual(len(payload["matrix"]), 6)

    def test_point_of_truth_ping_parses_and_records_core_measurement(self):
        self.add_device("192.0.2.1", "CORE01")
        self.app.config.public["core_switch_ip"] = "192.0.2.1"
        output = "Success rate is 100 percent (5/5), round-trip min/avg/max = 1/2/4 ms\n"
        with mock.patch.object(self.app, "capture", return_value=(0, output, "")), mock.patch.object(self.app, "live_log"), mock.patch.object(self.app, "emit") as emit:
            rc = self.app.point_of_truth_ping("192.0.2.50", netops.GlobalOptions(), count=5)
        payload = emit.call_args.args[0]
        self.assertEqual(rc, netops.SUCCESS)
        self.assertEqual(payload["avg_ms"], 2.0)
        self.assertEqual(payload["source"]["ip"], "192.0.2.1")
        row = self.app.state.one("SELECT * FROM probe_results WHERE mode='core-ping:192.0.2.1'")
        self.assertIsNotNone(row)
        self.assertEqual(row["packet_loss_pct"], 0.0)

    def test_core_lookup_uses_fastiron_driver_for_arp_fdb_and_interface(self):
        self.add_device("192.0.2.1", "CORE01", platform="Ruckus FastIron", model="ICX7850")
        self.app.config.public["core_switch_ip"] = "192.0.2.1"
        responses = [
            (0, "192.0.2.50 0200.0000.0025 Dynamic ve 131\n", ""),
            (0, "[192.0.2.1] CORE01 -> MAC FOUND\n  - 131 020000000025 Dynamic 1/1/12\n", ""),
            (0, "GigabitEthernet1/1/12 is up, line protocol is up\n Description: AP uplink\n", ""),
        ]
        with mock.patch.object(self.app, "capture", side_effect=responses) as capture, mock.patch.object(self.app, "live_log"), mock.patch.object(self.app, "emit") as emit:
            rc = self.app.core_lookup_workflow("192.0.2.50", netops.GlobalOptions())
        payload = emit.call_args.args[0]
        self.assertEqual(rc, netops.SUCCESS)
        self.assertEqual(payload["driver_family"], "ruckus-fastiron")
        self.assertEqual((payload["mac"], payload["vlan"], payload["port"]), ("0200.0000.0025", "131", "1/1/12"))
        self.assertEqual(payload["description"], "AP uplink")
        first_command = capture.call_args_list[0].args[0]
        self.assertEqual(first_command[-1], "show arp | include 192.0.2.50")
        self.assertIn("mac-lookup", capture.call_args_list[1].args[0])
        self.assertEqual(capture.call_args_list[2].args[0][-1], "show interfaces 1/1/12")

    def test_point_of_truth_ping_accepts_parsed_device_report_from_nonzero_helper(self):
        self.add_device("192.0.2.1", "CORE01")
        self.app.config.public["core_switch_ip"] = "192.0.2.1"
        output = "Type escape sequence to abort.\n!!!!!\nSuccess rate is 100 percent (5/5), round-trip min/avg/max = 1/2/4 ms\n"
        with mock.patch.object(self.app, "capture", return_value=(1, output, "")), mock.patch.object(self.app, "live_log"), mock.patch.object(self.app, "emit") as emit:
            rc = self.app.point_of_truth_ping("192.0.2.50", netops.GlobalOptions(), count=5)
        payload = emit.call_args.args[0]
        self.assertEqual(rc, netops.SUCCESS)
        self.assertTrue(payload["helper_exit_ignored"])
        self.assertEqual(payload["status"], "REACHABLE")

    def test_mac_observation_moves_and_inspection_reports_l2_without_ip(self):
        self.app.state.record_mac_observation("02:00:00:00:00:25", "192.0.2.1", "SW-A", "Gi1/0/7", "131", "DYNAMIC")
        self.app.state.record_mac_observation("02:00:00:00:00:25", "192.0.2.2", "SW-B", "Gi1/0/9", "131", "DYNAMIC")
        current = self.app.state.one("SELECT * FROM relationships_current WHERE rel_type='mac_location'")
        events = self.app.state.rows("SELECT * FROM relationship_events WHERE rel_type='mac_location' ORDER BY id")
        payload = self.app.mac_cached_payload("02:00:00:00:00:25")
        self.assertEqual(current["switch_ip"], "192.0.2.2")
        self.assertEqual([row["event_type"] for row in events], ["first_seen", "moved"])
        self.assertTrue(payload["layer2_present"])
        self.assertFalse(payload["ip_evidence_present"])
        self.assertIn("no current IP correlation", payload["assessment"])

    def test_active_mac_locate_records_edge_forwarding_evidence(self):
        self.add_device("192.0.2.1", "SW-A")
        self.add_device("192.0.2.2", "SW-B")

        def capture(command, timeout):
            if command[-2] == "192.0.2.2":
                return 0, " 131  0200.0000.0025  DYNAMIC  Gi1/0/7\n", ""
            return 0, "[192.0.2.1] SW-A -> MAC NOT FOUND\n", ""

        with mock.patch.object(self.app, "capture", side_effect=capture), mock.patch.object(self.app, "live_log"), mock.patch.object(self.app, "emit") as emit:
            rc = self.app.locate_mac_live("02:00:00:00:00:25", netops.GlobalOptions(limit=10), "all", False)
        payload = emit.call_args.args[0]
        self.assertEqual(rc, netops.SUCCESS)
        self.assertEqual(payload["counts"]["hits"], 1)
        self.assertEqual(payload["hits"][0]["role"], "edge-candidate")
        location = self.app.state.one("SELECT * FROM relationships_current WHERE rel_type='mac_location'")
        self.assertEqual(location["switch_ip"], "192.0.2.2")
        self.assertEqual(location["switch_port"], "Gi1/0/7")


if __name__ == "__main__":
    unittest.main()
