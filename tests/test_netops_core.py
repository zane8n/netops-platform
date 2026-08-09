import importlib.util
import io
import os
import contextlib
import signal
import subprocess
import sys
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
SPEC = importlib.util.spec_from_file_location("netops_core_under_test", ROOT / "netops_core.py")
netops = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = netops
SPEC.loader.exec_module(netops)

from netops_identity import identity_match_evidence, normalize_mac, reconcile_ap_rows, reconcile_device_rows
from netops_platform import identity as identity_module


class NetOpsCoreTest(unittest.TestCase):
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

    def add_device(self, ip, name, status="ONLINE", platform="Cisco"):
        self.app.state.execute(
            "INSERT INTO devices(ip,hostname,platform,model,serial,mac,source,last_seen,status) VALUES(?,?,?,?,?,?,?,?,?)",
            (ip, name, platform, "C9300", f"SERIAL-{ip}", "", "test", 1000, status),
        )

    def add_ap(self, ip, name, switch_ip="", switch_name="", switch_port="", mac="", status="ONLINE", seen=1000):
        self.app.state.execute(
            "INSERT INTO aps(ip,name,platform,switch_ip,switch_name,switch_port,mac,last_seen,status) VALUES(?,?,?,?,?,?,?,?,?)",
            (ip, name, "cisco C9136I-ROW", switch_ip, switch_name, switch_port, mac, seen, status),
        )

    def seed_building9(self):
        self.add_device("198.51.100.96", "SITEAZONE10BLDG9SW01")
        for idx, status in enumerate(("ONLINE", "ONLINE", "ONLINE", "OFFLINE"), 1):
            self.add_ap(
                f"192.0.2.{90 + idx}",
                f"SITEAZONE10BLDG9AP{300 + idx}",
                "198.51.100.96",
                "SITEAZONE10BLDG9SW01",
                f"Gi1/0/{idx}",
                f"0011223344{idx:02d}",
                status,
                1000 + idx,
            )

    def test_shorthand_ip_is_host_not_network_id(self):
        self.assertEqual(netops.normalize_target_literal("2.71"), "2.71")
        with mock.patch.dict(os.environ, {"NETOPS_TARGET_ABBREVIATION_PREFIX": "192.0"}):
            self.assertEqual(netops.normalize_target_literal("2.71"), "192.0.2.71")
        self.assertEqual(netops.normalize_target_literal("198.51.100.71"), "198.51.100.71")

    def test_runtime_bounds_and_signal_exit_codes_are_normalized(self):
        self.assertEqual(netops.bounded_int("0", 3, 1, 32), 1)
        self.assertEqual(netops.bounded_int("invalid", 3, 1, 32), 3)
        self.assertEqual(netops.bounded_int("999", 3, 1, 32), 32)
        self.assertEqual(netops.normalized_exit_code(-signal.SIGINT), 130)
        self.assertEqual(netops.normalized_exit_code(-signal.SIGTERM), 143)

    def test_speed_profile_is_not_consumed_as_the_state_profile(self):
        opts, args = netops.parse_global(["diagnose", "speed", "--profile", "quick", "--runs", "1"])
        self.assertEqual(opts.profile, "")
        self.assertEqual(args, ["diagnose", "speed", "--profile", "quick", "--runs", "1"])

        opts, args = netops.parse_global([
            "--profile", "lab", "diagnose", "speed", "--profile", "thorough", "--runs", "3",
        ])
        self.assertEqual(opts.profile, "lab")
        self.assertEqual(args, ["diagnose", "speed", "--profile", "thorough", "--runs", "3"])

        opts, args = netops.parse_global([
            "commands", "run", "diagnose-speed", "--profile", "quick", "--runs", "1", "--preview",
        ])
        self.assertEqual(opts.profile, "")
        self.assertIn("--profile", args)

    def test_diagnostic_local_options_survive_global_option_parsing(self):
        with mock.patch.object(self.app, "internet_speed_diagnostic", return_value=0) as speed:
            rc = self.app.dispatch(["diagnose", "speed", "--profile", "quick", "--runs", "1"])
        self.assertEqual(rc, 0)
        self.assertEqual(speed.call_args.args[0], 1)
        self.assertEqual(speed.call_args.args[3], "quick")

        with mock.patch.object(self.app, "point_of_truth_ping", return_value=0) as core_ping:
            rc = self.app.dispatch(["diagnose", "core-ping", "192.0.2.50", "--source", "CORE01"])
        self.assertEqual(rc, 0)
        self.assertEqual(core_ping.call_args.args[2], "CORE01")

        with mock.patch.object(self.app, "throughput_diagnostic", return_value=0) as throughput:
            rc = self.app.dispatch(["diagnose", "throughput", "203.0.113.20", "--source", "192.0.2.25"])
        self.assertEqual(rc, 0)
        self.assertEqual(throughput.call_args.args[5], "192.0.2.25")

    def test_ssh_username_validation_matches_the_shell_boundary(self):
        self.assertTrue(netops.valid_ssh_username("operator"))
        self.assertFalse(netops.valid_ssh_username(""))
        self.assertFalse(netops.valid_ssh_username("invalid user"))
        self.assertFalse(netops.valid_ssh_username("x" * 256))

        self.app.config.public["ssh_user"] = "invalid user"
        with mock.patch.object(self.app, "emit") as emit:
            rc = self.app.cmd_config(["validate"], netops.GlobalOptions())
        self.assertEqual(rc, netops.VALIDATION)
        self.assertEqual(emit.call_args.args[0]["findings"][0]["key"], "ssh_user")

    def test_vault_status_is_non_prompting_versioned_and_chronological(self):
        vault = Path(self.temp.name) / "sshpass.gpg"
        vault.write_bytes(b"NETOPS-SUDO-GPG-V1\nfixture-ciphertext")
        vault.chmod(0o600)
        os.utime(vault, (1704067200, 1704067200))
        with mock.patch.dict(
            os.environ,
            {"NETOPS_PASSWORD_FILE": str(vault), "NETOPS_TEST_MODE": "true"},
            clear=False,
        ), mock.patch.object(netops.subprocess, "run", return_value=mock.Mock(returncode=1)) as run:
            payload = self.app.vault_status_payload()
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["mode"], "sudo-gpg-v1")
        self.assertEqual(payload["permissions"], "0600")
        self.assertEqual(payload["modified_at_iso"], "2024-01-01T00:00:00Z")
        self.assertEqual(payload["password_recorded_at_iso"], "2024-01-01T00:00:00Z")
        self.assertEqual(payload["expected_expiry_at_iso"], "2024-01-04T00:00:00Z")
        self.assertEqual(payload["expiry_window_start_iso"], "2024-01-03T23:40:00Z")
        self.assertEqual(payload["expiry_window_end_iso"], "2024-01-04T00:20:00Z")
        self.assertEqual(payload["credential_state"], "EXPIRED")
        self.assertEqual(payload["sudo_session"], "locked")
        self.assertFalse(payload["graphical_pinentry"])
        run.assert_called_once_with(
            [mock.ANY, "-n", "-v"],
            stdin=netops.subprocess.DEVNULL,
            stdout=netops.subprocess.DEVNULL,
            stderr=netops.subprocess.DEVNULL,
            timeout=2,
            check=False,
        )

    def test_vault_status_rejects_insecure_root_key_permissions(self):
        base = Path(self.temp.name)
        vault = base / "sshpass.gpg"
        vault.write_bytes(b"NETOPS-SUDO-GPG-V1\nfixture-ciphertext")
        vault.chmod(0o600)
        key_dir = base / "vault-keys"
        key_dir.mkdir()
        key = key_dir / f"{os.getuid()}.key"
        key.write_text("fixture-key\n", encoding="ascii")
        key.chmod(0o644)
        bin_dir = base / "bin"
        bin_dir.mkdir()
        sudo = bin_dir / "sudo"
        sudo.write_text(
            "#!/usr/bin/env bash\n"
            "if [[ \"$1\" == -n && \"$2\" == -v ]]; then exit 0; fi\n"
            "[[ \"$1\" == -n ]] && shift\n"
            "if [[ \"$1\" == /usr/bin/stat ]]; then\n"
            "  metadata=$(/usr/bin/stat -c '%a:%F' \"${@: -1}\") || exit $?\n"
            "  printf '65534:%s\\r\\n' \"$metadata\"; exit 0\n"
            "fi\n"
            "exec \"$@\"\n",
            encoding="ascii",
        )
        sudo.chmod(0o700)
        with mock.patch.dict(
            os.environ,
            {
                "NETOPS_PASSWORD_FILE": str(vault),
                "NETOPS_TEST_MODE": "true",
                "NETOPS_SUDO_VAULT_KEY_DIR": str(key_dir),
                "PATH": f"{bin_dir}:{os.environ.get('PATH', '')}",
            },
            clear=False,
        ):
            insecure_key = self.app.vault_status_payload()
            key.chmod(0o600)
            insecure_dir = self.app.vault_status_payload()
            key_dir.chmod(0o700)
            secure = self.app.vault_status_payload()
        self.assertEqual(insecure_key["sudo_session"], "unlocked")
        self.assertEqual(insecure_key["root_key"], "insecure")
        self.assertEqual(insecure_dir["root_key"], "insecure")
        self.assertEqual(secure["root_key"], "available")

    def test_vault_set_dispatches_to_interactive_helper_and_audits(self):
        vault = Path(self.temp.name) / "sshpass.gpg"
        with mock.patch.dict(os.environ, {"NETOPS_PASSWORD_FILE": str(vault)}, clear=False), \
                mock.patch.object(self.app, "run_vault_interactive", return_value=0) as run, \
                mock.patch.object(self.app.state, "record_audit_event") as audit:
            rc = self.app.cmd_vault(["set", "--legacy-vault"], netops.GlobalOptions())
        self.assertEqual(rc, 0)
        self.assertEqual(run.call_args.args[0][-2:], ["--set-password", "--legacy-vault"])
        self.assertEqual(audit.call_args.args[:2], ("vault_password_set", "vault-set"))

    def test_vault_runner_preserves_the_foreground_terminal_session(self):
        proc = mock.Mock()
        proc.wait.return_value = 0
        with mock.patch.object(netops.subprocess, "Popen", return_value=proc) as popen, \
                mock.patch.object(self.app, "_terminate_process_group") as terminate_group:
            rc = self.app.run_vault_interactive(["vault-helper"], netops.GlobalOptions())
        self.assertEqual(rc, 0)
        self.assertFalse(popen.call_args.kwargs["start_new_session"])
        terminate_group.assert_not_called()

    def test_device_ssh_uses_foreground_runner_for_tty_scoped_vault_auth(self):
        with mock.patch.object(self.app, "run_vault_interactive", return_value=0) as foreground, \
                mock.patch.object(self.app, "run_interactive") as detached:
            rc = self.app.cmd_device(["ssh", "7.71"], netops.GlobalOptions())
        self.assertEqual(rc, 0)
        helper = foreground.call_args.args[0]
        self.assertEqual(Path(helper[0]).name, "netops-connect")
        self.assertEqual(helper[1:], ["7.71"])
        detached.assert_not_called()

    def test_device_ssh_normalizes_legacy_option_and_rejects_unknown_options(self):
        with mock.patch.object(self.app, "run_vault_interactive", return_value=0) as foreground:
            rc = self.app.cmd_device(["ssh", "--legacy", "SITE-A-ACCESS-01"], netops.GlobalOptions())
        self.assertEqual(rc, 0)
        helper = foreground.call_args.args[0]
        self.assertEqual(Path(helper[0]).name, "netops-connect")
        self.assertEqual(helper[1:], ["--legacy", "SITE-A-ACCESS-01"])

        with mock.patch.object(self.app, "run_vault_interactive") as blocked, mock.patch.object(self.app, "emit"):
            rc = self.app.cmd_device(["ssh", "--unsupported", "SITE-A-ACCESS-01"], netops.GlobalOptions())
        self.assertEqual(rc, netops.VALIDATION)
        blocked.assert_not_called()

    def test_app_concurrency_environment_cannot_deadlock_or_crash_startup(self):
        with mock.patch.dict(os.environ, {"NETOPS_JOB_CONCURRENCY": "invalid"}, clear=False):
            app = netops.App(ROOT)
            self.assertEqual(app.sem._value, 3)
        with mock.patch.dict(os.environ, {"NETOPS_JOB_CONCURRENCY": "0"}, clear=False):
            app = netops.App(ROOT)
            self.assertEqual(app.sem._value, 1)

    def test_capture_interrupt_terminates_managed_process_group(self):
        proc = mock.Mock()
        proc.communicate.side_effect = KeyboardInterrupt
        with mock.patch.object(netops.subprocess, "Popen", return_value=proc), mock.patch.object(
            self.app, "_terminate_process_group"
        ) as terminate:
            with self.assertRaises(KeyboardInterrupt):
                self.app.capture(["helper"])
        terminate.assert_called_once_with(proc, signal.SIGINT, 1.5)

    def test_streamed_capture_interrupt_terminates_managed_process_group(self):
        proc = mock.Mock()
        proc.stdout = io.StringIO("")
        proc.stderr = io.StringIO("")
        proc.poll.return_value = None

        class ThreadStub:
            def __init__(self, *args, **kwargs):
                pass

            def start(self):
                pass

            def join(self, timeout=None):
                pass

        with mock.patch.object(netops.subprocess, "Popen", return_value=proc), mock.patch.object(
            netops.threading, "Thread", ThreadStub
        ), mock.patch.object(netops.time, "sleep", side_effect=KeyboardInterrupt), mock.patch.object(
            self.app, "_terminate_process_group"
        ) as terminate:
            with self.assertRaises(KeyboardInterrupt):
                self.app.capture_streamed(["helper"])
        terminate.assert_called_once_with(proc, signal.SIGINT, 1.5)

    def test_process_group_cleanup_stops_descendant_after_parent_exit(self):
        code = (
            "import subprocess,sys; "
            "child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)']); "
            "print(child.pid, flush=True)"
        )
        parent = subprocess.Popen(
            [sys.executable, "-c", code],
            stdout=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        child_pid = int(parent.stdout.readline().strip())
        parent.wait(timeout=5)
        parent.stdout.close()
        try:
            self.app._terminate_process_group(parent, signal.SIGTERM, 0.5)
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                stat = Path(f"/proc/{child_pid}/stat")
                if not stat.exists() or stat.read_text().split()[2] == "Z":
                    break
                time.sleep(0.05)
            else:
                self.fail("descendant process remained alive after group cleanup")
        finally:
            try:
                os.kill(child_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

    def test_timestamps_use_unambiguous_iso_8601_utc(self):
        self.assertEqual(netops.fmt_time(1704067200), "2024-01-01T00:00:00Z")
        self.assertEqual(netops.fmt_time(0), "")
        row = netops.timestamp_row({"created_at": 1704067200, "last_seen": 1704067200})
        self.assertEqual(row["created_at"], 1704067200)
        self.assertEqual(row["recorded_at_iso"], "2024-01-01T00:00:00Z")
        self.assertEqual(row["last_seen_iso"], "2024-01-01T00:00:00Z")
        self.assertIn("2024-01-01T00:00:00Z", self.app.render_table([row], ["last_seen"]))

    def test_memory_current_and_timeline_are_newest_first_with_dates(self):
        for suffix, seen in (("old", 100), ("new", 200)):
            self.app.state.execute(
                "INSERT INTO relationships_current(rel_key,rel_type,subject_kind,subject_id,object_kind,object_id,source,confidence,status,first_seen,last_seen,updated_at,attrs_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (f"identity_ip|{suffix}", "identity_ip", "device", "192.0.2.1", "ip", f"192.0.2.{seen}", "test", 90, "active", 50, seen, seen, "{}"),
            )
            self.app.state.execute(
                "INSERT INTO relationship_events(created_at,event_type,rel_key,rel_type,subject_kind,subject_id,object_kind,object_id,source,confidence,detail) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (seen, "changed", f"identity_ip|{suffix}", "identity_ip", "device", "192.0.2.1", "ip", f"192.0.2.{seen}", "test", 90, suffix),
            )

        payload = self.app.memory_device_payload("192.0.2.1", 20)
        self.assertEqual(payload["chronology"], "newest_first")
        self.assertEqual(payload["time_format"], "ISO 8601 UTC")
        self.assertEqual([row["last_seen"] for row in payload["current"]], [200, 100])
        self.assertEqual(payload["current"][0]["last_seen_iso"], "1970-01-01T00:03:20Z")
        self.assertEqual([row["created_at"] for row in payload["timeline"]], [200, 100])
        self.assertEqual(payload["timeline"][0]["version_label"], "version 1 (latest/current)")
        self.assertEqual(payload["timeline"][0]["recorded_at_iso"], "1970-01-01T00:03:20Z")
        self.assertEqual(payload["latest_recorded_at"], 200)

    def test_inventory_history_is_versioned_and_timestamped_newest_first(self):
        for event_id, created_at in (("old", 100), ("new", 200)):
            self.app.state.execute(
                "INSERT INTO inventory_history(created_at,entity_type,identity_kind,identity_value,event_type,name,status) VALUES(?,?,?,?,?,?,?)",
                (created_at, "device", "ip", "192.0.2.1", event_id, "switch-1", "ONLINE"),
            )

        payload = self.app.inventory_history_payload("192.0.2.1", 20)
        self.assertEqual([row["created_at"] for row in payload["rows"]], [200, 100])
        self.assertEqual(payload["rows"][0]["version"], 1)
        self.assertEqual(payload["rows"][0]["recorded_at_iso"], "1970-01-01T00:03:20Z")
        self.assertEqual(payload["latest_recorded_at_iso"], "1970-01-01T00:03:20Z")

    def test_show_command_policy_accepts_reads_and_blocks_escape_or_secrets(self):
        self.assertTrue(self.app.safe_show_command("show version"))
        self.assertTrue(self.app.safe_show_command("show interface status | include connected"))
        for command in (
            "show running-config",
            "show tech-support",
            "show version; reload",
            "show version\nconfigure terminal",
            "configure terminal",
            "show users && reload",
        ):
            with self.subTest(command=command):
                self.assertFalse(self.app.safe_show_command(command))

    def test_mac_identity_accepts_physical_unicast_and_rejects_placeholders(self):
        self.assertEqual(normalize_mac("02:00:00:00:00:25"), "020000000025")
        self.assertEqual(normalize_mac("00:00:00:0b:00:00"), "")
        self.assertEqual(normalize_mac("01:7c:57:58:56:91"), "")
        self.assertEqual(normalize_mac("ff:ff:ff:ff:ff:ff"), "")

    def test_migration_cleans_invalid_mac_identity_without_recreating_history(self):
        self.app.state.execute(
            "INSERT INTO devices(ip,hostname,platform,model,serial,mac,source,last_seen,status) VALUES(?,?,?,?,?,?,?,?,?)",
            ("198.51.100.53", "TESTSW01", "Aruba", "2930F", "SERIAL", "00:00:00:0b:00:00", "test", 1000, "ONLINE"),
        )
        self.app.state.execute(
            "INSERT INTO inventory_history(created_at,entity_type,identity_kind,identity_value,event_type,mac) VALUES(?,?,?,?,?,?)",
            (1000, "device", "mac", "0000000b0000", "field_changed", "00:00:00:0b:00:00"),
        )
        result = self.app.state.migrate()
        self.assertGreater(result["mac_identity_cleanup"]["changed"], 0)
        self.assertEqual(self.app.state.one("SELECT mac FROM devices WHERE ip='198.51.100.53'")["mac"], "")
        self.assertEqual(self.app.state.one("SELECT COUNT(*) AS count FROM inventory_history WHERE identity_kind='mac'")["count"], 0)
        self.app.state.sync_derived_state()
        before = self.app.state.one("SELECT COUNT(*) AS count FROM inventory_history")["count"]
        self.app.state.sync_derived_state()
        after = self.app.state.one("SELECT COUNT(*) AS count FROM inventory_history")["count"]
        self.assertEqual(before, after)

    def test_ap_aliases_merge_by_location_and_ap_number(self):
        rows = reconcile_ap_rows([
            {"ip": "192.0.2.133", "name": "SITE-A-ZONE34-AP239", "status": "OFFLINE", "last_seen": 100},
            {"ip": "192.0.2.139", "name": "SITEAZONE34AP239", "status": "ONLINE", "last_seen": 200},
        ])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["status"], "ONLINE")
        self.assertEqual(rows[0]["merged_records"], 2)
        self.assertEqual(rows[0]["addresses"], ["192.0.2.133", "192.0.2.139"])
        self.assertEqual(set(rows[0]["aliases"]), {"SITE-A-ZONE34-AP239", "SITEAZONE34AP239"})

    def test_requested_fuzzy_thresholds_use_corroborrating_asset_evidence(self):
        ap = identity_match_evidence(
            {"name": "SITE-A-PLNT-PLN-AP190"},
            {"name": "SITEAPLNTPLANAP190"},
            "ap",
        )
        switch = identity_match_evidence(
            {"hostname": "SITE-A-PLNT-PLN-SW01"},
            {"hostname": "SITEAPLNTPLANSW01"},
            "switch",
        )
        distinct = identity_match_evidence(
            {"hostname": "SITEAPLNTPLANSW01"},
            {"hostname": "SITEAPLNTPLANSW02"},
            "switch",
        )
        similar_location = identity_match_evidence(
            {"hostname": "SITEACMPAH22SW01"},
            {"hostname": "SITE-A-CMPA-H21-SW01"},
            "switch",
        )
        self.assertTrue(ap["same_device"])
        self.assertEqual(ap["signals"]["name_threshold"], 85)
        self.assertTrue(switch["same_device"])
        self.assertEqual(switch["signals"]["name_threshold"], 75)
        self.assertFalse(distinct["same_device"])
        self.assertIn("asset-number", distinct["conflicts"])
        self.assertTrue(similar_location["candidate"])
        self.assertFalse(similar_location["same_device"])

    def test_switch_reconciliation_retains_old_and_new_names(self):
        rows = reconcile_device_rows([
            {"ip": "192.0.2.1", "hostname": "SITE-A-PLNT-PLN-SW01", "status": "OFFLINE", "last_seen": 100},
            {"ip": "192.0.2.2", "hostname": "SITEAPLNTPLANSW01", "status": "ONLINE", "last_seen": 200},
        ])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["status"], "ONLINE")
        self.assertEqual(rows[0]["addresses"], ["192.0.2.1", "192.0.2.2"])
        self.assertEqual(len(rows[0]["aliases"]), 2)

    def test_identity_reconciliation_uses_bounded_candidate_blocks(self):
        aps = [
            {
                "ip": f"198.18.{index // 250}.{index % 250 + 1}",
                "name": f"SITE-{index:04d}-AP{index + 1}",
                "model": "AP-FIXTURE",
                "status": "ONLINE",
            }
            for index in range(600)
        ]
        devices = [
            {
                "ip": f"198.19.{index // 250}.{index % 250 + 1}",
                "hostname": f"SITE-{index:04d}-SW{index + 1}",
                "model": "SW-FIXTURE",
                "status": "ONLINE",
            }
            for index in range(600)
        ]
        with mock.patch.object(identity_module, "identity_match_evidence", wraps=identity_module.identity_match_evidence) as assessment:
            self.assertEqual(len(reconcile_ap_rows(aps)), 600)
            self.assertEqual(len(reconcile_device_rows(devices)), 600)
        self.assertLess(assessment.call_count, 1200)

    def test_manual_device_merge_retires_source_preserves_memory_and_is_reversible(self):
        self.add_device("192.0.2.11", "SITE-A-OLD-SW01")
        self.add_device("192.0.2.21", "SITE-A-ACCESS-SW01")

        with mock.patch.object(self.app, "emit") as emit:
            preview = self.app.cmd_inventory(
                ["merge", "SITE-A-OLD-SW01", "SITE-A-ACCESS-SW01", "--reason", "approved replacement"],
                netops.GlobalOptions(dry_run=True),
            )
        self.assertEqual(preview, netops.SUCCESS)
        self.assertEqual(self.app.state.one("SELECT COUNT(*) AS count FROM inventory_merges")["count"], 0)
        self.assertIn("Manual device merge preview", emit.call_args.args[2])

        with mock.patch.object(self.app, "emit"):
            applied = self.app.cmd_inventory(
                ["merge", "SITE-A-OLD-SW01", "SITE-A-ACCESS-SW01", "--reason", "approved replacement"],
                netops.GlobalOptions(confirm=True),
            )
        self.assertEqual(applied, netops.SUCCESS)
        self.assertIsNone(self.app.state.one("SELECT * FROM devices WHERE ip='192.0.2.11'"))
        merge = self.app.state.one("SELECT * FROM inventory_merges WHERE revoked_at IS NULL")
        self.assertIsNotNone(merge)
        self.assertEqual(merge["suppressed_observations"], 1)
        self.assertIsNotNone(self.app.state.one("SELECT * FROM inventory_history WHERE event_type='manually_merged'"))
        self.assertIsNotNone(self.app.state.one("SELECT * FROM relationships_current WHERE rel_type='manual_identity_merge' AND status='active'"))
        rows = self.app.inventory_rows("SITE-A-OLD-SW01", netops.GlobalOptions(limit=10))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["ip"], "192.0.2.21")
        self.assertIn("SITE-A-OLD-SW01", rows[0]["aliases"])
        self.assertEqual(rows[0]["historical_addresses"], ["192.0.2.11"])
        self.assertNotIn("192.0.2.11", self.app.paths.devices_file.read_text(encoding="utf-8"))

        self.add_device("192.0.2.11", "SITE-A-OLD-SW01")
        self.app.state.sync_derived_state()
        self.assertIsNone(self.app.state.one("SELECT * FROM devices WHERE ip='192.0.2.11'"))
        self.assertEqual(self.app.state.one("SELECT suppressed_observations FROM inventory_merges WHERE merge_id=?", (merge["merge_id"],))["suppressed_observations"], 2)

        with mock.patch.object(self.app, "emit"):
            revoked = self.app.cmd_inventory(
                ["unmerge", merge["merge_id"], "--reason", "association corrected"],
                netops.GlobalOptions(confirm=True),
            )
        self.assertEqual(revoked, netops.SUCCESS)
        restored = self.app.state.one("SELECT * FROM devices WHERE ip='192.0.2.11'")
        self.assertIsNotNone(restored)
        self.assertEqual(restored["last_seen"], 1000)
        self.assertIn("192.0.2.11", self.app.paths.devices_file.read_text(encoding="utf-8"))
        self.assertEqual(self.app.state.one("SELECT COUNT(*) AS count FROM inventory_merges WHERE revoked_at IS NULL")["count"], 0)
        self.assertIsNotNone(self.app.state.one("SELECT * FROM inventory_history WHERE event_type='manual_merge_revoked'"))
        self.assertEqual(self.app.state.one("SELECT COUNT(*) AS count FROM audit_events WHERE event_type LIKE 'inventory_device_merge%'")["count"], 2)

    def test_action_hub_manual_merge_is_preview_only(self):
        preview = self.app.preview_for_action(
            "inventory-merge",
            {"source": "SITE-A-OLD-SW01", "target": "SITE-A-ACCESS-SW01", "reason": "approved replacement"},
        )
        self.assertTrue(preview["ok"])
        self.assertTrue(preview["blocked"])
        self.assertFalse(preview["run_supported"])
        self.assertIn("--dry-run", preview["command"])
        self.assertNotIn("--confirm", preview["command"])

    def test_manual_unmerge_refuses_reassigned_source_ip(self):
        self.add_device("192.0.2.11", "SITE-A-OLD-SW01")
        self.add_device("192.0.2.21", "SITE-A-ACCESS-SW01")
        with mock.patch.object(self.app, "emit"):
            self.assertEqual(
                self.app.cmd_inventory(
                    ["merge", "SITE-A-OLD-SW01", "SITE-A-ACCESS-SW01", "--reason", "approved replacement"],
                    netops.GlobalOptions(confirm=True),
                ),
                netops.SUCCESS,
            )
        merge = self.app.state.one("SELECT merge_id FROM inventory_merges WHERE revoked_at IS NULL")
        self.app.state.execute(
            "INSERT INTO devices(ip,hostname,platform,model,serial,mac,source,last_seen,status) VALUES(?,?,?,?,?,?,?,?,?)",
            ("192.0.2.11", "SITE-A-NEW-OWNER-SW99", "Aruba", "6300", "NEW-SERIAL", "02:00:00:00:00:99", "test", 2000, "ONLINE"),
        )
        with mock.patch.object(self.app, "emit"), mock.patch.object(self.app, "usage_error", return_value=netops.VALIDATION) as usage:
            code = self.app.cmd_inventory(
                ["unmerge", merge["merge_id"], "--reason", "association corrected"],
                netops.GlobalOptions(confirm=True),
            )
        self.assertEqual(code, netops.VALIDATION)
        self.assertIn("owned by a different active device", usage.call_args.args[3])
        self.assertIsNone(self.app.state.one("SELECT revoked_at FROM inventory_merges WHERE merge_id=? AND revoked_at IS NOT NULL", (merge["merge_id"],)))

    def test_vendor_writes_fail_closed_before_transport(self):
        self.add_device("192.0.2.9", "ARUBA01", platform="Aruba AOS-CX")
        with mock.patch.object(self.app, "run_subprocess") as run, mock.patch.object(self.app, "capture") as capture, mock.patch.object(self.app, "emit") as emit:
            config_rc = self.app.cmd_device(
                ["config", "ARUBA01", "interface 1/1/1"],
                netops.GlobalOptions(confirm=True),
            )
            request = self.app.vlan_change_request({
                "target": "ARUBA01",
                "interface": "1/1/1",
                "vlan_mode": "access",
                "vlan": "131",
            })
            vlan_rc = self.app.apply_vlan_change(request, netops.GlobalOptions(confirm=True))
        self.assertEqual((config_rc, vlan_rc), (netops.UNSUPPORTED, netops.UNSUPPORTED))
        run.assert_not_called()
        capture.assert_not_called()
        self.assertIn("no network command was executed", emit.call_args.args[2])

    def test_device_rename_keeps_historical_hostname_resolvable(self):
        self.app.state.execute(
            "INSERT INTO devices(ip,hostname,platform,model,serial,mac,source,last_seen,status) VALUES(?,?,?,?,?,?,?,?,?)",
            ("192.0.2.1", "SITE-A-PLNT-PLN-SW01", "Cisco IOS", "C9300", "N/A", "", "SNMP", 100, "ONLINE"),
        )
        self.app.state.sync_derived_state()
        self.app.state.execute(
            "UPDATE devices SET hostname=?,last_seen=? WHERE ip=?",
            ("SITEAPLNTPLANSW01", 200, "192.0.2.1"),
        )
        self.app.state.sync_derived_state()

        resolved, choices = self.app.resolve_device_record("SITE-A-PLNT-PLN-SW01")
        self.assertIsNotNone(resolved)
        self.assertEqual(len(choices), 1)
        self.assertEqual(resolved["hostname"], "SITEAPLNTPLANSW01")
        aliases = self.app.state.rows(
            "SELECT subject_id FROM relationships_current "
            "WHERE rel_type='device_alias' AND status='active'"
        )
        self.assertIn("site-a-plnt-pln-sw01", {row["subject_id"] for row in aliases})

    def test_placeholder_serial_does_not_link_unrelated_history(self):
        self.app.state.execute(
            "INSERT INTO devices(ip,hostname,platform,model,serial,mac,source,last_seen,status) VALUES(?,?,?,?,?,?,?,?,?)",
            ("192.0.2.1", "SITEAZONE01SW01", "Cisco IOS", "C9300", "N/A", "", "SNMP", 100, "ONLINE"),
        )
        self.app.state.execute(
            "INSERT INTO inventory_identity_state(identity_kind,identity_value,entity_type,ip,mac,name,platform,model,serial,source,status,first_seen,last_seen,updated_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("name", "unrelatedsw99", "device", "192.0.2.99", "", "UNRELATEDSW99", "Cisco IOS", "C9300", "N/A", "SNMP", "ONLINE", 50, 50, 50),
        )

        resolved, choices = self.app.resolve_device_record("UNRELATEDSW99")
        self.assertIsNone(resolved)
        self.assertEqual(choices, [])

    def test_meaningful_location_and_ap_number_keep_distinct_aps(self):
        rows = reconcile_ap_rows([
            {"ip": "203.0.113.1", "name": "SITE-A-House19-AP123", "status": "ONLINE"},
            {"ip": "203.0.113.2", "name": "SITE-A-H19-ANNEX-AP124", "status": "ONLINE"},
            {"ip": "203.0.113.3", "name": "SITEAH19ANNEXAP123", "status": "ONLINE"},
        ])
        self.assertEqual(len(rows), 3)

    def test_no_mac_observation_cannot_bridge_conflicting_macs(self):
        rows = reconcile_ap_rows([
            {"ip": "203.0.113.1", "name": "SITE-A-ZONE34-AP239", "mac": "0200.0000.0025", "status": "ONLINE"},
            {"ip": "203.0.113.2", "name": "SITEAZONE34AP239", "mac": "", "status": "ONLINE"},
            {"ip": "203.0.113.3", "name": "SITE-ZONE34-AP239", "mac": "0200.0000.0026", "status": "ONLINE"},
        ])
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(len(row["macs"]) <= 1 for row in rows))

    def test_active_inventory_and_counts_use_canonical_aps(self):
        self.add_ap("192.0.2.133", "SITE-A-ZONE34-AP239", status="OFFLINE", seen=100)
        self.add_ap("192.0.2.139", "SITEAZONE34AP239", status="ONLINE", seen=200)
        self.add_ap("192.0.2.140", "SITE-A-House19-AP123", status="OFFLINE", seen=300)

        rows = self.app.inventory_rows("", netops.GlobalOptions(limit=20))
        aps = [row for row in rows if row["kind"] == "ap"]
        self.assertEqual(len(aps), 2)
        self.assertEqual(aps[0]["status"], "OFFLINE")
        counts = self.app.state.counts()
        self.assertEqual(counts["aps"], 2)
        self.assertEqual(counts["ap_observations"], 3)
        self.assertEqual(counts["ap_alias_records"], 1)

    def test_natural_ask_ap_on_switch_handles_location_wording(self):
        self.seed_building9()
        for question in (
            "How many APs are on the building9 switch at sq10?",
            "AP count for the b9 switch in ZONE10",
            "How many access points sit on building 9 at square 10?",
        ):
            with self.subTest(question=question):
                payload = self.app.ask_payload(question, netops.GlobalOptions(limit=50))
                self.assertTrue(payload["ok"])
                self.assertEqual(payload["intent"], "ap_on_switch")
                self.assertIn("4 APs", payload["answer"])
                self.assertIn("3 online", payload["answer"])
                self.assertIn("1 offline", payload["answer"])

    def test_phrase_alias_preserves_switch_qualifier(self):
        self.add_device("198.51.100.10", "SITEAENGGOFCSW01")
        self.add_device("198.51.100.11", "SITEAENGGOFCSW02")
        self.add_ap("192.0.2.10", "SITEAENGGOFCAP010", "198.51.100.11", "SITEAENGGOFCSW02", "Gi1/0/1")
        self.app.natural_ask.set_alias("engineering office", "engg ofc")

        payload = self.app.ask_payload(
            "How many APs are on SW02 at engineering office?",
            netops.GlobalOptions(limit=50),
        )
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["intent"], "ap_on_switch")
        self.assertEqual(payload["selected"]["ip"], "198.51.100.11")
        self.assertIn("1 AP", payload["answer"])

    def test_ap_location_does_not_call_controller_data_a_physical_port(self):
        self.add_ap(
            "192.0.2.1",
            "SITE-SQ21-AP161",
            "",
            "Ruckus-vSZ",
            "wireless",
            "02:00:00:00:00:25",
            "OFFLINE",
        )
        payload = self.app.ask_payload(
            "Where was SITE-SQ21-AP161 connected before it went offline?",
            netops.GlobalOptions(limit=20),
        )
        self.assertIn("no physical switch port is cached", payload["answer"])
        self.assertIn("netops lookup mac all 0200.0000.0025", payload["answer"])

    def test_natural_ask_compares_same_and_distinct_ap_names(self):
        self.add_ap("192.0.2.133", "SITE-A-ZONE34-AP239")
        self.add_ap("192.0.2.139", "SITEAZONE34AP239")
        self.add_ap("203.0.113.1", "SITE-A-House19-AP123")
        self.add_ap("203.0.113.2", "SITE-A-H19-ANNEX-AP124")

        same = self.app.ask_payload(
            "Are SITE-A-ZONE34-AP239 and SITEAZONE34AP239 the same AP?",
            netops.GlobalOptions(),
        )
        different = self.app.ask_payload(
            "Are SITE-A-House19-AP123 and SITE-A-H19-ANNEX-AP124 the same AP?",
            netops.GlobalOptions(),
        )
        self.assertTrue(same["comparison"]["same"])
        self.assertFalse(different["comparison"]["same"])

    def test_name_comparison_is_deterministic_without_current_records(self):
        same = self.app.ask_payload(
            "Are SITE-A-ZONE34-AP239 and SITEAZONE34AP239 the same AP?",
            netops.GlobalOptions(),
        )
        different = self.app.ask_payload(
            "Are SITE-A-House19-AP123 and SITE-A-H19-ANNEX-AP124 the same AP?",
            netops.GlobalOptions(),
        )
        self.assertTrue(same["comparison"]["same"])
        self.assertFalse(different["comparison"]["same"])
        self.assertEqual(same["result"]["rows"], [])
        self.assertEqual(different["result"]["rows"], [])

    def test_blank_and_malformed_generic_ap_observations_are_not_active(self):
        rows = reconcile_ap_rows([
            {"ip": "", "name": "", "mac": "", "status": "OFFLINE"},
            {"ip": ".1.3.6.1.4.1.25053.1", "name": "Ruckus-AP", "mac": "N/A", "status": "OFFLINE"},
            {"ip": "192.0.2.10", "name": "10 F9 20 EF B2 14", "mac": "N/A", "status": "ONLINE"},
        ])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["macs"], ["10f920efb214"])

    def test_canonical_relationships_keep_aliases_and_one_attachment(self):
        self.add_device("198.51.100.34", "SITEAZONE34SW01")
        self.add_ap("192.0.2.133", "SITE-A-ZONE34-AP239", "198.51.100.34", "SITEAZONE34SW01", "Gi1/0/1")
        self.add_ap("192.0.2.139", "SITEAZONE34AP239", "198.51.100.34", "SITEAZONE34SW01", "Gi1/0/1")
        self.app.state.sync_derived_state()

        attachments = self.app.state.rows(
            "SELECT * FROM relationships_current WHERE rel_type='ap_attachment' AND status!='disappeared'"
        )
        aliases = self.app.state.rows(
            "SELECT * FROM relationships_current WHERE rel_type='identity_alias' AND status!='disappeared'"
        )
        self.assertEqual(len(attachments), 1)
        self.assertEqual(len(aliases), 2)

    def test_migration_reconciliation_suppresses_structural_events(self):
        self.add_device("198.51.100.34", "SITEAZONE34SW01")
        self.add_ap("192.0.2.139", "SITEAZONE34AP239", "198.51.100.34", "SITEAZONE34SW01", "Gi1/0/1")
        result = self.app.state.sync_derived_state(origin="migration")

        self.assertGreater(sum(result["suppressed_structural_events"].values()), 0)
        self.assertEqual(self.app.state.one("SELECT COUNT(*) AS count FROM relationship_events")["count"], 0)
        self.assertEqual(self.app.state.one("SELECT COUNT(*) AS count FROM health_events")["count"], 0)
        self.assertGreater(self.app.state.one("SELECT COUNT(*) AS count FROM relationships_current")["count"], 0)
        run = self.app.state.one("SELECT * FROM scan_runs WHERE domain='migration'")
        self.assertIsNotNone(run)
        self.assertEqual(run["status"], "completed")

    def test_session_result_supports_natural_followups(self):
        self.seed_building9()
        session = {"history": []}
        first = self.app.ask_payload("List APs in ZONE10", netops.GlobalOptions(limit=20), session)
        self.app.natural_ask.update_session("List APs in ZONE10", first, session)
        followup = self.app.ask_payload("Which of them are offline?", netops.GlobalOptions(limit=20), session)
        self.assertTrue(followup["ok"])
        self.assertEqual(followup["intent"], "session_followup")
        self.assertEqual(followup["result"]["count"], 1)
        self.assertEqual(followup["result"]["rows"][0]["status"], "OFFLINE")

    def test_command_center_plans_representative_operations(self):
        cases = [
            ("Run a fast health check for ZONE34", "health-check", {"target": "ZONE34"}, "ready"),
            ("Refresh the AP and topology inventory", "workflow-refresh-inventory", {}, "ready"),
            ("Ping 198.51.100.92 five times", "diagnose-latency", {"target": "198.51.100.92", "count": "5"}, "ready"),
            ("Run a speed test three times", "diagnose-speed", {"runs": "3"}, "ready"),
            ("Run a quick speed test", "diagnose-speed", {"profile": "quick"}, "ready"),
            ("Test filtering for example.com", "diagnose-filtering", {"target": "example.com"}, "ready"),
            ("Run show version on SITEAZONE34SW01", "device-show", {"target": "SITEAZONE34SW01", "command": "show version"}, "ready"),
            ("Connect to admin-hill over SSH", "device-ssh", {"target": "admin-hill"}, "preview_only"),
            ("Locate VLAN 120 on ZONE34", "vlan-locate", {"target": "ZONE34", "vlan": "120"}, "ready"),
            ("Monitor Gi1/0/7 on ZONE34 once", "diagnose-interface", {"device": "ZONE34", "interface": "Gi1/0/7", "once": True}, "ready"),
        ]
        for question, action, expected_args, status in cases:
            with self.subTest(question=question):
                payload = self.app.ask_payload(question, netops.GlobalOptions(), {"history": []})
                plan = payload["command_plan"]
                self.assertEqual(payload["intent"], "command_plan")
                self.assertEqual(plan["action"], action)
                self.assertEqual(plan["args"], expected_args)
                self.assertEqual(plan["status"], status)
                self.assertIn("netops", plan["command"])

    def test_typed_vlan_plan_is_guarded_and_unsafe_show_is_blocked(self):
        config = self.app.ask_payload(
            "Preview changing Gi1/0/7 on ZONE34 to access VLAN 120",
            netops.GlobalOptions(),
            {"history": []},
        )["command_plan"]
        self.assertEqual(config["status"], "preview_only")
        self.assertTrue(config["run_supported"])
        self.assertIn("--confirm", config["command"])
        self.assertIn("configuration-backup", config["state_effects"])
        self.assertIn("post-change-verification", config["state_effects"])

        unsafe = self.app.ask_payload(
            "Run show version; reload on ZONE34",
            netops.GlobalOptions(),
            {"history": []},
        )["command_plan"]
        self.assertEqual(unsafe["status"], "blocked")
        self.assertFalse(unsafe["run_supported"])
        self.assertIn("policy-approved", unsafe["reason"])

    def test_command_plan_execution_has_separate_confirmation_gate(self):
        payload = self.app.ask_payload("Run a fast health check for ZONE34", netops.GlobalOptions(), {"history": []})
        with mock.patch.object(self.app, "emit"), mock.patch.object(self.app, "run_subprocess") as run:
            rc = self.app.execute_ask_plan(payload, netops.GlobalOptions(execute=True))
            self.assertEqual(rc, netops.CONFIRM_REQUIRED)
            run.assert_not_called()

        with mock.patch.object(self.app, "run_subprocess", return_value=0) as run:
            rc = self.app.execute_ask_plan(payload, netops.GlobalOptions(execute=True, confirm=True))
            self.assertEqual(rc, 0)
            self.assertEqual(run.call_args.args[0][-3:], ["health", "check", "ZONE34"])

    def test_read_only_local_plan_can_execute_without_active_confirmation(self):
        payload = self.app.ask_payload("Prepare the database status command", netops.GlobalOptions(), {"history": []})
        self.assertEqual(payload["command_plan"]["action"], "db-status")
        self.assertFalse(payload["command_plan"]["requires_confirmation"])
        with mock.patch.object(self.app, "run_subprocess", return_value=0) as run:
            rc = self.app.execute_ask_plan(payload, netops.GlobalOptions(execute=True))
            self.assertEqual(rc, 0)
            self.assertEqual(run.call_args.args[0][-2:], ["db", "status"])

    def test_registry_actions_all_generate_validated_previews(self):
        values = {
            "target": "ZONE34", "device": "ZONE34", "interface": "Gi1/0/7", "question": "show offline APs",
            "command": "show version", "commands": "interface Gi1/0/7", "vlan": "120", "vlan_mode": "access",
            "mac": "0200.0000.0025", "job_id": "abcd1234", "run_id": "abcd1234", "action": "db-status",
            "count": "3", "runs": "2", "chart": "classic", "profile": "quick", "port": "5201", "seconds": "1",
            "parallel": "1", "sample_seconds": "1", "expected_speed": "1000", "wait": "1", "depth": "1",
            "max_nodes": "8", "mode": "cached", "native_vlan": "", "replace": "false", "once": "true",
            "online": "false", "explain": "false", "refresh_neighbors": "false", "target2": "ZONE35",
            "fingerprint": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "group": "netops.parsers",
            "plugin_id": "netops.parsers:fixture", "direction": "both", "scope": "all", "source": "CORE01",
            "destination": "ZONE34", "reason": "verified fixture relationship", "merge_id": "merge-fixture",
            "phrase": "test site", "alias_target": "ZONE34", "name": "audit-profile", "key": "core_switch_ip",
            "value": "192.0.2.1", "channel": "fixture", "endpoint": "0200.0000.0025", "bind": "192.0.2.25",
            "ca_file": "/tmp/netops-fixture-ca.pem", "core": "ZONE35",
        }
        specs = self.app.command_registry()
        self.assertGreaterEqual(len(specs), 60)
        self.assertEqual(len({spec.id for spec in specs}), len(specs))
        self.assertTrue(set(netops.HELP_TOPICS).issubset({spec.domain for spec in specs}))
        for spec in specs:
            with self.subTest(action=spec.id):
                args = {field["name"]: values.get(field["name"], "value") for field in spec.inferred_arg_schema()}
                preview = self.app.preview_for_action(spec.id, args)
                self.assertEqual(preview["action"], spec.id)
                self.assertIn("netops", preview["command"])
                self.assertEqual(preview["validation_error"], "")
                self.assertEqual(preview["read_only"], spec.read_only)
                self.assertEqual(preview["writes_local"], spec.writes_local)
        command_payload = {item["id"]: item for item in self.app.command_payload()["commands"]}
        health_target = next(field for field in command_payload["health-check"]["arg_schema"] if field["name"] == "target")
        lookup_mac_target = next(field for field in command_payload["lookup-mac"]["arg_schema"] if field["name"] == "target")
        self.assertFalse(health_target["required"])
        self.assertFalse(lookup_mac_target["required"])

    def test_every_registry_label_is_naturally_addressable(self):
        for spec in self.app.command_registry():
            if spec.id == "ask-query":
                continue
            with self.subTest(action=spec.id):
                payload = self.app.ask_payload(
                    f"Prepare the {spec.label} command",
                    netops.GlobalOptions(),
                    {"history": []},
                )
                self.assertEqual((payload.get("command_plan") or {}).get("action"), spec.id)

    def test_public_help_actions_have_registry_coverage(self):
        semantic_aliases = {
            ("ap", "show"): "ap-list",
            ("db", "import-flat"): "inventory-import-flat",
            ("db", "export-flat"): "inventory-export-flat",
            ("ask", "question"): "ask-query",
            ("ask", "alias"): "ask-alias-set",
            ("commands", "run"): "commands-run",
        }
        ids = {spec.id for spec in self.app.command_registry()}
        for domain, topic in netops.HELP_TOPICS.items():
            for action in topic["actions"]:
                expected = semantic_aliases.get((domain, action), f"{domain}-{action}")
                with self.subTest(domain=domain, action=action):
                    self.assertIn(expected, ids)

    def test_every_public_action_help_route_executes(self):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            for domain, topic in netops.HELP_TOPICS.items():
                for action in topic["actions"]:
                    with self.subTest(domain=domain, action=action):
                        code = netops.main([domain, action, "--help"]) if domain == "tui" else self.app.dispatch([domain, action, "--help"])
                        self.assertEqual(code, netops.SUCCESS)

    def test_every_supported_registry_command_reaches_a_real_handler(self):
        values = {
            "target": "ZONE34", "device": "ZONE34", "interface": "Gi1/0/7",
            "question": "show offline APs", "command": "show version",
            "commands": "interface Gi1/0/7", "vlan": "120", "vlan_mode": "access",
            "mac": "0200.0000.0025", "job_id": "abcd1234", "run_id": "abcd1234",
            "action": "db-status", "count": "3", "runs": "2", "chart": "classic",
            "profile": "quick", "name": "audit-profile", "key": "core_switch_ip",
            "value": "192.0.2.1", "channel": "fixture", "plugin_id": "netops.parsers:fixture",
            "group": "netops.parsers", "endpoint": "0200.0000.0025", "source": "CORE01",
            "destination": "ZONE34", "reason": "verified fixture relationship",
            "merge_id": "merge-fixture", "alias_target": "ZONE34", "phrase": "test site",
            "direction": "both", "parallel": "1", "sample_seconds": "1",
            "expected_speed": "1000", "mode": "cached", "depth": "1", "max_nodes": "8",
            "native_vlan": "", "replace": "false", "target2": "ZONE35",
            "port": "5201", "seconds": "1", "wait": "1", "once": "true", "online": "false",
            "explain": "false", "refresh_neighbors": "false", "fingerprint": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "scope": "all", "bind": "192.0.2.25", "ca_file": "/tmp/netops-fixture-ca.pem",
            "core": "ZONE35",
        }
        self.add_device("198.51.100.34", "ZONE34")
        self.add_device("198.51.100.35", "ZONE35")
        failures = []
        with mock.patch.object(self.app, "capture", return_value=(0, "", "")), \
                mock.patch.object(self.app, "capture_streamed", return_value=(0, "", "")), \
                mock.patch.object(self.app, "emit"), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            for spec in self.app.command_registry():
                if not spec.run_supported:
                    continue
                for ip, hostname in (("198.51.100.34", "ZONE34"), ("198.51.100.35", "ZONE35")):
                    self.app.state.execute(
                        "INSERT OR REPLACE INTO devices(ip,hostname,platform,model,serial,mac,source,last_seen,status) VALUES(?,?,?,?,?,?,?,?,?)",
                        (ip, hostname, "Cisco", "C9300", f"SERIAL-{ip}", "", "test", 1000, "ONLINE"),
                    )
                self.app.config.public["core_switch_ip"] = "198.51.100.35"
                arguments = {
                    field["name"]: values.get(field["name"], "value")
                    for field in spec.inferred_arg_schema()
                }
                if spec.id == "lookup-core":
                    arguments["target"] = "192.0.2.50"
                try:
                    command, _, _ = self.app.command_for_action(spec.id, arguments)
                    code = self.app.dispatch([*command[1:], "--dry-run", "--plain", "--no-color"])
                except Exception as exc:  # pragma: no cover - reported with the action id below
                    failures.append(f"{spec.id}: raised {type(exc).__name__}: {exc}")
                    continue
                expected_validation = {"ingest-run", "plugin-enable", "plugin-disable", "path-show", "jobs-show", "jobs-logs"}
                if code in {netops.USAGE, netops.INTERNAL} or (code == netops.VALIDATION and spec.id not in expected_validation):
                    failures.append(f"{spec.id}: exited {code} for {command[1:]}")
        self.assertFalse(failures, "\n".join(failures))

    def test_natural_alias_administration_is_structured(self):
        plan = self.app.ask_payload(
            "Set Ask alias 'engineering office' to 'engg ofc'",
            netops.GlobalOptions(),
            {"history": []},
        )["command_plan"]
        self.assertEqual(plan["action"], "ask-alias-set")
        self.assertEqual(plan["args"], {"phrase": "engineering office", "alias_target": "engg ofc"})
        self.assertEqual(plan["safety_class"], "local-write")
        self.assertTrue(plan["requires_confirmation"])

    def test_command_plan_followup_reuses_and_changes_previous_plan(self):
        session = {"history": []}
        first = self.app.ask_payload("Run a health check for ZONE34", netops.GlobalOptions(), session)
        self.app.natural_ask.update_session("Run a health check for ZONE34", first, session)
        changed = self.app.ask_payload("Change the target to SQ21", netops.GlobalOptions(), session)
        self.assertEqual(changed["intent"], "command_followup")
        self.assertEqual(changed["command_plan"]["args"]["target"], "SQ21")
        self.assertIn("SQ21", changed["command_plan"]["command"])

    def test_health_predicate_reports_actual_state_and_dates_are_iso(self):
        self.add_device("198.51.100.22", "SITEAPAMAOSW02", status="OFFLINE")
        self.app.state.sync_derived_state()
        health = self.app.ask_payload("Is pamaosw02 online?", netops.GlobalOptions(), {"history": []})
        self.assertIn("offline, not online", health["answer"])
        details = self.app.ask_payload("When was SITEAPAMAOSW02 last seen?", netops.GlobalOptions(), {"history": []})
        self.assertIn("1970-01-01T00:16:40Z", details["answer"])

    def test_collection_fillers_and_connected_device_wording(self):
        self.seed_building9()
        aps = self.app.ask_payload("all APs that are down", netops.GlobalOptions(limit=20), {"history": []})
        self.assertEqual(aps["intent"], "ap_inventory")
        self.assertEqual(aps["result"]["count"], 1)
        self.assertEqual(aps["target"], "")

        self.add_device("198.51.100.44", "SITE-A-ACCESS-01")
        self.app.state.execute(
            "INSERT INTO neighbors(local_ip,local_name,local_port,remote_name,remote_port,remote_ip) VALUES(?,?,?,?,?,?)",
            ("198.51.100.44", "SITE-A-ACCESS-01", "Gi1/0/1", "SITE-A-EDGE-01", "Gi0/1", "198.51.100.45"),
        )
        connected = self.app.ask_payload("List all devices connected on SITE-A-ACCESS-01", netops.GlobalOptions(limit=20), {"history": []})
        self.assertEqual(connected["intent"], "topology")
        self.assertIn("SITE-A-EDGE-01", connected["answer"])

    def test_target_cleanup_preserves_opaque_identifiers(self):
        self.assertEqual(
            self.app.natural_ask._target_from_question("List all devices connected on SITE-A-ACCESS-01", (r"\b(?:devices?|connected)\b",)),
            "SITE-A-ACCESS-01",
        )
        self.assertEqual(
            self.app.natural_ask._target_from_question("What is connected to Gi1/0/48 on 192.0.2.10?", (r"\bconnected\b",)),
            "Gi1/0/48 192.0.2.10",
        )

    def test_question_catalog_is_broad_and_deterministic(self):
        payload = self.app.natural_ask.patterns_payload()
        self.assertGreaterEqual(len(payload["patterns"]), 18)
        self.assertGreaterEqual(payload["count"], 120)
        self.assertEqual(payload["engine"], "deterministic-command-center")

    def test_source_has_no_hidden_backspace_characters(self):
        for filename in ("netops_core.py", "netops_ask.py", "netops_identity.py"):
            source = (ROOT / filename).read_text(encoding="utf-8")
            self.assertNotIn("\x08", source, filename)

    def test_version_and_root_help_do_not_initialize_runtime_state(self):
        version_output = io.StringIO()
        help_output = io.StringIO()
        with mock.patch.object(netops.App, "__init__", side_effect=AssertionError("runtime state initialized")), mock.patch(
            "sys.stdout", version_output
        ):
            version_rc = netops.main(["--version"])
        with mock.patch.object(netops.App, "__init__", side_effect=AssertionError("runtime state initialized")), mock.patch(
            "sys.stdout", help_output
        ):
            help_rc = netops.main(["--help"])
        self.assertEqual((version_rc, help_rc), (netops.SUCCESS, netops.SUCCESS))
        self.assertEqual(version_output.getvalue().strip(), f"NetOps {netops.VERSION}")
        self.assertIn("Usage:", help_output.getvalue())


if __name__ == "__main__":
    unittest.main()
