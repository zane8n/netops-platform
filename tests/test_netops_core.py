import base64
import importlib.util
import io
import json
import os
import re
import contextlib
import signal
import subprocess
import sys
from pathlib import Path
import tempfile
import threading
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
        with mock.patch.dict(os.environ, {"NETRUNE_TARGET_ABBREVIATION_PREFIX": "192.0"}):
            self.assertEqual(netops.normalize_target_literal("2.71"), "192.0.2.71")
        with mock.patch.dict(os.environ, {"NETOPS_TARGET_ABBREVIATION_PREFIX": "192.0"}, clear=True):
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
        self.assertEqual(Path(helper[0]).name, "netrune-connect")
        self.assertEqual(helper[1:], ["7.71"])
        detached.assert_not_called()

    def test_device_ssh_normalizes_legacy_option_and_rejects_unknown_options(self):
        with mock.patch.object(self.app, "run_vault_interactive", return_value=0) as foreground:
            rc = self.app.cmd_device(["ssh", "--legacy", "SITE-A-ACCESS-01"], netops.GlobalOptions())
        self.assertEqual(rc, 0)
        helper = foreground.call_args.args[0]
        self.assertEqual(Path(helper[0]).name, "netrune-connect")
        self.assertEqual(helper[1:], ["--legacy", "SITE-A-ACCESS-01"])

        with mock.patch.object(self.app, "run_vault_interactive") as blocked, mock.patch.object(self.app, "emit"):
            rc = self.app.cmd_device(["ssh", "--unsupported", "SITE-A-ACCESS-01"], netops.GlobalOptions())
        self.assertEqual(rc, netops.VALIDATION)
        blocked.assert_not_called()

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

    def test_continuity_match_evidence_detects_vendor_swap_via_attachment(self):
        old = {"name": "SITE-A-AP12", "mac": "aabbccddeeff", "model": "Ruckus R510",
               "switch_ip": "198.51.100.5", "switch_port": "Gi1/0/12", "last_seen": 1000}
        new = {"name": "NEWCISCO-AP-01", "mac": "001122334455", "model": "Cisco 9120",
               "switch_ip": "198.51.100.5", "switch_port": "Gi1/0/12", "first_seen": 1200}
        assessment = identity_module.continuity_match_evidence(old, new, "ap", window_days=14)
        self.assertTrue(assessment["candidate"])
        self.assertTrue(assessment["signals"]["same_attachment_transition"])
        self.assertFalse(assessment["signals"]["same_model"])
        self.assertGreaterEqual(assessment["confidence"], 55)

    def test_continuity_match_evidence_detects_role_number_across_location_change(self):
        old = {"name": "SITE-B-SW03", "last_seen": 1000}
        new = {"name": "TOWER-C-SW03", "first_seen": 1100}
        assessment = identity_module.continuity_match_evidence(old, new, "switch", window_days=14)
        self.assertTrue(assessment["candidate"])
        self.assertTrue(assessment["signals"]["same_role_number_only"])
        self.assertFalse(assessment["signals"]["same_location_and_role_number"])

    def test_continuity_match_evidence_requires_a_structural_signal_not_timing_alone(self):
        old = {"name": "RANDOM-THING", "last_seen": 1000}
        new = {"name": "UNRELATED-OTHER", "first_seen": 1005}
        assessment = identity_module.continuity_match_evidence(old, new, "switch", window_days=14)
        self.assertFalse(assessment["candidate"])
        self.assertEqual(assessment["confidence"], 0)

    def test_identity_continuity_candidates_ignores_unrelated_pairs(self):
        old_pool = [{"name": "SITE-A-SW01", "last_seen": 1000}, {"name": "UNRELATED-SW09", "last_seen": 1000}]
        new_pool = [{"name": "BUILDING-7-SW01", "first_seen": 1200}, {"name": "SOMETHING-ELSE-SW22", "first_seen": 1200}]
        candidates = identity_module.identity_continuity_candidates(old_pool, new_pool, "switch", window_days=14)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["old"]["name"], "SITE-A-SW01")
        self.assertEqual(candidates[0]["new"]["name"], "BUILDING-7-SW01")

    def test_cluster_rename_candidates_collapses_a_consistent_site_rename(self):
        candidates = [
            {"old": {"name": f"SITE-B-SW0{i}"}, "new": {"name": f"TOWER-C-SW0{i}"}}
            for i in range(1, 4)
        ]
        clusters, singles = identity_module.cluster_rename_candidates(candidates, min_members=3)
        self.assertEqual(len(clusters), 1)
        self.assertEqual(clusters[0]["member_count"], 3)
        self.assertEqual(len(singles), 0)

        below_minimum = candidates[:2]
        clusters2, singles2 = identity_module.cluster_rename_candidates(below_minimum, min_members=3)
        self.assertEqual(clusters2, [])
        self.assertEqual(len(singles2), 2)

    def test_switch_learned_ap_port_wins_over_the_controller_placeholder(self):
        # The controller record is newer and is the only one carrying an
        # address, so it wins the identity contest. It must still not overwrite
        # the physical port that only the switch can know.
        rows = reconcile_ap_rows([
            {"ip": "198.51.100.55", "name": "SITE-A-AP07", "platform": "Cisco-AP",
             "switch_ip": "198.51.100.9", "switch_name": "Cisco-WLC", "switch_port": "wireless",
             "mac": "00:11:22:33:44:55", "last_seen": 2000, "status": "ONLINE"},
            {"ip": "", "name": "SITE-A-AP07", "platform": "Cisco AIR-AP2802I",
             "switch_ip": "198.51.100.12", "switch_name": "SITE-A-FIN-SW02", "switch_port": "7",
             "mac": "00:11:22:33:44:55", "last_seen": 1900, "status": "ONLINE"},
        ])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["ip"], "198.51.100.55")
        self.assertEqual(rows[0]["switch_name"], "SITE-A-FIN-SW02")
        self.assertEqual(rows[0]["switch_port"], "7")
        self.assertEqual(rows[0]["attachment_source"], "switch")

    def test_controller_only_ap_reports_its_attachment_honestly(self):
        rows = reconcile_ap_rows([
            {"ip": "198.51.100.57", "name": "SITE-A-AP08", "platform": "Ruckus R650",
             "switch_ip": "198.51.100.8", "switch_name": "Ruckus-vSZ", "switch_port": "wireless",
             "mac": "00:11:22:33:44:66", "last_seen": 2000, "status": "ONLINE"},
        ])
        self.assertEqual(rows[0]["switch_port"], "wireless")
        self.assertEqual(rows[0]["attachment_source"], "controller")

    def test_ap_move_still_follows_the_newest_switch_attachment(self):
        rows = reconcile_ap_rows([
            {"ip": "198.51.100.55", "name": "SITE-A-AP07", "switch_ip": "198.51.100.12",
             "switch_name": "SITE-A-FIN-SW02", "switch_port": "7",
             "mac": "00:11:22:33:44:55", "last_seen": 1900, "status": "ONLINE"},
            {"ip": "198.51.100.55", "name": "SITE-A-AP07", "switch_ip": "198.51.100.13",
             "switch_name": "SITE-A-FIN-SW03", "switch_port": "12",
             "mac": "00:11:22:33:44:55", "last_seen": 2500, "status": "ONLINE"},
        ])
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0]["switch_name"], rows[0]["switch_port"]), ("SITE-A-FIN-SW03", "12"))

    def test_flat_ap_dedupe_keeps_the_switch_learned_port(self):
        deduped = self.app.state._dedupe_ap_pipe_rows([
            ["198.51.100.55", "SITE-A-AP07", "Cisco-AP", "198.51.100.9", "Cisco-WLC", "wireless",
             "00:11:22:33:44:55", "2000", "ONLINE"],
            ["198.51.100.55", "SITE-A-AP07", "Cisco AIR-AP2802I", "198.51.100.12", "SITE-A-FIN-SW02", "7",
             "00:11:22:33:44:55", "1900", "ONLINE"],
        ])
        self.assertEqual(len(deduped), 1)
        self.assertEqual(deduped[0][4], "SITE-A-FIN-SW02")
        self.assertEqual(deduped[0][5], "7")

    def stp_report(self, own, root_mac, root_port, ports):
        rows = "\n".join(
            f"  {port:<5} 1000LX     | {cost:<9} 128  {state:<12} | {bridge:<17} 2    Yes {edge}"
            for port, cost, state, bridge, edge in ports
        )
        return (
            " Multiple Spanning Tree (MST) Information\n"
            "  STP Enabled   : Yes\n"
            "  Force Version : MSTP-operation\n"
            f"  Switch MAC Address : {own}\n"
            f"  CST Root MAC Address : {root_mac}\n"
            f"  CST Root Port        : {root_port}\n\n"
            "  Port  Type       | Cost      rity State        | Bridge            Time PtP Edge\n"
            "  ----- ---------- + --------- ---- ------------ + ----------------- ---- --- ----\n"
            + rows + "\n"
        )

    def build_stp_network(self):
        """CORE is root; DIST and ACCESS hang below it. LLDP knows CORE<->DIST only."""
        reports = {
            "192.0.2.1": self.stp_report("ccb6c8-4eed80", "ccb6c8-4eed80", "", [
                ("1", "20000", "Forwarding", "ccb6c8-4eed80", "No"),
                ("3", "20000", "Forwarding", "ccb6c8-4eed80", "Yes"),
            ]),
            "192.0.2.2": self.stp_report("94f128-2daa00", "ccb6c8-4eed80", "25", [
                ("7", "20000", "Forwarding", "94f128-2daa00", "No"),
                ("25", "20000", "Forwarding", "ccb6c8-4eed80", "No"),
            ]),
            "192.0.2.11": self.stp_report("d06726-f2b6a0", "ccb6c8-4eed80", "25", [
                ("1", "20000", "Forwarding", "d06726-f2b6a0", "Yes"),
                ("25", "20000", "Forwarding", "94f128-2daa00", "No"),
                ("26", "20000", "Blocking", "ccb6c8-4eed80", "No"),
            ]),
        }
        names = {"192.0.2.1": "SITE-CORE-01", "192.0.2.2": "SITE-DIST-01", "192.0.2.11": "SITE-ACCESS-01"}
        for ip, name in names.items():
            # Only the core has a MAC on file; the others were found by scan.
            mac = "ccb6c84eed80" if ip == "192.0.2.1" else ""
            self.app.state.execute(
                "INSERT INTO devices(ip,hostname,platform,model,serial,mac,source,last_seen,status) VALUES(?,?,?,?,?,?,?,?,?)",
                (ip, name, "Aruba AOS-S", "2930F", "", mac, "test", 1000, "ONLINE"),
            )
        self.app.state.execute(
            "INSERT INTO neighbors(local_ip,local_name,local_port,remote_name,remote_port,remote_ip) VALUES(?,?,?,?,?,?)",
            ("192.0.2.1", "SITE-CORE-01", "1", "SITE-DIST-01", "25", "192.0.2.2"),
        )

        def capture(command, timeout=0):
            return (0, reports.get(command[2] if len(command) > 2 else "", ""), "")

        return capture

    def test_spanning_tree_derives_links_from_designated_bridge_addresses(self):
        capture = self.build_stp_network()
        with mock.patch.object(self.app, "capture", side_effect=capture):
            report = self.app.collect_spanning_tree_topology(netops.GlobalOptions())

        self.assertEqual(report["switches_inspected"], 3)
        self.assertEqual(report["switches_failed"], 0)
        links = {(row["local_id"], row["local_port"], row["remote_id"]) for row in report["links"]}
        self.assertEqual(links, {
            ("192.0.2.2", "25", "192.0.2.1"),    # DIST root port toward CORE
            ("192.0.2.11", "25", "192.0.2.2"),   # ACCESS root port toward DIST
            ("192.0.2.11", "26", "192.0.2.1"),   # blocked redundant link to CORE
        })
        # A port whose designated bridge is this switch faces downstream and
        # names nobody, so it must not produce a link.
        self.assertNotIn("192.0.2.1", {row["local_id"] for row in report["links"]})
        # Edge ports are never links.
        self.assertNotIn("1", {row["local_port"] for row in report["links"]})

    def test_spanning_tree_marks_a_blocked_redundant_link_as_alternate(self):
        capture = self.build_stp_network()
        with mock.patch.object(self.app, "capture", side_effect=capture):
            report = self.app.collect_spanning_tree_topology(netops.GlobalOptions())
        blocked = next(row for row in report["links"] if row["local_port"] == "26")
        self.assertEqual(blocked["role"], "alternate")
        self.assertEqual(blocked["state"], "blocking")

    def test_spanning_tree_link_confirmed_by_lldp_scores_above_either_alone(self):
        capture = self.build_stp_network()
        with mock.patch.object(self.app, "capture", side_effect=capture):
            report = self.app.collect_spanning_tree_topology(netops.GlobalOptions())
        by_port = {row["local_port"]: row for row in report["links"]}
        # LLDP records the CORE side of the CORE<->DIST link; spanning tree
        # records the DIST side. Corroboration is per device pair.
        self.assertTrue(by_port["25"]["corroborates_lldp"])
        self.assertEqual(by_port["25"]["confidence"], 96)
        self.assertFalse(by_port["26"]["corroborates_lldp"])
        self.assertEqual(by_port["26"]["confidence"], 82)
        self.assertEqual(report["corroborated_links"], 1)
        self.assertEqual(report["new_links"], 2)

    def test_spanning_tree_records_a_switch_bridge_mac_without_overwriting_inventory(self):
        capture = self.build_stp_network()
        before = {row["ip"]: row["mac"] for row in self.app.state.rows("SELECT ip,mac FROM devices")}
        self.assertEqual(before["192.0.2.2"], "")
        with mock.patch.object(self.app, "capture", side_effect=capture):
            self.app.collect_spanning_tree_topology(netops.GlobalOptions())
        after = {row["ip"]: row["mac"] for row in self.app.state.rows("SELECT ip,mac FROM devices")}
        self.assertEqual(after["192.0.2.2"], "94f1282daa00")
        self.assertEqual(after["192.0.2.11"], "d06726f2b6a0")
        # An address already on file stays authoritative.
        self.assertEqual(after["192.0.2.1"], before["192.0.2.1"])

    def test_spanning_tree_leaves_an_unknown_designated_bridge_unresolved(self):
        self.add_device("192.0.2.50", "SITE-LONE-SW01", platform="Aruba AOS-S")
        report_text = self.stp_report("0a1b2c-3d4e5f", "ccb6c8-4eed80", "25", [
            ("25", "20000", "Forwarding", "feee00-112233", "No"),
        ])
        with mock.patch.object(self.app, "capture", return_value=(0, report_text, "")):
            report = self.app.collect_spanning_tree_topology(netops.GlobalOptions())
        self.assertEqual(report["links"], [])
        self.assertEqual(len(report["unresolved_bridges"]), 1)
        self.assertEqual(report["unresolved_bridges"][0]["designated_bridge"], "feee00112233")

    def test_spanning_tree_links_extend_the_path_graph_without_replacing_lldp(self):
        from netops_platform.path_inspector import PathInspector

        capture = self.build_stp_network()
        inspector = PathInspector(self.app)
        _, aliases = inspector._devices()
        before, _ = inspector._topology(aliases)
        before_pairs = {tuple(sorted((e.source, e.destination))) for edges in before.values() for e in edges}
        self.assertEqual(len(before_pairs), 1)

        with mock.patch.object(self.app, "capture", side_effect=capture):
            self.app.collect_spanning_tree_topology(netops.GlobalOptions())

        _, aliases = inspector._devices()
        after, _ = inspector._topology(aliases)
        after_pairs = {tuple(sorted((e.source, e.destination))) for edges in after.values() for e in edges}
        self.assertEqual(len(after_pairs), 3)

        # The LLDP edge survives with both ports; spanning-tree edges leave the
        # far-end port empty because spanning tree cannot name it.
        lldp_edge = next(e for e in after["192.0.2.1"] if e.destination == "192.0.2.2")
        self.assertEqual(lldp_edge.source_kind, "topology-cache")
        self.assertEqual((lldp_edge.source_port, lldp_edge.destination_port), ("1", "25"))
        stp_edge = next(e for e in after["192.0.2.11"] if e.destination == "192.0.2.2")
        self.assertEqual(stp_edge.source_kind, "spanning-tree")
        self.assertEqual(stp_edge.destination_port, "")

    class FakeTty(io.StringIO):
        def isatty(self):
            return True

        def fileno(self):
            return 2

    def render_progress(self, action, columns=80, tty=True, env=None):
        """Run a progress action against a fake terminal and return what it wrote.

        The suite disables progress globally, so the baseline here re-enables it
        and each case opts back out through `env`.
        """
        stream = self.FakeTty() if tty else io.StringIO()
        size = os.terminal_size((columns, 24))
        baseline = {"NETOPS_PROGRESS": "1"}
        baseline.update(env or {})
        netops.App._progress_active = False
        with mock.patch.object(netops.sys, "stderr", stream), \
             mock.patch.object(netops.os, "get_terminal_size", return_value=size), \
             mock.patch.dict(os.environ, baseline, clear=False):
            for key in ("NO_COLOR", "NETRUNE_PROGRESS"):
                if key not in baseline:
                    os.environ.pop(key, None)
            action()
        return stream.getvalue()

    def test_progress_line_never_reaches_the_last_column(self):
        long_name = "SITE-A-VERY-LONG-SWITCH-HOSTNAME-THAT-KEEPS-GOING-AND-GOING-01"
        for columns in (40, 60, 80, 120):
            with self.subTest(columns=columns):
                output = self.render_progress(
                    lambda: self.app._progress_step("topology stp", long_name, 3, 12, netops.GlobalOptions()),
                    columns=columns,
                )
                line = output.replace("\r", "").replace("\033[2K", "")
                # Writing into the final cell wraps the line, which turns a
                # transient status into a permanent one.
                self.assertLessEqual(len(line), columns - 1)
                self.assertTrue(line.startswith("[STATUS] topology stp"))

    def test_progress_counted_line_has_the_standard_shape(self):
        output = self.render_progress(
            lambda: self.app._progress_step("topology stp", "SITE-CORE-01", 3, 12, netops.GlobalOptions()),
            columns=120,
        )
        line = output.replace("\r", "").replace("\033[2K", "")
        self.assertEqual(line, "[STATUS] topology stp | SITE-CORE-01 | 3/12 | Ctrl+C cancels")

    def test_progress_is_suppressed_when_it_would_pollute_output(self):
        step = lambda: self.app._progress_step("topology stp", "SW01", 1, 2, netops.GlobalOptions())
        self.assertEqual(self.render_progress(step, tty=False), "")
        self.assertEqual(self.render_progress(step, env={"NO_COLOR": "1"}), "")
        self.assertEqual(self.render_progress(step, env={"NETRUNE_PROGRESS": "0"}), "")
        # The legacy name still works on its own; the canonical one wins when both are set.
        self.assertEqual(self.render_progress(step, env={"NETOPS_PROGRESS": "0"}), "")
        self.assertNotEqual(
            self.render_progress(step, env={"NETRUNE_PROGRESS": "1", "NETOPS_PROGRESS": "0"}), "")
        json_step = lambda: self.app._progress_step("topology stp", "SW01", 1, 2, netops.GlobalOptions(json=True))
        self.assertEqual(self.render_progress(json_step), "")

    def test_progress_line_is_cleared_before_any_full_line_write(self):
        def sequence():
            self.app._progress_step("topology stp", "SW01", 1, 2, netops.GlobalOptions())
            self.app.live_log("vault", "holding the vault open")

        output = self.render_progress(sequence, columns=120)
        # The clear must land between the status line and the log line, so the
        # log never shares a row with leftover status text.
        self.assertIn("Ctrl+C cancels\r\033[2K[VAULT]", output)

    def test_progress_line_is_cleared_before_final_output(self):
        def sequence():
            self.app._progress_step("topology stp", "SW01", 1, 2, netops.GlobalOptions())
            with contextlib.redirect_stdout(io.StringIO()):
                self.app.emit({"ok": True}, netops.GlobalOptions(), "done")

        self.assertTrue(self.render_progress(sequence, columns=120).endswith("\r\033[2K"))

    def test_progress_clear_is_a_no_op_when_no_line_is_showing(self):
        output = self.render_progress(lambda: self.app._progress_clear(netops.GlobalOptions()))
        self.assertEqual(output, "")

    def test_spanning_tree_run_reports_progress_per_switch(self):
        capture = self.build_stp_network()
        seen = []
        with mock.patch.object(self.app, "capture", side_effect=capture), \
             mock.patch.object(self.app, "_progress_step", side_effect=lambda *a, **k: seen.append(a)):
            self.app.collect_spanning_tree_topology(netops.GlobalOptions())
        self.assertEqual([(scope, current, total) for scope, _, current, total, _opts in seen],
                         [("topology stp", 1, 3), ("topology stp", 2, 3), ("topology stp", 3, 3)])

    def test_spanning_tree_run_does_not_prompt_for_the_vault_without_a_terminal(self):
        capture = self.build_stp_network()
        with mock.patch.object(self.app, "capture", side_effect=capture), \
             mock.patch.object(self.app, "run_vault_interactive") as unlock:
            report = self.app.collect_spanning_tree_topology(netops.GlobalOptions())
        # pytest gives no tty, so an unlock could never be answered.
        unlock.assert_not_called()
        self.assertFalse(report["vault_session_held"])

    def test_spanning_tree_run_leaves_an_existing_vault_session_untouched(self):
        capture = self.build_stp_network()
        with mock.patch.object(self.app, "capture", side_effect=capture), \
             mock.patch.object(self.app, "vault_session_payload", return_value={"active": True}), \
             mock.patch.object(self.app, "run_vault_interactive") as vault:
            report = self.app.collect_spanning_tree_topology(netops.GlobalOptions())
        # Already unlocked by the operator: do not re-unlock, and above all do
        # not lock it again on the way out.
        vault.assert_not_called()
        self.assertFalse(report["vault_session_held"])

    def test_spanning_tree_run_closes_a_session_it_opened_even_on_failure(self):
        calls = []

        def vault(command, opts):
            calls.append("unlock" if "--unlock-vault" in command else "lock")
            return netops.SUCCESS

        with mock.patch.object(netops.sys.stdin, "isatty", return_value=True), \
             mock.patch.object(self.app, "_progress_enabled", return_value=False), \
             mock.patch.object(self.app, "vault_session_payload", return_value={"active": False}), \
             mock.patch.object(self.app, "run_vault_interactive", side_effect=vault), \
             mock.patch.object(self.app, "inspect_spanning_tree", side_effect=RuntimeError("boom")):
            self.add_device("192.0.2.77", "SITE-BOOM-SW01", platform="Aruba AOS-S")
            with mock.patch.object(netops.sys.stderr, "isatty", return_value=True):
                report = self.app.collect_spanning_tree_topology(netops.GlobalOptions())
        self.assertEqual(calls, ["unlock", "lock"])
        self.assertTrue(report["vault_session_held"])
        self.assertEqual(report["switches_failed"], 1)

    def test_spanning_tree_reads_switches_in_parallel(self):
        capture = self.build_stp_network()
        concurrent_now = 0
        peak = 0
        guard = threading.Lock()

        def slow_capture(command, timeout=0):
            nonlocal concurrent_now, peak
            with guard:
                concurrent_now += 1
                peak = max(peak, concurrent_now)
            try:
                time.sleep(0.05)
                return capture(command, timeout)
            finally:
                with guard:
                    concurrent_now -= 1

        with mock.patch.object(self.app, "capture", side_effect=slow_capture):
            report = self.app.collect_spanning_tree_topology(netops.GlobalOptions(), jobs=3)
        self.assertEqual(report["parallel_jobs"], 3)
        self.assertGreater(peak, 1, "switches were still read one at a time")
        self.assertEqual(report["switches_inspected"], 3)

    def test_spanning_tree_parallel_reads_still_record_every_switch(self):
        capture = self.build_stp_network()
        with mock.patch.object(self.app, "capture", side_effect=capture):
            report = self.app.collect_spanning_tree_topology(netops.GlobalOptions(), jobs=3)
        # Recording is deferred out of the worker threads, so it must still happen.
        macs = {row["ip"]: row["mac"] for row in self.app.state.rows("SELECT ip,mac FROM devices")}
        self.assertEqual(macs["192.0.2.2"], "94f1282daa00")
        self.assertEqual(macs["192.0.2.11"], "d06726f2b6a0")
        evidence = self.app.state.rows("SELECT device_id FROM capability_evidence WHERE capability='stp'")
        self.assertEqual({row["device_id"] for row in evidence}, {"192.0.2.1", "192.0.2.2", "192.0.2.11"})
        self.assertEqual(len(report["links"]), 3)

    def test_spanning_tree_report_is_ordered_by_inventory_not_completion(self):
        capture = self.build_stp_network()
        delays = {"192.0.2.1": 0.15, "192.0.2.2": 0.05, "192.0.2.11": 0.0}

        def staggered(command, timeout=0):
            target = command[2] if len(command) > 2 else ""
            time.sleep(delays.get(target, 0))
            return capture(command, timeout)

        with mock.patch.object(self.app, "capture", side_effect=staggered):
            report = self.app.collect_spanning_tree_topology(netops.GlobalOptions(), jobs=3)
        # Inventory order is by hostname: ACCESS-01, CORE-01, DIST-01 - and the
        # slowest switch finishing first must not reorder the report.
        self.assertEqual([row["local_id"] for row in report["links"]],
                         ["192.0.2.11", "192.0.2.11", "192.0.2.2"])

    def test_spanning_tree_failure_records_what_the_switch_returned(self):
        self.add_device("192.0.2.61", "SITE-QUIET-SW01", platform="Aruba AOS-S")
        junk = "Invalid input: spanning\nsomething unexpected from the transport"
        with mock.patch.object(self.app, "capture", return_value=(0, junk, "")):
            report = self.app.collect_spanning_tree_topology(netops.GlobalOptions())

        self.assertEqual(report["switches_failed"], 1)
        failure = report["failures"][0]
        # A failed sweep must leave behind the bytes that failed, otherwise an
        # unparsed result is indistinguishable from an unreachable switch.
        self.assertIn("Invalid input", failure["raw_excerpt"])
        self.assertGreater(failure["raw_bytes"], 0)

        stored = self.app.state.one(
            "SELECT state,facts_json FROM capability_evidence WHERE capability='stp' AND device_id='192.0.2.61'"
        )
        self.assertIsNotNone(stored, "the failure was not recorded at all")
        facts = json.loads(stored["facts_json"])
        self.assertIn("Invalid input", facts["raw_excerpt"])
        self.assertEqual(stored["state"], "unsupported")

    def test_spanning_tree_unreachable_switch_is_distinguishable_from_bad_output(self):
        self.add_device("192.0.2.62", "SITE-DEAD-SW01", platform="Aruba AOS-S")
        with mock.patch.object(self.app, "capture", return_value=(1, "", "ssh: connect to host port 22: No route to host")):
            report = self.app.collect_spanning_tree_topology(netops.GlobalOptions())
        failure = report["failures"][0]
        self.assertIn("No route to host", failure["raw_excerpt"])

    def test_spanning_tree_sweep_skips_offline_devices(self):
        self.add_device("192.0.2.63", "SITE-UP-SW01", platform="Aruba AOS-S")
        self.add_device("192.0.2.64", "SITE-DOWN-SW01", platform="Aruba AOS-S", status="OFFLINE")
        seen = []

        def capture(command, timeout=0):
            seen.append(command[2] if len(command) > 2 else "")
            return (0, "", "")

        with mock.patch.object(self.app, "capture", side_effect=capture):
            report = self.app.collect_spanning_tree_topology(netops.GlobalOptions())
        # An offline switch cannot answer and would burn a full SSH timeout.
        self.assertNotIn("192.0.2.64", seen)
        self.assertEqual(report["switches_total"], 1)

    def test_a_device_change_reaches_the_flat_inventory_automatically(self):
        """The shell helpers read the flat file, so a change confined to SQLite
        made them keep using the wrong vendor driver. Nothing should have to
        remember to export."""
        self.add_device("192.0.2.80", "SITE-A-SW80", platform="Aruba AOS-S")
        self.app.state.export_flat_files()
        self.assertIn("Aruba AOS-S", self.app.paths.devices_file.read_text(encoding="utf-8"))

        self.app.state.execute("UPDATE devices SET platform='Cisco IOS' WHERE ip=?", ("192.0.2.80",))
        self.assertTrue(self.app.state.inventory_dirty, "an inventory write must mark an export owed")
        # Building the environment for any helper is what guarantees freshness:
        # the helper reads the flat file, so it must never predate the change.
        self.app.child_env(netops.GlobalOptions())
        flat = self.app.paths.devices_file.read_text(encoding="utf-8")
        self.assertIn("Cisco IOS", flat)
        self.assertNotIn("Aruba AOS-S", flat)
        self.assertFalse(self.app.state.inventory_dirty)

    def test_a_read_only_command_does_not_rewrite_the_flat_inventory(self):
        self.add_device("192.0.2.81", "SITE-A-SW81")
        self.app.state.inventory_dirty = False
        self.app.state.rows("SELECT ip FROM devices")
        self.assertFalse(self.app.state.inventory_dirty)

    def test_retention_prunes_history_but_never_audit_events(self):
        old_stamp = netops.now() - 400 * 86400
        self.app.state.execute(
            "INSERT INTO topology_events(created_at,event_type,local_ip,local_port,remote_name,remote_port,remote_ip,detail)"
            " VALUES(?,?,?,?,?,?,?,?)", (old_stamp, "link_added", "192.0.2.1", "Gi1/0/1", "X", "Gi1", "192.0.2.2", ""))
        self.app.state.record_audit_event("vault_unlocked", "vault-unlock", actor="tester", result="success")
        self.app.state.execute("UPDATE audit_events SET created_at=?", (old_stamp,))

        removed = self.app.state.prune_history()
        self.assertEqual(removed.get("topology_events"), 1)
        self.assertNotIn("audit_events", removed)
        # An audit record that expires is not an audit trail.
        self.assertEqual(self.app.state.one("SELECT COUNT(*) AS n FROM audit_events")["n"], 1)

    def test_retention_now_covers_the_tables_that_used_to_grow_unbounded(self):
        """command_history, scan_runs, and friends had no retention entry at
        all until now, so nothing ever pruned them on a long-running install."""
        old_stamp = netops.now() - 400 * 86400
        self.app.state.execute(
            "INSERT INTO command_history(created_at,action,command,exit_code,read_only) VALUES(?,?,?,?,?)",
            (old_stamp, "inventory-list", "netrune inventory list", 0, 1))
        self.app.state.execute(
            "INSERT INTO scan_runs(id,domain,started_at,finished_at,status,complete) VALUES(?,?,?,?,?,?)",
            ("scan-old", "topology", old_stamp, old_stamp, "completed", 1))
        self.app.state.execute(
            "INSERT INTO observation_rejects(run_id,channel,received_at,record_index,error_code,message)"
            " VALUES(?,?,?,?,?,?)", ("run-old", "test", old_stamp, 0, "bad_record", "malformed"))
        # Accepted observations are provenance, not diagnostic noise (ADR 0002):
        # this one must survive even though it is just as old as the rest.
        self.app.state.execute(
            "INSERT INTO observations(idempotency_key,entity_kind,stable_source_id,channel,observed_at,"
            "received_at,completeness,status,confidence,provenance_json,facts_json,raw_evidence_hash)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            ("idem-old", "device", "switch-old", "test", old_stamp, old_stamp,
             "partial", "observed", 90, "{}", "{}", "hash-old"))

        removed = self.app.state.prune_history()
        self.assertEqual(removed.get("command_history"), 1)
        self.assertEqual(removed.get("scan_runs"), 1)
        self.assertEqual(removed.get("observation_rejects"), 1)
        self.assertNotIn("observations", removed)
        self.assertEqual(self.app.state.one("SELECT COUNT(*) AS n FROM observations")["n"], 1)

    def test_redaction_masks_secrets_that_appear_inside_values(self):
        detail = {"excerpt": "snmp-server community PrivateStr RO", "port": "Gi1/0/1"}
        redacted = netops.redact_for_api({"detail": detail})
        self.assertIn("***", redacted["detail"]["excerpt"])
        self.assertNotIn("PrivateStr", redacted["detail"]["excerpt"])
        # Ordinary operational text must survive untouched.
        self.assertEqual(redacted["detail"]["port"], "Gi1/0/1")

    def test_cached_device_output_is_redacted_before_storage(self):
        self.app.state.record_core_lookup("192.0.2.90", "username admin password Sup3rSecret", 0)
        stored = self.app.state.one("SELECT output FROM core_lookup_cache ORDER BY id DESC LIMIT 1")["output"]
        self.assertNotIn("Sup3rSecret", stored)
        self.assertIn("***", stored)

    def test_every_multi_device_operation_holds_one_vault_session(self):
        """Guards a bug that recurred three times: a command that reads several
        devices without holding the vault authenticates once per read, which on
        a Windows Hello stack is one biometric prompt per device.

        core.py's App class is being split into per-domain mixins (device_cli.py,
        inventory_cli.py, and more to come); this scans core.py plus every
        `*_cli.py` module so a moved method does not silently drop out of this
        check.
        """
        platform_dir = ROOT / "netops_platform"
        sources = [platform_dir / "core.py"] + sorted(platform_dir.glob("*_cli.py"))

        touches = {}
        scoped = set()
        for path in sources:
            lines = path.read_text(encoding="utf-8").splitlines()

            def enclosing(index, lines=lines):
                for position in range(index, 0, -1):
                    match = re.match(r"    def (\w+)", lines[position])
                    if match:
                        return match.group(1)
                return "?"

            for index, line in enumerate(lines):
                if "self.capture(self.legacy_cmd" in line or "self.capture_batch(" in line:
                    name = enclosing(index)
                    touches[name] = touches.get(name, 0) + 1
            scoped |= {enclosing(i) for i, l in enumerate(lines)
                       if "vault_session_scope" in l and "def " not in l}
        # Methods reached only from an already-scoped caller.
        covered_by_caller = {
            "inspect_spanning_tree", "inspect_path_forwarding_node", "inspect_path_layer3",
            "collect_path_capabilities", "live_switch_neighbors", "profile_mac_port",
            "locate_mac_live", "core_lookup_workflow", "cable_diagnostic", "apply_vlan_change",
            "apply_device_config_change", "_run_guarded_device_config_change", "_run_guarded_vlan_change",
        }
        unscoped = sorted(
            name for name, count in touches.items()
            if count > 1 and name not in scoped and name not in covered_by_caller
        )
        self.assertEqual(unscoped, [], f"multi-device operations with no vault session: {unscoped}")

    def test_capture_batch_splits_a_transcript_on_command_markers(self):
        transcript = (
            "###NETRUNE-CMD 1###\npager output\n"
            "###NETRUNE-CMD 2###\nspanning tree body\n"
            "###NETRUNE-CMD 3###\ncdp body\n"
        )
        with mock.patch.object(self.app, "capture", return_value=(0, transcript, "")):
            result = self.app.capture_batch("192.0.2.1", ["show spanning-tree", "show cdp neighbors"])
        # Marker 1 is the pager the driver prepends; the requested commands
        # start after it.
        self.assertEqual([command for command, _ in result], ["show spanning-tree", "show cdp neighbors"])
        self.assertIn("spanning tree body", result[0][1])
        self.assertIn("cdp body", result[1][1])

    def test_capture_batch_degrades_when_no_markers_come_back(self):
        with mock.patch.object(self.app, "capture", return_value=(0, "unmarked output", "")):
            result = self.app.capture_batch("192.0.2.1", ["show a", "show b"])
        # Without boundaries the transcript cannot be split; give it all to the
        # first command rather than returning nothing for every one.
        self.assertEqual(result[0][1], "unmarked output")
        self.assertEqual(result[1][1], "")

    def test_capture_batch_attributes_a_transport_failure_to_every_command(self):
        with mock.patch.object(self.app, "capture", return_value=(1, "", "ssh: no route to host")):
            result = self.app.capture_batch("192.0.2.1", ["show a", "show b"])
        self.assertTrue(all("no route to host" in output for _, output in result))

    def test_mac_lookup_across_switches_names_the_vendor(self):
        self.add_device("192.0.2.31", "SITE-A-SW01")
        with mock.patch.object(self.app, "capture", return_value=(1, "", "no match")), \
             mock.patch.object(self.app, "emit") as emit:
            self.app.lookup_mac_all("00:00:5e:00:53:01", netops.GlobalOptions())
        payload, _, text = emit.call_args.args
        self.assertIn("oui", payload)
        self.assertEqual(payload["vendor"], payload["oui"].get("vendor") or "Unknown")
        self.assertIn("Vendor/OUI:", text)

    def write_named_ssh_secret(self, recorded_at):
        """Mimic what `vault set` leaves behind: a named secret plus its rotation time."""
        secrets = self.app.paths.secrets_file
        secrets.parent.mkdir(parents=True, exist_ok=True)
        secrets.write_bytes(b"NETOPS-NAMED-SECRETS-GPG-V1\nciphertext:x")
        secrets.chmod(0o600)
        meta = self.app.paths.secrets_meta_file
        meta.parent.mkdir(parents=True, exist_ok=True)
        encoded = base64.b64encode(b"ssh/default/password").decode("ascii")
        meta.write_text(f"{encoded}|{recorded_at}\n", encoding="utf-8")
        return secrets

    def test_vault_status_reports_the_named_secret_that_vault_set_actually_wrote(self):
        legacy = Path(self.temp.name) / "legacy-sshpass.gpg"
        legacy.write_bytes(b"NETOPS-SUDO-GPG-V1\nstale")
        legacy.chmod(0o600)
        os.utime(legacy, (1_690_000_000, 1_690_000_000))
        recorded = 1_760_000_000
        secrets = self.write_named_ssh_secret(recorded)

        with mock.patch.dict(os.environ, {"NETRUNE_PASSWORD_FILE": str(legacy)}, clear=False):
            payload = self.app.vault_status_payload()

        # The rotation time must come from what `vault set` recorded, not from
        # the modification time of a legacy file it never touches.
        self.assertEqual(payload["credential_store"], "named-secret ssh/default/password")
        self.assertEqual(payload["path"], str(secrets))
        self.assertEqual(payload["modified_at"], recorded)
        self.assertEqual(payload["mode"], "sudo-gpg-v1")
        self.assertTrue(payload["legacy_vault_present"])
        self.assertEqual(payload["legacy_vault_path"], str(legacy))
        self.assertNotEqual(payload["modified_at"], 1_690_000_000)

    def test_vault_status_falls_back_to_the_legacy_file_when_no_named_secret_exists(self):
        legacy = Path(self.temp.name) / "legacy-sshpass.gpg"
        legacy.write_bytes(b"NETOPS-SUDO-GPG-V1\npayload")
        legacy.chmod(0o600)
        os.utime(legacy, (1_690_000_000, 1_690_000_000))
        with mock.patch.dict(os.environ, {"NETRUNE_PASSWORD_FILE": str(legacy)}, clear=False):
            payload = self.app.vault_status_payload()
        self.assertEqual(payload["credential_store"], "legacy-ssh-vault")
        self.assertEqual(payload["path"], str(legacy))
        self.assertEqual(payload["modified_at"], 1_690_000_000)

    def test_vault_status_rotation_reminder_follows_the_named_secret(self):
        # A secret recorded now is inside the 72h policy, so the reminder must
        # not inherit EXPIRED from a years-old legacy file.
        legacy = Path(self.temp.name) / "legacy-sshpass.gpg"
        legacy.write_bytes(b"NETOPS-SUDO-GPG-V1\nstale")
        legacy.chmod(0o600)
        os.utime(legacy, (1_600_000_000, 1_600_000_000))
        self.write_named_ssh_secret(int(time.time()))
        with mock.patch.dict(os.environ, {"NETRUNE_PASSWORD_FILE": str(legacy)}, clear=False):
            payload = self.app.vault_status_payload()
        self.assertEqual(payload["credential_state"], "ACTIVE")

    def test_live_switch_neighbors_batches_lldp_and_cdp_into_one_session(self):
        """Neighbor discovery runs LLDP and CDP against every switch in a
        topology scan; each used to be its own SSH login."""
        from netops_platform.devices import DeviceDriver

        two_command_driver = DeviceDriver(
            family="fixture-two-command", vendor="Fixture", os_name="FixtureOS",
            device_kind="switch", support_level="claimed",
            command_templates={"neighbors": ("show lldp neighbors detail", "show cdp neighbors detail")},
            capabilities={}, detection_patterns={}, detection_confidence=0,
        )
        transcript = ("###NETRUNE-CMD 1###\npager\n"
                      "###NETRUNE-CMD 2###\nlldp body\n"
                      "###NETRUNE-CMD 3###\ncdp body\n")
        with mock.patch.object(self.app, "driver_for", return_value=two_command_driver), \
             mock.patch.object(self.app, "capture", return_value=(0, transcript, "")) as capture, \
             mock.patch("netops_platform.vlan_cli.parse_neighbor_detail_output") as parse:
            parse.side_effect = lambda text: [{"remote_name": text.strip(), "local_port": "Gi1"}]
            self.app.live_switch_neighbors({"ip": "192.0.2.1", "hostname": "SW1", "platform": "Cisco"})
        capture.assert_called_once()
        self.assertIn("show-batch", capture.call_args.args[0])
        self.assertEqual(parse.call_args_list[0].args[0].strip(), "lldp body")
        self.assertEqual(parse.call_args_list[1].args[0].strip(), "cdp body")

    def test_profile_mac_port_batches_its_six_commands_into_one_session(self):
        """Profiling a MAC's port touches four to six show commands on the
        same switch; locate_mac_live can call this once per switch a MAC was
        seen on, so an unbatched version multiplies both counts together."""
        requested = self.app._mac_profile_commands("Cisco IOS-XE", "Gi1/0/7", "0200.0000.0025")
        self.assertEqual(len(requested), 6)
        pieces = ["pager"] + [f"body for {command}" for _, command in requested]
        transcript = "".join(f"###NETRUNE-CMD {index}###\n{body}\n" for index, body in enumerate(pieces, 1))
        with mock.patch.object(self.app, "capture", return_value=(0, transcript, "")) as capture:
            profile = self.app.profile_mac_port(
                {"switch_ip": "192.0.2.1", "switch_name": "SW1", "port": "Gi1/0/7", "platform": "Cisco IOS-XE",
                 "mac": "0200.0000.0025"}, netops.GlobalOptions())
        capture.assert_called_once()
        self.assertIn("show-batch", capture.call_args.args[0])
        self.assertEqual(len(profile["evidence"]), 6)
        for (evidence_type, command), row in zip(requested, profile["evidence"]):
            self.assertEqual(row["type"], evidence_type)
            self.assertEqual(row["command"], command)
            self.assertIn(f"body for {command}", row["excerpt"])
            self.assertEqual(row["exit_code"], 0)

    def test_named_secret_recorded_at_matches_the_shell_encoding(self):
        self.write_named_ssh_secret(1_759_000_000)
        self.assertEqual(self.app.named_secret_recorded_at("ssh/default/password"), 1_759_000_000)
        self.assertEqual(self.app.named_secret_recorded_at("ssh/other/password"), 0)

    def test_secrets_delete_of_an_unknown_name_is_rejected_before_confirm_is_even_asked_for(self):
        code = self.app.dispatch(["secrets", "delete", "snmp/site-a/auth"])
        self.assertEqual(code, netops.VALIDATION)
        self.assertEqual(self.app.state.rows("SELECT * FROM audit_events"), [])

    def test_secrets_delete_without_confirm_previews_the_secret_and_does_not_touch_it(self):
        self.write_named_ssh_secret(1_759_000_000)
        with mock.patch.object(self.app, "emit") as emit:
            code = self.app.dispatch(["secrets", "delete", "ssh/default/password"])
        self.assertEqual(code, netops.VALIDATION)
        payload, _, text = emit.call_args.args
        self.assertTrue(payload["requires_confirm"])
        self.assertEqual(payload["name"], "ssh/default/password")
        self.assertIn("ssh/default/password", text)
        self.assertIn("--confirm", text)
        self.assertTrue(self.app.paths.secrets_file.is_file())
        self.assertEqual(self.app.state.rows("SELECT * FROM audit_events"), [])

    def test_secrets_delete_with_confirm_records_an_audit_event(self):
        # Deleting from the real GPG-encrypted store is exercised end-to-end in
        # the shell lifecycle tests; this only proves the newly-added audit
        # wiring fires on a successful delete, the way inventory-forget's does.
        self.write_named_ssh_secret(1_759_000_000)
        with mock.patch.object(self.app, "run_subprocess", return_value=netops.SUCCESS) as run:
            code = self.app.dispatch(["secrets", "delete", "ssh/default/password", "--confirm"])
        self.assertEqual(code, netops.SUCCESS)
        run.assert_called_once()
        self.assertIn("--secret-delete", run.call_args.args[0])
        event = self.app.state.one("SELECT * FROM audit_events WHERE event_type='secrets'")
        self.assertEqual(event["action"], "secret-delete")
        self.assertEqual(event["result"], "success")
        self.assertEqual(event["target"], "ssh/default/password")

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

    def test_switch_names_are_compared_without_their_dns_domain(self):
        # A shared site domain alone pushed these distinct same-model SW01s
        # past the 75% threshold, so connect reached the wrong switch.
        names = [
            "ST-KB-CSM-MRM-SW01.site.example.com",
            "ST-KB-SHFT-KCD-GEOMOS-SW01.site.example.com",
            "ST-KB-CAMPB-SQ2-PREFABS-SW01.site.example.com",
            "ST-KB-CMPA-H39-SW01.site.example.com",
        ]
        for index, left in enumerate(names):
            for right in names[index + 1:]:
                with self.subTest(left=left, right=right):
                    assessment = identity_match_evidence(
                        {"hostname": left, "model": "C2960S", "serial": "N/A"},
                        {"hostname": right, "model": "C2960S", "serial": "N/A"},
                        "switch",
                    )
                    self.assertFalse(assessment["same_device"])
        fqdn_and_short = identity_match_evidence(
            {"hostname": "ST-KB-CMPA-H39-SW01"},
            {"hostname": "ST-KB-CMPA-H39-SW01.site.example.com"},
            "switch",
        )
        self.assertTrue(fqdn_and_short["same_device"])
        self.assertEqual(fqdn_and_short["signals"]["name_similarity"], 100)
        dotted_ap = identity_match_evidence({"name": "SITE.OFC.AP12"}, {"name": "SITE.OFC.AP13"}, "ap")
        self.assertIn("asset-number", dotted_ap["conflicts"])
        self.assertEqual(dotted_ap["left_normalized_name"], "SITEOFCAP12")
        rows = reconcile_device_rows([
            {"ip": "192.0.2.4", "hostname": names[0], "model": "C2960S", "serial": "N/A", "status": "ONLINE"},
            {"ip": "192.0.2.79", "hostname": names[3], "model": "C2960S", "serial": "N/A", "status": "ONLINE"},
        ])
        self.assertEqual(len(rows), 2)

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

    def merge_failure_detail(self, old, current):
        with mock.patch.object(self.app, "emit"), mock.patch.object(self.app, "usage_error", return_value=netops.VALIDATION) as usage:
            code = self.app.cmd_inventory(
                ["merge", old, current, "--reason", "hardware replacement"],
                netops.GlobalOptions(dry_run=True),
            )
        self.assertEqual(code, netops.VALIDATION)
        return usage.call_args.args[3]

    def test_manual_merge_names_the_argument_that_failed_to_resolve(self):
        self.add_device("192.0.2.21", "SITE-A-ACCESS-SW01")
        detail = self.merge_failure_detail("SITE-A-OLD-SW01", "SITE-A-ACCESS-SW01")
        self.assertIn("old-device 'SITE-A-OLD-SW01'", detail)
        self.assertIn("no active or historical device record", detail)

        detail = self.merge_failure_detail("SITE-A-ACCESS-SW01", "SITE-A-NEW-SW01")
        self.assertIn("current-device 'SITE-A-NEW-SW01'", detail)

    def test_manual_merge_reports_ambiguous_candidates(self):
        self.add_device("192.0.2.11", "SITE-A-OLD-SW01")
        self.add_device("192.0.2.21", "SITE-A-ACCESS-SW01")
        self.add_device("192.0.2.22", "SITE-A-ACCESS-SW01-SPARE")
        detail = self.merge_failure_detail("SITE-A-OLD-SW01", "SITEAACCESSSW01")
        self.assertIn("matched 2 devices", detail)
        self.assertIn("SITE-A-ACCESS-SW01-SPARE", detail)

    def test_manual_merge_explains_a_source_that_is_already_historical(self):
        self.add_device("192.0.2.21", "SITE-A-ACCESS-SW01")
        self.app.state.execute(
            "INSERT OR REPLACE INTO inventory_identity_state(identity_kind,identity_value,entity_type,ip,mac,name,platform,"
            "model,serial,switch_ip,switch_name,switch_port,source,status,first_seen,last_seen,updated_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("name", "site-a-old-sw01", "device", "192.0.2.11", "", "SITE-A-OLD-SW01", "Aruba AOS-S",
             "2930F", "SER", "", "", "", "test", "HISTORICAL", 900, 1000, 1000),
        )
        detail = self.merge_failure_detail("SITE-A-OLD-SW01", "SITE-A-ACCESS-SW01")
        self.assertIn("historical memory, not an active record", detail)
        self.assertIn("192.0.2.11", detail)

    def test_manual_merge_refuses_both_arguments_naming_one_device(self):
        self.add_device("192.0.2.21", "SITE-A-ACCESS-SW01")
        detail = self.merge_failure_detail("192.0.2.21", "SITE-A-ACCESS-SW01")
        self.assertIn("already one device", detail)

    def test_manual_merge_accepts_every_spelling_inventory_list_accepts(self):
        self.add_device("192.0.2.11", "SITE-A-OLD-SW01")
        self.add_device("192.0.2.21", "SITE-A-ACCESS-SW01.example.internal")
        with mock.patch.object(self.app, "emit") as emit:
            code = self.app.cmd_inventory(
                ["merge", "SITE-A-OLD-SW01", "SITE-A-ACCESS-SW01", "--reason", "hardware replacement"],
                netops.GlobalOptions(dry_run=True),
            )
        self.assertEqual(code, netops.SUCCESS)
        self.assertIn("192.0.2.21", emit.call_args.args[2])

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

    def test_sync_derived_state_detects_ap_vendor_swap_and_retracts_on_false_alarm(self):
        now = int(time.time())
        self.add_ap("192.0.2.50", "SITE-A-AP12", "198.51.100.10", "SITE-A-SW01", "Gi1/0/12", "aabbccddeeff", seen=now - 3600)
        self.app.state.sync_derived_state()
        self.app.state.execute("DELETE FROM aps WHERE ip='192.0.2.50'")
        self.add_ap("192.0.2.51", "NEWCISCO-AP-01", "198.51.100.10", "SITE-A-SW01", "Gi1/0/12", "001122334455", seen=now)
        self.app.state.sync_derived_state()

        rows = self.app.state.rows("SELECT * FROM relationships_current WHERE rel_type='identity_swap_candidate' AND status!='disappeared'")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["subject_id"], "mac:aabbccddeeff")
        self.assertEqual(rows[0]["object_id"], "mac:001122334455")
        signals = json.loads(rows[0]["attrs_json"])["signals"]
        self.assertTrue(signals["same_attachment_transition"])

        # False alarm: the old AP comes back. The candidate must auto-retract.
        self.add_ap("192.0.2.50", "SITE-A-AP12", "198.51.100.10", "SITE-A-SW01", "Gi1/0/12", "aabbccddeeff", seen=now + 60)
        self.app.state.sync_derived_state()
        active = self.app.state.rows("SELECT * FROM relationships_current WHERE rel_type='identity_swap_candidate' AND status!='disappeared'")
        self.assertEqual(len(active), 0)

    def test_attention_payload_surfaces_identity_swap_candidate_with_actionable_command(self):
        now = int(time.time())
        self.add_ap("192.0.2.50", "SITE-A-AP12", "198.51.100.10", "SITE-A-SW01", "Gi1/0/12", "aabbccddeeff", seen=now - 3600)
        self.app.state.sync_derived_state()
        self.app.state.execute("DELETE FROM aps WHERE ip='192.0.2.50'")
        self.add_ap("192.0.2.51", "NEWCISCO-AP-01", "198.51.100.10", "SITE-A-SW01", "Gi1/0/12", "001122334455", seen=now)
        self.app.state.sync_derived_state()

        payload = self.app.attention_payload(80)
        items = [item for item in payload["items"] if item["kind"] == "identity_swap_candidate"]
        self.assertEqual(len(items), 1)
        self.assertIn("SITE-A-AP12", items[0]["title"])
        self.assertIn("netrune ap merge 'SITE-A-AP12' 'NEWCISCO-AP-01'", items[0]["text"])
        self.assertIn("--dry-run", items[0]["text"])

    def test_attention_payload_collapses_site_rename_cluster_despite_low_member_confidence(self):
        now = int(time.time())
        for i in range(1, 4):
            self.add_device(f"198.51.100.{10 + i}", f"SITE-B-SW0{i}")
            self.app.state.execute("UPDATE devices SET last_seen=? WHERE ip=?", (now - 1800, f"198.51.100.{10 + i}"))
        self.app.state.sync_derived_state()
        for i in range(1, 4):
            self.app.state.execute("DELETE FROM devices WHERE ip=?", (f"198.51.100.{10 + i}",))
            self.add_device(f"198.51.100.{20 + i}", f"TOWER-C-SW0{i}")
            self.app.state.execute("UPDATE devices SET last_seen=? WHERE ip=?", (now, f"198.51.100.{20 + i}"))
        self.app.state.sync_derived_state()

        # Each pair is role-number-only (15) + model match (10) + near-full
        # temporal bonus: well below the default 55 floor on its own.
        pairs = self.app.state.rows("SELECT confidence FROM relationships_current WHERE rel_type='identity_swap_candidate' AND status!='disappeared'")
        self.assertEqual(len(pairs), 3)
        self.assertTrue(all(row["confidence"] < 55 for row in pairs))

        payload = self.app.attention_payload(80)
        clusters = [item for item in payload["items"] if item["kind"] == "identity_rename_cluster"]
        singles = [item for item in payload["items"] if item["kind"] == "identity_swap_candidate"]
        self.assertEqual(len(clusters), 1)
        self.assertEqual(clusters[0]["row"]["member_count"], 3)
        self.assertEqual(len(singles), 0)

    def test_attention_payload_hides_an_isolated_candidate_below_the_confidence_floor(self):
        now = int(time.time())
        # One lone role-number-only rename, with no siblings to cluster with,
        # scores the same way as a member of the cluster test above (well
        # under the floor) -- but with nothing to corroborate it, it must
        # stay out of the attention queue rather than add noise.
        self.add_device("198.51.100.201", "SITE-D-SW01")
        self.app.state.execute("UPDATE devices SET last_seen=? WHERE ip=?", (now - 1800, "198.51.100.201"))
        self.app.state.sync_derived_state()
        self.app.state.execute("DELETE FROM devices WHERE ip='198.51.100.201'")
        self.add_device("198.51.100.202", "ISLAND-E-SW01")
        self.app.state.execute("UPDATE devices SET last_seen=? WHERE ip=?", (now, "198.51.100.202"))
        self.app.state.sync_derived_state()

        stored = self.app.state.one("SELECT confidence FROM relationships_current WHERE rel_type='identity_swap_candidate' AND status!='disappeared'")
        self.assertIsNotNone(stored)
        self.assertLess(stored["confidence"], 55)

        payload = self.app.attention_payload(80)
        self.assertEqual([item for item in payload["items"] if item["kind"] in ("identity_swap_candidate", "identity_rename_cluster")], [])

    def test_attention_payload_stops_surfacing_a_candidate_past_its_ttl_but_keeps_the_record(self):
        now = int(time.time())
        self.add_ap("192.0.2.50", "SITE-A-AP12", "198.51.100.10", "SITE-A-SW01", "Gi1/0/12", "aabbccddeeff", seen=now - 3600)
        self.app.state.sync_derived_state()
        self.app.state.execute("DELETE FROM aps WHERE ip='192.0.2.50'")
        self.add_ap("192.0.2.51", "NEWCISCO-AP-01", "198.51.100.10", "SITE-A-SW01", "Gi1/0/12", "001122334455", seen=now)
        self.app.state.sync_derived_state()
        self.assertTrue(any(item["kind"] == "identity_swap_candidate" for item in self.app.attention_payload(80)["items"]))

        # Backdate the candidate past the default 30-day attention TTL without
        # touching the underlying evidence -- the record itself is retained
        # (same precedent as `ap_move_events`), only the surfaced queue ages out.
        self.app.state.execute(
            "UPDATE relationships_current SET last_seen=? WHERE rel_type='identity_swap_candidate'",
            (now - 31 * 86400,),
        )
        payload = self.app.attention_payload(80)
        self.assertFalse(any(item["kind"] == "identity_swap_candidate" for item in payload["items"]))
        self.assertEqual(self.app.state.one("SELECT COUNT(*) AS count FROM relationships_current WHERE rel_type='identity_swap_candidate' AND status!='disappeared'")["count"], 1)

    def ap_merge_failure_detail(self, old, current):
        with mock.patch.object(self.app, "emit"), mock.patch.object(self.app, "usage_error", return_value=netops.VALIDATION) as usage:
            code = self.app.cmd_ap(
                ["merge", old, current, "--reason", "vendor replacement"],
                netops.GlobalOptions(dry_run=True),
            )
        self.assertEqual(code, netops.VALIDATION)
        return usage.call_args.args[3]

    def test_ap_merge_retires_source_preserves_memory_and_is_reversible(self):
        self.add_ap("192.0.2.50", "SITE-A-AP12", "198.51.100.10", "SITE-A-SW01", "Gi1/0/12", "aabbccddeeff")
        self.add_ap("192.0.2.51", "NEWCISCO-AP-01", "198.51.100.10", "SITE-A-SW01", "Gi1/0/12", "001122334455")

        with mock.patch.object(self.app, "emit") as emit:
            preview = self.app.cmd_ap(
                ["merge", "SITE-A-AP12", "NEWCISCO-AP-01", "--reason", "vendor replacement"],
                netops.GlobalOptions(dry_run=True),
            )
        self.assertEqual(preview, netops.SUCCESS)
        self.assertEqual(self.app.state.one("SELECT COUNT(*) AS count FROM inventory_merges WHERE entity_type='ap'")["count"], 0)
        self.assertIn("Manual AP merge preview", emit.call_args.args[2])

        with mock.patch.object(self.app, "emit"):
            applied = self.app.cmd_ap(
                ["merge", "SITE-A-AP12", "NEWCISCO-AP-01", "--reason", "vendor replacement"],
                netops.GlobalOptions(confirm=True),
            )
        self.assertEqual(applied, netops.SUCCESS)
        self.assertIsNone(self.app.state.one("SELECT * FROM aps WHERE ip='192.0.2.50'"))
        merge = self.app.state.one("SELECT * FROM inventory_merges WHERE entity_type='ap' AND revoked_at IS NULL")
        self.assertIsNotNone(merge)
        self.assertIsNotNone(self.app.state.one("SELECT * FROM audit_events WHERE event_type='ap_device_merged'"))

        with mock.patch.object(self.app, "emit"):
            revoked = self.app.cmd_ap(
                ["unmerge", merge["merge_id"], "--reason", "association corrected"],
                netops.GlobalOptions(confirm=True),
            )
        self.assertEqual(revoked, netops.SUCCESS)
        self.assertIsNotNone(self.app.state.one("SELECT * FROM aps WHERE ip='192.0.2.50'"))
        self.assertEqual(self.app.state.one("SELECT COUNT(*) AS count FROM inventory_merges WHERE entity_type='ap' AND revoked_at IS NULL")["count"], 0)
        self.assertIsNotNone(self.app.state.one("SELECT * FROM audit_events WHERE event_type='ap_device_merge_revoked'"))

    def test_ap_merge_resolves_a_source_already_wiped_from_the_live_table(self):
        # `ap scan` replaces the whole `aps` table from the controller's
        # current sweep, so the identity a continuity candidate names is
        # routinely gone from the live table by the time an operator reviews
        # it -- this is the realistic case, not an edge case.
        now = int(time.time())
        self.add_ap("192.0.2.50", "SITE-A-AP12", "198.51.100.10", "SITE-A-SW01", "Gi1/0/12", "aabbccddeeff", seen=now - 3600)
        self.app.state.sync_derived_state()
        self.app.state.execute("DELETE FROM aps WHERE ip='192.0.2.50'")
        self.add_ap("192.0.2.51", "NEWCISCO-AP-01", "198.51.100.10", "SITE-A-SW01", "Gi1/0/12", "001122334455", seen=now)
        self.app.state.sync_derived_state()
        self.assertIsNone(self.app.state.one("SELECT * FROM aps WHERE ip='192.0.2.50'"))

        with mock.patch.object(self.app, "emit"):
            applied = self.app.cmd_ap(
                ["merge", "SITE-A-AP12", "NEWCISCO-AP-01", "--reason", "vendor replacement"],
                netops.GlobalOptions(confirm=True),
            )
        self.assertEqual(applied, netops.SUCCESS)
        merge = self.app.state.one("SELECT * FROM inventory_merges WHERE entity_type='ap' AND revoked_at IS NULL")
        self.assertEqual(merge["source_ip"], "192.0.2.50")
        self.assertEqual(merge["target_ip"], "192.0.2.51")

    def test_ap_merge_clears_the_matching_continuity_candidate(self):
        now = int(time.time())
        self.add_ap("192.0.2.50", "SITE-A-AP12", "198.51.100.10", "SITE-A-SW01", "Gi1/0/12", "aabbccddeeff", seen=now - 3600)
        self.app.state.sync_derived_state()
        self.app.state.execute("DELETE FROM aps WHERE ip='192.0.2.50'")
        self.add_ap("192.0.2.51", "NEWCISCO-AP-01", "198.51.100.10", "SITE-A-SW01", "Gi1/0/12", "001122334455", seen=now)
        self.app.state.sync_derived_state()
        self.assertEqual(self.app.state.one("SELECT COUNT(*) AS count FROM relationships_current WHERE rel_type='identity_swap_candidate' AND status!='disappeared'")["count"], 1)

        with mock.patch.object(self.app, "emit"):
            self.app.cmd_ap(
                ["merge", "SITE-A-AP12", "NEWCISCO-AP-01", "--reason", "vendor replacement"],
                netops.GlobalOptions(confirm=True),
            )
        self.app.state.sync_derived_state()
        self.assertEqual(self.app.state.one("SELECT COUNT(*) AS count FROM relationships_current WHERE rel_type='identity_swap_candidate' AND status!='disappeared'")["count"], 0)

    def test_ap_merge_names_the_argument_that_failed_to_resolve(self):
        self.add_ap("192.0.2.51", "NEWCISCO-AP-01")
        detail = self.ap_merge_failure_detail("SITE-A-AP12", "NEWCISCO-AP-01")
        self.assertIn("old-ap 'SITE-A-AP12'", detail)
        self.assertIn("no active or historical AP record", detail)

    def test_ap_merge_reports_ambiguous_candidates(self):
        # Distinct, valid unicast MACs keep these two from being reconciled
        # into one canonical AP -- the AP table has no serial column, so MAC
        # is the only thing (besides a real attachment) that can block a
        # same-role-number union the way a device's serial does.
        self.add_ap("192.0.2.50", "SITE-A-AP12")
        self.add_ap("192.0.2.51", "NEWCISCO-AP-01", mac="001122334401")
        self.add_ap("192.0.2.52", "NEWCISCO-AP-01-SPARE", mac="001122334402")
        detail = self.ap_merge_failure_detail("SITE-A-AP12", "NEWCISCOAP01")
        self.assertIn("matched 2 APs", detail)
        self.assertIn("NEWCISCO-AP-01-SPARE", detail)

    def test_ap_merge_refuses_both_arguments_naming_one_ap(self):
        self.add_ap("192.0.2.51", "NEWCISCO-AP-01")
        detail = self.ap_merge_failure_detail("192.0.2.51", "NEWCISCO-AP-01")
        self.assertIn("already one AP", detail)

    def test_action_hub_ap_manual_merge_is_preview_only(self):
        preview = self.app.preview_for_action(
            "ap-merge",
            {"source": "SITE-A-AP12", "target": "NEWCISCO-AP-01", "reason": "vendor replacement"},
        )
        self.assertTrue(preview["ok"])
        self.assertTrue(preview["blocked"])
        self.assertFalse(preview["run_supported"])
        self.assertIn("--dry-run", preview["command"])
        self.assertNotIn("--confirm", preview["command"])

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

    def test_current_hostname_outranks_another_devices_historical_name(self):
        # Hardware swap: switch S1 ran as SITEAZONE05SW01 at .1, was replaced
        # there by S2, and now runs elsewhere as a temp switch. S1 keeps the
        # old name in its history (matched by serial), but typing the name
        # means S2 -- the switch that holds it now -- not "ambiguous".
        insert = "INSERT INTO devices(ip,hostname,platform,model,serial,mac,source,last_seen,status) VALUES(?,?,?,?,?,?,?,?,?)"
        self.app.state.execute(insert, ("192.0.2.1", "SITEAZONE05SW01", "Cisco IOS", "C9300", "FVH0000BBBB", "", "SNMP", 200, "ONLINE"))
        self.app.state.execute(insert, ("192.0.2.2", "SITEATMPSW02", "Cisco IOS", "C9300", "FJC0000AAAA", "", "SNMP", 200, "ONLINE"))
        self.app.state.execute(
            "INSERT INTO inventory_identity_state(identity_kind,identity_value,entity_type,ip,mac,name,platform,model,serial,source,status,first_seen,last_seen,updated_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("name", "siteazone05sw01-old", "device", "192.0.2.1", "", "SITEAZONE05SW01", "Cisco IOS", "C9300", "FJC0000AAAA", "SNMP", "ONLINE", 100, 100, 100),
        )
        old_hardware, _ = self.app.resolve_device_record("SITEATMPSW02")
        self.assertIn("SITEAZONE05SW01", old_hardware["aliases"])

        resolved, choices = self.app.resolve_device_record("SITEAZONE05SW01")
        self.assertIsNotNone(resolved, [row.get("ip") for row in choices])
        self.assertEqual(resolved["ip"], "192.0.2.1")
        self.assertEqual(len(choices), 1)
        resolved, _ = self.app.resolve_device_record("SITEATMPSW02")
        self.assertEqual(resolved["ip"], "192.0.2.2")

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
        self.assertIn("netrune lookup mac all 0200.0000.0025", payload["answer"])

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
                self.assertIn("netrune", plan["command"])

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
            "value": "192.0.2.1", "down": "100M", "channel": "fixture", "endpoint": "0200.0000.0025", "bind": "192.0.2.25",
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
                self.assertIn("netrune", preview["command"])
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

    def test_a_fragment_of_an_alias_phrase_never_names_a_device(self):
        """An operator typing a short word must not be handed a specific switch.

        'camp admin office' naming one switch must not make the bare word
        'admin' name it too. Every device command resolves through here,
        including the ones that open a session or write configuration, so a
        guess at this layer lands on hardware nobody chose.
        """
        self.app.natural_ask.set_alias("camp admin office", "SITE-C-OFFICE-SW01")
        for fragment in ("admin", "camp", "office", "camp admin"):
            with self.subTest(fragment=fragment):
                self.assertEqual(
                    self.app.natural_ask.apply_aliases(fragment, strict=True), fragment)

    def test_a_whole_alias_phrase_still_names_its_device(self):
        self.app.natural_ask.set_alias("camp admin office", "SITE-C-OFFICE-SW01")
        self.assertEqual(
            self.app.natural_ask.apply_aliases("camp admin office", strict=True),
            "SITE-C-OFFICE-SW01")
        # Spacing and case are not what makes a phrase a different phrase.
        self.assertEqual(
            self.app.natural_ask.apply_aliases("Camp  Admin  Office", strict=True),
            "SITE-C-OFFICE-SW01")

    def test_a_question_may_still_be_phrased_loosely(self):
        # Natural Ask reads sentences, where a phrase inside a longer question
        # is exactly what an alias is for.
        self.app.natural_ask.set_alias("camp admin office", "SITE-C-OFFICE-SW01")
        self.assertIn("SITE-C-OFFICE-SW01",
                      self.app.natural_ask.apply_aliases("how many APs in camp admin office"))

    def test_an_ambiguous_device_target_picks_nothing(self):
        for index, name in enumerate(("SITE-A-ADMIN-SW01", "SITE-A-ADMIN-SW02", "SITE-B-ADMIN-SW01")):
            self.add_device(f"198.51.100.{index + 20}", name)
        device, choices = self.app.resolve_device_record("admin")
        self.assertIsNone(device)
        self.assertEqual(len(choices), 3)

    def test_an_abbreviated_address_is_an_address_not_a_name_fragment(self):
        """The shell resolver has always expanded these; Python had not.

        Two resolvers disagreeing about what an operator typed is how a command
        lands on hardware nobody chose: `7.71` meant 198.51.7.71 in one and a
        digit fragment that could match anything in the other.
        """
        from netops_platform.core import expand_abbreviated_target
        self.assertEqual(expand_abbreviated_target("7.71", "198.51"), "198.51.7.71")
        self.assertEqual(expand_abbreviated_target("0.7", "198.51"), "198.51.0.7")
        self.assertEqual(expand_abbreviated_target("71", "198.51.100"), "198.51.100.71")
        # Not an abbreviation: too many parts, out of range, or not numeric.
        self.assertEqual(expand_abbreviated_target("1.2.3.4", "198.51"), "")
        self.assertEqual(expand_abbreviated_target("7.999", "198.51"), "")
        self.assertEqual(expand_abbreviated_target("SW01", "198.51"), "")
        self.assertEqual(expand_abbreviated_target("7.71", ""), "")

    def test_a_digit_fragment_no_longer_matches_addresses_it_is_inside_of(self):
        self.app.config.public["target_abbreviation_prefix"] = "198.51"
        for index, name in enumerate(("SITE-A-SW01", "SITE-A-SW02", "SITE-B-SW01")):
            self.add_device(f"198.51.100.{index + 70}", name)
        # "0.7" is inside 198.51.100.70/71/72 but names none of them; with the
        # prefix it means 198.51.0.7, which nothing answers on.
        device, choices = self.app.resolve_device_record("0.7")
        self.assertIsNone(device)
        self.assertEqual(choices, [])
        # The whole abbreviation still resolves.
        device, _ = self.app.resolve_device_record("100.71")
        self.assertEqual((device or {}).get("ip"), "198.51.100.71")

    def test_forgetting_a_device_clears_it_from_every_derived_table(self):
        self.add_device("198.51.100.60", "SITE-A-SW09")
        self.app.state.record_capability_evidence("198.51.100.60", "stp", "supported", {"ok": True})
        removed = self.app.state.forget_device(["198.51.100.60"])
        self.assertEqual(removed.get("devices"), 1)
        self.assertEqual(removed.get("capability_evidence"), 1)
        self.assertEqual(self.app.state.rows("SELECT * FROM devices WHERE ip='198.51.100.60'"), [])

    def test_forgetting_leaves_the_audit_trail_alone(self):
        # Correcting an inventory record must not be a way to erase what was
        # observed or who did what.
        self.add_device("198.51.100.61", "SITE-A-SW10")
        self.app.state.record_audit_event("inventory", "test-event", result="success",
                                          target="198.51.100.61")
        before = len(self.app.state.rows("SELECT * FROM audit_events"))
        self.app.state.forget_device(["198.51.100.61"])
        self.assertEqual(len(self.app.state.rows("SELECT * FROM audit_events")), before)
        self.assertNotIn("audit_events", dict(self.app.state.DEVICE_STATE_TABLES))

    def test_naming_history_survives_unless_it_is_the_thing_being_corrected(self):
        self.add_device("198.51.100.62", "SITE-A-SW11")
        self.app.state.execute(
            "INSERT INTO inventory_identity_state(entity_type,identity_kind,identity_value,ip,name,"
            "first_seen,last_seen,updated_at)"
            " VALUES('device','name','OLD-NAME','198.51.100.62','OLD-NAME',1,1,1)")
        self.app.state.forget_device(["198.51.100.62"])
        kept = self.app.state.rows("SELECT * FROM inventory_identity_state WHERE ip='198.51.100.62'")
        self.assertEqual(len(kept), 1, "a moved device keeps its history by default")
        self.app.state.forget_device(["198.51.100.62"], forget_identity=True)
        self.assertEqual(
            self.app.state.rows("SELECT * FROM inventory_identity_state WHERE ip='198.51.100.62'"), [])

    def test_forgetting_requires_confirmation_and_shows_what_it_would_remove(self):
        self.add_device("198.51.100.63", "SITE-A-SW12")
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer), contextlib.redirect_stderr(io.StringIO()):
            code = self.app.dispatch(["inventory", "forget", "SITE-A-SW12", "--plain", "--no-color"])
        self.assertEqual(code, netops.VALIDATION)
        self.assertIn("Would forget", buffer.getvalue())
        self.assertEqual(len(self.app.state.rows("SELECT * FROM devices WHERE ip='198.51.100.63'")), 1)

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
                expected_validation = {"ingest-run", "plugin-enable", "plugin-disable", "path-show",
                                       # Nothing is on the watchlist in this fixture, so naming a target is a
                                       # validation failure rather than a broken handler.
                                       "traffic-pause", "traffic-resume", "traffic-interval", "traffic-unwatch",
                                       "traffic-name", "traffic-subscribe",
                                       # No poller is registered in this fixture, so naming one is a
                                       # validation failure rather than a broken handler.
                                       "traffic-pull"}
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
        self.assertEqual(version_output.getvalue().strip(), f"Netrune {netops.VERSION}")
        self.assertIn("Usage:", help_output.getvalue())


if __name__ == "__main__":
    unittest.main()


class InstallationRootTest(unittest.TestCase):
    """Where the shell helpers are, which is not simply where Python is.

    The collector shells out to netops-control for every SNMP read. A wheel
    installed into a virtualenv -- which is how a poller is installed -- puts
    those helpers in the venv's bin, but `sys.executable` there is a symlink,
    and resolving it lands on the system Python. Looking for the helpers beside
    that finds nothing, and the collector then reports every switch as
    unreachable with no error naming the cause.
    """

    def test_a_source_tree_is_recognised_by_its_helpers(self):
        self.assertEqual(netops.installation_root(), ROOT)
        self.assertTrue((ROOT / "netops-lib.sh").is_file())

    def test_a_venv_is_found_through_its_unresolved_executable(self):
        with tempfile.TemporaryDirectory() as temp:
            venv = Path(temp) / "venv"
            (venv / "bin").mkdir(parents=True)
            (venv / "bin" / "netops-lib.sh").write_text("#!/usr/bin/env bash\n")
            # A venv's python is a symlink to the system one, so the resolved
            # directory is /usr/bin and has no helpers in it. Standing in for
            # that here with a directory that simply does not exist.
            system_bin = Path(temp) / "system" / "bin"
            system_bin.mkdir(parents=True)
            (system_bin / "python3").write_text("")
            link = venv / "bin" / "python3"
            link.symlink_to(system_bin / "python3")
            found = netops._first_root_holding_helpers(
                Path(temp) / "not-a-source-tree", link, venv)
            self.assertEqual(found, venv / "bin")

    def test_a_source_tree_wins_over_an_installed_copy(self):
        """Working on the tree must not silently run an older installed helper."""
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "src"
            source.mkdir()
            (source / "netops-lib.sh").write_text("")
            venv = Path(temp) / "venv"
            (venv / "bin").mkdir(parents=True)
            (venv / "bin" / "netops-lib.sh").write_text("")
            (venv / "bin" / "python3").write_text("")
            self.assertEqual(
                netops._first_root_holding_helpers(source, venv / "bin" / "python3", venv),
                source)

    def test_nothing_found_still_returns_somewhere_rather_than_raising(self):
        with tempfile.TemporaryDirectory() as temp:
            python = Path(temp) / "python3"
            python.write_text("")
            self.assertEqual(
                netops._first_root_holding_helpers(Path(temp) / "no", python, Path(temp) / "no"),
                Path(temp))

    def test_the_markers_are_files_that_only_sit_beside_the_helpers(self):
        for marker in netops._ROOT_MARKERS:
            with self.subTest(marker=marker):
                self.assertTrue((ROOT / marker).is_file(), marker)


class DeviceInventoryReachesSqliteTest(unittest.TestCase):
    """Enriching a device has to leave it somewhere the CLI can find it.

    There are two stores. The legacy helper writes a flat device cache, and
    everything the CLI reads -- inventory list, resolving a name, the identity
    work -- reads SQLite, which is rebuilt from that cache. `device inventory`
    ran the helper and stopped there, so a device came back "Inventory
    synchronized" and then "No records": `connect` found it, because the shell
    path reads the flat file, and every Python path did not.
    """

    def test_the_helper_run_is_followed_by_an_import(self):
        source = (ROOT / "netops_platform" / "device_cli.py").read_text()
        branch = source[source.index('if verb=="inventory":'):]
        branch = branch[:branch.index("\n        return self.unknown_action")]
        self.assertIn('legacy_cmd("netrune-control","inventory"', branch)
        self.assertIn("import_flat_state", branch)

    def test_it_imports_only_on_success_and_not_on_a_dry_run(self):
        source = (ROOT / "netops_platform" / "device_cli.py").read_text()
        branch = source[source.index('if verb=="inventory":'):]
        branch = branch[:branch.index("\n        return self.unknown_action")]
        self.assertIn("rc == SUCCESS", branch)
        self.assertIn("opts.dry_run", branch)

    def test_it_matches_what_a_scan_already_did(self):
        """The scan path had this from the start; this one was never given it."""
        scan_source = (ROOT / "netops_platform" / "inventory_cli.py").read_text()
        scan = scan_source[scan_source.index('if verb=="scan":'):]
        scan = scan[:scan.index("\n        if verb")]
        self.assertIn('import_flat_state(("device",)', scan)
        inventory_source = (ROOT / "netops_platform" / "device_cli.py").read_text()
        branch = inventory_source[inventory_source.index('if verb=="inventory":'):]
        branch = branch[:branch.index("\n        return self.unknown_action")]
        self.assertIn('import_flat_state(("device",)', branch)
