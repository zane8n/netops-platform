import base64
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

import netops_core as netops

ROOT = Path(__file__).resolve().parents[1]

class NetOpsV8Test(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.env = mock.patch.dict(
            os.environ,
            {
                "NETOPS_CONFIG_DIR": str(self.base / "config"),
                "NETOPS_CACHE_DIR": str(self.base / "cache"),
                "NETOPS_SQLITE_DB": str(self.base / "cache" / "netops.sqlite3"),
                "NETOPS_BACKUP_DIR": str(self.base / "backups"),
                "NETOPS_SSH_KNOWN_HOSTS_FILE": str(self.base / "config" / "known_hosts"),
                "NETOPS_PROGRESS": "0",
                "NETOPS_DEVICE_WRITES_ENABLED": "true",
            },
            clear=False,
        )
        self.env.start()
        self.app = netops.App(ROOT)

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def add_device(self, ip="192.0.2.1", hostname="SW1", platform="Cisco IOS XE 17.9", serial="SERIAL", model="C9300"):
        self.app.state.execute(
            "INSERT INTO devices(ip,hostname,platform,model,serial,mac,source,last_seen,status) VALUES(?,?,?,?,?,?,?,?,?)",
            (ip, hostname, platform, model, serial, "", "test", 1_700_000_000, "ONLINE"),
        )

    def test_version_falls_back_to_installed_distribution_metadata(self):
        with mock.patch.object(Path, "read_text", side_effect=OSError), mock.patch.object(netops, "distribution_version", return_value="8.5.0b1"):
            self.assertEqual(netops.resolved_version(), "8.5.0b1")

    def test_ssh_trust_enrollment_requires_matching_fingerprint_and_is_audited(self):
        self.add_device()
        key_data = base64.b64encode(b"netops-fixture-host-key").decode("ascii")
        fingerprint = self.app._host_key_fingerprint(key_data)
        scanned = [{"host":"192.0.2.1", "key_type":"ssh-ed25519", "fingerprint":fingerprint, "key_line":f"192.0.2.1 ssh-ed25519 {key_data}"}]
        with mock.patch.object(self.app, "_scan_host_keys", return_value=(scanned, "")), mock.patch("sys.stdout", new_callable=io.StringIO) as output:
            rc = self.app.cmd_device_trust(["enroll", "SW1", "--fingerprint", fingerprint], netops.GlobalOptions(confirm=True, json=True))
        self.assertEqual(rc, netops.SUCCESS)
        self.assertTrue(json.loads(output.getvalue())["ok"])
        known_hosts = self.app.paths.ssh_known_hosts_file
        self.assertIn("ssh-ed25519", known_hosts.read_text(encoding="utf-8"))
        self.assertEqual(stat.S_IMODE(known_hosts.stat().st_mode), 0o600)
        rows = self.app._known_host_rows(["192.0.2.1"])
        self.assertEqual(rows[0]["fingerprint"], fingerprint)
        audit = self.app.state.one("SELECT event_type,target,result FROM audit_events ORDER BY id DESC LIMIT 1")
        self.assertEqual(audit, {"event_type":"ssh_trust_enrolled", "target":"192.0.2.1", "result":"success"})

    def test_ssh_trust_mismatch_does_not_modify_store(self):
        self.add_device()
        key_data = base64.b64encode(b"different-key").decode("ascii")
        observed = self.app._host_key_fingerprint(key_data)
        scanned = [{"host":"192.0.2.1", "key_type":"ssh-ed25519", "fingerprint":observed, "key_line":f"192.0.2.1 ssh-ed25519 {key_data}"}]
        with mock.patch.object(self.app, "_scan_host_keys", return_value=(scanned, "")), mock.patch("sys.stdout", new_callable=io.StringIO):
            rc = self.app.cmd_device_trust(["enroll", "SW1", "--fingerprint", "SHA256:not-the-key"], netops.GlobalOptions(confirm=True, json=True))
        self.assertEqual(rc, netops.AUTH)
        self.assertFalse(self.app.paths.ssh_known_hosts_file.exists())

    def test_vlan_preview_is_bound_to_exact_intent_and_stays_confirm_gated(self):
        args = {"target":"SW1", "interface":"Gi1/0/7", "vlan_mode":"access", "vlan":"131"}
        preview = self.app.preview_for_action("vlan-set", args)
        self.assertEqual(preview["validation_error"], "")
        self.assertIn("--access 131 --confirm", preview["command"])
        self.assertEqual(preview["safety_class"], "config-write")
        self.assertTrue(preview["requires_confirmation"])
        self.assertFalse(preview["read_only"])

    def test_vlan_change_runs_preflight_backup_apply_and_verification(self):
        self.add_device()
        request = self.app.vlan_change_request({"target":"SW1", "interface":"Gi1/0/7", "vlan_mode":"access", "vlan":"131"})
        responses = [
            (0, "Interface Gi1/0/7 switchport enabled", ""),
            (0, "Backup saved", ""),
            (0, "Config applied", ""),
            (0, "[192.0.2.1] SW1 -> DEFINED\nAccess Ports: Gi1/0/7\nTrunk Ports: none\n", ""),
        ]
        with mock.patch.object(self.app, "capture", side_effect=responses) as capture, mock.patch("sys.stdout", new_callable=io.StringIO) as output:
            rc = self.app.apply_vlan_change(request, netops.GlobalOptions(confirm=True, json=True))
        payload = json.loads(output.getvalue())
        self.assertEqual(rc, netops.SUCCESS)
        self.assertTrue(payload["verified"])
        self.assertEqual([row["phase"] for row in payload["phases"]], ["preflight", "backup", "apply", "verify"])
        self.assertEqual(capture.call_count, 4)
        apply_env = capture.call_args_list[2].args[2]
        self.assertTrue(apply_env.confirm)
        audit = self.app.state.one("SELECT action,result FROM audit_events ORDER BY id DESC LIMIT 1")
        self.assertEqual(audit, {"action":"vlan-set", "result":"success"})

    def test_vlan_change_stops_when_backup_fails(self):
        self.add_device()
        request = self.app.vlan_change_request({"target":"SW1", "interface":"Gi1/0/7", "vlan_mode":"access", "vlan":"131"})
        with mock.patch.object(self.app, "capture", side_effect=[(0, "pre-state", ""), (1, "", "backup failed")]) as capture, mock.patch("sys.stdout", new_callable=io.StringIO) as output:
            rc = self.app.apply_vlan_change(request, netops.GlobalOptions(confirm=True, json=True))
        self.assertEqual(rc, netops.PARTIAL)
        self.assertEqual(capture.call_count, 2)
        self.assertEqual(json.loads(output.getvalue())["status"], "BLOCKED")

    def test_parse_vlan_set_tokens_accepts_access_and_trunk_forms(self):
        self.assertEqual(
            self.app._parse_vlan_set_tokens(["SW1", "Gi1/0/7", "--access", "120"]),
            {"target": "SW1", "interface": "Gi1/0/7", "vlan_mode": "access", "vlan": "120"},
        )
        self.assertEqual(
            self.app._parse_vlan_set_tokens(["SW1", "Gi1/0/48", "--trunk", "10-20", "--native", "1", "--replace"]),
            {"target": "SW1", "interface": "Gi1/0/48", "vlan_mode": "trunk", "vlan": "10-20", "native_vlan": "1", "replace": True},
        )

    def test_parse_vlan_set_tokens_rejects_missing_and_unknown_options(self):
        with self.assertRaises(ValueError):
            self.app._parse_vlan_set_tokens(["SW1"])
        with self.assertRaises(ValueError):
            self.app._parse_vlan_set_tokens(["SW1", "Gi1/0/7", "--bogus"])

    def test_vlan_batch_file_runs_each_line_independently(self):
        self.add_device(ip="192.0.2.1", hostname="SW1")
        self.add_device(ip="192.0.2.2", hostname="SW2")
        file_path = self.base / "vlan_changes.txt"
        file_path.write_text("SW1 Gi1/0/7 --access 120\nSW2 Gi1/0/8 --access 130\n", encoding="utf-8")
        responses = [
            (0, "Interface Gi1/0/7 switchport enabled", ""),
            (0, "Backup saved", ""),
            (0, "Config applied", ""),
            (0, "[192.0.2.1] SW1 -> DEFINED\nAccess Ports: Gi1/0/7\nTrunk Ports: none\n", ""),
            (0, "Interface Gi1/0/8 switchport enabled", ""),
            (0, "Backup saved", ""),
            (0, "Config applied", ""),
            (0, "[192.0.2.2] SW2 -> DEFINED\nAccess Ports: Gi1/0/8\nTrunk Ports: none\n", ""),
        ]
        with mock.patch.object(self.app, "capture", side_effect=responses) as capture, mock.patch("sys.stdout", new_callable=io.StringIO) as output:
            rc = self.app.cmd_vlan(["set", "--file", str(file_path)], netops.GlobalOptions(confirm=True, json=True))
        payload = json.loads(output.getvalue())
        self.assertEqual(rc, netops.SUCCESS)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["counts"], {"total": 2, "success": 2, "attention": 0, "blocked": 0, "failed": 0, "skipped": 0})
        self.assertEqual(capture.call_count, 8)
        audits = self.app.state.rows("SELECT action,result FROM audit_events WHERE action='vlan-set' ORDER BY id")
        self.assertEqual(len(audits), 2)

    def test_vlan_batch_aborts_before_touching_any_device_when_a_line_does_not_resolve(self):
        self.add_device(ip="192.0.2.1", hostname="SW1")
        file_path = self.base / "vlan_changes.txt"
        file_path.write_text("SW1 Gi1/0/7 --access 120\nGHOST Gi1/0/8 --access 130\n", encoding="utf-8")
        with mock.patch.object(self.app, "capture") as capture, mock.patch("sys.stdout", new_callable=io.StringIO):
            rc = self.app.cmd_vlan(["set", "--file", str(file_path)], netops.GlobalOptions(confirm=True, json=True))
        self.assertEqual(rc, netops.VALIDATION)
        capture.assert_not_called()

    def test_vlan_batch_skip_unverified_continues_past_a_bad_line(self):
        self.add_device(ip="192.0.2.1", hostname="SW1")
        file_path = self.base / "vlan_changes.txt"
        file_path.write_text("SW1 Gi1/0/7 --access 120\nGHOST Gi1/0/8 --access 130\n", encoding="utf-8")
        responses = [
            (0, "Interface Gi1/0/7 switchport enabled", ""),
            (0, "Backup saved", ""),
            (0, "Config applied", ""),
            (0, "[192.0.2.1] SW1 -> DEFINED\nAccess Ports: Gi1/0/7\nTrunk Ports: none\n", ""),
        ]
        with mock.patch.object(self.app, "capture", side_effect=responses) as capture, mock.patch("sys.stdout", new_callable=io.StringIO) as output:
            rc = self.app.cmd_vlan(["set", "--file", str(file_path), "--skip-unverified"], netops.GlobalOptions(confirm=True, json=True))
        payload = json.loads(output.getvalue())
        # A batch with anything skipped is reported PARTIAL even when every
        # line that did run succeeded -- something in the file still wasn't
        # done, same semantics as apply_device_config_batch.
        self.assertEqual(rc, netops.PARTIAL)
        self.assertEqual(payload["counts"]["skipped"], 1)
        self.assertEqual(payload["counts"]["success"], 1)
        self.assertEqual(capture.call_count, 4)

    def test_device_config_comma_targets_run_as_a_batch_and_dedupe_by_device(self):
        self.add_device(ip="192.0.2.1", hostname="SW1", serial="SER-SW1")
        self.add_device(ip="192.0.2.2", hostname="SW2", serial="SER-SW2")
        with mock.patch.object(self.app, "capture") as capture, mock.patch("sys.stdout", new_callable=io.StringIO) as output:
            rc = self.app.cmd_device(["config", "SW1,SW2,192.0.2.1", "description AP"], netops.GlobalOptions(dry_run=True, json=True))
        payload = json.loads(output.getvalue())
        self.assertEqual(rc, netops.SUCCESS)
        self.assertEqual([row["ip"] for row in payload["devices"]], ["192.0.2.1", "192.0.2.2"])
        self.assertEqual(payload["commands"], ["description AP"])
        capture.assert_not_called()

    def test_device_config_file_and_repeated_target_combine(self):
        self.add_device(ip="192.0.2.1", hostname="SW1", serial="SER-SW1")
        self.add_device(ip="192.0.2.2", hostname="SW2", serial="SER-SW2")
        self.add_device(ip="192.0.2.3", hostname="SW3", serial="SER-SW3")
        file_path = self.base / "devices.txt"
        file_path.write_text("SW1\n# lab spare\n\nSW2\n", encoding="utf-8")
        with mock.patch("sys.stdout", new_callable=io.StringIO) as output:
            rc = self.app.cmd_device(["config", "--file", str(file_path), "--target", "SW3", "description AP"], netops.GlobalOptions(dry_run=True, json=True))
        payload = json.loads(output.getvalue())
        self.assertEqual(rc, netops.SUCCESS)
        self.assertEqual([row["target"] for row in payload["devices"]], ["SW1", "SW2", "SW3"])
        self.assertEqual(payload["commands"], ["description AP"])

    def test_device_config_skip_offline_previews_which_devices_would_be_skipped(self):
        self.add_device(ip="192.0.2.1", hostname="SW1", serial="SER-SW1")
        self.add_device(ip="192.0.2.2", hostname="SW2", serial="SER-SW2")
        with mock.patch.object(self.app, "ping", side_effect=lambda ip, timeout: ip == "192.0.2.1"), mock.patch.object(self.app, "capture") as capture, mock.patch("sys.stdout", new_callable=io.StringIO) as output:
            rc = self.app.cmd_device(["config", "SW1,SW2", "description AP", "--skip-offline"], netops.GlobalOptions(dry_run=True, json=True))
        payload = json.loads(output.getvalue())
        self.assertEqual(rc, netops.SUCCESS)
        self.assertEqual([row["target"] for row in payload["devices"]], ["SW1"])
        self.assertEqual(payload["skipped"], [{"target": "SW2", "name": "SW2", "reason": "offline: no ping reply from 192.0.2.2"}])
        capture.assert_not_called()

    def test_device_config_skip_offline_never_connects_to_an_offline_device(self):
        self.add_device(ip="192.0.2.1", hostname="SW1", serial="SER-SW1")
        self.add_device(ip="192.0.2.2", hostname="SW2", serial="SER-SW2")
        file_path = self.base / "devices.txt"
        file_path.write_text("SW1\nSW2\n", encoding="utf-8")
        responses = [
            (0, "Backup saved to .../SW1.conf", ""),
            (0, "Config applied.", ""),
            (0, "Backup saved to .../SW1.conf", ""),
        ]
        with mock.patch.object(self.app, "ping", side_effect=lambda ip, timeout: ip == "192.0.2.1"), mock.patch.object(self.app, "capture", side_effect=responses) as capture, mock.patch("sys.stdout", new_callable=io.StringIO) as output, mock.patch("time.sleep"):
            rc = self.app.cmd_device(["config", "--file", str(file_path), "description AP", "--skip-offline"], netops.GlobalOptions(confirm=True, json=True))
        payload = json.loads(output.getvalue())
        # Something in the list wasn't configured, so the batch is PARTIAL
        # even though every device that ran succeeded.
        self.assertEqual(rc, netops.PARTIAL)
        self.assertEqual(payload["counts"]["success"], 1)
        self.assertEqual(payload["counts"]["skipped"], 1)
        self.assertEqual(capture.call_count, 3)
        self.assertTrue(all("192.0.2.2" not in call.args[0] for call in capture.call_args_list))

    def test_device_config_reports_unreachable_when_every_device_is_offline(self):
        self.add_device(ip="192.0.2.1", hostname="SW1", serial="SER-SW1")
        with mock.patch.object(self.app, "ping", return_value=False), mock.patch.object(self.app, "capture") as capture, mock.patch("sys.stdout", new_callable=io.StringIO):
            rc = self.app.cmd_device(["config", "SW1", "description AP", "--skip-offline"], netops.GlobalOptions(confirm=True, json=True))
        self.assertEqual(rc, netops.UNREACHABLE)
        capture.assert_not_called()

    def test_device_config_commands_file_feeds_a_device_list_batch(self):
        self.add_device(ip="192.0.2.1", hostname="SW1", serial="SER-SW1")
        self.add_device(ip="192.0.2.2", hostname="SW2", serial="SER-SW2")
        devices = self.base / "devices.txt"
        devices.write_text("SW1\nSW2\n", encoding="utf-8")
        commands = self.base / "commands.txt"
        commands.write_text("# baseline\ninterface Gi1/0/7\n  description AP-07\n\nntp server 198.51.100.5\n", encoding="utf-8")
        with mock.patch("sys.stdout", new_callable=io.StringIO) as output:
            rc = self.app.cmd_device(["config", "--file", str(devices), "--commands-file", str(commands)], netops.GlobalOptions(dry_run=True, json=True))
        payload = json.loads(output.getvalue())
        self.assertEqual(rc, netops.SUCCESS)
        self.assertEqual(payload["commands"], ["interface Gi1/0/7", "description AP-07", "ntp server 198.51.100.5"])
        self.assertEqual([row["target"] for row in payload["devices"]], ["SW1", "SW2"])

    def test_device_config_commands_file_reaches_the_apply_phase_and_refuses_inline_mixing(self):
        self.add_device(ip="192.0.2.1", hostname="SW1", serial="SER-SW1")
        commands = self.base / "commands.txt"
        commands.write_text("interface Gi1/0/7\nshutdown\n", encoding="utf-8")
        responses = [
            (0, "Backup saved to .../SW1.conf", ""),
            (0, "Config applied.", ""),
            (0, "Backup saved to .../SW1.conf", ""),
        ]
        with mock.patch.object(self.app, "capture", side_effect=responses) as capture, mock.patch("sys.stdout", new_callable=io.StringIO), mock.patch("time.sleep"):
            rc = self.app.cmd_device(["config", "SW1", "--commands-file", str(commands)], netops.GlobalOptions(confirm=True, json=True))
        self.assertEqual(rc, netops.SUCCESS)
        apply_call = capture.call_args_list[1].args[0]
        self.assertEqual(apply_call[-2:], ["interface Gi1/0/7", "shutdown"])

        with mock.patch.object(self.app, "capture") as capture, mock.patch("sys.stdout", new_callable=io.StringIO), mock.patch("sys.stderr", new_callable=io.StringIO):
            rc = self.app.cmd_device(["config", "SW1", "no shutdown", "--commands-file", str(commands)], netops.GlobalOptions(confirm=True, json=True))
        self.assertEqual(rc, netops.VALIDATION)
        capture.assert_not_called()

    def test_device_config_unresolved_target_under_sudo_explains_the_root_profile(self):
        with mock.patch.dict(os.environ, {"SUDO_USER": "operator"}), mock.patch("os.geteuid", return_value=0, create=True):
            gate = self.app._device_config_gate("GHOST-SW01", netops.GlobalOptions(confirm=True))
        self.assertFalse(gate["resolved"])
        self.assertIn("running under sudo uses root's netrune profile, not operator's", gate["reason"])

    def add_mixed_vendor_devices(self):
        self.add_device(ip="192.0.2.1", hostname="SW1", serial="SER-SW1")
        self.add_device(ip="192.0.2.2", hostname="ARUBA1", platform="HPE Aruba JL261A 2930F-24G-PoE+", model="JL261A", serial="SER-ARUBA1")
        self.add_device(ip="192.0.2.3", hostname="ICX1", platform="RUCKUS ICX7150 FastIron 08.0.95", model="ICX7150-48P", serial="SER-ICX1")

    def test_device_config_vendor_filter_previews_only_matching_devices(self):
        self.add_mixed_vendor_devices()
        with mock.patch("sys.stdout", new_callable=io.StringIO) as output:
            rc = self.app.cmd_device(["config", "SW1,ARUBA1,ICX1", "description AP", "--cisco"], netops.GlobalOptions(dry_run=True, json=True))
        payload = json.loads(output.getvalue())
        # The RUCKUS switch isn't approved for writes, but the filter removes
        # it before the approval gate, so it doesn't refuse the batch.
        self.assertEqual(rc, netops.SUCCESS)
        self.assertEqual([row["target"] for row in payload["devices"]], ["SW1"])
        self.assertEqual([row["target"] for row in payload["filtered"]], ["ARUBA1", "ICX1"])
        self.assertIn("Aruba is not cisco", payload["filtered"][0]["reason"])

    def test_device_config_vendor_flags_combine(self):
        self.add_mixed_vendor_devices()
        with mock.patch("sys.stdout", new_callable=io.StringIO) as output:
            rc = self.app.cmd_device(["config", "SW1,ARUBA1,ICX1", "description AP", "--cisco", "--aruba"], netops.GlobalOptions(dry_run=True, json=True))
        payload = json.loads(output.getvalue())
        self.assertEqual(rc, netops.SUCCESS)
        self.assertEqual([row["target"] for row in payload["devices"]], ["SW1", "ARUBA1"])
        self.assertEqual([row["target"] for row in payload["filtered"]], ["ICX1"])

    def test_device_config_without_a_target_requires_all(self):
        self.add_mixed_vendor_devices()
        with mock.patch("sys.stdout", new_callable=io.StringIO), mock.patch("sys.stderr", new_callable=io.StringIO) as err:
            rc = self.app.cmd_device(["config", "ntp server 198.51.100.5"], netops.GlobalOptions(dry_run=True))
        self.assertEqual(rc, netops.USAGE)
        self.assertIn("add --all", err.getvalue())
        # A first argument that names no device is a command, not a typo'd
        # target worth resolving further.
        with mock.patch("sys.stdout", new_callable=io.StringIO), mock.patch("sys.stderr", new_callable=io.StringIO) as err:
            rc = self.app.cmd_device(["config", "interface Gi1/0/7", "description AP", "--cisco"], netops.GlobalOptions(dry_run=True))
        self.assertEqual(rc, netops.VALIDATION)
        self.assertIn("No inventory device matches 'interface Gi1/0/7'", err.getvalue())
        self.assertIn("add --all", err.getvalue())

    def test_device_config_all_runs_every_device_and_vendor_flags_narrow_it(self):
        self.add_mixed_vendor_devices()
        with mock.patch("sys.stdout", new_callable=io.StringIO) as output:
            rc = self.app.cmd_device(["config", "description AP", "--skip-unverified"], netops.GlobalOptions(dry_run=True, json=True, all=True))
        payload = json.loads(output.getvalue())
        self.assertEqual(rc, netops.SUCCESS)
        self.assertEqual(payload["commands"], ["description AP"])
        listed = [row["ip"] for row in payload["devices"]] + [row["target"] for row in payload["skipped"]]
        self.assertEqual(sorted(listed), ["192.0.2.1", "192.0.2.2", "192.0.2.3"])
        self.assertEqual({row["name"]: row["manufacturer"] for row in payload["devices"]}["SW1"], "Cisco")

        # A C9200L that an earlier scan mislabelled is still Cisco to --cisco.
        self.add_device(ip="192.0.2.4", hostname="SW4", platform="Ruckus FastIron", model="C9200L-24P-4G", serial="SER-SW4")
        with mock.patch("sys.stdout", new_callable=io.StringIO) as output:
            rc = self.app.cmd_device(["config", "description AP", "--cisco"], netops.GlobalOptions(dry_run=True, json=True, all=True))
        payload = json.loads(output.getvalue())
        self.assertEqual(rc, netops.SUCCESS)
        self.assertEqual(sorted(row["name"] for row in payload["devices"]), ["SW1", "SW4"])
        self.assertEqual(sorted(row["name"] for row in payload["filtered"]), ["ARUBA1", "ICX1"])

    def test_device_config_all_does_not_combine_with_a_device_list(self):
        self.add_device()
        devices = self.base / "devices.txt"
        devices.write_text("SW1\n", encoding="utf-8")
        with mock.patch("sys.stdout", new_callable=io.StringIO), mock.patch("sys.stderr", new_callable=io.StringIO) as err:
            rc = self.app.cmd_device(["config", "--file", str(devices), "description AP"], netops.GlobalOptions(dry_run=True, all=True))
        self.assertEqual(rc, netops.VALIDATION)
        self.assertIn("--all already means every inventory device", err.getvalue())

    def test_db_coherence_flags_and_realigns_a_model_contradicted_platform_label(self):
        self.add_device(ip="192.0.2.1", hostname="SW1", serial="SER-SW1")
        self.add_device(ip="192.0.2.4", hostname="SW4", platform="Ruckus FastIron", model="C9200L-24P-4G", serial="SER-SW4")
        self.app.state.export_flat_files()
        with mock.patch("sys.stdout", new_callable=io.StringIO) as output:
            rc = self.app.dispatch(["db", "coherence", "--json"])
        payload = json.loads(output.getvalue())
        self.assertEqual(rc, netops.PARTIAL)
        labels = next(check for check in payload["checks"] if check["check"] == "platform_labels")
        self.assertEqual(labels["status"], "WARN")
        self.assertIn("'Ruckus FastIron' -> 'Cisco IOS'", labels["items"][0])
        # Reporting alone changes nothing.
        self.assertEqual(self.app.state.one("SELECT platform FROM devices WHERE ip='192.0.2.4'")["platform"], "Ruckus FastIron")

        with mock.patch("sys.stdout", new_callable=io.StringIO) as output:
            rc = self.app.dispatch(["db", "coherence", "--realign", "--json"])
        payload = json.loads(output.getvalue())
        self.assertEqual(rc, netops.SUCCESS, payload)
        statuses = {check["check"]: check["status"] for check in payload["checks"]}
        self.assertEqual(statuses["platform_labels"], "FIXED")
        self.assertEqual(statuses["realign"], "PASS")
        self.assertEqual(self.app.state.one("SELECT platform FROM devices WHERE ip='192.0.2.4'")["platform"], "Cisco IOS")
        # The shell helpers read the flat cache, so the fix has to reach it
        # too -- or the next import puts the wrong label back.
        self.assertIn("192.0.2.4|SW4|Cisco IOS|", self.app.paths.devices_file.read_text(encoding="utf-8"))
        changed = self.app.state.rows("SELECT previous_value,current_value FROM inventory_history WHERE field_name='platform'")
        self.assertIn({"previous_value": "Ruckus FastIron", "current_value": "Cisco IOS"}, changed)

    def test_db_coherence_realign_skips_reimporting_unchanged_caches(self):
        self.add_device()
        self.app.state.export_flat_files()
        self.app.state.import_flat_files()
        with mock.patch.object(self.app.state, "import_flat_files", wraps=self.app.state.import_flat_files) as imported, mock.patch("sys.stdout", new_callable=io.StringIO):
            rc = self.app.dispatch(["db", "coherence", "--realign", "--json"])
        self.assertEqual(rc, netops.SUCCESS)
        imported.assert_not_called()
        self.app.paths.devices_file.write_text(self.app.paths.devices_file.read_text(encoding="utf-8") + "192.0.2.9|SW9|Cisco IOS|C9300|S9||test|1700000000|ONLINE\n", encoding="utf-8")
        with mock.patch.object(self.app.state, "import_flat_files", wraps=self.app.state.import_flat_files) as imported, mock.patch("sys.stdout", new_callable=io.StringIO):
            self.app.dispatch(["db", "coherence", "--realign", "--json"])
        imported.assert_called_once()
        self.assertTrue(self.app.state.one("SELECT ip FROM devices WHERE ip='192.0.2.9'"))

    def test_db_coherence_dry_run_does_not_realign(self):
        self.add_device(ip="192.0.2.4", hostname="SW4", platform="Ruckus FastIron", model="C9200L-24P-4G", serial="SER-SW4")
        self.app.state.export_flat_files()
        with mock.patch("sys.stdout", new_callable=io.StringIO):
            rc = self.app.dispatch(["db", "coherence", "--realign", "--dry-run", "--json"])
        self.assertEqual(rc, netops.PARTIAL)
        self.assertEqual(self.app.state.one("SELECT platform FROM devices WHERE ip='192.0.2.4'")["platform"], "Ruckus FastIron")

    def test_morning_check_realigns_in_place_of_a_separate_memory_refresh(self):
        steps = self.app.workflow_steps("morning-check")
        commands = [step[1:] for step in steps]
        self.assertIn(["db", "coherence", "--realign"], commands)
        self.assertNotIn(["memory", "refresh"], commands)
        self.assertLess(commands.index(["topology", "scan"]), commands.index(["db", "coherence", "--realign"]))
        self.assertLess(commands.index(["db", "coherence", "--realign"]), commands.index(["health", "attention"]))

    def test_device_config_vendor_filtered_devices_do_not_make_the_batch_partial(self):
        self.add_mixed_vendor_devices()
        responses = [
            (0, "Backup saved to .../SW1.conf", ""),
            (0, "Config applied.", ""),
            (0, "Backup saved to .../SW1.conf", ""),
        ]
        with mock.patch.object(self.app, "capture", side_effect=responses) as capture, mock.patch("sys.stdout", new_callable=io.StringIO) as output, mock.patch("time.sleep"):
            rc = self.app.cmd_device(["config", "SW1,ARUBA1", "description AP", "--cisco"], netops.GlobalOptions(confirm=True, json=True))
        payload = json.loads(output.getvalue())
        self.assertEqual(rc, netops.SUCCESS)
        self.assertEqual(payload["counts"]["filtered"], 1)
        self.assertEqual(capture.call_count, 3)
        self.assertTrue(all("192.0.2.2" not in call.args[0] for call in capture.call_args_list))

    def test_device_config_vendor_filter_with_no_match_is_a_validation_error(self):
        self.add_mixed_vendor_devices()
        with mock.patch.object(self.app, "capture") as capture, mock.patch("sys.stdout", new_callable=io.StringIO), mock.patch("sys.stderr", new_callable=io.StringIO):
            rc = self.app.cmd_device(["config", "ARUBA1,ICX1", "description AP", "--cisco"], netops.GlobalOptions(confirm=True, json=True))
        self.assertEqual(rc, netops.VALIDATION)
        capture.assert_not_called()

    def test_device_config_vendor_filter_still_applies_the_write_gate(self):
        self.add_mixed_vendor_devices()
        with mock.patch.object(self.app, "capture") as capture, mock.patch("sys.stdout", new_callable=io.StringIO):
            rc = self.app.cmd_device(["config", "SW1,ICX1", "description AP", "--ruckus"], netops.GlobalOptions(confirm=True, json=True))
        self.assertEqual(rc, netops.UNSUPPORTED)
        capture.assert_not_called()

    def test_device_config_refuses_an_unknown_option_instead_of_sending_it(self):
        self.add_device(ip="192.0.2.1", hostname="SW1", serial="SER-SW1")
        with mock.patch.object(self.app, "capture") as capture, mock.patch.object(self.app, "run_subprocess") as run_subprocess, mock.patch("sys.stdout", new_callable=io.StringIO), mock.patch("sys.stderr", new_callable=io.StringIO):
            rc = self.app.cmd_device(["config", "SW1", "description AP", "--skip-ofline"], netops.GlobalOptions(confirm=True, json=True))
        self.assertEqual(rc, netops.USAGE)
        capture.assert_not_called()
        run_subprocess.assert_not_called()

    def test_device_config_runs_backup_apply_and_verify_and_is_audited(self):
        self.add_device()
        device, _ = self.app.resolve_device_record("SW1")
        responses = [
            (0, "Backup saved to .../SW1.conf", ""),
            (0, "Config applied.", ""),
            (0, "Backup saved to .../SW1.conf", ""),
        ]
        with mock.patch.object(self.app, "capture", side_effect=responses) as capture, mock.patch("sys.stdout", new_callable=io.StringIO) as output, mock.patch("time.sleep"):
            rc = self.app.apply_device_config_change(device, "192.0.2.1", ["interface Gi1/0/7", "shutdown"], netops.GlobalOptions(confirm=True, json=True))
        payload = json.loads(output.getvalue())
        self.assertEqual(rc, netops.SUCCESS)
        self.assertTrue(payload["changed"])
        self.assertEqual([row["phase"] for row in payload["phases"]], ["backup", "apply", "verify"])
        self.assertEqual(capture.call_count, 3)
        backup_call, apply_call, verify_call = capture.call_args_list
        self.assertIn("backup", backup_call.args[0])
        self.assertIn("config", apply_call.args[0])
        self.assertIn("interface Gi1/0/7", apply_call.args[0])
        self.assertIn("backup", verify_call.args[0])
        audit = self.app.state.one("SELECT event_type,action,target,result FROM audit_events ORDER BY id DESC LIMIT 1")
        self.assertEqual(audit, {"event_type": "device_config_finished", "action": "device-config", "target": "192.0.2.1", "result": "success"})

    def test_device_config_stops_and_does_not_apply_when_backup_fails(self):
        self.add_device()
        device, _ = self.app.resolve_device_record("SW1")
        with mock.patch.object(self.app, "capture", side_effect=[(1, "", "backup failed")]) as capture, mock.patch("sys.stdout", new_callable=io.StringIO) as output:
            rc = self.app.apply_device_config_change(device, "192.0.2.1", ["reload"], netops.GlobalOptions(confirm=True, json=True))
        self.assertEqual(rc, netops.PARTIAL)
        self.assertEqual(capture.call_count, 1)
        self.assertEqual(json.loads(output.getvalue())["status"], "BLOCKED")
        self.assertIsNone(self.app.state.one("SELECT 1 FROM audit_events WHERE event_type='device_config_finished'"))

    def test_device_config_reports_attention_when_nothing_actually_changed(self):
        self.add_device()
        device, _ = self.app.resolve_device_record("SW1")
        responses = [
            (0, "Backup saved", ""),
            (0, "Config applied.", ""),
            (0, "Backup unchanged; skipped write.", ""),
        ]
        with mock.patch.object(self.app, "capture", side_effect=responses), mock.patch("sys.stdout", new_callable=io.StringIO) as output, mock.patch("time.sleep"):
            rc = self.app.apply_device_config_change(device, "192.0.2.1", ["show run"], netops.GlobalOptions(confirm=True, json=True))
        payload = json.loads(output.getvalue())
        self.assertEqual(rc, netops.PARTIAL)
        self.assertEqual(payload["status"], "ATTENTION")
        self.assertFalse(payload["changed"])
        audit = self.app.state.one("SELECT result FROM audit_events WHERE event_type='device_config_finished'")
        self.assertEqual(audit["result"], "attention")

    def test_device_config_verify_retries_once_after_a_transient_ssh_failure_then_succeeds(self):
        # Every phase opens its own fresh SSH session; reconnecting for
        # verify immediately after apply's "write memory" + "exit" can race
        # a device that's still settling (transport-level SSH failure, not
        # a real problem). A retry after a brief pause should recover.
        self.add_device()
        device, _ = self.app.resolve_device_record("SW1")
        responses = [
            (0, "Backup saved", ""),
            (0, "Config applied.", ""),
            (255, "", "SSH transport failed (exit 255)"),
            (0, "Backup saved to .../SW1.conf", ""),
        ]
        with mock.patch.object(self.app, "capture", side_effect=responses) as capture, mock.patch("sys.stdout", new_callable=io.StringIO) as output, mock.patch("time.sleep") as sleep:
            rc = self.app.apply_device_config_change(device, "192.0.2.1", ["show run"], netops.GlobalOptions(confirm=True, json=True))
        payload = json.loads(output.getvalue())
        self.assertEqual(rc, netops.SUCCESS)
        self.assertEqual(payload["status"], "SUCCESS")
        self.assertTrue(payload["changed"])
        self.assertEqual(capture.call_count, 4)
        self.assertEqual(sleep.call_count, 2)  # settle pause, then the retry backoff

    def test_device_config_verify_reports_unverified_when_the_retry_also_fails(self):
        self.add_device()
        device, _ = self.app.resolve_device_record("SW1")
        responses = [
            (0, "Backup saved", ""),
            (0, "Config applied.", ""),
            (255, "", "SSH transport failed (exit 255)"),
            (255, "", "SSH transport failed (exit 255)"),
        ]
        with mock.patch.object(self.app, "capture", side_effect=responses) as capture, mock.patch("sys.stdout", new_callable=io.StringIO) as output, mock.patch("time.sleep"):
            rc = self.app.apply_device_config_change(device, "192.0.2.1", ["show run"], netops.GlobalOptions(confirm=True, json=True))
        payload = json.loads(output.getvalue())
        self.assertEqual(rc, netops.PARTIAL)
        self.assertEqual(payload["status"], "UNVERIFIED")
        self.assertFalse(payload["changed"])
        self.assertIn("could not reconnect", payload["rollback"])
        self.assertEqual(capture.call_count, 4)
        audit = self.app.state.one("SELECT result FROM audit_events WHERE event_type='device_config_finished'")
        self.assertEqual(audit["result"], "unverified")

    def test_large_trunk_change_is_sampled_and_never_claimed_fully_verified(self):
        self.add_device()
        request = self.app.vlan_change_request({"target":"SW1", "interface":"Gi1/0/48", "vlan_mode":"trunk", "vlan":"100-120"})
        located = "[192.0.2.1] SW1 -> DEFINED\nTrunk Ports: Gi1/0/48\n"
        responses = [(0, "pre-state", ""), (0, "backup", ""), (0, "applied", ""), (0, located, ""), (0, located, "")]
        with mock.patch.object(self.app, "capture", side_effect=responses) as capture, mock.patch("sys.stdout", new_callable=io.StringIO) as output:
            rc = self.app.apply_vlan_change(request, netops.GlobalOptions(confirm=True, json=True))
        payload = json.loads(output.getvalue())
        self.assertEqual(rc, netops.PARTIAL)
        self.assertEqual(capture.call_count, 5)
        self.assertEqual(payload["verification_vlans"], [100, 120])
        self.assertFalse(payload["verification_complete"])
        self.assertTrue(payload["verification_observed"])
        self.assertFalse(payload["verified"])
        self.assertEqual(payload["status"], "ATTENTION")

    def workflow_steps(self, name="morning-check"):
        # Read the manifest rather than hard-coding a count, so adding a step
        # does not fail a test that is about failure policy.
        return len(self.app.workflow_manifest(name)["steps"])

    def run_workflow(self, responses, name="morning-check"):
        with mock.patch.object(self.app, "capture_streamed", side_effect=responses) as capture, \
                mock.patch("sys.stdout", new_callable=io.StringIO) as output:
            rc = self.app.cmd_workflow([name], netops.GlobalOptions(json=True))
        return rc, json.loads(output.getvalue()), capture

    def test_workflow_emits_one_structured_summary_and_continues_by_policy(self):
        total = self.workflow_steps()
        responses = [(0, '{"ok":true,"status":"PASS"}', ""), (4, '{"ok":false,"status":"DOWN"}', "")]
        responses.extend((0, '{"ok":true}', "") for _ in range(total - 2))
        rc, payload, capture = self.run_workflow(responses)
        self.assertEqual(rc, netops.PARTIAL)
        self.assertEqual(payload["status"], "PARTIAL")
        self.assertEqual(payload["completed_steps"], total)
        self.assertEqual(payload["failed_steps"], 1)
        self.assertEqual(capture.call_count, total)

    def test_a_step_that_reports_findings_has_not_failed(self):
        """`health attention` exits PARTIAL exactly when it has something to show.

        Calling that a failure put a red row on every healthy morning, which is
        how an operator learns to stop reading the summary.
        """
        total = self.workflow_steps()
        responses = [(0, '{"ok":true}', "") for _ in range(total - 1)]
        responses.append((netops.PARTIAL, '{"ok":true,"rows":[{"kind":"health"}]}', ""))
        rc, payload, _ = self.run_workflow(responses)
        self.assertEqual(payload["failed_steps"], 0)
        self.assertEqual(payload["attention_steps"], 1)
        self.assertEqual(payload["status"], "ATTENTION")
        self.assertEqual(payload["steps"][-1]["status"], "ATTENTION")
        self.assertTrue(payload["ok"])
        self.assertEqual(rc, netops.PARTIAL)

    def test_findings_do_not_stop_a_workflow_that_stops_on_failure(self):
        # on_failure="stop" must react to a broken step, not to a step that
        # found something worth reporting.
        manifest = self.app.workflow_manifest("morning-check")
        total = len(manifest["steps"])
        responses = [(netops.PARTIAL, '{"ok":true}', "") for _ in range(total)]
        with mock.patch.object(self.app, "workflow_manifest", return_value={
            **manifest,
            "steps": [{**item, "on_failure": "stop"} for item in manifest["steps"]],
        }):
            _, payload, capture = self.run_workflow(responses)
        self.assertEqual(capture.call_count, total)
        self.assertFalse(payload["stopped"])

    def test_a_clean_morning_reports_success(self):
        total = self.workflow_steps()
        _, payload, _ = self.run_workflow([(0, '{"ok":true}', "") for _ in range(total)])
        self.assertEqual(payload["status"], "SUCCESS")
        self.assertEqual(payload["attention_steps"], 0)

    def test_morning_check_refreshes_topology_before_reviewing_it(self):
        """Reviewing recorded changes without scanning reports yesterday."""
        steps = [item["id"] for item in self.app.workflow_manifest("morning-check")["steps"]]
        self.assertIn("topology-scan", steps)
        self.assertLess(steps.index("topology-scan"), steps.index("topology"))
        # Reachability first, so the scan has fresh status to skip offline by.
        self.assertLess(steps.index("health"), steps.index("topology-scan"))

if __name__ == "__main__":
    unittest.main()
