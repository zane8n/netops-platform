import base64
import io
import json
import os
from pathlib import Path
import runpy
import stat
import subprocess
import tempfile
import tomllib
import unittest
from unittest import mock


import netops_core as netops
from netops_platform.preferences import PreferenceStore
from netops_platform.service import NetOpsService


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
        self.service = NetOpsService(self.app)

    def tearDown(self):
        self.app.shutdown_jobs(wait=0.1)
        self.env.stop()
        self.temp.cleanup()

    def add_device(self, ip="192.0.2.1", hostname="SW1", platform="Cisco IOS XE 17.9"):
        self.app.state.execute(
            "INSERT INTO devices(ip,hostname,platform,model,serial,mac,source,last_seen,status) VALUES(?,?,?,?,?,?,?,?,?)",
            (ip, hostname, platform, "C9300", "SERIAL", "", "test", 1_700_000_000, "ONLINE"),
        )

    def test_registry_is_fully_enriched_for_generated_forms(self):
        registry = self.service.registry()
        self.assertGreaterEqual(len(registry), 90)
        required = {"id", "label", "description", "domain", "arg_schema", "safety_class", "output_view", "capability", "confirmation_policy"}
        for command in registry:
            with self.subTest(command=command["id"]):
                self.assertTrue(required.issubset(command))
                for field in command["arg_schema"]:
                    self.assertIn("help", field)
                    self.assertIn("group", field)
                    self.assertIn("default", field)

    def test_tui_help_is_side_effect_free_and_open_is_a_supported_alias(self):
        from netops_platform.tui.main import parse_tui_args

        with mock.patch.object(netops.App, "__init__", side_effect=AssertionError("help initialized runtime state")), mock.patch("sys.stdout", new_callable=io.StringIO) as output:
            rc = netops.main(["tui", "--help"])
        self.assertEqual(rc, netops.SUCCESS)
        self.assertIn("netops tui", output.getvalue())
        self.assertEqual(parse_tui_args([]), ("operations", ""))
        self.assertEqual(parse_tui_args(["--view", "inventory", "--target", "SW1"]), ("inventory", "SW1"))
        scripts = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["scripts"]
        self.assertEqual(scripts["netop"], scripts["netops"])
        core = object()
        with mock.patch.dict(os.environ, {"TERM": "xterm-256color"}), \
             mock.patch.object(netops.sys.stdin, "isatty", return_value=True), \
             mock.patch.object(netops.sys.stdout, "isatty", return_value=True), \
             mock.patch.object(netops, "App", return_value=core), \
             mock.patch("netops_platform.tui.main.launch_tui", return_value=0) as launch:
            rc = netops.main(["tui", "open", "--view", "inventory"])
        self.assertEqual(rc, netops.SUCCESS)
        launch.assert_called_once_with(core, ["--view", "inventory"])

    def test_source_launcher_hands_tui_to_managed_runtime_and_tui_import_is_lazy(self):
        system_python = Path("/usr/bin/python3")
        managed_python = ROOT / ".venv" / "bin" / "python"
        if not system_python.is_file() or not managed_python.is_file():
            self.skipTest("source-runtime handoff requires the local synchronized environment")
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(ROOT)
        imported = subprocess.run(
            [str(system_python), "-c", "import netops_platform.tui.main; print('lazy-ok')"],
            cwd=ROOT, env=environment, text=True, capture_output=True, timeout=10,
        )
        self.assertEqual(imported.returncode, 0, imported.stderr)
        self.assertIn("lazy-ok", imported.stdout)
        with mock.patch("sys.argv", [str(ROOT / "netops"), "--no-color", "tui"]), \
             mock.patch.object(netops.sys, "prefix", "/usr"), \
             mock.patch("importlib.util.find_spec", return_value=None), \
             mock.patch("os.execve", side_effect=RuntimeError("managed handoff")) as execute:
            with self.assertRaisesRegex(RuntimeError, "managed handoff"):
                runpy.run_path(str(ROOT / "netops"), run_name="netops_bootstrap_test")
        self.assertEqual(Path(execute.call_args.args[0]), managed_python)
        self.assertEqual(execute.call_args.args[1][1:], [str(ROOT / "netops"), "--no-color", "tui"])
        launched = subprocess.run(
            [str(system_python), str(ROOT / "netops"), "tui", "--help"],
            cwd=ROOT, env=environment, text=True, capture_output=True, timeout=10,
        )
        self.assertEqual(launched.returncode, 0, launched.stderr)
        self.assertIn("command-first local operator console", launched.stdout)
        self.assertNotIn("No module named 'textual'", launched.stderr)

    def test_version_falls_back_to_installed_distribution_metadata(self):
        with mock.patch.object(Path, "read_text", side_effect=OSError), mock.patch.object(netops, "distribution_version", return_value="8.5.0b1"):
            self.assertEqual(netops.resolved_version(), "8.5.0b1")

    def test_preferences_are_normalized_private_and_atomic(self):
        path = self.base / "preferences" / "tui.json"
        store = PreferenceStore(path)
        store.save(
            {
                "theme": "invalid",
                "density": "comfortable",
                "saved_filters": {"inventory": "offline"},
                "pinned_actions": ["health-check"],
                "visible_columns": {"inventory": ["name", "ip"]},
            }
        )
        loaded = store.load()
        self.assertEqual(loaded["theme"], "auto")
        self.assertEqual(loaded["preferences_version"], 2)
        self.assertEqual(loaded["density"], "comfortable")
        self.assertEqual(loaded["saved_filters"], {"inventory": "offline"})
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
        self.assertEqual(list(path.parent.glob(".tui.*.tmp")), [])

    def test_legacy_default_tui_preferences_migrate_to_neutral_action_hub(self):
        path = self.base / "preferences" / "legacy-tui.json"
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps({"theme": "netops-dark", "last_view": "overview"}), encoding="utf-8")
        loaded = PreferenceStore(path).load()
        self.assertEqual(loaded["preferences_version"], 2)
        self.assertEqual(loaded["theme"], "auto")
        self.assertEqual(loaded["last_view"], "operations")

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

    def test_vlan_preview_and_service_confirmation_are_bound_to_exact_intent(self):
        args = {"target":"SW1", "interface":"Gi1/0/7", "vlan_mode":"access", "vlan":"131"}
        preview = self.service.preview("vlan-set", args)
        self.assertFalse(preview.blocked)
        self.assertIn("--access 131 --confirm", preview.command)
        self.assertEqual(preview.confirmation_phrase, "APPLY SW1 Gi1/0/7")
        with self.assertRaises(PermissionError):
            self.service.submit("vlan-set", args, reason="approved", ticket="CHG-1", preview_hash=preview.preview_hash, typed_confirmation="APPLY SOMETHING ELSE")
        with mock.patch.object(self.app, "create_job", return_value={"id":"job1", "action":"vlan-set"}) as create:
            result = self.service.submit("vlan-set", args, reason="approved", ticket="CHG-1", preview_hash=preview.preview_hash, typed_confirmation=preview.confirmation_phrase)
        self.assertEqual(result["id"], "job1")
        context = create.call_args.kwargs["context"]
        self.assertEqual(context["ticket"], "CHG-1")
        self.assertEqual(context["typed_confirmation"], preview.confirmation_phrase)

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

    def test_workflow_emits_one_structured_summary_and_continues_by_policy(self):
        responses = [(0, '{"ok":true,"status":"PASS"}', ""), (4, '{"ok":false,"status":"DOWN"}', "")]
        responses.extend((0, '{"ok":true}', "") for _ in range(4))
        with mock.patch.object(self.app, "capture_streamed", side_effect=responses) as capture, mock.patch("sys.stdout", new_callable=io.StringIO) as output:
            rc = self.app.cmd_workflow(["morning-check"], netops.GlobalOptions(json=True))
        payload = json.loads(output.getvalue())
        self.assertEqual(rc, netops.PARTIAL)
        self.assertEqual(payload["status"], "PARTIAL")
        self.assertEqual(payload["completed_steps"], 6)
        self.assertEqual(payload["failed_steps"], 1)
        self.assertEqual(capture.call_count, 6)

    def test_job_results_are_adapted_to_dynamic_datasets(self):
        self.app.state.execute(
            "INSERT INTO jobs(id,action,command,status,created_at,started_at,finished_at,exit_code,read_only,writes_local,result_json,summary,duration_ms) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("job-v8", "diagnose-speed", "netops diagnose speed", "partial", 100, 101, 102, 3, 1, 1, json.dumps({"status":"PARTIAL", "rows":[{"status":"WARN", "target":"internet"}], "findings":[{"severity":"warning", "code":"LOW_CONFIDENCE", "message":"Only one server completed"}]}), "PARTIAL", 1200),
        )
        self.app.state.execute(
            "INSERT INTO job_logs(job_id,created_at,stream,line,event_type,payload_json) VALUES(?,?,?,?,?,?)",
            ("job-v8", 101, "system", "started", "log", "{}"),
        )
        envelope = self.service.job_result("job-v8")
        self.assertIsNotNone(envelope)
        self.assertEqual(envelope.status, "partial")
        self.assertIn("rows", {dataset.id for dataset in envelope.datasets})
        self.assertIn("job_events", {dataset.id for dataset in envelope.datasets})
        self.assertGreaterEqual(len(envelope.findings), 2)


if __name__ == "__main__":
    unittest.main()
