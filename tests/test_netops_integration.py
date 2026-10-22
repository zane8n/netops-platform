"""Cross-module behaviour: identity, topology evidence, coherence, and the weekly workflow."""

import contextlib
import io
import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import netops_core as netops

from netops_platform import identity
from netops_platform.inventory_ingest import merge_device_observations


ROOT = Path(__file__).resolve().parents[1]


class IdentityEvidenceTest(unittest.TestCase):
    def test_one_name_on_two_live_addresses_is_two_switches(self):
        seen = 1_800_000_000
        rows = [
            {"ip": "192.0.2.79", "hostname": "SITE-A-H39-SW01", "mac": "", "serial": "", "status": "ONLINE", "last_seen": seen},
            {"ip": "192.0.2.36", "hostname": "SITE-A-H39-SW01", "mac": "", "serial": "", "status": "ONLINE", "last_seen": seen + 30},
        ]
        self.assertEqual(len(identity.reconcile_device_rows(rows)), 2)
        # The same name on an address it has since left is still one switch.
        moved = [dict(rows[0]), {**rows[1], "status": "OFFLINE", "last_seen": seen - 7 * 86400}]
        self.assertEqual(len(identity.reconcile_device_rows(moved)), 1)
        self.assertIn("concurrent-addresses", identity.identity_match_evidence(rows[0], rows[1], "switch")["conflicts"])

    def test_snmp_never_replaces_the_cisco_motherboard_serial_for_the_same_model(self):
        stored = {"ip": "192.0.2.5", "hostname": "SW", "platform": "Cisco IOS", "model": "C9300L-24P-4G",
                  "serial": "FOC26301087", "mac": "02a9b8070c00", "source": "SNMP", "status": "ONLINE", "last_seen": 1}
        snmp = {**stored, "serial": "FOC2630YV8B", "source": "SNMP", "last_seen": 2}
        merged, _ = merge_device_observations(stored, snmp)
        self.assertEqual(merged["serial"], "FOC26301087")
        swapped, _ = merge_device_observations(stored, {**snmp, "model": "C9200-24PXG"})
        self.assertEqual(swapped["serial"], "FOC2630YV8B")
        filled, _ = merge_device_observations({**stored, "serial": "N/A"}, snmp)
        self.assertEqual(filled["serial"], "FOC2630YV8B")
        # SSH reads `show version`, whose Motherboard serial wins.
        ssh, _ = merge_device_observations({**stored, "serial": "FOC2630YV8B"}, {**stored, "serial": "FOC26301087", "source": "SSH"})
        self.assertEqual(ssh["serial"], "FOC26301087")

    def events(self, *rows):
        return [dict(zip(("created_at", "event_type", "local_ip", "local_port", "remote_name", "remote_ip"), row)) for row in rows]

    def test_a_neighbour_port_that_now_sees_another_switch_is_a_swap(self):
        t = 1_800_000_000
        found = identity.neighbor_port_transitions(self.events(
            (t, "link_removed", "192.0.2.1", "Te1/1/3", "SITE-A-ADMIN-YARD-SW01.example.com", "192.0.2.40"),
            (t, "link_added", "192.0.2.1", "Te1/1/3", "SITEA-FIELD-SW01.example.com", "192.0.2.41"),
            # Another switch where much changed at once: weaker evidence.
            (t, "link_removed", "192.0.2.2", "Gi1/0/1", "SW-OLD", ""), (t, "link_added", "192.0.2.2", "Gi1/0/1", "SW-NEW", ""),
            (t, "link_added", "192.0.2.2", "Gi1/0/2", "X1", ""), (t, "link_added", "192.0.2.2", "Gi1/0/3", "X2", ""),
            (t, "link_added", "192.0.2.2", "Gi1/0/4", "X3", ""),
            # A port that sees two switches in turn, and a port shared by two.
            (t, "link_removed", "192.0.2.5", "Gi0/1", "SW-A", ""), (t, "link_added", "192.0.2.5", "Gi0/1", "SW-B", ""),
            (t + 86400, "link_removed", "192.0.2.5", "Gi0/1", "SW-B", ""), (t + 86400, "link_added", "192.0.2.5", "Gi0/1", "SW-A", ""),
            (t, "link_removed", "192.0.2.6", "Gi1/1/1", "SW-C", ""), (t, "link_added", "192.0.2.6", "Gi1/1/1", "SW-D", ""),
            (t, "link_added", "192.0.2.6", "Gi1/1/1", "SW-E", ""),
            # A phone and an addressless host are not positions.
            (t, "link_removed", "192.0.2.7", "Gi1/0/5", "SEP001122334455", ""), (t, "link_added", "192.0.2.7", "Gi1/0/5", "SITE-A-AP9", ""),
            # An AP that moved ports.
            (t, "link_removed", "192.0.2.3", "Gi1/0/9", "SITE-A-AP7", ""),
            (t + 86400, "link_added", "192.0.2.4", "Gi1/0/2", "SITE-A-AP7", ""),
        ))
        swaps = {(swap["old_name"], swap["new_name"]): swap for swap in found["swaps"]}
        stable = swaps[("SITE-A-ADMIN-YARD-SW01", "SITEA-FIELD-SW01")]
        self.assertEqual((stable["confidence"], stable["other_link_changes"], stable["local_port"]), (90, 0, "Te1/1/3"))
        self.assertEqual(swaps[("SW-OLD", "SW-NEW")]["confidence"], 55)
        self.assertEqual(set(swaps), {("SITE-A-ADMIN-YARD-SW01", "SITEA-FIELD-SW01"), ("SW-OLD", "SW-NEW")})
        self.assertEqual([(move["name"], move["from"], move["to"]) for move in found["moves"]],
                         [("SITE-A-AP7", "192.0.2.3 Gi1/0/9", "192.0.2.4 Gi1/0/2")])

    def test_port_evidence_pairs_a_switch_renamed_beyond_recognition(self):
        t = 1_800_000_000
        swaps = identity.neighbor_port_transitions(self.events(
            (t, "link_removed", "192.0.2.1", "Te1/1/3", "SITE-B-ADMIN-YARD-SW01", "192.0.2.40"),
            (t, "link_added", "192.0.2.1", "Te1/1/3", "SITEAFIELDOFFICESW07", "192.0.2.41"),
        ))["swaps"]
        old = [{"name": "SITE-B-ADMIN-YARD-SW01", "canonical_id": "mac:02aa", "last_seen": t - 600}]
        new = [{"name": "SITEAFIELDOFFICESW07", "canonical_id": "mac:02bb", "first_seen": t}]
        self.assertEqual(identity.identity_continuity_candidates(old, new, "switch"), [])
        found = identity.identity_continuity_candidates(old, new, "switch", port_swaps=swaps)
        self.assertEqual(len(found), 1)
        self.assertTrue(found[0]["signals"]["same_neighbor_port_transition"])
        self.assertEqual(found[0]["signals"]["neighbor_port"], "192.0.2.1 Te1/1/3")
        self.assertGreaterEqual(found[0]["confidence"], 80)


class CheckCatalogueTest(unittest.TestCase):
    def test_every_check_runs_a_real_command(self):
        from netops_platform import checks_cli
        for check in checks_cli.CHECKS:
            with self.subTest(check=check.name):
                domain, action = check.argv[0], check.argv[1]
                self.assertIn(action, netops.HELP_TOPICS[domain]["actions"])
                self.assertTrue(check.reach and check.speed and check.tells)
        self.assertEqual(len({check.name for check in checks_cli.CHECKS}), len(checks_cli.CHECKS))

    def test_a_check_expands_with_its_flags_kept_in_order(self):
        from netops_platform.checks_cli import expand_argv
        self.assertEqual(expand_argv(["--json", "check", "vlan-trace", "SW1", "20", "--depth", "3"]),
                         ["--json", "vlan", "propagation", "SW1", "20", "--depth", "3"])
        self.assertEqual(expand_argv(["check", "port-health", "SW1", "Gi1/0/5"]), ["diagnose", "port-health", "SW1", "on", "Gi1/0/5"])
        self.assertEqual(expand_argv(["check", "ap-ports", "--all", "--dry-run"]), ["ap", "neighbors", "--all", "--dry-run"])
        self.assertIsNone(expand_argv(["check", "port-history", "SW1"]))           # an argument short
        self.assertIsNone(expand_argv(["check", "vlan-trace", "SW1", "20", "--show"]))
        self.assertIsNone(expand_argv(["inventory", "list", "check"]))             # a target named check


class AppTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        base = Path(self.temp.name)
        self.env = mock.patch.dict(os.environ, {
            "NETOPS_CONFIG_DIR": str(base / "config"), "NETOPS_CACHE_DIR": str(base / "cache"),
            "NETOPS_STATE_DIR": str(base / "state"), "NETOPS_DATA_DIR": str(base / "data"),
            "NETOPS_SQLITE_DB": str(base / "cache" / "netops.sqlite3"), "NETOPS_BACKUP_DIR": str(base / "backups"),
            "NETOPS_PROGRESS": "0",
        }, clear=False)
        self.env.start()
        self.app = netops.App(ROOT)
        seen = int(time.time()) - 600
        for ip, name, platform, model in (("192.0.2.10", "SITE-A-CORE-SW01", "Cisco IOS", "C9200-24PXG"),
                                          ("192.0.2.11", "SITE-A-BLDG2-SW01", "Aruba AOS-S", "2930F-8G-PoE+-2SFP+")):
            self.app.state.execute("INSERT INTO devices(ip,hostname,platform,model,serial,mac,source,last_seen,status) VALUES(?,?,?,?,?,?,?,?,?)",
                                   (ip, name, platform, model, "", "", "SSH", seen, "ONLINE"))

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def run_cli(self, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            code = self.app.dispatch([*args, "--plain", "--no-color"])
        return code, out.getvalue()


class CoherenceTest(AppTest):
    def test_realign_removes_switches_filed_as_aps(self):
        for ip, name, platform in (("192.0.2.62", "04 09 73 98 B0 40", "Aruba JL356A 2540-24G-PoE+-4SFP+ Switch, revision YC.16"),
                                   ("192.0.2.70", "SITE-A-AP70", "cisco C9136I-ROW")):
            self.app.state.execute("INSERT INTO aps(ip,name,platform,mac,last_seen,status) VALUES(?,?,?,?,?,?)",
                                   (ip, name, platform, "", int(time.time()), "ONLINE"))
        self.app.state.export_flat_files()
        code, output = self.run_cli("db", "coherence")
        self.assertIn("switch rows among APs", output)
        code, output = self.run_cli("db", "coherence", "--realign")
        self.assertIn("removed 1 switch rows", output)
        self.assertEqual([row["name"] for row in self.app.state.rows("SELECT name FROM aps")], ["SITE-A-AP70"])
        # The flat cache follows, so the next import does not bring it back.
        self.app.state.import_flat_files()
        self.assertEqual([row["name"] for row in self.app.state.rows("SELECT name FROM aps")], ["SITE-A-AP70"])

    def test_one_name_on_several_live_switches_is_reported(self):
        self.app.state.execute("UPDATE devices SET hostname='SITE-A-CORE-SW01'")
        payload = self.app.db_coherence_payload()
        shared = next(check for check in payload["checks"] if check["check"] == "shared_names")
        self.assertEqual((shared["status"], shared["items"]), ("WARN", ["SITE-A-CORE-SW01: 192.0.2.10, 192.0.2.11"]))


class CheckCommandTest(AppTest):
    def test_check_lists_explains_and_runs(self):
        code, output = self.run_cli("check")
        self.assertEqual(code, netops.SUCCESS)
        self.assertIn("What is up or down", output)
        self.assertIn("pulse [target]", output)
        code, output = self.run_cli("check", "vlan-trace", "--show")
        self.assertIn("Runs:  netrune vlan propagation <switch> <vlan>", output)
        code, output = self.run_cli("check", "port-history", "SW1")
        self.assertEqual(code, netops.VALIDATION)
        code, output = self.run_cli("check", "find", "CORE")
        self.assertEqual(code, netops.SUCCESS, output)
        self.assertIn("SITE-A-CORE-SW01", output)
        code, output = self.run_cli("check", "pulsee")
        self.assertEqual(code, netops.VALIDATION)
        self.assertIn("pulse", output)


class WeeklyWorkflowTest(AppTest):
    def test_ssh_steps_wait_for_the_vault_and_resume_runs_only_them(self):
        ran = []

        def fake_run(command, timeout=0, opts=None):
            ran.append(" ".join(command[1:3]))
            return 0, json.dumps({"ok": True, "summary": "done"}), ""
        locked = mock.patch.object(self.app, "vault_session_scope", lambda opts, minutes=30, desktop_prompt=False: contextlib.nullcontext(False))
        with mock.patch.object(self.app, "capture_streamed", fake_run), locked, \
                mock.patch.object(self.app, "vault_session_payload", lambda: {"active": False}):
            code, output = self.run_cli("workflow", "weekly")
        self.assertEqual(code, netops.PARTIAL, output)
        self.assertNotIn("device inventory", ran)
        self.assertIn("inventory scan", ran)
        self.assertEqual(output.count("(DEFERRED: vault locked)"), 4)
        pending = json.loads(self.app.state.get_marker("workflow_deferred:weekly"))
        self.assertEqual(pending["steps"], ["hardware", "ap-neighbors", "stp", "backup"])
        items = self.app.attention_payload()["items"]
        self.assertEqual(items[0]["kind"], "workflow")
        self.assertIn("netrune workflow weekly --resume", items[0]["text"])
        ran.clear()
        unlocked = mock.patch.object(self.app, "vault_session_scope", lambda opts, minutes=30, desktop_prompt=False: contextlib.nullcontext(True))
        with mock.patch.object(self.app, "capture_streamed", fake_run), unlocked:
            code, output = self.run_cli("workflow", "weekly", "--resume")
        self.assertEqual(code, netops.SUCCESS, output)
        self.assertEqual(ran, ["device inventory", "ap neighbors", "topology stp", "backup run"])
        self.assertEqual(self.app.state.get_marker("workflow_deferred:weekly"), "")

    def test_ssh_steps_wait_when_no_switch_is_reachable(self):
        self.app.state.execute("UPDATE devices SET status='OFFLINE'")
        with mock.patch.object(self.app, "capture_streamed", lambda command, timeout=0, opts=None: (0, "{}", "")), \
                mock.patch.object(self.app, "vault_session_scope", side_effect=AssertionError("no unlock off-site")):
            code, output = self.run_cli("workflow", "weekly")
        self.assertEqual(code, netops.PARTIAL)
        self.assertEqual(output.count("(DEFERRED: no switch reachable)"), 4)
        self.assertEqual(json.loads(self.app.state.get_marker("workflow_deferred:weekly"))["steps"], ["hardware", "ap-neighbors", "stp", "backup"])

    def test_schedule_writes_a_persistent_timer(self):
        code, output = self.run_cli("workflow", "schedule", "weekly", "--when", "Sat *-*-* 22:00:00", "--dry-run")
        self.assertEqual(code, netops.SUCCESS, output)
        self.assertIn("Persistent=true", output)
        self.assertIn("OnCalendar=Sat *-*-* 22:00:00", output)
        self.assertIn("NETRUNE_VAULT_DESKTOP_PROMPT=1", output)
        self.assertIn("workflow weekly", output)
        code, output = self.run_cli("workflow", "schedule", "morning-check")
        self.assertEqual(code, netops.VALIDATION)

    def test_device_inventory_all_refreshes_each_online_switch_once(self):
        asked = []

        def fake_capture(command, timeout=120, opts=None):
            asked.append(command[-1])
            return 0, "", ""
        with mock.patch.object(self.app, "capture", fake_capture), \
                mock.patch.object(self.app, "vault_session_scope", lambda opts, minutes=30, desktop_prompt=False: contextlib.nullcontext(False)):
            code, output = self.run_cli("device", "inventory", "--all", "--cisco")
        self.assertEqual(code, netops.SUCCESS, output)
        self.assertEqual(asked, ["192.0.2.10"])
        self.assertIn("Refreshed hardware details on 1 of 1 switch(es)", output)


if __name__ == "__main__":
    unittest.main()
