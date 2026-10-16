import glob
import json
import os
from pathlib import Path
import signal
import shlex
import shutil
import sqlite3
import stat
import subprocess
import sys
import re
import tempfile
import time
import types
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")

from netops_platform.network import parse_vlan_control_output


class NetOpsShellLifecycleTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        base = Path(self.temp.name)
        self.config_dir = base / "config"
        self.cache_dir = base / "cache"
        self.bin_dir = base / "bin"
        self.config_dir.mkdir()
        self.cache_dir.mkdir()
        self.bin_dir.mkdir()
        (self.config_dir / "netsnmp.conf").write_text('scan_workers="4"\n', encoding="utf-8")
        (self.config_dir / ".env").write_text('ssh_user="admin"\n', encoding="utf-8")
        self.password_file = base / "sshpass.gpg"
        self.password_file.write_text("fixture", encoding="utf-8")
        perl = self.bin_dir / "perl"
        perl.write_text("#!/usr/bin/env bash\nprintf 'Connection refused'\nexit 1\n", encoding="utf-8")
        perl.chmod(0o700)
        self.env = os.environ.copy()
        self.env.update(
            {
                "NETOPS_CONFIG_DIR": str(self.config_dir),
                "NETOPS_CACHE_DIR": str(self.cache_dir),
                "NETOPS_PASSWORD_FILE": str(self.password_file),
                "NETOPS_AUTO_CONFIGURE": "false",
                "NETOPS_PROGRESS": "0",
                "NETOPS_TEST_MODE": "true",
                # Fixtures answer instantly; the real login settle delay only
                # makes timing-sensitive assertions flaky.
                "NETOPS_SSH_SETTLE_TIMEOUT": "1",
                # Never fall back to the operator's real runtime directory: a
                # live vault session there would silently satisfy reads that a
                # test expects to cost an authentication.
                "NETRUNE_VAULT_SESSION_DIR": str(base / "vault-session"),
                "NETOPS_SUDO_VAULT_KEY_DIR": str(base / "sudo-vault-keys"),
                "PATH": f"{self.bin_dir}:{self.env.get('PATH', '')}",
            }
        )

    def tearDown(self):
        self.temp.cleanup()

    def run_helper(self, *args, input_text=None):
        return subprocess.run(
            [str(ROOT / args[0]), *args[1:]],
            cwd=ROOT,
            env=self.env,
            input=input_text,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
        )

    def run_control_function(self, script, *, stubs=""):
        """Run a netops-control shell function in isolation against fixtures."""
        preamble = (
            "set -u\n"
            "NEIGHBOR_DB=/dev/null\n"
            "DEEP_MODE=false\n"
            f"NETOPS_INGEST_HELPER={shlex.quote(str(ROOT / 'netops_ingest.py'))}\n"
            f"{stubs}\n"
            "eval \"$(sed -n '/^control_management_vlan() {/,/^}$/p' netops-control)\"\n"
            "eval \"$(sed -n '/^analyze_propagation() {/,/^}$/p' netops-control)\"\n"
            "eval \"$(sed -n '/^refine_inventory_from_ssh() {/,/^}$/p' netops-control)\"\n"
        )
        return subprocess.run(
            ["bash", "-c", preamble + script],
            cwd=ROOT, env=self.env, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20,
        )

    def run_offline_filter(self, targets, *, flags="", devices=None):
        """Exercise filter_offline_targets against a fixture inventory."""
        rows = devices if devices is not None else [
            "198.51.100.1|SW-ONLINE-1|Cisco IOS|C9300|S1|aa|SSH|1000|ONLINE",
            "198.51.100.2|SW-OFFLINE-1|Cisco IOS|C9300|S2|bb|SSH|1000|OFFLINE",
            "198.51.100.3|SW-OFFLINE-2|Cisco IOS|C9300|S3|cc|SSH|1000|offline",
            "198.51.100.4|SW-ONLINE-2|Cisco IOS|C9300|S4|dd|SSH|1000|ONLINE",
        ]
        (self.cache_dir / "devices.db").write_text("\n".join(rows) + "\n", encoding="utf-8")
        assignments = "\n".join(
            f'{name}="{value}"' for name, value in
            [("INCLUDE_OFFLINE", "false"), ("ONLINE_ONLY", "false"), ("JSON_OUTPUT", "false"),
             ("DRY_RUN", "true")] if f"{name}=" not in flags)
        script = (
            "set -u\n"
            f'DEVICES_DB="{self.cache_dir}/devices.db"\n'
            "db_get_device() { awk -F'|' -v ip=\"$1\" '$1 == ip { print; exit }' \"$DEVICES_DB\"; }\n"
            "warn() { echo \"[WARN] $1\"; }\n"
            f"{assignments}\n{flags}\n"
            "eval \"$(sed -n '/^device_marked_offline() {/,/^}$/p' netops-control)\"\n"
            "eval \"$(sed -n '/^filter_offline_targets() {/,/^}$/p' netops-control)\"\n"
            f"TARGETS=({' '.join(targets)})\n"
            "filter_offline_targets\n"
            'printf "%s\\n" "REMAINING:${TARGETS[*]}"\n'
        )
        return subprocess.run(["bash", "-c", script], cwd=ROOT, env=self.env, text=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)

    def test_a_sweep_skips_devices_the_last_check_could_not_reach(self):
        """Each unreachable device costs a full SSH timeout, about five seconds.

        A job spanning an estate pays that for every one of them before doing
        any work, which is time spent learning something already recorded.
        """
        result = self.run_offline_filter(["198.51.100.1", "198.51.100.2", "198.51.100.3", "198.51.100.4"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("REMAINING:198.51.100.1 198.51.100.4", result.stdout)
        self.assertIn("Skipped 2 device(s)", result.stdout)

    def test_a_recorded_status_is_read_whatever_its_case(self):
        result = self.run_offline_filter(["198.51.100.2", "198.51.100.3"])
        self.assertIn("REMAINING:", result.stdout)
        self.assertNotIn("198.51.100.3", result.stdout.split("REMAINING:")[1])

    def test_one_named_device_is_still_attempted_even_when_offline(self):
        # Naming a single device is how an operator asks whether it is back.
        result = self.run_offline_filter(["198.51.100.2"])
        self.assertIn("REMAINING:198.51.100.2", result.stdout)
        self.assertNotIn("Skipped", result.stdout)

    def test_online_only_skips_even_a_single_named_device(self):
        result = self.run_offline_filter(["198.51.100.2"], flags='ONLINE_ONLY="true"')
        self.assertIn("Skipped 1 device(s)", result.stdout)

    def test_include_offline_attempts_everything(self):
        result = self.run_offline_filter(
            ["198.51.100.1", "198.51.100.2", "198.51.100.3"], flags='INCLUDE_OFFLINE="true"')
        self.assertIn("REMAINING:198.51.100.1 198.51.100.2 198.51.100.3", result.stdout)
        self.assertNotIn("Skipped", result.stdout)

    def test_a_device_absent_from_the_inventory_is_not_assumed_offline(self):
        # Unknown is not the same as unreachable; a target nobody has scanned
        # yet still deserves an attempt.
        result = self.run_offline_filter(["198.51.100.1", "198.51.100.99"])
        self.assertIn("REMAINING:198.51.100.1 198.51.100.99", result.stdout)

    def test_a_sweep_of_only_offline_devices_stops_rather_than_hanging(self):
        result = self.run_offline_filter(
            ["198.51.100.2", "198.51.100.3"], flags='DRY_RUN="false"')
        self.assertIn("No online targets remain", result.stdout)

    ARUBA_PROPAGATION_FIXTURE = """
vlan 4
   name "Management-of-Switch-Range"
   tagged 7,25
   exit
vlan 104
   name "BGC02-Cisco-WAP"
   tagged 25
   exit
vlan 240
   name "Cisco-Voip"
   tagged 7,25
   exit

 Multiple Spanning Tree (MST) Information
  STP Enabled   : Yes
  Force Version : MSTP-operation
  Switch MAC Address : d06726-f2b6a0
  CST Root Port        : 25

  Port  Type       | Cost      rity State        | Bridge            Time PtP Edge
  ----- ---------- + --------- ---- ------------ + ----------------- ---- --- ----
  1     100/1000T  | 20000     128  Forwarding   | d06726-f2b6a0     2    Yes Yes
  4     100/1000T  | Auto      128  Disabled     |                   2    Yes No
  7     100/1000T  | 20000     128  Forwarding   | d06726-f2b6a0     2    Yes No
  25    1000LX     | 20000     128  Forwarding   | 94f128-2daa00     2    Yes No
"""

    PROPAGATION_STUBS = (
        "netops_platform_family() { printf 'aruba-aos-switch'; }\n"
        "db_get_device() { printf '|SITE-A-FIN-SW02|Aruba AOS-S|2930F|||||ONLINE'; }\n"
    )

    def test_aruba_propagation_selects_uplinks_from_spanning_tree(self):
        result = self.run_control_function(
            f"RAW={shlex.quote(self.ARUBA_PROPAGATION_FIXTURE)}\n"
            'analyze_propagation "198.51.100.12" "104" "$RAW" "false" "Aruba AOS-S"\n',
            stubs=self.PROPAGATION_STUBS,
        )
        output = ANSI.sub("", result.stdout)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        # Port 7 is forwarding and non-edge, so it is a real uplink even though
        # it carries few VLANs. The old VLAN-count heuristic dropped it.
        self.assertIn("- 7: MISSING", output)
        self.assertIn("- 25: PROPAGATED", output)
        self.assertIn("spanning tree", output)
        self.assertIn("root port: 25", output)
        # Edge and disabled ports are never reported as uplinks.
        self.assertNotIn("- 1:", output)
        self.assertNotIn("- 4:", output)

    def test_aruba_propagation_report_keeps_the_parsed_line_format(self):
        result = self.run_control_function(
            f"RAW={shlex.quote(self.ARUBA_PROPAGATION_FIXTURE)}\n"
            'analyze_propagation "198.51.100.12" "104" "$RAW" "false" "Aruba AOS-S"\n',
            stubs=self.PROPAGATION_STUBS,
        )
        parsed = parse_vlan_control_output(result.stdout, "propagation")
        self.assertTrue(parsed["defined"])
        self.assertEqual(
            {row["port"]: row["carries_vlan"] for row in parsed["trunks"]},
            {"7": False, "25": True},
        )

    def test_aruba_propagation_falls_back_to_the_heuristic_without_spanning_tree(self):
        # A port carrying the management VLAN plus more than five VLANs is all
        # the old heuristic could recognise; it stays as the fallback for
        # FastIron and for switches with spanning tree disabled.
        vlans = "".join(
            f'vlan {vlan}\n   name "V{vlan}"\n   tagged 25\n   exit\n'
            for vlan in (4, 10, 20, 30, 40, 50, 104)
        )
        result = self.run_control_function(
            f"RAW={shlex.quote(vlans)}\n"
            'analyze_propagation "198.51.100.12" "104" "$RAW" "false" "Aruba AOS-S"\n',
            stubs=self.PROPAGATION_STUBS,
        )
        output = ANSI.sub("", result.stdout)
        self.assertIn("VLAN-count heuristic", output)
        self.assertIn("- 25: PROPAGATED", output)

    def test_aruba_propagation_heuristic_misses_the_uplink_spanning_tree_finds(self):
        # Guards the reason spanning tree was introduced: port 7 is a real
        # forwarding uplink that the VLAN-count heuristic cannot see.
        without_stp = self.ARUBA_PROPAGATION_FIXTURE.split("Multiple Spanning Tree")[0]
        fallback = self.run_control_function(
            f"RAW={shlex.quote(without_stp)}\n"
            'analyze_propagation "198.51.100.12" "104" "$RAW" "false" "Aruba AOS-S"\n',
            stubs=self.PROPAGATION_STUBS,
        )
        self.assertIn("No valid uplinks found", ANSI.sub("", fallback.stdout))

        with_stp = self.run_control_function(
            f"RAW={shlex.quote(self.ARUBA_PROPAGATION_FIXTURE)}\n"
            'analyze_propagation "198.51.100.12" "104" "$RAW" "false" "Aruba AOS-S"\n',
            stubs=self.PROPAGATION_STUBS,
        )
        self.assertIn("- 7: MISSING", ANSI.sub("", with_stp.stdout))

    def test_management_vlan_prefers_what_the_device_states(self):
        result = self.run_control_function(
            'control_management_vlan "  Management VLAN : 15"; printf "\\n"\n'
            'control_management_vlan "  Management VLAN :"; printf "\\n"\n'
            'control_management_vlan "  management-vlan 7"; printf "\\n"\n'
        )
        self.assertEqual(result.stdout.split(), ["15", "4", "7"])

    def test_aruba_inventory_refinement_reads_serial_model_and_base_mac(self):
        fixture = (
            " Status and Counters - General System Information\n"
            "  System Name        : SITE-A-FIN-SW02\n"
            "  Base MAC Addr      : d06726-f2b6a0\n"
            "  Serial Number      : SG04KLM123\n"
            " Status and Counters - Module Information\n"
            "  Chassis: Aruba JL256A 2930F-48G-PoE+-4SFP+ Switch\n"
        )
        result = self.run_control_function(
            f"RAW={shlex.quote(fixture)}\n"
            'refine_inventory_from_ssh "198.51.100.12" "$RAW" "Aruba AOS-S"\n',
            stubs=(
                "netops_platform_family() { printf 'aruba-aos-switch'; }\n"
                "db_update_device() { printf '%s|%s|%s|%s\\n' \"$2\" \"$4\" \"$5\" \"$6\"; }\n"
            ),
        )
        name, model, serial, mac = result.stdout.strip().split("|")
        self.assertEqual(name, "SITE-A-FIN-SW02")
        # The model is the chassis name alone, without product number or "Switch".
        self.assertEqual(model, "2930F-48G-PoE+-4SFP+")
        # Both families label the field "Serial Number"; it must not be filtered out.
        self.assertEqual(serial, "SG04KLM123")
        self.assertEqual(mac, "d06726f2b6a0")

    def test_aruba_cx_inventory_refinement_reads_hostname_and_product_name(self):
        fixture = (
            "ArubaOS-CX\n"
            " Hostname           : SITE-A-CORE-CX01\n"
            " Product Name       : 6300M 48SR5 CL6 PoE 4SFP56 Swch\n"
            " Serial Number      : SG09ABC456\n"
            " Base MAC Address   : 88:3a:30:11:22:33\n"
        )
        result = self.run_control_function(
            f"RAW={shlex.quote(fixture)}\n"
            'refine_inventory_from_ssh "198.51.100.13" "$RAW" "Aruba AOS-CX"\n',
            stubs=(
                "netops_platform_family() { printf 'aruba-aos-cx'; }\n"
                "db_update_device() { printf '%s|%s|%s|%s\\n' \"$2\" \"$4\" \"$5\" \"$6\"; }\n"
            ),
        )
        name, model, serial, mac = result.stdout.strip().split("|")
        self.assertEqual(name, "SITE-A-CORE-CX01")
        self.assertEqual(model, "6300M 48SR5 CL6 PoE 4SFP56")
        self.assertEqual(serial, "SG09ABC456")
        self.assertEqual(mac, "883a30112233")

    def test_cisco_inventory_refinement_reads_labelled_show_version_fields(self):
        fixture = (
            "SITE-A-SW09#show version\n"
            "Base Ethernet MAC Address          : 02:00:00:c5:be:00\n"
            "Motherboard Serial Number          : FVH0000MB09\n"
            "Model Number                      : C9200-24PXG\n"
            "System Serial Number               : FVH0000SY09\n"
        )
        stubs = (
            "netops_platform_family() { printf 'cisco-ios'; }\n"
            "db_update_device() { printf '%s|%s|%s|%s\\n' \"$2\" \"$4\" \"$5\" \"$6\"; }\n"
        )
        result = self.run_control_function(
            f"RAW={shlex.quote(fixture)}\n"
            'refine_inventory_from_ssh "198.51.100.19" "$RAW" "Cisco IOS"\n',
            stubs=stubs,
        )
        self.assertEqual(result.stdout.strip(), "SITE-A-SW09|C9200-24PXG|FVH0000MB09|020000c5be00", result.stderr)
        # A non-inventory job must not turn an interface address into the base MAC.
        other = self.run_control_function(
            "RAW=$'SITE-A-SW09#show interfaces\\n  Hardware is Gigabit Ethernet, address is 0200.0000.be81'\n"
            'refine_inventory_from_ssh "198.51.100.19" "$RAW" "Cisco IOS"\n',
            stubs=stubs,
        )
        self.assertEqual(other.stdout.strip(), "SITE-A-SW09|N/A|N/A|N/A", other.stderr)

    def run_scan_host(self, answers, sysdescr):
        """Run netops-discovery's scan_host against canned SNMP answers."""
        table = "\n".join(f"{oid}\t{value}" for oid, value in answers.items())
        script = (
            "set -u\n"
            f"NETOPS_INGEST_HELPER={shlex.quote(str(ROOT / 'netops_ingest.py'))}\n"
            "declare -A CONFIG=([ping_timeout]=1)\n"
            f"ANSWERS={shlex.quote(table)}\n"
            "ping() { return 0; }\n"
            "netops_snmp_get() { case \"$2\" in sysName.0) echo SITE-A-SW10 ;; "
            f"sysDescr.0) echo {shlex.quote(sysdescr)} ;; 1.3.6.1.2.1.17.1.1.0) echo '02 A9 B8 07 0C 00 ' ;; esac; }}\n"
            "netops_snmp_get_many() { local ip=\"$1\" oid; shift; for oid in \"$@\"; do "
            "awk -F'\\t' -v o=\"SNMPv2-SMI::mib-2.${oid#1.3.6.1.2.1.}\" '$1 == o' <<< \"$ANSWERS\"; done; }\n"
            "netops_snmp_walk() { return 1; }\n"
            "eval \"$(sed -n '/^sanitize_string()/p' netops-discovery)\"\n"
            "eval \"$(sed -n '/^netops_platform_family() {/,/^}$/p' netops-lib.sh)\"\n"
            "eval \"$(sed -n '/^scan_host() {/,/^}$/p' netops-discovery)\"\n"
            "scan_host 198.51.100.20\n"
        )
        result = subprocess.run(["bash", "-c", script], cwd=ROOT, env=self.env, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip().split("|")

    def test_scan_reads_model_and_serial_from_the_chassis_entity(self):
        entity = "SNMPv2-SMI::mib-2.47.1.1.1.1"
        no_such = "No Such Instance currently exists at this OID"
        catalyst = self.run_scan_host({
            f"{entity}.5.1": "11", f"{entity}.5.1000": "3", f"{entity}.5.1001": no_such,
            f"{entity}.13.1000": "C9200-24PXG", f"{entity}.11.1000": "FVH0000SY10", f"{entity}.2.1000": "C9200-24PXG",
        }, "Cisco IOS Software [Dublin], Catalyst L3 Switch Software (CAT9K_LITE_IOSXE), Version 17.12.4")
        self.assertEqual(catalyst[2:7], ["Cisco IOS", "C9200-24PXG", "FVH0000SY10", "02a9b8070c00", "SNMP"])
        aruba = self.run_scan_host({
            f"{entity}.5.1": no_such, f"{entity}.5.1000": no_such, f"{entity}.5.1001": "3",
            f"{entity}.13.1001": "J9851A", f"{entity}.11.1001": "SG00TEST10", f"{entity}.2.1001": "HP J9851A Switch 5412Rzl2",
        }, "HP J9851A Switch 5412Rzl2, revision KB.16.10.0010, ROM KB.16.01.0006")
        self.assertEqual(aruba[2:5], ["Aruba AOS-S", "5412Rzl2", "SG00TEST10"])

    def run_vault_session(self, script, session_dir):
        """Run the vault-session helpers with a stubbed sudo-backed key read."""
        preamble = (
            "set -u\n"
            f'export NETRUNE_VAULT_SESSION_DIR={shlex.quote(str(session_dir))}\n'
            f'SUDO_CALLS={shlex.quote(str(session_dir) + ".calls")}\n'
            ": > \"$SUDO_CALLS\"\n"
            "eval \"$(sed -n '/^_vault_session_dir() {/,/^_sudo_vault_emit_key() {/p' netops-lib.sh | head -n -1)\"\n"
            # Stand in for the real sudo/Windows Hello key read and count it.
            "_sudo_vault_emit_key() {\n"
            "    if [[ ! \"${NETRUNE_VAULT_SESSION_BYPASS:-false}\" =~ ^(1|true|yes)$ ]] && _vault_session_read; then\n"
            "        return 0\n"
            "    fi\n"
            "    echo sudo >> \"$SUDO_CALLS\"\n"
            "    printf 'FAKEKEYMATERIAL==\\n'\n"
            "}\n"
            "calls() { wc -l < \"$SUDO_CALLS\" | tr -d ' '; }\n"
            "start_session() { NETRUNE_VAULT_SESSION_BYPASS=1 _sudo_vault_emit_key | _vault_session_store \"$1\"; }\n"
        )
        return subprocess.run(
            ["bash", "-c", preamble + script],
            cwd=ROOT, env=self.env, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20,
        )

    def make_session_dir(self):
        """A tmpfs directory, which is the only place a session may live."""
        for base in (os.environ.get("XDG_RUNTIME_DIR"), "/dev/shm"):
            if not base or not os.path.isdir(base):
                continue
            path = Path(base) / f"netrune-test-{os.getpid()}-{time.time_ns()}"
            path.mkdir(mode=0o700, parents=True, exist_ok=True)
            self.addCleanup(shutil.rmtree, path, ignore_errors=True)
            self.addCleanup(lambda p=str(path) + ".calls": Path(p).unlink(missing_ok=True))
            return path
        self.skipTest("no tmpfs directory available for a vault session")

    def test_vault_session_replaces_repeated_authentication_with_one(self):
        session = self.make_session_dir()
        result = self.run_vault_session(
            'for _ in 1 2 3; do _sudo_vault_emit_key >/dev/null; done\n'
            'echo "unlocked=$(calls)"\n'
            'start_session 5 >/dev/null\n'
            # Reset after storing: unlocking itself costs one authentication,
            # which is the one the session is meant to replace.
            ': > "$SUDO_CALLS"\n'
            'for _ in 1 2 3 4 5; do _sudo_vault_emit_key >/dev/null; done\n'
            'echo "session=$(calls)"\n'
            'echo "key=$(_sudo_vault_emit_key)"\n',
            session,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        output = dict(line.split("=", 1) for line in result.stdout.strip().splitlines() if "=" in line)
        # Without a session every read costs an authentication.
        self.assertEqual(output["unlocked"], "3")
        # With one, the whole batch is free and the key is unchanged.
        self.assertEqual(output["session"], "0")
        self.assertEqual(output["key"], "FAKEKEYMATERIAL==")

    def test_vault_session_key_is_private_and_memory_backed(self):
        session = self.make_session_dir()
        result = self.run_vault_session(
            'start_session 5 >/dev/null\n'
            'stat -c "keymode=%a" "$NETRUNE_VAULT_SESSION_DIR/netrune-vault/key"\n'
            'stat -c "dirmode=%a" "$NETRUNE_VAULT_SESSION_DIR/netrune-vault"\n'
            'stat -f -c "fstype=%T" "$NETRUNE_VAULT_SESSION_DIR/netrune-vault"\n',
            session,
        )
        output = dict(line.split("=", 1) for line in result.stdout.strip().splitlines() if "=" in line)
        self.assertEqual(output["keymode"], "600")
        self.assertEqual(output["dirmode"], "700")
        self.assertIn(output["fstype"], {"tmpfs", "ramfs"})

    def test_vault_session_expires_and_purges_itself(self):
        session = self.make_session_dir()
        result = self.run_vault_session(
            'start_session 5 >/dev/null\n'
            'printf "%s\\n" "$(( $(date +%s) - 1 ))" > "$NETRUNE_VAULT_SESSION_DIR/netrune-vault/expires-at"\n'
            ': > "$SUDO_CALLS"\n'
            '_sudo_vault_emit_key >/dev/null\n'
            'echo "calls=$(calls)"\n'
            'echo "purged=$([[ -e "$NETRUNE_VAULT_SESSION_DIR/netrune-vault/key" ]] && echo no || echo yes)"\n',
            session,
        )
        output = dict(line.split("=", 1) for line in result.stdout.strip().splitlines() if "=" in line)
        # An expired session authenticates again rather than serving a stale key.
        self.assertEqual(output["calls"], "1")
        self.assertEqual(output["purged"], "yes")

    def test_vault_session_rejects_a_key_that_became_readable_by_others(self):
        session = self.make_session_dir()
        result = self.run_vault_session(
            'start_session 5 >/dev/null\n'
            'chmod 644 "$NETRUNE_VAULT_SESSION_DIR/netrune-vault/key"\n'
            ': > "$SUDO_CALLS"\n'
            '_sudo_vault_emit_key >/dev/null\n'
            'echo "calls=$(calls)"\n'
            'echo "purged=$([[ -e "$NETRUNE_VAULT_SESSION_DIR/netrune-vault/key" ]] && echo no || echo yes)"\n',
            session,
        )
        output = dict(line.split("=", 1) for line in result.stdout.strip().splitlines() if "=" in line)
        self.assertEqual(output["calls"], "1")
        self.assertEqual(output["purged"], "yes")
        self.assertIn("Discarding the vault session", result.stderr)

    def test_vault_session_refuses_a_location_that_is_not_memory_backed(self):
        # Must be a genuinely disk-backed path: /tmp is tmpfs on many systems,
        # which would satisfy the check the test is trying to exercise.
        disk_root = Path(tempfile.mkdtemp(dir=Path.home(), prefix=".netrune-test-"))
        self.addCleanup(shutil.rmtree, disk_root, ignore_errors=True)
        if subprocess.run(["stat", "-f", "-c", "%T", str(disk_root)], text=True,
                          stdout=subprocess.PIPE).stdout.strip() in {"tmpfs", "ramfs"}:
            self.skipTest("no disk-backed path available to test the refusal")
        on_disk = disk_root / "ondisk"
        result = self.run_vault_session(
            f'NETRUNE_VAULT_SESSION_DIR={shlex.quote(str(on_disk))} '
            'start_session 5 && echo "stored" || echo "refused"\n'
            f'echo "written=$([[ -e {shlex.quote(str(on_disk))}/netrune-vault/key ]] && echo yes || echo no)"\n',
            self.make_session_dir(),
        )
        self.assertIn("refused", result.stdout)
        self.assertIn("memory-backed tmpfs is required", result.stderr)
        self.assertIn("written=no", result.stdout)

    def test_vault_session_ttl_is_bounded(self):
        session = self.make_session_dir()
        for minutes in ("0", "9999", "abc"):
            with self.subTest(minutes=minutes):
                result = self.run_vault_session(
                    f'start_session {minutes} && echo accepted || echo rejected\n', session
                )
                self.assertIn("rejected", result.stdout)
        accepted = self.run_vault_session('start_session 480 >/dev/null && echo accepted\n', session)
        self.assertIn("accepted", accepted.stdout)

    def run_discovery_progress(self, script, columns="60", env=None):
        environment = dict(self.env)
        environment["COLUMNS"] = columns
        environment.pop("NO_COLOR", None)
        environment.update(env or {})
        preamble = (
            "set -u\n"
            "eval \"$(sed -n '/^progress_enabled() {/,/^progress_start() {/p' netops-discovery | head -n -1)\"\n"
            # Force the tty gate on; the shape and trimming are what matter here.
            "progress_enabled() { [[ \"${FORCE_PROGRESS:-1}\" != 0 ]]; }\n"
        )
        # Capture bytes: text mode applies universal newlines and would rewrite
        # the carriage return that makes the status line redraw in place.
        completed = subprocess.run(
            ["bash", "-c", preamble + script],
            cwd=ROOT, env=environment,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20,
        )
        return types.SimpleNamespace(
            returncode=completed.returncode,
            stdout=completed.stdout.decode("utf-8", "replace"),
            stderr=completed.stderr.decode("utf-8", "replace"),
        )

    def test_discovery_progress_line_is_trimmed_to_the_terminal(self):
        long_label = "resolving a very long switch hostname that would otherwise wrap the line"
        for columns in ("40", "60", "100"):
            with self.subTest(columns=columns):
                result = self.run_discovery_progress(
                    f'progress_note "{long_label}"\n', columns=columns
                )
                line = ANSI.sub("", result.stderr).replace("\r", "")
                self.assertLessEqual(len(line), int(columns) - 1)
                self.assertTrue(line.startswith("[STATUS] discovery |"))

    def test_discovery_progress_matches_the_python_status_shape(self):
        result = self.run_discovery_progress('progress_note "AP switch scan"\n', columns="120")
        line = ANSI.sub("", result.stderr).replace("\r", "")
        self.assertEqual(line, "[STATUS] discovery | AP switch scan | Ctrl+C cancels")

    def test_discovery_progress_honours_both_env_names_and_no_color(self):
        script = 'progress_enabled && echo enabled || echo disabled\n'
        # Restore the real gate for this one: it is the gate under test.
        preamble_script = (
            "eval \"$(sed -n '/^progress_enabled() {/,/^progress_width() {/p' netops-discovery | head -n -1)\"\n"
            + script
        )

        def gate(env):
            environment = dict(self.env)
            environment.pop("NO_COLOR", None)
            environment.update(env)
            return subprocess.run(
                ["bash", "-c", preamble_script], cwd=ROOT, env=environment,
                text=True, stdout=subprocess.PIPE, timeout=20,
            ).stdout.strip()

        # No tty under pytest, so the gate must refuse regardless.
        self.assertEqual(gate({}), "disabled")
        self.assertEqual(gate({"NO_COLOR": "1"}), "disabled")
        self.assertEqual(gate({"NETRUNE_PROGRESS": "0"}), "disabled")
        self.assertEqual(gate({"NETOPS_PROGRESS": "0"}), "disabled")

    def build_vault_fixture(self):
        """A working sudo-gated vault backed by stub sudo/gpg that log their use."""
        base = Path(self.temp.name)
        sudo_log = base / "sudo.log"
        sudo_cache = base / "sudo.cache"
        gpg_log = base / "gpg.log"
        sudo = self.bin_dir / "sudo"
        gpg = self.bin_dir / "gpg"
        sudo.write_text(
            "#!/usr/bin/env bash\n"
            "printf '<%s>' \"$@\" >> \"$SUDO_ARGUMENT_LOG\"; printf '\\n' >> \"$SUDO_ARGUMENT_LOG\"\n"
            "if [[ \"$1\" == -n && \"$2\" == -v ]]; then [[ -f \"$SUDO_CACHE_FILE\" ]]; exit; fi\n"
            "if [[ \"$1\" == -v ]]; then\n"
            "  if [[ ! -f \"$SUDO_CACHE_FILE\" ]]; then printf '<AUTH>\\n' >> \"$SUDO_ARGUMENT_LOG\"; : > \"$SUDO_CACHE_FILE\"; fi\n"
            "  exit 0\n"
            "fi\n"
            "if [[ \"$1\" != -n && ! -f \"$SUDO_CACHE_FILE\" ]]; then\n"
            "  printf '<AUTH>\\n' >> \"$SUDO_ARGUMENT_LOG\"; : > \"$SUDO_CACHE_FILE\"\n"
            "fi\n"
            "[[ \"$1\" == -n ]] && shift\n"
            "if [[ \"$1\" == /usr/bin/stat ]]; then\n"
            "  metadata=$(/usr/bin/stat -c '%a:%F' \"${@: -1}\") || exit $?\n"
            "  printf '65534:%s\\r\\n' \"$metadata\"; exit 0\n"
            "fi\n"
            "exec \"$@\"\n",
            encoding="utf-8",
        )
        gpg.write_text(
            "#!/usr/bin/env bash\n"
            "printf '<%s>' \"$@\" >> \"$GPG_ARGUMENT_LOG\"; printf '\\n' >> \"$GPG_ARGUMENT_LOG\"\n"
            "passphrase_fd=''\n"
            "args=(\"$@\")\n"
            "for ((i=0; i < ${#args[@]} - 1; i++)); do\n"
            "  [[ \"${args[$i]}\" == --passphrase-fd ]] && passphrase_fd=\"${args[$((i + 1))]}\"\n"
            "done\n"
            "[[ -n \"$passphrase_fd\" ]] || exit 13\n"
            "IFS= read -r vault_key <&\"$passphrase_fd\" || exit 14\n"
            "[[ -n \"$vault_key\" ]] || exit 15\n"
            "payload=$(cat)\n"
            "if [[ \" $* \" == *' --symmetric '* ]]; then\n"
            "  printf 'ciphertext:%s' \"$payload\"\n"
            "elif [[ \"$payload\" == ciphertext:* ]]; then\n"
            "  printf '%s' \"${payload#ciphertext:}\"\n"
            "else\n"
            "  exit 10\n"
            "fi\n",
            encoding="utf-8",
        )
        sudo.chmod(0o700)
        gpg.chmod(0o700)
        env = dict(self.env)
        env.update({
            "SUDO_ARGUMENT_LOG": str(sudo_log),
            "SUDO_CACHE_FILE": str(sudo_cache),
            "GPG_ARGUMENT_LOG": str(gpg_log),
            "NETRUNE_VAULT_SESSION_DIR": str(self.make_session_dir()),
        })
        vault = base / "vault.gpg"
        created = subprocess.run(
            ["bash", "-c", 'source ./netops-lib.sh; PASSWORD_FILE="$1"; set_password sudo-gpg', "x", str(vault)],
            cwd=ROOT, env=env, input="switch secret\nswitch secret\n",
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
        )
        self.assertEqual(created.returncode, 0, created.stderr)
        return env, vault, sudo_log, sudo_cache

    def vault_reads(self, env, vault, count, sudo_cache=None):
        """Read the vault from `count` separate processes, as a real sweep does.

        Clearing the sudo ticket before each one models what actually happens
        during a sweep: every device read is spawned into its own session with
        no controlling tty, so sudo's tty-bound ticket does not carry over.
        """
        script = 'source ./netops-lib.sh; PASSWORD_FILE="$1"; get_password_from_store || exit $?; printf "%s" "$SSHPASS"'
        results = []
        for _ in range(count):
            if sudo_cache is not None:
                sudo_cache.unlink(missing_ok=True)
            results.append(subprocess.run(
                ["bash", "-c", script, "x", str(vault)],
                cwd=ROOT, env=env, text=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
            ))
        return results

    def test_each_device_read_authenticates_when_no_vault_session_is_open(self):
        env, vault, sudo_log, sudo_cache = self.build_vault_fixture()
        sudo_log.write_text("", encoding="utf-8")
        for result in self.vault_reads(env, vault, 3, sudo_cache):
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "switch secret")
        # Three devices, three authentications. This is the behaviour reported
        # from the field: one Windows Hello prompt per switch.
        self.assertEqual(sudo_log.read_text(encoding="utf-8").count("<AUTH>"), 3)

    def test_one_vault_session_covers_every_device_read_in_a_sweep(self):
        env, vault, sudo_log, sudo_cache = self.build_vault_fixture()
        unlocked = subprocess.run(
            ["bash", "-c", 'source ./netops-lib.sh; PASSWORD_FILE="$1"; unlock_password_store 30', "x", str(vault)],
            cwd=ROOT, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
        )
        self.assertEqual(unlocked.returncode, 0, unlocked.stderr)
        self.assertIn("SSH vault unlocked until", unlocked.stderr)

        sudo_log.write_text("", encoding="utf-8")
        for result in self.vault_reads(env, vault, 5, sudo_cache):
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "switch secret")
        # The whole sweep runs without a single further authentication.
        self.assertEqual(sudo_log.read_text(encoding="utf-8").count("<AUTH>"), 0)

        locked = subprocess.run(
            ["bash", "-c", 'source ./netops-lib.sh; lock_password_store'],
            cwd=ROOT, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
        )
        self.assertEqual(locked.returncode, 0, locked.stderr)
        sudo_log.write_text("", encoding="utf-8")
        self.vault_reads(env, vault, 1, sudo_cache)
        self.assertEqual(sudo_log.read_text(encoding="utf-8").count("<AUTH>"), 1)

    def run_prompt_match(self, buffer_literal):
        """Match a buffer against the wrapper's live prompt pattern."""
        script = (
            'set source [open "netops_aruba_ssh.exp" r]\n'
            'set text [read $source]\n'
            'close $source\n'
            # Evaluate only the three pattern lines, not the whole wrapper.
            'foreach line [split $text "\\n"] {\n'
            '    if {[string match "set escape_run *" $line] '
            '|| [string match "set escape_tail *" $line] '
            '|| [string match "set prompt_pattern *" $line]} { eval $line }\n'
            '}\n'
            f'set buf {buffer_literal}\n'
            'puts [regexp -- $prompt_pattern $buf]\n'
        )
        result = subprocess.run(["tclsh", "-"], input=script, cwd=ROOT, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip() == "1"

    def test_prompt_matches_aos_s_full_screen_redraw(self):
        # Captured from an Aruba 2540 running YC.16.10: the switch redraws a
        # 24-line screen and emits partial CSI escapes such as "\x1b[?" with no
        # final byte. Requiring only complete sequences left the prompt
        # unreachable, so every command timed out with the prompt on screen.
        real = (
            r'"Your previous successful login (as manager) was on 2026-08-13\r\n'
            r' from 198.51.100.226\r\n'
            r'\x1b\[1;24r\x1b\[24;1H\x1b\[2K\x1b\[24;1H\x1b\[?\x1b\[24;1H'
            r'SITE-A-FIN-SW02# '
            r'\x1b\[24;1H\x1b\[24;24H\x1b\[?\x1b\[24;24H"'
        )
        self.assertTrue(self.run_prompt_match(real))

    def test_prompt_still_matches_plain_prompts(self):
        for label, literal in (
            ("exec", r'"\r\nSWITCH-01# "'),
            ("operator", r'"\r\nSWITCH-01> "'),
            ("config", r'"\r\nSWITCH-01(config)# "'),
            ("trailing-csi", r'"\r\nSWITCH-01# \x1b\[24;1H"'),
        ):
            with self.subTest(prompt=label):
                self.assertTrue(self.run_prompt_match(literal))

    def test_prompt_does_not_match_command_output(self):
        for label, literal in (
            # A comparison sign in output must not end a command early.
            ("comparison", r'"\r\nPort 25 cost 20000 > 4000 threshold"'),
            ("stp-row", r'"\r\n  1     100/1000T  | 20000  128  Forwarding   | d06726-f2b6a0"'),
            ("vlan-row", r'"\r\n  4       Management-of-Switch-Range       | Port-based No    No"'),
        ):
            with self.subTest(output=label):
                self.assertFalse(self.run_prompt_match(literal))

    FAKE_AOS_S_SWITCH = r'''#!/usr/bin/env python3
"""An Aruba AOS-S that will not proceed until its cursor report is answered."""
import sys, os, tty
try:
    tty.setraw(0)   # a real switch drives its PTY raw; canonical mode blocks
except Exception:
    pass
E = "\x1b"
out = sys.stdout
log = open(os.environ["FAKE_SWITCH_LOG"], "a")
out.write("Aruba JL356A 2540-24G-PoE+-4SFP+ Switch\r\nSoftware revision YC.16.10.0010\r\n\r\n")
out.write("Press any key to continue")
out.flush()
os.read(0, 1)
out.write(f"{E}[13;1H{E}[?{E}[24;27H{E}[?6l{E}[1;24r{E}[?7h{E}[2J{E}[1;1H")
out.write(f"{E}[1920;1920H{E}[6n")
out.flush()
log.write("waiting for cursor report\n"); log.flush()
reply = ""
while not reply.endswith("R"):
    ch = os.read(0, 1).decode("latin-1")
    if not ch:
        log.write("stdin closed while waiting\n"); log.flush()
        sys.exit(1)
    reply += ch
log.write(f"got cursor report {reply!r}\n"); log.flush()
out.write(f"{E}[1;1HYour previous successful login (as manager) was on 2026-08-13\r\n from 198.51.100.1\r\n")
out.write(f"{E}[1;24r{E}[24;1H{E}[2K{E}[24;1H{E}[?{E}[24;1HSITE-A-FIN-SW02# {E}[24;24H{E}[?{E}[24;24H")
out.flush()

def readline_raw():
    buf = ""
    while not buf.endswith("\n") and not buf.endswith("\r"):
        c = os.read(0, 1).decode("latin-1")
        if not c:
            return ""
        buf += c
    return buf

while True:
    line = readline_raw()
    if not line:
        break
    cmd = line.strip()
    if cmd == "exit":
        break
    out.write(cmd + "\r\n")
    if cmd == "show spanning-tree":
        out.write(" Multiple Spanning Tree (MST) Information\r\n\r\n  STP Enabled   : Yes\r\n")
        out.write("  Force Version : MSTP-operation\r\n  Switch MAC Address : d06726-f2b6a0\r\n")
        out.write("  CST Root MAC Address : ccb6c8-4eed80\r\n  CST Root Port        : 25\r\n\r\n")
        out.write("  Port  Type       | Cost      rity State        | Bridge            Time PtP Edge\r\n")
        out.write("  1     100/1000T  | 20000     128  Forwarding   | d06726-f2b6a0     2    Yes Yes\r\n")
        out.write(f"{E}[?  25    1000LX     | 20000     128  Forwarding   | 94f128-2daa00     2    Yes No\r\n")
    out.write(f"{E}[24;1H{E}[?{E}[24;1HSITE-A-FIN-SW02# {E}[24;24H")
    out.flush()
'''

    def test_wrapper_survives_aos_s_full_screen_login(self):
        """End to end against a switch that behaves like a real 2540 on YC.16.10.

        The screen redraw emits partial CSI escapes around the prompt. Before
        this was handled, every command timed out at 60s with the prompt
        plainly visible in the buffer, and no spanning-tree output was ever
        collected from any Aruba switch.
        """
        if not shutil.which("expect"):
            self.skipTest("expect is not installed")
        fake = self.bin_dir / "sshpass"
        fake.write_text(self.FAKE_AOS_S_SWITCH, encoding="utf-8")
        fake.chmod(0o700)
        env = dict(self.env)
        log_path = Path(self.temp.name) / "fake-switch.log"
        env.update({"SSHPASS": "x", "CREDS_ssh_user": "admin",
                    "NETOPS_SSH_COMMAND_TIMEOUT": "8", "FAKE_SWITCH_LOG": str(log_path)})
        result = subprocess.run(
            [str(ROOT / "netops_aruba_ssh.exp"), "198.51.100.1"],
            cwd=ROOT, env=env, input="no page\nshow spanning-tree\n",
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60,
        )
        self.assertEqual(result.returncode, 0, f"stderr: {result.stderr}")
        self.assertIn("Multiple Spanning Tree", result.stdout)
        self.assertIn("d06726-f2b6a0", result.stdout)
        # The row preceded by a partial escape must survive cleaning intact.
        self.assertIn("25    1000LX", result.stdout)
        # No escape debris may leak into the text the parser receives.
        self.assertNotIn("\x1b", result.stdout)
        self.assertNotIn("[?", result.stdout)

    def test_command_markers_split_one_session_into_per_command_output(self):
        """Markers are what let several commands share a single login."""
        if not shutil.which("expect"):
            self.skipTest("expect is not installed")
        fake = self.bin_dir / "sshpass"
        fake.write_text(self.FAKE_AOS_S_SWITCH, encoding="utf-8")
        fake.chmod(0o700)
        log_path = Path(self.temp.name) / "fake-switch.log"
        env = dict(self.env)
        env.update({"SSHPASS": "x", "CREDS_ssh_user": "admin", "NETOPS_SSH_COMMAND_TIMEOUT": "8",
                    "FAKE_SWITCH_LOG": str(log_path), "NETOPS_CMD_MARKERS": "1"})
        result = subprocess.run(
            [str(ROOT / "netops_aruba_ssh.exp"), "198.51.100.1"],
            cwd=ROOT, env=env, input="no page\nshow spanning-tree\n",
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("###NETRUNE-CMD 1###", result.stdout)
        self.assertIn("###NETRUNE-CMD 2###", result.stdout)
        # The second command's output must land after the second marker.
        _, _, after = result.stdout.partition("###NETRUNE-CMD 2###")
        self.assertIn("Multiple Spanning Tree", after)

    def test_wrapper_reports_cleanly_when_the_session_yields_nothing(self):
        """A failure handler must not itself fail."""
        if not shutil.which("expect"):
            self.skipTest("expect is not installed")
        silent = self.bin_dir / "sshpass"
        silent.write_text("#!/usr/bin/env bash\nexec sleep 30\n", encoding="utf-8")
        silent.chmod(0o700)
        env = dict(self.env)
        env.update({"SSHPASS": "x", "CREDS_ssh_user": "admin", "NETOPS_SSH_COMMAND_TIMEOUT": "2"})
        result = subprocess.run(
            [str(ROOT / "netops_aruba_ssh.exp"), "198.51.100.1", "show version"],
            cwd=ROOT, env=env, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=40,
        )
        # Previously expect_out(buffer) was unset here and the handler raised a
        # Tcl error instead of saying what happened.
        self.assertNotIn("can't read", result.stderr)
        self.assertIn("Timeout", result.stderr)
        self.assertIn("saw 0 chars", result.stderr)

    def test_aos_s_screen_mode_output_reaches_the_parser(self):
        """The bytes the wrapper emits must parse into real spanning-tree facts."""
        if not shutil.which("expect"):
            self.skipTest("expect is not installed")
        fake = self.bin_dir / "sshpass"
        fake.write_text(self.FAKE_AOS_S_SWITCH, encoding="utf-8")
        fake.chmod(0o700)
        env = dict(self.env)
        log_path = Path(self.temp.name) / "fake-switch.log"
        env.update({"SSHPASS": "x", "CREDS_ssh_user": "admin",
                    "NETOPS_SSH_COMMAND_TIMEOUT": "8", "FAKE_SWITCH_LOG": str(log_path)})
        result = subprocess.run(
            [str(ROOT / "netops_aruba_ssh.exp"), "198.51.100.1"],
            cwd=ROOT, env=env, input="no page\nshow spanning-tree\n",
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60,
        )
        sys.path.insert(0, str(ROOT))
        from netops_platform.network import parse_spanning_tree_output

        parsed = parse_spanning_tree_output(result.stdout)
        self.assertTrue(parsed["parsed"], result.stdout)
        self.assertEqual(parsed["mode"], "mstp")
        self.assertEqual(parsed["switch_mac"], "d06726f2b6a0")
        self.assertEqual(parsed["root_port"], "25")
        self.assertEqual([row["port"] for row in parsed["ports"]], ["1", "25"])
        self.assertEqual([row["port"] for row in parsed["ports"] if row["network_facing"]], ["25"])

    def test_closed_tcp_probe_is_not_mislabeled_as_timeout(self):
        result = self.run_helper("netops-probe", "127.0.0.1", "--port", "65000", "--count", "1")
        output = result.stdout + result.stderr
        self.assertEqual(result.returncode, 4)
        self.assertIn("CLOSED", output)
        self.assertIn("1 sent, 0 recv", output)
        self.assertNotIn("TIMEOUT", output)

    def test_legacy_launcher_reports_central_version(self):
        result = self.run_helper("netops-legacy", "--version")
        expected = (ROOT / "VERSION").read_text(encoding="ascii").strip()
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), f"Netrune {expected}")

    def test_canonical_helper_launchers_preserve_legacy_environment_compatibility(self):
        environment = dict(self.env)
        environment["NETRUNE_CONFIG_DIR"] = environment.pop("NETOPS_CONFIG_DIR")
        environment["NETRUNE_CACHE_DIR"] = environment.pop("NETOPS_CACHE_DIR")
        result = subprocess.run(
            [str(ROOT / "netrune-control"), "show", "--help"],
            cwd=ROOT,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Usage:", result.stdout)

    def test_every_control_helper_mode_has_working_command_help(self):
        modes = (
            "shell", "backup", "backup-history", "diff", "inventory", "propagated",
            "locate-vlan", "show", "core-lookup", "mac-lookup", "config", "vlan",
        )
        for mode in modes:
            with self.subTest(mode=mode):
                result = self.run_helper("netops-control", mode, "--help")
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("Usage:", result.stdout)

    def test_interrupted_probe_skips_route_and_ssh_followups_and_cleans_state(self):
        before = set(glob.glob("/tmp/netops-probe.*"))
        proc = subprocess.Popen(
            [str(ROOT / "netops-probe"), "127.0.0.1", "--port", "65000"],
            cwd=ROOT,
            env=self.env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        try:
            time.sleep(0.35)
            os.killpg(proc.pid, signal.SIGINT)
            stdout, stderr = proc.communicate(timeout=5)
        finally:
            if proc.poll() is None:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait(timeout=5)
        output = stdout + stderr
        self.assertEqual(proc.returncode, 130)
        self.assertIn("Stats for 127.0.0.1", output)
        self.assertNotIn("Routing path", output)
        self.assertNotIn("SSH is open", output)
        self.assertEqual(set(glob.glob("/tmp/netops-probe.*")) - before, set())

    def test_direct_probe_termination_reaps_ping_descendant(self):
        ping = self.bin_dir / "ping"
        ping_child_file = Path(self.temp.name) / "probe-ping-child.pid"
        ping.write_text(
            "#!/usr/bin/env bash\n"
            "sleep 30 &\n"
            "child=$!\n"
            "printf '%s' \"$child\" > \"$PROBE_PING_CHILD_FILE\"\n"
            "wait \"$child\"\n",
            encoding="utf-8",
        )
        ping.chmod(0o700)
        env = dict(self.env)
        env["PROBE_PING_CHILD_FILE"] = str(ping_child_file)
        before = set(glob.glob("/tmp/netops-probe.*"))
        proc = subprocess.Popen(
            [str(ROOT / "netops-probe"), "127.0.0.1", "--count", "20"],
            cwd=ROOT, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True,
        )
        child_pid = None
        try:
            deadline = time.monotonic() + 4
            while time.monotonic() < deadline and not ping_child_file.exists():
                time.sleep(0.05)
            self.assertTrue(ping_child_file.exists(), "ping fixture did not start")
            child_pid = int(ping_child_file.read_text(encoding="utf-8"))
            os.kill(proc.pid, signal.SIGTERM)
            proc.communicate(timeout=5)
            self.assertEqual(proc.returncode, 143)
            with self.assertRaises(ProcessLookupError):
                os.kill(child_pid, 0)
            self.assertEqual(set(glob.glob("/tmp/netops-probe.*")) - before, set())
        finally:
            if proc.poll() is None:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait(timeout=5)
            if child_pid is not None:
                try:
                    os.kill(child_pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def test_control_editor_path_has_no_top_level_local_runtime_error(self):
        env = dict(self.env)
        env["EDITOR"] = "true"
        result = subprocess.run(
            [str(ROOT / "netops-control"), "config", "127.0.0.1", "--dry-run"],
            cwd=ROOT,
            env=env,
            input="",
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("local: can only be used in a function", result.stderr)
        self.assertIn("Dry run: config", result.stdout)

    def test_connect_interrupt_removes_private_error_state(self):
        gpg = self.bin_dir / "gpg"
        sshpass = self.bin_dir / "sshpass"
        gpg.write_text("#!/usr/bin/env bash\nprintf 'fixture-password'\n", encoding="utf-8")
        sshpass.write_text("#!/usr/bin/env bash\nsleep 30\n", encoding="utf-8")
        gpg.chmod(0o700)
        sshpass.chmod(0o700)
        env = dict(self.env)
        env["PATH"] = f"{self.bin_dir}:{env.get('PATH', '')}"
        before = set(glob.glob("/tmp/netops-connect.*"))
        proc = subprocess.Popen(
            [str(ROOT / "netops-connect"), "127.0.0.1"],
            cwd=ROOT,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        try:
            time.sleep(0.3)
            os.killpg(proc.pid, signal.SIGINT)
            proc.communicate(timeout=5)
        finally:
            if proc.poll() is None:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait(timeout=5)
        self.assertEqual(proc.returncode, 130)
        self.assertEqual(set(glob.glob("/tmp/netops-connect.*")) - before, set())

    def test_connect_requires_ssh_username_before_vault_or_transport(self):
        (self.config_dir / ".env").write_text("", encoding="utf-8")
        sshpass_marker = Path(self.temp.name) / "sshpass-invoked"
        gpg_marker = Path(self.temp.name) / "gpg-invoked"
        sshpass = self.bin_dir / "sshpass"
        gpg = self.bin_dir / "gpg"
        sshpass.write_text("#!/usr/bin/env bash\nprintf invoked > \"$SSHPASS_MARKER\"\n", encoding="utf-8")
        gpg.write_text("#!/usr/bin/env bash\nprintf invoked > \"$GPG_MARKER\"\n", encoding="utf-8")
        sshpass.chmod(0o700)
        gpg.chmod(0o700)
        env = dict(self.env)
        env.update({"SSHPASS_MARKER": str(sshpass_marker), "GPG_MARKER": str(gpg_marker)})
        result = subprocess.run(
            [str(ROOT / "netops-connect"), "127.0.0.1"], cwd=ROOT, env=env,
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5,
        )
        self.assertEqual(result.returncode, 6, result.stdout + result.stderr)
        self.assertIn("netrune config set ssh_user <username>", result.stderr)
        self.assertFalse(sshpass_marker.exists())
        self.assertFalse(gpg_marker.exists())

    def test_connect_names_a_silent_sshpass_password_rejection(self):
        # sshpass exits 5 on a second password prompt without writing to
        # stderr, so only the exit code can tell this apart from a hang-up.
        gpg = self.bin_dir / "gpg"
        sshpass = self.bin_dir / "sshpass"
        gpg.write_text("#!/usr/bin/env bash\nprintf 'fixture-password'\n", encoding="utf-8")
        sshpass.write_text("#!/usr/bin/env bash\nexit 5\n", encoding="utf-8")
        gpg.chmod(0o700)
        sshpass.chmod(0o700)
        result = subprocess.run(
            [str(ROOT / "netops-connect"), "127.0.0.1"], cwd=ROOT, env=self.env,
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5,
        )
        self.assertEqual(result.returncode, 5, result.stdout + result.stderr)
        self.assertIn("SSH authentication was rejected by 127.0.0.1 (127.0.0.1)", result.stdout)
        self.assertIn("connect -p", result.stdout)
        self.assertNotIn("ended with exit code", result.stdout)

    def test_connect_builds_valid_explicit_ssh_login_arguments(self):
        argument_log = Path(self.temp.name) / "connect-ssh-arguments.log"
        gpg = self.bin_dir / "gpg"
        sshpass = self.bin_dir / "sshpass"
        gpg.write_text("#!/usr/bin/env bash\nprintf 'fixture-password'\n", encoding="utf-8")
        sshpass.write_text(
            "#!/usr/bin/env bash\n"
            "printf '<%s>\\n' \"$@\" > \"$SSH_ARGUMENT_LOG\"\n",
            encoding="utf-8",
        )
        gpg.chmod(0o700)
        sshpass.chmod(0o700)
        env = dict(self.env)
        env["SSH_ARGUMENT_LOG"] = str(argument_log)
        result = subprocess.run(
            [str(ROOT / "netops-connect"), "127.0.0.1"], cwd=ROOT, env=env,
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        arguments = argument_log.read_text(encoding="utf-8").splitlines()
        self.assertIn("<-l>", arguments)
        self.assertIn("<admin>", arguments)
        self.assertIn("<127.0.0.1>", arguments)
        self.assertNotIn("<admin@127.0.0.1>", arguments)

    def test_public_device_ssh_route_reaches_valid_transport_arguments(self):
        argument_log = Path(self.temp.name) / "public-ssh-arguments.log"
        gpg = self.bin_dir / "gpg"
        sshpass = self.bin_dir / "sshpass"
        gpg.write_text("#!/usr/bin/env bash\nprintf 'fixture-password'\n", encoding="utf-8")
        sshpass.write_text(
            "#!/usr/bin/env bash\n"
            "printf '<%s>\\n' \"$@\" > \"$SSH_ARGUMENT_LOG\"\n",
            encoding="utf-8",
        )
        gpg.chmod(0o700)
        sshpass.chmod(0o700)
        env = dict(self.env)
        env["SSH_ARGUMENT_LOG"] = str(argument_log)
        result = subprocess.run(
            [str(ROOT / "netops"), "device", "ssh", "127.0.0.1"], cwd=ROOT, env=env,
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("usage:", (result.stdout + result.stderr).lower())
        arguments = argument_log.read_text(encoding="utf-8").splitlines()
        self.assertIn("<-l>", arguments)
        self.assertIn("<admin>", arguments)
        self.assertIn("<127.0.0.1>", arguments)

    def test_public_speed_profile_reaches_the_speed_backend_unchanged(self):
        result = subprocess.run(
            [str(ROOT / "netops"), "diagnose", "speed", "--profile", "quick", "--runs", "1", "--dry-run", "--plain"],
            cwd=ROOT, env=self.env, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("--profile quick --speed-runs 1", result.stdout)
        self.assertNotIn("--profile balanced", result.stdout)

    def test_shell_config_save_preserves_public_ssh_username(self):
        result = subprocess.run(
            [
                "bash", "-c",
                'source "$1"; CONFIG[ssh_user]="operator"; save_config',
                "netops-config-save-test", str(ROOT / "netops-lib.sh"),
            ],
            cwd=ROOT, env=self.env, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        saved = (self.config_dir / "netsnmp.conf").read_text(encoding="utf-8")
        self.assertIn('ssh_user="operator"', saved)

    def test_direct_connect_termination_reaps_ssh_descendant(self):
        gpg = self.bin_dir / "gpg"
        sshpass = self.bin_dir / "sshpass"
        ssh_pid_file = Path(self.temp.name) / "connect-ssh.pid"
        gpg.write_text("#!/usr/bin/env bash\nprintf 'fixture-password'\n", encoding="utf-8")
        sshpass.write_text(
            "#!/usr/bin/env bash\n"
            "printf '%s' \"$$\" > \"$CONNECT_SSH_PID_FILE\"\n"
            "exec sleep 30\n",
            encoding="utf-8",
        )
        gpg.chmod(0o700)
        sshpass.chmod(0o700)
        env = dict(self.env)
        env["CONNECT_SSH_PID_FILE"] = str(ssh_pid_file)
        before = set(glob.glob("/tmp/netops-connect.*"))
        proc = subprocess.Popen(
            [str(ROOT / "netops-connect"), "127.0.0.1"],
            cwd=ROOT,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        child_pid = None
        try:
            deadline = time.monotonic() + 4
            while time.monotonic() < deadline and not ssh_pid_file.exists():
                time.sleep(0.05)
            self.assertTrue(ssh_pid_file.exists(), "SSH fixture did not start")
            child_pid = int(ssh_pid_file.read_text(encoding="utf-8"))
            os.kill(proc.pid, signal.SIGTERM)
            proc.communicate(timeout=5)
            self.assertEqual(proc.returncode, 143)
            with self.assertRaises(ProcessLookupError):
                os.kill(child_pid, 0)
            self.assertEqual(set(glob.glob("/tmp/netops-connect.*")) - before, set())
        finally:
            if proc.poll() is None:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait(timeout=5)
            if child_pid is not None:
                try:
                    os.kill(child_pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def test_prompt_aware_ssh_waits_for_a_complete_prompt_line(self):
        sshpass = self.bin_dir / "sshpass"
        argument_log = Path(self.temp.name) / "prompted-ssh-arguments.log"
        sshpass.write_text(
            """#!/usr/bin/env bash
printf '<%s>' "$@" >> "$SSH_ARGUMENT_LOG"
printf '\n' >> "$SSH_ARGUMENT_LOG"
printf '\033[24;1HFIXTURE-SW# \033[24;12H'
while IFS= read -r line; do
    line=${line%$'\\r'}
    case "$line" in
        'show comparison')
            printf '\\r\\nshow comparison\\r\\nvalue > threshold\\r\\nresult complete\\r\\n\\033[24;1HFIXTURE-SW# \\033[24;12H'
            ;;
        exit) exit 0 ;;
        *) printf '\\r\\nunknown command\\r\\n\\033[24;1HFIXTURE-SW# \\033[24;12H' ;;
    esac
done
""",
            encoding="utf-8",
        )
        sshpass.chmod(0o700)
        env = dict(self.env)
        env.update({
            "CREDS_ssh_user": "admin",
            "SSHPASS": "fixture",
            "SSH_ARGUMENT_LOG": str(argument_log),
            "NETOPS_SSH_KEX_ALGORITHMS": "diffie-hellman-group14-sha1",
            "NETOPS_SSH_HOST_KEY_ALGORITHMS": "ssh-rsa",
            "NETOPS_SSH_CIPHERS": "aes128-cbc",
            "NETOPS_SSH_MACS": "hmac-sha1",
        })
        result = subprocess.run(
            [str(ROOT / "netops_aruba_ssh.exp"), "192.0.2.1", "show comparison"],
            cwd=ROOT,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("value > threshold", result.stdout)
        self.assertIn("result complete", result.stdout)
        self.assertNotIn("FIXTURE-SW#", result.stdout)
        arguments = argument_log.read_text(encoding="utf-8")
        self.assertIn("<KexAlgorithms=+diffie-hellman-group14-sha1>", arguments)
        self.assertIn("<HostKeyAlgorithms=+ssh-rsa>", arguments)
        self.assertIn("<Ciphers=+aes128-cbc>", arguments)
        self.assertIn("<MACs=+hmac-sha1>", arguments)

    def test_prompt_aware_ssh_reports_early_eof_and_kills_timed_out_child(self):
        sshpass = self.bin_dir / "sshpass"
        sshpass.write_text("#!/usr/bin/env bash\nprintf 'authentication failed\\n' >&2\nexit 7\n", encoding="utf-8")
        sshpass.chmod(0o700)
        env = dict(self.env)
        env.update({"CREDS_ssh_user": "admin", "SSHPASS": "fixture"})
        early_eof = subprocess.run(
            [str(ROOT / "netops_aruba_ssh.exp"), "192.0.2.1", "show version"],
            cwd=ROOT,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
        )
        self.assertEqual(early_eof.returncode, 7)
        self.assertIn("before the initial device prompt", early_eof.stderr)

        pid_file = Path(self.temp.name) / "timed-out-ssh.pid"
        sshpass.write_text(
            """#!/usr/bin/env bash
printf 'FIXTURE-SW# '
IFS= read -r line
printf '%s' "$$" > "$SSH_FIXTURE_PID_FILE"
exec sleep 30
""",
            encoding="utf-8",
        )
        sshpass.chmod(0o700)
        env.update({"NETOPS_SSH_COMMAND_TIMEOUT": "1", "SSH_FIXTURE_PID_FILE": str(pid_file)})
        timed_out = subprocess.run(
            [str(ROOT / "netops_aruba_ssh.exp"), "192.0.2.1", "show slow"],
            cwd=ROOT,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
        )
        self.assertEqual(timed_out.returncode, 9, timed_out.stderr)
        self.assertIn("command 1", timed_out.stderr)
        child_pid = int(pid_file.read_text(encoding="utf-8"))
        with self.assertRaises(ProcessLookupError):
            os.kill(child_pid, 0)

    def test_target_resolution_rejects_invalid_ip_and_emits_ranges_one_per_line(self):
        script = "source ./netops-lib.sh; resolve_targets \"$1\" DEVICES true"
        invalid = subprocess.run(
            ["bash", "-c", script, "resolve", "999.1.1.1"],
            cwd=ROOT,
            env=self.env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
        )
        valid_range = subprocess.run(
            ["bash", "-c", script, "resolve", "198.51.100.3-5"],
            cwd=ROOT,
            env=self.env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
        )
        self.assertEqual(invalid.returncode, 1)
        self.assertIn("Invalid IPv4 target", invalid.stderr)
        self.assertEqual(valid_range.returncode, 0)
        self.assertEqual(valid_range.stdout.splitlines(), ["198.51.100.3", "198.51.100.4", "198.51.100.5"])

    def test_missing_local_vault_returns_to_sourced_caller(self):
        missing = Path(self.temp.name) / "missing-vault.gpg"
        script = 'source ./netops-lib.sh; PASSWORD_FILE="$1"; get_password_from_store; rc=$?; printf "after:%s\\n" "$rc"; exit 0'
        result = subprocess.run(
            ["bash", "-c", script, "vault-return", str(missing)],
            cwd=ROOT, env=self.env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5,
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), "after:1")
        self.assertIn("SSH password not found", result.stderr)

    def test_local_vault_update_is_private_atomic_and_preserves_previous_value_on_failure(self):
        vault = Path(self.temp.name) / "vault" / "sshpass.gpg"
        gpg = self.bin_dir / "gpg"
        gpg.write_text(
            "#!/usr/bin/env bash\n"
            "output=''\n"
            "while (($#)); do\n"
            "  if [[ \"$1\" == '-o' ]]; then output=$2; shift 2; else shift; fi\n"
            "done\n"
            "payload=$(cat)\n"
            "printf 'ciphertext:%s' \"$payload\" > \"$output\"\n"
            "[[ \"${GPG_FIXTURE_FAIL:-false}\" == true ]] && exit 9\n"
            "exit 0\n",
            encoding="utf-8",
        )
        gpg.chmod(0o700)
        script = 'source ./netops-lib.sh; PASSWORD_FILE="$1"; set_password legacy-gpg'

        success = subprocess.run(
            ["bash", "-c", script, "vault-set", str(vault)],
            cwd=ROOT, env=self.env, input="new secret\nnew secret\nvault phrase\nvault phrase\n", text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5,
        )
        self.assertEqual(success.returncode, 0, success.stderr)
        self.assertEqual(vault.read_text(encoding="utf-8"), "ciphertext:new secret")
        self.assertEqual(vault.stat().st_mode & 0o777, 0o600)

        failed_env = dict(self.env)
        failed_env["GPG_FIXTURE_FAIL"] = "true"
        failed = subprocess.run(
            ["bash", "-c", script, "vault-set", str(vault)],
            cwd=ROOT, env=failed_env, input="replacement\nreplacement\nvault phrase\nvault phrase\n", text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5,
        )
        self.assertEqual(failed.returncode, 1)
        self.assertEqual(vault.read_text(encoding="utf-8"), "ciphertext:new secret")
        self.assertEqual(list(vault.parent.glob(".netops-vault.*")), [])

    def test_sudo_gated_vault_uses_cached_terminal_auth_and_never_pinentry(self):
        vault = Path(self.temp.name) / "sudo-vault" / "sshpass.gpg"
        sudo_log = Path(self.temp.name) / "sudo-arguments.log"
        gpg_log = Path(self.temp.name) / "gpg-arguments.log"
        sudo_cache = Path(self.temp.name) / "sudo-cache"
        sudo = self.bin_dir / "sudo"
        gpg = self.bin_dir / "gpg"
        sudo.write_text(
            "#!/usr/bin/env bash\n"
            "printf '<%s>' \"$@\" >> \"$SUDO_ARGUMENT_LOG\"; printf '\\n' >> \"$SUDO_ARGUMENT_LOG\"\n"
            "if [[ \"$1\" == -n && \"$2\" == -v ]]; then [[ -f \"$SUDO_CACHE_FILE\" ]]; exit; fi\n"
            "if [[ \"$1\" == -v ]]; then\n"
            "  if [[ ! -f \"$SUDO_CACHE_FILE\" ]]; then printf '<AUTH>\\n' >> \"$SUDO_ARGUMENT_LOG\"; sleep \"${SUDO_AUTH_DELAY:-0}\"; : > \"$SUDO_CACHE_FILE\"; fi\n"
            "  exit 0\n"
            "fi\n"
            "if [[ \"$1\" != -n && ! -f \"$SUDO_CACHE_FILE\" ]]; then\n"
            "  printf '<AUTH>\\n' >> \"$SUDO_ARGUMENT_LOG\"; sleep \"${SUDO_AUTH_DELAY:-0}\"; : > \"$SUDO_CACHE_FILE\"\n"
            "fi\n"
            "[[ \"${SUDO_FAIL_CAT:-false}\" == true && (\"$1\" == /bin/sh || \"$2\" == /bin/sh) ]] && exit 12\n"
            "[[ \"$1\" == -n ]] && shift\n"
            "if [[ \"$1\" == /usr/bin/stat ]]; then\n"
            "  metadata=$(/usr/bin/stat -c '%a:%F' \"${@: -1}\") || exit $?\n"
            "  printf '65534:%s\\r\\n' \"$metadata\"; exit 0\n"
            "fi\n"
            "exec \"$@\"\n",
            encoding="utf-8",
        )
        gpg.write_text(
            "#!/usr/bin/env bash\n"
            "printf '<%s>' \"$@\" >> \"$GPG_ARGUMENT_LOG\"; printf '\\n' >> \"$GPG_ARGUMENT_LOG\"\n"
            "passphrase_fd=''\n"
            "args=(\"$@\")\n"
            "for ((i=0; i < ${#args[@]} - 1; i++)); do\n"
            "  [[ \"${args[$i]}\" == --passphrase-fd ]] && passphrase_fd=\"${args[$((i + 1))]}\"\n"
            "done\n"
            "[[ -n \"$passphrase_fd\" ]] || exit 13\n"
            "IFS= read -r vault_key <&\"$passphrase_fd\" || exit 14\n"
            "[[ -n \"$vault_key\" ]] || exit 15\n"
            "payload=$(cat)\n"
            "if [[ \" $* \" == *' --symmetric '* ]]; then\n"
            "  [[ \"${GPG_FIXTURE_FAIL:-false}\" == true ]] && exit 9\n"
            "  printf 'ciphertext:%s' \"$payload\"\n"
            "elif [[ \"$payload\" == ciphertext:* ]]; then\n"
            "  printf '%s' \"${payload#ciphertext:}\"\n"
            "else\n"
            "  exit 10\n"
            "fi\n",
            encoding="utf-8",
        )
        sudo.chmod(0o700)
        gpg.chmod(0o700)
        env = dict(self.env)
        env.update(
            {
                "SUDO_ARGUMENT_LOG": str(sudo_log),
                "SUDO_CACHE_FILE": str(sudo_cache),
                "GPG_ARGUMENT_LOG": str(gpg_log),
            }
        )
        set_script = 'source ./netops-lib.sh; PASSWORD_FILE="$1"; set_password sudo-gpg'
        created = subprocess.run(
            ["bash", "-c", set_script, "vault-set", str(vault)],
            cwd=ROOT,
            env=env,
            input="new secret\nnew secret\n",
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
        )
        self.assertEqual(created.returncode, 0, created.stderr)
        secret_store = self.cache_dir / "secrets.gpg"
        self.assertTrue(secret_store.read_bytes().startswith(b"NETOPS-NAMED-SECRETS-GPG-V1\nciphertext:"))
        self.assertNotIn(b"new secret", secret_store.read_bytes())
        self.assertEqual(secret_store.stat().st_mode & 0o777, 0o600)
        root_key = Path(env["NETOPS_SUDO_VAULT_KEY_DIR"]) / f"{os.getuid()}.key"
        self.assertTrue(root_key.is_file())
        self.assertEqual(root_key.stat().st_mode & 0o777, 0o600)
        self.assertIn("Unlocking the Netrune SSH vault with", created.stderr)
        gpg_arguments = gpg_log.read_text(encoding="utf-8")
        self.assertIn("<--pinentry-mode><loopback>", gpg_arguments)
        self.assertIn("<--passphrase-fd>", gpg_arguments)
        self.assertIn("<--no-symkey-cache>", gpg_arguments)
        self.assertNotIn("pinentry.exe", gpg_arguments)
        sudo_arguments = sudo_log.read_text(encoding="utf-8")
        self.assertIn("<-v>", sudo_arguments)
        self.assertNotIn("<-S>", sudo_arguments)

        read_script = 'source ./netops-lib.sh; PASSWORD_FILE="$1"; get_password_from_store || exit $?; printf "<%s>" "$SSHPASS"'
        opened = subprocess.run(
            ["bash", "-c", read_script, "vault-open", str(vault)],
            cwd=ROOT,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
        )
        self.assertEqual(opened.returncode, 0, opened.stderr)
        self.assertEqual(opened.stdout, "<new secret>")
        self.assertNotIn("Unlocking", opened.stderr)

        sudo_cache.unlink()
        concurrent_env = dict(env)
        concurrent_env["SUDO_AUTH_DELAY"] = "0.2"
        prompts_before = sudo_log.read_text(encoding="utf-8").splitlines().count("<AUTH>")
        workers = [
            subprocess.Popen(
                ["bash", "-c", read_script, "vault-open", str(vault)],
                cwd=ROOT,
                env=concurrent_env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            for _ in range(2)
        ]
        worker_results = [worker.communicate(timeout=5) for worker in workers]
        self.assertEqual([worker.returncode for worker in workers], [0, 0], worker_results)
        self.assertEqual([stdout for stdout, _ in worker_results], ["<new secret>", "<new secret>"])
        prompts_after = sudo_log.read_text(encoding="utf-8").splitlines().count("<AUTH>")
        self.assertEqual(prompts_after - prompts_before, 1)

        read_failure_env = dict(env)
        read_failure_env["SUDO_FAIL_CAT"] = "true"
        blocked = subprocess.run(
            ["bash", "-c", read_script, "vault-open", str(vault)],
            cwd=ROOT,
            env=read_failure_env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
        )
        self.assertEqual(blocked.returncode, 1)
        self.assertEqual(blocked.stdout, "")
        self.assertIn("Failed to decrypt named secret ssh/default/password", blocked.stderr)

        original = secret_store.read_bytes()
        failed_env = dict(env)
        failed_env["GPG_FIXTURE_FAIL"] = "true"
        failed = subprocess.run(
            ["bash", "-c", set_script, "vault-set", str(vault)],
            cwd=ROOT,
            env=failed_env,
            input="replacement\nreplacement\n",
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
        )
        self.assertEqual(failed.returncode, 1)
        self.assertEqual(secret_store.read_bytes(), original)
        self.assertEqual(list(secret_store.parent.glob(".netops-secrets.*")), [])

        root_key.chmod(0o644)
        insecure = subprocess.run(
            ["bash", "-c", read_script, "vault-open", str(vault)],
            cwd=ROOT,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
        )
        self.assertEqual(insecure.returncode, 1)
        self.assertIn("key mode is 644, expected 400 or 600", insecure.stderr)

    def test_secret_input_uses_inherited_tty_without_a_controlling_terminal(self):
        master_fd, slave_fd = os.openpty()
        proc = None
        try:
            script = (
                "source ./netops-lib.sh; NETOPS_TEST_MODE=false; exec() { return 1; }; "
                "_read_secret_value captured 'Inherited terminal secret: ' || exit $?; "
                "printf '<%s>' \"$captured\""
            )
            proc = subprocess.Popen(
                ["bash", "-c", script],
                cwd=ROOT,
                env=self.env,
                stdin=slave_fd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
            os.close(slave_fd)
            slave_fd = -1
            os.write(master_fd, b"terminal-secret\n")
            stdout, stderr = proc.communicate(timeout=5)
        finally:
            if proc is not None and proc.poll() is None:
                proc.kill()
                proc.wait(timeout=2)
            os.close(master_fd)
            if slave_fd >= 0:
                os.close(slave_fd)
        self.assertEqual(proc.returncode, 0, stderr.decode(errors="replace"))
        self.assertIn(b"Inherited terminal secret: ", stderr)
        self.assertEqual(stdout, b"<terminal-secret>")
        self.assertNotIn(b"terminal-secret", stderr)

    def test_legacy_vault_migration_uses_loopback_once_then_sudo_gpg(self):
        vault = Path(self.temp.name) / "legacy-vault.gpg"
        vault.write_text("legacy-ciphertext", encoding="utf-8")
        sudo_cache = Path(self.temp.name) / "migration-sudo-cache"
        sudo = self.bin_dir / "sudo"
        gpg = self.bin_dir / "gpg"
        gpg_log = Path(self.temp.name) / "migration-gpg-arguments.log"
        sudo.write_text(
            "#!/usr/bin/env bash\n"
            "if [[ \"$1\" == -n && \"$2\" == -v ]]; then [[ -f \"$SUDO_CACHE_FILE\" ]]; exit; fi\n"
            "if [[ \"$1\" == -v ]]; then : > \"$SUDO_CACHE_FILE\"; exit 0; fi\n"
            "[[ \"$1\" == -n ]] && shift\n"
            "exec \"$@\"\n",
            encoding="utf-8",
        )
        gpg.write_text(
            "#!/usr/bin/env bash\n"
            "printf '<%s>' \"$@\" >> \"$GPG_ARGUMENT_LOG\"; printf '\\n' >> \"$GPG_ARGUMENT_LOG\"\n"
            "if [[ \" $* \" == *' --no-symkey-cache '* && \" $* \" == *' --symmetric '* ]]; then\n"
            "  args=(\"$@\"); passphrase_fd=''\n"
            "  for ((i=0; i < ${#args[@]} - 1; i++)); do\n"
            "    [[ \"${args[$i]}\" == --passphrase-fd ]] && passphrase_fd=\"${args[$((i + 1))]}\"\n"
            "  done\n"
            "  [[ -n \"$passphrase_fd\" ]] || exit 12\n"
            "  IFS= read -r vault_key <&\"$passphrase_fd\" || exit 13\n"
            "  [[ -n \"$vault_key\" ]] || exit 14\n"
            "  payload=$(cat); printf 'migrated:%s' \"$payload\"; exit 0\n"
            "fi\n"
            "if [[ \" $* \" == *' --passphrase-fd 0 '* ]]; then\n"
            "  passphrase=$(cat)\n"
            "  [[ \"$passphrase\" == 'old vault phrase' ]] || exit 11\n"
            "  printf 'fixture-ssh-password'; exit 0\n"
            "fi\n"
            "exit 9\n",
            encoding="utf-8",
        )
        sudo.chmod(0o700)
        gpg.chmod(0o700)
        env = dict(self.env)
        env.update(
            {
                "SUDO_CACHE_FILE": str(sudo_cache),
                "GPG_ARGUMENT_LOG": str(gpg_log),
            }
        )
        script = 'source ./netops-lib.sh; PASSWORD_FILE="$1"; migrate_password_store'
        migrated = subprocess.run(
            ["bash", "-c", script, "vault-migrate", str(vault)],
            cwd=ROOT,
            env=env,
            input="old vault phrase\n",
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
        )
        self.assertEqual(migrated.returncode, 0, migrated.stderr)
        self.assertEqual(vault.read_bytes(), b"legacy-ciphertext")
        secret_store = self.cache_dir / "secrets.gpg"
        self.assertTrue(secret_store.read_bytes().startswith(b"NETOPS-NAMED-SECRETS-GPG-V1\nmigrated:"))
        self.assertNotIn(b"fixture-ssh-password", secret_store.read_bytes())
        self.assertIn("original vault was left unchanged", migrated.stderr.lower())
        arguments = gpg_log.read_text(encoding="utf-8")
        self.assertGreaterEqual(arguments.count("<--pinentry-mode><loopback>"), 3)
        self.assertIn("<--passphrase-fd><0>", arguments)
        self.assertIn("<--no-symkey-cache>", arguments)
        self.assertGreaterEqual(arguments.count("<--passphrase-fd>"), 2)
        self.assertNotIn("pinentry.exe", arguments)

    def test_vault_lifecycle_uses_three_day_rotation_and_twenty_minute_window(self):
        vault = Path(self.temp.name) / "lifecycle.gpg"
        vault.write_text("fixture", encoding="utf-8")
        os.utime(vault, (1704067200, 1704067200))
        script = (
            'source ./netops-lib.sh; PASSWORD_FILE="$1"; '
            'for epoch in 1704283200 1704325200 1704327600; do '
            'NETOPS_VAULT_NOW_EPOCH="$epoch" _vault_credential_lifecycle; done'
        )
        result = subprocess.run(
            ["bash", "-c", script, "vault-lifecycle", str(vault)],
            cwd=ROOT,
            env=self.env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = [line.split("|") for line in result.stdout.splitlines()]
        self.assertEqual([row[0] for row in rows], ["DUE_SOON", "EXPIRY_WINDOW", "EXPIRED"])
        self.assertTrue(all(row[2] == "1704326400" for row in rows))
        self.assertTrue(all(row[3] == "1704325200" and row[4] == "1704327600" for row in rows))

    @unittest.skipUnless(shutil.which("gpg"), "GPG is required for the real vault round trip")
    def test_named_ssh_secret_round_trips_with_real_gpg(self):
        vault = Path(self.temp.name) / "real-gpg" / "sshpass.gpg"
        secrets = Path(self.temp.name) / "real-gpg" / "secrets.gpg"
        secrets_metadata = Path(self.temp.name) / "real-gpg" / "secrets.meta"
        sudo_cache = Path(self.temp.name) / "real-gpg-sudo-cache"
        gnupg_home = Path(self.temp.name) / "gnupg"
        gnupg_home.mkdir(mode=0o700)
        sudo = self.bin_dir / "sudo"
        sudo.write_text(
            "#!/usr/bin/env bash\n"
            "if [[ \"$1\" == -n && \"$2\" == -v ]]; then [[ -f \"$SUDO_CACHE_FILE\" ]]; exit; fi\n"
            "if [[ \"$1\" == -v ]]; then : > \"$SUDO_CACHE_FILE\"; exit 0; fi\n"
            "[[ \"$1\" == -n ]] && shift\n"
            "exec \"$@\"\n",
            encoding="utf-8",
        )
        sudo.chmod(0o700)
        env = dict(self.env)
        env.update({
            "SUDO_CACHE_FILE": str(sudo_cache),
            "GNUPGHOME": str(gnupg_home),
            "NETOPS_PASSWORD_FILE": str(vault),
            "NETOPS_SECRETS_FILE": str(secrets),
            "NETOPS_SECRETS_META_FILE": str(secrets_metadata),
        })
        script = (
            'source ./netops-lib.sh; '
            'set_password sudo-gpg || exit $?; '
            'get_password_from_store || exit $?; printf "<%s>" "$SSHPASS"'
        )
        result = subprocess.run(
            ["bash", "-c", script, "vault-real-gpg"],
            cwd=ROOT,
            env=env,
            input="actual roundtrip secret\nactual roundtrip secret\n",
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=20,
        )
        if result.returncode != 0 and (
            "failed to start gpg-agent" in result.stderr
            or "can't connect to the gpg-agent" in result.stderr
        ):
            self.skipTest("execution sandbox prevents the temporary GPG Agent socket")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "<actual roundtrip secret>")
        encrypted = secrets.read_bytes()
        self.assertTrue(encrypted.startswith(b"NETOPS-NAMED-SECRETS-GPG-V1\n"))
        self.assertNotIn(b"actual roundtrip secret", encrypted)
        self.assertTrue(secrets_metadata.is_file())
        self.assertEqual(secrets.stat().st_mode & 0o777, 0o600)
        self.assertFalse(vault.exists())

    def test_snmpv3_credentials_with_spaces_remain_single_arguments(self):
        argument_log = Path(self.temp.name) / "snmp-arguments.log"
        snmpget = self.bin_dir / "snmpget"
        snmpget.write_text(
            "#!/usr/bin/env bash\n"
            "printf '<%s>\\n' \"$@\" > \"$SNMP_ARGUMENT_LOG\"\n"
            "printf 'fixture-system-name\\n'\n",
            encoding="utf-8",
        )
        snmpget.chmod(0o700)
        env = dict(self.env)
        env["SNMP_ARGUMENT_LOG"] = str(argument_log)
        script = (
            "source ./netops-lib.sh; "
            "CREDS[snmp_version]=v3; CREDS[snmpv3_user]='ops user'; "
            "CREDS[snmpv3_auth_pass]='auth phrase'; CREDS[snmpv3_priv_pass]='privacy phrase'; "
            "netops_snmp_get 192.0.2.1 sysName.0"
        )
        result = subprocess.run(
            ["bash", "-c", script], cwd=ROOT, env=env, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "fixture-system-name")
        arguments = argument_log.read_text(encoding="utf-8").splitlines()
        self.assertIn("<ops user>", arguments)
        self.assertIn("<auth phrase>", arguments)
        self.assertIn("<privacy phrase>", arguments)

    def test_remote_vault_sync_is_disabled_without_invoking_curl(self):
        marker = Path(self.temp.name) / "curl-invoked"
        curl = self.bin_dir / "curl"
        curl.write_text("#!/usr/bin/env bash\nprintf invoked > \"$CURL_MARKER\"\n", encoding="utf-8")
        curl.chmod(0o700)
        env = dict(self.env)
        env["CURL_MARKER"] = str(marker)
        result = subprocess.run(
            ["bash", "-c", "source ./netops-lib.sh; sync_password_from_gist"],
            cwd=ROOT, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("remote SSH vault sync is disabled", result.stderr)
        self.assertFalse(marker.exists())

    def test_ssh_uses_managed_known_hosts_and_rejects_unapproved_break_glass(self):
        command = 'source ./netops-lib.sh; declare -a opts; _build_ssh_opts opts || exit $?; printf "%s\\n" "${opts[@]}"'
        managed = subprocess.run(
            ["bash", "-c", command], cwd=ROOT, env=self.env, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5,
        )
        self.assertEqual(managed.returncode, 0, managed.stderr)
        self.assertIn("StrictHostKeyChecking=accept-new", managed.stdout)
        self.assertIn(f"UserKnownHostsFile={self.config_dir / 'known_hosts'}", managed.stdout)
        self.assertEqual(stat.S_IMODE((self.config_dir / "known_hosts").stat().st_mode), 0o600)

        blocked_env = dict(self.env)
        blocked_env["NETOPS_SSH_HOST_KEY_MODE"] = "break-glass"
        blocked = subprocess.run(
            ["bash", "-c", command], cwd=ROOT, env=blocked_env, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5,
        )
        self.assertEqual(blocked.returncode, 8)
        self.assertIn("NETOPS_SSH_BREAK_GLASS=true", blocked.stderr)

    def test_device_families_and_legacy_ssh_algorithms_are_selected_explicitly(self):
        ssh = self.bin_dir / "ssh"
        ssh.write_text(
            "#!/usr/bin/env bash\n"
            "if [[ \"$1\" == -Q ]]; then\n"
            "  case \"$2\" in\n"
            "    kex) printf 'diffie-hellman-group14-sha1\\n' ;;\n"
            "    key) printf 'ssh-rsa\\n' ;;\n"
            "    cipher) printf 'aes128-cbc\\n' ;;\n"
            "    mac) printf 'hmac-sha1\\n' ;;\n"
            "  esac\n"
            "fi\n",
            encoding="utf-8",
        )
        ssh.chmod(0o700)
        script = """
source ./netops-lib.sh
printf 'families=%s,%s,%s,%s,%s,%s\n' \
  "$(netops_platform_family 'Cisco IOS XE C9300')" \
  "$(netops_platform_family 'Aruba 2930F ProCurve')" \
  "$(netops_platform_family 'ArubaOS-CX 10.13 CX 6300')" \
  "$(netops_platform_family 'Ruckus ICX7150 FastIron 08.0.95')" \
  "$(netops_platform_family 'Ruckus SmartZone vSZ')" \
  "$(netops_platform_family 'Ruckus AP R750')"
CONFIG[legacy_ssh]=true
declare -a opts
_build_ssh_opts opts || exit $?
printf 'opts=%s\n' "${opts[*]}"
printf 'exports=%s|%s|%s|%s\n' "$NETOPS_SSH_KEX_ALGORITHMS" "$NETOPS_SSH_HOST_KEY_ALGORITHMS" "$NETOPS_SSH_CIPHERS" "$NETOPS_SSH_MACS"
printf 'failure=%s\n' "$(ssh_failure_kind 'Unable to negotiate: no matching cipher found. Their offer: aes128-cbc')"
"""
        result = subprocess.run(
            ["bash", "-c", script],
            cwd=ROOT,
            env=self.env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("families=cisco-ios,aruba-aos-switch,aruba-aos-cx,ruckus-fastiron,ruckus-smartzone,ruckus-ap", result.stdout)
        self.assertIn("KexAlgorithms=+diffie-hellman-group14-sha1", result.stdout)
        self.assertIn("HostKeyAlgorithms=+ssh-rsa", result.stdout)
        self.assertIn("Ciphers=+aes128-cbc", result.stdout)
        self.assertIn("MACs=+hmac-sha1", result.stdout)
        self.assertIn("exports=diffie-hellman-group14-sha1|ssh-rsa|aes128-cbc|hmac-sha1", result.stdout)
        self.assertIn("failure=CIPHER", result.stdout)

    def test_missing_config_snippet_stops_control_dry_run(self):
        result = self.run_helper("netops-control", "config", "127.0.0.1", "@definitely-missing", "--dry-run")
        self.assertEqual(result.returncode, 1)
        self.assertIn("Snippet definitely-missing not found", result.stdout + result.stderr)

    def test_direct_control_show_is_read_only_but_allows_diagnostic_commands(self):
        rejected = self.run_helper(
            "netops-control", "show", "127.0.0.1", "configure terminal", "--dry-run"
        )
        injected = self.run_helper(
            "netops-control", "show", "127.0.0.1", "show version; reload", "--dry-run"
        )
        unquoted = self.run_helper(
            "netops-control", "show", "127.0.0.1", "show", "version", "--dry-run"
        )
        self.assertEqual((rejected.returncode, injected.returncode, unquoted.returncode), (2, 2, 2))
        self.assertIn("only bounded read-only", rejected.stdout + rejected.stderr)
        self.assertIn("exactly one quoted command", unquoted.stdout + unquoted.stderr)

        for command in (
            "show interfaces Gi1/0/1",
            "ping 192.0.2.8 repeat 5 timeout 2",
            "test cable-diagnostics tdr interface Gi1/0/1",
            "diag cable-diagnostic show 1",
        ):
            with self.subTest(command=command):
                allowed = self.run_helper(
                    "netops-control", "show", "127.0.0.1", command, "--dry-run"
                )
                self.assertEqual(allowed.returncode, 0, allowed.stdout + allowed.stderr)
                self.assertIn(command, allowed.stdout)

    def test_direct_control_validates_vlan_arguments_before_execution(self):
        access = self.run_helper(
            "netops-control", "vlan", "127.0.0.1", "Gi1/0/8", "--access", "131", "--dry-run"
        )
        trunk = self.run_helper(
            "netops-control", "vlan", "127.0.0.1", "Gi1/0/48", "--trunk", "10,20-22",
            "--native", "99", "--replace", "--dry-run",
        )
        numeric_interface = self.run_helper(
            "netops-control", "vlan", "127.0.0.1", "1/1/1", "--access", "131", "--dry-run"
        )
        self.assertEqual(
            (access.returncode, trunk.returncode, numeric_interface.returncode),
            (0, 0, 0),
            access.stderr + trunk.stderr + numeric_interface.stderr,
        )
        self.assertIn("switchport access vlan 131", access.stdout)
        self.assertIn("switchport trunk allowed vlan 10,20-22", trunk.stdout)
        self.assertIn("switchport trunk native vlan 99", trunk.stdout)

        invalid_cases = (
            ("Gi1/0/8", "--access"),
            ("Gi1/0/8", "--access", "4095"),
            ("Gi1/0/48", "--trunk", "10,22-20"),
            ("Gi1/0/48", "--trunk", "10,20,"),
            ("Gi1/0/8;reload", "--access", "131"),
            ("Gi1/0/8", "--access", "131", "--trunk", "10"),
            ("Gi1/0/8", "--access", "131", "--native", "99"),
        )
        for arguments in invalid_cases:
            with self.subTest(arguments=arguments):
                result = self.run_helper(
                    "netops-control", "vlan", "127.0.0.1", *arguments, "--dry-run"
                )
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)

        invalid_vlan = self.run_helper(
            "netops-control", "propagated", "127.0.0.1", "5000", "--dry-run"
        )
        invalid_mac = self.run_helper(
            "netops-control", "mac-lookup", "127.0.0.1", "not-a-mac", "--dry-run"
        )
        self.assertEqual((invalid_vlan.returncode, invalid_mac.returncode), (2, 2))

    def test_direct_control_blocks_unreviewed_configuration_execution(self):
        (self.cache_dir / "devices.db").write_text(
            "127.0.0.1|FIXTURE-SW|Cisco|C9300|SERIAL|N/A|test|1|ONLINE\n",
            encoding="utf-8",
        )
        config = self.run_helper("netops-control", "config", "127.0.0.1", "hostname reviewed-only")
        vlan = self.run_helper("netops-control", "vlan", "127.0.0.1", "Gi1/0/8", "--access", "131")
        for result in (config, vlan):
            self.assertEqual(result.returncode, 7, result.stdout + result.stderr)
            self.assertIn("Direct configuration execution is blocked", result.stdout + result.stderr)

    def test_control_selects_ruckus_driver_from_model_when_platform_is_unknown(self):
        (self.cache_dir / "devices.db").write_text(
            "127.0.0.1|FIXTURE-SW|Unknown|ICX7150|SERIAL|N/A|test|1|ONLINE\n",
            encoding="utf-8",
        )
        stream_file = Path(self.temp.name) / "command-stream.txt"
        gpg = self.bin_dir / "gpg"
        sshpass = self.bin_dir / "sshpass"
        gpg.write_text("#!/usr/bin/env bash\nprintf 'fixture-password'\n", encoding="utf-8")
        sshpass.write_text(
            "#!/usr/bin/env bash\n"
            "cat > \"$CONTROL_STREAM_FILE\"\n"
            "printf 'MAC not present\\n'\n",
            encoding="utf-8",
        )
        gpg.chmod(0o700)
        sshpass.chmod(0o700)
        env = dict(self.env)
        env["CONTROL_STREAM_FILE"] = str(stream_file)
        result = subprocess.run(
            [str(ROOT / "netops-control"), "mac-lookup", "127.0.0.1", "0200.0000.0025"],
            cwd=ROOT,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        stream = stream_file.read_text(encoding="utf-8")
        self.assertIn("skip-page-display", stream)
        self.assertIn("show mac-address 020000000025", stream)
        self.assertNotIn("terminal length 0", stream)

    def test_shell_device_update_uses_normalized_ingest_boundary(self):
        devices = self.cache_dir / "devices.db"
        devices.write_text(
            "192.0.2.8|OLD-SW|Unknown|ICX7150|SERIAL-8|0200.0000.0025|SNMP|100|OFFLINE\n",
            encoding="utf-8",
        )
        result = subprocess.run(
            [
                "bash",
                "-c",
                'source "$1"; db_update_device 192.0.2.8 NEW-SW Unknown N/A N/A N/A SSH ONLINE',
                "_",
                str(ROOT / "netops-lib.sh"),
            ],
            cwd=ROOT,
            env=self.env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        fields = devices.read_text(encoding="utf-8").strip().split("|")
        self.assertEqual(fields[1:7], ["NEW-SW", "Ruckus FastIron", "ICX7150", "SERIAL-8", "020000000025", "SNMP+SSH"])
        self.assertEqual(fields[8], "ONLINE")

    def test_python_helper_resolution_falls_back_to_installed_module(self):
        empty_install = Path(self.temp.name) / "empty-install"
        empty_install.mkdir()
        result = subprocess.run(
            [
                "bash",
                "-c",
                'source "$1"; NETOPS_INSTALL_DIR="$2"; netops_python_helper_path netops_devices netops_devices.py',
                "_",
                str(ROOT / "netops-lib.sh"),
                str(empty_install),
            ],
            cwd=ROOT,
            env=self.env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(Path(result.stdout.strip()).resolve(), (ROOT / "netops_devices.py").resolve())

    def test_direct_control_termination_reaps_nested_ssh_processes(self):
        (self.cache_dir / "devices.db").write_text(
            "127.0.0.1|FIXTURE-SW|Cisco|C9300|SERIAL|N/A|test|1|ONLINE\n",
            encoding="utf-8",
        )
        child_pid_file = Path(self.temp.name) / "control-ssh-child.pid"
        gpg = self.bin_dir / "gpg"
        sshpass = self.bin_dir / "sshpass"
        gpg.write_text("#!/usr/bin/env bash\nprintf 'fixture-password'\n", encoding="utf-8")
        sshpass.write_text(
            "#!/usr/bin/env bash\n"
            "printf 'FIXTURE-SW# '\n"
            "IFS= read -r line\n"
            "sleep 30 &\n"
            "child=$!\n"
            "printf '%s' \"$child\" > \"$CONTROL_CHILD_PID_FILE\"\n"
            "wait \"$child\"\n",
            encoding="utf-8",
        )
        gpg.chmod(0o700)
        sshpass.chmod(0o700)
        env = dict(self.env)
        env["CONTROL_CHILD_PID_FILE"] = str(child_pid_file)
        proc = subprocess.Popen(
            [str(ROOT / "netops-control"), "show", "127.0.0.1", "show version"],
            cwd=ROOT, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True,
        )
        child_pid = None
        try:
            deadline = time.monotonic() + 4
            while time.monotonic() < deadline and not child_pid_file.exists():
                time.sleep(0.05)
            self.assertTrue(child_pid_file.exists(), "nested SSH fixture did not start")
            child_pid = int(child_pid_file.read_text(encoding="utf-8"))
            os.kill(proc.pid, signal.SIGTERM)
            proc.communicate(timeout=5)
            self.assertEqual(proc.returncode, 143)
            with self.assertRaises(ProcessLookupError):
                os.kill(child_pid, 0)
        finally:
            if proc.poll() is None:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait(timeout=5)
            if child_pid is not None:
                try:
                    os.kill(child_pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def test_backups_use_safe_atomic_names_and_reuse_real_path_when_unchanged(self):
        (self.cache_dir / "devices.db").write_text(
            "127.0.0.1|../../escape|Cisco|C9300|SERIAL|N/A|test|1|ONLINE\n",
            encoding="utf-8",
        )
        gpg = self.bin_dir / "gpg"
        sshpass = self.bin_dir / "sshpass"
        gpg.write_text("#!/usr/bin/env bash\nprintf 'fixture-password'\n", encoding="utf-8")
        sshpass.write_text(
            "#!/usr/bin/env bash\n"
            "printf 'hostname fixture\\ninterface GigabitEthernet1/0/1\\n description fixture\\n'\n",
            encoding="utf-8",
        )
        gpg.chmod(0o700)
        sshpass.chmod(0o700)
        backup_dir = Path(self.temp.name) / "backups"

        first = self.run_helper("netops-control", "backup", "127.0.0.1", "--changed-only", "--output", str(backup_dir))
        second = self.run_helper("netops-control", "backup", "127.0.0.1", "--changed-only", "--output", str(backup_dir))
        self.assertEqual((first.returncode, second.returncode), (0, 0), first.stderr + second.stderr)
        configs = list(backup_dir.rglob("*.conf"))
        saved_configs = [path for path in configs if not path.is_symlink()]
        self.assertEqual(len(saved_configs), 1)
        self.assertTrue(saved_configs[0].resolve().is_relative_to(backup_dir.resolve()))
        self.assertNotIn("..", saved_configs[0].name)
        self.assertEqual(saved_configs[0].stat().st_mode & 0o777, 0o600)

        db = self.cache_dir / "netrune.sqlite3"
        with sqlite3.connect(db) as connection:
            rows = connection.execute(
                "SELECT status,path FROM backup_history ORDER BY id"
            ).fetchall()
        self.assertEqual([row[0] for row in rows], ["saved", "unchanged"])
        self.assertEqual(rows[0][1], rows[1][1])
        self.assertTrue(Path(rows[1][1]).is_file())

    def test_discovery_dry_run_expands_targets_bounds_cidrs_and_cleans_runtime(self):
        before = set(glob.glob("/tmp/netops-discovery.*"))
        small = self.run_helper("netops-discovery", "--no-color", "--dry-run", "--update", "192.0.2.0/30")
        explicit_range = self.run_helper("netops-discovery", "--no-color", "--dry-run", "--update", "192.0.2.5-7")
        oversized = self.run_helper("netops-discovery", "--no-color", "--dry-run", "--update", "198.18.0.0/15")
        self.assertEqual(small.returncode, 0, small.stderr)
        self.assertIn("Would scan 2 target(s)", small.stdout)
        self.assertEqual(small.stdout.splitlines()[-2:], ["192.0.2.1", "192.0.2.2"])
        self.assertEqual(explicit_range.returncode, 0, explicit_range.stderr)
        self.assertEqual(explicit_range.stdout.splitlines()[-3:], ["192.0.2.5", "192.0.2.6", "192.0.2.7"])
        self.assertEqual(oversized.returncode, 6)
        self.assertIn("limit is 4096", oversized.stderr)
        self.assertNotIn("\x1b", small.stderr + explicit_range.stderr + oversized.stderr)
        self.assertRegex(small.stderr, r"^\[\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\]")
        self.assertEqual(set(glob.glob("/tmp/netops-discovery.*")) - before, set())

    def test_quick_speed_reuses_discovery_cache_and_runs_one_paired_session(self):
        helper_log = Path(self.temp.name) / "speed-helper.log"
        servers = json.dumps(
            {
                "ok": True,
                "backend": "fixture",
                "tls_trust": {"verified": True, "source": "fixture-ca"},
                "servers": [{"id": 42, "host": "speed.example:8080", "sponsor": "Fixture", "name": "Lab"}],
            }
        )
        pair = json.dumps(
            {
                "ok": True,
                "directions": {
                    "upload": {"megabits_per_second": 40.0, "bytes": 5_000_000, "loaded_latency_ms": {"avg": 8.0, "jitter": 1.0, "samples": 6}},
                    "download": {"megabits_per_second": 100.0, "bytes": 12_500_000, "loaded_latency_ms": {"avg": 12.0, "jitter": 2.0, "samples": 7}},
                },
            }
        )
        python = self.bin_dir / "python3"
        python.write_text(
            "#!/usr/bin/env bash\n"
            f"real_python={shlex.quote(sys.executable)}\n"
            "if [[ \"$*\" == *\"netops_speed.py\"* ]]; then\n"
            "  printf '%s\\n' \"$*\" >> \"$SPEED_HELPER_LOG\"\n"
            "  if [[ \" $* \" == *\" servers \"* ]]; then\n"
            f"    printf '%s\\n' {shlex.quote(servers)}\n"
            "  else\n"
            f"    printf '%s\\n' {shlex.quote(pair)}\n"
            "  fi\n"
            "  exit 0\n"
            "fi\n"
            "exec \"$real_python\" \"$@\"\n",
            encoding="utf-8",
        )
        ping = self.bin_dir / "ping"
        ping.write_text(
            "#!/usr/bin/env bash\n"
            "printf '64 bytes from speed.example: time=4.0 ms\\n64 bytes from speed.example: time=6.0 ms\\n2 packets transmitted, 2 received, 0%% packet loss\\n'\n",
            encoding="utf-8",
        )
        ip = self.bin_dir / "ip"
        ip.write_text(
            "#!/usr/bin/env bash\n"
            "case \"$*\" in\n"
            "  'route get 1.1.1.1') printf '1.1.1.1 via 192.0.2.1 dev fixture0 src 192.0.2.2\\n' ;;\n"
            "  '-o link show up') printf '2: fixture0: <UP> mtu 1500\\n' ;;\n"
            "esac\n",
            encoding="utf-8",
        )
        for path in (python, ping, ip):
            path.chmod(0o700)
        env = dict(self.env)
        env["SPEED_HELPER_LOG"] = str(helper_log)

        first = subprocess.run(
            [str(ROOT / "netops-probe"), "--speed-test", "--profile", "quick", "--runs", "1", "--json"],
            cwd=ROOT, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
        )
        second = subprocess.run(
            [str(ROOT / "netops-probe"), "--speed-test", "--profile", "quick", "--json"],
            cwd=ROOT, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
        )
        self.assertEqual((first.returncode, second.returncode), (0, 0), first.stderr + second.stderr)
        self.assertTrue(first.stdout.strip(), first.stderr)
        self.assertTrue(second.stdout.strip(), second.stderr)
        first_payload = json.loads(first.stdout)
        second_payload = json.loads(second.stdout)
        self.assertFalse(first_payload["server_discovery"]["cached"])
        self.assertTrue(second_payload["server_discovery"]["cached"])
        self.assertEqual(first_payload["latency_samples"], {"idle": 2, "loaded_download": 7, "loaded_upload": 6})
        calls = helper_log.read_text(encoding="utf-8").splitlines()
        self.assertEqual(sum(" servers " in f" {line} " for line in calls), 1)
        self.assertEqual(sum(" run " in f" {line} " and "--direction both" in line for line in calls), 2)

        real_jq = shutil.which("jq", path=os.environ.get("PATH"))
        self.assertIsNotNone(real_jq)
        jq = self.bin_dir / "jq"
        jq.write_text(
            "#!/usr/bin/env bash\n"
            "if [[ \"${1:-}\" == '-n' ]]; then exit 7; fi\n"
            f"exec {shlex.quote(str(real_jq))} \"$@\"\n",
            encoding="utf-8",
        )
        jq.chmod(0o700)
        render_failure = subprocess.run(
            [str(ROOT / "netops-probe"), "--speed-test", "--profile", "quick", "--json"],
            cwd=ROOT, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
        )
        self.assertEqual(render_failure.returncode, 10)
        self.assertIn("could not render", render_failure.stderr)

    def test_direct_speed_termination_reaps_transfer_descendant_and_runtime(self):
        transfer_child_file = Path(self.temp.name) / "speed-transfer-child.pid"
        servers = json.dumps(
            {
                "ok": True,
                "backend": "fixture",
                "tls_trust": {"verified": True, "source": "fixture-ca"},
                "servers": [{"id": 42, "host": "speed.example:8080", "sponsor": "Fixture", "name": "Lab"}],
            }
        )
        python = self.bin_dir / "python3"
        python.write_text(
            "#!/usr/bin/env bash\n"
            "if [[ \" $* \" == *\" servers \"* ]]; then\n"
            f"  printf '%s\\n' {shlex.quote(servers)}\n"
            "  exit 0\n"
            "fi\n"
            "sleep 30 &\n"
            "child=$!\n"
            "printf '%s' \"$child\" > \"$SPEED_TRANSFER_CHILD_FILE\"\n"
            "wait \"$child\"\n",
            encoding="utf-8",
        )
        ping = self.bin_dir / "ping"
        ping.write_text(
            "#!/usr/bin/env bash\n"
            "printf '64 bytes from speed.example: time=4.0 ms\\n1 packets transmitted, 1 received, 0%% packet loss\\n'\n",
            encoding="utf-8",
        )
        ip = self.bin_dir / "ip"
        ip.write_text(
            "#!/usr/bin/env bash\n"
            "case \"$*\" in\n"
            "  'route get 1.1.1.1') printf '1.1.1.1 via 192.0.2.1 dev fixture0 src 192.0.2.2\\n' ;;\n"
            "  '-o link show up') printf '2: fixture0: <UP> mtu 1500\\n' ;;\n"
            "esac\n",
            encoding="utf-8",
        )
        for path in (python, ping, ip):
            path.chmod(0o700)
        env = dict(self.env)
        env["SPEED_TRANSFER_CHILD_FILE"] = str(transfer_child_file)
        before = set(glob.glob("/tmp/netops-speed.*"))
        proc = subprocess.Popen(
            [str(ROOT / "netops-probe"), "--speed-test", "--profile", "quick", "--json"],
            cwd=ROOT, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True,
        )
        child_pid = None
        try:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and not transfer_child_file.exists():
                time.sleep(0.05)
            self.assertTrue(transfer_child_file.exists(), "speed transfer fixture did not start")
            child_pid = int(transfer_child_file.read_text(encoding="utf-8"))
            os.kill(proc.pid, signal.SIGTERM)
            proc.communicate(timeout=5)
            self.assertEqual(proc.returncode, 143)
            with self.assertRaises(ProcessLookupError):
                os.kill(child_pid, 0)
            self.assertEqual(set(glob.glob("/tmp/netops-speed.*")) - before, set())
        finally:
            if proc.poll() is None:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait(timeout=5)
            if child_pid is not None:
                try:
                    os.kill(child_pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def test_interface_sampler_uses_real_ifindex_and_reuses_cached_identity(self):
        base = Path(self.temp.name)
        fixture_bin = base / "snmp-bin"
        fixture_bin.mkdir()
        walk_log = base / "walk.log"
        sysname_log = base / "sysname.log"
        counter_log = base / "counter.log"

        (fixture_bin / "sleep").write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
        (fixture_bin / "snmpwalk").write_text(
            """#!/usr/bin/env bash
printf 'walk\\n' >> "$SNMP_WALK_LOG"
cat <<'EOF'
.1.3.6.1.2.1.2.2.1.2.2 = STRING: Vlan1
.1.3.6.1.2.1.2.2.1.2.47 = STRING: GigabitEthernet1/0/1
EOF
""",
            encoding="utf-8",
        )
        (fixture_bin / "snmpget").write_text(
            """#!/usr/bin/env bash
if [[ "$*" == *"sysName.0"* ]]; then
    printf 'sysname\\n' >> "$SNMP_SYSNAME_LOG"
    exit 0
fi
if [[ "$*" == *"ifInOctets.47"* && "$*" != *"ifHCInOctets.47"* ]]; then
    printf '100\\n50\\n1000\\n1\\n1\\n'
    exit 0
fi
[[ "$*" == *"ifHCInOctets.47"* ]] || exit 8
printf 'sample\\n' >> "$SNMP_COUNTER_LOG"
n=$(wc -l < "$SNMP_COUNTER_LOG")
case "$n" in
    1) printf '1000\\n2000\\n1000\\n1\\n1\\n' ;;
    2) printf '100001000\\n50002000\\n1000\\n1\\n1\\n' ;;
    *) printf '200001000\\n100002000\\n1000\\n1\\n1\\n' ;;
esac
""",
            encoding="utf-8",
        )
        for path in fixture_bin.iterdir():
            path.chmod(0o700)

        env = dict(self.env)
        env.update(
            {
                "PATH": f"{fixture_bin}:{env.get('PATH', '')}",
                "SNMP_WALK_LOG": str(walk_log),
                "SNMP_SYSNAME_LOG": str(sysname_log),
                "SNMP_COUNTER_LOG": str(counter_log),
            }
        )

        first = subprocess.run(
            [
                str(ROOT / "netops-legacy"),
                "interface",
                "192.0.2.10",
                "on",
                "Gi1/0/1",
                "--json",
                "--once",
                "--interval",
                "1",
                "--community",
                "public",
            ],
            cwd=ROOT,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
        )
        self.assertEqual(first.returncode, 0, first.stderr)
        sample = json.loads(first.stdout)
        self.assertEqual(sample["interface_index"], 47)
        self.assertEqual(sample["interface_name"], "GigabitEthernet1/0/1")
        self.assertEqual(sample["in_bps"], 800_000_000)
        self.assertEqual(sample["out_bps"], 400_000_000)
        self.assertEqual(sample["aggregate_bps"], 1_200_000_000)
        self.assertEqual(sample["peak_direction_bps"], 800_000_000)
        self.assertEqual(sample["utilization_pct"], 80)
        self.assertEqual(sample["counters"]["in_octets"], 100_001_000)
        self.assertRegex(sample["timestamp"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

        second = subprocess.run(
            [
                str(ROOT / "netops-legacy"),
                "interface",
                "192.0.2.10",
                "on",
                "Gi1/0/1",
                "--json",
                "--once",
                "--interval",
                "1",
                "--community",
                "public",
                "--if-index",
                str(sample["interface_index"]),
                "--if-name",
                sample["interface_name"],
                "--baseline-in",
                str(sample["counters"]["in_octets"]),
                "--baseline-out",
                str(sample["counters"]["out_octets"]),
                "--baseline-speed",
                str(sample["speed_mbps"]),
                "--baseline-admin",
                str(sample["admin_status_code"]),
                "--baseline-oper",
                str(sample["oper_status_code"]),
                "--counter-bits",
                str(sample["counter_bits"]),
            ],
            cwd=ROOT,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
        )
        self.assertEqual(second.returncode, 0, second.stderr)
        cached_sample = json.loads(second.stdout)
        self.assertEqual(cached_sample["interface_index"], 47)
        self.assertEqual(walk_log.read_text(encoding="utf-8").splitlines(), ["walk"])
        self.assertEqual(sysname_log.read_text(encoding="utf-8").splitlines(), ["sysname"])

        wrapped = subprocess.run(
            [
                str(ROOT / "netops-legacy"),
                "interface",
                "192.0.2.10",
                "on",
                "Gi1/0/1",
                "--json",
                "--once",
                "--interval",
                "1",
                "--community",
                "public",
                "--if-index",
                "47",
                "--if-name",
                "GigabitEthernet1/0/1",
                "--baseline-in",
                "4294967200",
                "--baseline-out",
                "4294967100",
                "--baseline-speed",
                "1000",
                "--baseline-admin",
                "1",
                "--baseline-oper",
                "1",
                "--counter-bits",
                "32",
            ],
            cwd=ROOT,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
        )
        self.assertEqual(wrapped.returncode, 0, wrapped.stderr)
        wrap_sample = json.loads(wrapped.stdout)
        self.assertEqual(wrap_sample["in_bps"], 1568)
        self.assertEqual(wrap_sample["out_bps"], 1968)
        self.assertFalse(wrap_sample["counter_reset_detected"])


if __name__ == "__main__":
    unittest.main()
