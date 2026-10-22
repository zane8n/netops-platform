import contextlib
import io
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import netops_core as netops

from netops_platform import ap_neighbors
from netops_platform.network import parse_neighbor_detail_output


ROOT = Path(__file__).resolve().parents[1]

CISCO_CDP = """
-------------------------
Device ID: SITE-A-SQ37-AP149
Entry address(es):
  IP address: 192.0.2.149
Platform: cisco C9136I-ROW,  Capabilities: Trans-Bridge Source-Route-Bridge IGMP
Interface: GigabitEthernet1/0/5,  Port ID (outgoing port): GigabitEthernet0
Holdtime : 133 sec

Version :
Cisco AP Software, ap1g6a-k9w8 Version: 17.15.3.28

Management address(es):
  IP address: 192.0.2.149
-------------------------
Device ID: SEP001122334455
Entry address(es):
  IP address: 192.0.2.201
Platform: Cisco IP Phone 8841,  Capabilities: Host Phone Two-port Mac Relay
Interface: GigabitEthernet1/0/7,  Port ID (outgoing port): Port 1
-------------------------
Device ID: SITE-A-BLDG2-SW01
Entry address(es):
  IP address: 192.0.2.11
Platform: cisco C9200L-24P-4G,  Capabilities: Switch IGMP
Interface: TenGigabitEthernet1/1/1,  Port ID (outgoing port): TenGigabitEthernet1/1/1
"""

CISCO_LLDP = """
------------------------------------------------
Local Intf: Gi1/0/9
Chassis id: 02bb.0000.0061
Port id: Gi0
Port Description: GigabitEthernet0
System Name: AP-STORE

System Description:
Cisco AP Software, ap1g8-k9w8 Version: 17.15.3.28

Time remaining: 101 seconds
System Capabilities: B,W
Enabled Capabilities: B,W
Management Addresses:
    IP: 192.0.2.61

Total entries displayed: 1
"""

ARUBA_LLDP_SUMMARY = """
 LLDP Remote Devices Information

  LocalPort | ChassisId                 PortId PortDescr SysName
  --------- + ------------------------- ------ --------- ----------------------
  3         | 02 bb 00 00 00 77         3      3         KIB-YARD-AP77
  24        | 02 a9 b8 07 0c 00         24     24        SITE-A-CORE-SW01
"""

ARUBA_LLDP_PORT_3 = """
 LLDP Remote Device Information Detail

  Local Port   : 3
  ChassisType  : mac-address
  ChassisId    : 02 bb 00 00 00 77
  PortType     : mac-address
  PortId       : 02 bb 00 00 00 77
  SysName      : KIB-YARD-AP77
  System Descr : Ruckus R610 Multimedia Hotzone Wireless AP/SW Version: 5.2.2.0.2069
  PortDescr    : eth0

  System Capabilities Supported  : bridge, wlan-access-point
  System Capabilities Enabled    : bridge, wlan-access-point

  Remote Management Address
     Type    : ipv4
     Address : 192.0.2.77
"""

ARUBA_LLDP_PORT_24 = """
 LLDP Remote Device Information Detail

  Local Port   : 24
  ChassisType  : mac-address
  ChassisId    : 02 a9 b8 07 0c 00
  SysName      : SITE-A-CORE-SW01
  System Descr : Cisco IOS Software, C9200 Software
  System Capabilities Enabled    : bridge, router

  Remote Management Address
     Address : 192.0.2.10
"""

ARUBA_CDP = """
 CDP neighbors information for port 6

  Port : 6
  Device ID : KIB-GATE-AP06
  Address Type : IP
  Address : 192.0.2.66
  Platform : cisco AIR-AP2802I-E-K9
  Capability : Router Trans-Bridge
  Device Port : GigabitEthernet0
  Version : Cisco AP Software, ap3g3-k9w8
"""


class ParserTest(unittest.TestCase):
    def test_mac_verdicts(self):
        self.assertEqual(ap_neighbors.mac_verdict({}, ["02bb00000061"], ["02bb00000061", "02bb00000099"]), ("confirmed", ""))
        self.assertEqual(ap_neighbors.mac_verdict({}, [""], ["0cbb00000061"]), ("learned", "0cbb00000061"))
        self.assertEqual(ap_neighbors.mac_verdict({}, ["02bb00000061"], ["0ccc00000099"]), ("elsewhere", ""))
        # The AP's own radio/Ethernet MACs are a few addresses apart; another AP
        # from the same batch is not.
        self.assertEqual(ap_neighbors.mac_verdict({}, ["e4379fa25425"], ["e4379fa25424"]), ("confirmed", ""))
        self.assertEqual(ap_neighbors.mac_verdict({}, ["e4379fa25425"], ["e4379fa2508c"]), ("elsewhere", ""))
        # Only randomized client MACs: its wireless clients.
        self.assertEqual(ap_neighbors.mac_verdict({}, ["60b9c0893764"], ["92b3a4c44bd5", "0e2f5135ebcd"]), ("clients", ""))
        table = ap_neighbors.table_port_macs("Vlan Mac Address Type Ports\n 112  e437.9fa2.5425  DYNAMIC  Gi1/0/2\n", "cisco-ios")
        self.assertEqual(table, {"gi1/0/2": ["e4379fa25425"]})
        self.assertEqual(ap_neighbors.table_port_macs("  02bb00-000077   3    20\n", "aruba-aos-switch"), {"3": ["02bb00000077"]})
        self.assertEqual(ap_neighbors.mac_verdict({}, ["02bb00000061"], []), ("empty", ""))
        self.assertEqual(ap_neighbors.port_macs("  20  0cd5.d36a.8f44  DYNAMIC Gi1/0/5\n 02bb00-000077 20"),
                         ["02bb00000077", "0cd5d36a8f44"])

    def test_cisco_and_aruba_neighbour_detail_is_read_with_ports_platforms_and_addresses(self):
        cdp = {row["remote_name"]: row for row in parse_neighbor_detail_output(CISCO_CDP)}
        self.assertEqual((cdp["SITE-A-SQ37-AP149"]["local_port"], cdp["SITE-A-SQ37-AP149"]["remote_ip"], cdp["SITE-A-SQ37-AP149"]["platform"]),
                         ("GigabitEthernet1/0/5", "192.0.2.149", "cisco C9136I-ROW"))
        lldp = parse_neighbor_detail_output(CISCO_LLDP)[0]
        # The description sits on the line after its label on IOS.
        self.assertEqual((lldp["local_port"], lldp["remote_mac"], lldp["platform"], lldp["remote_ip"]),
                         ("Gi1/0/9", "02bb00000061", "Cisco AP Software, ap1g8-k9w8 Version: 17.15.3.28", "192.0.2.61"))
        aruba = parse_neighbor_detail_output(ARUBA_LLDP_PORT_3)[0]
        self.assertEqual((aruba["local_port"], aruba["remote_name"], aruba["remote_ip"], aruba["remote_mac"]),
                         ("3", "KIB-YARD-AP77", "192.0.2.77", "02bb00000077"))
        self.assertIn("wlan-access-point", aruba["capabilities"])
        aruba_cdp = parse_neighbor_detail_output(ARUBA_CDP)[0]
        self.assertEqual((aruba_cdp["local_port"], aruba_cdp["remote_name"], aruba_cdp["remote_ip"], aruba_cdp["remote_port"]),
                         ("6", "KIB-GATE-AP06", "192.0.2.66", "GigabitEthernet0"))

    def test_only_aps_are_taken_from_the_neighbour_tables(self):
        switches = {"192.0.2.11": "SITE-A-BLDG2-SW01"}
        verdicts = {row["remote_name"]: ap_neighbors.classify(row, switches) for row in parse_neighbor_detail_output(CISCO_CDP)}
        self.assertEqual(verdicts["SITE-A-SQ37-AP149"], (True, "AP model C9136I-ROW"))
        self.assertEqual(verdicts["SEP001122334455"], (False, "phone"))
        self.assertEqual(verdicts["SITE-A-BLDG2-SW01"], (False, "known switch SITE-A-BLDG2-SW01"))
        self.assertEqual(ap_neighbors.classify(parse_neighbor_detail_output(ARUBA_LLDP_PORT_3)[0], {})[0], True)
        # An Aruba switch the inventory does not know still says it is one.
        self.assertEqual(ap_neighbors.classify({"platform": "Aruba JL258A 2930F-8G-PoE+-2SFP+ Switch, revision WC.16",
                                                "capabilities": "bridge"}, {}), (False, "describes itself as a switch"))
        self.assertEqual(ap_neighbors.short_port("TenGigabitEthernet1/1/1"), "Te1/1/1")


class ApMergeTest(unittest.TestCase):
    def rows(self, *lines):
        from netops_platform.ap_merge import parse
        return parse("\n".join(lines))

    def test_controller_names_switch_attaches_and_hostname_joins_them(self):
        from netops_platform.ap_merge import merge_ap_scan
        out = merge_ap_scan(
            self.rows("192.0.2.5|AP-LOBBY|cisco C9136I-ROW|||not-joined|aabbcc000001|100|ONLINE"),
            self.rows("192.0.2.5|AP-LOBBY|Cisco AP Software, ap1g6a|192.0.2.10|SW1.example.com|Gi1/0/5|aabbcc0000ff|200|ONLINE"),
            self.rows("192.0.2.8|AP-GONE|Cisco-AP|192.0.2.10|SW1|Gi1/0/8|aabbcc000008|50|ONLINE"))
        rows = {row["name"]: row for row in out}
        self.assertEqual((rows["AP-LOBBY"]["platform"], rows["AP-LOBBY"]["switch_name"], rows["AP-LOBBY"]["switch_port"]),
                         ("cisco C9136I-ROW", "SW1", "Gi1/0/5"))
        self.assertEqual(rows["AP-GONE"]["status"], "OFFLINE")
        self.assertEqual(len(out), 2)

    def test_a_port_confirmed_on_the_mac_table_beats_snmp_on_the_same_switch_only(self):
        from netops_platform.ap_merge import ATTACHMENT_FIELDS, merge_ap_scan, parse
        now = 1_800_000_000
        confirmed = parse(f"aabbcc000001|AP-LOBBY|192.0.2.5|192.0.2.10|SW1|Gi1/0/9|confirmed|{now - 3600}", ATTACHMENT_FIELDS)
        snmp_same = self.rows("192.0.2.5|AP-LOBBY|cisco C9136I-ROW|192.0.2.10|SW1|Gi1/0/5|aabbcc000001|200|ONLINE")
        out = merge_ap_scan([], snmp_same, [], confirmed, now=now)
        self.assertEqual(out[0]["switch_port"], "Gi1/0/9")
        moved = self.rows("192.0.2.5|AP-LOBBY|cisco C9136I-ROW|192.0.2.11|SW2|Gi1/0/2|aabbcc000001|200|ONLINE")
        self.assertEqual(merge_ap_scan([], moved, [], confirmed, now=now)[0]["switch_ip"], "192.0.2.11")
        stale = parse(f"aabbcc000001|AP-LOBBY|192.0.2.5|192.0.2.10|SW1|Gi1/0/9|confirmed|{now - 30 * 86400}", ATTACHMENT_FIELDS)
        self.assertEqual(merge_ap_scan([], snmp_same, [], stale, now=now)[0]["switch_port"], "Gi1/0/5")
        # A controller-only AP (no physical port) takes the confirmed one.
        wireless = self.rows("192.0.2.5|AP-LOBBY|cisco C9136I-ROW|192.0.2.250|WLC|wireless|aabbcc000001|200|ONLINE")
        self.assertEqual(merge_ap_scan(wireless, [], [], confirmed, now=now)[0]["switch_port"], "Gi1/0/9")


class ApNeighborsCommandTest(unittest.TestCase):
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
        for ip, name, platform, model, mac in (
            ("192.0.2.10", "SITE-A-CORE-SW01", "Cisco IOS", "C9200-24PXG", "02a9b8070c00"),
            ("192.0.2.11", "SITE-A-BLDG2-SW01", "Aruba AOS-S", "2930F-8G-PoE+-2SFP+", "02c1c7b9aa40"),
        ):
            self.app.state.execute("INSERT INTO devices(ip,hostname,platform,model,serial,mac,source,last_seen,status) VALUES(?,?,?,?,?,?,?,?,?)",
                                   (ip, name, platform, model, "", mac, "SSH", seen, "ONLINE"))
        # AP-STORE is recorded on the wrong switch; SITE-A-SQ37-AP149 is right.
        for ip, name, platform, switch_ip, switch_name, port, mac in (
            ("192.0.2.61", "AP-STORE", "Cisco-AP", "192.0.2.11", "SITE-A-BLDG2-SW01", "9", "02bb00000061"),
            ("192.0.2.149", "SITE-A-SQ37-AP149", "cisco C9136I-ROW", "192.0.2.10", "SITE-A-CORE-SW01", "Gi1/0/5", ""),
        ):
            self.app.state.execute("INSERT INTO aps(ip,name,platform,switch_ip,switch_name,switch_port,mac,last_seen,status) VALUES(?,?,?,?,?,?,?,?,?)",
                                   (ip, name, platform, switch_ip, switch_name, port, mac, seen, "ONLINE"))
        self.app.state.export_flat_files()
        self.app.import_flat_state(("ap",), "test")

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def run_cli(self, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            code = self.app.dispatch(["ap", *args, "--plain", "--no-color"])
        return code, out.getvalue()

    def fake_batch(self, target, commands, timeout=120, opts=None):
        outputs = {
            ("192.0.2.10", "show cdp neighbors detail"): CISCO_CDP,
            ("192.0.2.10", "show lldp neighbors detail"): CISCO_LLDP,
            # The whole table: AP-STORE's LLDP MAC on its port; Gi1/0/5 quiet.
            ("192.0.2.10", "show mac address-table"): " 20    02bb.0000.0061    DYNAMIC     Gi1/0/9\n 20 02aa.0000.0001 DYNAMIC Te1/1/1",
            ("192.0.2.11", "show lldp info remote-device"): ARUBA_LLDP_SUMMARY,
            ("192.0.2.11", "show cdp neighbors detail"): ARUBA_CDP,
            ("192.0.2.11", "show lldp info remote-device 3"): ARUBA_LLDP_PORT_3,
            ("192.0.2.11", "show lldp info remote-device 24"): ARUBA_LLDP_PORT_24,
            # The CDP-only AP is the one MAC on port 6.
            ("192.0.2.11", "show mac-address"): " 0ccc00-000066    6    20\n 02bb00-000077    3    20",
            # Re-read after the AP was pinged: now learned.
            ("192.0.2.10", "show mac address-table interface GigabitEthernet1/0/5"): " 20    0cd5.d36a.8f44    DYNAMIC     Gi1/0/5",
        }
        self.batches.append((target, list(commands)))
        self.mac_asks = getattr(self, "mac_asks", [])
        self.mac_asks.extend((target, command) for command in commands if "mac" in command)
        return [(command, outputs.get((target, command), "")) for command in commands]

    def test_neighbors_needs_a_switch_or_all_and_dry_run_connects_to_nothing(self):
        code, output = self.run_cli("neighbors")
        self.assertEqual(code, netops.VALIDATION)
        self.assertIn("--all", output)
        self.batches = []
        with mock.patch.object(self.app, "capture_batch", self.fake_batch):
            code, output = self.run_cli("neighbors", "--all", "--dry-run", "--json")
        self.assertEqual(code, netops.SUCCESS, output)
        self.assertFalse(self.batches)
        self.assertIn("show lldp info remote-device ; show cdp neighbors detail", output)

    def test_neighbors_corrects_attachments_and_adds_unknown_aps(self):
        self.batches = []
        pinged = []
        with mock.patch.object(self.app, "capture_batch", self.fake_batch), \
                mock.patch.object(ap_neighbors, "MAC_CHECK_PAUSE", 0), \
                mock.patch.object(ap_neighbors, "_ping_from_here", lambda addresses: pinged.extend(addresses)), \
                mock.patch.object(self.app, "vault_session_scope", lambda opts, minutes=30: contextlib.nullcontext(False)):
            code, output = self.run_cli("neighbors", "--all")
        self.assertEqual(code, netops.SUCCESS, output)
        # Aruba's LLDP summary is followed by the detail of the ports it listed, in one more login.
        self.assertIn(("192.0.2.11", ["show lldp info remote-device 24", "show lldp info remote-device 3"]), self.batches)
        aps = {row["name"]: row for row in self.app.state.rows("SELECT * FROM aps")}
        # Matched by the MAC LLDP advertised, and moved to the port the switch reports.
        self.assertEqual((aps["AP-STORE"]["switch_ip"], aps["AP-STORE"]["switch_port"]), ("192.0.2.10", "Gi1/0/9"))
        self.assertEqual((aps["KIB-YARD-AP77"]["switch_name"], aps["KIB-YARD-AP77"]["switch_port"], aps["KIB-YARD-AP77"]["mac"]),
                         ("SITE-A-BLDG2-SW01", "3", "02bb00000077"))
        self.assertEqual((aps["KIB-GATE-AP06"]["ip"], aps["KIB-GATE-AP06"]["switch_port"]), ("192.0.2.66", "6"))
        self.assertNotIn("SEP001122334455", aps)
        self.assertNotIn("SITE-A-CORE-SW01", aps)
        move = self.app.state.one("SELECT * FROM ap_move_events WHERE ap_name='AP-STORE'")
        self.assertEqual((move["previous_switch_ip"], move["current_switch_ip"], move["current_switch_port"]),
                         ("192.0.2.11", "192.0.2.10", "Gi1/0/9"))
        self.assertIn("1 AP(s) on a different port than recorded, 2 new, 1 confirmed where recorded", output)
        # Gi1/0/5 was empty in the whole table: the AP was pinged from here and
        # the port re-read once; CDP gave that AP no MAC, so the one MAC on its
        # port became its MAC.
        self.assertEqual(sum(1 for asked in self.mac_asks if asked[1].endswith("GigabitEthernet1/0/5")), 1)
        self.assertEqual(pinged, ["192.0.2.149"])
        self.assertIn("2 confirmed, 2 learned", output)
        self.assertEqual(aps["SITE-A-SQ37-AP149"]["mac"], "0cd5d36a8f44")
        self.assertEqual(aps["KIB-GATE-AP06"]["mac"], "0ccc00000066")
        # What the switches confirmed is kept for the next AP scan's merge.
        from netops_platform.ap_merge import ATTACHMENT_FIELDS, parse
        kept = {row["name"]: row for row in parse(self.app.paths.aps_file.with_name("ap_attachments.db").read_text(), ATTACHMENT_FIELDS)}
        self.assertEqual((kept["AP-STORE"]["switch_port"], kept["AP-STORE"]["verdict"]), ("Gi1/0/9", "confirmed"))
        self.assertIn("phone", output)


if __name__ == "__main__":
    unittest.main()
