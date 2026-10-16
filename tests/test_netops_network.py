import tempfile
import unittest
from pathlib import Path

from netops_network import (
    interface_matches,
    lookup_oui,
    normalize_interface,
    parse_arp_output,
    parse_mac_table_output,
    parse_cable_diagnostics_output,
    parse_interface_health_output,
    parse_iperf3_output,
    parse_cdp_neighbors_table,
    parse_neighbor_detail_output,
    parse_ping_output,
    parse_spanning_tree_output,
    parse_svi_output,
    parse_vlan_control_output,
    parse_trunk_summary,
    parse_vlan_table_output,
    classify_uplink_ports,
    expand_vlan_list,
)


class NetOpsNetworkParserTest(unittest.TestCase):
    def test_interface_normalization_matches_long_and_short_names(self):
        self.assertEqual(normalize_interface("GigabitEthernet1/0/48"), "gi1/0/48")
        self.assertTrue(interface_matches("Gi1/0/48", "GigabitEthernet 1/0/48"))
        self.assertTrue(interface_matches("Port-channel10", "Po10"))
        self.assertFalse(interface_matches("Gi1/0/47", "Gi1/0/48"))

    def test_vlan_propagation_report_parses_missing_and_neighbor(self):
        output = """
Propagation Map for: SITE-A-CORE (192.0.2.1)
  Target VLAN: 131 | Status: DEFINED
  Detected Uplinks:
    - Gi1/0/47: PROPAGATED
    - Gi1/0/48: MISSING -> Adj Switch: ACCESS-02 (192.0.2.2)
"""
        parsed = parse_vlan_control_output(output, "propagation")
        self.assertTrue(parsed["defined"])
        self.assertEqual(parsed["device_name"], "SITE-A-CORE")
        self.assertEqual(len(parsed["trunks"]), 2)
        self.assertFalse(parsed["trunks"][1]["carries_vlan"])
        self.assertEqual(parsed["trunks"][1]["neighbor_name"], "ACCESS-02")
        self.assertEqual(parsed["trunks"][1]["neighbor_ip"], "192.0.2.2")

    def test_vlan_locate_report_parses_access_and_trunk_ports(self):
        output = """
[192.0.2.1] SITE-A-CORE -> DEFINED
  Access Ports: Gi1/0/1, Gi1/0/2
  Trunk Ports:  Po1, Gi1/0/48
"""
        parsed = parse_vlan_control_output(output, "locate")
        self.assertTrue(parsed["defined"])
        self.assertEqual(parsed["access_ports"], ["Gi1/0/1", "Gi1/0/2"])
        self.assertEqual([row["port"] for row in parsed["trunks"]], ["Po1", "Gi1/0/48"])

    def test_aruba_aos_s_vlan_table_parses_names_voice_and_blank_management_vlan(self):
        output = """
 Status and Counters - VLAN Information

  Maximum VLANs to support : 256
  Primary VLAN : DEFAULT_VLAN
  Management VLAN :

  VLAN ID Name                             | Status     Voice Jumbo
  ------- -------------------------------- + ---------- ----- -----
  1       DEFAULT_VLAN                     | Port-based No    No
  4       Management-of-Switch-Range       | Port-based No    No
  240     Cisco-Voip                       | Port-based Yes   No
  720     Strika_Digital                   | Port-based No    No
"""
        parsed = parse_vlan_table_output(output)
        self.assertTrue(parsed["parsed"])
        self.assertEqual(parsed["primary_vlan"], "DEFAULT_VLAN")
        self.assertEqual(parsed["max_vlans"], 256)
        # The device prints the field and leaves it blank. A blank field must
        # not be filled in from the next line of the report, nor guessed from a
        # VLAN named "Management-...".
        self.assertIsNone(parsed["management_vlan"])
        self.assertEqual([row["vlan"] for row in parsed["vlans"]], [1, 4, 240, 720])
        self.assertEqual(parsed["vlans"][1]["name"], "Management-of-Switch-Range")
        self.assertEqual([row["vlan"] for row in parsed["vlans"] if row["voice"]], [240])

    def test_vlan_table_parser_reads_a_stated_management_vlan(self):
        parsed = parse_vlan_table_output(
            "  Primary VLAN : DEFAULT_VLAN\n  Management VLAN : 4\n\n"
            "  VLAN ID Name        | Status     Voice Jumbo\n"
            "  1       DEFAULT_VLAN| Port-based No    No\n"
        )
        self.assertEqual(parsed["management_vlan"], "4")

    def test_vlan_table_parser_handles_aos_cx_and_cisco_columns(self):
        cx = parse_vlan_table_output(
            "VLAN  Name       Status  Reason      Type     Interfaces\n"
            "----------------------------------------------------------\n"
            "1     DEFAULT    up      ok          default  1/1/1,1/1/2\n"
            "4     MGMT       up      ok          static   1/1/3\n"
        )
        self.assertEqual([row["vlan"] for row in cx["vlans"]], [1, 4])
        self.assertEqual(cx["vlans"][0]["interfaces"], ["1/1/1", "1/1/2"])
        cisco = parse_vlan_table_output(
            "VLAN Name          Status    Ports\n"
            "---- ------------- --------- ----------------\n"
            "1    default       active    Gi1/0/1, Gi1/0/2\n"
            "240  voice         active    Gi1/0/3\n"
        )
        self.assertEqual([row["vlan"] for row in cisco["vlans"]], [1, 240])
        self.assertEqual(cisco["vlans"][1]["interfaces"], ["Gi1/0/3"])

    def test_vlan_table_parser_reports_an_unsupported_command(self):
        parsed = parse_vlan_table_output("Invalid input: vlan")
        self.assertTrue(parsed["unsupported"])
        self.assertFalse(parsed["parsed"])

    def test_aruba_aos_s_mstp_parser_derives_uplinks_and_edge_ports(self):
        output = """
 Multiple Spanning Tree (MST) Information

  STP Enabled   : Yes
  Force Version : MSTP-operation
  Switch MAC Address : d06726-f2b6a0
  Switch Priority    : 32768

  Topology Change Count  : 930,701

  CST Root MAC Address : ccb6c8-4eed80
  CST Root Priority    : 0
  CST Root Path Cost   : 2000
  CST Root Port        : 25

  IST Regional Root MAC Address : 94f128-2daa00

  Root Guard Ports     :
  PVST Protected Ports :
  PVST Filtered Ports  :

                   |           Prio              | Designated        Hello
  Port  Type       | Cost      rity State        | Bridge            Time PtP Edge
  ----- ---------- + --------- ---- ------------ + ----------------- ---- --- ----
  1     100/1000T  | 20000     128  Forwarding   | d06726-f2b6a0     2    Yes Yes
  4     100/1000T  | Auto      128  Disabled     |                   2    Yes No
  7     100/1000T  | 20000     128  Forwarding   | d06726-f2b6a0     2    Yes No
  25    1000LX     | 20000     128  Forwarding   | 94f128-2daa00     2    Yes No
  27               | Auto      128  Disabled     |                   2    Yes No
"""
        parsed = parse_spanning_tree_output(output)
        self.assertTrue(parsed["parsed"])
        # "PVST Protected Ports" must not be mistaken for PVST mode.
        self.assertEqual(parsed["mode"], "mstp")
        self.assertTrue(parsed["enabled"])
        self.assertFalse(parsed["is_root"])
        self.assertEqual(parsed["switch_mac"], "d06726f2b6a0")
        self.assertEqual(parsed["root_mac"], "ccb6c84eed80")
        self.assertEqual(parsed["regional_root_mac"], "94f1282daa00")
        self.assertEqual(parsed["root_port"], "25")
        self.assertEqual(parsed["topology_changes"], 930701)

        roles = {row["port"]: row["role"] for row in parsed["ports"]}
        self.assertEqual(roles, {"1": "edge", "4": "disabled", "7": "designated", "25": "root", "27": "disabled"})
        # Forwarding and Edge=No is what makes a port face other infrastructure.
        self.assertEqual([row["port"] for row in parsed["ports"] if row["network_facing"]], ["7", "25"])
        # A port row whose Type column is blank still parses.
        self.assertEqual([row["port"] for row in parsed["ports"]], ["1", "4", "7", "25", "27"])

    def test_spanning_tree_parser_reads_cisco_and_aos_cx_roles_directly(self):
        cisco = parse_spanning_tree_output("""
  Spanning tree enabled protocol rstp
  Root ID    Priority    32769
             Address     0011.2233.4455
             Port        24 (GigabitEthernet1/0/24)

Interface        Role Sts Cost      Prio.Nbr Type
---------------- ---- --- --------- -------- ----------------
Gi1/0/1          Desg FWD 4         128.1    P2p Edge
Gi1/0/2          Altn BLK 4         128.2    P2p
Gi1/0/24         Root FWD 4         128.24   P2p
""")
        self.assertEqual(cisco["mode"], "rstp")
        self.assertEqual({row["port"]: row["role"] for row in cisco["ports"]},
                         {"Gi1/0/1": "designated", "Gi1/0/2": "alternate", "Gi1/0/24": "root"})
        self.assertEqual([row["port"] for row in cisco["ports"] if row["network_facing"]], ["Gi1/0/24"])

        cx = parse_spanning_tree_output("""
Spanning tree status: Enabled
Root ID    Priority  :  0
           MAC-Address: cc:b6:c8:4e:ed:80

Bridge ID  Priority  : 32768
           MAC-Address: 10:20:30:40:50:60

Port         Role           State      Cost    Priority   Type
------------ -------------- ---------- ------- ---------- ----------
1/1/2        Alternate      Blocking   20000   128        point_to_point
1/1/25       Root           Forwarding 2000    128        point_to_point
""")
        self.assertTrue(cx["enabled"])
        self.assertEqual(cx["switch_mac"], "102030405060")
        self.assertEqual(cx["root_mac"], "ccb6c84eed80")
        self.assertEqual([row["port"] for row in cx["ports"] if row["network_facing"]], ["1/1/25"])

    def test_cisco_bridge_address_survives_the_priority_parenthetical(self):
        # Real IOS prints "Priority 32769  (priority 32768 sys-id-ext 1)".
        # A pattern that expected the address on the very next token missed it,
        # leaving every Cisco switch without its own bridge MAC.
        parsed = parse_spanning_tree_output("""
VLAN0001
  Spanning tree enabled protocol rstp
  Root ID    Priority    32769
             Address     0011.2233.4455
             Cost        4
             Port        24 (GigabitEthernet1/0/24)

  Bridge ID  Priority    32769  (priority 32768 sys-id-ext 1)
             Address     aabb.ccdd.eeff
             Aging Time  300 sec

Interface           Role Sts Cost      Prio.Nbr Type
------------------- ---- --- --------- -------- --------------------------------
Te1/0/10            Root FWD 4         128.10   P2p Peer(STP)
Gi1/0/1             Desg FWD 4         128.1    P2p Edge
Gi1/0/2             Altn BLK 4         128.2    P2p
""")
        self.assertEqual(parsed["switch_mac"], "aabbccddeeff")
        self.assertEqual(parsed["root_mac"], "001122334455")
        self.assertEqual([row["port"] for row in parsed["ports"]], ["Te1/0/10", "Gi1/0/1", "Gi1/0/2"])
        self.assertFalse(parsed["is_root"])

    def test_spanning_tree_parser_reports_an_unsupported_command(self):
        parsed = parse_spanning_tree_output("Invalid input: stp")
        self.assertTrue(parsed["unsupported"])
        self.assertFalse(parsed["parsed"])

    def test_spanning_tree_parser_detects_the_root_bridge(self):
        parsed = parse_spanning_tree_output(
            "  STP Enabled : Yes\n  Force Version : MSTP-operation\n"
            "  Switch MAC Address : ccb6c8-4eed80\n"
            "  CST Root MAC Address : ccb6c8-4eed80\n"
            "  CST Root Port :\n"
        )
        self.assertTrue(parsed["is_root"])
        # A blank root-port field must not absorb the following lines.
        self.assertEqual(parsed["root_port"], "")

    ARUBA_CDP = """
 CDP neighbors information

  Port   Device ID                     | Platform                     Capability
  ------ ----------------------------- + ---------------------------- -----------
  1      90 3a 72 07 8e d0             | Ruckus R610 Multimedia Ho... R S
  7      f4 03 43 fb f3 f0             | Aruba JL258A 2930F-8G-PoE... S
  11     SEP20CC274A41A4               | Cisco IP Phone 7841          H P M
  11     198.51.100.56                 | Cisco IP Phone 7841, V1, ... S P
  14     SEPECCE138E7C86               | CTS-CODEC-Touch 10           H P
  19     40 f4 9f 60 6a 00             | Cisco IOS Software [Dubli... S
  19     SITEAADMINFINSW01.exampl...   | cisco C9200-24PXG            S I
  25     94 f1 28 2d aa 00             | HP J9851A Switch 5412Rzl2... S
"""

    def test_cdp_table_reads_capability_letters_from_the_right(self):
        rows = parse_cdp_neighbors_table(self.ARUBA_CDP)
        by_port = {}
        for row in rows:
            by_port.setdefault(row["port"], []).append(row)
        self.assertEqual(by_port["1"][0]["capabilities"], ["R", "S"])
        self.assertEqual(by_port["7"][0]["capabilities"], ["S"])
        self.assertEqual(by_port["11"][0]["capabilities"], ["H", "P", "M"])
        self.assertEqual(by_port["19"][1]["capabilities"], ["S", "I"])
        self.assertEqual(by_port["1"][0]["platform"], "Ruckus R610 Multimedia Ho...")
        # A neighbour advertising switch and nothing else is infrastructure;
        # an access point adds R and a phone adds P/H/M.
        self.assertEqual(
            sorted({row["port"] for row in rows if row["switch_only"]}, key=int),
            ["7", "19", "25"],
        )

    def test_uplinks_combine_spanning_tree_with_cdp_capability(self):
        stp = parse_spanning_tree_output("""
  STP Enabled   : Yes
  Force Version : MSTP-operation
  Switch MAC Address : d06726-f2b6a0
  CST Root Port        : 25

  Port  Type       | Cost      rity State        | Bridge            Time PtP Edge
  1     100/1000T  | 20000     128  Forwarding   | d06726-f2b6a0     2    Yes Yes
  7     100/1000T  | 20000     128  Forwarding   | d06726-f2b6a0     2    Yes No
  19    100/1000T  | 20000     128  Forwarding   | d06726-f2b6a0     2    Yes Yes
  25    1000LX     | 20000     128  Forwarding   | 94f128-2daa00     2    Yes No
  26    1000LX     | Auto      128  Disabled     |                   2    Yes No
""")
        verdicts = classify_uplink_ports(stp["ports"], parse_cdp_neighbors_table(self.ARUBA_CDP))
        uplinks = sorted((port for port, row in verdicts.items() if row["uplink"]), key=int)
        # Spanning tree alone misses 19: its neighbour is a Cisco outside this
        # MSTP region, so the port is marked Edge Yes.
        self.assertEqual(sorted((row["port"] for row in stp["ports"] if row["network_facing"]), key=int), ["7", "25"])
        self.assertEqual(uplinks, ["7", "19", "25"])
        self.assertEqual(verdicts["19"]["reasons"], ["cdp-switch-only"])
        self.assertIn("fiber-media", verdicts["25"]["reasons"])
        # A fibre port that is not forwarding is not an uplink.
        self.assertNotIn("26", uplinks)
        # An access point is not an uplink even though it advertises S.
        self.assertNotIn("1", uplinks)

    def test_trunk_summary_parses_every_section(self):
        trunks = parse_trunk_summary("""
Port           Mode             Encapsulation  Status        Native vlan
Gi1/0/1        on               802.1q         trunking      112
Te1/1/3        on               802.1q         trunking      1

Port           Vlans allowed on trunk
Gi1/0/1        104,108,112,116,704
Te1/1/3        4-5,15,40,50,60,104,108,112,116,120,129,131,240,704

Port           Vlans in spanning tree forwarding state and not pruned
Gi1/0/1        104,108,112,116,704
Te1/1/3        4-5,15,40,50,60,104,108,112,116,120,129,131,240,704
""")
        self.assertEqual(trunks["Gi1/0/1"]["native_vlan"], 112)
        self.assertEqual(trunks["Te1/1/3"]["status"], "trunking")
        self.assertEqual(trunks["Gi1/0/1"]["allowed_vlans"], [104, 108, 112, 116, 704])
        # "4-5" must expand to both 4 and 5.
        self.assertIn(4, trunks["Te1/1/3"]["allowed_vlans"])
        self.assertIn(5, trunks["Te1/1/3"]["allowed_vlans"])
        self.assertEqual(len(trunks["Te1/1/3"]["allowed_vlans"]), 15)
        self.assertEqual(trunks["Te1/1/3"]["forwarding_vlans"], trunks["Te1/1/3"]["allowed_vlans"])

    def test_cisco_uplinks_come_from_trunks_carrying_the_management_vlan(self):
        stp = parse_spanning_tree_output("""
VLAN0004
  Spanning tree enabled protocol rstp
  Root ID    Priority    0
             Address     ccb6.c84e.ed80
             Port        11 (TenGigabitEthernet1/1/3)

  Bridge ID  Priority    32772  (priority 32768 sys-id-ext 4)
             Address     24d5.e414.5b80

Interface           Role Sts Cost      Prio.Nbr Type
------------------- ---- --- --------- -------- ----------------
Te1/1/3             Root FWD 20000     128.11   P2p Peer(STP)
Te1/1/4             Desg FWD 20000     128.12   P2p
""")
        trunks = parse_trunk_summary("""
Port           Mode             Encapsulation  Status        Native vlan
Gi1/0/1        on               802.1q         trunking      112
Gi1/0/2        on               802.1q         trunking      5
Te1/1/3        on               802.1q         trunking      1
Te1/1/4        on               802.1q         trunking      1

Port           Vlans allowed on trunk
Gi1/0/1        104,108,112,116,704
Gi1/0/2        5,40,50,60,120,704
Te1/1/3        4-5,15,40,50,60,104,108,112,116,120,129,131,240,704
Te1/1/4        4-5,15,40,50,60,104,108,112,116,120,129,131,240,704
""")
        self.assertEqual(stp["switch_mac"], "24d5e4145b80")
        self.assertEqual([row["vlan"] for row in stp["ports"]], [4, 4])

        verdicts = classify_uplink_ports(stp["ports"], [], trunks, management_vlan=4)
        uplinks = sorted(port for port, row in verdicts.items() if row["uplink"])
        # Only the trunks carrying VLAN 4 reach the rest of the infrastructure;
        # the access-layer trunks carry their own handful of VLANs.
        self.assertEqual(uplinks, ["Te1/1/3", "Te1/1/4"])
        self.assertIn("trunk-carries-management-vlan", verdicts["Te1/1/3"]["reasons"])
        self.assertNotIn("Gi1/0/1", uplinks)
        self.assertNotIn("Gi1/0/2", uplinks)

    def test_cisco_spanning_tree_tags_each_instance_with_its_vlan(self):
        parsed = parse_spanning_tree_output("""
VLAN0004
Interface           Role Sts Cost      Prio.Nbr Type
Te1/1/3             Root FWD 20000     128.11   P2p

VLAN0015
Interface           Role Sts Cost      Prio.Nbr Type
Te1/1/3             Root FWD 20000     128.11   P2p
Te1/1/4             Altn BLK 20000     128.12   P2p
""")
        self.assertEqual([(row["vlan"], row["port"], row["role"]) for row in parsed["ports"]],
                         [(4, "Te1/1/3", "root"), (15, "Te1/1/3", "root"), (15, "Te1/1/4", "alternate")])

    def test_vlan_range_expansion(self):
        self.assertEqual(expand_vlan_list("4-5,15,40"), [4, 5, 15, 40])
        self.assertEqual(expand_vlan_list("none"), [])
        self.assertEqual(expand_vlan_list(""), [])
        self.assertEqual(expand_vlan_list("10-8"), [])

    def test_aruba_lldp_detail_survives_its_indentation(self):
        records = parse_neighbor_detail_output("""
 LLDP Remote Device Information Detail

  Local Port   : 7
  ChassisId    : f40343-fbf3f0
  PortId       : 7
  SysName      : SITE-A-FIN-SW03
  System Descr : Aruba JL258A 2930F-8G-PoE+-2SFP+ Switch, revision WC.16.1...
  PortDescr    : 7

  System Capabilities Supported  : bridge, router
  System Capabilities Enabled    : bridge

  Remote Management Address
     Type    : ipv4
     Address : 198.51.100.38
""")
        # AOS-S indents every field; anchoring at column 0 hid the whole block.
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["local_port"], "7")
        self.assertEqual(records[0]["remote_name"], "SITE-A-FIN-SW03")
        self.assertEqual(records[0]["remote_ip"], "198.51.100.38")
        self.assertEqual(records[0]["remote_mac"], "f40343fbf3f0")

    def test_cdp_and_lldp_detail_parsing(self):
        output = """
Device ID: ACCESS-02
IP address: 192.0.2.2
Platform: cisco C9300-48P, Capabilities: Switch IGMP
Interface: GigabitEthernet1/0/48, Port ID (outgoing port): GigabitEthernet1/0/48

Local Intf: Gi1/0/47
Port id: 1/48
System Name: ACCESS-03
System Description: Aruba 2930F Switch
Management Address: 192.0.2.3
Enabled Capabilities: Bridge
"""
        rows = parse_neighbor_detail_output(output)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["remote_name"], "ACCESS-02")
        self.assertEqual(rows[0]["remote_ip"], "192.0.2.2")
        self.assertEqual(rows[1]["local_port"], "Gi1/0/47")
        self.assertEqual(rows[1]["platform"], "Aruba 2930F Switch")

    def test_mac_table_parser_handles_cisco_and_aruba(self):
        cisco = " 131    0200.0000.0025    DYNAMIC     Gi1/0/7\n"
        aruba = "020000-000025 131 7\n"
        cisco_hit = parse_mac_table_output(cisco, "02:00:00:00:00:25")[0]
        aruba_hit = parse_mac_table_output(aruba, "0200.0000.0025")[0]
        self.assertEqual((cisco_hit["vlan"], cisco_hit["port"], cisco_hit["entry_type"]), ("131", "Gi1/0/7", "DYNAMIC"))
        self.assertEqual((aruba_hit["vlan"], aruba_hit["port"]), ("131", "7"))

    def test_svi_parser_is_explicit_and_conservative(self):
        up = parse_svi_output(
            "=== 192.0.2.1 === Vlan131 is up, line protocol is up , Autostate Enabled\n"
            "Hardware is Ethernet SVI\nKeepalive not supported",
            131,
        )
        down = parse_svi_output("Virtual Ethernet 131 is administratively down, line protocol is down", 131)
        unknown = parse_svi_output("VLAN ID : 131\nName : USERS", 131)
        self.assertEqual((up["interface"], up["state"], up["parsed"]), ("Vlan131", "up", True))
        self.assertEqual((down["interface"], down["state"], down["parsed"]), ("VirtualEthernet131", "administratively-down", True))
        self.assertEqual((unknown["state"], unknown["parsed"]), ("unknown", False))

    def test_arp_parser_handles_cisco_aruba_and_fastiron_formats(self):
        output = """
Internet  192.0.2.50  3  0200.0000.0025  ARPA  Vlan131
192.0.2.51  02:00:00:00:00:26  dynamic  1/1/1
192.0.2.52  0200.0000.0027  Dynamic  1/1/12
"""
        by_ip = parse_arp_output(output, "192.0.2.51")
        by_mac = parse_arp_output(output, "02:00:00:00:00:27")
        self.assertEqual(by_ip[0]["mac"], "020000000026")
        self.assertEqual(by_ip[0]["interface"], "1/1/1")
        self.assertEqual(by_mac[0]["ip"], "192.0.2.52")

    def test_ping_parser_handles_cisco_and_unix_style_summaries(self):
        cisco = "Success rate is 80 percent (4/5), round-trip min/avg/max = 1/3/8 ms"
        unix = "5 packets transmitted, 5 received, 0% packet loss\nrtt min/avg/max/mdev = 1.0/2.5/4.0/0.2 ms"
        first = parse_ping_output(cisco, 5)
        second = parse_ping_output(unix, 5)
        self.assertEqual(first["status"], "DEGRADED")
        self.assertEqual(first["packet_loss_pct"], 20.0)
        self.assertEqual(first["avg_ms"], 3.0)
        self.assertEqual(second["status"], "REACHABLE")
        self.assertEqual(second["avg_ms"], 2.5)

    def test_ping_parser_uses_cisco_reply_marks_when_summary_is_missing(self):
        reachable = parse_ping_output("Type escape sequence to abort.\n!!!!!\n", 5)
        degraded = parse_ping_output("Type escape sequence to abort.\n!!...\n", 5)
        self.assertEqual((reachable["transmitted"], reachable["received"], reachable["status"]), (5, 5, "REACHABLE"))
        self.assertEqual((degraded["packet_loss_pct"], degraded["status"]), (60.0, "DEGRADED"))

    def test_interface_health_parser_handles_cisco_link_and_counters(self):
        output = """
GigabitEthernet1/0/12 is up, line protocol is up (connected)
  Full-duplex, 1000Mb/s, media type is 10/100/1000BaseTX
  5 minute input rate 24000 bits/sec, 12 packets/sec
  5 minute output rate 12000 bits/sec, 9 packets/sec
     3 input errors, 2 CRC, 1 frame, 0 overrun, 0 ignored
     4 output errors, 5 collisions, 0 interface resets
  Total output drops: 6
"""
        parsed = parse_interface_health_output(output)
        self.assertTrue(parsed["parsed"])
        self.assertEqual(parsed["oper_status"], "UP")
        self.assertEqual(parsed["speed_mbps"], 1000.0)
        self.assertEqual(parsed["duplex"], "FULL")
        self.assertEqual(parsed["input_bps"], 24000)
        self.assertEqual(parsed["counters"]["crc_errors"], 2)
        self.assertEqual(parsed["counters"]["output_drops"], 6)

    def test_interface_health_parser_handles_aruba_aos_switch(self):
        output = """
  Port Enabled : Yes
  Link Status  : Up
  Mode         : 1000FDx
  9            1000LX     | No        Yes     Up     1000FDx    NA   off  0
  Total Rx (bps) : 3,388,520             Total Tx (bps) : 4,959,320
  FCS Rx       : 4
  Alignment Rx : 1
  Runts Rx     : 2
  Giants Rx    : 0
  Total Rx Errors : 7
  Drops Tx     : 3
  Collisions Tx: 0
  Late Colln   : 0
"""
        parsed = parse_interface_health_output(output)
        self.assertEqual(parsed["admin_status"], "UP")
        self.assertEqual(parsed["oper_status"], "UP")
        self.assertEqual(parsed["speed_mbps"], 1000.0)
        self.assertEqual(parsed["duplex"], "FULL")
        self.assertEqual(parsed["media"], "1000LX")
        self.assertEqual(parsed["input_bps"], 3388520)
        self.assertEqual(parsed["output_bps"], 4959320)
        self.assertEqual(parsed["counters"]["crc_errors"], 4)
        self.assertEqual(parsed["counters"]["rx_errors"], 7)

    def test_interface_health_parser_handles_aruba_aos_cx_table(self):
        output = """
Interface 1/1/1 is up
Admin state is up
Link state: up for 2 days
Hardware: Ethernet, MAC Address: 02:00:00:00:00:74
Type 1GbT
Full-duplex
Speed 1000 Mb/s
Rate collection interval: 300 seconds
Rates RX TX Total (RX+TX)
Mbits / sec 3.25 1.50 4.75
Statistics RX TX Total
Packets 1000 800 1800
Dropped 2 3 5
Errors 4 5 9
CRC/FCS 4 n/a 4
Collision n/a 5 5
Runts 1 n/a 1
Giants 0 n/a 0
"""
        parsed = parse_interface_health_output(output)
        self.assertTrue(parsed["parsed"])
        self.assertEqual(parsed["interface"], "1/1/1")
        self.assertEqual((parsed["admin_status"], parsed["oper_status"]), ("UP", "UP"))
        self.assertEqual((parsed["speed_mbps"], parsed["duplex"], parsed["media"]), (1000.0, "FULL", "1GbT"))
        self.assertEqual((parsed["input_bps"], parsed["output_bps"]), (3250000, 1500000))
        self.assertEqual(parsed["counters"]["input_errors"], 4)
        self.assertEqual(parsed["counters"]["output_errors"], 5)
        self.assertEqual(parsed["counters"]["output_drops"], 3)

    def test_interface_health_parser_handles_fastiron_speed_rates_and_errors(self):
        output = """
GigabitEthernet1/1/12 is up, line protocol is up
  Configured speed auto, actual 1Gbit, configured duplex fdx, actual duplex full
  300 second input rate: 24000 bits/sec, 10 packets/sec
  300 second output rate: 12000 bits/sec, 8 packets/sec
  3 input errors, 2 CRC, 1 frame, 0 overrun, 0 ignored
  4 output errors, 5 collisions, 0 interface resets
"""
        parsed = parse_interface_health_output(output)
        self.assertTrue(parsed["parsed"])
        self.assertEqual(parsed["speed_mbps"], 1000.0)
        self.assertEqual(parsed["duplex"], "FULL")
        self.assertEqual((parsed["input_bps"], parsed["output_bps"]), (24000, 12000))
        self.assertEqual(parsed["counters"]["crc_errors"], 2)

    def test_cable_parser_distinguishes_not_run_healthy_and_fault(self):
        self.assertEqual(parse_cable_diagnostics_output("% TDR test was never run on Gi1/0/12")["status"], "NOT_RUN")
        healthy = parse_cable_diagnostics_output("Pair A 12 +/- 1 meters Pair B Normal\nPair B 12 +/- 1 meters Pair A Good")
        fault = parse_cable_diagnostics_output("Pair A 18 +/- 1 meters N/A Open\nPair B 3 +/- 1 meters N/A Short")
        self.assertEqual(healthy["status"], "HEALTHY")
        self.assertTrue(healthy["healthy"])
        self.assertEqual(fault["status"], "FAULT")
        self.assertEqual(fault["pairs"][0]["distance_m"], 18.0)

    def test_iperf_parser_uses_receiver_goodput_and_direction(self):
        payload = {
            "start": {"test_start": {"protocol": "TCP", "duration": 10, "num_streams": 2, "reverse": 1}, "connected": [{"local_host": "192.0.2.20", "remote_host": "192.0.2.1"}]},
            "end": {"sum_sent": {"retransmits": 4}, "sum_received": {"seconds": 10.1, "bytes": 125000000, "bits_per_second": 99000000}},
        }
        parsed = parse_iperf3_output(payload)
        self.assertTrue(parsed["ok"])
        self.assertEqual(parsed["direction"], "download")
        self.assertEqual(parsed["megabits_per_second"], 99.0)
        self.assertEqual(parsed["retransmits"], 4)

    def test_oui_lookup_uses_local_data_and_does_not_claim_a_model(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "oui.txt"
            path.write_text("00005E IANA\n", encoding="utf-8")
            result = lookup_oui("00:00:5e:00:53:01", [path])
        self.assertEqual(result["prefix"], "00005E")
        self.assertEqual(result["vendor"], "IANA")


if __name__ == "__main__":
    unittest.main()
