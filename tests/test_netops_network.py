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
    parse_neighbor_detail_output,
    parse_ping_output,
    parse_vlan_control_output,
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
