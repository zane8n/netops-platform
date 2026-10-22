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

from netops_platform import inventory_ingest, wlc
from netops_platform.ap_merge import merge_ap_scan, parse


ROOT = Path(__file__).resolve().parents[1]
T = wlc.RUCKUS_AP_TABLE

# Shapes taken from a live SmartZone 5.2 walk: the index is the MAC,
# length-prefixed; a MAC whose bytes are all printable comes back as STRING;
# a disconnected AP keeps its last IP and uptime; long values wrap.
RUCKUS_WALK = f"""\
{T}.1.6.2.0.0.0.0.1 = Hex-STRING: 02 00 00 00 00 01
{T}.1.6.66.80.45.49.50.51 = STRING: "BP-123"
{T}.1.6.2.0.0.0.0.3 = Hex-STRING: 02 00 00 00 00 03
{T}.5.6.2.0.0.0.0.1 = STRING: "SITE-A-SQ08-AP096"
{T}.5.6.66.80.45.49.50.51 = STRING: "SITE-A-H24-AP204"
{T}.5.6.2.0.0.0.0.3 = STRING: "SITE-A-H38-AP189"
{T}.6.6.2.0.0.0.0.1 = Timeticks: (44343600) 5 days, 3:10:36.00
{T}.6.6.66.80.45.49.50.51 = Timeticks: (44145500) 5 days, 2:37:35.00
{T}.6.6.2.0.0.0.0.3 = Timeticks: (71272400) 8 days, 5:58:44.00
{T}.7.6.2.0.0.0.0.1 = STRING: "5.2.2.0.2069"
{T}.8.6.2.0.0.0.0.1 = STRING: "H510"
{T}.8.6.66.80.45.49.50.51 = STRING: "H510"
{T}.8.6.2.0.0.0.0.3 = STRING: "R610"
{T}.9.6.2.0.0.0.0.1 = STRING: "SERIAL000122"
{T}.10.6.2.0.0.0.0.1 = IpAddress: 192.0.2.190
{T}.10.6.66.80.45.49.50.51 = IpAddress: 192.0.2.94
{T}.10.6.2.0.0.0.0.3 = IpAddress: 192.0.2.39
{T}.16.6.2.0.0.0.0.1 = STRING: "Connect"
{T}.16.6.66.80.45.49.50.51 = STRING: "Connect"
{T}.16.6.2.0.0.0.0.3 = STRING: "Disconnect"
{T}.17.6.2.0.0.0.0.1 = STRING: "Approved"
{T}.22.6.2.0.0.0.0.1 = STRING: "line one
continued"
"""


class RuckusWalkTest(unittest.TestCase):
    def test_every_ap_is_read_with_its_mac_from_the_index(self):
        aps = {ap.name: ap for ap in wlc.ruckus_aps(RUCKUS_WALK)}
        self.assertEqual(len(aps), 3)
        first = aps["SITE-A-SQ08-AP096"]
        self.assertEqual((first.mac, first.ip, first.model, first.serial, first.firmware, first.status, first.uptime_s),
                         ("02:00:00:00:00:01", "192.0.2.190", "H510", "SERIAL000122", "5.2.2.0.2069", "ONLINE", 443436))
        # net-snmp printed this MAC as text; the index still says what it is.
        self.assertEqual(aps["SITE-A-H24-AP204"].mac, "42:50:2d:31:32:33")
        # A disconnected AP keeps its address, but its uptime is history.
        gone = aps["SITE-A-H38-AP189"]
        self.assertEqual((gone.status, gone.uptime_s, gone.ip, gone.detail), ("OFFLINE", None, "192.0.2.39", "Disconnect"))

    def test_values_lose_their_type_labels_and_wrapped_lines_rejoin(self):
        self.assertEqual(wlc.value('STRING: "SITE-A-AP1"'), "SITE-A-AP1")
        self.assertEqual(wlc.value("IpAddress: 192.0.2.1"), "192.0.2.1")
        self.assertEqual(wlc.value("Timeticks: (44343600) 5 days, 3:10:36.00"), "44343600")
        self.assertEqual(wlc.value('""'), "")
        self.assertEqual(wlc.value("No Such Instance currently exists at this OID"), "")
        self.assertEqual(wlc.parse_walk(RUCKUS_WALK, T)["6.2.0.0.0.0.1"][22], 'STRING: "line one continued"')
        self.assertEqual(wlc.index_mac("6.2.0.0.0.0.1"), "02:00:00:00:00:01")
        self.assertEqual(wlc.index_mac("0.44.200.63.186.224"), "00:2c:c8:3f:ba:e0")
        self.assertEqual(wlc.index_mac("6.1.2"), "")

    def test_a_short_walk_is_named_and_pipe_rows_carry_the_model(self):
        self.assertEqual(wlc.completeness(175, 175), "")
        self.assertEqual(wlc.completeness(55, 175), "walk returned 55 of the 175 AP(s) the controller counts")
        self.assertEqual(wlc.completeness(3, None), "")
        rows = parse(wlc.pipe_rows(wlc.ruckus_aps(RUCKUS_WALK), controller_ip="198.51.100.252", controller="Ruckus-vSZ",
                                   vendor="Ruckus", now=1000))
        row = next(row for row in rows if row["name"] == "SITE-A-SQ08-AP096")
        self.assertEqual((row["ip"], row["platform"], row["switch_name"], row["switch_port"], row["mac"], row["status"]),
                         ("192.0.2.190", "Ruckus H510", "Ruckus-vSZ", "wireless", "020000000001", "ONLINE"))

    def test_the_helper_replaces_only_its_controllers_sidecar_rows_and_keeps_them_on_an_empty_walk(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            walk, sidecar = base / "walk.txt", base / "ap_controller.db"
            sidecar.write_text("aa:bb:cc:00:00:01|192.0.2.99|Other|OTHER-AP|192.0.2.5|R610||||||1|\n"
                               "aa:bb:cc:00:00:02|198.51.100.252|Ruckus-vSZ|STALE-AP|192.0.2.2|R610||||||1|\n", encoding="utf-8")
            walk.write_text(RUCKUS_WALK, encoding="utf-8")
            args = ["controller-aps", "--vendor", "ruckus", "--controller-ip", "198.51.100.252", "--controller", "Ruckus-vSZ",
                    "--walk", str(walk), "--sidecar", str(sidecar)]
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                self.assertEqual(inventory_ingest.main(args + ["--expected", "4"]), 3)
            self.assertEqual(len(parse(out.getvalue())), 3)
            self.assertIn("walk returned 3 of the 4 AP(s)", err.getvalue())
            names = {row["name"] for row in wlc.parse_sidecar(sidecar.read_text(encoding="utf-8"))}
            self.assertEqual(names, {"OTHER-AP", "SITE-A-SQ08-AP096", "SITE-A-H24-AP204", "SITE-A-H38-AP189"})
            before = sidecar.read_text(encoding="utf-8")
            walk.write_text("", encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(inventory_ingest.main(args + ["--expected", "175"]), 2)
            self.assertEqual(sidecar.read_text(encoding="utf-8"), before)


B = wlc.CISCO_AP_TABLE
L = wlc.CISCO_LWAPP_TABLE
# Two APs joined to a shared Catalyst 9800: ours by name, another site's.
# The index is the radio MAC; .33 is the Ethernet MAC, once printed as text.
CISCO_WALK = f"""\
{B}.3.0.44.200.63.186.224 = STRING: "SITE-AAP001"
{B}.3.2.0.0.0.0.2 = STRING: "OTHERSITEAP07"
{B}.6.0.44.200.63.186.224 = INTEGER: 1
{B}.6.2.0.0.0.0.2 = INTEGER: 3
{B}.16.0.44.200.63.186.224 = STRING: "C9136I-ROW"
{B}.17.0.44.200.63.186.224 = STRING: "SERIAL0001"
{B}.19.0.44.200.63.186.224 = IpAddress: 192.0.2.50
{B}.19.2.0.0.0.0.2 = IpAddress: 198.51.100.7
{B}.33.0.44.200.63.186.224 = Hex-STRING: 02 3D C6 D7 A7 0A
{B}.33.2.0.0.0.0.2 = STRING: "BP-123"
{L}.6.0.44.200.63.186.224 = Timeticks: (1919283000) 222 days, 3:20:30.00
{L}.7.0.44.200.63.186.224 = Timeticks: (326269200) 37 days, 18:18:12.00
"""

JOIN_9800 = """\
Number of APs: 5
Base MAC        Ethernet MAC    AP Name                           IP Address        Status      Last Failure Phase    Last Disconnect Reason
------------------------------------------------------------------------------------------------------------------------------------------
002c.c83f.bae0  023d.c6d7.a70a  SITE-AAP001                       192.0.2.50        Joined      Run                   Max Retransmission to AP
0200.0000.0002  4250.2d31.3233  OTHERSITEAP07                     198.51.100.7      Joined      Run                   DTLS close alert from peer
0200.0000.0010  0200.0000.0011  SITE-AAP_SPARE1                   192.0.2.180       Not Joined  Run                   Max Retransmission to AP
0200.0000.0020  0200.0000.0021  AP0200.0000.0021                  192.0.2.184       Not Joined  Join                  Heart beat timer expiry
0200.0000.0030  0200.0000.0031  SITE-AAP001                       192.0.2.51        Not Joined  Run                   Max Retransmission to AP
0200.0000.0040  0200.0000.0041  OTHERSITEAP99                     198.51.100.9      Not Joined  Run                   Max Retransmission to AP
"""

JOIN_AIREOS = """\
Number of APs.................................... 2

Base Mac             AP EthernetMac       AP Name           IP Address       Status
00:0b:85:57:bc:c0    02:0b:85:57:bc:c0    SITE-AAP002       192.0.2.217      Joined
00:1c:0f:81:db:80    02:1c:63:23:ac:a0    SITE-AAP003       192.0.2.216      Not joined
"""

SITE = dict(ip_prefixes=["192.0.2."], name_prefixes=["SITE-A"])


class CiscoWlcTest(unittest.TestCase):
    def test_joined_aps_carry_the_ethernet_mac_the_real_address_and_both_uptimes(self):
        aps = {ap.name: ap for ap in wlc.cisco_aps(CISCO_WALK)}
        ours = aps["SITE-AAP001"]
        self.assertEqual((ours.mac, ours.ip, ours.model, ours.serial, ours.uptime_s, ours.join_uptime_s, ours.detail),
                         ("02:3d:c6:d7:a7:0a", "192.0.2.50", "C9136I-ROW", "SERIAL0001", 19192830, 3262692, ""))
        # net-snmp printed this Ethernet MAC as text; it is still the MAC.
        self.assertEqual((aps["OTHERSITEAP07"].mac, aps["OTHERSITEAP07"].detail), ("42:50:2d:31:32:33", "downloading image"))

    def test_join_statistics_parse_in_both_formats_and_errors_are_not_aps(self):
        rows = wlc.parse_join_summary(JOIN_9800)
        self.assertEqual(len(rows), 6)
        self.assertEqual((rows[2]["name"], rows[2]["status"], rows[2]["disconnect_reason"]),
                         ("SITE-AAP_SPARE1", "Not Joined", "Max Retransmission to AP"))
        self.assertEqual(wlc.joined_count(rows), 2)
        aireos = wlc.parse_join_summary(JOIN_AIREOS)
        self.assertEqual([(row["name"], row["ethernet_mac"], row["status"]) for row in aireos],
                         [("SITE-AAP002", "02:0b:85:57:bc:c0", "Joined"), ("SITE-AAP003", "02:1c:63:23:ac:a0", "Not joined")])
        error = 'Line has invalid autocommand "show ap join stats summary all"'
        self.assertEqual(wlc.parse_join_summary(error), [])
        self.assertTrue(wlc.join_rejected(error))
        self.assertFalse(wlc.join_rejected(JOIN_9800))

    def test_unjoined_aps_leave_out_replaced_hardware_and_keep_their_last_ip_as_history(self):
        unjoined = {ap.name: ap for ap in wlc.unjoined_aps(wlc.parse_join_summary(JOIN_9800), wlc.cisco_aps(CISCO_WALK))}
        # SITE-AAP001's old hardware: the name is joined under another MAC.
        self.assertEqual(sorted(unjoined), ["AP0200.0000.0021", "OTHERSITEAP99", "SITE-AAP_SPARE1"])
        spare = unjoined["SITE-AAP_SPARE1"]
        self.assertEqual((spare.mac, spare.ip, spare.status, spare.detail),
                         ("02:00:00:00:00:11", "", "OFFLINE", "Not Joined; last failure Run Max Retransmission to AP; last IP 192.0.2.180"))
        self.assertEqual(wlc.last_ip(spare), "192.0.2.180")

    def test_the_site_filter_is_ip_or_name_and_judges_an_unjoined_ap_by_its_last_ip(self):
        aps = {ap.name: ap for ap in wlc.cisco_aps(CISCO_WALK)}
        self.assertTrue(wlc.in_scope(aps["SITE-AAP001"], **SITE))
        self.assertFalse(wlc.in_scope(aps["OTHERSITEAP07"], **SITE))
        # Default-named, so only the address says it is ours.
        default_named = wlc.ControllerAP(mac="02:00:00:00:00:21", name="AP0200.0000.0021", ip="")
        self.assertTrue(wlc.in_scope(default_named, last_ip="192.0.2.184", **SITE))
        self.assertTrue(wlc.in_scope(wlc.ControllerAP(mac="", name="SITE-A-X", ip="203.0.113.1"), **SITE))
        self.assertTrue(wlc.in_scope(aps["OTHERSITEAP07"]))

    def test_the_helper_writes_our_joined_and_unjoined_aps_and_checks_the_walk_against_join_stats(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            walk, join, sidecar = base / "walk.txt", base / "join.txt", base / "ap_controller.db"
            walk.write_text(CISCO_WALK, encoding="utf-8")
            join.write_text(JOIN_9800, encoding="utf-8")
            args = ["controller-aps", "--vendor", "cisco", "--controller-ip", "198.51.100.131", "--controller", "Cisco-WLC",
                    "--walk", str(walk), "--join-stats", str(join), "--sidecar", str(sidecar),
                    "--ip-prefixes", "192.0.2.", "--name-prefixes", "SITE-A"]
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                self.assertEqual(inventory_ingest.main(args), 0)
            rows = {row["name"]: row for row in parse(out.getvalue())}
            self.assertEqual(sorted(rows), ["AP0200.0000.0021", "SITE-AAP001", "SITE-AAP_SPARE1"])
            self.assertEqual((rows["SITE-AAP001"]["ip"], rows["SITE-AAP001"]["platform"], rows["SITE-AAP001"]["switch_port"],
                              rows["SITE-AAP001"]["mac"]), ("192.0.2.50", "Cisco C9136I-ROW", "wireless", "023dc6d7a70a"))
            self.assertEqual((rows["SITE-AAP_SPARE1"]["ip"], rows["SITE-AAP_SPARE1"]["switch_port"], rows["SITE-AAP_SPARE1"]["status"]),
                             ("wlc:020000000011", "not-joined", "OFFLINE"))
            self.assertIn("3 AP(s), 1 joined, 2 not joined; 2 other-site AP(s) left out by the filter", err.getvalue())
            side = {row["name"]: row for row in wlc.parse_sidecar(sidecar.read_text(encoding="utf-8"))}
            self.assertEqual((side["SITE-AAP001"]["uptime_s"], side["SITE-AAP001"]["join_uptime_s"]), ("19192830", "3262692"))
            self.assertIn("last IP 192.0.2.180", side["SITE-AAP_SPARE1"]["detail"])
            # A walk that stopped short of what the controller says is joined.
            walk.write_text("\n".join(line for line in CISCO_WALK.splitlines() if ".2.0.0.0.0.2 " not in line), encoding="utf-8")
            err = io.StringIO()
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
                self.assertEqual(inventory_ingest.main(args), 3)
            self.assertIn("walk returned 1 of the 2 AP(s)", err.getvalue())


class ControllerMergeTest(unittest.TestCase):
    def test_a_shared_controllers_other_site_rows_are_dropped_and_ours_kept(self):
        existing = parse("198.51.100.7|OTHERSITEAP07|Cisco-AP|198.51.100.131|Cisco-WLC|wireless||100|ONLINE\n"
                         "wlc:Line|Line|Cisco-AP|198.51.100.131|Cisco-WLC|not-joined||100|OFFLINE\n"
                         "192.0.2.60|SITE-AAP009|Cisco-AP|198.51.100.131|Cisco-WLC|wireless||100|ONLINE\n"
                         "198.51.100.8|OTHERSITEAP08|cisco C9136I-ROW|192.0.2.10|SITE-A-SW01|Gi1/0/3|020000000088|100|ONLINE")
        scope = ("Cisco-WLC", lambda row: wlc.in_scope(wlc.ControllerAP(mac="", name=row["name"], ip=row["ip"]), **SITE))
        names = [row["name"] for row in merge_ap_scan([], [], existing, scope=scope)]
        # Our AP stays (OFFLINE, unseen); one a switch found stays: the
        # filter is about the controller's list, not what is plugged in here.
        self.assertEqual(names, ["SITE-AAP009", "OTHERSITEAP08"])

    def test_a_row_recorded_without_a_mac_joins_its_fresh_controller_record(self):
        controller = parse("192.0.2.190|SITE-A-SQ08-AP096|Ruckus H510|198.51.100.252|Ruckus-vSZ|wireless|02:00:00:00:00:01|200|ONLINE")
        existing = parse("192.0.2.190|SITE-A-SQ08-AP096|Ruckus-AP|198.51.100.252|Ruckus-vSZ|wireless||100|ONLINE\n"
                         ".1.3.6.1.4.1.25|Ruckus-AP|Ruckus-AP|198.51.100.252|Ruckus-vSZ|wireless||100|OFFLINE\n"
                         "||||||||\n"
                         "192.0.2.77|SITE-A-OLD-AP|Ruckus-AP|198.51.100.252|Ruckus-vSZ|wireless||100|ONLINE")
        out = merge_ap_scan(controller, [], existing)
        names = [row["name"] for row in out]
        # One record for the AP, with its MAC and model; the OID-for-address
        # and empty rows are gone; an AP neither source saw stays, OFFLINE.
        self.assertEqual(names, ["SITE-A-SQ08-AP096", "SITE-A-OLD-AP"])
        self.assertEqual((out[0]["mac"], out[0]["platform"]), ("02:00:00:00:00:01", "Ruckus H510"))
        self.assertEqual(out[1]["status"], "OFFLINE")

    def test_a_mac_matches_in_any_notation_and_a_disowned_switch_mac_is_the_same_ap(self):
        controller = parse("192.0.2.10|SITE-A-IT-AP001|Ruckus R610|198.51.100.252|Ruckus-vSZ|wireless|020000000fd0|200|ONLINE\n"
                           "192.0.2.11|SITE-A-MINEXP-AP009|Ruckus R610|198.51.100.252|Ruckus-vSZ|wireless|020000000eb0|200|ONLINE")
        # The switch's MAC table put a client's MAC on AP009's port.
        switch = parse("192.0.2.11|SITE-A-MINEXP-AP009|Ruckus R610|198.51.100.20|SITE-A-MINEXP-SW01|7|02000000311e|200|ONLINE")
        existing = parse("192.0.2.10|SITE-A-IT-AP001|Ruckus R610|198.51.100.21|SITE-A-IT-SW01|Gi1/0/1|02:00:00:00:0F:D0|100|ONLINE\n"
                         "192.0.2.11|SITE-A-MINEXP-AP009|Ruckus R610|198.51.100.20|SITE-A-MINEXP-SW01|7|02000000311e|100|ONLINE")
        out = merge_ap_scan(controller, switch, existing)
        self.assertEqual(sorted(row["name"] for row in out), ["SITE-A-IT-AP001", "SITE-A-MINEXP-AP009"])
        rows = {row["name"]: row for row in out}
        self.assertEqual((rows["SITE-A-MINEXP-AP009"]["mac"], rows["SITE-A-MINEXP-AP009"]["switch_port"]), ("020000000eb0", "7"))
        # No switch read AP001 this scan; the controller says it is up, and
        # its last port stands.
        self.assertEqual((rows["SITE-A-IT-AP001"]["status"], rows["SITE-A-IT-AP001"]["switch_name"],
                          rows["SITE-A-IT-AP001"]["switch_port"]), ("ONLINE", "SITE-A-IT-SW01", "Gi1/0/1"))

    def test_a_switchs_port_mac_one_above_the_controllers_is_the_same_ap(self):
        from netops_platform.ap_merge import near_mac
        controller = parse("wlc:020000009d78|SITE-AAP777|Cisco-AP|198.51.100.131|Cisco-WLC|not-joined|020000009d78|200|OFFLINE")
        existing = parse("192.0.2.189|SITE-AAP777|cisco C9136I-ROW|198.51.100.94|SITE-A-SW07|Gi1/0/2|020000009d79|100|OFFLINE")
        out = merge_ap_scan(controller, [], existing)
        self.assertEqual(len(out), 1)
        self.assertEqual((out[0]["mac"], out[0]["switch_name"], out[0]["switch_port"]), ("020000009d78", "SITE-A-SW07", "Gi1/0/2"))
        self.assertTrue(near_mac("02:00:00:00:9d:78", "020000009d7a"))
        self.assertFalse(near_mac("020000009d78", "020000009d7b"))
        self.assertFalse(near_mac("02000000ffff", "020000010000"))

    def test_the_controller_mac_beats_the_switch_guess_and_old_hardware_stays_its_own_record(self):
        controller = parse("192.0.2.94|SITE-A-GH7-AP044|Ruckus R610|198.51.100.252|Ruckus-vSZ|wireless|02:00:00:00:44:10|200|ONLINE")
        switch = parse("192.0.2.94|SITE-A-GH7-AP044|Ruckus R610 Multimedia Hotzone|198.51.100.10|SITE-A-GH7-SW01|5|02:00:00:00:99:5c|200|ONLINE")
        existing = parse("192.0.2.94|SITE-A-GH7-AP044|Ruckus R610|198.51.100.10|SITE-A-GH7-SW01|5|02:00:00:00:44:20|100|ONLINE")
        out = merge_ap_scan(controller, switch, existing)
        current = next(row for row in out if row["mac"] == "02:00:00:00:44:10")
        self.assertEqual((current["switch_name"], current["switch_port"], current["platform"]), ("SITE-A-GH7-SW01", "5", "Ruckus R610"))
        replaced = next(row for row in out if row["mac"] == "02:00:00:00:44:20")
        self.assertEqual(replaced["status"], "OFFLINE")
        self.assertEqual(len(out), 2)


class ApControllerCommandTest(unittest.TestCase):
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
        self.polled = int(time.time()) - 60
        aps = wlc.ruckus_aps(RUCKUS_WALK)
        self.app.paths.aps_file.write_text(wlc.pipe_rows(aps, controller_ip="198.51.100.252", controller="Ruckus-vSZ",
                                                         vendor="Ruckus", now=self.polled), encoding="utf-8")
        self.app.paths.aps_file.with_name("ap_controller.db").write_text(wlc.render_sidecar(wlc.sidecar_rows(
            aps, controller_ip="198.51.100.252", controller="Ruckus-vSZ", now=self.polled)), encoding="utf-8")
        self.app.import_flat_state(("ap",), "test")

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def run_cli(self, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            code = self.app.dispatch(["ap", *args, "--plain", "--no-color"])
        return code, out.getvalue()

    def test_ap_controller_lists_what_the_controller_reported(self):
        code, output = self.run_cli("controller")
        self.assertEqual(code, netops.SUCCESS, output)
        self.assertIn("SITE-A-SQ08-AP096", output)
        self.assertIn("5d 3h", output)
        self.assertIn("3 AP(s), 2 connected", output)
        code, output = self.run_cli("controller", "R610", "--json")
        payload = json.loads(output)
        self.assertEqual([row["name"] for row in payload["rows"]], ["SITE-A-H38-AP189"])
        self.assertEqual((payload["rows"][0]["status"], payload["rows"][0]["uptime_s"]), ("OFFLINE", None))
        code, output = self.run_cli("controller", "disconnect", "--json")
        self.assertEqual([row["name"] for row in json.loads(output)["rows"]], ["SITE-A-H38-AP189"])
        code, output = self.run_cli("controller", "0200.0000.0001", "--json")
        row = json.loads(output)["rows"][0]
        self.assertEqual((row["mac"], row["booted_at"]), ("02:00:00:00:00:01", self.polled - 443436))
        self.assertTrue(row["booted_at_iso"])

    def test_ap_unjoined_says_where_an_ap_last_was_and_why_it_is_not_joined(self):
        joined = wlc.cisco_aps(CISCO_WALK)
        aps = [ap for ap in joined + wlc.unjoined_aps(wlc.parse_join_summary(JOIN_9800), joined)
               if wlc.in_scope(ap, last_ip=wlc.last_ip(ap), **SITE)]
        self.app.paths.aps_file.write_text(wlc.pipe_rows(aps, controller_ip="198.51.100.131", controller="Cisco-WLC",
                                                         vendor="Cisco", now=self.polled), encoding="utf-8")
        self.app.paths.aps_file.with_name("ap_controller.db").write_text(wlc.render_sidecar(wlc.sidecar_rows(
            aps, controller_ip="198.51.100.131", controller="Cisco-WLC", now=self.polled)), encoding="utf-8")
        self.app.import_flat_state(("ap",), "test")
        code, output = self.run_cli("unjoined", "--json")
        self.assertEqual(code, netops.SUCCESS, output)
        rows = {row["name"]: row for row in json.loads(output)["rows"]}
        self.assertEqual(sorted(rows), ["AP0200.0000.0021", "SITE-AAP_SPARE1"])
        self.assertEqual(rows["SITE-AAP_SPARE1"]["last_ip"], "192.0.2.180")
        self.assertIn("Max Retransmission to AP", rows["SITE-AAP_SPARE1"]["detail"])
        code, output = self.run_cli("unjoined")
        self.assertIn("192.0.2.184", output)

    def test_duration_text_reads_at_a_glance(self):
        self.assertEqual([netops.duration_text(value) for value in (443436, 15180, 540, None)], ["5d 3h", "4h 13m", "9m", ""])
