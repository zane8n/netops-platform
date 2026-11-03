"""The operator's network map: format, importers, correlation, write-back."""

import base64
import contextlib
import io
import json
import os
import tempfile
import time
import unittest
import urllib.parse
import xml.etree.ElementTree as ET
import zipfile
import zlib
from pathlib import Path
from unittest import mock

import netops_core as netops
from netops_platform import netmap as m

ROOT = Path(__file__).resolve().parents[1]

SAMPLE = """\
# my map
[Server room]
CORE-SW01 192.0.2.1 model=C9500
  Te1/1/1 -> DIST-A Te1/1/1
  Te1/1/2 -> DIST-B   # fibre to plant

[Admin block]
DIST-A 192.0.2.10
  Gi1/0/1-4 phone
  Gi1/0/5   ap ADMIN-AP01
  Gi1/0/6   Reception printer
  Gi1/0/7 -> SEPAABBCCDDEEFF
  Gi1/0/48 -> ACCESS-1

ACCESS-1 192.0.2.20 @"First floor" serial=FOC1
DIST-B router 192.0.2.11 @Plant workshop north
SW-X Gi1/0/1 -> SW-Y Gi1/0/2
"""


def inventory_rows():
    seen = int(time.time()) - 60
    return [
        {"kind": "device", "name": "CORE-SW01.example.net", "ip": "192.0.2.1", "addresses": ["192.0.2.1"], "model": "C9500-24Y4C",
         "serial": "FDO111", "mac": "00aa00aa00aa", "status": "ONLINE", "last_seen": seen, "canonical_id": "ip:192.0.2.1"},
        {"kind": "device", "name": "DIST-A", "ip": "192.0.2.10", "addresses": ["192.0.2.10"], "model": "C9300-48P",
         "serial": "FOC222", "status": "ONLINE", "last_seen": seen, "canonical_id": "ip:192.0.2.10"},
        {"kind": "device", "name": "DIST-B", "ip": "192.0.2.12", "addresses": ["192.0.2.12"], "model": "2930F",
         "serial": "SG333", "status": "ONLINE", "last_seen": seen, "canonical_id": "ip:192.0.2.12"},
        {"kind": "device", "name": "ACCESS-1", "ip": "192.0.2.20", "addresses": ["192.0.2.20"], "model": "C2960X",
         "serial": "FOC999", "status": "ONLINE", "last_seen": seen, "canonical_id": "ip:192.0.2.20"},
        {"kind": "device", "name": "EDGE-NEW", "ip": "192.0.2.30", "addresses": ["192.0.2.30"], "model": "C9200",
         "serial": "JAE444", "status": "ONLINE", "last_seen": seen, "canonical_id": "ip:192.0.2.30"},
        {"kind": "ap", "name": "ADMIN-AP01", "ip": "198.51.100.1", "addresses": ["198.51.100.1"], "switch_ip": "192.0.2.10",
         "switch_name": "DIST-A", "switch_port": "Gi1/0/5", "status": "ONLINE", "canonical_id": "mac:aa"},
        {"kind": "ap", "name": "ADMIN-AP02", "ip": "198.51.100.2", "addresses": ["198.51.100.2"], "switch_ip": "192.0.2.10",
         "switch_name": "DIST-A", "switch_port": "Gi1/0/9", "status": "ONLINE", "canonical_id": "mac:bb"},
    ]


def neighbours():
    return [
        {"local_ip": "192.0.2.1", "local_name": "CORE-SW01", "local_port": "TenGigabitEthernet1/1/1",
         "remote_name": "DIST-A.example.net", "remote_port": "TenGigabitEthernet1/1/1", "remote_ip": "192.0.2.10"},
        {"local_ip": "192.0.2.1", "local_name": "CORE-SW01", "local_port": "TenGigabitEthernet1/1/3",
         "remote_name": "DIST-B", "remote_port": "\"DIST-B port 49\"", "remote_ip": "?.?.?.?"},
        {"local_ip": "192.0.2.10", "local_name": "DIST-A", "local_port": "GigabitEthernet1/0/1",
         "remote_name": "SEP001122334455", "remote_port": "Port 1", "remote_ip": ""},
        {"local_ip": "192.0.2.10", "local_name": "DIST-A", "local_port": "GigabitEthernet1/0/7",
         "remote_name": "SEPAABBCCDDEEFF", "remote_port": "Port 1", "remote_ip": ""},
        {"local_ip": "192.0.2.10", "local_name": "DIST-A", "local_port": "GigabitEthernet1/0/11",
         "remote_name": "SEP0A0B0C0D0E0F", "remote_port": "Port 1", "remote_ip": ""},
        {"local_ip": "192.0.2.10", "local_name": "DIST-A", "local_port": "GigabitEthernet1/0/47",
         "remote_name": "EDGE-NEW", "remote_port": "GigabitEthernet1/1/1", "remote_ip": "192.0.2.30"},
        {"local_ip": "192.0.2.20", "local_name": "ACCESS-1", "local_port": "Gi1/1/1",
         "remote_name": "DIST-A", "remote_port": "GigabitEthernet1/0/48", "remote_ip": "192.0.2.10"},
        {"local_ip": "192.0.2.20", "local_name": "ACCESS-1", "local_port": "Gi1/1/2",
         "remote_name": "DIST-B", "remote_port": "50", "remote_ip": "192.0.2.12"},
    ]


def checked(text=SAMPLE, current=None, history=()):
    inventory = m.Inventory(inventory_rows())
    seen = m.build_seen(inventory, neighbours() if current is None else current, history)
    netmap = m.parse_map(text)
    return netmap, m.check(netmap, inventory, seen)


def finding(result, subject_start, status=None, kind=None):
    for item in result.findings:
        if item["subject"].startswith(subject_start) and (status is None or item["status"] == status) \
                and (kind is None or item["kind"] == kind):
            return item
    raise AssertionError(f"no finding {subject_start!r} {status or ''}: " + json.dumps(result.findings, indent=1))


class FormatTest(unittest.TestCase):
    def test_devices_links_and_attachments_are_read(self):
        netmap = m.parse_map(SAMPLE)
        self.assertEqual(netmap.problems, [])
        core = netmap.node("core-sw01")
        self.assertEqual((core.ip, core.location, core.fields["model"]), ("192.0.2.1", "Server room", "C9500"))
        self.assertEqual(netmap.node("ACCESS-1").location, "First floor")
        self.assertEqual(netmap.node("ACCESS-1").fields["serial"], "FOC1")
        dist_b = netmap.node("DIST-B")
        self.assertEqual((dist_b.kind, dist_b.location), ("router", "Plant workshop north"))
        self.assertTrue(netmap.node("SW-X").implicit)
        links = {(link.a, link.a_port, link.b, link.b_port) for link in netmap.links}
        self.assertIn(("CORE-SW01", "Te1/1/1", "DIST-A", "Te1/1/1"), links)
        self.assertIn(("SW-X", "Gi1/0/1", "SW-Y", "Gi1/0/2"), links)
        self.assertEqual(next(link for link in netmap.links if link.b == "DIST-B").note, "fibre to plant")
        kinds = {(item.port, item.kind, item.label) for item in netmap.attachments}
        self.assertTrue({("Gi1/0/1", "phone", ""), ("Gi1/0/4", "phone", ""), ("Gi1/0/5", "ap", "ADMIN-AP01"),
                         ("Gi1/0/6", "printer", "Reception printer")} <= kinds)
        # A cable to a phone is the phone plugged into that port.
        self.assertIn(("Gi1/0/7", "phone", "SEPAABBCCDDEEFF"), kinds)
        self.assertIsNone(netmap.node("SEPAABBCCDDEEFF"))

    def test_mistakes_are_reported_with_line_numbers(self):
        netmap = m.parse_map("  Gi1/0/1 -> CORE\nSW1\n  Gi1/0/2 ->\nSW1 192.0.2.9\n")
        self.assertTrue(any(problem.startswith("line 1:") for problem in netmap.problems))
        self.assertTrue(any(problem.startswith("line 3:") for problem in netmap.problems))
        self.assertTrue(any("already described on line 2" in problem for problem in netmap.problems))

    def test_ranges_lists_and_leading_arrows(self):
        self.assertEqual(m.expand_ports("Gi1/0/1-3"), ["Gi1/0/1", "Gi1/0/2", "Gi1/0/3"])
        self.assertEqual(m.expand_ports("1-2,5"), ["1", "2", "5"])
        self.assertEqual(m.expand_ports("Gi1/0/1"), ["Gi1/0/1"])
        netmap = m.parse_map("ACC\n  -> CORE Gi1/0/9\n")
        self.assertEqual((netmap.links[0].a_port, netmap.links[0].b, netmap.links[0].b_port), ("", "CORE", "Gi1/0/9"))

    def test_render_and_parse_round_trip(self):
        first = m.parse_map(SAMPLE)
        text = m.render_map(first, header="# map")
        self.assertIn("  Gi1/0/1-4   phone", text)
        self.assertIn("[Server room]", text)
        again = m.parse_map(text)
        self.assertEqual(again.problems, [])
        self.assertEqual(sorted((l.a, l.a_port, l.b, l.b_port) for l in again.links), sorted((l.a, l.a_port, l.b, l.b_port) for l in first.links))
        self.assertEqual(sorted((a.switch, a.port, a.kind, a.label) for a in again.attachments),
                         sorted((a.switch, a.port, a.kind, a.label) for a in first.attachments))
        self.assertEqual({k: (n.ip, n.location, n.kind) for k, n in again.nodes.items()},
                         {k: (n.ip, n.location, n.kind) for k, n in first.nodes.items()})

    def test_port_spellings_compare_equal(self):
        self.assertEqual(m.port_key("GigabitEthernet1/0/48"), m.port_key("Gi1/0/48"))
        self.assertEqual(m.port_key('"DIST-B port 49"'), m.port_key("49"))
        self.assertEqual(m.name_key("CORE-SW01.example.net"), "core-sw01")
        self.assertEqual(m.mac_key("SEPAABBCCDDEEFF"), "aabbccddeeff")
        self.assertEqual(m.guess_endpoint_kind("2nd floor printer"), "printer")
        self.assertEqual(m.guess_endpoint_kind("DRCK-SQ27AP336"), "ap")


class ImportTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_a_sheet_of_links_with_blank_device_cells(self):
        path = self.base / "links.csv"
        path.write_text("Switch,Mgmt IP,Building,Local Port,Connected To,Remote Port,Type,Description\n"
                        "CORE-SW01,192.0.2.1,Server room,Te1/1/1,DIST-A,Te1/1/1,,\n"
                        ",,,Te1/1/2,DIST-B,,,\n"
                        "DIST-A,192.0.2.10,Admin,Gi1/0/1-24,,,phone,\n"
                        ",,,Gi1/0/25,,,,Reception printer\n"
                        "DIST-B,192.0.2.11,Plant,,,,router,\n", encoding="utf-8")
        netmap = m.read_any(path)
        self.assertEqual(netmap.problems, [])
        self.assertEqual(netmap.node("CORE-SW01").ip, "192.0.2.1")
        self.assertEqual(netmap.node("CORE-SW01").location, "Server room")
        self.assertEqual(netmap.node("DIST-B").kind, "router")
        self.assertEqual(len([a for a in netmap.attachments if a.kind == "phone"]), 24)
        self.assertIn(("DIST-A", "Gi1/0/25", "printer"), {(a.switch, a.port, a.kind) for a in netmap.attachments})
        self.assertEqual({(l.a, l.a_port, l.b) for l in netmap.links}, {("CORE-SW01", "Te1/1/1", "DIST-A"), ("CORE-SW01", "Te1/1/2", "DIST-B")})

    def test_an_excel_sheet(self):
        try:
            from openpyxl import Workbook
        except ImportError:
            self.skipTest("openpyxl not installed")
        workbook = Workbook()
        workbook.active.title = "Notes"
        workbook.active.append(["nothing here"])
        sheet = workbook.create_sheet("Uplinks")
        sheet.append(["Device", "Port", "Neighbour", "Neighbour Port"])
        sheet.append(["ACC-1", "Gi1/1/1", "CORE", "Gi1/0/3"])
        path = self.base / "map.xlsx"
        workbook.save(path)
        netmap = m.read_any(path)
        self.assertEqual([(l.a, l.a_port, l.b, l.b_port) for l in netmap.links], [("ACC-1", "Gi1/1/1", "CORE", "Gi1/0/3")])

    DRAWIO = """<mxfile><diagram name="Page-1"><mxGraphModel><root>
      <mxCell id="0"/><mxCell id="1" parent="0"/>
      <mxCell id="room" value="Server room" style="swimlane;container=1;" vertex="1" parent="1"/>
      <mxCell id="core" value="CORE-SW01&lt;br&gt;192.0.2.1" style="shape=mxgraph.cisco.switches.layer_3_switch;" vertex="1" parent="room"/>
      <object id="dist" label="DIST-A" ip="192.0.2.10" serial="FOC222"><mxCell style="rounded=1;" vertex="1" parent="1"/></object>
      <mxCell id="ph" value="Reception phone" style="shape=mxgraph.cisco.misc.ip_phone;" vertex="1" parent="1"/>
      <mxCell id="title" value="Site network" style="text;" vertex="1" parent="1"/>
      <mxCell id="e1" value="" style="endArrow=none;" edge="1" parent="1" source="core" target="dist"/>
      <mxCell id="l1" value="Te1/1/1" style="edgeLabel;" vertex="1" connectable="0" parent="e1"><mxGeometry x="-0.8" relative="1" as="geometry"/></mxCell>
      <mxCell id="l2" value="Te1/1/2" style="edgeLabel;" vertex="1" connectable="0" parent="e1"><mxGeometry x="0.8" relative="1" as="geometry"/></mxCell>
      <mxCell id="e2" value="Gi1/0/5" edge="1" parent="1" source="dist" target="ph"/>
      <mxCell id="e3" value="Gi1/0/48 - Gi1/1/1" edge="1" parent="1" source="dist" target="acc"/>
      <mxCell id="acc" value="ACCESS-1" vertex="1" parent="1"/>
    </root></mxGraphModel></diagram></mxfile>"""

    def test_a_drawio_diagram(self):
        path = self.base / "site.drawio"
        path.write_text(self.DRAWIO, encoding="utf-8")
        netmap = m.read_any(path)
        core = netmap.node("CORE-SW01")
        self.assertEqual((core.ip, core.location), ("192.0.2.1", "Server room"))
        self.assertEqual(netmap.node("DIST-A").fields["serial"], "FOC222")
        self.assertEqual(netmap.node("DIST-A").ip, "192.0.2.10")
        self.assertIsNone(netmap.node("Site network"))
        links = {(l.a, l.a_port, l.b, l.b_port) for l in netmap.links}
        self.assertEqual(links, {("CORE-SW01", "Te1/1/1", "DIST-A", "Te1/1/2"), ("DIST-A", "Gi1/0/48", "ACCESS-1", "Gi1/1/1")})
        self.assertEqual([(a.switch, a.port, a.kind, a.label) for a in netmap.attachments], [("DIST-A", "Gi1/0/5", "phone", "Reception phone")])

    def test_a_compressed_drawio_page(self):
        model = self.DRAWIO.split("<diagram name=\"Page-1\">")[1].split("</diagram>")[0]
        compressor = zlib.compressobj(9, zlib.DEFLATED, -15)
        payload = base64.b64encode(compressor.compress(urllib.parse.quote(model).encode()) + compressor.flush()).decode()
        path = self.base / "site.drawio"
        path.write_text(f'<mxfile><diagram name="Page-1">{payload}</diagram></mxfile>', encoding="utf-8")
        self.assertEqual(len(m.read_any(path).links), 2)

    def test_a_visio_drawing(self):
        ns = "http://schemas.microsoft.com/office/visio/2012/main"
        page = f"""<PageContents xmlns="{ns}"><Shapes>
          <Shape ID="1" Master="2"><Section N="Property"><Row N="IPAddress"><Cell N="Value" V="192.0.2.1"/></Row></Section><Text>CORE-SW01</Text></Shape>
          <Shape ID="2" Master="2" Type="Group"><Shapes><Shape ID="3"><Text>DIST-A</Text></Shape></Shapes></Shape>
          <Shape ID="4" Master="3"><Text>Desk phone</Text></Shape>
          <Shape ID="5" Master="1"><Text>Te1/1/1 - Te1/1/2</Text></Shape>
          <Shape ID="6" Master="1"><Text>Gi1/0/3</Text></Shape>
        </Shapes><Connects>
          <Connect FromSheet="5" FromCell="BeginX" ToSheet="1"/><Connect FromSheet="5" FromCell="EndX" ToSheet="3"/>
          <Connect FromSheet="6" FromCell="BeginX" ToSheet="2"/><Connect FromSheet="6" FromCell="EndX" ToSheet="4"/>
        </Connects></PageContents>"""
        masters = f"""<Masters xmlns="{ns}"><Master ID="1" NameU="Dynamic connector"/><Master ID="2" NameU="Layer 3 switch"/>
          <Master ID="3" NameU="IP phone"/></Masters>"""
        path = self.base / "site.vsdx"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("visio/pages/page1.xml", page)
            archive.writestr("visio/masters/masters.xml", masters)
        netmap = m.read_any(path)
        self.assertEqual(netmap.node("CORE-SW01").ip, "192.0.2.1")
        self.assertEqual({(l.a, l.a_port, l.b, l.b_port) for l in netmap.links}, {("CORE-SW01", "Te1/1/1", "DIST-A", "Te1/1/2")})
        self.assertEqual([(a.switch, a.port, a.kind) for a in netmap.attachments], [("DIST-A", "Gi1/0/3", "phone")])

    def test_pictures_are_refused_with_a_way_forward(self):
        path = self.base / "map.png"
        path.write_bytes(b"\x89PNG")
        with self.assertRaisesRegex(m.MapError, "text format"):
            m.read_any(path)


class CheckTest(unittest.TestCase):
    def test_devices_are_matched_and_differences_named(self):
        _, result = checked()
        self.assertEqual(finding(result, "CORE-SW01", kind="device")["status"], "OK")
        dist_b = finding(result, "DIST-B", "DIFFERENT")
        self.assertIn("IP 192.0.2.11 on the map, 192.0.2.12 found", dist_b["hint"])
        access = finding(result, "ACCESS-1", "DIFFERENT")
        self.assertIn("serial FOC1 on the map, FOC999 found (replaced?)", access["hint"])
        self.assertEqual(finding(result, "SW-X", kind="device")["status"], "NO MATCH")

    def test_a_typo_gets_a_suggestion(self):
        _, result = checked("DIST-AA\n")
        self.assertIn("did you mean DIST-A?", finding(result, "DIST-AA")["hint"])

    def test_links_agree_differ_or_go_unseen(self):
        _, result = checked()
        self.assertEqual(finding(result, "CORE-SW01 Te1/1/1 -> DIST-A")["status"], "OK")
        # The map says Te1/1/2; LLDP shows the cable on Te1/1/3 (Aruba's
        # '"DIST-B port 49"' remote port spelling included).
        moved = finding(result, "CORE-SW01 Te1/1/2 -> DIST-B")
        self.assertEqual(moved["status"], "DIFFERENT")
        self.assertIn("CORE-SW01 Te1/1/3 -> DIST-B 49", moved["network"])
        # Seen from the far side only (ACCESS-1 reports DIST-A).
        self.assertEqual(finding(result, "DIST-A Gi1/0/48 -> ACCESS-1")["status"], "OK")

    def test_a_link_with_no_current_evidence_is_stale_or_unknown(self):
        history = [{"local_ip": "192.0.2.1", "local_name": "CORE-SW01", "local_port": "Te1/1/1", "remote_name": "DIST-A",
                    "remote_ip": "192.0.2.10", "remote_port": "Te1/1/1", "last_seen": 1_700_000_000}]
        _, result = checked("CORE-SW01\n  Te1/1/1 -> DIST-A Te1/1/1\n  Te1/1/4 -> ACCESS-1\n", current=[], history=history)
        self.assertEqual(finding(result, "CORE-SW01 Te1/1/1")["status"], "STALE")
        self.assertEqual(finding(result, "CORE-SW01 Te1/1/4")["status"], "UNKNOWN")

    def test_a_scanned_switch_that_does_not_show_the_link(self):
        _, result = checked("CORE-SW01\n  Te1/1/8 -> ACCESS-1\nACCESS-1\n")
        self.assertEqual(finding(result, "CORE-SW01 Te1/1/8")["status"], "NOT SEEN")

    def test_a_port_that_leads_elsewhere(self):
        _, result = checked("CORE-SW01\n  Te1/1/1 -> ACCESS-1\nACCESS-1\nDIST-A\n")
        item = finding(result, "CORE-SW01 Te1/1/1 -> ACCESS-1")
        self.assertEqual(item["status"], "DIFFERENT")
        self.assertIn("DIST-A", item["network"])

    def test_aps_and_phones(self):
        _, result = checked()
        self.assertEqual(finding(result, "DIST-A Gi1/0/5 ap")["status"], "OK")
        self.assertEqual(finding(result, "DIST-A Gi1/0/1 phone")["status"], "OK")
        self.assertEqual(finding(result, "DIST-A Gi1/0/2 phone")["status"], "NOT SEEN")
        self.assertEqual(finding(result, "DIST-A Gi1/0/7 phone")["status"], "OK")
        self.assertEqual(finding(result, "DIST-A Gi1/0/6 printer")["status"], "UNKNOWN")
        _, result = checked("DIST-A\n  Gi1/0/5 ap OTHER-AP\n")
        self.assertEqual(finding(result, "DIST-A Gi1/0/5 ap")["status"], "DIFFERENT")

    def test_what_the_network_shows_beyond_the_map(self):
        _, result = checked()
        # ACCESS-1 Gi1/1/2 -> DIST-B: both mapped, cable not on the map.
        extra = finding(result, "ACCESS-1 Gi1/1/2 -> DIST-B", "NOT ON MAP")
        self.assertIn("map update", extra["hint"])
        self.assertEqual([entry["name"] for entry in result.unmapped_neighbors], ["EDGE-NEW"])
        self.assertEqual({(entry["port"], entry["kind"]) for entry in result.endpoints},
                         {("Gi1/0/11", "phone"), ("Gi1/0/9", "ap")})
        self.assertGreater(result.attention, 0)

    def test_arubas_double_lldp_entry_keeps_the_interface(self):
        # One Aruba port, the same Cisco neighbour twice: by name with its
        # interface, and by chassis MAC with an escaped port description.
        rows = [{"local_ip": "192.0.2.12", "local_name": "DIST-B", "local_port": "9", "remote_name": "ACCESS-1.example.net",
                 "remote_port": "GigabitEthernet1/1/2", "remote_ip": "192.0.2.20"},
                {"local_ip": "192.0.2.12", "local_name": "DIST-B", "local_port": "9", "remote_name": "ACCESS-1",
                 "remote_port": '\\"ACCESS-1 port 9\\"', "remote_ip": ""}]
        inventory = m.Inventory(inventory_rows())
        seen = m.build_seen(inventory, rows)
        self.assertEqual([(item.a_port, item.b_port) for item in seen], [("9", "Gi1/1/2")])

    def test_an_ap_seen_through_an_uplink_is_not_offered_for_that_port(self):
        rows = inventory_rows()
        rows[-1]["switch_port"] = "Gi1/0/47"  # where EDGE-NEW hangs off DIST-A
        inventory = m.Inventory(rows)
        result = m.check(m.parse_map("DIST-A\n"), inventory, m.build_seen(inventory, neighbours()))
        self.assertNotIn("Gi1/0/47", [entry["port"] for entry in result.endpoints])

    def test_spanning_tree_does_not_vouch_for_a_port_lldp_contradicts(self):
        stp = [{"local_ip": "192.0.2.1", "local_name": "CORE-SW01", "local_port": "Te1/1/1", "remote_name": "DIST-A",
                "remote_ip": "192.0.2.10", "remote_port": "", "last_seen": int(time.time())}]
        inventory = m.Inventory(inventory_rows())
        seen = m.build_seen(inventory, neighbours(), (), stp)
        result = m.check(m.parse_map("CORE-SW01\n  Te1/1/1 -> DIST-A Te1/1/9\n  Te1/1/7 -> DIST-A\n"), inventory, seen)
        far = finding(result, "CORE-SW01 Te1/1/1 -> DIST-A Te1/1/9")
        self.assertEqual(far["status"], "DIFFERENT")
        self.assertIn("DIST-A Te1/1/1 (lldp/cdp)", far["network"])
        self.assertEqual(finding(result, "CORE-SW01 Te1/1/7")["status"], "DIFFERENT")

    def test_the_name_outranks_a_mistyped_ip(self):
        # 192.0.2.20 is ACCESS-1's address; the map's DIST-A line has it by mistake.
        _, result = checked("DIST-A 192.0.2.20\nCORE-SW01\n  Te1/1/1 -> DIST-A Te1/1/1\n")
        device = finding(result, "DIST-A", kind="device")
        self.assertEqual(device["status"], "DIFFERENT")
        self.assertIn("IP 192.0.2.20 on the map (that address is ACCESS-1), 192.0.2.10 found", device["hint"])
        self.assertEqual(finding(result, "CORE-SW01 Te1/1/1 -> DIST-A")["status"], "OK")

    def test_two_map_entries_for_one_device(self):
        _, result = checked("CORE-SW01\nCORE 192.0.2.1\n")
        self.assertIn("the same device as CORE-SW01", finding(result, "CORE", "DIFFERENT")["hint"])


class WriteBackTest(unittest.TestCase):
    def test_update_fills_blanks_adds_links_and_keeps_the_operators_lines(self):
        text = "# my notes stay\nCORE-SW01  # the core\n  Te1/1/1 -> DIST-A   # fibre\n\nDIST-A 192.0.2.10 @Admin\nACCESS-1\n  Gi1/1/1 -> DIST-A\n"
        netmap, result = checked(text)
        edits = m.plan_update(netmap, result, stamp="netrune TEST")
        after = m.apply_edits(netmap, edits, section="# --- added ---")
        lines = after.splitlines()
        self.assertEqual(lines[0], "# my notes stay")
        self.assertTrue(lines[1].startswith("CORE-SW01 192.0.2.1 model=C9500-24Y4C serial=FDO111 mac=00:aa:00:aa:00:aa"))
        self.assertTrue(lines[1].endswith("# the core"))
        # The far-end port the map left blank, filled in place: spacing and comment kept.
        self.assertEqual(lines[2], "  Te1/1/1 -> DIST-A Te1/1/1   # fibre")
        self.assertIn("DIST-A 192.0.2.10 model=C9300-48P serial=FOC222 @Admin", after)
        # The link's ports, which the map left blank, from the one cable LLDP shows.
        self.assertIn("  Gi1/1/1 -> DIST-A Gi1/0/48", after)
        self.assertNotIn("EDGE-NEW", after)
        again = m.parse_map(after)
        self.assertEqual(again.problems, [])
        # A second run has nothing left to do.
        _, second = checked(after)
        self.assertEqual(m.apply_edits(again, m.plan_update(again, second, stamp="netrune TEST")), after)

    def test_update_adds_neighbours_and_endpoints_only_when_asked(self):
        netmap, result = checked("DIST-A\nCORE-SW01\n  Te1/1/1 -> DIST-A Te1/1/1\n")
        after = m.apply_edits(netmap, m.plan_update(netmap, result, add_new=True, attachments=True, stamp="netrune TEST"),
                              section="# --- added ---")
        self.assertIn("\nEDGE-NEW 192.0.2.30 model=C9200 serial=JAE444  # netrune TEST: next to DIST-A\n"
                      "  Gi1/1/1     -> DIST-A Gi1/0/47\n", after)
        # DIST-B is not on this map either: it hangs off CORE-SW01, on Aruba port 49.
        self.assertIn("\nDIST-B 192.0.2.12 model=2930F serial=SG333  # netrune TEST: next to CORE-SW01\n"
                      "  49          -> CORE-SW01 Te1/1/3\n", after)
        self.assertIn("  Gi1/0/11    phone SEP0A0B0C0D0E0F  # netrune TEST", after)
        self.assertIn("ap ADMIN-AP02  # netrune TEST", after)
        self.assertEqual(m.parse_map(after).problems, [])

    def test_overwrite_replaces_differing_values(self):
        netmap, result = checked("DIST-B 192.0.2.11\n")
        self.assertNotIn("192.0.2.12", m.apply_edits(netmap, m.plan_update(netmap, result)))
        self.assertIn("DIST-B 192.0.2.12", m.apply_edits(netmap, m.plan_update(netmap, result, overwrite=True)))

    def test_an_import_merges_into_the_existing_map(self):
        current = m.parse_map("CORE-SW01 192.0.2.1  # mine\n  Te1/1/1 -> DIST-A Te1/1/1\n")
        incoming = m.parse_map("CORE-SW01 @Server room serial=FDO111\n  Te1/1/1 -> DIST-A Te1/1/1\n  Te1/1/2 -> DIST-B\n"
                               "DIST-B 192.0.2.12\n  Gi1/0/1-2 phone\n")
        after = m.apply_edits(current, m.plan_merge(current, incoming, stamp="netrune import TEST"), section="# --- imported ---")
        self.assertTrue(after.startswith("CORE-SW01 192.0.2.1 serial=FDO111 @\"Server room\"  # mine\n  Te1/1/1 -> DIST-A Te1/1/1\n"
                                         "  Te1/1/2     -> DIST-B  # netrune import TEST\n"))
        self.assertIn("# --- imported ---\nDIST-B 192.0.2.12  # netrune import TEST\n  Gi1/0/1     phone\n  Gi1/0/2     phone", after)
        self.assertNotIn("\nDIST-A", after)  # only named by links, here and in the import
        self.assertEqual(after.count("Te1/1/1 -> DIST-A"), 1)
        merged = m.parse_map(after)
        self.assertEqual(merged.problems, [])
        self.assertEqual(m.plan_merge(merged, incoming), [])

    def test_drawio_export_reads_back_as_the_same_map(self):
        netmap, result = checked()
        text = m.to_drawio(netmap, result)
        ET.fromstring(text)
        again = m.from_drawio(text)
        # The map's links, plus the one the check found that the map lacks.
        self.assertEqual({(l.a, l.a_port, l.b, l.b_port) for l in again.links},
                         {(l.a, l.a_port, l.b, l.b_port) for l in netmap.links} | {("ACCESS-1", "Gi1/1/2", "DIST-B", "50")})

    def test_csv_export_reads_back(self):
        netmap = m.parse_map(SAMPLE)
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "map.csv"
            path.write_text(m.to_csv(netmap), encoding="utf-8")
            again = m.read_any(path)
        self.assertEqual(sorted((l.a, l.a_port, l.b, l.b_port) for l in again.links), sorted((l.a, l.a_port, l.b, l.b_port) for l in netmap.links))
        self.assertEqual(len(again.attachments), len(netmap.attachments))
        self.assertEqual(again.node("DIST-B").location, "Plant workshop north")


class MapCommandTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        base = Path(self.temp.name)
        self.base = base
        self.env = mock.patch.dict(os.environ, {
            "NETOPS_CONFIG_DIR": str(base / "config"), "NETOPS_CACHE_DIR": str(base / "cache"),
            "NETOPS_STATE_DIR": str(base / "state"), "NETOPS_DATA_DIR": str(base / "data"),
            "NETOPS_SQLITE_DB": str(base / "cache" / "netops.sqlite3"), "NETOPS_BACKUP_DIR": str(base / "backups"),
            "NETOPS_PROGRESS": "0",
        }, clear=False)
        self.env.start()
        self.app = netops.App(ROOT)
        seen = int(time.time()) - 60
        for ip, name, model, serial in (("192.0.2.1", "SITE-A-CORE-01", "C9500", "FDO1"), ("192.0.2.10", "SITE-A-DIST-01", "C9300", "FOC2"),
                                        ("192.0.2.20", "SITE-A-ACC-01", "2930F", "SG3")):
            self.app.state.execute("INSERT INTO devices(ip,hostname,platform,model,serial,mac,source,last_seen,status) VALUES(?,?,?,?,?,?,?,?,?)",
                                   (ip, name, "Cisco IOS", model, serial, "", "SSH", seen, "ONLINE"))
        for row in (("192.0.2.1", "SITE-A-CORE-01", "Te1/1/1", "SITE-A-DIST-01.example.net", "Te1/1/1", "192.0.2.10"),
                    ("192.0.2.10", "SITE-A-DIST-01", "Gi1/0/48", "SITE-A-ACC-01", "49", "192.0.2.20"),
                    ("192.0.2.10", "SITE-A-DIST-01", "Gi1/0/3", "SEP001122334455", "Port 1", "")):
            self.app.state.execute("INSERT INTO neighbors(local_ip,local_name,local_port,remote_name,remote_port,remote_ip) VALUES(?,?,?,?,?,?)", row)

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def run_cli(self, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            code = self.app.dispatch([*args, "--plain", "--no-color"])
        return code, out.getvalue()

    def test_without_a_map_every_verb_says_how_to_start(self):
        for verb in ("show", "check"):
            code, output = self.run_cli("map", verb)
            self.assertEqual(code, netops.SUCCESS, output)
            self.assertIn("netrune map init --from-network", output)

    def test_draft_check_update_round(self):
        code, output = self.run_cli("map", "init", "--from-network", "--dry-run")
        self.assertEqual(code, netops.SUCCESS, output)
        self.assertIn("3 switch(es), 2 link(s)", output)
        self.assertFalse(Path(self.app.paths.config_dir, "network-map.txt").exists())
        code, output = self.run_cli("map", "init", "--from-network")
        self.assertEqual(code, netops.SUCCESS, output)
        path = Path(self.app.paths.config_dir) / "network-map.txt"
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        code, output = self.run_cli("map", "check")
        self.assertEqual(code, netops.SUCCESS, output)
        self.assertIn("0 item(s) disagree", output)
        # A replaced switch and a moved cable, written by hand.
        text = path.read_text().replace("serial=FOC2", "serial=OLD9").replace("Gi1/0/48    -> SITE-A-ACC-01", "Gi1/0/47    -> SITE-A-ACC-01")
        path.write_text(text)
        code, output = self.run_cli("map", "check")
        self.assertEqual(code, netops.PARTIAL, output)
        self.assertIn("serial OLD9 on the map, FOC2 found (replaced?)", output)
        self.assertIn("same two devices, different port(s)", output)
        items = self.app.attention_payload()["items"]
        self.assertTrue(any(item["kind"] == "map" and "2 item(s) disagree" in item["text"] for item in items))
        code, output = self.run_cli("map", "update", "--attachments", "--overwrite")
        self.assertEqual(code, netops.CONFIRM_REQUIRED, output)
        self.assertIn("+  Gi1/0/3     phone SEP001122334455", output)
        self.assertEqual(path.read_text(), text)
        code, output = self.run_cli("map", "update", "--attachments", "--overwrite", "--confirm")
        self.assertEqual(code, netops.SUCCESS, output)
        self.assertIn("Previous map backed up to", output)
        self.assertIn("serial=FOC2", path.read_text())
        events = self.app.state.rows("SELECT action FROM audit_events WHERE event_type='map' ORDER BY id")
        self.assertEqual([row["action"] for row in events], ["map-init", "map-update"])

    def test_import_preview_then_confirm(self):
        source = self.base / "links.csv"
        source.write_text("device,ip,port,connects to,remote port\nSITE-A-CORE-01,192.0.2.1,Te1/1/1,SITE-A-DIST-01,Te1/1/1\n"
                          "SITE-A-DIST-01,,Gi1/0/48,SITE-A-ACC-01,49\n", encoding="utf-8")
        code, output = self.run_cli("map", "import", str(source), "--dry-run")
        self.assertEqual(code, netops.SUCCESS, output)
        self.assertIn("Read links.csv: 3 device(s), 2 link(s)", output)
        self.assertFalse((Path(self.app.paths.config_dir) / "network-map.txt").exists())
        code, output = self.run_cli("map", "import", str(source), "--confirm")
        self.assertEqual(code, netops.SUCCESS, output)
        code, output = self.run_cli("map", "check", "--json")
        payload = json.loads(output)
        self.assertEqual(payload["attention"], 0, output)
        self.assertEqual(payload["counts"]["OK"], 5)
        code, output = self.run_cli("map", "show", "SITE-A-DIST-01")
        self.assertIn("Linked from:", output)
        self.assertIn("SITE-A-CORE-01 Te1/1/1 -> Te1/1/1", output)

    def test_check_a_file_without_importing_it(self):
        other = self.base / "plan.txt"
        other.write_text("SITE-A-CORE-01\n  Te1/1/9 -> SITE-A-DIST-01\n", encoding="utf-8")
        code, output = self.run_cli("map", "check", "--file", str(other))
        self.assertEqual(code, netops.PARTIAL, output)
        self.assertIn("same two devices, different port(s)", output)
        self.assertEqual(self.app.state.get_marker("map_check_last"), "")

    def test_export_csv_and_drawio(self):
        self.run_cli("map", "init", "--from-network")
        for name in ("map.csv", "map.drawio"):
            code, output = self.run_cli("map", "export", str(self.base / name))
            self.assertEqual(code, netops.SUCCESS, output)
        self.assertTrue((self.base / "map.csv").read_text().startswith("device,kind,ip,location"))
        self.assertEqual(len(m.read_any(self.base / "map.drawio").links), 2)
        code, output = self.run_cli("map", "export", str(self.base / "map.csv"))
        self.assertEqual(code, netops.CONFIRM_REQUIRED)

    def test_the_weekly_workflow_reviews_topology_and_the_map(self):
        steps = [item["id"] for item in self.app.workflow_manifest("weekly")["steps"]]
        self.assertEqual(steps[-3:], ["topology-changes", "map-check", "attention"])
        command = next(item["command"] for item in self.app.workflow_manifest("weekly")["steps"] if item["id"] == "map-check")
        self.assertEqual(command[1:], ["map", "check"])

    def test_topology_changes_since_names_a_mass_removal(self):
        now = int(time.time())
        for index in range(120):
            self.app.state.execute("INSERT INTO topology_events(created_at,event_type,local_ip,local_port,remote_name,remote_port,remote_ip,detail) "
                                   "VALUES(?,?,?,?,?,?,?,?)", (now - 3600, "link_removed", "192.0.2.1", f"Gi1/0/{index}", "X", "Y", "", "gone"))
        self.app.state.execute("INSERT INTO topology_events(created_at,event_type,local_ip,local_port,remote_name,remote_port,remote_ip,detail) "
                               "VALUES(?,?,?,?,?,?,?,?)", (now - 30 * 86400, "link_added", "192.0.2.1", "Gi1/0/1", "X", "Y", "", "old"))
        code, output = self.run_cli("topology", "changes", "--since", "7d", "--limit", "3")
        self.assertEqual(code, netops.SUCCESS, output)
        self.assertIn("0 link(s) added, 120 removed on 1 switch(es)", output)
        self.assertIn("120 links vanished in one scan", output)
        self.assertIn("117 more", output)
        code, output = self.run_cli("topology", "changes", "--since", "soon")
        self.assertEqual(code, netops.VALIDATION)
        self.assertNotIn("net", output.splitlines()[0])
        # Every vanished link comes back with the next good scan: no net change.
        for index in range(120):
            self.app.state.execute("INSERT INTO topology_events(created_at,event_type,local_ip,local_port,remote_name,remote_port,remote_ip,detail) "
                                   "VALUES(?,?,?,?,?,?,?,?)", (now - 60, "link_added", "192.0.2.1", f"Gi1/0/{index}", "X", "Y", "", "back"))
        code, output = self.run_cli("topology", "changes", "--since", "7d", "--json")
        payload = json.loads(output)
        self.assertEqual((payload["added"], payload["removed"], payload["net_added"], payload["net_removed"]), (120, 120, 0, 0))
        self.assertIn("; net 0 added, 0 removed", payload["summary"])


if __name__ == "__main__":
    unittest.main()
