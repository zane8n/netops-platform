import contextlib
import hashlib
import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import netops_core as netops

try:
    import openpyxl
    from openpyxl.chart import BarChart, Reference
    from openpyxl.worksheet.table import Table
except ImportError:  # pragma: no cover - environment dependent
    openpyxl = None

from netops_platform import excel


ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


@unittest.skipUnless(openpyxl, "openpyxl is not installed")
class ExcelSyncTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.env = mock.patch.dict(os.environ, {
            "NETOPS_CONFIG_DIR": str(self.base / "config"),
            "NETOPS_CACHE_DIR": str(self.base / "cache"),
            "NETOPS_STATE_DIR": str(self.base / "state"),
            "NETOPS_DATA_DIR": str(self.base / "data"),
            "NETOPS_SQLITE_DB": str(self.base / "cache" / "netops.sqlite3"),
            "NETOPS_BACKUP_DIR": str(self.base / "backups"),
            "NETOPS_PROGRESS": "0",
        }, clear=False)
        self.env.start()
        self.app = netops.App(ROOT)
        devices = [
            ("192.0.2.10", "SITE-A-CORE-SW01.site.example.com", "Cisco IOS", "C9200-24PXG", "FVH0000AA01", "02a9b8070c00", "ONLINE"),
            ("192.0.2.11", "SITE-A-BLDG2-SW01", "Aruba AOS-S", "2930F-8G-PoE+-2SFP+", "CN00TEST01", "02c1c7b9aa40", "ONLINE"),
            ("192.0.2.12", "SITE-A-PUMP-SW01", "Cisco IOS", "WS-C3560CX-8PC-S", "FOC0000BB02", "02eb34dab580", "OFFLINE"),
        ]
        for ip, name, platform, model, serial, mac, status in devices:
            self.app.state.execute(
                "INSERT INTO devices(ip,hostname,platform,model,serial,mac,source,last_seen,status) VALUES(?,?,?,?,?,?,?,?,?)",
                (ip, name, platform, model, serial, mac, "SSH+SNMP", 1_790_000_000, status),
            )

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def register(self, name="register.xlsx", rows=None, extra=None):
        wb = openpyxl.Workbook()
        ws = wb.active
        ws.title = "Switches"
        ws["A1"] = "Switch register"
        ws.append([])
        ws.append(["Device Name", "Mgmt IP", "Model", "S/N", "MAC Address", "Vendor", "Status", "Label"])
        rows = rows if rows is not None else [
            ("SITE-A-CORE-SW01", "192.0.2.10", "C9200", None, "02A9.B807.FFFF", "Cisco", "In service"),
            (None, "192.0.2.11", None, None, None, None, "In service"),
            ("OLD-PUMP-NAME", "192.0.2.12", None, "FOC0000BB02", None, None, "Spare"),
            ("SITE-A-BLDG2-SW01", "192.0.2.10", None, None, None, None, "In service"),
            ("UNKNOWN-SW99", "198.51.100.99", None, None, None, None, "In stock"),
        ]
        for number, row in enumerate(rows, start=4):
            ws.append(list(row) + [f'=A{number}&" ("&B{number}&")"'])
        ws.add_table(Table(displayName="Register", ref=f"A3:H{3 + len(rows)}"))
        wb.create_sheet("Notes")["A1"] = "keep me"
        if extra:
            extra(wb)
        path = self.base / name
        wb.save(path)
        return path

    def run_cli(self, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            code = self.app.dispatch(["excel", *map(str, args), "--plain", "--no-color"])
        return code, out.getvalue()

    def plan(self, path, **kwargs):
        wb = excel.load_workbook(path)
        ws = wb["Switches"]
        layout = excel.detect_layout(ws)
        devices = [row for row in self.app.inventory_rows("", netops.GlobalOptions(limit=1000)) if row.get("kind") == "device"]
        return wb, excel.plan_sheet(ws, layout, excel.DeviceIndex.build(devices), **kwargs)

    def test_header_row_and_columns_are_found_below_a_title(self):
        wb = excel.load_workbook(self.register())
        layout = excel.detect_layout(wb["Switches"])
        self.assertEqual(layout.header_row, 3)
        self.assertEqual(layout.columns, {"hostname": 1, "ip": 2, "model": 3, "serial": 4, "mac": 5, "platform": 6, "status": 7})
        self.assertEqual(layout.mac_format, ("dotted", True))
        self.assertIsNone(excel.detect_layout(wb["Notes"]))
        remapped = excel.detect_layout(wb["Switches"], excel.parse_column_map("H=hostname"))
        self.assertEqual(remapped.columns["hostname"], 8)

    def test_rows_match_by_their_strongest_agreeing_keys(self):
        _, plan = self.plan(self.register())
        changes = {(change.row, change.field): change for change in plan.changes}
        # Name and IP agree: model and serial are filled, the stale MAC is
        # rewritten in the column's own dotted upper-case notation.
        self.assertEqual(changes[(4, "model")].new, "C9200-24PXG")
        self.assertEqual(changes[(4, "mac")].new, "02A9.B807.0C00")
        self.assertEqual(changes[(4, "mac")].matched_by, "ip+hostname")
        # A row with only an IP is populated from the switch at that address,
        # with a short name because the column uses short names.
        self.assertEqual(changes[(5, "hostname")].new, "SITE-A-BLDG2-SW01")
        self.assertEqual(changes[(5, "model")].new, "2930F-8G-PoE+-2SFP+")
        # A renamed switch is matched by serial and IP and takes its new name.
        self.assertEqual(changes[(6, "hostname")].new, "SITE-A-PUMP-SW01")
        self.assertEqual(changes[(6, "hostname")].kind, "update")
        # "Cisco" in a Vendor column already agrees with "Cisco IOS".
        self.assertNotIn((4, "platform"), changes)
        # Lifecycle Status is not reachability and is not written by default.
        self.assertFalse([change for change in plan.changes if change.field == "status"])
        self.assertEqual([row["row"] for row in plan.conflicts], [7])
        self.assertEqual([row["row"] for row in plan.unmatched], [8])
        _, preferred = self.plan(self.register(), prefer="ip")
        self.assertFalse(preferred.conflicts)

    def test_fill_only_keeps_values_that_are_already_there(self):
        _, plan = self.plan(self.register(), fill_only=True)
        fields = {(change.row, change.field) for change in plan.changes}
        self.assertNotIn((4, "mac"), fields)
        self.assertIn((4, "serial"), fields)
        self.assertTrue(any("--fill-only" in row["reason"] for row in plan.kept))

    def test_preview_writes_nothing_and_confirm_backs_up_saves_and_verifies(self):
        path = self.register()
        os.chmod(path, 0o644)
        before = digest(path)
        code, output = self.run_cli("sync", path)
        self.assertEqual(code, netops.CONFIRM_REQUIRED, output)
        self.assertIn("Nothing written", output)
        self.assertEqual(digest(path), before)
        code, output = self.run_cli("sync", path, "--confirm")
        self.assertEqual(code, netops.SUCCESS, output)
        self.assertIn("Read back and verified", output)
        # The atomic replace must not turn a shared workbook owner-only.
        self.assertEqual(path.stat().st_mode & 0o777, 0o644)
        backups = list((self.base / "data" / "excel-backups").glob("register-*.xlsx"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(digest(backups[0]), before)
        wb = openpyxl.load_workbook(path)
        ws = wb["Switches"]
        self.assertEqual(ws["E4"].value, "02A9.B807.0C00")
        self.assertIn("was '02A9.B807.FFFF'", ws["E4"].comment.text)
        self.assertEqual(ws["H4"].value, '=A4&" ("&B4&")"')
        self.assertEqual(ws["G4"].value, "In service")
        self.assertEqual(wb["Notes"]["A1"].value, "keep me")
        event = self.app.state.one("SELECT * FROM audit_events WHERE event_type='excel'")
        self.assertEqual((event["action"], event["result"]), ("excel-sync", "success"))
        code, output = self.run_cli("sync", path, "--dry-run")
        self.assertEqual(code, netops.SUCCESS)
        self.assertIn("already agrees", output)

    def test_add_missing_appends_styled_rows_and_extends_the_table(self):
        path = self.register(rows=[("SITE-A-CORE-SW01", "192.0.2.10", "C9200-24PXG", "FVH0000AA01", "02A9.B807.0C00", "Cisco", "In service")])
        output_path = self.base / "out.xlsx"
        code, output = self.run_cli("sync", path, "--sheet", "Switches", "--add-missing", "--output", output_path, "--confirm")
        self.assertEqual(code, netops.SUCCESS, output)
        ws = openpyxl.load_workbook(output_path)["Switches"]
        self.assertEqual(ws.tables["Register"].ref, "A3:H6")
        added = {ws.cell(row=row, column=1).value: row for row in (5, 6)}
        self.assertEqual(set(added), {"SITE-A-BLDG2-SW01", "SITE-A-PUMP-SW01"})
        row = added["SITE-A-PUMP-SW01"]
        self.assertEqual(ws.cell(row=row, column=8).value, f'=A{row}&" ("&B{row}&")"')
        self.assertIn("added", ws.cell(row=row, column=1).comment.text)
        # With one switch sheet the target is unambiguous; with two it is not.
        def second_sheet(wb):
            spares = wb.create_sheet("Spares")
            spares.append(["Hostname", "IP Address"])
            spares.append(["SITE-A-SPARE-SW01", "198.51.100.5"])
        two_sheets = self.register("two.xlsx", extra=second_sheet)
        code, output = self.run_cli("sync", two_sheets, "--add-missing", "--dry-run")
        self.assertEqual(code, netops.VALIDATION)
        self.assertIn("--add-missing needs --sheet", output)

    def test_open_or_feature_rich_workbooks_are_not_overwritten_in_place(self):
        path = self.register()
        lock = path.with_name("~$" + path.name)
        lock.write_text("owner", encoding="utf-8")
        code, output = self.run_cli("sync", path, "--confirm")
        self.assertEqual(code, netops.VALIDATION)
        self.assertIn("looks open in Excel", output)
        lock.unlink()

        def add_chart(wb):
            ws = wb["Notes"]
            ws.append([1])
            ws.append([2])
            chart = BarChart()
            chart.add_data(Reference(ws, min_col=1, min_row=2, max_row=3))
            ws.add_chart(chart, "C2")
        charted = self.register("charted.xlsx", extra=add_chart)
        before = digest(charted)
        code, output = self.run_cli("sync", charted, "--confirm")
        self.assertEqual(code, netops.VALIDATION)
        self.assertIn("charts", output)
        self.assertEqual(digest(charted), before)
        code, output = self.run_cli("sync", charted, "--output", self.base / "charted-copy.xlsx", "--confirm")
        self.assertEqual(code, netops.SUCCESS, output)
        (self.base / "legacy.xls").write_bytes(b"\xd0\xcf\x11\xe0")
        code, output = self.run_cli("inspect", self.base / "legacy.xls")
        self.assertEqual(code, netops.VALIDATION)
        self.assertIn("save .xls files as .xlsx", output)

    def test_export_builds_inventory_summary_and_migration_tracker(self):
        path = self.base / "tracker.xlsx"
        code, output = self.run_cli("export", path)
        self.assertEqual(code, netops.SUCCESS, output)
        wb = openpyxl.load_workbook(path)
        self.assertEqual(wb.sheetnames, ["Summary", "Inventory", "Migration Tracker"])
        inventory = wb["Inventory"]
        self.assertEqual(inventory.tables["Inventory"].ref, "A1:L4")
        self.assertEqual(inventory["A2"].value, "SITE-A-BLDG2-SW01")
        self.assertEqual(inventory["F2"].value, "02:c1:c7:b9:aa:40")
        self.assertTrue(str(inventory["I2"].value).startswith("=IF(H2"))
        tracker = wb["Migration Tracker"]
        self.assertIn("MATCH(A2,Inventory!$A$2:$A$4,0)", tracker["B2"].value)
        self.assertTrue(tracker.data_validations.dataValidation)
        self.assertTrue(str(wb["Summary"]["B4"].value).startswith("=COUNTA("))
        code, output = self.run_cli("export", path)
        self.assertEqual(code, netops.CONFIRM_REQUIRED)
        # The exported Inventory is itself a workbook sync keeps current.
        code, output = self.run_cli("sync", path, "--sheet", "Inventory", "--fields",
                                    "hostname,ip,platform,model,serial,mac,status,last_seen", "--dry-run")
        self.assertEqual(code, netops.SUCCESS, output)
        self.assertIn("already agrees", output)


class ExcelHelpersTest(unittest.TestCase):
    def test_header_synonyms_and_identity_keys(self):
        self.assertEqual(excel.header_field("S/N"), "serial")
        self.assertEqual(excel.header_field("Base Ethernet MAC Address"), "mac")
        self.assertEqual(excel.header_field("Mgmt IPv4 addr"), "ip")
        self.assertEqual(excel.header_field("Location"), "")
        self.assertEqual(excel.identity_key("ip", "192.0.2.7/24 (mgmt)"), "192.0.2.7")
        self.assertEqual(excel.identity_key("hostname", "site-a-sw01.site.example.com"), "SITEASW01")
        self.assertEqual(excel.identity_key("serial", "N/A"), "")
        self.assertEqual(excel.format_mac_as("02a9b8070c00", "hyphen-six", False), "02a9b8-070c00")


if __name__ == "__main__":
    unittest.main()
