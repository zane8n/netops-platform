import contextlib
import json
import hashlib
import io
import os
import tempfile
import time
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
        # Recently polled, so confidence reflects the match and not staleness.
        self.seen = int(time.time()) - 3600
        devices = [
            ("192.0.2.10", "SITE-A-CORE-SW01.site.example.com", "Cisco IOS", "C9200-24PXG", "FVH0000AA01", "02a9b8070c00", "ONLINE"),
            ("192.0.2.11", "SITE-A-BLDG2-SW01", "Aruba AOS-S", "2930F-8G-PoE+-2SFP+", "CN00TEST01", "02c1c7b9aa40", "ONLINE"),
            ("192.0.2.12", "SITE-A-PUMP-SW01", "Cisco IOS", "WS-C3560CX-8PC-S", "FOC0000BB02", "02eb34dab580", "OFFLINE"),
        ]
        for ip, name, platform, model, serial, mac, status in devices:
            self.app.state.execute(
                "INSERT INTO devices(ip,hostname,platform,model,serial,mac,source,last_seen,status) VALUES(?,?,?,?,?,?,?,?,?)",
                (ip, name, platform, model, serial, mac, "SSH+SNMP", self.seen, status),
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
        # A Vendor column holds the maker, not netrune's driver label.
        self.assertEqual(layout.columns, {"hostname": 1, "ip": 2, "model": 3, "serial": 4, "mac": 5, "manufacturer": 6, "status": 7})
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
        # "Cisco" in the Vendor column already agrees with the manufacturer;
        # a blank one is filled with the maker, not the "Aruba AOS-S" label.
        self.assertNotIn((4, "manufacturer"), changes)
        self.assertEqual(changes[(5, "manufacturer")].new, "Aruba")
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
        # Written cells are shaded by confidence instead of carrying notes:
        # the model (row pinned by IP and name) is blue, a replaced MAC yellow.
        self.assertIsNone(ws["E4"].comment)
        self.assertEqual(ws["C4"].fill.fgColor.rgb[-6:], excel.CONFIDENCE_FILLS["strong"])
        self.assertEqual(ws["E4"].fill.fgColor.rgb[-6:], excel.CONFIDENCE_FILLS["fair"])
        self.assertIn("shaded green (certain), blue (strong), yellow (fair), tan (weak), red (doubtful)", output)
        self.assertEqual(ws["G4"].fill.fill_type, None)
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
        self.assertEqual(ws.cell(row=row, column=1).fill.fgColor.rgb[-6:], excel.CONFIDENCE_FILLS["strong"])
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

    def test_confidence_follows_the_match_the_change_and_how_fresh_the_switch_is(self):
        _, plan = self.plan(self.register())
        changes = {(change.row, change.field): change for change in plan.changes}
        # Two keys agreeing nearly pin the switch, but a sheet MAC that
        # disagrees with them is a typo or a swap.
        self.assertEqual((changes[(4, "model")].confidence, changes[(4, "model")].why), ("strong", "2 keys match; replaced value"))
        self.assertEqual(changes[(4, "mac")].confidence, "fair")
        # An IP alone may belong to a replaced switch: filling is a glance,
        self.assertEqual((changes[(5, "model")].confidence, changes[(5, "model")].why), ("fair", "ip only; blank filled"))
        # a serial pins the switch even when its name changed.
        self.assertEqual((changes[(6, "hostname")].confidence, changes[(6, "hostname")].why), ("certain", "serial match; replaced value"))
        _, preferred = self.plan(self.register(), prefer="ip")
        forced = [change for change in preferred.changes if change.row == 7]
        self.assertTrue(forced)
        self.assertEqual({(change.confidence, change.why) for change in forced}, {("doubtful", "--prefer overrode a conflict")})
        # Sixty days without a poll drops every cell a step.
        _, stale = self.plan(self.register(), now=self.seen + 60 * 86400)
        changes = {(change.row, change.field): change for change in stale.changes}
        self.assertEqual((changes[(4, "model")].confidence, changes[(4, "model")].why), ("fair", "last seen 60 days ago"))
        self.assertEqual(changes[(5, "model")].confidence, "weak")

    def test_each_confidence_step_has_its_own_case_and_its_own_shade(self):
        fresh = {"last_seen": 1_000_000}

        def level(matched_by, kind="update", field_name="model", forced=False):
            return excel.change_confidence(matched_by=matched_by, forced=forced, kind=kind,
                                           field_name=field_name, device=fresh, now=1_000_000)[0]
        self.assertEqual(level("serial"), "certain")
        self.assertEqual(level("mac", kind="fill"), "certain")
        self.assertEqual(level("ip+hostname"), "strong")
        self.assertEqual(level("", kind="add"), "strong")
        self.assertEqual(level("ip", kind="fill"), "fair")
        self.assertEqual(level("serial", field_name="mac"), "fair")
        self.assertEqual(level("hostname"), "weak")
        self.assertEqual(level("serial", forced=True), "doubtful")
        self.assertEqual(set(excel.CONFIDENCE_FILLS), set(excel.CONFIDENCE_LEVELS))
        self.assertEqual(len(set(excel.CONFIDENCE_FILLS.values())), len(excel.CONFIDENCE_LEVELS))
        self.assertEqual(len(set(excel.CONFIDENCE_SHADES.values())), len(excel.CONFIDENCE_LEVELS))

    def test_refresh_rewrites_a_whole_column_and_does_not_match_on_it(self):
        rows = [
            ("SITE-A-CORE-SW01", "192.0.2.10", "C9200-24PXG", "FVH0000AA01", "02:a9:b8:07:0c:00", "Cisco", "In service"),
            # A stale MAC copied from another switch's row.
            ("SITE-A-BLDG2-SW01", "192.0.2.11", "2930F-8G-PoE+-2SFP+", "CN00TEST01", "02EB.34DA.B580", "Aruba", "In service"),
            ("SITE-A-PUMP-SW01", "192.0.2.12", "WS-C3560CX-8PC-S", "FOC0000BB02", "02EB.34DA.B580", "Cisco", "Spare"),
        ]
        path = self.register(rows=rows)
        _, plain = self.plan(path)
        # Same MAC in another notation is left alone, and the stale MAC makes
        # its row a conflict between two switches.
        self.assertFalse(plain.changes)
        self.assertEqual([row["row"] for row in plain.conflicts], [5])
        _, refreshed = self.plan(path, refresh=["mac"], fill_only=True)
        changes = {(change.row, change.field): change for change in refreshed.changes}
        self.assertFalse(refreshed.conflicts)
        self.assertEqual(set(changes), {(4, "mac"), (5, "mac")})
        self.assertEqual((changes[(4, "mac")].new, changes[(4, "mac")].kind, changes[(4, "mac")].confidence),
                         ("02A9.B807.0C00", "refresh", "certain"))
        # --refresh overrides --fill-only for its own columns.
        self.assertEqual((changes[(5, "mac")].new, changes[(5, "mac")].kind), ("02C1.C7B9.AA40", "update"))
        self.assertEqual(changes[(5, "mac")].matched_by, "serial+ip+hostname")
        code, output = self.run_cli("sync", path, "--refresh", "mac,serial", "--dry-run")
        self.assertEqual(code, netops.SUCCESS, output)
        self.assertIn("2 cell change", output.replace("cell_changes", ""))
        # Refreshing every key still matches: a row falls back to the keys it has.
        code, output = self.run_cli("sync", path, "--refresh", "all", "--dry-run")
        self.assertEqual(code, netops.SUCCESS, output)
        code, output = self.run_cli("sync", path, "--refresh", "colour", "--dry-run")
        self.assertEqual(code, netops.VALIDATION)
        self.assertIn("or all", output)

    def test_sheet_is_chosen_by_name_in_any_case_by_number_or_as_a_list(self):
        def second_sheet(wb):
            spares = wb.create_sheet("Spare Stock")
            spares.append(["Hostname", "IP Address", "Model"])
            spares.append(["SITE-A-PUMP-SW01", "192.0.2.12", None])
        names = ["Switches", "Notes", "Spare Stock"]
        self.assertEqual(excel.select_sheets(names, "switches"), ["Switches"])
        self.assertEqual(excel.select_sheets(names, "spare-stock"), ["Spare Stock"])
        self.assertEqual(excel.select_sheets(names, "3,1,Switches"), ["Spare Stock", "Switches"])
        path = self.register(extra=second_sheet)
        code, output = self.run_cli("inspect", path, "--sheet", "3")
        self.assertEqual(code, netops.SUCCESS, output)
        self.assertIn("Sheet 'Spare Stock'", output)
        self.assertNotIn("Sheet 'Switches'", output)
        code, output = self.run_cli("inspect", path, "--sheet", "9")
        self.assertEqual(code, netops.VALIDATION)
        self.assertIn("1=Switches, 2=Notes, 3=Spare Stock", output)
        code, output = self.run_cli("inspect", path, "--sheet", "notes")
        self.assertEqual(code, netops.VALIDATION)
        self.assertIn("Sheet 'Notes' has no header row", output)

    def test_comments_are_opt_in_and_shading_can_be_turned_off(self):
        path = self.register()
        code, output = self.run_cli("sync", path, "--comments", "--no-shade", "--confirm")
        self.assertEqual(code, netops.SUCCESS, output)
        ws = openpyxl.load_workbook(path)["Switches"]
        self.assertIn("Was '02A9.B807.FFFF'", ws["E4"].comment.text)
        self.assertNotIn("Netrune", ws["E4"].comment.text + ws["E4"].comment.author)
        self.assertEqual(ws["E4"].fill.fill_type, None)

    def ip_plan(self, rows, remarks=True):
        wb = openpyxl.Workbook()
        ws = wb.active
        ws.title = "VLAN 20"
        ws.append(["IP Address", "Hostname", "VLAN"] + (["Remarks"] if remarks else []))
        for row in rows:
            ws.append(list(row)[:4 if remarks else 3])
        ws.add_table(Table(displayName="Plan", ref=f"A1:{'D' if remarks else 'C'}{1 + len(rows)}"))
        path = self.base / "ipplan.xlsx"
        wb.save(path)
        return path

    def seed_ip_memory(self):
        now = time.time()
        self.app.state.execute("INSERT INTO aps(ip,name,platform,mac,last_seen,status) VALUES(?,?,?,?,?,?)",
                               ("192.0.2.40", "AP-LOBBY", "Aruba AP", "02aa00000040", self.seen, "OFFLINE"))
        for ip, name, seen in (("192.0.2.41", "OLD-CAM", now - 200 * 86400), ("192.0.2.42", "PLC-7", now - 3 * 86400)):
            self.app.state.execute(
                "INSERT INTO inventory_identity_state(identity_kind,identity_value,entity_type,ip,name,last_seen,updated_at) VALUES(?,?,?,?,?,?,?)",
                ("ip", ip, "ap", ip, name, int(seen), int(now)))

    def review(self, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            code = self.app.dispatch(["health", "review", *args, "--json"])
        return code, json.loads(out.getvalue())

    def test_a_conflicting_row_waits_for_review_and_the_answer_is_written_by_the_next_sync(self):
        path = self.register()
        self.run_cli("inspect", path)
        code, waiting = self.review("--list", "--kind", "excel")
        self.assertEqual(code, netops.PARTIAL)
        item = next(row for row in waiting["items"] if row["kind"] == "excel-conflict")
        self.assertIn("row 7", item["question"])
        self.assertIn("hostname says SITE-A-BLDG2-SW01", item["choices"])
        choice = next(part.split("=")[0] for part in item["choices"].split(" / ") if "hostname" in part)
        code, answered = self.review("answer", item["id"], choice)
        self.assertEqual(code, netops.SUCCESS, answered)
        # Answered: off the queue now, and the next plan follows it.
        self.assertEqual([row for row in self.review("--list", "--kind", "excel")[1]["items"] if row["id"] == item["id"]], [])
        code, output = self.run_cli("sync", path, "--confirm")
        self.assertEqual(code, netops.SUCCESS, output)
        ws = openpyxl.load_workbook(path)["Switches"]
        self.assertEqual(ws["B7"].value, "192.0.2.11")
        from netops_platform import excel_cli
        self.assertEqual(excel_cli.review_answers(self.app, path), {})

    def test_an_unconfirmed_address_waits_for_review_and_a_yes_frees_it_on_the_next_sync(self):
        from netops_platform import excel_cli
        path = self.ip_plan([("192.0.2.43", "PRINTER-2", 20, None)])
        probe = mock.patch.object(excel_cli, "_probe_ip", lambda ip, ports=excel_cli.PROBE_PORTS: "")
        calibrate = mock.patch.object(excel_cli, "_probe_calibration", lambda: (False, []))
        with probe, calibrate:
            self.run_cli("inspect", path, "--free-ips")
        item = self.review("--list", "--kind", "excel")[1]["items"][0]
        self.assertEqual((item["kind"], item["question"]), ("excel-free", "ipplan.xlsx > VLAN 20, row 2: is 192.0.2.43 free to use?"))
        self.assertEqual(self.review("answer", item["id"], "y")[0], netops.SUCCESS)
        with probe, calibrate:
            code, output = self.run_cli("sync", path, "--free-ips", "--confirm")
        self.assertEqual(code, netops.SUCCESS, output)
        self.assertEqual(openpyxl.load_workbook(path)["VLAN 20"]["D2"].value, "Free to use (old entry)")
        self.assertEqual(self.review("--list", "--kind", "excel")[1]["items"], [])

    def test_a_stale_row_answer_never_lands_on_another_row(self):
        _, plan = self.plan(self.register(), row_prefer={7: {"kind": "hostname", "label": "SOMETHING-ELSE"}})
        self.assertEqual([conflict["row"] for conflict in plan.conflicts], [7])
        _, plan = self.plan(self.register(), row_prefer={7: {"kind": "hostname", "label": "SITE-A-BLDG2-SW01"}})
        self.assertEqual(plan.conflicts, [])

    def test_free_ips_frees_empty_rows_from_memory_and_asks_about_unknown_entries(self):
        from netops_platform import excel_cli
        self.seed_ip_memory()
        path = self.ip_plan([
            ("192.0.2.30", None, 20, None),                         # empty, silent, no record: free
            ("192.0.2.34", None, 20, None),                         # empty, but something answers
            ("192.0.2.31", "CAM-9", 20, "Free to use (old entry)"),  # unknown, but answers now
            ("192.0.2.32", None, 20, "Reserved for CCTV"),
            ("192.0.2.33", None, 20, "Spare, ask Joe"),
            ("192.0.2.40", None, 20, None),                         # an AP Netrune knows, though offline
            ("192.0.2.41", None, 20, None),                         # used long ago
            ("192.0.2.42", None, 20, None),                         # used last week
            ("192.0.2.43", "PRINTER-2", 20, "Free to use"),         # unknown and silent: awaits an answer
            ("192.0.2.44", "OLD-PLC", 20, "Allocated, offline"),    # answered no on an earlier run
            ("192.0.2.45", "OLD-NVR", 20, None),                    # answered yes on the command line
            ("192.0.2.10", None, 20, None),                         # a switch: matched and filled instead
        ])
        probed = []

        def probe(ip, ports=excel_cli.PROBE_PORTS):
            probed.append(ip)
            return "answers ping" if ip in {"192.0.2.31", "192.0.2.34"} else ""
        calibrate = mock.patch.object(excel_cli, "_probe_calibration", lambda: (False, []))
        with mock.patch.object(excel_cli, "_probe_ip", probe), calibrate:
            code, output = self.run_cli("sync", path, "--free-ips", "--dry-run")
            self.assertEqual(code, netops.SUCCESS, output)
            self.assertIn("Suggested for allocation (empty rows first", output)
            self.assertIn("Rows naming something Netrune never saw, with nothing answering (2)", output)
            code, output = self.run_cli("sync", path, "--free-ips", "--accept-free", "192.0.2.45", "--confirm")
        self.assertEqual(code, netops.SUCCESS, output)
        # Every address Netrune holds no device for is probed, empty rows included.
        self.assertEqual(sorted(set(probed)), ["192.0.2.30", "192.0.2.31", "192.0.2.32", "192.0.2.33", "192.0.2.34",
                                               "192.0.2.41", "192.0.2.42", "192.0.2.43", "192.0.2.44", "192.0.2.45"])
        ws = openpyxl.load_workbook(path)["VLAN 20"]
        remarks = {ws.cell(row=row, column=1).value: ws.cell(row=row, column=4).value for row in range(2, 14)}
        names = {ws.cell(row=row, column=1).value: ws.cell(row=row, column=2).value for row in range(2, 14)}
        self.assertEqual(remarks["192.0.2.30"], "Free to use")
        self.assertEqual(remarks["192.0.2.31"], "In use (answers ping)")
        self.assertEqual(remarks["192.0.2.32"], "Reserved for CCTV")
        self.assertEqual(remarks["192.0.2.33"], "Spare, ask Joe; Free to use")
        # A device Netrune holds on an empty row is missing from the sheet: its name goes in.
        self.assertEqual((names["192.0.2.40"], remarks["192.0.2.40"]), ("AP-LOBBY", "In use (AP AP-LOBBY); Added name"))
        self.assertEqual(remarks["192.0.2.34"], "In use (answers ping)")
        self.assertTrue(remarks["192.0.2.41"].startswith("Free to use (was OLD-CAM until "))
        self.assertTrue(remarks["192.0.2.42"].startswith("Used by PLC-7 until "))
        self.assertIsNone(remarks["192.0.2.43"])
        self.assertEqual(remarks["192.0.2.44"], "Allocated, offline")
        self.assertEqual(remarks["192.0.2.45"], "Free to use (old entry)")
        self.assertEqual(remarks["192.0.2.10"], "Added name")
        self.assertEqual(ws["D2"].fill.fgColor.rgb[-6:], excel.CONFIDENCE_FILLS["certain"])
        self.assertEqual(ws["D9"].fill.fgColor.rgb[-6:], excel.CONFIDENCE_FILLS["weak"])
        self.assertIn("4 address(es) marked free to use", output)
        # A second run has nothing new to say; the printer row still waits.
        with mock.patch.object(excel_cli, "_probe_ip", probe), calibrate:
            code, output = self.run_cli("sync", path, "--free-ips", "--dry-run")
        self.assertIn("already agrees", output)

    def test_free_ips_asks_in_a_terminal_and_a_no_keeps_the_row_allocated(self):
        from netops_platform import excel_cli
        path = self.ip_plan([("192.0.2.50", "OLD-PLC", 20, None), ("192.0.2.51", "OLD-NVR", 20, None),
                             ("192.0.2.52", "OLD-DVR", 20, None)])
        with mock.patch.object(excel_cli, "_probe_ip", lambda ip, ports=(): ""), \
                mock.patch.object(excel_cli, "_probe_calibration", lambda: (False, [])), \
                mock.patch.object(excel_cli, "_interactive", lambda opts: True), \
                mock.patch("builtins.input", side_effect=["n", "y", ""]) as asked:
            code, output = self.run_cli("sync", path, "--free-ips", "--confirm")
        self.assertEqual(code, netops.SUCCESS, output)
        self.assertEqual(asked.call_count, 3)
        ws = openpyxl.load_workbook(path)["VLAN 20"]
        self.assertEqual([ws.cell(row=row, column=4).value for row in (2, 3, 4)],
                         ["Allocated, offline", "Free to use (old entry)", None])

    def test_free_ips_ignores_ports_a_proxy_answers_and_refuses_a_lying_ping(self):
        from netops_platform import excel_cli
        path = self.ip_plan([("192.0.2.30", "OLD-PLC", 20, None)])
        seen_ports = []
        def probe(ip, ports=excel_cli.PROBE_PORTS):
            seen_ports.append(ports)
            return ""
        with mock.patch.object(excel_cli, "_probe_ip", probe), \
                mock.patch.object(excel_cli, "_probe_calibration", lambda: (False, [80, 443])):
            code, output = self.run_cli("sync", path, "--free-ips", "--dry-run")
        self.assertEqual(code, netops.SUCCESS, output)
        self.assertNotIn(80, seen_ports[0])
        self.assertIn(445, seen_ports[0])
        self.assertIn("Ports 80, 443 answer for addresses that do not exist", output)
        with mock.patch.object(excel_cli, "_probe_calibration", lambda: (True, [])):
            code, output = self.run_cli("sync", path, "--free-ips", "--dry-run")
        self.assertEqual(code, netops.VALIDATION)
        self.assertIn("cannot tell a free address from a used one", output)

    def test_free_ips_adds_a_remarks_column_when_the_sheet_has_none(self):
        from netops_platform import excel_cli
        path = self.ip_plan([("192.0.2.30", None, 20), ("192.0.2.31", None, 20)], remarks=False)
        with mock.patch.object(excel_cli, "_probe_ip", lambda ip, ports=(): ""), \
                mock.patch.object(excel_cli, "_probe_calibration", lambda: (False, [])):
            code, output = self.run_cli("sync", path, "--free-ips", "--confirm")
        self.assertEqual(code, netops.SUCCESS, output)
        self.assertIn("Added a Remarks column (D) to 'VLAN 20'", output)
        ws = openpyxl.load_workbook(path)["VLAN 20"]
        self.assertEqual((ws["D1"].value, ws["D2"].value, ws["D3"].value), ("Remarks", "Free to use", "Free to use"))
        self.assertEqual(ws.tables["Plan"].ref, "A1:D3")
        self.assertEqual([column.name for column in ws.tables["Plan"].tableColumns][-1], "Remarks")

    def test_remarks_note_each_rows_changes_in_the_techs_words(self):
        def remarks_column(wb):
            ws = wb["Switches"]
            ws["I3"] = "Comments"
            ws["I6"] = "Moved to pump house"
        path = self.register(extra=remarks_column)
        code, output = self.run_cli("sync", path, "--remarks", "--confirm")
        self.assertEqual(code, netops.SUCCESS, output)
        ws = openpyxl.load_workbook(path)["Switches"]
        self.assertEqual(ws["I4"].value, "Updated model and MAC; Added serial")
        self.assertEqual(ws["I5"].value, "Added name, vendor, model, serial and MAC")
        # The operator's own note is kept; the offline switch says so.
        self.assertEqual(ws["I6"].value, "Moved to pump house; Renamed from OLD-PUMP-NAME; Added vendor, model and MAC; Offline")
        self.assertEqual(ws["I7"].value, "Check: IP is SITE-A-CORE-SW01, name is SITE-A-BLDG2-SW01")
        self.assertNotIn("Netrune", " ".join(str(ws.cell(row=r, column=9).value) for r in range(4, 9)))

    def seed_history(self):
        now = int(time.time())
        day = 86400
        state = self.app.state
        state.execute("INSERT INTO aps(ip,name,platform,switch_ip,switch_name,switch_port,mac,last_seen,status) VALUES(?,?,?,?,?,?,?,?,?)",
                      ("192.0.2.60", "AP-YARD", "cisco CW9162I-ROW", "192.0.2.10", "SITE-A-CORE-SW01", "Gi1/0/5", "02bb00000060", self.seen, "ONLINE"))
        state.execute("INSERT INTO aps(ip,name,platform,mac,last_seen,status) VALUES(?,?,?,?,?,?)",
                      ("192.0.2.61", "AP-STORE", "Ruckus R610 Multimedia Hotzone Wireless AP", "02bb00000061", self.seen - 40 * day, "OFFLINE"))
        state.execute("INSERT INTO aps(ip,name,platform,mac,last_seen,status) VALUES(?,?,?,?,?,?)",
                      ("192.0.2.62", "02 cc 00 00 00 62", "Aruba JL258A 2930F-8G-PoE+-2SFP+ Switch, revision WC.16", "02cc00000062", self.seen, "ONLINE"))

        def event(when, entity, kind, value, field, old, new, **snapshot):
            columns = {"name": "", "ip": "", "mac": "", "serial": "", "model": "", "platform": "", **snapshot}
            state.execute(
                "INSERT INTO inventory_history(created_at,entity_type,identity_kind,identity_value,event_type,field_name,previous_value,current_value,"
                "ip,mac,name,switch_ip,switch_name,switch_port,platform,model,serial,source,status) VALUES(?,?,?,?,'field_changed',?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (when, entity, kind, value, field, old, new, columns["ip"], columns["mac"], columns["name"], "", "", "",
                 columns["platform"], columns["model"], columns["serial"], "test", "ONLINE"))
        # Switch history is rebuilt from what each scan saw at each address.
        sequence = iter(range(1, 1000))

        def observe(when, ip, hostname, mac="", serial="N/A", model="N/A"):
            facts = {"hostname": hostname, "ip": ip, "mac": mac, "serial": serial, "model": model, "platform": "Cisco IOS",
                     "status": "ONLINE", "source": "SSH", "last_seen": when}
            state.execute(
                "INSERT INTO observations(idempotency_key,entity_kind,stable_source_id,channel,observed_at,received_at,completeness,"
                "status,confidence,provenance_json,facts_json,raw_evidence_hash) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (f"test-{next(sequence)}", "device", ip, "built-in-ssh-scan", when, when, "complete", "ONLINE", 85, "{}",
                 json.dumps(facts), "x"))
        t = now - 5 * day
        # A full replacement at 192.0.2.10: serial, base MAC, and model all change.
        observe(t - 3600, "192.0.2.10", "SITE-A-CORE-SW01", "02ffee000001", "FOC1111ZZ01", "WS-C2960X-24PS-L")
        observe(t, "192.0.2.10", "SITE-A-CORE-SW01", "02a9b8070c00", "FVH0000AA01", "C9200-24PXG")
        # Cosmetic: the domain added; N/A filled in.
        observe(t + 60, "192.0.2.10", "SITE-A-CORE-SW01.site.example.com", "02a9b8070c00", "FVH0000AA01", "C9200-24PXG")
        observe(t - 7200, "192.0.2.11", "SITE-A-BLDG2-SW01", "02c1c7b9aa40", "N/A", "2930F-8G-PoE+-2SFP+")
        # Cisco's motherboard serial read as the system serial: the base MAC
        # stays, so it is the same switch, not a replacement.
        observe(now - 8 * day, "192.0.2.11", "SITE-A-BLDG2-SW01", "02c1c7b9aa40", "CN00MOBO01", "2930F-8G-PoE+-2SFP+")
        observe(now - 7 * day, "192.0.2.11", "SITE-A-BLDG2-SW01", "02c1c7b9aa40", "CN00TEST01", "2930F-8G-PoE+-2SFP+")
        # A switch moved address 90 days ago, then a real rename, then a
        # serial misread and corrected back (not a replacement).
        observe(now - 91 * day, "192.0.2.99", "OLD-PUMP-NAME", "02eb34dab580", "FOC0000BB02")
        observe(now - 90 * day, "192.0.2.12", "OLD-PUMP-NAME", "02eb34dab580", "FOC0000BB02")
        observe(now - 2 * day, "192.0.2.12", "SITE-A-PUMP-SW01", "02eb34dab580", "FOC0000BB02")
        observe(now - 4 * day + 1, "192.0.2.12", "SITE-A-PUMP-SW01", "02eb34dab580", "FOC9999XX99")
        observe(now - 3 * day + 1, "192.0.2.12", "SITE-A-PUMP-SW01", "02eb34dab580", "FOC0000BB02")
        # AP: Ruckus swapped for Cisco at the same name; a banner flap; an IP handed to another AP.
        yard = {"ip": "192.0.2.60", "name": "AP-YARD", "mac": "02bb00000060", "platform": "cisco CW9162I-ROW"}
        event(now - day, "ap", "name", "ap-yard", "platform", "Ruckus-AP", "cisco CW9162I-ROW", **yard)
        event(now - day, "ap", "name", "ap-yard", "mac", "02bb00000099", "02bb00000060", **yard)
        event(now - 6 * day, "ap", "name", "ap-store", "platform", "Ruckus R610 Multimedia Hotzone Wireless AP",
              "Ruckus AP Software, Version 5.2", ip="192.0.2.61", name="AP-STORE")
        event(now - 6 * day, "ap", "ip", "192.0.2.61", "mac", "02bb00000070", "02bb00000061", ip="192.0.2.61", name="AP-STORE")
        # Outside the default 30 days.
        state.execute("INSERT INTO ap_move_events(created_at,ap_ip,ap_name,previous_switch_ip,previous_switch_port,current_switch_ip,current_switch_port) "
                      "VALUES(?,?,?,?,?,?,?)", (now - day, "192.0.2.60", "AP-YARD", "192.0.2.11", "3", "192.0.2.10", "Gi1/0/5"))

    def test_reports_follow_their_written_definitions(self):
        self.seed_history()
        path = self.base / "reports.xlsx"
        code, output = self.run_cli("report", path)
        self.assertEqual(code, netops.SUCCESS, output)
        wb = openpyxl.load_workbook(path)
        self.assertEqual(wb.sheetnames, ["Report Info", "Active APs", "Active Switches", "Transitions", "Switch History", "AP History"])

        def rows(sheet):
            ws = wb[sheet]
            header = [cell.value for cell in ws[1]]
            return [dict(zip(header, (cell.value for cell in row))) for row in ws.iter_rows(min_row=2)]
        # The switch hiding in the AP inventory is left out.
        self.assertEqual([(row["Name"], row["Model"], row["Switch Port"]) for row in rows("Active APs")],
                         [("AP-YARD", "CW9162I-ROW", "Gi1/0/5")])
        self.assertEqual({row["Hostname"] for row in rows("Active Switches")}, {"SITE-A-CORE-SW01", "SITE-A-BLDG2-SW01"})
        changes = {(row["Change"], row["Device"], row["From"], row["To"], row["Kept The Same"]) for row in rows("Transitions")}
        self.assertIn(("Renamed", "SITE-A-PUMP-SW01", "OLD-PUMP-NAME", "SITE-A-PUMP-SW01", "IP"), changes)
        self.assertIn(("Serial changed", "SITE-A-CORE-SW01", "FOC1111ZZ01", "FVH0000AA01", "IP"), changes)
        self.assertIn(("IP now on another device", "AP-STORE", "02:bb:00:00:00:70", "02:bb:00:00:00:61", "IP"), changes)
        self.assertIn(("Moved", "AP-YARD", "192.0.2.11 port 3", "192.0.2.10 port Gi1/0/5", "MAC"), changes)
        kinds = [change[0] for change in changes]
        self.assertNotIn("IP changed", kinds)          # 90 days ago, outside the period
        self.assertEqual(kinds.count("Renamed"), 1)     # the domain-only rename does not count
        switches = rows("Switch History")
        core = [row for row in switches if row["Hostname"] == "SITE-A-CORE-SW01"]
        self.assertEqual([row["State"] for row in core], ["Active", "Replaced"])
        self.assertEqual(core[0]["Hardware Change"], "Replaced FOC1111ZZ01 (WS-C2960X-24PS-L)")
        self.assertEqual((core[1]["Serial Number"], core[1]["Model"], core[1]["Hardware Change"]),
                         ("FOC1111ZZ01", "WS-C2960X-24PS-L", "Replaced by FVH0000AA01 (C9200-24PXG)"))
        self.assertEqual([row["State"] for row in switches if row["Hostname"] == "SITE-A-BLDG2-SW01"], ["Active"])
        # The misread serial that reverted is not a replacement; offline switches are listed.
        pump = [row for row in switches if row["Hostname"] == "SITE-A-PUMP-SW01"]
        self.assertEqual([row["State"] for row in pump], ["Offline"])
        aps = rows("AP History")
        self.assertEqual([(row["Name"], row["State"]) for row in aps], [("AP-STORE", "Offline"), ("AP-YARD", "Active"), ("AP-YARD", "Replaced")])
        self.assertEqual(aps[2]["Hardware Change"], "Replaced by 02:bb:00:00:00:60 (CW9162I-ROW)")
        self.assertEqual(aps[0]["Hardware Change"], None)   # a banner in place of the model is no swap
        self.assertIn("switches seen as neighbours", output)
        self.assertIn("A replacement changes the box itself", " ".join(str(c.value) for c in wb["Report Info"]["C"]))
        code, output = self.run_cli("report", path)
        self.assertEqual(code, netops.CONFIRM_REQUIRED)
        code, output = self.run_cli("report", path, "--report", "transitions", "--since", "all", "--confirm")
        self.assertEqual(code, netops.SUCCESS, output)
        wb = openpyxl.load_workbook(path)
        self.assertEqual(wb.sheetnames, ["Report Info", "Transitions"])
        self.assertIn("IP changed", [row["Change"] for row in rows("Transitions")])
        code, output = self.run_cli("report", path, "--report", "nonsense", "--confirm")
        self.assertEqual(code, netops.VALIDATION)

    def test_export_builds_inventory_summary_and_migration_tracker(self):
        path = self.base / "tracker.xlsx"
        code, output = self.run_cli("export", path)
        self.assertEqual(code, netops.SUCCESS, output)
        wb = openpyxl.load_workbook(path)
        self.assertEqual(wb.sheetnames, ["Summary", "Inventory", "Migration Tracker"])
        inventory = wb["Inventory"]
        self.assertEqual(inventory.tables["Inventory"].ref, "A1:M4")
        self.assertEqual(inventory["A2"].value, "SITE-A-BLDG2-SW01")
        self.assertEqual(inventory["C1"].value, "Manufacturer")
        self.assertEqual(inventory["G2"].value, "02:c1:c7:b9:aa:40")
        self.assertTrue(str(inventory["J2"].value).startswith("=IF(I2"))
        # Every summary formula moved with the inserted column.
        self.assertIn("Inventory!$H$2", str(wb["Summary"]["B5"].value))
        tracker = wb["Migration Tracker"]
        self.assertIn("MATCH(A2,Inventory!$A$2:$A$4,0)", tracker["B2"].value)
        self.assertTrue(tracker.data_validations.dataValidation)
        self.assertTrue(str(wb["Summary"]["B4"].value).startswith("=COUNTA("))
        code, output = self.run_cli("export", path)
        self.assertEqual(code, netops.CONFIRM_REQUIRED)
        # The exported Inventory is itself a workbook sync keeps current.
        code, output = self.run_cli("sync", path, "--sheet", "Inventory", "--fields",
                                    "hostname,ip,manufacturer,platform,model,serial,mac,status,last_seen", "--dry-run")
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

    def test_free_ip_classification_and_remark_merging(self):
        now = 1_800_000_000
        def judge(empty, **kwargs):
            values = {"known": {}, "history": {}, "reply": "", "now": now, **kwargs}
            return excel.classify_ip("192.0.2.9", empty=empty, **values)
        self.assertEqual((judge(True).state, judge(True).remark, judge(True).priority), ("free", "Free to use", 1))
        # Something Netrune knows holds it, online or offline: never free.
        self.assertEqual(judge(True, known={"192.0.2.9": "AP X"}).remark, "In use (AP X)")
        self.assertEqual(judge(False, reply="answers on port 445").remark, "In use (answers on port 445)")
        self.assertEqual(judge(True, history={"192.0.2.9": ("PLC", now - 86400)}).state, "recent")
        # An unknown entry nobody answers for waits for the operator.
        self.assertEqual(judge(False).state, "unconfirmed")
        self.assertEqual((judge(False, decision="accepted").remark, judge(False, decision="accepted").priority),
                         ("Free to use (old entry)", 3))
        self.assertEqual(judge(False, decision="rejected").remark, "Allocated, offline")
        self.assertEqual(excel.prior_decision("Old PLC; Allocated, offline"), "rejected")
        # Whatever a run wrote about an address is replaced; the operator's words stay.
        self.assertEqual(excel.merge_remark("Old PLC; Free to use", ["In use (answers ping)"]), "Old PLC; In use (answers ping)")
        self.assertEqual(excel.merge_remark("In use (finance)", ["Free to use"]), "In use (finance); Free to use")
        self.assertTrue(excel.RESERVED_WORDS.search("In use (finance)"))
        self.assertEqual(excel.merge_remark("Updated MAC", ["Updated MAC"]), "Updated MAC")


if __name__ == "__main__":
    unittest.main()
