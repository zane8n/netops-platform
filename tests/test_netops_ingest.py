import tempfile
import unittest
from pathlib import Path

from netops_ingest import (
    aruba_model_name,
    merge_device_observations,
    merge_device_record,
    merge_scan_files,
    normalize_device_observation,
    parse_cli_hardware,
    parse_snmp_hardware,
    render_device_pipe,
)


CISCO_SHOW_VERSION = """\
Base Ethernet MAC Address          : 02:00:00:c5:be:00
Motherboard Assembly Number        : 73-20066-04
Motherboard Serial Number          : FVH0000MB01
Model Revision Number              : M0
Motherboard Revision Number        : C0
Model Number                      : C9200-24PXG
System Serial Number               : FVH0000SY01
CLEI Code Number                   : INM8P10ARB
"""

ARUBA_SYSTEM_AND_MODULES = """\
SITE-A-BLDG2-SW01# sh system

 Status and Counters - General System Information

  System Name        : SITE-A-BLDG2-SW01
  MAC Age Time (sec) : 300

  Software revision  : WC.16.10.0010        Base MAC Addr      : 02c1c7-b9aa40
  ROM Version        : WC.16.01.0008        Serial Number      : CN00TEST01

  Up Time            : 140 days             Memory   - Total   : 339,186,176

SITE-A-BLDG2-SW01# show modules

 Status and Counters - Module Information

  Chassis: 2930F-8G-PoE+-2SFP+  JL258A         Serial Number:   CN00TEST01

SITE-A-BLDG2-SW01#
"""

ENTITY = "SNMPv2-SMI::mib-2.47.1.1.1.1"
NO_SUCH = "No Such Instance currently exists at this OID"


class InventoryIngestTest(unittest.TestCase):
    def test_fresh_snmp_name_and_status_update_richer_ssh_record(self):
        existing = {
            "ip": "192.0.2.1",
            "hostname": "SITE-A-PLNT-PLN-SW01",
            "platform": "Cisco",
            "model": "C9300-48P",
            "serial": "SERIAL-1",
            "mac": "02:00:00:00:00:25",
            "source": "SSH",
            "last_seen": 100,
            "status": "OFFLINE",
        }
        incoming = {
            "ip": "192.0.2.1",
            "hostname": "SITEAPLNTPLANSW01",
            "platform": "Cisco IOS XE",
            "model": "N/A",
            "serial": "N/A",
            "mac": "N/A",
            "source": "SNMP",
            "last_seen": 200,
            "status": "ONLINE",
        }
        merged, detail = merge_device_observations(existing, incoming)
        self.assertEqual(merged["hostname"], "SITEAPLNTPLANSW01")
        self.assertEqual(merged["model"], "C9300-48P")
        self.assertEqual(merged["serial"], "SERIAL-1")
        self.assertEqual(merged["status"], "ONLINE")
        self.assertEqual(merged["source"], "SSH+SNMP")
        self.assertTrue(detail["hostname_changed"])

    def test_scan_merge_records_poll_time_for_missing_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            inventory = base / "devices.db"
            targets = base / "targets"
            observations = base / "observations"
            inventory.write_text("192.0.2.1|SW1|Cisco|C9300|SERIAL|0200.0000.0025|SSH|100|ONLINE\n", encoding="utf-8")
            targets.write_text("192.0.2.1\n", encoding="utf-8")
            observations.write_text("", encoding="utf-8")
            rows, detail = merge_scan_files(inventory, targets, observations, observed_at=500)
        self.assertEqual(rows[0]["status"], "OFFLINE")
        self.assertEqual(rows[0]["last_seen"], 500)
        self.assertEqual(detail["changes"]["192.0.2.1"], ["status"])
        self.assertIn("|500|OFFLINE", render_device_pipe(rows))

    def test_icmp_only_observation_updates_status_without_erasing_inventory(self):
        existing = {
            "ip": "192.0.2.1",
            "hostname": "SITEAPLNTPLANSW01",
            "platform": "Ruckus FastIron",
            "model": "ICX7150",
            "serial": "SERIAL-1",
            "mac": "02:00:00:00:00:25",
            "source": "SSH+SNMP",
            "last_seen": 100,
            "status": "OFFLINE",
        }
        incoming = {
            "ip": "192.0.2.1",
            "hostname": "N/A",
            "platform": "Unknown",
            "model": "N/A",
            "serial": "N/A",
            "mac": "N/A",
            "source": "ICMP",
            "last_seen": 200,
            "status": "ONLINE",
        }
        merged, detail = merge_device_observations(existing, incoming)
        self.assertEqual(merged["hostname"], "SITEAPLNTPLANSW01")
        self.assertEqual(merged["platform"], "Ruckus FastIron")
        self.assertEqual(merged["model"], "ICX7150")
        self.assertEqual(merged["serial"], "SERIAL-1")
        self.assertEqual(merged["status"], "ONLINE")
        self.assertEqual(merged["source"], "SSH+SNMP+ICMP")
        self.assertFalse(detail["hostname_changed"])

    def test_single_provider_record_uses_normalized_non_destructive_merge(self):
        with tempfile.TemporaryDirectory() as temporary:
            inventory = Path(temporary) / "devices.db"
            inventory.write_text(
                "192.0.2.8|OLD-SW|Unknown|ICX7150|SERIAL-8|0200.0000.0025|SNMP|100|ONLINE\n",
                encoding="utf-8",
            )
            rows, detail = merge_device_record(
                inventory,
                "192.0.2.8|NEW-SW|Unknown|N/A|N/A|N/A|SSH|200|ONLINE",
                observed_at=200,
            )
        self.assertEqual(rows[0]["hostname"], "NEW-SW")
        self.assertEqual(rows[0]["platform"], "Ruckus FastIron")
        self.assertEqual(rows[0]["model"], "ICX7150")
        self.assertEqual(rows[0]["serial"], "SERIAL-8")
        self.assertEqual(rows[0]["source"], "SNMP+SSH")
        self.assertEqual(detail["driver_family"], "ruckus-fastiron")
        self.assertTrue(detail["hostname_changed"])


    def test_cisco_show_version_yields_model_motherboard_serial_and_base_mac(self):
        hardware = parse_cli_hardware(CISCO_SHOW_VERSION, "cisco-ios")
        self.assertEqual(hardware["model"], "C9200-24PXG")
        # The Motherboard serial is the device serial, even where System differs.
        self.assertEqual(hardware["serial"], "FVH0000MB01")
        self.assertEqual(hardware["mac"], "020000c5be00")

    def test_cisco_older_labels_and_show_inventory_fallbacks(self):
        legacy = "Model number                    : WS-C2960G-24TC-L\nSystem serial number            : FOC0000SY01\n"
        self.assertEqual(parse_cli_hardware(legacy, "cisco-ios")["model"], "WS-C2960G-24TC-L")
        self.assertEqual(parse_cli_hardware(legacy, "cisco-ios")["serial"], "FOC0000SY01")
        inventory = 'NAME: "1", DESCR: "WS-C3560CX-8PC-S"\nPID: WS-C3560CX-8PC-S  , VID: V03  , SN: FOC0000IN01\n'
        self.assertEqual(parse_cli_hardware(inventory, "cisco-ios"), {"model": "WS-C3560CX-8PC-S", "serial": "FOC0000IN01", "mac": ""})

    def test_aruba_two_column_show_system_and_show_modules_chassis(self):
        hardware = parse_cli_hardware(ARUBA_SYSTEM_AND_MODULES, "aruba-aos-switch")
        self.assertEqual(hardware, {"model": "2930F-8G-PoE+-2SFP+", "serial": "CN00TEST01", "mac": "02c1c7b9aa40"})

    def test_output_without_inventory_labels_records_nothing(self):
        # Every SSH job reaches the inventory refiner; an interface's MAC is
        # not the switch's base MAC and must not be recorded as one.
        interfaces = "Gi1/0/1 is up\n  Hardware is Gigabit Ethernet, address is 0200.0000.be81\n"
        self.assertEqual(parse_cli_hardware(interfaces, "cisco-ios"), {"model": "", "serial": "", "mac": ""})
        self.assertEqual(parse_cli_hardware("Vlan 10  02c1c7-000001  5", "aruba-aos-switch"), {"model": "", "serial": "", "mac": ""})

    def test_aruba_model_name_drops_vendor_product_number_and_switch(self):
        cases = {
            "Aruba JL258A 2930F-8G-PoE+-2SFP+ Switch, revision WC.16.10.0010": "2930F-8G-PoE+-2SFP+",
            "HP J9851A Switch 5412Rzl2, revision KB.16.10.0010": "5412Rzl2",
            "Aruba JL075A 3810M-16SFP+-2-slot Switch": "3810M-16SFP+-2-slot",
            "Aruba JL356A 2540-24G-PoE+-4SFP+ Switch": "2540-24G-PoE+-4SFP+",
            "ProCurve J9086A Switch 2610-24/12PWR, revision R.11.72": "2610-24/12PWR",
            "Aruba JL659A 6300M 48SR5 CL6 PoE 4SFP56 Swch FL.10.08.1010": "6300M 48SR5 CL6 PoE 4SFP56",
        }
        for description, model in cases.items():
            with self.subTest(description=description):
                self.assertEqual(aruba_model_name(description, require_product_number=True), model)
        self.assertEqual(aruba_model_name("Cisco IOS Software, C2960S Software", require_product_number=True), "")

    def test_snmp_reads_the_chassis_entity_wherever_it_is_indexed(self):
        catalyst_9000 = [  # index 1 is the stack container, the switch is 1000
            f"{ENTITY}.5.1\t11", f"{ENTITY}.5.1000\t3", f"{ENTITY}.5.1001\t{NO_SUCH}",
            f"{ENTITY}.13.1000\tC9200-24PXG", f"{ENTITY}.11.1000\tFVH0000SY02",
        ]
        catalyst_2960 = [f"{ENTITY}.5.1\t{NO_SUCH}", f"{ENTITY}.5.1001\t3", f"{ENTITY}.13.1001\tWS-C2960G-24TC-L", f"{ENTITY}.11.1001\tFOC0000SY03"]
        aruba_stackable = [f"{ENTITY}.5.1001\t3", f"{ENTITY}.13.1001\tJL075A", f"{ENTITY}.11.1001\tSG00TEST02",
                           f"{ENTITY}.2.1001\tAruba JL075A 3810M-16SFP+-2-slot Switch"]
        image_name = "Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M)"
        self.assertEqual(parse_snmp_hardware("cisco-ios", catalyst_9000, sysdescr="Catalyst L3 Switch Software (CAT9K_LITE_IOSXE)", bridge_mac="02 A9 B8 07 0C 00 "),
                         {"model": "C9200-24PXG", "serial": "FVH0000SY02", "mac": "02a9b8070c00"})
        self.assertEqual(parse_snmp_hardware("cisco-ios", catalyst_2960, sysdescr=image_name)["model"], "WS-C2960G-24TC-L")
        # sysDescr names the software image, which is not the hardware model.
        self.assertEqual(parse_snmp_hardware("cisco-ios", [], sysdescr=image_name)["model"], "")
        self.assertEqual(parse_snmp_hardware("aruba-aos-switch", aruba_stackable),
                         {"model": "3810M-16SFP+-2-slot", "serial": "SG00TEST02", "mac": ""})
        self.assertEqual(parse_snmp_hardware("aruba-aos-switch", [f"{ENTITY}.5.1\t3", f"{ENTITY}.11.1\tNot Avail"])["serial"], "")

    def test_snmp_system_serial_does_not_replace_ssh_motherboard_serial(self):
        existing = {"ip": "192.0.2.7", "hostname": "SW7", "platform": "Cisco IOS", "model": "WS-C3560CX-8PC-S",
                    "serial": "FOC0000MB07", "mac": "02:00:00:00:00:07", "source": "SSH+SNMP", "last_seen": 100, "status": "ONLINE"}
        scan = dict(existing, serial="FOC0000SY07", source="SNMP", last_seen=200)
        merged, _ = merge_device_observations(existing, scan)
        self.assertEqual(merged["serial"], "FOC0000MB07")
        # A different model is different hardware, so its serial is taken.
        swapped, _ = merge_device_observations(existing, dict(scan, model="C9200CX-12P-2X2G", serial="FJC0000SY08"))
        self.assertEqual(swapped["serial"], "FJC0000SY08")
        # SSH itself still updates the serial, and Arubas have a single serial.
        by_ssh, _ = merge_device_observations(existing, dict(scan, source="SSH"))
        self.assertEqual(by_ssh["serial"], "FOC0000SY07")
        aruba = dict(existing, platform="Aruba AOS-S", model="2930F-8G-PoE+-2SFP+")
        self.assertEqual(merge_device_observations(aruba, dict(aruba, serial="CN00TEST09", source="SNMP"))[0]["serial"], "CN00TEST09")

    def test_captured_error_text_is_not_kept_as_a_model(self):
        row = normalize_device_observation({"ip": "192.0.2.8", "model": '(file "/usr/local/bin/netops_aruba_ssh.exp" line'})
        self.assertEqual(row["model"], "N/A")


if __name__ == "__main__":
    unittest.main()
