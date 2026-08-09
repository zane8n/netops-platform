import tempfile
import unittest
from pathlib import Path

from netops_ingest import (
    merge_device_observations,
    merge_device_record,
    merge_scan_files,
    render_device_pipe,
)


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


if __name__ == "__main__":
    unittest.main()
