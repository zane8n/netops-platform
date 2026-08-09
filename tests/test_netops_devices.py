import contextlib
import io
import unittest
from pathlib import Path
import tempfile

from netops_devices import (
    DeviceDriver,
    DeviceDriverRegistry,
    UnsupportedDeviceAction,
    detect_device_family,
    driver_for,
    main,
)


class DeviceDriverTest(unittest.TestCase):
    def test_current_switch_families_are_detected_separately(self):
        fixtures = (
            ({"platform": "Cisco IOS XE", "model": "C9300-48P"}, "cisco-ios"),
            ({"platform": "Aruba", "model": "JL258A"}, "aruba-aos-switch"),
            ({"sysdescr": "ArubaOS-CX 10.13", "model": "CX 6300"}, "aruba-aos-cx"),
            ({"sysdescr": "RUCKUS ICX7150 FastIron 08.0.95"}, "ruckus-fastiron"),
            ({"platform": "Ruckus SmartZone", "model": "vSZ"}, "ruckus-smartzone"),
            ({"platform": "Ruckus AP", "model": "R750"}, "ruckus-ap"),
        )
        for evidence, family in fixtures:
            with self.subTest(family=family):
                self.assertEqual(detect_device_family(**evidence).family, family)

    def test_family_command_plans_are_semantic_and_vendor_specific(self):
        cisco = driver_for(family="cisco-ios").command_plan("mac_lookup", mac="02:00:00:00:00:25")
        aruba_s = driver_for(family="aruba-aos-switch").command_plan("neighbors")
        aruba_cx = driver_for(family="aruba-aos-cx").command_plan("cable_status", interface="1/1/8")
        ruckus = driver_for(family="ruckus-fastiron").command_plan("mac_lookup", mac="02:00:00:00:00:25")
        self.assertIn("show mac address-table | include 0200.0000.0025", cisco)
        self.assertIn("show lldp info remote-device", aruba_s)
        self.assertIn("diag cable-diagnostic show 1/1/8", aruba_cx)
        self.assertIn("show mac-address 020000000025", ruckus)
        self.assertEqual(ruckus[0], "skip-page-display")

    def test_stream_cli_consumes_separator_before_driver_arguments(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = main([
                "stream",
                "--platform",
                "Ruckus FastIron",
                "--action",
                "mac-lookup",
                "--",
                "0200.0000.0025",
            ])
        self.assertEqual(result, 0)
        self.assertEqual(
            output.getvalue().splitlines(),
            ["skip-page-display", "show mac-address 020000000025", "exit"],
        )

    def test_unvalidated_vendor_configuration_is_blocked(self):
        for family in ("aruba-aos-switch", "aruba-aos-cx", "ruckus-fastiron"):
            with self.subTest(family=family), self.assertRaises(UnsupportedDeviceAction):
                driver_for(family=family).command_plan("config", commands=["hostname unsafe"])

    def test_registry_accepts_future_third_party_driver_without_core_changes(self):
        registry = DeviceDriverRegistry()
        registry.register(DeviceDriver(
            family="unknown",
            vendor="Unknown",
            os_name="Unknown",
            device_kind="unknown",
            support_level="unclassified",
        ))
        registry.register(DeviceDriver(
            family="fixture-os",
            vendor="Fixture",
            os_name="FixtureOS",
            device_kind="switch",
            support_level="test",
            command_templates={"inventory": ("display device",)},
            capabilities={"inventory": "supported"},
        ))
        self.assertEqual(registry.get("fixture-os").command_plan("inventory"), ["display device", "exit"])

    def test_declarative_driver_is_profile_local_detectable_and_read_only(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.toml"
            path.write_text(
                "schema_version = 1\n"
                "[driver]\nfamily = \"fixture-os\"\nvendor = \"Fixture\"\n"
                "operating_system = \"FixtureOS\"\npager_commands = [\"terminal length 0\"]\n"
                "[match]\nplatform = \"FixtureOS\"\nmodel = \"^EX-[0-9]{4}$\"\nconfidence = 84\n"
                "[commands]\ninventory = [\"show system\"]\n"
                "[capabilities]\ninventory = \"fixture-validated\"\n"
                "[parsers]\ninventory = \"fixture.inventory.v1\"\n",
                encoding="utf-8",
            )
            registry = __import__("netops_devices").REGISTRY.clone()
            self.assertEqual(registry.load_declarative(Path(directory))[0]["status"], "loaded")
            detection = registry.detect(platform="FixtureOS 4.2", model="EX-1000")
            self.assertEqual((detection.family, detection.confidence), ("fixture-os", 84))
            self.assertEqual(registry.get("fixture-os").parser_templates["inventory"], "fixture.inventory.v1")
            self.assertEqual(detect_device_family(platform="FixtureOS 4.2", model="EX-1000").family, "unknown")

    def test_declarative_driver_rejects_disguised_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "unsafe.toml"
            path.write_text(
                "schema_version = 1\n"
                "[driver]\nfamily = \"unsafe-os\"\n"
                "[match]\nplatform = \"UnsafeOS\"\n"
                "[commands]\ninventory = [\"configure terminal\"]\n",
                encoding="utf-8",
            )
            registry = __import__("netops_devices").REGISTRY.clone()
            report = registry.load_declarative(Path(directory))[0]
            self.assertEqual(report["status"], "rejected")
            self.assertIn("approved read operation", report["error"])

    def test_firmware_profiles_cover_common_version_banners(self):
        self.assertEqual(
            detect_device_family(sysdescr="Cisco NX-OS Software, Version 10.3(4a)").firmware_profile,
            "nxos-10.x",
        )
        self.assertEqual(
            detect_device_family(sysdescr="ArubaOS-CX Version 10.13.1040", model="CX 6300").firmware_profile,
            "aos-cx-10.x",
        )


if __name__ == "__main__":
    unittest.main()
