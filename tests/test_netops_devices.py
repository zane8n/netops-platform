import contextlib
import io
import unittest
from pathlib import Path
import tempfile

from netops_devices import (
    REGISTRY,
    DeviceDriver,
    DeviceDriverRegistry,
    UnsupportedDeviceAction,
    detect_device_family,
    device_manufacturer,
    driver_for,
    firmware_certification,
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

    def test_manufacturer_comes_from_the_model_before_any_label(self):
        fixtures = (
            ({"platform": "Cisco IOS", "model": "C9200CX-12P-2X2G"}, "Cisco"),
            ({"platform": "Ruckus FastIron", "model": "C9200L-24P-4G"}, "Cisco"),
            ({"platform": "Cisco IOS", "model": "IE-3300-8U2X"}, "Cisco"),
            ({"platform": "Aruba AOS-S", "model": "2930F-8G-PoE+-2SFP+"}, "Aruba"),
            ({"platform": "Aruba AOS-S", "model": "5412Rzl2"}, "Aruba"),
            ({"platform": "", "model": "JL258A"}, "Aruba"),
            ({"platform": "Ruckus R610 Multimedia Hotzone Wireless AP"}, "Ruckus"),
            ({"platform": "cisco C9136I-ROW"}, "Cisco"),
            ({"platform": "Cisco-AP"}, "Cisco"),
            ({"platform": "UAP-AC-Mesh-Pro, 4.3.21.11325"}, "Ubiquiti"),
            ({"platform": "Cisco IOS", "model": "N/A"}, "Cisco"),
            ({"platform": "", "model": "N/A", "family": "aruba-aos-cx"}, "Aruba"),
            ({"platform": "ex House14 AP"}, ""),
        )
        for evidence, maker in fixtures:
            with self.subTest(evidence=evidence):
                self.assertEqual(device_manufacturer(**evidence), maker)

    def test_model_number_overrides_a_label_naming_another_maker(self):
        # A stored platform label is netrune's own earlier verdict; fed back in
        # it used to keep a mislabelled switch on the wrong driver forever.
        cisco = detect_device_family(platform="Ruckus FastIron", model="C9200L-24P-4G", hostname="SW1")
        self.assertEqual(cisco.family, "cisco-ios")
        self.assertIn("model C9200L-24P-4G is Cisco", cisco.reasons[0])
        self.assertEqual(detect_device_family(platform="Cisco IOS", model="2930F-8G-PoE+-2SFP+").family, "aruba-aos-switch")
        # A hostname left over from the vendor a switch replaced is a stale label too.
        self.assertEqual(detect_device_family(platform="Cisco IOS", model="C9300", hostname="ARUBA-SW").family, "cisco-ios")
        # Agreement, and a model that names no maker, change nothing.
        self.assertEqual(detect_device_family(platform="Cisco IOS", model="C9300-48P").reasons, ("Cisco IOS platform marker",))
        self.assertEqual(detect_device_family(platform="RUCKUS ICX7150 FastIron", model="N/A").family, "ruckus-fastiron")

    def test_family_command_plans_are_semantic_and_vendor_specific(self):
        cisco = driver_for(family="cisco-ios").command_plan("mac_lookup", mac="02:00:00:00:00:25")
        aruba_s = driver_for(family="aruba-aos-switch").command_plan("neighbors")
        aruba_cx = driver_for(family="aruba-aos-cx").command_plan("cable_status", interface="1/1/8")
        ruckus = driver_for(family="ruckus-fastiron").command_plan("mac_lookup", mac="02:00:00:00:00:25")
        cisco_address = "show mac address-table address 0200.0000.0025"
        cisco_filter = "show mac address-table | include 0200.0000.0025"
        self.assertLess(cisco.index(cisco_address), cisco.index(cisco_filter))
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

    def test_supported_config_write_only_requires_writes_enabled(self):
        # cisco-ios, cisco-nxos, aruba-aos-switch, and aruba-aos-cx all carry
        # capability("configuration") == "supported": their config_enter/
        # config_exit/save are trusted across the whole product line, so
        # device_writes_enabled is the only thing command_plan("config", ...)
        # still requires -- no firmware_certified needed. Missing
        # writes_enabled must still refuse regardless of anything else.
        for family in ("cisco-ios", "cisco-nxos", "aruba-aos-switch", "aruba-aos-cx"):
            with self.subTest(family=family):
                driver = driver_for(family=family)
                self.assertEqual(driver.capability("configuration"), "supported")
                with self.assertRaises(UnsupportedDeviceAction):
                    driver.command_plan("config", commands=["hostname test"])
                with self.assertRaises(UnsupportedDeviceAction):
                    driver.command_plan("config", commands=["hostname test"], firmware_certified=True)
                self.assertTrue(driver.command_plan("config", commands=["hostname test"], writes_enabled=True))

    def test_firmware_gated_config_write_still_requires_both_certification_and_writes_enabled(self):
        # No built-in driver uses "firmware-gated" for "configuration" today
        # (see the test above -- all four writable ones are unconditionally
        # "supported"), but the mechanism stays real for a future driver
        # whose write syntax genuinely does vary by firmware. Regression
        # guard: command_plan("config", ...) must never silently allow a
        # firmware-gated write -- a caller that omits firmware_certified/
        # writes_enabled (the shape every real caller used before this was
        # wired up) has to be refused, not treated as certified by default.
        driver = DeviceDriver(
            family="fixture-gated-os", vendor="Fixture", os_name="FixtureOS", device_kind="switch",
            support_level="test", source="built-in",
            command_templates={"config_enter": ("configure",), "config_exit": ("end",), "save": ("write memory",)},
            capabilities={"configuration": "firmware-gated"},
            firmware_profiles=("fixture-15.x",),
        )
        with self.assertRaises(UnsupportedDeviceAction):
            driver.command_plan("config", commands=["hostname test"])
        with self.assertRaises(UnsupportedDeviceAction):
            driver.command_plan("config", commands=["hostname test"], firmware_certified=True)
        with self.assertRaises(UnsupportedDeviceAction):
            driver.command_plan("config", commands=["hostname test"], writes_enabled=True)
        self.assertTrue(driver.command_plan("config", commands=["hostname test"], firmware_certified=True, writes_enabled=True))

    def test_certified_and_enabled_config_write_renders_the_full_command_sequence(self):
        driver = driver_for(family="cisco-ios")
        commands = driver.command_plan(
            "config", commands=["no logging host 192.0.2.1"],
            firmware_certified=True, writes_enabled=True,
        )
        self.assertEqual(
            commands,
            ["terminal length 0", "configure terminal", "no logging host 192.0.2.1", "end", "write memory", "exit"],
        )

    def test_firmware_certification_covers_built_in_operator_and_floor_paths(self):
        driver = driver_for(family="cisco-ios")
        certified_detection = detect_device_family(platform="Cisco IOS XE Software", sysdescr="Version 17.9.1")
        self.assertEqual(certified_detection.firmware_profile, "ios-xe-17.x")
        self.assertEqual(firmware_certification(driver, certified_detection, "IRRELEVANT EVIDENCE"), (True, "built-in"))

        uncertified_detection = detect_device_family(platform="Cisco IOS", model="C9300L-24P-4G")
        self.assertEqual(uncertified_detection.firmware_profile, "unverified")

        self.assertEqual(
            firmware_certification(driver, uncertified_detection, "CISCO IOS C9300L-24P-4G HOST1"),
            (False, ""),
        )
        self.assertEqual(
            firmware_certification(
                driver, uncertified_detection, "CISCO IOS C9300L-24P-4G HOST1",
                exact_patterns="cisco-ios:C9300L",
            ),
            (True, "operator"),
        )
        self.assertEqual(
            firmware_certification(
                driver, uncertified_detection, "CISCO IOS C9300L-24P-4G HOST1",
                exact_patterns="aruba-aos-switch:C9300L",  # wrong family, must not match
            ),
            (False, ""),
        )
        self.assertEqual(
            firmware_certification(
                driver, uncertified_detection, "CISCO IOS SOMETHING VERSION 12.2(55)SE",
                floor_ranges="cisco-ios:12.0",
            ),
            (True, "operator-floor"),
        )
        self.assertEqual(
            firmware_certification(
                driver, uncertified_detection, "CISCO IOS SOMETHING VERSION 11.3(2)T",
                floor_ranges="cisco-ios:12.0",
            ),
            (False, ""),
        )

    def test_stream_cli_threads_certification_flags_into_a_real_config_write(self):
        # This is the exact path netops-control shells out to: without
        # --writes-enabled/--certified-patterns (or --certified-floors)
        # reaching this CLI, a "config" action can never succeed no matter
        # what the Python-level preflight gate decided.
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = main([
                "stream", "--platform", "Cisco IOS", "--model", "C9300L-24P-4G", "--hostname", "SW1",
                "--action", "config", "--writes-enabled", "--certified-patterns", "cisco-ios:C9300L",
                "--", "no logging host 192.0.2.1", "logging host 198.51.100.1",
            ])
        self.assertEqual(result, 0)
        self.assertEqual(
            output.getvalue().splitlines(),
            [
                "terminal length 0", "configure terminal",
                "no logging host 192.0.2.1", "logging host 198.51.100.1",
                "end", "write memory", "exit",
            ],
        )

        # Without --writes-enabled, the same otherwise-certified request is refused.
        refused = io.StringIO()
        with contextlib.redirect_stdout(refused), contextlib.redirect_stderr(refused):
            result = main([
                "stream", "--platform", "Cisco IOS", "--model", "C9300L-24P-4G", "--hostname", "SW1",
                "--action", "config", "--certified-patterns", "cisco-ios:C9300L",
                "--", "no logging host 192.0.2.1",
            ])
        self.assertEqual(result, 5)
        self.assertIn("not enabled for the", refused.getvalue())

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


class NxosDriverTest(unittest.TestCase):
    """NX-OS was registered but never exercised: its templates had never been
    rendered, and no output had ever been run through a parser."""

    def setUp(self):
        self.driver = REGISTRY.get("cisco-nxos")

    def test_nxos_is_detected_from_its_own_version_banner(self):
        detection = REGISTRY.detect(
            sysdescr="Cisco Nexus Operating System (NX-OS) Software, Version 9.3(10)"
        )
        self.assertEqual(detection.family, "cisco-nxos")
        self.assertEqual(detection.firmware_profile, "nxos-9.x")

    def test_nxos_renders_every_declared_read_operation(self):
        values = {"vlan": 112, "interface": "Ethernet1/1", "destination": "198.51.100.5",
                  "lookup": "198.51.100.5", "count": 5, "timeout": 2, "mac": "0200.0000.0025"}
        for operation in sorted(self.driver.command_templates):
            if operation in {"config_enter", "config_exit", "save"}:
                continue
            with self.subTest(operation=operation):
                plan = self.driver.command_plan(operation, **values)
                # The pager must lead and the logout must close every stream.
                self.assertEqual(plan[0], "terminal length 0")
                self.assertEqual(plan[-1], "exit")
                self.assertTrue(all(str(step).strip() for step in plan))
                self.assertNotIn("{", " ".join(plan), "an unsubstituted placeholder reached the device")

    def test_nxos_uses_nxos_spellings_not_ios_ones(self):
        self.assertEqual(self.driver.command_templates["lag"], ("show port-channel summary",))
        self.assertEqual(self.driver.command_templates["svi"], ("show interface vlan {vlan}",))
        self.assertEqual(self.driver.command_templates["save"], ("copy running-config startup-config",))

    def test_nxos_output_parses_with_the_shared_parsers(self):
        from netops_network import (
            parse_lag_output,
            parse_mac_table_output,
            parse_spanning_tree_output,
        )
        stp = parse_spanning_tree_output("""
VLAN0112
  Spanning tree enabled protocol rstp
  Root ID    Priority    32880
             Address     0011.2233.4455

  Bridge ID  Priority    32880  (priority 32768 sys-id-ext 112)
             Address     aabb.ccdd.eeff

Interface        Role Sts Cost      Prio.Nbr Type
---------------- ---- --- --------- -------- ------
Eth1/1           Root FWD 4         128.1    P2p
Eth1/2           Desg FWD 4         128.2    P2p
""")
        self.assertEqual(stp["switch_mac"], "aabbccddeeff")
        self.assertEqual([row["port"] for row in stp["ports"]], ["Eth1/1", "Eth1/2"])
        self.assertEqual([row["vlan"] for row in stp["ports"]], [112, 112])

        fdb = parse_mac_table_output(
            "* 112      0200.0000.0025   dynamic  0    F  F  Eth1/12", "0200.0000.0025"
        )
        self.assertEqual(fdb[0]["vlan"], "112")
        self.assertEqual(fdb[0]["port"], "Eth1/12")

        lag = parse_lag_output("""
Group Port-       Type     Protocol  Member Ports
      Channel
--------------------------------------------------------------------------------
1     Po1(SU)     Eth      LACP      Eth1/1(P) Eth1/2(P)
""")
        self.assertTrue(lag["groups"][0]["operational"])
        self.assertEqual(lag["interfaces"]["eth1/1"]["group"], "Po1")
