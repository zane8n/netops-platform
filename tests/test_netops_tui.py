import asyncio
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock


try:
    import textual  # noqa: F401
except ModuleNotFoundError:
    TEXTUAL_AVAILABLE = False
else:
    TEXTUAL_AVAILABLE = True


ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(TEXTUAL_AVAILABLE, "Textual is installed by the v8 package")
class NetOpsTUITest(unittest.TestCase):
    def setUp(self):
        from netops_core import App
        from netops_platform.service import NetOpsService

        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.env = mock.patch.dict(
            os.environ,
            {
                "NETOPS_CONFIG_DIR": str(self.base / "config"),
                "NETOPS_CACHE_DIR": str(self.base / "cache"),
                "NETOPS_SQLITE_DB": str(self.base / "cache" / "netops.sqlite3"),
                "NETOPS_TUI_CONFIG": str(self.base / "tui.json"),
                "NETOPS_PROGRESS": "0",
            },
            clear=False,
        )
        self.env.start()
        self.core = App(ROOT)
        self.service = NetOpsService(self.core)

    def tearDown(self):
        self.core.shutdown_jobs(wait=0.1)
        self.env.stop()
        self.temp.cleanup()

    def test_console_mounts_without_network_io_at_supported_sizes(self):
        from netops_platform.tui.app import NetOpsConsole

        async def exercise():
            for size, expected in (((160, 48), (False, False)), ((120, 36), (True, False)), ((80, 24), (True, True))):
                app = NetOpsConsole(self.service)
                with mock.patch.object(self.core, "capture", side_effect=AssertionError("mount opened a transport")), mock.patch.object(self.core, "run_subprocess", side_effect=AssertionError("mount ran a helper")):
                    async with app.run_test(size=size) as pilot:
                        await pilot.pause()
                        self.assertEqual(app.screen.has_class("compact"), expected[0])
                        self.assertEqual(app.screen.has_class("narrow"), expected[1])
                        self.assertEqual(app.current_view, "operations")
                        self.assertTrue(app.screen.has_class("command-hub"))
                        self.assertTrue(app.screen.has_class("monochrome"))
                        self.assertTrue(app.theme.startswith("netops-plain-"))
                        self.assertEqual(app.query_one("#workbench").active_dataset.id, "commands")
                        self.assertFalse(app.query_one("#side-panel").display)
                        self.assertFalse(app.query_one("#metric-strip").display)
                        self.assertIsNotNone(app.query_one("#workbench"))
                        screenshot = app.export_screenshot()
                        self.assertIn("NetOps&#160;Operator&#160;Console", screenshot)
                        self.assertGreater(len(screenshot), 10_000)

        asyncio.run(exercise())

    def test_action_catalog_filter_enter_and_guarded_vlan_form(self):
        from textual.widgets import Button, Input, Select
        from netops_platform.tui.app import NetOpsConsole
        from netops_platform.tui.forms import ActionForm
        from netops_platform.tui.widgets import ResultWorkbench

        async def exercise():
            app = NetOpsConsole(self.service)
            async with app.run_test(size=(140, 42)) as pilot:
                await pilot.pause()
                await pilot.press("a")
                await app.workers.wait_for_complete()
                workbench = app.query_one(ResultWorkbench)
                self.assertEqual(workbench.active_dataset.id, "commands")
                filter_input = app.query_one("#result-filter", Input)
                filter_input.value = "guarded vlan"
                await pilot.pause()
                table = app.query_one("#result-table")
                self.assertEqual(table.row_count, 1)
                table.focus()
                await pilot.press("enter")
                await pilot.pause()
                self.assertIsInstance(app.screen, ActionForm)
                form = app.screen
                form.query_one("#field-target", Input).value = "SW1"
                form.query_one("#field-interface", Input).value = "Gi1/0/7"
                form.query_one("#field-vlan-mode", Select).value = "access"
                form.query_one("#field-vlan", Input).value = "131"
                form.refresh_preview()
                self.assertFalse(form.query_one("#action-run", Button).disabled)
                self.assertEqual(form.preview.confirmation_phrase, "APPLY SW1 Gi1/0/7")
                self.assertEqual(form.values()["target"], "SW1")
                self.assertEqual(form.values()["interface"], "Gi1/0/7")
                self.assertEqual(form.values()["vlan"], "131")
                await pilot.click("#action-cancel")
                await pilot.pause()
                self.assertNotIsInstance(app.screen, ActionForm)
                self.assertEqual(app.preference_values["saved_filters"]["commands"], "guarded vlan")

        asyncio.run(exercise())

    def test_theme_toggle_and_preferences_persist(self):
        from netops_platform.preferences import PreferenceStore
        from netops_platform.tui.app import NetOpsConsole
        from netops_platform.tui.forms import ExitScreen

        async def exercise():
            with mock.patch.dict(os.environ, {"NO_COLOR": ""}):
                app = NetOpsConsole(self.service)
                async with app.run_test(size=(120, 36)) as pilot:
                    await pilot.pause()
                    previous = app.theme
                    await pilot.press("t")
                    self.assertNotEqual(app.theme, previous)
                    app.preferences.save(app.preference_values)
                    app.active_jobs["job-active"] = 0
                    await pilot.press("q")
                    await pilot.pause()
                    self.assertIsInstance(app.screen, ExitScreen)
                    await pilot.click("#exit-stay")
                    await pilot.pause()
                    self.assertNotIsInstance(app.screen, ExitScreen)
                    app.active_jobs.clear()
            saved = PreferenceStore(self.base / "tui.json").load()
            self.assertEqual(saved["theme"], "netops-light")

        asyncio.run(exercise())

    def test_functions_details_and_drawer_are_on_demand(self):
        from netops_platform.tui.app import NetOpsConsole
        from netops_platform.tui.forms import FunctionScreen
        from netops_platform.tui.widgets import ResultWorkbench

        async def exercise():
            app = NetOpsConsole(self.service)
            async with app.run_test(size=(140, 42)) as pilot:
                await pilot.pause()
                self.assertFalse(app.query_one("#side-panel").display)
                workbench = app.query_one(ResultWorkbench)
                self.assertFalse(workbench.has_class("details-open"))
                await pilot.press("f")
                await pilot.pause()
                self.assertIsInstance(app.screen, FunctionScreen)
                await pilot.press("enter")
                await app.workers.wait_for_complete()
                self.assertEqual(app.current_view, "inventory")
                self.assertFalse(app.screen.has_class("command-hub"))
                await pilot.press("d")
                await pilot.pause()
                self.assertTrue(workbench.has_class("details-open"))
                self.assertTrue(app.query_one("#metric-strip").display)
                await pilot.press("i")
                self.assertTrue(app.screen.has_class("drawer-open"))
                self.assertTrue(app.query_one("#side-panel").display)
                await pilot.click("#drawer-close")
                self.assertFalse(app.screen.has_class("drawer-open"))

        asyncio.run(exercise())


if __name__ == "__main__":
    unittest.main()
