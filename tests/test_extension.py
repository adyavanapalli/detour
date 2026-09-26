"""The extension's background.js, run in Node with fake chrome and fetch objects (tests/extension_harness.mjs)."""
import json
import shutil
import subprocess
import unittest
from importlib import resources
from pathlib import Path

NODE = shutil.which("node")


@unittest.skipUnless(NODE, "needs Node")
class ToolbarTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        background = resources.files("detour").joinpath("extension/background.js")
        harness = Path(__file__).with_name("extension_harness.mjs")
        out = subprocess.run([NODE, str(harness), str(background)], capture_output=True, text=True, check=True)
        cls.result = json.loads(out.stdout)

    def test_icon_per_tab_state(self):
        icons = self.result["ok"]["icons"]
        self.assertEqual(icons["1"], "icons/icon-16.png")  # listed: tunneled
        self.assertEqual(icons["2"], "icons/icon-direct-16.png")  # unlisted: direct
        self.assertEqual(icons["3"], "icons/icon-direct-16.png")  # not a web page

    def test_tooltip_is_the_state_and_the_sync_time(self):
        titles = self.result["ok"]["titlesAfterBlocks"]
        self.assertRegex(titles["1"], r"^Detour Sentry\nTUNNELED\nSynced at .+\nClick to sync now$")
        self.assertRegex(titles["2"], r"^Detour Sentry\nDIRECT\nSynced at .+\nClick to sync now$")
        self.assertRegex(titles["3"], r"^Detour Sentry\nDIRECT\n")  # not a web page

    def test_badge_shows_the_count_on_listed_tabs_only(self):
        badges = self.result["ok"]["badgesAfterBlocks"]
        self.assertEqual(badges["1"], "2")
        self.assertEqual(badges["2"], "")  # direct
        self.assertEqual(badges["3"], "")  # not a web page

    def test_count_resets_on_a_new_page(self):
        self.assertEqual(self.result["ok"]["badgesAfterNavigation"]["1"], "")  # empty at 0, like uBlock Origin

    def test_click_shows_progress_on_the_clicked_tab(self):
        log = self.result["ok"]["clickLog"]
        self.assertEqual(log[0], "\u2026")
        self.assertEqual(log[-1], "")  # the count (0 before any block) is back

    def test_failed_sync_turns_every_tab_red(self):
        failed = self.result["failed"]
        self.assertEqual(set(failed["icons"].values()), {"icons/icon-error-16.png"})
        self.assertRegex(failed["titlesAfterBlocks"]["2"],
                         r"^Detour Sentry\nSync failed: config.json must set gist_url and user_agent.*\nDIRECT\nNever synced\n")


if __name__ == "__main__":
    unittest.main()
