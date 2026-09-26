"""detour.chrome, with every path in a temporary directory. Nothing here needs root."""
import json
import shutil
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from detour import chrome

TABLE = {"rules_url": "https://example.invalid/rules.jsonc", "user_agent": "test-agent/1"}
HAS_OPENSSL = shutil.which("openssl") is not None


class ChromeTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.dirs = (root / "opt-ext", root / "share-ext")
        for d in self.dirs:
            d.mkdir()
        patches = {
            "DATA_DIR": root / "data", "LEGACY_DIR": root / "legacy",
            "POLICY": root / "policy.json", "LEGACY_POLICY": root / "chromium-policy.json",
            "DESCRIPTOR_DIRS": self.dirs,
        }
        for name, value in patches.items():
            p = mock.patch.object(chrome, name, value)
            p.start()
            self.addCleanup(p.stop)
        self.addCleanup(self.tmp.cleanup)

    def test_preflight_fails_without_chrome(self):
        with mock.patch.object(chrome.shutil, "which", return_value=None):
            with self.assertRaises(OSError) as cm:
                chrome.preflight()
        self.assertIn("Google Chrome is not installed", str(cm.exception))

    def test_config_json_has_no_defaults(self):
        self.assertEqual(json.loads(chrome.config_json(TABLE)),
                         {"gist_url": TABLE["rules_url"], "user_agent": "test-agent/1"})
        with self.assertRaises(ValueError) as cm:
            chrome.config_json({"rules_url": "x"})
        self.assertIn("missing user_agent", str(cm.exception))

    def test_version_grows_with_each_install(self):
        chrome.DATA_DIR.mkdir()
        self.assertEqual(chrome.next_version("1.1.0"), "1.1.0.1")
        self.assertEqual(chrome.next_version("1.1.0"), "1.1.0.2")

    def test_stage_adds_config_and_version(self):
        chrome.DATA_DIR.mkdir()
        dest = Path(self.tmp.name) / "stage"
        version = chrome.stage(dest, TABLE)
        self.assertEqual(json.loads((dest / "manifest.json").read_text())["version"], version)
        self.assertEqual((dest / "config.json").read_text(), chrome.config_json(TABLE))
        for prefix in ("icon", "icon-direct", "icon-error"):
            for size in (16, 32, 48, 128):
                self.assertTrue((dest / f"icons/{prefix}-{size}.png").exists(), f"{prefix}-{size}")
        manifest = json.loads((dest / "manifest.json").read_text())
        self.assertNotIn("default_popup", manifest["action"])  # the icon is the whole UI
        self.assertIn("webRequest", manifest["permissions"])  # for the blocked-request count

    @unittest.skipUnless(HAS_OPENSSL, "openssl is not installed")
    def test_key_moves_from_the_old_installer_and_keeps_the_id(self):
        chrome.LEGACY_DIR.mkdir()
        old = chrome.LEGACY_DIR / "key.pem"
        old.write_bytes(chrome.subprocess.run(["openssl", "genrsa", "2048"], capture_output=True).stdout)
        key = chrome.ensure_key()
        self.assertEqual(key.read_bytes(), old.read_bytes())
        self.assertEqual(stat.S_IMODE(key.stat().st_mode), 0o600)
        ext_id = chrome.extension_id(key)
        self.assertRegex(ext_id, r"^[a-p]{32}$")
        self.assertEqual(ext_id, chrome.extension_id(old))

    def test_root_files_find_only_our_descriptors(self):
        ours = self.dirs[0] / "aaaa.json"
        ours.write_text(json.dumps({"external_crx": str(chrome.LEGACY_DIR / "detour-sentry.crx")}))
        other = self.dirs[0] / "bbbb.json"
        other.write_text(json.dumps({"external_crx": "/home/someone/.local/share/url-owl/url-owl.crx"}))
        chrome.LEGACY_POLICY.write_text("{}")
        self.assertEqual(chrome.root_files(), [chrome.LEGACY_POLICY, ours])

    def test_current_needs_the_policy_and_the_same_config(self):
        chrome.DATA_DIR.mkdir()
        (chrome.DATA_DIR / "config.json").write_text(chrome.config_json(TABLE))
        self.assertFalse(chrome.current(TABLE))  # no policy
        chrome.POLICY.write_text("{}")
        self.assertTrue(chrome.current(TABLE))
        self.assertFalse(chrome.current({**TABLE, "user_agent": "other/2"}))
        self.assertFalse(chrome.current({"rules_url": "x"}))

    def test_put_first_moves_both_copies_and_keeps_the_rest(self):
        prefs = {"extensions": {"pinned_extensions": ["a", "me", "b"]},
                 "account_values": {"extensions": {"pinned_extensions": ["c", "a", "me"]}}}
        chrome.put_first(prefs, "me")
        self.assertEqual(prefs["extensions"]["pinned_extensions"], ["me", "a", "b"])
        self.assertEqual(prefs["account_values"]["extensions"]["pinned_extensions"], ["me", "c", "a"])

    def test_put_first_removes_duplicates(self):
        # Chrome adds a default_pinned ID again at the end; a drag with a duplicate crashes Chrome
        prefs = {"extensions": {"pinned_extensions": ["a", "me", "b", "me"]},
                 "account_values": {"extensions": {"pinned_extensions": ["a", "me", "b", "me"]}}}
        chrome.put_first(prefs, "me")
        self.assertEqual(prefs["extensions"]["pinned_extensions"], ["me", "a", "b"])
        self.assertEqual(prefs["account_values"]["extensions"]["pinned_extensions"], ["me", "a", "b"])

    def test_put_first_adds_a_new_id_but_never_creates_the_account_copy(self):
        prefs = {"account_values": {"other": 1}}
        chrome.put_first(prefs, "me")
        self.assertEqual(prefs["extensions"]["pinned_extensions"], ["me"])
        self.assertEqual(prefs["account_values"], {"other": 1})

    def test_pin_first_edits_every_profile_with_chrome_stopped(self):
        user_data = Path(self.tmp.name) / "google-chrome"
        for name in ("Default", "Profile 1", "System Profile"):
            (user_data / name).mkdir(parents=True)
            (user_data / name / "Preferences").write_text(json.dumps({"extensions": {"pinned_extensions": ["x"]}}))
        (user_data / "Profile 1" / "Preferences").chmod(0o600)
        with mock.patch.object(chrome, "USER_DATA_DIR", user_data), \
                mock.patch.object(chrome, "stop_chrome", return_value=False) as stop:
            chrome.pin_first("me")
        stop.assert_called_once()
        for name, want in (("Default", ["me", "x"]), ("Profile 1", ["me", "x"]), ("System Profile", ["x"])):
            got = json.loads((user_data / name / "Preferences").read_text())["extensions"]["pinned_extensions"]
            self.assertEqual(got, want, name)
        self.assertEqual(stat.S_IMODE((user_data / "Profile 1" / "Preferences").stat().st_mode), 0o600)

    def test_chrome_pids_match_only_the_browser_of_this_user(self):
        proc = Path(self.tmp.name) / "proc"
        for pid, exe in (("100", chrome.CHROME_EXE), ("101", "/opt/google/chrome/chrome_crashpad_handler"),
                         ("102", "/usr/bin/bash")):
            (proc / pid).mkdir(parents=True)
            (proc / pid / "exe").symlink_to(exe)
        (proc / "self").mkdir()
        self.assertEqual(chrome.chrome_pids(proc), [100])

    def test_only_main_browser_processes_get_sigterm(self):
        proc = Path(self.tmp.name) / "proc"
        # 200 is a browser started by a shell (1), 201 and 202 are its children, 300 is a second browser
        for pid, ppid in ((200, 1), (201, 200), (202, 201), (300, 1)):
            (proc / str(pid)).mkdir(parents=True)
            (proc / str(pid) / "stat").write_text(f"{pid} (chrome (x)) S {ppid} 0 0")
        self.assertEqual(chrome.browsers([200, 201, 202, 300], proc), [200, 300])

    @unittest.skipUnless(HAS_OPENSSL and any(map(shutil.which, chrome.CHROME_NAMES)), "needs Chrome and openssl")
    def test_build_packs_with_chrome(self):
        ext_id, files = chrome.build(chrome.find_chrome(), TABLE)
        crx = chrome.DATA_DIR / chrome.CRX_NAME
        self.assertTrue(crx.exists())
        self.assertEqual(ext_id, chrome.extension_id(chrome.DATA_DIR / "key.pem"))
        policy = json.loads(files[chrome.POLICY])["ExtensionSettings"][ext_id]
        self.assertEqual(policy["installation_mode"], "force_installed")
        self.assertEqual(policy["toolbar_pin"], "force_pinned")
        self.assertIn(ext_id, (chrome.DATA_DIR / "update.xml").read_text())
        for d in self.dirs:
            self.assertEqual(json.loads(files[d / f"{ext_id}.json"])["external_crx"], str(crx))
        self.assertFalse(chrome.current(TABLE))  # linux.py has not written the policy yet


if __name__ == "__main__":
    unittest.main()
