"""Tests for detour.config in a temporary XDG_CONFIG_HOME."""
import os
import stat
import tempfile
import unittest

from detour import config


class ConfigTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ["XDG_CONFIG_HOME"] = self.tmp.name

    def tearDown(self):
        os.environ.pop("XDG_CONFIG_HOME", None)
        self.tmp.cleanup()

    def test_missing_file_reads_as_empty(self):
        self.assertEqual(config.load(), {})
        self.assertEqual(config.get("linux"), {})
        self.assertIsNone(config.get("linux", "rules_url"))

    def test_round_trip_escapes_and_mode(self):
        tricky = 'quote " backslash \\ tab \t end'
        config.put("linux", "rules_url", "https://example.invalid/list.jsonc")
        config.put("linux", "device_private_key", tricky)
        self.assertEqual(config.get("linux", "device_private_key"), tricky)
        mode = stat.S_IMODE(os.stat(config.path()).st_mode)
        self.assertEqual(mode, 0o600)

    def test_replaces_a_loose_file_with_0600(self):
        config.path().parent.mkdir(parents=True)
        config.path().write_text('[linux]\nrules_url = "x"\n')
        os.chmod(config.path(), 0o644)
        config.put("linux", "tunnel_dns", "10.0.0.1")
        self.assertEqual(stat.S_IMODE(os.stat(config.path()).st_mode), 0o600)
        self.assertEqual(config.get("linux", "rules_url"), "x")

    def test_targets_are_independent(self):
        config.put("linux", "rules_url", "https://a.invalid/")
        config.put("android", "rules_url", "https://b.invalid/")
        self.assertEqual(config.get("linux", "rules_url"), "https://a.invalid/")
        self.assertEqual(config.get("android", "rules_url"), "https://b.invalid/")

    def test_rejects_unknown_target_and_key(self):
        with self.assertRaises(ValueError):
            config.get("windows")
        with self.assertRaises(ValueError):
            config.put("linux", "rules", "x")

    def test_require_names_every_missing_key(self):
        config.put("android", "rules_url", "https://b.invalid/")
        with self.assertRaises(ValueError) as cm:
            config.require("android", ("rules_url", "server_endpoint", "device_address"))
        self.assertIn("server_endpoint, device_address", str(cm.exception))
        config.put("android", "server_endpoint", "h:1")
        config.put("android", "device_address", "10.0.0.3/24")
        self.assertEqual(config.require("android", ("server_endpoint",))["server_endpoint"], "h:1")


if __name__ == "__main__":
    unittest.main()
