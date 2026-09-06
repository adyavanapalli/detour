"""Tests for detour.render, plus a sing-box check of the real Linux template when the binary exists."""
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from detour import render, wireguard

TEMPLATE = Path(__file__).resolve().parents[1] / "src" / "detour" / "templates" / "linux.json"


class RenderTest(unittest.TestCase):
    def test_replaces_every_occurrence(self):
        out = render.render('{"a": "__X__", "b": "__X__", "n": __N__}', {"x": "1", "n": "2"})
        self.assertEqual(out, '{"a": "1", "b": "1", "n": 2}')

    def test_missing_and_unused_values_are_named(self):
        with self.assertRaisesRegex(ValueError, "no value for X"):
            render.render("__X__", {})
        with self.assertRaisesRegex(ValueError, "no placeholder for Y"):
            render.render("__X__", {"x": "1", "y": "2"})

    def test_rejects_values_that_could_break_json(self):
        for bad in ("", 'a"b', "a\\b", "a\nb", 5):
            with self.assertRaises(ValueError):
                render.render("__X__", {"x": bad})

    def test_linux_template_renders_and_checks(self):
        values = dict(rules_url="https://example.invalid/r.jsonc", server_host="203.0.113.1", server_port="51820",
                      server_public_key="3p7bfXt9wbTTW2HC7OQ1Nz+DQ8hbeGdNrfx+FG+IK08=", tunnel_dns="10.0.0.1",
                      device_address="10.0.0.2/24", device_private_key=wireguard.generate_private_key(),
                      api_secret="secret")
        out = render.render(TEMPLATE.read_text(), values)
        self.assertEqual(render.PLACEHOLDER.findall(out), [])
        if shutil.which("sing-box"):
            with tempfile.NamedTemporaryFile("w", suffix=".json") as f:
                f.write(out); f.flush()
                subprocess.run(["sing-box", "check", "-c", f.name], check=True)


if __name__ == "__main__":
    unittest.main()
