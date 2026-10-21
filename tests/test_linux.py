"""detour.linux without root: the lockdown files, the readiness gate, and the order of install_system."""
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from detour import linux, probes, render

STUB_RESOLV_CONF = """# This is /run/systemd/resolve/stub-resolv.conf managed by man:systemd-resolved(8).
# Do not edit.

nameserver 127.0.0.53
options edns0 trust-ad
"""


class ResolvConfTest(unittest.TestCase):
    def test_the_stub_file_of_resolved_is_managed(self):
        self.assertTrue(linux.resolved_managed(STUB_RESOLV_CONF))

    def test_other_files_are_not(self):
        self.assertFalse(linux.resolved_managed("nameserver 127.0.0.53\n"))
        self.assertFalse(linux.resolved_managed("# written by hand\nnameserver 127.0.0.53\n"))
        self.assertFalse(linux.resolved_managed("\n" + STUB_RESOLV_CONF))  # sing-box stops at an empty line
        self.assertFalse(linux.resolved_managed(""))


class LockdownFilesTest(unittest.TestCase):
    def test_rules_name_the_sing_box_user_and_keep_the_order(self):
        rules = linux.lockdown_rules(123)
        self.assertEqual(render.PLACEHOLDER.findall(rules), [])
        self.assertIn("meta skuid 123 accept", rules)
        self.assertIn("meta mark & 0x00ff0000 == 0x00080000 accept", rules)  # tailscaled
        self.assertIn('oifname "tailscale0" ip daddr 100.64.0.0/10 accept', rules)
        self.assertIn('oifname "tailscale0" ip6 daddr fd7a:115c:a1e0::/48 accept', rules)
        order = ['oifname "sbtun0" accept', 'oifname "tailscale0" ip daddr', "th dport 53 reject", "jump lan",
                 "reject with icmpx admin-prohibited"]
        positions = [rules.index(line) for line in order]
        self.assertEqual(positions, sorted(positions))  # DNS is refused before the LAN and the final reject

    def test_lan_chain_is_empty_until_sing_box_fills_it(self):
        rules = linux.lockdown_rules(123)
        start = rules.index("chain lan {")
        body = rules[start:rules.index("}", start)]
        self.assertNotIn("accept", body)
        for private in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"):
            self.assertNotIn(private, rules)
        lan = linux.template("lan.nft")
        self.assertIn("flush chain inet detour lan", lan)
        self.assertIn("ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } accept", lan)

    def test_sing_box_unit_opens_the_lan_while_it_runs(self):
        self.assertIn(f"ExecStartPost=-+{linux.NFT} -f {linux.LAN_RULES}\n", linux.UNIT_TEXT)
        self.assertIn(f"ExecStopPost=-+{linux.NFT} flush chain inet detour lan\n", linux.UNIT_TEXT)

    def test_lockdown_unit_loads_before_the_network_and_never_stops_open(self):
        text = linux.LOCKDOWN_UNIT_TEXT
        self.assertIn("Before=network-pre.target", text)
        self.assertIn(f"ExecStart={linux.NFT} -f {linux.LOCKDOWN_RULES}\n", text)
        self.assertNotIn("ExecStop=", text)
        # a restart of the unit empties the lan chain; it opens the LAN again when sing-box runs
        self.assertIn(f"systemctl is-active --quiet {linux.UNIT} && exec {linux.NFT} -f {linux.LAN_RULES}", text)

    def test_template_starts_from_the_saved_rule_list(self):
        self.assertIn(f'"initial_path": "{linux.RULES_COPY}"', linux.template("linux.json"))


class WaitReadyTest(unittest.TestCase):
    def problem(self, state="active", intercepted=True, resolved=("203.0.113.1",)):
        with mock.patch.object(linux, "service_state", return_value=state), \
                mock.patch.object(probes, "dns_intercepted", return_value=intercepted), \
                mock.patch.object(probes, "resolve", return_value=list(resolved)):
            return linux.wait_ready(seconds=0)

    def test_ready(self):
        self.assertIsNone(self.problem())

    def test_each_problem_is_named(self):
        self.assertEqual(self.problem(state="failed"), "sing-box is failed")
        self.assertEqual(self.problem(intercepted=None), "nothing answers DNS on 127.0.0.53")
        self.assertIn("DNS bypasses sing-box", self.problem(intercepted=False))
        self.assertIn("cannot resolve", self.problem(resolved=()))


class InstallSystemTest(unittest.TestCase):
    """The safety rules: the lockdown comes on only when sing-box is ready, and never goes off on a failure."""

    def install(self, locked: bool, problem: str | None) -> tuple[mock.Mock, list]:
        calls = []
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        steps = mock.Mock()
        patches = [
            mock.patch.object(linux, "fail_closed", return_value=locked),
            mock.patch.object(linux, "install_package"),
            mock.patch.object(linux, "save_rules_copy"),
            mock.patch.object(linux.device, "rendered_config", return_value="{}"),
            mock.patch.object(linux, "CONF_DIR", Path(tmp.name)),
            mock.patch.object(linux, "run", side_effect=lambda *cmd, **kw: calls.append(cmd)),
            mock.patch.object(linux, "write_root_file", side_effect=lambda path, *a, **kw: calls.append(("write", path))),
            mock.patch.object(linux, "wait_ready", return_value=problem),
            mock.patch.object(linux, "enable_lockdown", steps.enable_lockdown),
            mock.patch.object(linux, "restore_resolver", steps.restore_resolver),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        return steps, calls

    def test_ready_turns_the_lockdown_on(self):
        steps, calls = self.install(locked=False, problem=None)
        linux.install_system({"rules_url": "https://example.invalid/r.jsonc"})
        steps.enable_lockdown.assert_called_once()
        steps.restore_resolver.assert_not_called()
        stub_off = calls.index(("write", linux.RESOLVED_DROPIN))
        resolved = calls.index(("systemctl", "restart", "systemd-resolved"))
        sing_box = calls.index(("systemctl", "restart", linux.UNIT))
        self.assertLess(stub_off, resolved)  # resolved frees 127.0.0.53 before sing-box takes it
        self.assertLess(resolved, sing_box)

    def test_first_install_that_fails_puts_dns_back(self):
        steps, _ = self.install(locked=False, problem="sing-box is failed")
        with self.assertRaisesRegex(OSError, "lockdown is off"):
            linux.install_system({"rules_url": "https://example.invalid/r.jsonc"})
        steps.restore_resolver.assert_called_once()
        steps.enable_lockdown.assert_not_called()

    def test_failure_under_the_lockdown_stays_closed(self):
        steps, _ = self.install(locked=True, problem="sing-box is failed")
        with self.assertRaisesRegex(OSError, "lockdown stays on"):
            linux.install_system({"rules_url": "https://example.invalid/r.jsonc"})
        steps.restore_resolver.assert_not_called()
        steps.enable_lockdown.assert_not_called()


if __name__ == "__main__":
    unittest.main()
