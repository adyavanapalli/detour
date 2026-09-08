"""detour.android: the parsers that read a phone's answers. Samples are real output from Android 17."""
import unittest
from unittest.mock import patch

from detour import android

PING_FAKEIP = "PING ipv4.icanhazip.com (198.18.0.2) 56(84) bytes of data.\n\n--- ipv4.icanhazip.com ping statistics ---\n"
PING_REAL = "PING comcast.com (96.99.227.0) 56(84) bytes of data.\n"
PING_UNKNOWN = "ping: unknown host nxdomain-test.invalid\n"
PING_DENIED = "ping: socket: Permission denied\n"

HTTP_REPLY = "HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/plain\r\n\r\n203.0.113.7\n"
HTTP_REDIRECT = "HTTP/1.1 301 Moved Permanently\r\nLocation: https://example.com/\r\n\r\n<html></html>\n"

KEYS_SET = "io.nekohasekai.sfa\n1\n"
KEYS_CLEARED = "null\n0\n"
DUMP_ON = ("VPNs:\n  0: io.nekohasekai.sfa\n    Active package name: io.nekohasekai.sfa\n"
           "    mEventChanges (most recent first):\n"
           "      2026-09-08T03:29:30 - [LockdownAlwaysOn] Mode changed: lockdown=true alwaysOn=true calling from 1000\n"
           "      2026-09-08T03:24:02 - [LockdownAlwaysOn] Mode changed: lockdown=false alwaysOn=false calling from 1000\n")
DUMP_OFF = DUMP_ON.replace("lockdown=true alwaysOn=true", "lockdown=false alwaysOn=false", 1)
DUMP_FRESH = "VPNs:\n  0: null\n    mEventChanges (most recent first):\n"

SYS_CLASS_NET = "aware_nmi0 dummy0 lo tun0 tunl0 wlan0 wwan0\n"

CHECK_UPDATE = ('<node index="0" text="Check Update" class="android.widget.TextView" bounds="[100,100][900,200]" />'
                '<node index="1" text="Would you like to enable automatic update checking from GitHub?" bounds="[100,220][900,300]" />'
                '<node index="2" text="No, thanks" class="android.widget.Button" bounds="[1000,1500][1200,1600]" />'
                '<node index="3" text="OK" class="android.widget.Button" bounds="[1450,1500][1650,1600]" />')
EDIT_PROFILE = ('<node index="0" text="Edit Profile" class="android.widget.TextView" bounds="[100,100][900,200]" />'
                '<node index="1" text="detour" class="android.widget.EditText" bounds="[100,300][900,400]" />')

class PingTest(unittest.TestCase):
    def test_answers(self):
        self.assertEqual(android.parse_ping(PING_FAKEIP), ["198.18.0.2"])
        self.assertEqual(android.parse_ping(PING_REAL), ["96.99.227.0"])

    def test_unknown_host_is_nxdomain(self):
        self.assertEqual(android.parse_ping(PING_UNKNOWN), [])

    def test_other_failures_are_unknown(self):
        self.assertIsNone(android.parse_ping(PING_DENIED))
        self.assertIsNone(android.parse_ping(""))


class BodyTest(unittest.TestCase):
    def test_ip_body(self):
        self.assertEqual(android.parse_body(HTTP_REPLY), "203.0.113.7")

    def test_anything_else_is_none(self):
        self.assertIsNone(android.parse_body(HTTP_REDIRECT))
        self.assertIsNone(android.parse_body(""))


class FailClosedTest(unittest.TestCase):
    def test_saved_and_in_effect(self):
        self.assertTrue(android.parse_fail_closed(KEYS_SET, DUMP_ON))

    def test_saved_but_not_in_effect_until_reboot(self):
        self.assertFalse(android.parse_fail_closed(KEYS_SET, DUMP_OFF))
        self.assertFalse(android.parse_fail_closed(KEYS_SET, DUMP_FRESH))

    def test_in_effect_but_cleared_for_next_boot(self):
        self.assertFalse(android.parse_fail_closed(KEYS_CLEARED, DUMP_ON))

    def test_another_vpn_app(self):
        self.assertFalse(android.parse_fail_closed("com.example.vpn\n1\n", DUMP_ON))


ERROR_DIALOG = ["Error", "Failed to decode profile: invalid message", "Copy", "OK"]
IMPORT_DIALOG = ["Import Profile", 'Import profile "detour"?', "Cancel", "Import"]


class FakeSelector:
    """What d(text=...) or d(description=...) returns on the fake device."""
    def __init__(self, dev, kind, value):
        self.dev, self.kind, self.value = dev, kind, value

    @property
    def exists(self):
        return self.value in self.dev.screen()

    def wait(self, timeout=0):
        return self.exists

    def click(self, timeout=None):
        if self.kind == "switch":
            self.dev.switches[self.value] = not self.dev.switches[self.value]
        elif not self.exists:
            raise LookupError(self.value)
        self.dev.clicks.append(self.value)
        self.dev.advance()

    def right(self, **selector):
        return FakeSelector(self.dev, "switch", self.value)

    @property
    def info(self):
        return {"checked": self.dev.switches[self.value]}

    class scroll:
        @staticmethod
        def to(**selector):
            return True


class FakeDevice:
    """Screens are lists of visible texts; a click moves to the next screen."""
    def __init__(self, screens, switches=None):
        self.screens, self.switches, self.clicks, self.presses = list(screens), dict(switches or {}), [], []

    def __call__(self, **selector):
        (kind, value), = selector.items()
        return FakeSelector(self, kind, value)

    def screen(self):
        return self.screens[0] if self.screens else []

    def advance(self):
        if len(self.screens) > 1:
            self.screens.pop(0)

    def dump_hierarchy(self):
        return "".join(f'<node text="{t}" />' for t in self.screen())

    def press(self, key):
        self.presses.append(key)


class ConfirmImportTest(unittest.TestCase):
    def test_import_is_confirmed(self):
        d = FakeDevice([IMPORT_DIALOG, ["Edit Profile"]])
        with patch("detour.android.time.sleep"):
            android.confirm_import(d)
        self.assertEqual(d.clicks, ["Import"])

    def test_late_update_prompt_is_answered_first(self):
        d = FakeDevice([["Check Update", "No, thanks", "OK"], IMPORT_DIALOG, ["Edit Profile"]])
        with patch("detour.android.time.sleep"):
            android.confirm_import(d)
        self.assertEqual(d.clicks, ["OK", "Import"])

    def test_error_dialog_raises_with_its_message(self):
        d = FakeDevice([ERROR_DIALOG])
        with patch("detour.android.time.sleep"), self.assertRaisesRegex(OSError, "Failed to decode profile: invalid message"):
            android.confirm_import(d)
        self.assertEqual(d.clicks, ["OK"])


class EnableUpdatesTest(unittest.TestCase):
    def test_only_the_off_switches_are_clicked(self):
        page = ["Settings", "App", *android.UPDATE_SWITCHES]
        d = FakeDevice([page], {android.UPDATE_SWITCHES[0]: True, android.UPDATE_SWITCHES[1]: False, android.UPDATE_SWITCHES[2]: False})
        with patch("detour.android.time.sleep"):
            android.enable_updates(d)
        self.assertEqual(d.clicks, ["Settings", "App", android.UPDATE_SWITCHES[1], android.UPDATE_SWITCHES[2]])
        self.assertTrue(all(d.switches.values()))
        self.assertEqual(d.presses, ["back", "back"])


class TunTest(unittest.TestCase):
    def test_tun_but_not_tunl(self):
        self.assertTrue(android.TUN_NAME.search(SYS_CLASS_NET))
        self.assertFalse(android.TUN_NAME.search(SYS_CLASS_NET.replace("tun0 ", "")))


if __name__ == "__main__":
    unittest.main()
