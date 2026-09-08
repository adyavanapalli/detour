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

DIALOG = ('<node index="0" text="Import Profile" class="android.widget.TextView" bounds="[100,100][900,200]" />'
          '<node index="1" text=\'Import profile "detour"?\' class="android.widget.TextView" bounds="[100,220][900,300]" />'
          '<node index="2" text="Cancel" class="android.widget.Button" bounds="[1200,1500][1400,1600]" />'
          '<node index="3" text="Import" class="android.widget.Button" bounds="[1450,1500][1650,1600]" />')
ERROR = ('<node index="0" text="Error" class="android.widget.TextView" bounds="[100,100][900,200]" />'
         '<node index="1" text="Failed to decode profile: invalid message" bounds="[100,220][900,300]" />'
         '<node index="2" text="Copy" class="android.widget.Button" bounds="[1000,1500][1200,1600]" />'
         '<node index="3" text="OK" class="android.widget.Button" bounds="[1450,1500][1650,1600]" />')


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


class ScreenTest(unittest.TestCase):
    def test_texts_in_document_order(self):
        self.assertEqual(android.texts(ERROR), ["Error", "Failed to decode profile: invalid message", "Copy", "OK"])

    def test_single_quoted_text_is_read_too(self):
        self.assertEqual(android.texts(DIALOG), ["Import Profile", 'Import profile "detour"?', "Cancel", "Import"])

    def test_exact_label_only(self):
        self.assertEqual(android.bounds(DIALOG, "Import"), (1450, 1500, 1650, 1600))  # not "Import Profile"
        self.assertIsNone(android.bounds(ERROR, "Import"))


class ConfirmImportTest(unittest.TestCase):
    def replay(self, screens):
        """Run confirm_import against a sequence of screens; return the labels it tapped."""
        taps, shown = [], iter(screens)

        def tap(xml, label):
            if android.bounds(xml, label):
                taps.append(label)
                return True
            return False
        with patch("detour.android.time.sleep"):
            android.confirm_import(screen=lambda: next(shown), tap=tap)
        return taps

    def test_first_launch_prompt_before_and_after_the_import(self):
        screens = [CHECK_UPDATE, DIALOG, EDIT_PROFILE, CHECK_UPDATE] + [EDIT_PROFILE] * 6
        self.assertEqual(self.replay(screens), ["OK", "Import", "OK"])

    def test_plain_import(self):
        self.assertEqual(self.replay([DIALOG] + [EDIT_PROFILE] * 6), ["Import"])

    def test_error_dialog_raises_with_its_message(self):
        with self.assertRaisesRegex(OSError, "Failed to decode profile: invalid message"):
            self.replay([ERROR] * 3)


APP_PAGE = ('<node text="Automatic Update Check" class="android.widget.TextView" bounds="[78,1300][700,1400]" />'
            '<node text="" checkable="true" checked="true" class="android.view.View" bounds="[875,1295][1002,1412]" />'
            '<node text="Silent Install" class="android.widget.TextView" bounds="[78,1470][700,1520]" />'
            '<node text="Install updates without interaction" class="android.widget.TextView" bounds="[78,1530][700,1580]" />'
            '<node text="" checkable="true" checked="false" class="android.view.View" bounds="[875,1461][1002,1578]" />')


class SwitchesTest(unittest.TestCase):
    def test_switch_state_and_box_by_preceding_text(self):
        found = android.switches(APP_PAGE)
        self.assertEqual(found["Automatic Update Check"], (True, (875, 1295, 1002, 1412)))
        self.assertEqual(found["Install updates without interaction"], (False, (875, 1461, 1002, 1578)))


class TunTest(unittest.TestCase):
    def test_tun_but_not_tunl(self):
        self.assertTrue(android.TUN_NAME.search(SYS_CLASS_NET))
        self.assertFalse(android.TUN_NAME.search(SYS_CLASS_NET.replace("tun0 ", "")))


if __name__ == "__main__":
    unittest.main()
