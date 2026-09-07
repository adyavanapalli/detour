"""detour.android: the parsers that read a phone's answers. Samples are real output from Android 17."""
import unittest

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


class TunTest(unittest.TestCase):
    def test_tun_but_not_tunl(self):
        self.assertTrue(android.TUN_NAME.search(SYS_CLASS_NET))
        self.assertFalse(android.TUN_NAME.search(SYS_CLASS_NET.replace("tun0 ", "")))


if __name__ == "__main__":
    unittest.main()
