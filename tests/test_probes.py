"""One test per rule in detour.probes.assess, and the captive-portal check against a local server."""
import http.server
import threading
import unittest

from detour import probes
from detour.probes import Facts, assess

HEALTHY = dict(service="active", tun=True, fail_closed=True, dns_intercepted=True, health_listed=True,
               exit_checked=True, exit_tunnel="203.0.113.7", exit_direct="198.51.100.9")


class AssessTest(unittest.TestCase):
    def state(self, **changes):
        return assess(Facts(**{**HEALTHY, **changes})).state

    def test_healthy_is_on(self):
        self.assertEqual(self.state(), "on")

    def test_service_down_is_off(self):
        self.assertEqual(self.state(service="inactive"), "off")
        self.assertEqual(self.state(service="failed"), "off")

    def test_degraded_states_are_warn(self):
        self.assertEqual(self.state(tun=False), "warn")
        self.assertEqual(self.state(dns_intercepted=False), "warn")
        self.assertEqual(self.state(health_listed=False), "warn")
        self.assertEqual(self.state(exit_tunnel=None), "warn")  # tunnel down
        self.assertEqual(self.state(fail_closed=False), "warn")
        self.assertEqual(self.state(extension=False), "warn")  # Linux: missing or out of date

    def test_extension_unknown_is_not_judged(self):
        self.assertEqual(self.state(extension=None), "on")  # Android has no extension

    def test_same_exit_is_leak(self):
        self.assertEqual(self.state(exit_direct="203.0.113.7"), "leak")
        self.assertEqual(self.state(exit_direct="203.0.113.7", fail_closed=False), "leak")  # the leak outranks it

    def test_two_failed_fetches_are_not_a_leak(self):
        self.assertEqual(self.state(exit_tunnel=None, exit_direct=None), "warn")

    def test_unchecked_is_still_running(self):
        self.assertEqual(self.state(exit_checked=False, exit_tunnel=None, exit_direct=None), "warn")
        self.assertEqual(self.state(dns_intercepted=None), "warn")

    def test_captive_portal_is_warn(self):
        self.assertEqual(self.state(portal=True), "warn")
        self.assertIn("sign-in", assess(Facts(**{**HEALTHY, "portal": True})).reason)
        self.assertEqual(self.state(portal=False), "on")
        self.assertEqual(self.state(portal=None), "on")  # not checked, or no answer

    def test_reason_names_the_addresses(self):
        self.assertIn("203.0.113.7", assess(Facts(**HEALTHY)).reason)
        self.assertIn("203.0.113.7", assess(Facts(**{**HEALTHY, "exit_direct": "203.0.113.7"})).reason)


class PortalHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        status = int(self.path.strip("/"))
        self.send_response(status)
        if status == 302:
            self.send_header("Location", "http://portal.invalid/login")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):
        pass


class PortalTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.HTTPServer(("127.0.0.1", 0), PortalHandler)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_204_is_no_portal(self):
        self.assertIs(probes.portal(f"{self.base}/204"), False)

    def test_a_redirect_or_a_page_is_a_portal(self):
        self.assertIs(probes.portal(f"{self.base}/302"), True)  # not followed: the login page is elsewhere
        self.assertIs(probes.portal(f"{self.base}/200"), True)

    def test_other_answers_and_no_answer_are_unknown(self):
        self.assertIsNone(probes.portal(f"{self.base}/500"))
        free = http.server.HTTPServer(("127.0.0.1", 0), PortalHandler)
        port = free.server_address[1]
        free.server_close()  # nothing listens on this port now
        self.assertIsNone(probes.portal(f"http://127.0.0.1:{port}/204", timeout=2))


if __name__ == "__main__":
    unittest.main()
