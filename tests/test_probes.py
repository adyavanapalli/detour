"""One test per rule in detour.probes.assess."""
import unittest

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

    def test_same_exit_is_leak(self):
        self.assertEqual(self.state(exit_direct="203.0.113.7"), "leak")
        self.assertEqual(self.state(exit_direct="203.0.113.7", fail_closed=False), "leak")  # the leak outranks it

    def test_two_failed_fetches_are_not_a_leak(self):
        self.assertEqual(self.state(exit_tunnel=None, exit_direct=None), "warn")

    def test_unchecked_is_still_running(self):
        self.assertEqual(self.state(exit_checked=False, exit_tunnel=None, exit_direct=None), "warn")
        self.assertEqual(self.state(dns_intercepted=None), "warn")

    def test_reason_names_the_addresses(self):
        self.assertIn("203.0.113.7", assess(Facts(**HEALTHY)).reason)
        self.assertIn("203.0.113.7", assess(Facts(**{**HEALTHY, "exit_direct": "203.0.113.7"})).reason)


if __name__ == "__main__":
    unittest.main()
