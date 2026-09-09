"""detour.device: the template values that every target renders."""
import unittest
from importlib import resources

from detour import device, render

TABLE = dict(rules_url="https://example.com/rules.jsonc", server_endpoint="203.0.113.1:51820",
             server_public_key="xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=", tunnel_dns="192.0.2.1",
             device_address="192.0.2.2/24", device_private_key="yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=",
             api_secret="0123456789abcdef")


class ValuesTest(unittest.TestCase):
    def test_endpoint_splits_into_host_and_port(self):
        v = device.values(TABLE)
        self.assertEqual((v["server_host"], v["server_port"]), ("203.0.113.1", "51820"))

    def test_hostname_endpoint(self):
        v = device.values({**TABLE, "server_endpoint": "vpn.example.com:51820"})
        self.assertEqual((v["server_host"], v["server_port"]), ("vpn.example.com", "51820"))

    def test_every_template_renders_from_these_values(self):
        templates = [p.name for p in resources.files("detour").joinpath("templates").iterdir() if p.name.endswith(".json")]
        self.assertTrue(templates)
        for name in templates:
            with self.subTest(template=name):
                render.render(device.template(name.removesuffix(".json")), device.values(TABLE))

    def test_android_rendered_config_injects_tailscale_when_configured(self):
        import json
        ts_table = {**TABLE, "tailscale_auth_key": "tskey-auth-test1234", "tailscale_hostname": "test-device"}
        rendered = device.rendered_config("android", ts_table)
        data = json.loads(rendered)
        
        # Check endpoint
        ts_ep = next((ep for ep in data["endpoints"] if ep.get("type") == "tailscale"), None)
        self.assertIsNotNone(ts_ep)
        self.assertEqual(ts_ep["tag"], "ts-ep")
        self.assertEqual(ts_ep["auth_key"], "tskey-auth-test1234")
        self.assertEqual(ts_ep["hostname"], "test-device")
        self.assertTrue(ts_ep["accept_routes"])
        self.assertTrue(ts_ep["ssh_server"])

        # Check DNS
        ts_dns = next((srv for srv in data["dns"]["servers"] if srv.get("type") == "tailscale"), None)
        self.assertIsNotNone(ts_dns)
        self.assertTrue(ts_dns["accept_search_domain"])

        ts_dns_rule = next((r for r in data["dns"]["rules"] if "dns-tailscale" in r.get("preferred_by", [])), None)
        self.assertIsNotNone(ts_dns_rule)
        self.assertEqual(ts_dns_rule["server"], "dns-tailscale")

        # Check Route
        ts_inbound = next((r for r in data["route"]["rules"] if "ts-ep" in r.get("inbound", [])), None)
        self.assertIsNotNone(ts_inbound)
        self.assertEqual(ts_inbound["outbound"], "direct")

        ts_route = next((r for r in data["route"]["rules"] if "100.64.0.0/10" in r.get("ip_cidr", [])), None)
        self.assertIsNotNone(ts_route)
        self.assertEqual(ts_route["outbound"], "ts-ep")

    def test_android_rendered_config_omits_tailscale_when_not_configured(self):
        import json
        rendered = device.rendered_config("android", TABLE)
        data = json.loads(rendered)
        ts_ep = next((ep for ep in data["endpoints"] if ep.get("type") == "tailscale"), None)
        self.assertIsNone(ts_ep)


if __name__ == "__main__":
    unittest.main()
