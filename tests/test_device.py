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


if __name__ == "__main__":
    unittest.main()
