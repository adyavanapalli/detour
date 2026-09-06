"""Tests for detour.wireguard. No network, no wg binary needed."""
import unittest

from detour import wireguard as wg

ALICE_PRIVATE = "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo="
ALICE_PUBLIC = "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo="


class WireGuardTest(unittest.TestCase):
    def test_public_key_matches_rfc_vector(self):
        self.assertEqual(wg.public_key(ALICE_PRIVATE), ALICE_PUBLIC)

    def test_generated_key_is_32_clamped_bytes(self):
        raw = wg.decode_key(wg.generate_private_key())
        self.assertEqual(len(raw), 32)
        self.assertEqual(raw[0] & 7, 0)
        self.assertEqual(raw[31] & 0xC0, 0x40)

    def test_rejects_bad_keys(self):
        with self.assertRaises(ValueError):
            wg.decode_key("not base64!!")
        with self.assertRaises(ValueError):
            wg.decode_key("c2hvcnQ=")  # "short"

    def test_peer_block_uses_single_host_prefix(self):
        block = wg.peer_block(ALICE_PUBLIC, "10.0.0.2/24")
        self.assertEqual(block, f"[Peer]\nPublicKey = {ALICE_PUBLIC}\nAllowedIPs = 10.0.0.2/32\n")
        self.assertIn("AllowedIPs = fd00::2/128", wg.peer_block(ALICE_PUBLIC, "fd00::2/64"))
        with self.assertRaises(ValueError):
            wg.peer_block(ALICE_PUBLIC, "not-an-address")

    def test_parse_conf_maps_the_five_keys(self):
        conf = (
            "[Interface]\nAddress = 10.0.0.2/24, fd00::2/64\nPrivateKey = PRIV=\n"
            "DNS = 10.0.0.1\nMTU = 1420\n# comment\nPostUp = ip rule add x\n\n"
            "[Peer]\nAllowedIPs = 0.0.0.0/0\nEndpoint = 203.0.113.1:51820\n"
            "PublicKey = PUB=  # trailing comment\n"
        )
        self.assertEqual(wg.parse_conf(conf), {
            "device_address": "10.0.0.2/24", "device_private_key": "PRIV=", "tunnel_dns": "10.0.0.1",
            "server_endpoint": "203.0.113.1:51820", "server_public_key": "PUB=",
        })


if __name__ == "__main__":
    unittest.main()
