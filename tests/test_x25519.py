"""RFC 7748 section 6.1 test vectors for detour.x25519."""
import unittest

from detour.x25519 import clamp, public_key, x25519

ALICE_PRIVATE = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
ALICE_PUBLIC = bytes.fromhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
BOB_PRIVATE = bytes.fromhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
BOB_PUBLIC = bytes.fromhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
SHARED = bytes.fromhex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")


class X25519Test(unittest.TestCase):
    def test_public_keys(self):
        self.assertEqual(public_key(ALICE_PRIVATE), ALICE_PUBLIC)
        self.assertEqual(public_key(BOB_PRIVATE), BOB_PUBLIC)

    def test_shared_secret_is_symmetric(self):
        bob_u = int.from_bytes(BOB_PUBLIC, "little")
        alice_u = int.from_bytes(ALICE_PUBLIC, "little")
        self.assertEqual(x25519(clamp(ALICE_PRIVATE), bob_u).to_bytes(32, "little"), SHARED)
        self.assertEqual(x25519(clamp(BOB_PRIVATE), alice_u).to_bytes(32, "little"), SHARED)

    def test_rejects_wrong_length(self):
        with self.assertRaises(ValueError):
            public_key(b"too short")


if __name__ == "__main__":
    unittest.main()
