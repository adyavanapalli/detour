"""X25519 public-key derivation (RFC 7748). Not constant-time."""

P = 2**255 - 19  # the field prime
A24 = 121665  # (A - 2) / 4 for Curve25519, where A = 486662


def clamp(private: bytes) -> int:
    """Turn 32 private bytes into a scalar (RFC 7748 section 5)."""
    b = bytearray(private)
    b[0] &= 248
    b[31] &= 127
    b[31] |= 64
    return int.from_bytes(b, "little")


def ladder_step(x1, x2, z2, x3, z3):
    """One Montgomery ladder step; returns the new (x2, z2, x3, z3)."""
    a, b = (x2 + z2) % P, (x2 - z2) % P
    aa, bb = a * a % P, b * b % P
    e = (aa - bb) % P
    c, d = (x3 + z3) % P, (x3 - z3) % P
    da, cb = d * a % P, c * b % P
    x3 = (da + cb) ** 2 % P
    z3 = x1 * (da - cb) ** 2 % P
    return aa * bb % P, e * (aa + A24 * e) % P, x3, z3


def x25519(k: int, u: int) -> int:
    """Scalar multiplication k * u on Curve25519 (RFC 7748 section 5)."""
    u &= (1 << 255) - 1  # the top bit of u is ignored
    x1, x2, z2, x3, z3, swap = u, 1, 0, u, 1, 0
    for t in range(254, -1, -1):
        kt = (k >> t) & 1
        swap ^= kt
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = kt
        x2, z2, x3, z3 = ladder_step(x1, x2, z2, x3, z3)
    if swap:
        x2, x3, z2, z3 = x3, x2, z3, z2
    return x2 * pow(z2, P - 2, P) % P


def public_key(private: bytes) -> bytes:
    """Public key for a 32-byte private key, as WireGuard expects."""
    if len(private) != 32:
        raise ValueError("private key must be 32 bytes")
    return x25519(clamp(private), 9).to_bytes(32, "little")
