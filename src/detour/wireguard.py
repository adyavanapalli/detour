"""WireGuard identities: keys, the server-side peer block, wg-quick conf import."""
import base64
import ipaddress
import secrets

from detour import x25519


def generate_private_key() -> str:
    """A new private key as base64, clamped the way wg genkey does it."""
    scalar = x25519.clamp(secrets.token_bytes(32))
    return base64.b64encode(scalar.to_bytes(32, "little")).decode()


def decode_key(key_b64: str) -> bytes:
    """32 raw bytes from a base64 WireGuard key, or a ValueError."""
    try:
        raw = base64.b64decode(key_b64, validate=True)
    except ValueError:
        raise ValueError("key is not valid base64") from None
    if len(raw) != 32:
        raise ValueError("key must decode to 32 bytes")
    return raw


def public_key(private_b64: str) -> str:
    """Base64 public key for a base64 private key."""
    return base64.b64encode(x25519.public_key(decode_key(private_b64))).decode()


def peer_block(device_public_key: str, device_address: str) -> str:
    """The [Peer] section to add on the server for this device."""
    host = ipaddress.ip_interface(device_address).ip
    return f"[Peer]\nPublicKey = {device_public_key}\nAllowedIPs = {host}/{host.max_prefixlen}\n"


FIELDS = {
    ("interface", "privatekey"): "device_private_key",
    ("interface", "address"): "device_address",
    ("interface", "dns"): "tunnel_dns",
    ("peer", "publickey"): "server_public_key",
    ("peer", "endpoint"): "server_endpoint",
}


def parse_conf(text: str) -> dict:
    """The detour config keys found in a wg-quick style conf."""
    found, section = {}, None
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip().lower()
        elif "=" in line and section:
            name, value = (s.strip() for s in line.split("=", 1))
            key = FIELDS.get((section, name.lower()))
            if key and key not in found:
                found[key] = value.split(",")[0].strip()
    return found
