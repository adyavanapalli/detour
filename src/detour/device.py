"""What every target shares: the device identity, the template values, and the rendered config."""
import os
import secrets
import shutil
import subprocess
import tempfile
from importlib import resources

from detour import config, render, wireguard

REQUIRED = ("rules_url", "server_endpoint", "server_public_key", "tunnel_dns", "device_address")


def ensure_identity(target: str) -> dict:
    """The target's table, complete: generates the device key and the API secret if missing."""
    table = config.require(target, REQUIRED)
    if not table.get("device_private_key"):
        config.put(target, "device_private_key", wireguard.generate_private_key())
        public = wireguard.public_key(config.get(target, "device_private_key"))
        print("new device key. Add this peer on the server:\n")
        print(wireguard.peer_block(public, table["device_address"]))
    if not table.get("api_secret"):
        config.put(target, "api_secret", secrets.token_hex(24))
    return config.get(target)


def values(table: dict) -> dict:
    """The template values from a complete table."""
    host, port = table["server_endpoint"].rsplit(":", 1)
    return dict(rules_url=table["rules_url"], server_host=host, server_port=port,
                server_public_key=table["server_public_key"], tunnel_dns=table["tunnel_dns"],
                device_address=table["device_address"], device_private_key=table["device_private_key"],
                api_secret=table["api_secret"])


def template(target: str) -> str:
    return resources.files("detour").joinpath(f"templates/{target}.json").read_text()


def rendered_config(target: str, table: dict) -> str:
    """The sing-box config for the target, checked by sing-box on this machine when it is installed."""
    text = render.render(template(target), values(table))
    if not shutil.which("sing-box"):
        print("sing-box is not installed here, so the profile is not checked before it goes to the target")
        return text
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        f.write(text)
    try:
        cmd = ["sing-box", "check", "-c", f.name]
        print("+", " ".join(cmd))
        subprocess.run(cmd, check=True)
    finally:
        os.unlink(f.name)
    return text
