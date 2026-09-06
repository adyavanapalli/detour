"""Linux target: install, uninstall, and status facts for the sing-box service."""
import os
import secrets
import subprocess
import tempfile
import urllib.request
from importlib import resources
from pathlib import Path

from detour import config, probes, render, wireguard

UNIT = "sing-box"
TUN = Path("/sys/class/net/sbtun0")
CONF_DIR = Path("/etc/sing-box")
STATE_DIR = "/var/lib/sing-box"
RESOLVED_DROPIN = Path("/etc/systemd/resolved.conf.d/10-detour.conf")
RESOLVED_TEXT = "[Resolve]\nDNS=127.0.0.1\nDomains=~.\n"
UNIT_DROPIN = Path("/etc/systemd/system/sing-box.service.d/override.conf")
UNIT_TEXT = "[Service]\nRestart=always\nRestartSec=3s\n"
REQUIRED = ("rules_url", "server_endpoint", "server_public_key", "tunnel_dns", "device_address")

APT_KEY = Path("/etc/apt/keyrings/sagernet.asc")
APT_KEY_URL = "https://sing-box.app/gpg.key"
APT_SOURCES = Path("/etc/apt/sources.list.d/sagernet.sources")
APT_SOURCES_TEXT = (
    "Types: deb\nURIs: https://deb.sagernet.org/\nSuites: *\nComponents: *\n"
    f"Enabled: yes\nSigned-By: {APT_KEY}\n"
)


def run(*cmd: str, root: bool = False, check: bool = True, **kwargs) -> subprocess.CompletedProcess:
    """Run a command and print it first. Root commands go through sudo, one at a time."""
    argv = ["sudo", *cmd] if root else list(cmd)
    print("+", " ".join(argv))
    return subprocess.run(argv, check=check, **kwargs)


def write_root_file(path: Path, text: str, mode: str, owner: str = "root", group: str = "root") -> None:
    """Install text at a root-owned path; the content passes through a private temp file."""
    with tempfile.NamedTemporaryFile("w", delete=False) as f:
        f.write(text)
    try:
        run("install", "-D", "-m", mode, "-o", owner, "-g", group, f.name, str(path), root=True)
    finally:
        os.unlink(f.name)


def service_state() -> str:
    r = subprocess.run(["systemctl", "is-active", UNIT], capture_output=True, text=True)
    return r.stdout.strip() or "unknown"


def collect(timeout: float = 8) -> probes.Facts:
    """The status facts for this machine."""
    f = probes.Facts(service=service_state(), tun=TUN.exists())
    if f.service == "active":
        f.dns_intercepted = probes.dns_intercepted()
        f.health_listed = probes.health_listed()
        if f.health_listed:
            f.exit_tunnel, f.exit_direct = probes.exit_ips(timeout)
            f.exit_checked = True
    return f


def ensure_identity() -> dict:
    """The [linux] table, complete: generates the device key and the API secret if missing."""
    table = config.require("linux", REQUIRED)
    if not table.get("device_private_key"):
        config.put("linux", "device_private_key", wireguard.generate_private_key())
        public = wireguard.public_key(config.get("linux", "device_private_key"))
        print("new device key. Add this peer on the server:\n")
        print(wireguard.peer_block(public, table["device_address"]))
    if not table.get("api_secret"):
        config.put("linux", "api_secret", secrets.token_hex(24))
    return config.get("linux")


def values(table: dict) -> dict:
    """The template values from a complete [linux] table."""
    host, port = table["server_endpoint"].rsplit(":", 1)
    return dict(rules_url=table["rules_url"], server_host=host, server_port=port,
                server_public_key=table["server_public_key"], tunnel_dns=table["tunnel_dns"],
                device_address=table["device_address"], device_private_key=table["device_private_key"],
                api_secret=table["api_secret"])


def rendered_config(table: dict) -> str:
    """The sing-box config for this machine, accepted by sing-box check."""
    template = resources.files("detour").joinpath("templates/linux.json").read_text()
    text = render.render(template, values(table))
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        f.write(text)
    try:
        run("sing-box", "check", "-c", f.name)
    finally:
        os.unlink(f.name)
    return text


def install_package() -> None:
    """Add SagerNet's apt repository and install sing-box from it."""
    with urllib.request.urlopen(APT_KEY_URL, timeout=30) as r:
        write_root_file(APT_KEY, r.read().decode(), "0644")
    write_root_file(APT_SOURCES, APT_SOURCES_TEXT, "0644")
    run("apt-get", "update", root=True)
    run("apt-get", "install", "-y", UNIT, root=True)


def install() -> None:
    """Make this machine a detour client. Each root step is printed as it runs."""
    table = ensure_identity()
    install_package()
    text = rendered_config(table)
    for stale in CONF_DIR.glob("*.json"):  # the service loads every file in this directory
        if stale.name != "config.json":
            run("rm", "-f", str(stale), root=True)
    write_root_file(CONF_DIR / "config.json", text, "0640", "root", UNIT)
    write_root_file(RESOLVED_DROPIN, RESOLVED_TEXT, "0644")
    write_root_file(UNIT_DROPIN, UNIT_TEXT, "0644")
    run("systemctl", "daemon-reload", root=True)
    run("systemctl", "enable", UNIT, root=True)
    run("systemctl", "restart", UNIT, root=True)
    run("systemctl", "restart", "systemd-resolved", root=True)
    print("installed. Check it with: detour linux status")


def uninstall(purge: bool = False) -> None:
    """Stop the service and restore the system resolver. With purge, remove the package too."""
    run("systemctl", "disable", "--now", UNIT, root=True, check=False)
    run("rm", "-f", str(RESOLVED_DROPIN), root=True)
    run("rm", "-rf", str(UNIT_DROPIN.parent), root=True)
    run("systemctl", "daemon-reload", root=True)
    run("systemctl", "restart", "systemd-resolved", root=True)
    if purge:
        run("apt-get", "purge", "-y", UNIT, root=True)
        run("rm", "-rf", str(CONF_DIR), STATE_DIR, str(APT_SOURCES), str(APT_KEY), root=True)
