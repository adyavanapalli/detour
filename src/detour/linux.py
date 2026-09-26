"""Linux target: install, uninstall, and status facts for the sing-box service."""
import os
import subprocess
import tempfile
import urllib.request
from pathlib import Path

from detour import chrome, config, device, probes

UNIT = "sing-box"
TUN = Path("/sys/class/net/sbtun0")
CONF_DIR = Path("/etc/sing-box")
STATE_DIR = "/var/lib/sing-box"
RESOLVED_DROPIN = Path("/etc/systemd/resolved.conf.d/10-detour.conf")
RESOLVED_TEXT = "[Resolve]\nDNS=127.0.0.1\nDomains=~.\n"
UNIT_DROPIN = Path("/etc/systemd/system/sing-box.service.d/override.conf")
UNIT_TEXT = "[Service]\nRestart=always\nRestartSec=3s\n"

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


def fail_closed() -> bool | None:
    """True when systemd-resolved sends every query to sing-box, so DNS fails while it is down."""
    try:
        dns = subprocess.run(["resolvectl", "dns"], capture_output=True, text=True, check=True).stdout
        domain = subprocess.run(["resolvectl", "domain"], capture_output=True, text=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError):
        return None
    return dns.startswith("Global: 127.0.0.1\n") and domain.startswith("Global: ~.\n")


def collect(timeout: float = 8, exit_check: bool = True) -> probes.Facts:
    """The status facts for this machine."""
    f = probes.Facts(service=service_state(), tun=TUN.exists(), fail_closed=fail_closed(),
                     extension=chrome.current(config.get("linux")))
    if f.service == "active":
        f.dns_intercepted = probes.dns_intercepted()
        f.health_listed = probes.health_listed()
        if f.health_listed and exit_check:
            f.exit_tunnel, f.exit_direct = probes.exit_ips(timeout)
            f.exit_checked = True
    return f


def install_package() -> None:
    """Add SagerNet's apt repository and install sing-box from it."""
    with urllib.request.urlopen(APT_KEY_URL, timeout=30) as r:
        write_root_file(APT_KEY, r.read().decode(), "0644")
    write_root_file(APT_SOURCES, APT_SOURCES_TEXT, "0644")
    run("apt-get", "update", root=True)
    run("apt-get", "install", "-y", UNIT, root=True)


def install_extension(chrome_bin: str, table: dict) -> None:
    """Pack the Chrome extension, force-install it by policy, and pin it first. This stops Chrome."""
    ext_id, files = chrome.build(chrome_bin, table)
    for path, text in files.items():
        write_root_file(path, text, "0644")
    stale = [str(p) for p in chrome.root_files() if p not in files]  # for example, the old Chromium policy
    if stale:
        run("rm", "-f", *stale, root=True)
    chrome.remove_local(purge=False)
    chrome.pin_first(ext_id)


def uninstall_extension(purge: bool) -> None:
    """Remove the policy and the descriptors, so Chrome drops the extension at its next start."""
    files = chrome.root_files()
    if files:
        run("rm", "-f", *map(str, files), root=True)
    chrome.remove_local(purge)


def install() -> None:
    """Make this machine a detour client. Each root step is printed as it runs."""
    chrome_bin = chrome.preflight()  # like the config check below: before anything changes
    table = device.ensure_identity("linux")
    install_package()
    text = device.rendered_config("linux", table)
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
    install_extension(chrome_bin, table)
    print()
    probes.report(collect())


def uninstall(purge: bool = False) -> None:
    """Remove the extension, stop the service, and restore the resolver. With purge, remove the package too."""
    uninstall_extension(purge)  # first: the extension must not outlive the tunnel
    run("systemctl", "disable", "--now", UNIT, root=True, check=False)
    run("rm", "-f", str(RESOLVED_DROPIN), root=True)
    run("rm", "-rf", str(UNIT_DROPIN.parent), root=True)
    run("systemctl", "daemon-reload", root=True)
    run("systemctl", "restart", "systemd-resolved", root=True)
    if purge:
        run("apt-get", "purge", "-y", UNIT, root=True)
        run("rm", "-rf", str(CONF_DIR), STATE_DIR, str(APT_SOURCES), str(APT_KEY), root=True)
