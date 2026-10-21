"""Linux target: install, uninstall, and status facts for the sing-box service and the lockdown."""
import os
import pwd
import subprocess
import tempfile
import time
import urllib.request
from importlib import resources
from pathlib import Path

from detour import chrome, config, device, probes, render

UNIT = "sing-box"
TUN = Path("/sys/class/net/sbtun0")
CONF_DIR = Path("/etc/sing-box")
STATE_DIR = "/var/lib/sing-box"
# The rule list as install downloaded it. The template names this path in initial_path: sing-box
# starts from it when it has no cached list. The service loads only *.json from CONF_DIR as config.
RULES_COPY = CONF_DIR / "vpn-domains.jsonc"

RESOLV_CONF = Path("/etc/resolv.conf")
RESOLVED_DROPIN = Path("/etc/systemd/resolved.conf.d/10-detour.conf")
# sing-box answers on 127.0.0.53 in place of the stub of systemd-resolved. resolved keeps running:
# it holds the DNS servers that NetworkManager learned, and sing-box reads them over D-Bus.
RESOLVED_TEXT = "[Resolve]\nDNSStubListener=no\n"
NM_DROPIN = Path("/etc/NetworkManager/conf.d/90-detour.conf")
# NetworkManager sends its connectivity check past the tun, so the lockdown blocks it. The top-bar
# indicator does the captive-portal check through sing-box instead.
NM_TEXT = "[connectivity]\nenabled=false\n"

NFT = "/usr/sbin/nft"
LOCKDOWN = "detour-lockdown.service"
LOCKDOWN_DIR = Path("/etc/detour")
LOCKDOWN_RULES = LOCKDOWN_DIR / "lockdown.nft"
LAN_RULES = LOCKDOWN_DIR / "lan.nft"
LOCKDOWN_UNIT = Path("/etc/systemd/system") / LOCKDOWN
LOCKDOWN_UNIT_TEXT = f"""[Unit]
Description=detour lockdown: outside the sing-box tun, only sing-box, Tailscale, and the LAN can send
DefaultDependencies=no
Wants=network-pre.target
Before=network-pre.target shutdown.target
Conflicts=shutdown.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart={NFT} -f {LOCKDOWN_RULES}
# A restart empties the lan chain. If sing-box runs, open the LAN again, as sing-box.service does.
ExecStartPost=-/bin/sh -c 'systemctl is-active --quiet {UNIT} && exec {NFT} -f {LAN_RULES}'
# No ExecStop: a stop must not open the machine. detour linux uninstall removes the table.

[Install]
WantedBy=sysinit.target
"""

UNIT_DROPIN = Path("/etc/systemd/system/sing-box.service.d/override.conf")
UNIT_TEXT = (
    "[Service]\nRestart=always\nRestartSec=3s\n"
    "# The lockdown lets private LAN addresses out only while sing-box runs.\n"
    f"ExecStartPost=-+{NFT} -f {LAN_RULES}\n"
    f"ExecStopPost=-+{NFT} flush chain inet detour lan\n"
)

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


def template(name: str) -> str:
    return resources.files("detour").joinpath(f"templates/{name}").read_text()


def lockdown_rules(uid: int) -> str:
    """The lockdown table, with the user of sing-box filled in."""
    return render.render(template("lockdown.nft"), {"singbox_uid": str(uid)})


def service_state() -> str:
    r = subprocess.run(["systemctl", "is-active", UNIT], capture_output=True, text=True)
    return r.stdout.strip() or "unknown"


def fail_closed() -> bool | None:
    """True when the lockdown is on: when sing-box stops, only Tailscale and the network setup can send."""
    try:
        r = subprocess.run(["systemctl", "is-active", LOCKDOWN], capture_output=True, text=True)
    except OSError:
        return None
    return r.stdout.strip() == "active"


def resolved_managed(text: str) -> bool:
    """True when resolv.conf comes from systemd-resolved. sing-box makes the same test: if it fails,
    its local server reads resolv.conf, finds 127.0.0.53, and asks itself."""
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("#"):
            return False
        if "systemd-resolved" in line:
            return True
    return False


def preflight() -> None:
    """Check what the system part needs, before install changes anything."""
    if not Path(NFT).exists():
        raise OSError(f"{NFT} is missing; the lockdown needs nftables (sudo apt install nftables)")
    try:
        managed = resolved_managed(RESOLV_CONF.read_text())
    except OSError as e:
        raise OSError(f"cannot read {RESOLV_CONF}: {e}") from e
    if not managed:
        raise OSError(f"{RESOLV_CONF} does not come from systemd-resolved; sing-box takes over 127.0.0.53 "
                      "and reads the network's DNS servers from resolved")
    if subprocess.run(["systemctl", "is-active", "--quiet", "systemd-resolved"]).returncode != 0:
        raise OSError("systemd-resolved is not running; sing-box reads the network's DNS servers from it")


def collect(timeout: float = 8, exit_check: bool = True, portal_check: bool = True) -> probes.Facts:
    """The status facts for this machine."""
    f = probes.Facts(service=service_state(), tun=TUN.exists(), fail_closed=fail_closed(),
                     extension=chrome.current(config.get("linux")))
    if f.service == "active":
        f.dns_intercepted = probes.dns_intercepted()
        f.health_listed = probes.health_listed()
        if portal_check:
            f.portal = probes.portal()
        if f.health_listed and exit_check:
            f.exit_tunnel, f.exit_direct = probes.exit_ips(timeout)
            f.exit_checked = True
    return f


def package_installed() -> bool:
    r = subprocess.run(["dpkg-query", "-W", "-f=${Status}", UNIT], capture_output=True, text=True)
    return r.returncode == 0 and r.stdout.strip() == "install ok installed"


def install_package() -> None:
    """Add SagerNet's apt repository and install or update sing-box from it.

    If sing-box is already installed and the repository is out of reach, for example under the
    lockdown with sing-box stopped, the installed version stays.
    """
    installed = package_installed()
    try:
        with urllib.request.urlopen(APT_KEY_URL, timeout=30) as r:
            write_root_file(APT_KEY, r.read().decode(), "0644")
        write_root_file(APT_SOURCES, APT_SOURCES_TEXT, "0644")
        run("apt-get", "update", root=True)
        run("apt-get", "install", "-y", UNIT, root=True)
    except (OSError, subprocess.CalledProcessError) as e:
        if not installed:
            raise
        print(f"sing-box stays at the installed version: {e}")


def valid_rules(text: str) -> bool:
    """True when sing-box can read text as a rule list in source format."""
    with tempfile.TemporaryDirectory() as tmp:
        source = Path(tmp) / "rules.json"
        source.write_text(text)
        r = subprocess.run(["sing-box", "rule-set", "compile", "-o", str(Path(tmp) / "rules.srs"), str(source)],
                           capture_output=True)
    return r.returncode == 0


def save_rules_copy(url: str) -> None:
    """Save the rule list for initial_path. If the download fails, the copy from before stays."""
    try:
        with urllib.request.urlopen(url, timeout=30) as r:
            text = r.read().decode()
    except (OSError, UnicodeDecodeError) as e:
        print(f"the rule list was not saved ({e}); sing-box starts from its cache or downloads the list")
        return
    if not valid_rules(text):
        print("the rule list was not saved: sing-box cannot read it")
        return
    write_root_file(RULES_COPY, text, "0640", "root", UNIT)


def wait_ready(seconds: float = 30) -> str | None:
    """None when sing-box answers DNS on 127.0.0.53 and resolves through the network. Else the problem."""
    deadline = time.monotonic() + seconds
    while True:
        state = service_state()
        if state != "active":
            problem = f"sing-box is {state}"
        else:
            intercepted = probes.dns_intercepted()
            if intercepted is None:
                problem = "nothing answers DNS on 127.0.0.53"
            elif not intercepted:
                problem = f"DNS bypasses sing-box: {probes.CANARY_DOMAIN} got a real answer"
            elif not probes.resolve(probes.DIRECT_HOST):
                problem = "sing-box cannot resolve names through the DNS server of the network"
            else:
                return None
        if time.monotonic() >= deadline:
            return problem
        time.sleep(1)


def enable_lockdown() -> None:
    """Load the lockdown now and at every boot. Turn off NetworkManager's check, which it blocks."""
    write_root_file(LOCKDOWN_RULES, lockdown_rules(pwd.getpwnam(UNIT).pw_uid), "0644")
    write_root_file(LAN_RULES, template("lan.nft"), "0644")
    write_root_file(LOCKDOWN_UNIT, LOCKDOWN_UNIT_TEXT, "0644")
    run(NFT, "-c", "-f", str(LOCKDOWN_RULES), root=True)
    run("systemctl", "daemon-reload", root=True)
    run("systemctl", "enable", LOCKDOWN, root=True)
    run("systemctl", "restart", LOCKDOWN, root=True)  # loads the table, also on a second install
    write_root_file(NM_DROPIN, NM_TEXT, "0644")
    run("systemctl", "reload", "NetworkManager", root=True)


def remove_lockdown() -> None:
    run("systemctl", "disable", "--now", LOCKDOWN, root=True, check=False)
    run(NFT, "destroy", "table", "inet", "detour", root=True, check=False)
    run("rm", "-rf", str(LOCKDOWN_DIR), str(LOCKDOWN_UNIT), root=True)
    run("systemctl", "daemon-reload", root=True)


def restore_resolver() -> None:
    """Give DNS back to systemd-resolved: stop sing-box, and turn the stub listener on again."""
    run("systemctl", "disable", "--now", UNIT, root=True, check=False)
    run("rm", "-f", str(RESOLVED_DROPIN), root=True)
    run("systemctl", "restart", "systemd-resolved", root=True)


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


def install_system(table: dict) -> None:
    """Everything except the Chrome extension. The lockdown comes on only after sing-box answers DNS.

    On a first install, a failure puts DNS back as it was, and the lockdown stays off. On a later
    install, the lockdown is already on: it stays on, and nothing leaks.
    """
    locked = fail_closed() is True
    install_package()
    save_rules_copy(table["rules_url"])
    text = device.rendered_config("linux", table)
    for stale in CONF_DIR.glob("*.json"):  # the service loads every *.json file in this directory
        if stale.name != "config.json":
            run("rm", "-f", str(stale), root=True)
    write_root_file(CONF_DIR / "config.json", text, "0640", "root", UNIT)
    write_root_file(UNIT_DROPIN, UNIT_TEXT, "0644")
    write_root_file(RESOLVED_DROPIN, RESOLVED_TEXT, "0644")
    run("systemctl", "daemon-reload", root=True)
    run("systemctl", "enable", UNIT, root=True)
    run("systemctl", "restart", "systemd-resolved", root=True)  # frees 127.0.0.53 for sing-box
    run("systemctl", "restart", UNIT, root=True)
    problem = wait_ready()
    if problem and locked:
        raise OSError(f"{problem}. The lockdown stays on, so nothing leaks. See: journalctl -u {UNIT}")
    if problem:
        restore_resolver()
        raise OSError(f"{problem}. The lockdown is off, and DNS is back with systemd-resolved. "
                      f"See: journalctl -u {UNIT}")
    enable_lockdown()


def install() -> None:
    """Make this machine a detour client. Each root step is printed as it runs."""
    chrome_bin = chrome.preflight()  # like the checks below: before anything changes
    preflight()
    table = device.ensure_identity("linux")
    install_system(table)
    install_extension(chrome_bin, table)
    print()
    probes.report(collect())


def uninstall(purge: bool = False) -> None:
    """Remove the extension, stop the service, restore DNS, and remove the lockdown last.

    With purge, remove the package and its files too.
    """
    uninstall_extension(purge)  # first: the extension must not outlive the tunnel
    restore_resolver()
    run("rm", "-f", str(NM_DROPIN), root=True)
    run("rm", "-rf", str(UNIT_DROPIN.parent), root=True)
    run("systemctl", "daemon-reload", root=True)
    run("systemctl", "reload", "NetworkManager", root=True, check=False)
    remove_lockdown()  # last: until here, nothing can leave outside the tunnel
    if purge:
        run("apt-get", "purge", "-y", UNIT, root=True)
        run("rm", "-rf", str(CONF_DIR), STATE_DIR, str(APT_SOURCES), str(APT_KEY), root=True)
