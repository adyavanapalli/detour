"""Android target: sing-box for Android (SFA) on a phone reached over ADB."""
import os
import re
import shutil
import subprocess
from pathlib import Path
from urllib.parse import urlparse

from detour import probes

PACKAGE = "io.nekohasekai.sfa"
VPN_SERVICE = f"{PACKAGE}/.bg.VPNService"
DIRECT_HOST = urlparse(probes.DIRECT_URL).hostname

PING_ANSWER = re.compile(r"^PING \S+ \(([\d.]+)\)")
IPV4 = re.compile(r"\d{1,3}(\.\d{1,3}){3}")
TUN_NAME = re.compile(r"\btun\d+\b")
MODE_CHANGE = re.compile(r"Mode changed: lockdown=(true|false) alwaysOn=(true|false)")


def adb_path() -> str:
    """adb from PATH, or from the SDK named by ANDROID_HOME or ANDROID_SDK_ROOT, or ~/Android/Sdk."""
    found = shutil.which("adb")
    if found:
        return found
    roots = [os.environ.get("ANDROID_HOME"), os.environ.get("ANDROID_SDK_ROOT"), Path.home() / "Android/Sdk"]
    for root in filter(None, roots):
        candidate = Path(root) / "platform-tools/adb"
        if candidate.exists():
            return str(candidate)
    raise OSError("adb not found: install Android platform-tools or set ANDROID_HOME")


def adb(*args: str, check: bool = True, quiet: bool = True) -> str:
    """Run adb and return its output. ANDROID_SERIAL picks the phone when several are attached."""
    if not quiet:
        print("+ adb", " ".join(args))
    r = subprocess.run([adb_path(), *args], capture_output=True, text=True)
    if check and r.returncode:
        raise OSError(f"adb {args[0]} failed: {(r.stderr or r.stdout).strip()}")
    return r.stdout.replace("\r", "")


def shell(command: str, **kwargs) -> str:
    return adb("shell", command, **kwargs)


def parse_ping(output: str) -> list[str] | None:
    """What ping resolved a name to: [] for an unknown host, None when ping said something else."""
    line = output.strip().splitlines()[0] if output.strip() else ""
    answer = PING_ANSWER.match(line)
    if answer:
        return [answer.group(1)]
    return [] if line.startswith("ping: unknown host") else None


def resolve(name: str) -> list[str] | None:
    """Resolve on the phone, through the same path every app uses. ping is the only resolver the shell has."""
    return parse_ping(shell(f"ping -c1 -W1 {name}", check=False))


def parse_body(output: str) -> str | None:
    """The last line of an HTTP response when it is an IPv4 address."""
    body = output.strip().splitlines()[-1].strip() if output.strip() else ""
    return body if IPV4.fullmatch(body) else None


def fetch_ip(host: str) -> str | None:
    """Ask an IP echo service from the phone over plain HTTP; the shell has no TLS client."""
    request = f"GET / HTTP/1.0\\r\\nHost: {host}\\r\\n\\r\\n"
    return parse_body(shell(f"(printf '{request}'; sleep 2) | nc -w 6 {host} 80", check=False))


def parse_fail_closed(keys: str, dump: str) -> bool:
    """True when always-on lockdown for SFA is both saved in settings and in effect.

    keys is the output of the two settings reads; dump is dumpsys vpn_management, whose event list
    is newest first, so the first mode change is the state in effect.
    """
    if keys.split() != [PACKAGE, "1"]:
        return False
    mode = MODE_CHANGE.search(dump)
    return bool(mode) and mode.groups() == ("true", "true")


def fail_closed() -> bool:
    keys = shell("settings get secure always_on_vpn_app; settings get secure always_on_vpn_lockdown")
    return parse_fail_closed(keys, shell("dumpsys vpn_management"))


def service_state() -> str:
    if not shell(f"pm path {PACKAGE}", check=False).strip():
        return "not installed"
    return "active" if "startRequested=true" in shell(f"dumpsys activity services {VPN_SERVICE}") else "inactive"


def collect(exit_check: bool = True) -> probes.Facts:
    """The status facts for the phone."""
    f = probes.Facts(service=service_state())
    if f.service == "not installed":
        return f
    f.tun = bool(TUN_NAME.search(shell("ls /sys/class/net")))
    f.fail_closed = fail_closed()
    if f.service == "active":
        f.dns_intercepted = probes.dns_intercepted(resolve)
        f.health_listed = probes.health_listed(resolve)
        if f.health_listed and exit_check:
            f.exit_tunnel, f.exit_direct = fetch_ip(probes.HEALTH_DOMAIN), fetch_ip(DIRECT_HOST)
            f.exit_checked = True
    return f
