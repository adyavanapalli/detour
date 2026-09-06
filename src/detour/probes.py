"""Health facts about a device and the shared rules that judge them."""
import socket
import urllib.request
from dataclasses import dataclass

CANARY_DOMAIN = "use-application-dns.net"  # a sing-box rule answers it NXDOMAIN
HEALTH_DOMAIN = "ipv4.icanhazip.com"  # must be in the rules; echoes the public address
DIRECT_URL = "https://api.ipify.org"  # not in the rules; echoes the public address
FAKEIP_PREFIXES = ("198.18.", "198.19.")


@dataclass
class Facts:
    """What a target reports. None means not checked yet."""
    service: str = "unknown"  # active, inactive, failed, ...
    tun: bool = False
    dns_intercepted: bool | None = None  # the canary returned NXDOMAIN
    health_listed: bool | None = None  # the health domain resolved to a FakeIP
    exit_checked: bool = False
    exit_tunnel: str | None = None  # address via the health domain; None after a check: unreachable
    exit_direct: str | None = None  # address via the direct URL


@dataclass
class Verdict:
    state: str  # on, warn, leak, off
    reason: str


def assess(f: Facts) -> Verdict:
    """The one place that turns facts into a state. Every display uses it."""
    if f.service != "active":
        return Verdict("off", f"service is {f.service}; DNS is closed while it is down")
    if not f.tun:
        return Verdict("warn", "tunnel interface is missing")
    if f.dns_intercepted is False:
        return Verdict("warn", f"DNS bypasses sing-box: {CANARY_DOMAIN} got a real answer")
    if f.health_listed is False:
        return Verdict("warn", f"{HEALTH_DOMAIN} is not in the rules; add it back")
    if f.exit_checked and f.exit_tunnel is None:
        return Verdict("warn", "tunnel down: listed domains cannot reach the internet")
    if f.exit_checked and f.exit_tunnel == f.exit_direct:
        return Verdict("leak", f"listed traffic exits directly via {f.exit_tunnel}")
    if None in (f.dns_intercepted, f.health_listed) or not f.exit_checked:
        return Verdict("warn", "checks still running")
    return Verdict("on", f"listed traffic exits via the VPN at {f.exit_tunnel}")


def resolve(name: str) -> list[str] | None:
    """IPv4 answers for name: [] for NXDOMAIN, None when the resolver failed."""
    try:
        return sorted({info[4][0] for info in socket.getaddrinfo(name, None, socket.AF_INET)})
    except socket.gaierror as e:
        return [] if e.errno == socket.EAI_NONAME else None


def dns_intercepted() -> bool | None:
    """True when the canary returns NXDOMAIN, which only the sing-box rule does."""
    answers = resolve(CANARY_DOMAIN)
    return None if answers is None else answers == []


def health_listed() -> bool | None:
    """True when the health domain resolves to a FakeIP."""
    answers = resolve(HEALTH_DOMAIN)
    return None if not answers else any(a.startswith(FAKEIP_PREFIXES) for a in answers)


def fetch_ip(url: str, timeout: float = 8) -> str | None:
    """The body of an IP echo service, or None when it cannot be reached."""
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.read(64).decode("utf-8", "replace").strip() or None
    except OSError:
        return None


def exit_ips(timeout: float = 8) -> tuple[str | None, str | None]:
    """Public address via the health domain (listed) and via the direct URL (not listed)."""
    return fetch_ip(f"https://{HEALTH_DOMAIN}", timeout), fetch_ip(DIRECT_URL, timeout)
