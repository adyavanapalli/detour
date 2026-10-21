"""Health facts about a device and the shared rules that judge them."""
import socket
import urllib.error
import urllib.request
from dataclasses import dataclass

CANARY_DOMAIN = "use-application-dns.net"  # a sing-box rule answers it NXDOMAIN
HEALTH_DOMAIN = "ipv4.icanhazip.com"  # must be in the rules; echoes the public address
DIRECT_HOST = "api.ipify.org"  # not in the rules
DIRECT_URL = f"https://{DIRECT_HOST}"  # echoes the public address
PORTAL_URL = "http://connectivity-check.ubuntu.com/"  # NetworkManager's check on Ubuntu: 204 when no portal is in the way
FAKEIP_PREFIXES = ("198.18.", "198.19.")


@dataclass
class Facts:
    """What a target reports. None means not checked yet."""
    service: str = "unknown"  # active, inactive, failed, ...
    tun: bool = False
    fail_closed: bool | None = None  # the system blocks traffic, not just this tool's, when the service is down
    dns_intercepted: bool | None = None  # the canary returned NXDOMAIN
    health_listed: bool | None = None  # the health domain resolved to a FakeIP
    exit_checked: bool = False
    exit_tunnel: str | None = None  # address via the health domain; None after a check: unreachable
    exit_direct: str | None = None  # address via the direct URL
    extension: bool | None = None  # Linux: the Chrome extension is installed with the current config
    portal: bool | None = None  # Linux: a captive portal answered the check instead of the check server


@dataclass
class Verdict:
    state: str  # on, warn, leak, off
    reason: str


def assess(f: Facts) -> Verdict:
    """The one place that turns facts into a state. Every display uses it."""
    if f.service != "active":
        blocked = "the system blocks traffic" if f.fail_closed else "nothing blocks traffic"
        return Verdict("off", f"service is {f.service}; {blocked} while it is down")
    if not f.tun:
        return Verdict("warn", "tunnel interface is missing")
    if f.dns_intercepted is False:
        return Verdict("warn", f"DNS bypasses sing-box: {CANARY_DOMAIN} got a real answer")
    if f.health_listed is False:
        return Verdict("warn", f"{HEALTH_DOMAIN} is not in the rules; add it back")
    if f.portal:
        return Verdict("warn", "the network needs a sign-in: open any web page to log in")
    if f.exit_checked and f.exit_tunnel is None:
        return Verdict("warn", "tunnel down: listed domains cannot reach the internet")
    if f.exit_checked and f.exit_tunnel == f.exit_direct:
        return Verdict("leak", f"listed traffic exits directly via {f.exit_tunnel}")
    if f.fail_closed is False:
        return Verdict("warn", "not fail-closed: traffic is not blocked when the service stops")
    if f.extension is False:
        return Verdict("warn", "the Chrome extension is missing or out of date; run detour linux install")
    if None in (f.dns_intercepted, f.health_listed) or not f.exit_checked:
        return Verdict("warn", "checks still running")
    return Verdict("on", f"listed traffic exits via the VPN at {f.exit_tunnel}")


def report(facts: Facts) -> int:
    """Print the verdict and every fact; the exit code is 0 only for on."""
    verdict = assess(facts)
    print(f"{verdict.state}: {verdict.reason}")
    for name, value in vars(facts).items():
        print(f"  {name:<16} {value}")
    return 0 if verdict.state == "on" else 1


def resolve(name: str) -> list[str] | None:
    """IPv4 answers for name: [] for NXDOMAIN, None when the resolver failed."""
    try:
        return sorted({info[4][0] for info in socket.getaddrinfo(name, None, socket.AF_INET)})
    except socket.gaierror as e:
        return [] if e.errno == socket.EAI_NONAME else None


def dns_intercepted(resolve=resolve) -> bool | None:
    """True when the canary returns NXDOMAIN, which only the sing-box rule does."""
    answers = resolve(CANARY_DOMAIN)
    return None if answers is None else answers == []


def health_listed(resolve=resolve) -> bool | None:
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


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None  # urllib then raises HTTPError with the 3xx status


def portal(url: str = PORTAL_URL, timeout: float = 5) -> bool | None:
    """True when a captive portal answers the check, False for 204, None when the answer means neither."""
    try:
        with urllib.request.build_opener(_NoRedirect).open(url, timeout=timeout) as r:
            status = r.status
    except urllib.error.HTTPError as e:
        status = e.code
        e.close()
    except OSError:
        return None
    if status == 204:
        return False
    if status == 200 or 300 <= status < 400:  # a login page, or a redirect to one
        return True
    return None


def exit_ips(timeout: float = 8) -> tuple[str | None, str | None]:
    """Public address via the health domain (listed) and via the direct URL (not listed)."""
    return fetch_ip(f"https://{HEALTH_DOMAIN}", timeout), fetch_ip(DIRECT_URL, timeout)
