"""Android target: sing-box for Android (SFA) on a phone reached over ADB."""
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

from detour import device, probes

PACKAGE = "io.nekohasekai.sfa"
VPN_SERVICE = f"{PACKAGE}/.bg.VPNService"
MAIN_ACTIVITY = f"{PACKAGE}/.compose.MainActivity"
TILE = f"{PACKAGE}/.bg.TileService"
FILES_DIR = f"/sdcard/Android/data/{PACKAGE}/files"  # SFA's working directory: the shell may write here, other apps may not
PROFILE = "detour"  # SFA names the imported profile after the file
RELEASES = "https://api.github.com/repos/SagerNet/sing-box/releases/latest"
DASHBOARD_PORT = 9091  # on the desktop, forwarded to the phone's 9090
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
    return parse_ping(shell(f"ping -c1 -W1 {name} 2>&1", check=False))  # unknown host is reported on stderr


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
    f.tun = tun_present()
    f.fail_closed = fail_closed()
    if f.service == "active":
        f.dns_intercepted = probes.dns_intercepted(resolve)
        f.health_listed = probes.health_listed(resolve)
        if f.health_listed and exit_check:
            f.exit_tunnel, f.exit_direct = fetch_ip(probes.HEALTH_DOMAIN), fetch_ip(DIRECT_HOST)
            f.exit_checked = True
    return f


def tun_present() -> bool:
    return bool(TUN_NAME.search(shell("ls /sys/class/net")))


def wait_for(condition, seconds: int) -> bool:
    """Poll once a second until condition() is true; False when the time runs out."""
    for _ in range(seconds):
        if condition():
            return True
        time.sleep(1)
    return False


def install_app() -> None:
    """Install SFA from the latest sing-box release, in the build for the phone's CPU."""
    abi = shell("getprop ro.product.cpu.abi").strip()
    with urllib.request.urlopen(RELEASES, timeout=30) as r:
        version = json.load(r)["tag_name"].removeprefix("v")
    url = f"https://github.com/SagerNet/sing-box/releases/download/v{version}/SFA-{version}-{abi}.apk"
    print("downloading", url)
    with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f, urllib.request.urlopen(url, timeout=600) as r:
        shutil.copyfileobj(r, f)
    try:
        adb("install", "-r", f.name, quiet=False)
    finally:
        os.unlink(f.name)


def screen() -> str:
    """The current screen as uiautomator XML."""
    return shell("uiautomator dump /sdcard/detour-ui.xml >/dev/null && cat /sdcard/detour-ui.xml; rm -f /sdcard/detour-ui.xml")


def texts(xml: str) -> list[str]:
    """Every non-empty text on the screen, in document order."""
    return [t for t in re.findall(r' text="([^"]*)"', xml) if t]


def bounds(xml: str, label: str) -> tuple[int, int, int, int] | None:
    """The box of the control with exactly this text, if the screen has one."""
    node = re.search(rf' text="{re.escape(label)}"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', xml)
    return tuple(map(int, node.groups())) if node else None


def tap(xml: str, label: str) -> bool:
    box = bounds(xml, label)
    if not box:
        return False
    x1, y1, x2, y2 = box
    shell(f"input tap {(x1 + x2) // 2} {(y1 + y2) // 2}", quiet=False)
    return True


def confirm_import() -> None:
    """Answer SFA's import dialog. An error dialog instead means SFA refused the profile."""
    for _ in range(10):
        xml = screen()
        if tap(xml, "Import"):
            return
        shown = texts(xml)
        if "Error" in shown:
            tap(xml, "OK")
            raise OSError("SFA refused the profile: " + shown[shown.index("Error") + 1])
        time.sleep(1)
    input(f"On the phone, tap Import to import profile {PROFILE}, then press Enter here: ")


def import_profile(text: str) -> None:
    """Hand the profile to SFA the way a file manager would; SFA checks it, saves it, and selects it."""
    shell(f"am start -n {MAIN_ACTIVITY}", quiet=False)  # first run creates the working directory
    time.sleep(2)
    remote = f"{FILES_DIR}/{PROFILE}.json"
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        f.write(text)
    try:
        adb("push", f.name, remote, quiet=False)
        shell(f"am start -a android.intent.action.VIEW -d file://{remote} -n {MAIN_ACTIVITY}", quiet=False)
        confirm_import()
        time.sleep(2)  # SFA reads the file again after the confirmation
    finally:
        os.unlink(f.name)
        shell(f"rm -f {remote}", quiet=False)  # the copy in SFA's private storage is the one that runs


def reload() -> None:
    """Stop and start SFA's service through its Quick Settings tile, as a tap would; the selected profile loads on start."""
    shell(f"cmd statusbar add-tile {TILE}", quiet=False)
    try:
        steps = [("stop", lambda: not tun_present()), ("start", tun_present)] if tun_present() else [("start", tun_present)]
        for step, done in steps:
            shell("cmd statusbar expand-settings")  # the tile learns the service state only while it is on screen
            time.sleep(2)
            shell(f"cmd statusbar click-tile {TILE}", quiet=False)
            if not wait_for(done, 30):
                raise OSError(f"SFA did not {step} within 30 seconds")
            shell("cmd statusbar collapse")
    finally:
        shell(f"cmd statusbar remove-tile {TILE}")


def reboot_and_wait() -> None:
    adb("reboot", quiet=False)
    time.sleep(5)
    adb("wait-for-device")
    wait_for(lambda: shell("getprop sys.boot_completed", check=False).strip() == "1", 300)
    print("Unlock the phone. The VPN starts after the unlock.")
    if not wait_for(tun_present, 600):
        raise OSError("the VPN did not start after the reboot")


def install() -> None:
    """Make the phone a detour client. Each adb step is printed as it runs."""
    table = device.ensure_identity("android")
    text = device.rendered_config("android", table)
    if service_state() == "not installed":
        install_app()
    import_profile(text)
    shell("settings put global private_dns_mode off", quiet=False)  # DNS over TLS would leave the split
    shell(f"dumpsys deviceidle whitelist +{PACKAGE}", quiet=False)  # no battery limits on the VPN
    adb("forward", f"tcp:{DASHBOARD_PORT}", "tcp:9090", quiet=False)
    if fail_closed():
        reload()
    else:
        shell(f"settings put secure always_on_vpn_app {PACKAGE}; settings put secure always_on_vpn_lockdown 1", quiet=False)
        print("Always-on VPN with lockdown is saved. Android applies it at boot, and grants the VPN consent then.")
        if input("Reboot the phone now? [y/N] ").strip().lower() == "y":
            reboot_and_wait()
        else:
            print("Until the next reboot, traffic is not blocked while the VPN is down.")
            reload()
    print(f"installed. Check it with: detour android status\ndashboard: http://127.0.0.1:{DASHBOARD_PORT}/dashboard/")


def uninstall(purge: bool = False) -> None:
    """Undo the system settings. With purge, remove SFA and its profiles; Android drops always-on with the package."""
    in_effect = fail_closed()
    adb("forward", "--remove", f"tcp:{DASHBOARD_PORT}", check=False, quiet=False)
    shell("settings delete secure always_on_vpn_app; settings put secure always_on_vpn_lockdown 0", quiet=False)
    shell("settings put global private_dns_mode opportunistic", quiet=False)
    shell(f"dumpsys deviceidle whitelist -{PACKAGE}", quiet=False)
    if purge:
        adb("uninstall", PACKAGE, quiet=False)
    elif in_effect:
        print("SFA and its profile stay. Always-on lockdown stays in effect until the phone reboots.")
        if input("Reboot the phone now? [y/N] ").strip().lower() == "y":
            adb("reboot", quiet=False)
