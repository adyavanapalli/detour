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
    for attempt in (1, 2):
        r = subprocess.run([adb_path(), *args], capture_output=True, text=True, stdin=subprocess.DEVNULL)  # keep stdin for prompts
        gone = "no devices/emulators found" in r.stderr or "device offline" in r.stderr or "not found" in r.stderr
        if r.returncode and gone and attempt == 1:  # a USB link can drop for a few seconds; wait for it once
            subprocess.run([adb_path(), "wait-for-device"], stdin=subprocess.DEVNULL, timeout=60, check=False)
            continue
        break
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
    if PACKAGE not in shell(f"pm list packages {PACKAGE}"):  # an adb failure raises instead of reading as absent
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
        try:
            if condition():
                return True
        except OSError:  # adb loses the phone for a while during a reboot
            pass
        time.sleep(1)
    return False


def download_apk() -> str:
    """The latest SFA release APK for the phone's CPU, in a temp file that the caller deletes."""
    abi = shell("getprop ro.product.cpu.abi").strip()
    with urllib.request.urlopen(RELEASES, timeout=30) as r:
        version = json.load(r)["tag_name"].removeprefix("v")
    url = f"https://github.com/SagerNet/sing-box/releases/download/v{version}/SFA-{version}-{abi}.apk"
    print("downloading", url)
    with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f, urllib.request.urlopen(url, timeout=600) as r:
        shutil.copyfileobj(r, f)
    return f.name


def installed_apk() -> str:
    """A copy of the APK the phone runs, for when the release would be a downgrade."""
    path = shell(f"pm path {PACKAGE}").split()[0].removeprefix("package:")
    local = tempfile.NamedTemporaryFile(suffix=".apk", delete=False).name
    adb("pull", path, local, quiet=False)
    return local


def install_apk(apk: str, replace: bool) -> None:
    """Install SFA. A replace also makes Android restart the always-on VPN, as after any app update."""
    flags = ["-r"] if replace else []
    try:
        try:
            adb("install", *flags, "-i", PACKAGE, apk, quiet=False)  # SFA as its own installer of record, for silent updates
        except OSError as e:
            if "DOWNGRADE" in str(e):
                raise
            adb("install", *flags, apk, quiet=False)
    except OSError as e:
        if "DOWNGRADE" not in str(e):
            raise
        print("the phone runs a newer SFA than the latest release: reinstalling its own copy instead")
        own = installed_apk()
        try:
            adb("install", "-r", own, quiet=False)
        finally:
            os.unlink(own)


def screen() -> str:
    """The current screen as uiautomator XML."""
    return shell("uiautomator dump /sdcard/detour-ui.xml >/dev/null && cat /sdcard/detour-ui.xml; rm -f /sdcard/detour-ui.xml")


TEXT_ATTR = r""" text=(?:"([^"]*)"|'([^']*)')"""  # uiautomator switches to single quotes when the text has double quotes


def texts(xml: str) -> list[str]:
    """Every non-empty text on the screen, in document order."""
    return [a or b for a, b in re.findall(TEXT_ATTR, xml) if a or b]


def bounds(xml: str, label: str, attr: str = "text") -> tuple[int, int, int, int] | None:
    """The box of the control whose attr (text, or content-desc for icons) is exactly label, if the screen has one."""
    quoted = f'"{re.escape(label)}"|' + f"'{re.escape(label)}'"
    node = re.search(rf' {attr}=(?:{quoted})[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', xml)
    return tuple(map(int, node.groups())) if node else None


def tap(xml: str, label: str, attr: str = "text") -> bool:
    box = bounds(xml, label, attr)
    if not box:
        return False
    x1, y1, x2, y2 = box
    shell(f"input tap {(x1 + x2) // 2} {(y1 + y2) // 2}", quiet=False)
    return True


def delete_older_profiles() -> None:
    """After an import, remove the earlier profiles with the same name; the newest one, last in the list, is selected."""
    if not tap(screen(), "Expand", "content-desc"):  # opens the profile list sheet on the dashboard
        return
    time.sleep(2)
    for _ in range(10):
        xml = screen()
        rows = list(re.finditer(rf' text="{PROFILE}"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', xml))
        if len(rows) < 2:
            break
        y = (int(rows[0].group(2)) + int(rows[0].group(4))) // 2  # the oldest sits first
        menus = [tuple(map(int, m.groups())) for m in re.finditer(r'content-desc="More options"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', xml)]
        near = [b for b in menus if abs((b[1] + b[3]) // 2 - y) < 80]
        if not near:
            break
        x1, y1, x2, y2 = near[0]
        shell(f"input tap {(x1 + x2) // 2} {(y1 + y2) // 2}", quiet=False)
        time.sleep(2)
        if not tap(screen(), "Delete"):
            break
        time.sleep(2)
    shell("input keyevent BACK")  # close the sheet
    time.sleep(1)


def confirm_import(screen=screen, tap=tap) -> None:
    """Answer SFA's dialogs: OK to its one-time update prompt, Import to the profile. An error dialog means refusal."""
    imported_at = None
    for tick in range(15):
        xml = screen()
        shown = texts(xml)
        if "Error" in shown:
            tap(xml, "OK")
            raise OSError("SFA refused the profile: " + shown[shown.index("Error") + 1])
        if "Check Update" in shown:  # first launch only: yes to update checks from GitHub
            tap(xml, "OK")
        elif imported_at is None and tap(xml, "Import"):
            imported_at = tick
        elif imported_at is not None and tick - imported_at >= 3:  # the update prompt can follow the import
            return
        time.sleep(1)
    if imported_at is None:
        input(f"On the phone, tap Import to import profile {PROFILE}, then press Enter here: ")


def switches(xml: str) -> dict[str, tuple[bool, tuple[int, int, int, int]]]:
    """Every switch on the screen, keyed by the text that precedes it: {text: (on, bounds)}."""
    found, last = {}, ""
    for node in re.findall(r"<node ([^>]*)/?>", xml):
        attrs = {k: (a or b) for k, a, b in re.findall(r"""([\w-]+)=(?:"([^"]*)"|'([^']*)')""", node)}
        if attrs.get("text"):
            last = attrs["text"]
        if attrs.get("checkable") == "true":
            found[last] = (attrs.get("checked") == "true", tuple(map(int, re.findall(r"\d+", attrs["bounds"]))))
    return found


UPDATE_SWITCHES = (  # the text SFA shows right before each switch on Settings > App
    "Automatic Update Check",
    "Install updates without interaction",  # Silent Install
    "Automatically download and install updates in background",  # Auto Update
)


def enable_updates() -> None:
    """Turn on SFA's own update checks, silent installs, and automatic updates on its App settings page."""
    for label in ("Settings", "App"):
        if not tap(screen(), label):
            raise OSError(f"SFA's {label} page was not found on screen")
        time.sleep(2)
    for wanted in UPDATE_SWITCHES:
        for _ in range(4):  # the switches sit below the fold; a tap can also shift the ones after it
            found = switches(screen())
            if wanted in found:
                break
            shell("input swipe 540 1800 540 600 300")
            time.sleep(1.5)
        else:
            raise OSError(f"the switch after {wanted!r} was not found on SFA's App page")
        on, (x1, y1, x2, y2) = found[wanted]
        if not on:
            shell(f"input tap {(x1 + x2) // 2} {(y1 + y2) // 2}", quiet=False)
            time.sleep(2)
    shell("input keyevent BACK; input keyevent BACK")  # back to the dashboard


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
    shell("input keyevent BACK")  # SFA opens the profile editor after an import; the dashboard is behind it
    time.sleep(1)
    delete_older_profiles()


def grant_permissions() -> None:
    """Everything Android would otherwise ask for on the first start, granted up front."""
    shell(f"pm grant {PACKAGE} android.permission.POST_NOTIFICATIONS", quiet=False)
    shell(f"appops set {PACKAGE} ACTIVATE_VPN allow", quiet=False)  # the VPN consent dialog checks this app-op
    shell(f"appops set {PACKAGE} REQUEST_INSTALL_PACKAGES allow", quiet=False)  # its own updates
    # Android 16 and later: sing-box's TCP stack needs local network access, or every TCP flow dies silently
    shell(f"pm grant {PACKAGE} android.permission.ACCESS_LOCAL_NETWORK", check=False, quiet=False)
    shell(f"appops set {PACKAGE} ACCESS_LOCAL_NETWORK allow", check=False, quiet=False)


def restart_service() -> None:
    """Stop the service if it runs, then start it, through SFA's own dashboard buttons; the selected profile loads."""
    shell(f"am start -n {MAIN_ACTIVITY}", quiet=False)
    time.sleep(2)
    if tap(screen(), "Stop", "content-desc"):
        if not wait_for(lambda: not tun_present(), 30):
            raise OSError("SFA did not stop within 30 seconds")
        time.sleep(1)
    if not tap(screen(), "Start", "content-desc"):
        raise OSError("SFA's Start button was not found on its dashboard")
    for _ in range(30):  # the grants above make prompts unlikely; answer them if they appear anyway
        xml = screen()
        shown = texts(xml)
        if "Connection request" in shown:
            tap(xml, "OK")
        elif "Allow" in shown:
            tap(xml, "Allow" if "notifications" in " ".join(shown) else "Don’t allow")
        elif tun_present():
            return
        time.sleep(1)
    raise OSError("the VPN did not start within 30 seconds")


def verify_tunnel() -> probes.Facts:
    """The facts, with the tunnel proven: listed traffic exits somewhere else than direct traffic."""
    facts = collect()
    verdict = probes.assess(facts)
    if facts.exit_tunnel is None or facts.exit_tunnel == facts.exit_direct:
        raise OSError(f"the tunnel does not work ({verdict.reason}); nothing was locked down")
    return facts


def reboot_and_wait() -> None:
    adb("reboot", quiet=False)
    time.sleep(5)
    adb("wait-for-device")
    wait_for(lambda: shell("getprop sys.boot_completed", check=False).strip() == "1", 300)
    print("Unlock the phone. The VPN starts after the unlock.")
    if not wait_for(tun_present, 600):
        raise OSError("the VPN did not start after the reboot")


def install() -> None:
    """Make the phone a detour client. The phone is never locked down before the tunnel is proven to work."""
    table = device.ensure_identity("android")
    text = device.rendered_config("android", table)
    apk = download_apk()
    try:
        if service_state() == "not installed":
            install_apk(apk, replace=False)
        import_profile(text)
        grant_permissions()
        shell("settings put global private_dns_mode off", quiet=False)  # DNS over TLS would leave the split
        shell(f"dumpsys deviceidle whitelist +{PACKAGE}", quiet=False)  # no battery limits on the VPN
        adb("forward", f"tcp:{DASHBOARD_PORT}", "tcp:9090", quiet=False)
        enable_updates()
        restart_service()
        verify_tunnel()
        print("the tunnel works")
        if not fail_closed():
            shell(f"settings put secure always_on_vpn_app {PACKAGE}; settings put secure always_on_vpn_lockdown 1", quiet=False)
            print("Always-on VPN with lockdown is saved. Android applies it at boot.")
            if input("Reboot the phone now? [y/N] ").strip().lower() == "y":
                reboot_and_wait()
            else:
                print("Until the next reboot, traffic is not blocked while the VPN is down.")
    finally:
        os.unlink(apk)
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
