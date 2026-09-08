"""Android target: sing-box for Android (SFA) on a phone reached over ADB."""
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urlparse

from detour import device, probes

PACKAGE = "io.nekohasekai.sfa"
VPN_SERVICE = f"{PACKAGE}/.bg.VPNService"
MAIN_ACTIVITY = f"{PACKAGE}/.compose.MainActivity"
FILES_DIR = f"/sdcard/Android/data/{PACKAGE}/files"  # SFA's working directory
PROFILE = "detour"  # SFA names the imported profile after the file
RELEASES = "https://api.github.com/repos/SagerNet/sing-box/releases/tags/v1.14.0"
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
        r = subprocess.run([adb_path(), *args], capture_output=True, text=True, stdin=subprocess.DEVNULL)
        gone = any(s in r.stderr for s in ("no devices/emulators found", "device offline", "device not found", "error: closed"))
        if r.returncode and gone and attempt == 1:
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
    return parse_ping(shell(f"ping -c1 -W1 {name} 2>&1", check=False))


def parse_body(output: str) -> str | None:
    """The last line of an HTTP response when it is an IPv4 address."""
    body = output.strip().splitlines()[-1].strip() if output.strip() else ""
    return body if IPV4.fullmatch(body) else None


def fetch_ip(host: str) -> str | None:
    """Ask an IP echo service from the phone over plain HTTP; the shell has no TLS client."""
    request = f"GET / HTTP/1.0\\r\\nHost: {host}\\r\\n\\r\\n"
    return parse_body(shell(f"(printf '{request}'; sleep 2) | nc -w 6 {host} 80", check=False))


def parse_fail_closed(keys: str, dump: str) -> bool:
    """True when always-on lockdown for SFA is both saved in settings and in effect."""
    if keys.split() != [PACKAGE, "1"]:
        return False
    mode = MODE_CHANGE.search(dump)
    return bool(mode) and mode.groups() == ("true", "true")


def fail_closed() -> bool:
    keys = shell("settings get secure always_on_vpn_app; settings get secure always_on_vpn_lockdown")
    return parse_fail_closed(keys, shell("dumpsys vpn_management"))


def service_state() -> str:
    if PACKAGE not in shell(f"pm list packages {PACKAGE}"):
        return "not installed"
    return "active" if "startRequested=true" in shell(f"dumpsys activity services {VPN_SERVICE}") else "inactive"


def collect(exit_check: bool = True) -> probes.Facts:
    """The status facts for the phone, collected in parallel."""
    f = probes.Facts(service=service_state())
    if f.service == "not installed":
        return f
    f.tun = tun_present()
    f.fail_closed = fail_closed()
    if f.service == "active":
        with ThreadPoolExecutor(max_workers=4) as ex:
            fut_dns = ex.submit(probes.dns_intercepted, resolve)
            fut_health = ex.submit(probes.health_listed, resolve)
            fut_tunnel = ex.submit(fetch_ip, probes.HEALTH_DOMAIN) if exit_check else None
            fut_direct = ex.submit(fetch_ip, DIRECT_HOST) if exit_check else None

            f.dns_intercepted = fut_dns.result()
            f.health_listed = fut_health.result()
            if exit_check and fut_tunnel and fut_direct:
                f.exit_tunnel = fut_tunnel.result()
                f.exit_direct = fut_direct.result()
                f.exit_checked = True
    return f


def tun_present() -> bool:
    return bool(TUN_NAME.search(shell("ls /sys/class/net")))


def wait_for(condition, seconds: int) -> bool:
    """Poll until condition() is true; False when the time runs out."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            if condition():
                return True
        except OSError:
            pass
        time.sleep(0.5)
    return False


def resolve_apk() -> tuple[str, bool]:
    """Find a local SFA APK in ~/Downloads, or download the release from GitHub.

    Returns the path to the APK and a boolean indicating if it is a temporary download.
    """
    downloads = Path.home() / "Downloads"
    candidates = list(downloads.glob("SFA*.apk"))
    if candidates:
        return str(candidates[0]), False
    abi = shell("getprop ro.product.cpu.abi").strip()
    url = f"https://github.com/SagerNet/sing-box/releases/download/v1.14.0/SFA-1.14.0-{abi}.apk"
    print("downloading", url)
    temp_apk = tempfile.NamedTemporaryFile(suffix=".apk", delete=False).name
    req = urllib.request.Request(url, headers={"User-Agent": "detour"})
    with urllib.request.urlopen(req, timeout=120) as r, open(temp_apk, "wb") as f:
        shutil.copyfileobj(r, f)
    return temp_apk, True


def install_apk(apk: str, replace: bool) -> None:
    """Install SFA. A replace also makes Android restart the always-on VPN, as after any app update."""
    flags = ["-r"] if replace else []
    try:
        adb("install", *flags, "-i", PACKAGE, apk, quiet=False)
    except OSError:
        adb("install", *flags, apk, quiet=False)


def ui():
    """SFA's screen, through uiautomator2. The phone runs its small UiAutomator service only while we drive it."""
    try:
        import uiautomator2
    except ImportError as e:
        raise OSError("the Android target needs uiautomator2: install detour with the [android] extra") from e
    return uiautomator2.connect(os.environ.get("ANDROID_SERIAL"))


def texts(xml: str) -> list[str]:
    """Every non-empty text in a screen hierarchy, in document order."""
    return [a or b for a, b in re.findall(r""" text=(?:"([^"]*)"|'([^']*)')""", xml) if a or b]


def node(d, label: str):
    """The screen element whose text or description is exactly label, as an xpath query."""
    return d.xpath(f'//*[@text="{label}" or @content-desc="{label}"]')


def wait_any(d, *labels: str, timeout: float) -> str | None:
    """The first of these labels to appear on screen, or None when none does in time."""
    query = d.xpath(" | ".join(f'//*[@text="{label}" or @content-desc="{label}"]' for label in labels))
    if not query.wait(timeout=timeout):
        return None
    found = {el.text for el in query.all()} | {el.attrib.get("content-desc") for el in query.all()}
    return next((label for label in labels if label in found), None)


def until(condition, timeout: float, every: float = 0.2) -> bool:
    """Poll a condition until it is true; False when the time runs out."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(every)
    return condition()


def launch(d, fresh: bool = False) -> None:
    """Open SFA. On a fresh installation, wait for the update check dialog and tap OK first."""
    shell(f"am start -n {MAIN_ACTIVITY}", quiet=False)
    if fresh and node(d, "Check Update").wait(timeout=8):
        node(d, "OK").click()
    node(d, "Dashboard").wait(timeout=10)


def confirm_import(d) -> None:
    """Answer SFA's import dialog. An error dialog instead means SFA refused the profile."""
    for _ in range(3):
        seen = wait_any(d, "Check Update", "Error", "Import", timeout=10)
        if seen == "Import":
            node(d, "Import").click()
            if not node(d, "Edit Profile").wait(timeout=10):
                raise OSError("SFA did not save the profile")
            return
        if seen == "Error":
            shown = texts(d.dump_hierarchy())
            message = shown[shown.index("Error") + 1] if "Error" in shown else "see the phone"
            node(d, "OK").click()
            raise OSError(f"SFA refused the profile: {message}")
        if seen == "Check Update":
            node(d, "OK").click()
            continue
        raise OSError("SFA did not show its import dialog")


def delete_all_profiles(d) -> None:
    """Remove every existing profile in SFA to guarantee a clean slate before importing."""
    if not node(d, "Expand").exists:
        return
    node(d, "Expand").click()
    node(d, "More options").wait(timeout=5)
    while (opts := node(d, "More options").all()):
        opts[0].click()
        node(d, "Delete").wait(timeout=5)
        node(d, "Delete").click()
        time.sleep(0.2)
    if not node(d, "Dashboard").exists:
        shell("input keyevent 4")
        node(d, "Dashboard").wait(timeout=5)


UPDATE_SWITCHES = (
    "Automatically download and install updates in background",  # Auto Update first
    "Install updates without interaction",  # Silent Install second
)


def switch_after(d, row: str):
    """The switch on the settings row that carries this text."""
    return d.xpath(f'//*[@text="{row}"]/following::*[@checkable="true"][1]')


def enable_updates(d) -> None:
    """Turn on automatic background updates and silent installs in SFA settings."""
    node(d, "Settings").click()
    node(d, "App").wait(timeout=5)
    node(d, "App").click()
    node(d, "Update Settings").wait(timeout=5)
    shell("input swipe 500 1700 500 900 50")  # fast 50ms flick
    for row in UPDATE_SWITCHES:
        sw = switch_after(d, row)
        for _ in range(5):
            el = sw.get(timeout=3)
            if el.attrib.get("checked") == "true":
                break
            el.click()
            time.sleep(0.08)
        if sw.get().attrib.get("checked") != "true":
            raise OSError(f"SFA's switch for {row!r} would not turn on")
    shell(f"am start -S -n {MAIN_ACTIVITY}", quiet=False)
    node(d, "Dashboard").wait(timeout=5)


def import_profile(d, text: str) -> None:
    """Hand the profile to SFA via a file intent; SFA validates, saves, and selects it."""
    remote = f"{FILES_DIR}/{PROFILE}.json"
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        f.write(text)
    try:
        adb("push", f.name, remote, quiet=False)
        shell(f"am start -a android.intent.action.VIEW -d file://{remote} -n {MAIN_ACTIVITY}", quiet=False)
        confirm_import(d)
    finally:
        os.unlink(f.name)
        shell(f"rm -f {remote}", quiet=False)
    shell(f"am start -S -n {MAIN_ACTIVITY}", quiet=False)
    node(d, "Dashboard").wait(timeout=10)


def grant_permissions() -> None:
    """Everything Android would otherwise ask for on the first start, granted up front."""
    shell(f"pm grant {PACKAGE} android.permission.POST_NOTIFICATIONS", quiet=False)
    shell(f"appops set {PACKAGE} ACTIVATE_VPN allow", quiet=False)
    shell(f"appops set {PACKAGE} REQUEST_INSTALL_PACKAGES allow", quiet=False)
    shell(f"pm grant {PACKAGE} android.permission.ACCESS_LOCAL_NETWORK", check=False, quiet=False)
    shell(f"appops set {PACKAGE} ACCESS_LOCAL_NETWORK allow", check=False, quiet=False)


def restart_service(d) -> None:
    """Stop the service if it runs, then start it through SFA's dashboard button."""
    shell(f"am start -n {MAIN_ACTIVITY}", quiet=False)
    node(d, "Dashboard").wait(timeout=10)
    if node(d, "Stop").exists or tun_present():
        node(d, "Stop").click()
        if not wait_for(lambda: not tun_present(), 15):
            raise OSError("SFA did not stop within 15 seconds")
    node(d, "Start").wait(timeout=10)
    node(d, "Start").click()
    if not wait_for(tun_present, 15):
        raise OSError("the VPN did not start within 15 seconds")


def verify_tunnel() -> probes.Facts:
    """The facts, with the tunnel proven: listed traffic exits somewhere else than direct traffic."""
    facts = collect()
    verdict = probes.assess(facts)
    if facts.exit_tunnel is None or facts.exit_tunnel == facts.exit_direct:
        raise OSError(f"the tunnel does not work ({verdict.reason}); nothing was locked down")
    return facts


def reboot_and_wait() -> None:
    """Reboot the orderly way, so pending settings writes reach the disk, and wait until the tunnel answers."""
    shell("svc power reboot", check=False)
    until(lambda: subprocess.run([adb_path(), "get-state"], capture_output=True).returncode != 0, 60, every=1)
    adb("wait-for-device")
    wait_for(lambda: shell("getprop sys.boot_completed", check=False).strip() == "1", 300)
    print("Unlock the phone. The VPN starts after the unlock.")
    if not wait_for(tun_present, 600):
        raise OSError("the VPN did not start after the reboot")
    if not wait_for(lambda: fetch_ip(probes.HEALTH_DOMAIN) is not None, 120):
        raise OSError("the tunnel did not answer after the reboot")


def install() -> None:
    """Make the phone a detour client. The phone is never locked down before the tunnel is proven to work."""
    table = device.ensure_identity("android")
    text = device.rendered_config("android", table)

    orig_timeout = shell("settings get system screen_off_timeout").strip()
    apk_path = None
    is_temp_apk = False
    try:
        shell("settings put system screen_off_timeout 900000")
        shell("input keyevent 224")

        def is_locked() -> bool:
            win = shell("dumpsys window", check=False)
            if "isKeyguardShowing=true" in win:
                return True
            trust = shell("dumpsys trust", check=False)
            m = re.search(r"\(current\):.*?deviceLocked=(\d+)", trust)
            return bool(m and m.group(1) == "1")

        if is_locked():
            print("Please unlock your phone to continue...")
            while is_locked():
                time.sleep(0.5)

        fresh = service_state() == "not installed"
        if fresh:
            apk_path, is_temp_apk = resolve_apk()
            install_apk(apk_path, replace=False)

        grant_permissions()
        shell("settings put global private_dns_mode off", quiet=False)
        shell(f"dumpsys deviceidle whitelist +{PACKAGE}", quiet=False)

        d = ui()
        launch(d, fresh=fresh)

        if node(d, "Stop").exists or tun_present():
            node(d, "Stop").click()
            wait_for(lambda: not tun_present(), 15)

        delete_all_profiles(d)
        import_profile(d, text)
        enable_updates(d)

        restart_service(d)
        verify_tunnel()
        print("the tunnel works")

        if not fail_closed():
            shell(f"settings put secure always_on_vpn_app {PACKAGE}; settings put secure always_on_vpn_lockdown 1", quiet=False)
            keys = f"{PACKAGE}\n1\n"
            if not until(lambda: shell("settings get secure always_on_vpn_app; settings get secure always_on_vpn_lockdown") == keys, 10):
                raise OSError("the always-on settings did not take")
            print("Always-on VPN with lockdown is saved. Android applies it at boot.")
            if input("Reboot the phone now? [Y/n] ").strip().lower() not in ("n", "no"):
                reboot_and_wait()
            else:
                print("Until the next reboot, traffic is not blocked while the VPN is down.")
    finally:
        shell(f"settings put system screen_off_timeout {orig_timeout}", check=False)
        if is_temp_apk and apk_path and os.path.exists(apk_path):
            os.unlink(apk_path)
        shell("rm -rf /data/local/tmp/u2 /data/local/tmp/u2.jar", check=False)

    print()
    sys.exit(probes.report(collect()))


def uninstall(purge: bool = False) -> None:
    """Undo the system settings. With purge, remove SFA and its profiles; Android drops always-on with the package."""
    in_effect = fail_closed()
    shell("settings delete secure always_on_vpn_app; settings put secure always_on_vpn_lockdown 0", quiet=False)
    shell("settings put global private_dns_mode opportunistic", quiet=False)
    shell(f"dumpsys deviceidle whitelist -{PACKAGE}", quiet=False)
    if purge:
        adb("uninstall", PACKAGE, quiet=False)
    elif in_effect:
        print("SFA and its profile stay. Always-on lockdown stays in effect until the phone reboots.")
        if input("Reboot the phone now? [Y/n] ").strip().lower() not in ("n", "no"):
            adb("reboot", quiet=False)
