"""The detour command: detour <target> <verb>."""
import argparse
import importlib
import subprocess
import sys
from pathlib import Path

from detour import config, probes, wireguard

SECRET_KEYS = ("device_private_key", "api_secret", "tailscale_auth_key")


def config_get(target: str, key: str | None) -> None:
    if key == "device_public_key":
        print(derived(target)["device_public_key"])
    elif key == "peer":
        print(derived(target)["peer"], end="")
    elif key:
        print(config.get(target, key) or "")
    else:
        listing(target)


def derived(target: str) -> dict:
    """device_public_key and the [Peer] block, when a private key and address exist."""
    table = config.get(target)
    if not table.get("device_private_key") or not table.get("device_address"):
        raise ValueError(f"{target}: device_private_key and device_address are needed first")
    public = wireguard.public_key(table["device_private_key"])
    return {"device_public_key": public, "peer": wireguard.peer_block(public, table["device_address"])}


def listing(target: str) -> None:
    table = config.get(target)
    for key in config.KEYS:
        value = table.get(key)
        shown = "(set)" if key in SECRET_KEYS and value else value or "(unset)"
        print(f"{key:<20} {shown}")
    if table.get("device_private_key") and table.get("device_address"):
        print(f"{'device_public_key':<20} {derived(target)['device_public_key']}")


def config_import(target: str, path: str | None) -> None:
    text = Path(path).read_text() if path else sys.stdin.read()
    found = wireguard.parse_conf(text)
    if not found:
        raise ValueError("no WireGuard settings found in the input")
    for key, value in found.items():
        config.put(target, key, value)
        print(f"set {key}")
    print("rules_url is not part of a WireGuard conf; set it with: detour", target, "config set rules_url <url>")


def status(target: str) -> int:
    return probes.report(importlib.import_module(f"detour.{target}").collect())


def install(target: str) -> None:
    if target == "android":
        from detour import android
        android.install()
        return
    from detour import linux, tray
    linux.install()
    if tray.available():
        tray.install()
        print("top-bar indicator installed")
    else:
        print("top-bar indicator skipped: the GTK and AppIndicator bindings are not installed")


def uninstall(target: str, purge: bool) -> None:
    if target == "android":
        from detour import android
        android.uninstall(purge=purge)
        return
    from detour import linux, tray
    tray.uninstall()
    linux.uninstall(purge=purge)


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="detour", description="Domain-based split tunneling with sing-box.")
    targets = p.add_subparsers(dest="target", required=True)
    for target in config.TARGETS:
        t = targets.add_parser(target).add_subparsers(dest="verb", required=True)
        c = t.add_parser("config").add_subparsers(dest="action", required=True)
        c.add_parser("get").add_argument("key", nargs="?")
        s = c.add_parser("set")
        s.add_argument("key"), s.add_argument("value")
        c.add_parser("import").add_argument("path", nargs="?")
        t.add_parser("install")
        t.add_parser("status")
        t.add_parser("uninstall").add_argument("--purge", action="store_true")
    return p


def main() -> None:
    a = parser().parse_args()
    try:
        if a.verb == "config":
            {"get": lambda: config_get(a.target, a.key), "set": lambda: config.put(a.target, a.key, a.value),
             "import": lambda: config_import(a.target, a.path)}[a.action]()
        elif a.verb == "status":
            sys.exit(status(a.target))
        else:
            {"install": lambda: install(a.target), "uninstall": lambda: uninstall(a.target, a.purge)}[a.verb]()
    except (ValueError, OSError, subprocess.CalledProcessError) as e:
        sys.exit(f"detour: {e}")
