"""The Chrome extension (Detour Sentry) for the Linux target.

On listed domains, the extension sets the User-Agent and blocks requests to unlisted domains.
Its files are in extension/. install packs them into a .crx with Google Chrome, and a managed
policy force-installs it. The extension reads rules_url and user_agent from the config.json that
is packed with it, so a change to either value needs a new install. This module does no root
work: linux.py writes and removes the root files that it names.
"""
import hashlib
import json
import os
import shutil
import signal
import subprocess
import tempfile
import time
from importlib import resources
from pathlib import Path

from detour import config

CHROME_NAMES = ("google-chrome", "google-chrome-stable")
CHROME_EXE = "/opt/google/chrome/chrome"  # the browser process; its helpers have other names
USER_DATA_DIR = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "google-chrome"
STOP_TIMEOUT = 20  # seconds between SIGTERM and SIGKILL
DATA_DIR = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local/share") / "detour" / "chrome"
LEGACY_DIR = Path.home() / ".local/share/detour-sentry"  # where the separate detour-sentry installer kept its files
CRX_NAME = "detour-sentry.crx"

POLICY = Path("/etc/opt/chrome/policies/managed/detour_sentry.json")
DESCRIPTOR_DIRS = (Path("/opt/google/chrome/extensions"), Path("/usr/share/google-chrome/extensions"))
LEGACY_POLICY = Path("/etc/chromium/policies/managed/detour_sentry.json")


def find_chrome() -> str:
    """The Google Chrome command, or an OSError: the Linux target needs Chrome."""
    for name in CHROME_NAMES:
        found = shutil.which(name)
        if found:
            return found
    raise OSError("Google Chrome is not installed; the Linux target needs it for the extension")


def preflight() -> str:
    """Check the tools that the extension needs, before install changes anything. Returns Chrome."""
    chrome = find_chrome()
    if not shutil.which("openssl"):
        raise OSError("openssl is not installed; the extension needs it for its signing key")
    return chrome


def config_json(table: dict) -> str:
    """The extension's config.json. It has no default values: both keys must be set."""
    missing = [k for k in ("rules_url", "user_agent") if not table.get(k)]
    if missing:
        raise ValueError(f"linux: missing {', '.join(missing)}")
    return json.dumps({"gist_url": table["rules_url"], "user_agent": table["user_agent"]}, indent=2) + "\n"


def ensure_key() -> Path:
    """The signing key. It sets the extension ID, so it is kept. A key of the old installer is taken over."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    key = DATA_DIR / "key.pem"
    if not key.exists():
        legacy = LEGACY_DIR / "key.pem"
        if legacy.exists():
            pem = legacy.read_text()
        else:
            pem = subprocess.run(["openssl", "genrsa", "2048"], capture_output=True, check=True, text=True).stdout
        config.write_private(key, pem)
    return key


def extension_id(key: Path) -> str:
    """Chrome's ID for a key: the first 32 hex digits of SHA-256 of the public key, with 0-f as a-p."""
    der = subprocess.run(["openssl", "rsa", "-in", str(key), "-pubout", "-outform", "DER"],
                         capture_output=True, check=True).stdout
    return hashlib.sha256(der).hexdigest()[:32].translate(str.maketrans("0123456789abcdef", "abcdefghijklmnop"))


def next_version(base: str) -> str:
    """base plus a build number that grows with each install. Chrome updates only to a higher version."""
    counter = DATA_DIR / "build"
    build = int(counter.read_text()) + 1 if counter.exists() else 1
    counter.write_text(f"{build}\n")
    return f"{base}.{build}"


def stage(dest: Path, table: dict) -> str:
    """Copy the extension files to dest, with config.json and a new version. Returns the version."""
    with resources.as_file(resources.files("detour").joinpath("extension")) as src:
        shutil.copytree(src, dest)
    manifest = json.loads((dest / "manifest.json").read_text())
    manifest["version"] = next_version(manifest["version"])
    (dest / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    (dest / "config.json").write_text(config_json(table))
    return manifest["version"]


def pack(chrome: str, key: Path, staged: Path) -> Path:
    """Pack staged into a .crx. A separate profile keeps the running browser out of it."""
    cmd = [chrome, f"--pack-extension={staged}", f"--pack-extension-key={key}", "--headless",
           f"--user-data-dir={staged.parent / 'profile'}", "--no-first-run"]
    print("+", " ".join(cmd))
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    crx = staged.parent / f"{staged.name}.crx"
    if not crx.exists():
        raise OSError(f"Chrome did not pack the extension: {(r.stderr or r.stdout).strip()[-300:]}")
    return crx


def update_xml(ext_id: str, version: str, crx: Path) -> str:
    return (
        "<?xml version='1.0' encoding='UTF-8'?>\n"
        "<gupdate xmlns='http://www.google.com/update2/response' protocol='2.0'>\n"
        f"  <app appid='{ext_id}'>\n"
        f"    <updatecheck codebase='file://{crx}' version='{version}' />\n"
        "  </app>\n"
        "</gupdate>\n"
    )


def policy_json(ext_id: str, update_url: str) -> str:
    # force_pinned, not default_pinned. pin_first() puts the ID into the pinned list before Chrome
    # installs the extension. With default_pinned, Chrome then adds the ID a second time at the end,
    # and a drag in the toolbar with a duplicate ID crashes Chrome. For a force-pinned ID, Chrome never
    # adds it to the list, and it keeps the position that pin_first() gave it. The user cannot drag it.
    settings = {ext_id: {"installation_mode": "force_installed", "update_url": update_url,
                         "toolbar_pin": "force_pinned"}}
    return json.dumps({"ExtensionSettings": settings}, indent=2) + "\n"


def descriptor_json(crx: Path, version: str) -> str:
    return json.dumps({"external_crx": str(crx), "external_version": version}, indent=2) + "\n"


def build(chrome: str, table: dict) -> tuple[str, dict[Path, str]]:
    """Pack the extension into DATA_DIR. Returns its ID and the root files that install it: {path: text}."""
    key = ensure_key()
    ext_id = extension_id(key)
    crx = DATA_DIR / CRX_NAME
    with tempfile.TemporaryDirectory() as tmp:
        staged = Path(tmp) / "detour-sentry"
        version = stage(staged, table)
        shutil.move(pack(chrome, key, staged), crx)
    crx.chmod(0o644)
    update = DATA_DIR / "update.xml"
    update.write_text(update_xml(ext_id, version, crx))
    (DATA_DIR / "config.json").write_text(config_json(table))  # what status compares against
    files = {POLICY: policy_json(ext_id, f"file://{update}")}
    for d in DESCRIPTOR_DIRS:
        files[d / f"{ext_id}.json"] = descriptor_json(crx, version)
    return ext_id, files


def is_ours(descriptor: Path) -> bool:
    """True when an external-extension descriptor points at a .crx from detour or detour-sentry."""
    try:
        crx = json.loads(descriptor.read_text()).get("external_crx", "")
    except (OSError, ValueError):
        return False
    return crx.startswith((str(DATA_DIR) + "/", str(LEGACY_DIR) + "/"))


def root_files() -> list[Path]:
    """Every root file that installs the extension now, including those of the old installer."""
    found = [p for p in (POLICY, LEGACY_POLICY) if p.exists()]
    for d in DESCRIPTOR_DIRS:
        found += sorted(p for p in d.glob("*.json") if is_ours(p))
    return found


def chrome_pids(proc: Path = Path("/proc")) -> list[int]:
    """The Google Chrome processes of this user, the headless ones included."""
    pids = []
    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            if entry.stat().st_uid == os.getuid() and os.readlink(entry / "exe") == CHROME_EXE:
                pids.append(int(entry.name))
        except OSError:
            pass  # the process ended, or it is not ours
    return pids


def parent(pid: int, proc: Path = Path("/proc")) -> int | None:
    try:
        return int((proc / str(pid) / "stat").read_text().rsplit(")", 1)[1].split()[1])
    except (OSError, IndexError, ValueError):
        return None


def browsers(pids: list[int], proc: Path = Path("/proc")) -> list[int]:
    """The main browser processes: those whose parent is not Chrome. The others are their renderers and helpers."""
    return [pid for pid in pids if parent(pid, proc) not in pids]


def stop_chrome() -> None:
    """Stop every Chrome process of this user.

    SIGTERM goes to each main browser process only, so that it saves the session and closes its own
    renderers. A signal to a renderer would make the browser record a crashed tab. SIGKILL goes to
    every process that is left after STOP_TIMEOUT.
    """
    pids = chrome_pids()
    if not pids:
        return
    print(f"stopping Google Chrome ({len(browsers(pids))} browser processes), so that its profile can be changed")
    for sig, wait in ((signal.SIGTERM, STOP_TIMEOUT), (signal.SIGKILL, 5)):
        pids = chrome_pids()
        for pid in browsers(pids) if sig == signal.SIGTERM else pids:
            try:
                os.kill(pid, sig)
            except ProcessLookupError:
                pass
        deadline = time.monotonic() + wait
        while chrome_pids() and time.monotonic() < deadline:
            time.sleep(0.2)
        if not chrome_pids():
            return
    raise OSError("Google Chrome did not stop")


def profiles() -> list[Path]:
    """The Preferences file of every profile: Default, Profile 1, Profile 2, and so on."""
    dirs = [USER_DATA_DIR / "Default", *sorted(USER_DATA_DIR.glob("Profile *"))]
    return [d / "Preferences" for d in dirs if (d / "Preferences").is_file()]


def put_first(prefs: dict, ext_id: str) -> None:
    """Move ext_id to the front of the pinned list. The list has a local copy and, with Sync, an account copy.

    A drag in the toolbar changes both copies in the same way. Chrome shows pinned icons in list order.
    """
    local = prefs.setdefault("extensions", {})
    local["pinned_extensions"] = [ext_id] + [i for i in local.get("pinned_extensions", []) if i != ext_id]
    account = (prefs.get("account_values") or {}).get("extensions") or {}
    if "pinned_extensions" in account:  # only with Sync; never create it
        account["pinned_extensions"] = [ext_id] + [i for i in account["pinned_extensions"] if i != ext_id]


def pin_first(ext_id: str) -> None:
    """Put the extension first on the toolbar of every profile. Chrome must not run: it rewrites Preferences."""
    stop_chrome()
    for path in profiles():
        with open(path, encoding="utf-8") as f:
            prefs = json.load(f)
        put_first(prefs, ext_id)
        mode = path.stat().st_mode & 0o777
        fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".detour-")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(prefs, f, ensure_ascii=False, separators=(",", ":"))
        os.chmod(tmp, mode)
        os.replace(tmp, path)
        print(f"pinned the extension first in {path.parent.name}")


def remove_local(purge: bool) -> None:
    """Remove the old installer's directory. With purge, also remove the key and the packed files."""
    shutil.rmtree(LEGACY_DIR, ignore_errors=True)
    if purge:
        shutil.rmtree(DATA_DIR, ignore_errors=True)


def current(table: dict) -> bool:
    """True when the policy is in place and the packed config.json matches the [linux] table."""
    try:
        return POLICY.exists() and (DATA_DIR / "config.json").read_text() == config_json(table)
    except (OSError, ValueError):
        return False
