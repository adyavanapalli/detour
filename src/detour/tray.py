"""GNOME top-bar indicator: the sing-box cube, colored by the shared verdict."""
import os
import shutil
import subprocess
import sys
import threading
from pathlib import Path

from detour import linux, probes


def xdg(var: str, default: str) -> Path:
    return Path(os.environ.get(var) or Path.home() / default)


ICON_DIR = xdg("XDG_DATA_HOME", ".local/share") / "detour" / "icons"
STATUS_FILE = xdg("XDG_CACHE_HOME", ".cache") / "detour" / "status"
UNIT_FILE = xdg("XDG_CONFIG_HOME", ".config") / "systemd" / "user" / "detour-tray.service"
DASHBOARD_URL = "http://127.0.0.1:9090/dashboard/"
INTERVAL = 5  # seconds between cheap checks
EXIT_EVERY = 12  # ticks between exit-IP checks (60 s)

FACES = {  # top, left, right
    "on": ("#4ade80", "#15803d", "#22c55e"),
    "warn": ("#fbbf24", "#b45309", "#f59e0b"),
    "off": ("#f87171", "#991b1b", "#ef4444"),
}
ICON_FOR = {"on": "on", "warn": "warn", "off": "off", "leak": "off"}

SVG = """<svg xmlns="http://www.w3.org/2000/svg" width="512" height="512" viewBox="0 0 512 512">
  <g transform="translate(-204.8 -227.3) scale(0.9)">
    <path d="M512 262 754.5 402 512 542 269.5 402Z" fill="{top}"/>
    <path d="M269.5 402 512 542 512 812 269.5 672Z" fill="{left}"/>
    <path d="M512 542 754.5 402 754.5 672 512 812Z" fill="{right}"/>
    <path d="M512 262 754.5 402" stroke="#0f172a" stroke-opacity="0.35" stroke-width="3" fill="none"/>
    <path d="M512 262 269.5 402" stroke="#0f172a" stroke-opacity="0.35" stroke-width="3" fill="none"/>
    <path d="M512 542 512 812" stroke="#0f172a" stroke-opacity="0.35" stroke-width="3" fill="none"/>
    <path d="M356.8 351.6 390.75 332 633.25 472 599.3 491.6Z" fill="#94a3b8"/>
    <path d="M390.75 332 424.7 312.4 667.2 452.4 633.25 472Z" fill="#f1f5f9"/>
    <path d="M599.3 491.6 633.25 472 633.25 592 599.3 611.6Z" fill="#64748b"/>
    <path d="M633.25 472 667.2 452.4 667.2 572.4 633.25 592Z" fill="#cbd5e1"/>
  </g>
</svg>
"""

UNIT_TEXT = """[Unit]
Description=detour top-bar indicator
PartOf=graphical-session.target
After=graphical-session.target

[Service]
ExecStart={exe} linux tray
Restart=on-failure
RestartSec=3

[Install]
WantedBy=graphical-session.target
"""


def write_icons() -> None:
    """One SVG per state."""
    ICON_DIR.mkdir(parents=True, exist_ok=True)
    for state, (top, left, right) in FACES.items():
        (ICON_DIR / f"detour-{state}.svg").write_text(SVG.format(top=top, left=left, right=right))


def write_status(verdict: probes.Verdict) -> None:
    STATUS_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATUS_FILE.write_text(f"{verdict.state}\t{verdict.reason}\n")


class Tray:
    def __init__(self, Gtk, Gdk, GLib, AppIndicator):
        self.Gtk, self.Gdk, self.GLib = Gtk, Gdk, GLib
        self.ind = AppIndicator.Indicator.new("detour", "detour-off", AppIndicator.IndicatorCategory.SYSTEM_SERVICES)
        self.ind.set_icon_theme_path(str(ICON_DIR))
        self.ind.set_status(AppIndicator.IndicatorStatus.ACTIVE)
        self.ind.set_title("detour")
        self.actions, self.tick, self.busy, self.last_exit = {}, 0, False, None
        self.ind.set_menu(self.menu())
        self.refresh()
        GLib.timeout_add_seconds(INTERVAL, self.refresh)

    def menu(self):
        menu = self.Gtk.Menu()
        item = self.Gtk.MenuItem(label="Open Dashboard")
        item.connect("activate", lambda *_: self.Gtk.show_uri_on_window(None, DASHBOARD_URL, self.Gdk.CURRENT_TIME))
        menu.append(item)
        menu.append(self.Gtk.SeparatorMenuItem())
        for label, action in (("Start Service", "start"), ("Restart Service", "restart"), ("Stop Service", "stop")):
            self.actions[action] = item = self.Gtk.MenuItem(label=label)
            item.connect("activate", lambda _i, a=action: subprocess.Popen(["pkexec", "systemctl", a, linux.UNIT]))
            menu.append(item)
        menu.show_all()
        return menu

    def refresh(self) -> bool:
        """Collect in a thread (the network calls live there), then apply on the GTK thread."""
        if not self.busy:
            self.busy = True
            threading.Thread(target=self.work, daemon=True).start()
        return True  # keep the timer

    def work(self) -> None:
        facts = linux.collect(exit_check=self.tick % EXIT_EVERY == 0)
        self.tick += 1
        if facts.exit_checked:
            self.last_exit = (facts.exit_tunnel, facts.exit_direct)
        elif self.last_exit and facts.health_listed:
            facts.exit_checked, (facts.exit_tunnel, facts.exit_direct) = True, self.last_exit
        self.GLib.idle_add(self.apply, probes.assess(facts))

    def apply(self, verdict: probes.Verdict) -> bool:
        self.ind.set_icon_full(f"detour-{ICON_FOR[verdict.state]}", f"detour: {verdict.reason}")
        running = verdict.state != "off"
        self.actions["start"].set_visible(not running)
        self.actions["restart"].set_visible(running)
        self.actions["stop"].set_visible(running)
        write_status(verdict)
        self.busy = False
        return False


def available() -> bool:
    """True when the GTK and AppIndicator bindings can be imported."""
    try:
        import gi
        gi.require_version("Gtk", "3.0")
        gi.require_version("AyatanaAppIndicator3", "0.1")
        return True
    except (ImportError, ValueError):
        return False


def main() -> None:
    import gi
    gi.require_version("Gtk", "3.0"), gi.require_version("Gdk", "3.0"), gi.require_version("AyatanaAppIndicator3", "0.1")
    from gi.repository import AyatanaAppIndicator3, Gdk, GLib, Gtk
    Tray(Gtk, Gdk, GLib, AyatanaAppIndicator3)
    Gtk.main()


def install() -> None:
    """Icons, the user unit, and start it. Re-running restarts the indicator with the new code."""
    write_icons()
    UNIT_FILE.parent.mkdir(parents=True, exist_ok=True)
    exe = Path(shutil.which("detour") or sys.argv[0]).resolve()
    UNIT_FILE.write_text(UNIT_TEXT.format(exe=exe))
    for step in (("daemon-reload",), ("enable", "detour-tray.service"), ("restart", "detour-tray.service")):
        subprocess.run(["systemctl", "--user", *step], check=True)


def uninstall() -> None:
    subprocess.run(["systemctl", "--user", "disable", "--now", "detour-tray.service"], check=False)
    UNIT_FILE.unlink(missing_ok=True)
    subprocess.run(["systemctl", "--user", "daemon-reload"], check=True)
