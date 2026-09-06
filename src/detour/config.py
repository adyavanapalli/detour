"""Per-target settings in ~/.config/detour/config.toml, file mode 0600."""
import json
import os
import tomllib
from pathlib import Path

TARGETS = ("linux", "android")
KEYS = ("rules", "server", "server_key", "dns", "address", "private_key")


def path() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config"
    return Path(base) / "detour" / "config.toml"


def load() -> dict:
    """The whole file as {target: {key: value}}, or {} if it does not exist."""
    try:
        with open(path(), "rb") as f:
            return tomllib.load(f)
    except FileNotFoundError:
        return {}


def check(target: str, key: str | None) -> None:
    if target not in TARGETS:
        raise ValueError(f"unknown target {target!r}, expected one of {', '.join(TARGETS)}")
    if key is not None and key not in KEYS:
        raise ValueError(f"unknown key {key!r}, expected one of {', '.join(KEYS)}")


def get(target: str, key: str | None = None):
    """One value, or the target's whole table when key is None."""
    check(target, key)
    table = load().get(target, {})
    return table if key is None else table.get(key)


def put(target: str, key: str, value: str) -> None:
    check(target, key)
    data = load()
    data.setdefault(target, {})[key] = value
    save(data)


def require(target: str, keys) -> dict:
    """The target's table, or a ValueError naming every missing key."""
    table = get(target)
    missing = [k for k in keys if not table.get(k)]
    if missing:
        hint = f"detour {target} config set <key> <value>"
        raise ValueError(f"{target}: missing {', '.join(missing)} (use: {hint})")
    return table


def quote(value: str) -> str:
    """A TOML basic string. JSON escaping is valid TOML for these values."""
    return json.dumps(str(value))


def write_private(p: Path, text: str) -> None:
    """Create or replace p with mode 0600 through a temp file, then rename."""
    tmp = p.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp, p)


def save(data: dict) -> None:
    """Write the known targets as flat TOML tables of strings."""
    lines = []
    for target in TARGETS:
        if data.get(target):
            lines.append(f"[{target}]")
            lines += [f"{k} = {quote(v)}" for k, v in data[target].items()]
            lines.append("")
    path().parent.mkdir(parents=True, exist_ok=True)
    write_private(path(), "\n".join(lines))
