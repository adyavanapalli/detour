#!/usr/bin/env bash
# Install detour for the current user. Read it before you pipe it into bash.
set -euo pipefail

REPO="https://github.com/adyavanapalli/detour"
VENV="$HOME/.local/share/detour/venv"
BIN="$HOME/.local/bin"

[ "$(id -u)" -ne 0 ] || { echo "run this as your user, not as root"; exit 1; }

for tool in git uv /usr/bin/python3; do
  command -v "$tool" >/dev/null || { echo "missing: $tool"; exit 1; }
done
if ! /usr/bin/python3 -c 'import gi' 2>/dev/null; then
  echo "note: python3-gi and gir1.2-ayatanaappindicator3-0.1 are not installed;"
  echo "      detour works, but the top-bar indicator will be skipped"
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
git clone --quiet --depth 1 "$REPO" "$work/detour"

uv venv --quiet --clear --system-site-packages --python /usr/bin/python3 "$VENV"
uv pip install --quiet --python "$VENV/bin/python" "$work/detour[android]"
mkdir -p "$BIN"
ln -sf "$VENV/bin/detour" "$BIN/detour"

echo "installed $("$VENV/bin/detour" --help | head -n 1 | sed 's/usage: //')"
case ":$PATH:" in *":$BIN:"*) ;; *) echo "note: add $BIN to your PATH" ;; esac
echo "next: detour linux config set rules_url <url>   (see README)"
