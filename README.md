<div align="center">
  <img src="assets/logo.png" alt="detour logo" width="160">
  <h1>detour</h1>
  <p><em>Domain-based split tunneling with sing-box over WireGuard.</em></p>
</div>

Listed domains take a detour through the tunnel. Everything else goes straight through.

## How it works

- sing-box answers all DNS on the device. A listed domain gets a FakeIP. An unlisted domain gets its real address from the local network's resolver.
- A connection to a FakeIP carries its domain name. sing-box resolves the real address inside the tunnel and sends the connection through WireGuard.
- Every other connection goes directly to the internet.
- If sing-box is not running, the device is closed. On Linux, DNS does not work at all, so listed domains cannot resolve. On Android, always-on VPN with lockdown blocks every connection.

## Requirements

- Ubuntu with systemd-resolved. Other systemd distributions are untested.
- Python 3.11 or newer, and uv.
- For the top-bar indicator: GNOME with the Ubuntu AppIndicator extension, plus the packages `python3-gi` and `gir1.2-ayatanaappindicator3-0.1`.
- For a phone: Android 12 or newer with USB debugging on, and `adb` on this machine, on PATH or under `ANDROID_HOME`. If `sing-box` is installed here too, the profile is checked before it goes to the phone.

## Install detour

    curl -fsSL https://raw.githubusercontent.com/adyavanapalli/detour/main/install.sh | bash

The script installs into `~/.local/share/detour/venv` on the system Python, so the indicator can use the OS GTK bindings, and links `~/.local/bin/detour`. Read `install.sh` before you run it; it is short.

## Commands

    detour <target> config get [KEY]       show every key, or one value
    detour <target> config set KEY VALUE
    detour <target> config import [PATH]   read a wg-quick conf; stdin when PATH is omitted
    detour <target> install
    detour <target> status
    detour <target> uninstall [--purge]

`<target>` is `linux` for this machine, or `android` for a phone over ADB.

## Set up a Linux machine

1. Set the values that every device needs:

        detour linux config set rules_url <url of the rule list>
        detour linux config set server_endpoint <host:port>
        detour linux config set server_public_key <server public key>
        detour linux config set tunnel_dns <resolver inside the tunnel>
        detour linux config set device_address <this device's tunnel address, with prefix>

   If the machine already has a wg-quick conf: `sudo cat /etc/wireguard/wg0.conf | detour linux config import`.

2. Run `detour linux install`. It generates a device key if there is none, prints the `[Peer]` block, and asks for your password before each root step.
3. Add the `[Peer]` block on the WireGuard server.
4. Run `detour linux status`. The first line is the verdict.

## Set up an Android phone

The phone runs sing-box for Android (SFA). detour talks to it over ADB and never needs root.

1. Connect the phone with USB debugging on. `adb devices` must list it. If several devices are attached, set `ANDROID_SERIAL`.
2. Set the same keys under the `android` target, or import a wg-quick conf: `detour android config import phone.conf`.
3. Unlock the phone and keep it unlocked. Then run `detour android install`.
4. If the device key is new, add the `[Peer]` block on the WireGuard server.
5. Run `detour android status`.

`detour android install` does these things, and prints each adb command as it runs:

- Installs SFA from the latest sing-box release if the phone does not have it.
- Renders the profile and hands it to SFA as a file. SFA asks "Import profile detour?" and the tool answers. It also answers SFA's one-time "Check Update" prompt with OK, and deletes older profiles with the same name.
- Grants what SFA would otherwise ask for: notifications, the VPN consent, local network access (Android 16 and later), and installs from SFA for its own updates. No prompt appears.
- Turns Private DNS off, so DNS over TLS cannot leave the split. Exempts SFA from battery limits.
- Turns on Silent Install and Auto Update on SFA's App settings page.
- Starts the service through SFA's Start button, then proves the tunnel: a listed domain must exit somewhere else than an unlisted one. If it does not, the tool stops there and nothing is locked down.
- If always-on VPN with lockdown is not in effect yet, saves both settings and offers a reboot. Android applies them at boot. Unlock the phone after the reboot. The VPN starts after the unlock.

The order matters: the phone is never locked down before the tunnel is proven to work. If the phone drops off USB for a moment, the tool waits for it and retries once.

## Config keys

| Key | Meaning |
|---|---|
| `rules_url` | URL of the rule list |
| `server_endpoint` | WireGuard server, `host:port` |
| `server_public_key` | WireGuard server public key |
| `tunnel_dns` | resolver inside the tunnel, used only for listed domains |
| `device_address` | this device's tunnel address, with prefix |
| `device_private_key` | generated by install if unset; masked by `config get` |
| `api_secret` | dashboard API secret; generated by install; masked |

Settings live in `~/.config/detour/config.toml`, mode 0600, one table per target.

## The rule list

`rules_url` points at a file that every device downloads and re-checks every 5 minutes. The file is a sing-box rule-set in source format, version 5. Comments and trailing commas are allowed, so the list can be grouped and annotated:

    {
      "version": 5,
      "rules": [
        {
          "domain_suffix": [
            // health check, used by status and the indicator
            "icanhazip.com",

            "example.com",
            "example.net", // a note on one entry
            "example.org",
          ]
        }
      ]
    }

Matching is by suffix: `example.org` also matches `www.example.org`. Keep `icanhazip.com` in the list: `status` and the indicator use it to check the tunnel.

## Status

`detour <target> status` prints one of:

- `on`: the service runs, DNS goes through sing-box, and a listed domain exits at the VPN address.
- `warn`: the service runs but something is degraded. The reason follows.
- `leak`: a listed domain exits at the same address as an unlisted one.
- `off`: the service is not running.

The exit code is 0 only for `on`. The top-bar indicator shows the same verdict as a green, amber, or red cube, and writes it to `~/.cache/detour/status`.

Both targets also report `fail_closed`: whether the system blocks traffic when the service is down. On Linux that is the resolver drop-in. On Android it is always-on VPN with lockdown, in effect and saved. A phone's checks run on the phone through adb. The DNS facts come from `ping`. The two exit addresses come over plain HTTP on port 80, because the shell has no TLS client.

## Dashboard

sing-box serves its official dashboard at http://127.0.0.1:9090/dashboard/, on this machine only. The secret is `detour linux config get api_secret`.

For a phone, `detour android install` forwards port 9091 to the phone, so its dashboard is at http://127.0.0.1:9091/dashboard/. The forward lasts until the adb server restarts. `adb forward tcp:9091 tcp:9090` brings it back.

## Uninstall

`detour linux uninstall` stops the service and restores the system resolver. Add `--purge` to remove the package, its config, and its state.

`detour android uninstall` clears the always-on settings, restores Private DNS, and removes the battery exemption. SFA and its profile stay. Lockdown stays in effect until the phone reboots, and the tool offers the reboot. Add `--purge` to remove SFA with its profiles. Android drops always-on with the package.

## Development

    PYTHONPATH=src python3 -m unittest discover -s tests

After a push, GitHub serves the raw `install.sh` up to 5 minutes late. Run the local copy when you test a change to it.
