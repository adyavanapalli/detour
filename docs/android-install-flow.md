# Android Install Flow

This document describes the steps for `detour android install`.

## 1. Configuration and Identity Verification

1. Read the `[android]` section from `~/.config/detour/config.toml`.
2. Verify that all required connection keys exist:
   - `rules_url`
   - `server_endpoint`
   - `server_public_key`
   - `tunnel_dns`
   - `device_address`
3. If any required key is missing, raise an error immediately.
4. If `device_private_key` is missing, generate a new WireGuard key and display the server peer block.
5. If `api_secret` is missing, generate a 24-byte secret for the dashboard.
6. Save any generated values back to `config.toml`.
7. Render the Android JSON template with these values.
8. Parse the rendered output with Python to verify JSON syntax.
   The local machine does not check for a local `sing-box` binary.

## 2. Display and Lock Preparation

1. Read and record the current value of `screen_off_timeout`.
2. Set `screen_off_timeout` to `900000` (15 minutes) through ADB.
3. Wake the display with `input keyevent 224`.
4. Check if the device is locked using `dumpsys window` and `dumpsys trust`.
5. If the device is locked, prompt the user to unlock the phone and wait until unlock completes.
6. Register a cleanup action to restore the original `screen_off_timeout` when the command exits.

## 3. Application Provisioning

1. Check if SFA (`io.nekohasekai.sfa`) is installed on the phone.
2. If SFA is already installed, skip downloading and installing the APK.
3. If SFA is missing, check `~/Downloads` for a matching `SFA-<version>-<abi>.apk` file.
4. If a matching APK exists in `~/Downloads`, install that file.
5. If no APK exists locally, query GitHub releases for the latest version and download the APK.
6. Install the APK through ADB.

## 4. Headless Permissions and System Settings

Execute these settings over ADB before opening the application:

1. Grant `POST_NOTIFICATIONS` permission so Android never prompts for notifications.
2. Set `ACTIVATE_VPN` app-op to `allow` to suppress the system VPN consent dialog.
3. Set `REQUEST_INSTALL_PACKAGES` app-op to `allow` so SFA can update itself.
4. Grant `ACCESS_LOCAL_NETWORK` permission and app-op to allow TCP flows.
5. Set `private_dns_mode` to `off` to prevent DNS leaks outside the tunnel.
6. Add SFA to the battery allowlist with `dumpsys deviceidle whitelist +io.nekohasekai.sfa`.

## 5. User Interface Automation and Profile Import

1. Launch SFA. On a fresh installation, wait for the "Check Update" dialog and tap "OK".
2. If the VPN service is currently running, tap "Stop" and wait until `tun0` disappears.
3. If existing profiles exist, tap "Expand" and delete each profile to guarantee a clean slate.
4. Push the rendered profile JSON to SFA storage and trigger the VIEW intent.
5. Tap "Import", wait for SFA to validate and save the profile.
6. Open Settings and navigate to App settings.
7. Execute a quick 50-millisecond flick using shell input to reveal update toggles.
8. Turn on "Automatically download and install updates in background" first.
9. Turn on "Install updates without interaction" second.
10. Return to the dashboard using intent navigation (`am start -S`).

## 6. Service Start and Pre-Lockdown Verification

1. Tap the "Start" button on the dashboard.
2. Wait until the `tun0` network interface appears.
3. Verify DNS interception: confirm that `use-application-dns.net` answers NXDOMAIN.
4. Verify tunnel routing: confirm that `api.ipify.org` exits through the WireGuard server IP.
5. Verify direct routing: confirm that unlisted traffic exits through your direct network IP.
6. If the tunnel fails to route traffic, stop immediately. Do not apply lockdown settings.

## 7. Lockdown Configuration and Reboot

1. If the tunnel is proven, set `always_on_vpn_app` to `io.nekohasekai.sfa`.
2. Set `always_on_vpn_lockdown` to `1`.
3. Verify that both settings persist in secure settings.
4. Prompt the user to reboot the phone.
5. If confirmed, issue `svc power reboot` through ADB.
6. Wait for the phone to boot and prompt the user to unlock the display.
7. Wait until `tun0` appears and the tunnel answers.
8. Print the final status report showing `on` with `fail_closed` active.
