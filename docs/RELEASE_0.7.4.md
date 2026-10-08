# EvilKey firmware 0.7.4

Native Jet rendering gives the screensaver and Apps/Settings icons real depth
while keeping the original icon designs, mint accent and LVGL touch controls.
Apps and Settings share orbit timing and composition; status icons stay steady.
Geometry caching, rasterizer improvements and double-buffered panel transfers
reduce the rendering cost. The accepted release uses Os optimization.

ABI v5 adds bounded native Scene3D rendering for independent microSD apps.
ABI v4 packages remain supported. Both use package revision 5 and the shared
corner-exit-v1 profile. App Scene3D is separate from the Jet GUI renderer.
Existing FIDO/PIN, launcher, saves, USB Tool, AirMouse and BLE controls remain.

## Accepted image and checks

The owner accepted the exact release on Waveshare PCB V1.0 on 2026-10-08.
Installation through EvilKey.cmd verified application readback and unchanged
nvs, wsdev, part0 and otadata digests. No partition migration was required.

- BIN: `EvilKey_0.7.4.bin`; 2,265,808 bytes.
- SHA-256: `7244d58bfd38c12cd81f7dcb865428227985e2cf5e3c3c7eafce4d801754db19`.
- Arduino-ESP32 3.3.12; Os; application capacity 4 MiB at `0x500000`.

Release host checks covered Jet bounds/depth, LVGL navigation, PIN and module
integration, Apps/Settings ring parity, ABI4 apps and saves, ABI5 validation/
clipping/timeouts, display transport and storage guards. These are software
checks; they do not qualify the timing or sustained play of every native 3D app.
V1.1 compatibility and long-duration endurance are not established.

Use [Build and flash](BUILD_AND_FLASH.md) and
[installation information](../firmware/INSTALLATION_INFORMATION.md).
A rebuilt image is a new artifact, even when its version label matches.
The source ZIP includes public firmware, canonical templates, generated sketch,
Jet notices and the ABI4/ABI5 MIT SDK, plus the exact accepted BIN.

## Development and licensing

This remains development firmware: credentials are stored in unencrypted NVS;
Secure Boot and encrypted flash/NVS provisioning are not enabled. The app API
boundary is not demonstrated hardware isolation. No FIDO certification is claimed.

Firmware/GUI are AGPLv3 with upstream notices; ABI/SDK are MIT. Manager stays
1.1.6 and is distributed separately, as are USB Tool examples and independently
licensed apps. No game packages or CAD are included in this release.

[Validation](VALIDATION.md) · [Graphics](GRAPHICS_AND_UI.md) ·
[ABI v5](../apps/ABI_V5.md) · [Artifact identity](../RELEASE_CURRENT.json)
