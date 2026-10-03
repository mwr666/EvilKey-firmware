# EvilKey firmware 0.6.0

Arduino firmware for the Waveshare ESP32-S3 Touch AMOLED 1.64 **PCB V1**:
FIDO2, LVGL, Apps on microSD, BLE Gamepad, USB/BLE AirMouse, Manager Drive
and USB Tool.

Start with **[EvilKey.cmd](../EvilKey.cmd)**:
**7** builds the BIN, **11** builds and flashes with NVS preservation checks.
See [Build and flash](../docs/BUILD_AND_FLASH.md) and
[installation information](INSTALLATION_INFORMATION.md).

From Home: right for screensaver, left for Apps, then left for Settings.
With no compatible apps, left opens Settings directly. Gamepad appears above
AirMouse in Settings. Only BLE module entry enables the radio; exit returns
to FIDO. See [Gamepad](../docs/BLE_CONTROLS.md) and [AirMouse](../docs/AIR_MOUSE.md).

Apps use [ABI v4](../apps/ABI_V4.md), revision-5 packages with names/icons and
the [corner exit profile](../apps/sdk/UI_PROFILE.md). The SDK is MIT;
game sources and licenses are separate from firmware.

## Source layout

- `EvilKeyV1/FidoConfig.h`: source defaults.
- `EvilKeyV1/src/`: application and generated engine.
- `templates/port/`: maintained source for regenerated board/UI changes.
- `tools/` and `tests/`: preparation and checks.
- [References](docs/README.md): M1 protocol and pinned source provenance.

Edit generated board code in its template as well, then run `prepare.cmd`;
regeneration replaces generated files. Build and dependency manifests are
required inputs, not release histories.

The device GUI is part of this AGPLv3 firmware.
[Release checks](../docs/VALIDATION.md) describe the accepted image's scope.
