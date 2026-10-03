# Changelog

## 0.6.0 — BLE controls

- Added landscape BLE Gamepad with PC/Xbox and Generic/Android HID profiles,
  calibrated IMU steering, touch buttons, dead zone and Rotate 180.
- Added BLE transport to AirMouse; MOVE remains hold-to-move and DRAG toggles
  one-finger dragging. Gamepad and AirMouse share their visual style.
- BLE starts only inside BLE modules; exit returns to FIDO with radio off.
- Separated BLE bonds/preferences from credentials and guarded NVS recovery.
- Increased application capacity to 4 MiB with verified partition migration
  preserving credential/storage offsets and protected partition digests.

## 0.5.1 — Apps launcher

- Animated Apps introduction, paged 3×3 icons and cached microSD catalog.
- Revision-5 packages with names/icons; runtime ABI v4 unchanged.
- Firmware-owned corner exit grip, visible progress and YES/NO confirmation.
- Shared firmware version source for the screensaver and build metadata.

## 0.5.0 — ABI v4

- Touch coordinates, accelerometer data, RGB565 assets and per-app `.save` files.
- Apps runtime buffers moved to PSRAM to retain internal RAM for USB/SD.

## Earlier releases

- 0.4.0: microSD Wasm apps and navigation with charger-only USB power.
- 0.3.0: USB AirMouse with calibrated tilt and touch controls.

Detailed implementation history is retained in Git.
