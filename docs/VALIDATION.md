# Release checks

Firmware **0.6.0** was flashed through `EvilKey.cmd` and accepted by the owner
on the PCB V1 device. The confirmation covers Gamepad appearance/controls,
Center and settings feedback, Rotate 180, AirMouse, return to USB/FIDO with
existing keys, and games/save-resume. The BIN identity is recorded once in
[RELEASE_CURRENT.json](../RELEASE_CURRENT.json).

Application readback passed. Before/after device digests matched for `nvs`,
`otadata`, `part0` and `wsdev`; protected credential bytes were not copied to
the host. The final installation required no partition migration.

Software checks cover native control logic, storage guards and migration,
production LVGL rendering in both Gamepad orientations, USB/BLE AirMouse,
launcher/PIN regressions, firmware version and linked build safety checks.
Windows measurements established both BLE HID Gamepad profiles and mouse
input; final touch/style changes additionally passed owner device tests.
Android handset, console/XInput compatibility and long-duration endurance
have not been established.

## Before a new release

1. Run **EvilKey.cmd → 6** and checks relevant to the changed firmware module.
2. Build with **7**; flash with **11** and check protected-storage verification.
3. Test the changed controls, FIDO return and app saves on the device.
4. Bind the accepted BIN hash in `RELEASE_CURRENT.json`, then package with **8**.

Local build/flash receipts remain in ignored working directories. They are
not user documentation or release payloads.
