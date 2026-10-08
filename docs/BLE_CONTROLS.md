# Gamepad and BLE

## Gamepad

Open **Settings → Gamepad**, select **PC/Xbox** or **Generic/Android**, then
Start. Pair the advertised device on the host; the status changes to
**BLE connected**. These profiles are BLE HID controllers; the PC/Xbox name
does not imply native XInput or console compatibility.

The landscape screen uses IMU steering and momentary touch buttons:

- A/B/X/Y form a central cross with a tilt indicator inside.
- Left: LB above LT; right: RT above RB.
- Lower left: Start and Center. Lower right: Select, Settings and Exit.
- Hold still at entry to establish neutral; Center or the tilt indicator
  recalibrates after finger release.
- Settings offers analog axes or eight-way D-pad, 5–35% dead zone,
  Rotate 180, pairing and confirmed Forget Pairing.
- Center and settings controls highlight on contact and activate on release.
  Hold Exit for the on-screen countdown and confirm YES/NO.

The tested panel reports a single contact. IMU supplies direction while one
touch button is held; simultaneous touch buttons and button combinations are
not provided. Gamepad and [AirMouse](AIR_MOUSE.md) share the selected accent,
dark cards and rounded controls.

## Radio lifecycle

BLE initializes only when starting Gamepad or BLE AirMouse. Selecting BLE as
a preference does not enable the radio. Home, Apps/games, Settings, screensaver,
USB Tool, USB storage and USB AirMouse keep BLE off. Modes are exclusive and
use a consumed one-shot RTC request; restart, exit or startup failure returns
to normal FIDO. USB supplies power in BLE modes and returns to FIDO on exit.

## Pairing and storage

Mouse, PC/Xbox and Generic have distinct identities and bond stores in `wsdev`:
`ek_ble_mouse`, `ek_ble_xbox`, `ek_ble_generic`. Controls use `ws_controls`;
pointer preferences use `ws_airmouse`. Forget Pairing deletes only the selected
BLE profile's bonds. If necessary, also remove that profile from the host.

BLE never opens FIDO credential storage. Automatic NVS erase recovery is
disabled; linked guards reject whole protected-partition erases while allowing
normal writes and NVS page garbage collection. Initialization errors return
failure instead of formatting storage.

## Installation

Use **EvilKey.cmd → 7** to build or **11** to build and flash with protected
storage verification. Firmware 0.7.4 uses a 4 MiB factory app at `0x500000`.
The uploader preserves `nvs`, `otadata`, `part0` and `wsdev` at their existing
offsets. No full-flash erase or eFuse provisioning is involved.
See [installation and rollback](../firmware/INSTALLATION_INFORMATION.md) and
[release checks](VALIDATION.md).
