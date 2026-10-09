# Getting started

EvilKey 0.7.5 is verified on the Waveshare **ESP32-S3 Touch AMOLED 1.64
PCB V1.0**, with 16 MiB flash, 8 MiB PSRAM and a 280×456 display.
PCB V1.1 compatibility has not yet been established.

## 1. Firmware and Windows tools

Get the [0.7.5 release](https://github.com/mwr666/EvilKey-firmware/releases/tag/v0.7.5).
It provides the accepted BIN, firmware source ZIP and checksums.
Use [Build and flash](BUILD_AND_FLASH.md) for prerequisites and the guarded
`EvilKey.cmd` installation workflow. Compare artifact identities with
[RELEASE_CURRENT.json](../RELEASE_CURRENT.json). A rebuilt image needs its own
acceptance even if its version label matches.

The [Windows Manager](https://github.com/mwr666/EvilKey-Manager/blob/main/manager/README.md) is supplied separately from
firmware source and connects in the normal FIDO USB role.

## 2. Optional microSD

Use a FAT32 card. Copy compatible `<id>.ekapp` packages into
`/evilkey/apps/`; no installer is needed. A `.save` beside each package stores
that app's progress. Keep saves when updating packages.
[Apps](../apps/README.md) explains compatibility and exit controls.

A card is needed for microSD apps, Manager Drive and USB Tool files/results.
[Original examples](https://github.com/mwr666/EvilKey-examples/blob/main/microSD_EVILKEY_EXAMPLES/README.md) are a separate
package. Power down before removing the card and finish/eject host storage
operations before changing its USB mode.

## 3. Navigation

| From Home | Destination |
| --- | --- |
| Swipe right | Screensaver |
| Swipe left | Apps; Settings directly if no compatible apps are present |
| Swipe left again from Apps | Settings |
| Swipe up/down in Apps or Settings | Change pages |

To leave an app, drag the top-left system grip right until progress is full,
release, then choose **YES**. **NO** resumes the app. This applies to ABI4
and ABI5; app-specific saves remain the app's responsibility.

## 4. Choose a function

- **FIDO2:** connect in the normal role. The client chooses host ClientPIN or
  compatible [on-device verification](ON_DEVICE_PIN.md).
- **Gamepad / AirMouse:** select the module in Settings. BLE starts only on
  entering a BLE module; exit returns to FIDO with BLE off.
  See [Gamepad](BLE_CONTROLS.md) and [AirMouse](AIR_MOUSE.md).
- **Manager Drive:** enable [USB storage](MANAGER_DRIVE.md) to access the card.
- **USB Tool:** select a script and press **RUN** on the device.
  Read [USB Tool](USB_TOOL.md) before executing a payload.

USB modes are exclusive; changing them may reconnect the USB device.
The tested panel supports one touch contact. IMU steering and one-finger drag
provide movement while a touch button is in use.

[All guides](README.md) · [Verification limits](VALIDATION.md)
