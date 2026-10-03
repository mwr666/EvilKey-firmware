# Installing modified firmware

These instructions cover the Waveshare ESP32-S3 Touch AMOLED 1.64 **PCB V1**.

1. Extract the complete firmware source package. Install Python, Git,
   Arduino CLI, Arduino-ESP32 **3.3.12** and the configured PCB V1 board.
2. Change `firmware/EvilKeyV1/FidoConfig.h` or the relevant sources.
   Changes to generated board code must also be made in `firmware/templates/port/`.
3. If the engine is missing or templates changed, run `firmware/prepare.cmd`.
   Open **EvilKey.cmd → 7** to build. Follow any required USB-hook instructions.
4. Connect USB. Hold BOOT, press/release RESET, then release BOOT.
   Choose **11**, select the COM port and confirm **Y**.
5. Wait for application readback and protected-storage verification.
   Press RESET without BOOT and test FIDO and the changed functionality.

The builder prepares pinned BLE dependencies and verifies linked erase guards.
Source pins are in `UPSTREAM_LOCK.json` and `BLE_LOCK.json`; upstream licenses
are in `EvilKeyV1/data/upstream-licenses/`. The uploader prepares esptool locally
and uses `EraseFlash=none`. Direct IDE upload omits the preservation checks.

## Partition handling

| Partition | Offset | Size | Operation |
| --- | --- | --- | --- |
| nvs | `0x9000` | `0x5000` | Preserve and compare digests |
| otadata | `0xE000` | `0x2000` | Preserve and compare digests |
| part0 | `0x200000` | `0x100000` | Preserve and compare digests |
| wsdev | `0x400000` | `0x10000` | Preserve and compare digests |
| factory | `0x500000` | `0x400000` | Write and verify application |

Only reviewed old/new layouts are accepted. When migrating the older layout,
the new app is verified first, then the table at `0x8000` is updated. Existing
data offsets and the old app at `0x10000` stay intact. Subsequent uploads on
the new layout need no table change. Full-flash and protected NVS erases are
forbidden by this process.

Receipts in `.flash-backups/` retain tables and digests. Protected data is
compared using device-side MD5; raw credential bytes are not transferred.
Local SHA-256 binds the build artifacts; it is an integrity check, not a signature.

## Rollback after migration

Enter BOOT/RESET download mode and restore only that device receipt's
`partition-before.bin` to `0x8000`; verify its 3072-byte readback before RESET.
The preserved old application then boots at `0x10000`. Do not move an old app
to `0x500000`, change data offsets or erase NVS. This rollback applies to the
reviewed migration, not an arbitrary partition layout.

## AGPL installation information

If retail devices enable secure boot, flash encryption, signed updates or other
installation restrictions, supply the materials necessary to install and run
modified firmware as required by AGPLv3 section 6, and verify them on that
hardware. These instructions make no claim about such a retail configuration.
