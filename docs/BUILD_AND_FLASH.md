# Build, test and flash

Open **EvilKey.cmd** in this repository on Windows:

| Option | Action |
| --- | --- |
| 6 | Run firmware storage, PCB, installer and packaging software checks without USB |
| 7 | Select PCB V1 or V1.1 and build its BIN |
| 8 | Package public source and both verified PCB image sets |
| 11 | Select PCB, build and flash after choosing and confirming the COM port |
| Q | Exit |

Requirements: Python 3, Git, Arduino CLI and pinned Arduino-ESP32 **3.3.12**
with the Waveshare ESP32-S3 Touch AMOLED 1.64 board package. Select the PCB
silkscreen revision: **V1** at the top, **V1.1** near the right-hand headers.
The programming COM port does not identify the PCB. Confirmed V1.1 firmware
compatibility begins with 0.8.0; the printable V1 enclosure has its own scope.

If generated source is missing, run firmware/prepare.cmd once. For changed PCB
templates in an existing engine, run python firmware/tools/sync_board_profiles.py.
BLE dependencies and the required USB hook are checked by the builder. Option **6**
prepares pinned BLE dependencies; its first run needs network access. Downloads
are checked against firmware/BLE_LOCK.json. Tests use mocks and do not open USB.

For installation, hold BOOT, press/release RESET and release BOOT. Choose **11**,
select the matching PCB and COM port, and confirm **Y**. Normal EvilKey updates
use EraseFlash=none, verify linked storage guards and compare protected digests
before/after writes. A reviewed older layout installs the app at 0x500000 before
updating the table, retaining credential/storage offsets.

A factory or blank module instead offers fresh initialization with exact
**ERASE** confirmation: erase all internal flash, install the matching
bootloader/table/application, and verify them. Credentials and internal data
are discarded; microSD is unchanged. Empty input, N or Y cancels this flow.
If existing internal data matters, cancel unsupported-layout initialization.
After verification, press RESET without BOOT and check the functions you use.

Outputs: firmware/build-arduino/v1/EvilKeyV1.ino.bin and
firmware/build-arduino/v1.1/EvilKeyV1.ino.bin, with separate build manifests.
Command line:

    python firmware/build_arduino.py --board-revision v1.1
    python firmware/flash_arduino.py --board-revision v1.1 --port COM6

A rebuild is a new artifact; release hashes apply only to the exact published files.

Option **8** operates on a Git checkout with intended source staged and no unstaged
changes. It requires both complete accepted sets listed in RELEASE_CURRENT.json
under artifacts/firmware and verifies BIN/ELF/table/bootloader/build records and
sidecars. The public source ZIP includes these files. Extracted source can build
and flash without Git; repackaging with option8 requires a Git checkout.
Outputs are ignored under release/. Private receipts/NVS data and game
code/packages are excluded.

Read [installation and rollback](../firmware/INSTALLATION_INFORMATION.md) and
[validation](VALIDATION.md).
