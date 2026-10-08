# Build, test and flash

Open **EvilKey.cmd** in this repository on Windows. It is the firmware entry point:

| Option | Action |
| --- | --- |
| 6 | Run firmware storage/uploader software checks without USB |
| 7 | Build firmware BIN |
| 8 | Package this public source and the accepted BIN |
| 11 | Build and flash after choosing and confirming the COM port |
| Q | Exit |

Requirements: Python 3, Git, Arduino CLI, pinned Arduino-ESP32 **3.3.12** and the Waveshare ESP32-S3 Touch AMOLED 1.64 **PCB V1** board package. If generated sources are missing, run `firmware/prepare.cmd` once. BLE dependencies and the required USB hook are checked by the builder.

Option **6** prepares the pinned BLE dependencies locally before running the
storage checks. Its first run needs network access; downloaded archives are
checked against `firmware/BLE_LOCK.json`. The checks use mocks and do not open USB.

For flashing, hold BOOT, press/release RESET and release BOOT. Choose **11** and follow its COM selection and **Y** confirmation. The uploader uses `EraseFlash=none`, checks the linked storage guards and compares protected partition digests before/after upload. It accepts reviewed layouts; when migrating from an older layout, it writes the app at `0x500000` before the partition table while preserving credential/storage offsets. Do not use a full-flash erase on a device holding credentials.

Output: `firmware/build-arduino/EvilKeyV1.ino.bin`. A rebuild is a new artifact; the accepted release hash applies only to the exact published BIN. Read [installation and rollback](../firmware/INSTALLATION_INFORMATION.md) and [validation](VALIDATION.md).

Option **8** operates on a Git checkout with all intended source changes staged
and no unstaged changes. It requires the accepted
`artifacts/firmware/EvilKey_0.7.4.bin` and verifies its SHA-256. Outputs are in
ignored `release/`; game code/packages, flash receipts and NVS data are excluded.
Source checkouts can build/flash without a release BIN. The published source ZIP
already contains the accepted BIN and can be used for building; copy that BIN
into a Git checkout if you want to create another source package with option 8.
