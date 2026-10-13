# EvilKey firmware 0.8.0

## Changes since 0.7.6

- Separate firmware profiles for Waveshare ESP32-S3 Touch AMOLED 1.64 PCB V1 and V1.1. Confirmed V1.1 compatibility begins with 0.8.0.
- PCB selection before building or choosing a COM port in EvilKey.cmd; V1.1 uses its revised pin map and shared display/touch reset sequence.
- Normal updates preserve credentials, settings and internal data. Factory or blank modules offer fresh initialization with exact ERASE confirmation and a new EvilKey partition table.
- Both PCB variants have their own BIN, ELF, bootloader, table, build record and SHA256 sidecars. Mismatched, missing or corrupted release inputs are rejected.
- Gamepad steering requires BLE CONNECTED before calibration and tilt input. USB/BLE AirMouse, Settings and Apps use the common IMU path.
- ABI v4/v5, package revision 5, SIMD rendering, SD models, clocks, rendering budgets and storage offsets remain. Manager stays at 1.1.6.

## Download and install

Use the BIN labelled for your PCB; read the revision from its silkscreen. The
public source ZIP contains both complete image sets, firmware, the MIT SDK and
licenses. Extract the complete archive and open **EvilKey.cmd**: **7** builds,
**11** builds and installs, **6** runs software checks and **8** packages source
with the verified release images.

For installation, select the PCB, enter BOOT mode and select the COM port.
Normal updates require Y and verify application/table readback and protected
storage. A fresh module additionally requires ERASE, erases all internal flash
including credentials/settings, and installs bootloader/table/application.
Empty input, N or Y cancels fresh initialization. microSD files are retained.
Press RESET without BOOT when verification finishes.

Both original release images passed functional checks and preserving
application/table readback on their matching PCBs. This does not establish
long-duration endurance, V1.1 enclosure fit, console/XInput compatibility or
FIDO certification. Historical PCB V1 videos and the 0.7.4 host UI tour retain
their original labels.

Arduino-ESP32 3.3.12, Os, application offset 0x500000; 16 MiB flash/8 MiB OPI
PSRAM. Use RELEASE_CURRENT.json and SHA256SUMS.txt to verify each download.
A rebuilt image is a separate artifact requiring its own validation.

Firmware and GUI remain AGPLv3 with upstream notices; the app SDK is MIT.
Manager, USB Tool examples and games retain their separate licenses.

[Getting started](GETTING_STARTED.md) · [Build and flash](BUILD_AND_FLASH.md)
· [Validation scope](VALIDATION.md).
