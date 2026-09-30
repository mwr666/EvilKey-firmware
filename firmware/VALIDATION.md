# Firmware validation

## 0.5.0 ABI v4 source candidate

The standalone public-source application image is 1,910,240 bytes (SHA-256
`cfce4b1292225169aa74b75a3f48ae8eb2c8d71b7d0b9e4832defa00dfc7f286`).
Arduino-ESP32 3.3.12 compiled it with `EraseFlash=none`; the unchanged
0x1F0000-byte factory partition has 121,376 bytes free. The corrected Apps
mailbox, Wasm3 allocations and bytecode copy use PSRAM; missing save files are
probed before opening. Earlier synthetic ABI v4, shared exit-dialog, `.save`
rollback and nine app-only flasher tests passed. Those host checks have not
been rerun for this exact image. No separately licensed application package
was used or included. The exact public-source image at
`release/EvilKey_0.5.0.bin` was written to COM5 at `0x10000` after the device
partition table matched the build; esptool verified the written data hash.
After reboot, the owner confirmed USB/FIDO, existing credentials, two
independent ABI v4 apps and their save/continue flows. This is a device smoke
test, not endurance, interrupted-write or concurrent CTAP qualification.
Public release is separate from this validation.

## 0.4.0 Apps and ABI v3

The standalone public-source 0.4.0 build is 1,902,976 bytes (SHA-256
`4903b8c9b095caa86196c292c85afb00441742257b8ad9e8966eed663eaf7633`).
It passed Arduino-ESP32 3.3.12 compilation with `EraseFlash=none` and leaves
128,640 bytes in the unchanged factory partition. The package parser and VM
probes passed with host and Arduino settings, including malformed package,
forbidden import, output bounds, memory and execution-limit cases.

On 2026-09-30 the owner reported that new firmware and an ABI v3 app worked
correctly on physical hardware. On the same date, the public-source BIN
identified by the SHA-256 above was written to the ESP32-S3 on COM5 at
`0x10000` using esptool 5.3.1. Before the write, the device partition table
was read and matched the build's partition table. The write erased only
`0x10000` through `0x1E0FFF`, outside both NVS partitions; esptool verified
the written data hash. After reboot, the owner confirmed that the ABI v3 app
launched and worked, and that the existing credentials remained available.
Endurance and concurrent CTAP response require separate verification.

## Previous 0.3.0 release

The 1,800,736-byte image in this package has SHA-256
`504d21eaa4002263ebbd8d36026ef0481978b27da68e466c9ef079c99be38678`.
It passed source checks and an Arduino-ESP32 3.3.12 build. The image was
uploaded to COM5 with `EraseFlash=none`; the upload tool verified the write.
After restart, the user confirmed Air Mouse entry, cursor directions and
diagonals, SETTINGS with calibration, sensitivity and vertical inversion, and
return to FIDO. This is a device smoke test, not endurance testing.

The hash above is the historical 0.3.0 release reference. It does not identify
the 0.4.0 candidate image.
