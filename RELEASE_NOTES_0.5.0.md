# EvilKey firmware 0.5.0

Firmware 0.5.0 expands the standalone Apps interface so new capabilities can
arrive as independent `.ekapp` packages copied to microSD. The firmware source
and its MIT licensed SDK contain no separately licensed application code or
application package.

- ABI v4 adds two simultaneous touch contacts, accelerometer readings,
  validated RGB565 assets, cropped blits and bounded `<id>.save` sidecars.
- Apps and Wasm3 use PSRAM for large allocations, leaving internal memory for
  USB and microSD operations. Save I/O runs after each guest step.
- The app-only upload helper checks the device's partition table and uses
  `EraseFlash=none`; it does not erase NVS.

**Hardware:** Waveshare ESP32-S3 Touch AMOLED 1.64, PCB V1.

**Binary:** `EvilKey_0.5.0.bin` (1,910,240 bytes)

**SHA-256:** `cfce4b1292225169aa74b75a3f48ae8eb2c8d71b7d0b9e4832defa00dfc7f286`

The exact binary was flashed at `0x10000` on COM5 after matching the existing
partition table. Esptool verified the write. After reboot, the owner confirmed
USB/FIDO, existing credentials, two independent ABI v4 apps and their
save/continue flows. This smoke test does not cover endurance, interrupted
save writes or concurrent CTAP response under sustained app load.

See [installation information](firmware/INSTALLATION_INFORMATION.md),
[ABI v4](apps/ABI_V4.md) and [validation](firmware/VALIDATION.md).
