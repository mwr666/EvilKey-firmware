# EvilKey firmware 0.3.0

Arduino firmware for the Waveshare ESP32-S3-Touch-AMOLED-1.64 PCB V1. It contains FIDO2, LVGL, the 3D logo, Manager Drive, USB Tool, and microSD integration. The display renderer attempts two 64-row RGB565 buffers in internal DMA memory; the LVGL object pool is allocated in PSRAM. If the second buffer does not fit, the renderer falls back to one 64-, 48-, 32-, or 16-row buffer.

The final Settings pages are **Diagnostics → Air Mouse → USB & Storage → USB Tool**. Diagnostics reports the real draw buffer allocation and memory status when enabled. Air Mouse uses a separate mouse-only USB role and its own pointer settings screen. See [Air Mouse](../docs/AIR_MOUSE.md).

Use `prepare_arduino.py`, `build_arduino.py`, and `flash_arduino.py` as described in [installation information](INSTALLATION_INFORMATION.md). Flashing asks for a COM port and `Y/N` confirmation and uses `EraseFlash=none`. See [firmware validation](VALIDATION.md).

Recipients of a device can use the [installation information](INSTALLATION_INFORMATION.md) to compile and install a modified firmware build. The device GUI is part of this AGPLv3 firmware source package.

Key paths: `EvilKeyV1/FidoConfig.h` for source defaults; `EvilKeyV1/src/` for generated application sources; `templates/` for the source of regenerated engine changes; `tools/` for preparation and checks; `tests/` for host tests. Changes to generated `src/engine/board` files must also be made in `templates/port` or they will be lost during regeneration.

In USB Tool STORAGE mode, an idle read-only session can return to HID after payload completion and 10 seconds without data operations. After a host write, firmware waits for `SYNCHRONIZE CACHE` following the last `WRITE10` or a host eject before detaching. See the relevant implementation checks in `tools/`.
