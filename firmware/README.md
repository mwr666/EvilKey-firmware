# EvilKey firmware 0.5.0 (ABI v4 source candidate)

Arduino firmware for the Waveshare ESP32-S3-Touch-AMOLED-1.64 PCB V1. It contains FIDO2, LVGL, the 3D logo, Manager Drive, USB Tool, and EvilKey Apps loaded from microSD. The display renderer attempts two 64-row RGB565 buffers in internal DMA memory; the LVGL object pool is allocated in PSRAM. If the second buffer does not fit, the renderer falls back to one 64-, 48-, 32-, or 16-row buffer.

Settings includes **Apps**, Diagnostics, Air Mouse, USB & Storage, and USB Tool. Apps, Settings, and the screensaver remain available when USB provides power without a host. Diagnostics reports the real draw buffer allocation and memory status when enabled. Air Mouse uses a separate mouse-only USB role and its own pointer settings screen. See [Air Mouse](../docs/AIR_MOUSE.md).

Apps ABI v4 accepts one `.ekapp` per app on microSD, exposes two touch
contacts, accelerometer samples and cropped RGB565 assets, and saves bounded
app state beside the package as `<id>.save`. Firmware owns the display and
microSD access; an app cannot access NVS or FIDO credentials. Older app ABI
packages are rejected. The [ABI specification](../apps/ABI_V4.md) and
[MIT SDK](../apps/sdk/README.md) describe the independent app contract.

Use `prepare_arduino.py`, `build_arduino.py`, and `flash_arduino.py` as described in [installation information](INSTALLATION_INFORMATION.md). Upload uses `EraseFlash=none` and writes only the factory application image after checking the device partition table. See [firmware validation](VALIDATION.md).

Recipients of a device can use the [installation information](INSTALLATION_INFORMATION.md) to compile and install a modified firmware build. The device GUI is part of this AGPLv3 firmware source package.

Key paths: `EvilKeyV1/FidoConfig.h` for source defaults; `EvilKeyV1/src/` for generated application sources; `templates/` for the source of regenerated engine changes; `tools/` for preparation and checks; `tests/` for host tests. Changes to generated `src/engine/board` files must also be made in `templates/port` or they will be lost during regeneration.

With Zig 0.13.0, run `python tools/verify_apps_abi.py --zig <path-to-zig>`
from `firmware/` to exercise a synthetic ABI v4 app, package validation,
assets, touch, motion input, save callbacks and the shared exit dialog.
Run `python tools/apps_storage_host/run.py --zig <path-to-zig>` for save
rollback and rate-limit checks. These tests need no private application.

In USB Tool STORAGE mode, an idle read-only session can return to HID after payload completion and 10 seconds without data operations. After a host write, firmware waits for `SYNCHRONIZE CACHE` following the last `WRITE10` or a host eject before detaching. See the relevant implementation checks in `tools/`.
