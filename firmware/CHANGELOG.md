# Firmware changelog

## 0.4.0 — 2026-09-30

- Added an Apps interpreter for separate `.ekapp` bytecode packages on microSD.
  ABI v3 takes touch coordinates and reads validated drawing commands from
  Wasm memory without guest imports. The firmware provides a shared exit
  confirmation for every app.
- Require package header revision 2 with owner, license, version, ABI and
  digest metadata. The loader rejects earlier revisions and does not write to
  microSD, NVS or FIDO credential partitions while launching apps.
- Kept Apps, Settings and the screensaver accessible when USB supplies power
  without a host connection.
- The owner reported successful firmware and app use on physical hardware.
  The public-source BIN SHA-256 recorded in `VALIDATION.md` was uploaded to
  the app partition and its written data verified. The owner confirmed that
  the app worked and existing credentials remained available after reboot.

## 0.3.0 — 2026-09-25

- Added a mouse-only USB HID role using QMI8658C tilt and touchscreen click/scroll controls.
- Added guarded pointer settings for calibration, sensitivity, and vertical inversion.
- The final firmware image passed the post-flash device smoke test described in `VALIDATION.md`.

## 0.2.17 — 2026-09-24

- Final Settings order: Diagnostics, USB & Storage, USB Tool.
- Retains the dual 64-row RGB565 DMA buffer request and the 64 KiB LVGL object pool in PSRAM.
- Retains the shared 3D screensaver, white rotating crystal, FIDO2, Manager Drive, and USB Tool behavior.

## 0.2.16-dev — 2026-09-24

- Added a Diagnostics page with actual draw buffer and memory status, refreshed only while the page is open.

## 0.2.15-dev — 2026-09-24

- Attempted two 64-row internal DMA buffers, with a one-buffer fallback, and moved the LVGL object pool to PSRAM.

## 0.2.14 — 2026-09-24

- Replaced two 32-row buffers with one 64-row RGB565 DMA buffer at the same 35,840-byte internal-RAM footprint. The user confirmed that the motion tear disappeared and animation, FIDO login, and both touch swipes worked after upload.

Older detailed notes are retained under `../docs/archive/pl/firmware/CHANGELOG.md` in the working catalog and excluded from the English source package.
