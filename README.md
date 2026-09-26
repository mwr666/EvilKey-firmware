<p align="center">
  <img src="docs/github/hero-lvgl.png" alt="EvilKey firmware and LVGL interface" width="100%">
</p>

<p align="center">
  <strong>Firmware and device GUI</strong> ·
  <a href="https://github.com/mwr666/EvilKey-Manager">Windows Manager</a> ·
  <a href="https://github.com/mwr666/EvilKey-examples">microSD examples</a>
</p>

<p align="center">
  <img src="docs/github/evilkey-lvgl-logo-motion.gif" alt="Animated EvilKey logo from the device GUI" width="128">
</p>

# EvilKey firmware

EvilKey is FIDO2 firmware for the **Waveshare ESP32-S3 Touch AMOLED 1.64, PCB V1**. Its touch GUI includes a local PIN keypad for compatible built-in user verification requests, an IMU-powered Air Mouse, diagnostics, USB storage controls and a deliberately activated USB Tool. Standard host-side ClientPIN remains supported. [On-device PIN details](docs/ON_DEVICE_PIN.md) explain the scope and validation limits.

This repository contains the device firmware, LVGL interface, generated upstream source, preparation tools, source notices and installation instructions. It does not contain the separately licensed Manager or microSD examples.

## Build and install

Read [installation information](firmware/INSTALLATION_INFORMATION.md) first. From `firmware/`, run `python prepare_arduino.py` and `python build_arduino.py` with the pinned Arduino-ESP32 and Waveshare board packages. `python flash_arduino.py` performs a rebuild and asks for a COM port and explicit confirmation. The upload uses `EraseFlash=none` to preserve NVS, but verify the exact board before flashing.

The [firmware guide](firmware/README.md) explains source generation and the two 64-row RGB565 draw buffers. Device test claims and limits are recorded in [validation](firmware/VALIDATION.md). The [Air Mouse](docs/AIR_MOUSE.md), [USB Tool](docs/USB_TOOL.md) and [Manager Drive](docs/MANAGER_DRIVE.md) documents cover individual roles.

## Related projects

- [EvilKey Manager](https://github.com/mwr666/EvilKey-Manager) — Windows device management and firmware configuration export. Its code is source available under separate noncommercial terms.
- [EvilKey examples](https://github.com/mwr666/EvilKey-examples) — original microSD script examples under separate noncommercial terms. Use security-testing examples only on systems you own or are authorized to test.

I welcome ideas for new EvilKey features. Open an issue with the intended behavior, hardware assumptions and a practical test plan.

## License and provenance

The EvilKey firmware and device GUI are distributed under GNU AGPL version 3 with upstream notices retained. See [LICENSE.md](LICENSE.md), [NOTICE.md](NOTICE.md), [firmware license](firmware/LICENSE.md) and [source provenance](firmware/docs/SOURCES.md). The Waveshare module is third-party hardware; EvilKey is an independent project.
