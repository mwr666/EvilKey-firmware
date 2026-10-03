# Firmware source and license notice

The Arduino PCB V1 port is based on an earlier V1 development package and Pico FIDO / Pico Keys SDK by Pol Henarejos and contributors. It is not an official Pico Keys, Waveshare, or Espressif release. The local port is AGPL-3.0-or-later and is provided without warranty.

Pico FIDO and Pico Keys SDK retain AGPLv3 notices. The Mbed TLS fork retains its repository licenses (Apache-2.0 or GPL-2.0-or-later depending on file and variant). TinyCBOR and LVGL 8.4.0 use MIT licenses. Arduino-ESP32 and the relevant USB APIs use Espressif's Apache-2.0 terms. The preparer retains upstream copyright headers, records exact source hashes, and copies available LICENSE, LICENCE, COPYING, and NOTICE files into the sketch.

The EvilKey Apps interpreter vendors Wasm3 at commit `0228c02233f6f4f5d3a85ab0b14244a2ebadc1ba` under its MIT license (`EvilKeyV1/src/apps/wasm3/LICENSE`). Its WASI and libc host bindings are excluded from the firmware source snapshot.

ESP32-BLE-Gamepad v0.8.0 (MIT) and NimBLE-Arduino 2.5.1 (Apache-2.0 and
retained component notices) are pinned in `BLE_LOCK.json`. Their licenses
and NimBLE NOTICE are retained under `EvilKeyV1/data/upstream-licenses/`.

The QSPI framing, display startup sequence, and touch registers follow Waveshare documentation and examples for **PCB V1**. V2 has a different pinout. The CO5300-compatible transport driver does not require the full vendor graphics library. The private cryptography namespace is an integration change and does not transfer ownership of upstream code. No cryptographic audit has been performed.

Default `FEFF:FCFC` and compatibility-profile `1050:0402` VID/PID values are local development identities. A compatibility label containing `Pico DEV` does not mean this is a Yubico device or a certified product. Resolve legal USB identifier allocation before distributing hardware.

The GUI uses pinned LVGL 8.4.0 and built-in Montserrat fonts; no separate
TTF/OTF files are bundled. The Manager is packaged and licensed separately;
its dependency notices ship with that package.

See `../NOTICE.md` and `docs/SOURCES.md` for more precise provenance and revisions.
