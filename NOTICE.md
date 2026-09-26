# Source and license notice

EvilKey firmware 0.3.0 is derived from Pico FIDO. Current device graphics originate from `firmware/assets/evilkey_mark_source.png`. The LVGL mark has separate masks for the mint body and white crystal. The separately published Manager uses artwork based on the same source.

The Arduino PCB V1 port is based on an earlier V1 development package and Pico FIDO / Pico Keys SDK by Pol Henarejos and contributors. EvilKey is not an official Pico Keys, Waveshare, or Espressif release.

- Pico FIDO and Pico Keys SDK: AGPLv3, as documented in their license files and source headers.
- EvilKey-authored firmware and LVGL GUI: AGPL-3.0-or-later file notices; the distributed firmware as a whole is provided under AGPL version 3 because the pinned upstream grants are version 3.
- EvilKey Manager and original microSD examples are separately published with their own licenses: [Manager](https://github.com/mwr666/EvilKey-Manager) and [examples](https://github.com/mwr666/EvilKey-examples).
- Mbed TLS fork: repository licenses (Apache-2.0 or GPL-2.0-or-later depending on selected variant and file); original headers are retained.
- TinyCBOR: MIT.
- LVGL 8.4.0: MIT, pinned to commit `4495f428630cc1741bd8bfd977f080e8460e8e8d`.
- Arduino-ESP32 and relevant USB APIs: Espressif, Apache-2.0.
- s3-ducky: Apache-2.0, pinned to commit `e1e172c26961b865da699969c109a99c78311434`; `prepare_arduino.py` copies its license files into the sketch.
- Printable ASCII DE/FR/ES keyboard maps are adapted from Arduino Keyboard 1.0.7, commit `3f7bad0a41839689684e3b46ce9deb0232f8ec2d`, LGPL-3.0. The source license copy is retained under the firmware data licenses.

For the exact third-party source and license inventory, see `firmware/docs/SOURCES.md` and the bundled upstream license files.
