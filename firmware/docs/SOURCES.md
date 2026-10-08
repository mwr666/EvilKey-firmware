# Source provenance

EvilKey derives from the Waveshare PCB V1 Arduino Pico FIDO port and the
pinned Pico FIDO / Pico Keys SDK sources below.

Primary reviewed sources:

- [Pico FIDO](https://github.com/polhenarejos/pico-fido/tree/fc7c60e9b45338fe815a43bb228d234322e48d97), commit `fc7c60e9b45338fe815a43bb228d234322e48d97`: CTAP configuration commands, authorization format and token lifecycle, limits, and vendor identifiers.
- [Pico Keys SDK](https://github.com/polhenarejos/pico-keys-sdk/tree/507ac45956b7f1c763bb5e88a6411438093d10c7), commit `507ac45956b7f1c763bb5e88a6411438093d10c7`: initialization order and task model.
- [Yubico python-fido2 2.2.1](https://github.com/Yubico/python-fido2/tree/2.2.1): production APIs in `fido2/ctap2/base.py`, `config.py`, `pin.py`, `credman.py`, and `hid/__init__.py`. The fakes under `tests/` are only test doubles.

M1 is a project-specific extension, not a standard CTAP feature or Yubico API. See [PROTOCOL_M1.md](PROTOCOL_M1.md). The original upstream review date was 2026-09-16; the project does not automatically follow later upstream branches.

Other pinned dependencies: Mbed TLS with EdDSA commit `fc39404125e93ee00e6758605e6c6f2c8db440f1`; TinyCBOR commit `c0aad2fb2137a31b9845fbaae3653540c410f215`; LVGL 8.4.0 commit `4495f428630cc1741bd8bfd977f080e8460e8e8d`. The preparer copies that exact LVGL source into the generated Arduino engine and uses `templates/lvgl_conf.h`; Arduino Library Manager is not required for LVGL. Built-in Montserrat fonts come from LVGL. Complete source pins and repository URLs are in `../ARDUINO_PORT.json` and `../prepare_arduino.py`. Available upstream license files are copied when the sketch is prepared.

BLE dependencies are pinned by archive SHA-256 in `../BLE_LOCK.json`:
ESP32-BLE-Gamepad **v0.8.0** and NimBLE-Arduino **2.5.1**. Their retained
license files are copied to `../EvilKeyV1/data/upstream-licenses/`.
`../tools/prepare_ble.py` applies the reviewed local storage,
memory and HID adaptations to isolated libraries; it does not modify globally
installed Arduino libraries.


## Jet GUI rasterizer

The software rasterizer is pinned to CubeCoders/Jet commit
`c56dfc0c012ba7a09a6e49b4123340ec24981441`. Its MIT license and
provenance are retained in `firmware/third_party/jet`; the Arduino license bundle
also includes `Jet_LICENSE`. The C++ frontend is native firmware code and does
not extend the microSD app ABI or expose authenticator state to apps.
