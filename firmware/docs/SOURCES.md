# Source provenance

The starting point was the Waveshare PCB V1 Arduino Pico FIDO 0.2.5-dev port, with C1, S1/S2 stack changes, UI1, and cancellation handling. EvilKey 0.2.6 and Manager 1.0.0 added the project-specific M1 API and desktop application. Historical overlay installers are not required to prepare a new project.

Primary reviewed sources:

- [Pico FIDO](https://github.com/polhenarejos/pico-fido/tree/fc7c60e9b45338fe815a43bb228d234322e48d97), commit `fc7c60e9b45338fe815a43bb228d234322e48d97`: CTAP configuration commands, authorization format and token lifecycle, limits, and vendor identifiers.
- [Pico Keys SDK](https://github.com/polhenarejos/pico-keys-sdk/tree/507ac45956b7f1c763bb5e88a6411438093d10c7), commit `507ac45956b7f1c763bb5e88a6411438093d10c7`: initialization order and task model.
- [Yubico python-fido2 2.2.1](https://github.com/Yubico/python-fido2/tree/2.2.1): production APIs in `fido2/ctap2/base.py`, `config.py`, `pin.py`, `credman.py`, and `hid/__init__.py`. The fakes under `tests/` are only test doubles.

M1 is a project-specific extension, not a standard CTAP feature or Yubico API. See [PROTOCOL_M1.md](PROTOCOL_M1.md). The original upstream review date was 2026-09-16; the project does not automatically follow later upstream branches.

Other pinned dependencies: Mbed TLS with EdDSA commit `fc39404125e93ee00e6758605e6c6f2c8db440f1`; TinyCBOR commit `c0aad2fb2137a31b9845fbaae3653540c410f215`; LVGL 8.4.0 commit `4495f428630cc1741bd8bfd977f080e8460e8e8d`. The preparer copies that exact LVGL source into the generated Arduino engine and uses `templates/lvgl_conf.h`; Arduino Library Manager is not required for LVGL. Built-in Montserrat fonts come from LVGL. Complete source pins and repository URLs are in `../ARDUINO_PORT.json` and `../prepare_arduino.py`. Available upstream license files are copied when the sketch is prepared.
