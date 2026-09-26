# Firmware project exported by EvilKey Manager

This is a complete, separate Arduino project copy. Manager changes only `EvilKeyV1/FidoConfig.h` during export. It does not flash firmware or modify the running device.

Review `EvilKeyV1/FidoConfig.h`. If `EvilKeyV1/src/engine_ready.h` is missing, run `prepare.cmd` or `python prepare_arduino.py`. Use Arduino-ESP32 3.3.12 and the Waveshare ESP32-S3-Touch-AMOLED-1.64 PCB V1 board. Check the required USB core hook with `python tools/check_usb_stack.py --require`. If it is missing, close Arduino IDE and explicitly run `python tools/check_usb_stack.py --apply`, then repeat `--require`.

Open `EvilKeyV1/EvilKeyV1.ino` in Arduino IDE or run `python build_arduino.py`. Building does not upload. Preserve a known-good image before flashing and do not use Erase All Flash as part of normal updates.

USB Tool never runs a payload automatically. Stage 8A/8B require local confirmation. Collected data is written to `loot.bin` with a neighboring `loot.idx` containing segment metadata and SHA-256. Stage 8C remains disabled.

Host tests include `python tools/run_ducky_runtime_tests.py` and `python tests/release_026/test_ducky_auditor_r35.py`. Host tests do not replace testing on the physical board and microSD.
