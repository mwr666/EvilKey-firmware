# Installing a modified firmware build

These instructions apply to the current Waveshare ESP32-S3-Touch-AMOLED-1.64
**PCB V1** EvilKey configuration. A later retail hardware or secure-boot
configuration must be checked again before it is sold.

1. Install Arduino-ESP32 3.3.12, the Waveshare PCB V1 board definition,
   Arduino CLI, Python, and Git. Extract the complete firmware source ZIP.
   Exact upstream revisions are in `UPSTREAM_LOCK.json`; license files are
   in `EvilKeyV1/data/upstream-licenses/`.
2. Edit `EvilKeyV1/FidoConfig.h` or the relevant source. Changes to generated
   `EvilKeyV1/src/engine/` must also be made in `templates/port/` because
   regeneration replaces generated files.
3. From the `firmware/` directory, run `python prepare_arduino.py`, then
   `python build_arduino.py`. The latter runs the USB stack check and builds
   `build-arduino/EvilKeyV1.ino.bin` using `EraseFlash=none`. If the pinned
   Arduino USB core needs the documented local hook, follow the output of
   `tools/check_usb_stack.py` before building.
4. Connect the device to the computer by its native USB port. Enter download
   mode by holding BOOT, pressing and releasing RESET, then releasing BOOT.
   Run `python flash_arduino.py`, choose the displayed COM port, and confirm
   with `Y`. The script rebuilds and verifies the image before upload.
5. Release BOOT and press RESET once after upload. Check display navigation,
   FIDO login, and any changed function on the device.

The upload path preserves NVS by using `EraseFlash=none`; it does not make a
backup of credentials or settings. A mistake in board choice or flash
partitioning can still make the device unusable. Never publish private FIDO
state or keys as part of source or build artifacts.

If production devices enable flash encryption, secure boot, signed updates,
or any other restriction on installing a modified build, this information
must be updated and the materials needed to install and run modified firmware
must be supplied as required by GNU AGPLv3 section 6. Test that process on an
actual retail device before publication.
