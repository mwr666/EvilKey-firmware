# Firmware 0.3.0 validation

The 1,800,736-byte image in this package has SHA-256
`504d21eaa4002263ebbd8d36026ef0481978b27da68e466c9ef079c99be38678`.
It passed source checks and an Arduino-ESP32 3.3.12 build. The image was
uploaded to COM5 with `EraseFlash=none`; the upload tool verified the write.
After restart, the user confirmed Air Mouse entry, cursor directions and
diagonals, SETTINGS with calibration, sensitivity and vertical inversion, and
return to FIDO. This is a device smoke test, not endurance testing.

The firmware and device GUI were not changed by the separate Manager and
microSD licensing work. The BIN hash above remains the release reference.
