# EvilKey firmware 0.7.6

## Changes since 0.7.5

- Shared ESP32-S3 SIMD pixel operations for the GUI, 2D apps and native 3D scenes.
- Independent apps load bounded indexed `.ekmesh` models from microSD; the MIT SDK includes model conversion and packaging tools.
- Diagnostics defaults OFF after startup. Settings enables complete-session FPS, maximum native rendering time and SD report export.
- ABI v4/v5, package revision 5, hardware clocks, rendering budgets and storage layout are retained. Manager remains 1.1.6.

## Installation

Extract the complete firmware source ZIP and open EvilKey.cmd. Option 7 builds;
option 11 builds and installs through the selected port in BOOT mode. Press RESET
without BOOT after application and protected-storage verification. Preserve
existing app save files, SD models and reports.

BIN: EvilKey_0.7.6.bin, 2,316,704 bytes.
SHA256: dd936d6aaf7151304425bf7d43ee23035a95dd9e85b2e329a451d817dfb3dcfb.
Arduino-ESP32 3.3.12; Os; app offset 0x500000; Waveshare PCB V1.0.

Firmware/GUI are AGPLv3 with upstream notices. The app SDK is MIT. Manager and
USB Tool examples retain their separate licenses. Game source/packages are not included.
