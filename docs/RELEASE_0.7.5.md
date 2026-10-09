# EvilKey firmware 0.7.5

## Changes since 0.7.4

- Jet GUI and native Scene3D rendering share work between both ESP32-S3 cores.
- Exact triangle spans, reused cube vertices and packed color/depth reduce
  redundant raster work and separate PSRAM accesses while preserving the visuals.
- Rendering and display work are coordinated; bounded internal-memory tiles and
  smaller direct DMA buffer fallbacks support available memory configurations.
- Diagnostics now has seven cards and **Save report**. One text file under
  `/evilkey/diagnostics/` contains the complete report, regardless of the visible card.
- Host **Eject** turns off Manager Drive. The device saves MSC OFF and briefly
  restarts, reconnecting without USB storage so local apps can access SD again.
  Enable Manager Drive in Settings to expose it again. Physical card removal is
  not the host Eject command. Failed setting persistence reports an error.

Jet and ABI v5 were introduced in 0.7.4. ABI v4/v5 compatibility, package revision
5, the corner exit profile and Manager 1.1.6 remain. Temporary debugging tools
and unused experimental rendering paths have been removed.

## Installation

Use [Getting started](GETTING_STARTED.md), [Build and flash](BUILD_AND_FLASH.md)
and [installation information](../firmware/INSTALLATION_INFORMATION.md).
The accepted image was installed on PCB V1.0 on 2026-10-09 with application
readback verified and protected nvs, wsdev, part0 and otadata unchanged.
No partition migration was required.

- BIN: `EvilKey_0.7.5.bin`; 2,286,848 bytes.
- SHA-256: `f4874dde9d72fbaf3e9312df4408138ca654030d134e44bef0c9d784f1d4b6eb`.
- Arduino-ESP32 3.3.12; Os; app at `0x500000`; unchanged partition layout.

The source ZIP contains firmware, templates, generated source, public SDK and the
exact accepted BIN. A rebuild produces a new artifact. See [Validation](VALIDATION.md).

## Development and licensing

This remains development firmware with unencrypted credential NVS. Secure Boot
and encrypted flash/NVS provisioning are not enabled; no FIDO certification is
claimed. PCB V1.1 compatibility remains unverified.

Firmware/GUI are AGPLv3 with upstream notices; ABI/SDK are MIT. Manager and USB
Tool examples are distributed separately under their existing licenses.
