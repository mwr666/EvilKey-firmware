# EvilKey firmware 0.8.1

## Changes since 0.8.0

- Replace the unbounded display completion wait with a yielding **500 ms** deadline.
- Check actual DMA ownership after completion notifications; a stale token cannot release a live transfer buffer.
- Safely abort and unwind a failed refresh while retaining in-flight buffers/context. A permanently failed panel uses existing unavailable-display handling.
- Both exact PCB images passed preserving installation/readback and owner UI/Race lap retests without freezing.
- PCB profiles, ABI v4/v5, rendering budgets, SIMD/SD models and storage offsets retain their contracts. Manager stays at **1.1.6**; V1.1 compatibility begins with **0.8.0**.

## Download and install

Choose the image labelled for your PCB silkscreen. The public source ZIP
contains both complete image sets, firmware, MIT SDK and licenses. Extract
it and open **EvilKey.cmd**: **7** builds, **11** installs with verification,
**6** checks software and **8** packages source with the accepted images.
Enter BOOT mode, select PCB and COM, confirm **Y**, then wait for readback
and protected-storage verification. Press RESET without BOOT afterward.
Existing updates retain credentials/settings and microSD. A fresh factory
module's separate **ERASE** action deletes internal flash; it is not needed
for an ordinary update. Application offset remains **0x500000**.

Both release images passed full Arduino-ESP32 3.3.12 builds and linked NVS
erase guards. Protected nvs, otadata, part0 and wsdev digests were unchanged
on both boards; SD was not accessed. The owner confirmed UI startup and
several Race laps without freezing on each PCB. New credential authentication,
quantitative FPS, long-duration endurance and physical injected DMA failure
were not tested in this repair. No FIDO certification or new hardware/enclosure
qualification is claimed. Rebuilding creates a different artifact needing
its own validation; published hashes refer to the exact tested files.

Firmware/GUI are AGPLv3 with upstream notices; the SDK is MIT. Manager,
original examples and separately licensed games retain their own terms.
Historical PCB V1 footage and the 0.7.4 interface tour keep their original scope.

[Getting started](GETTING_STARTED.md) · [Build and flash](BUILD_AND_FLASH.md)
· [Validation](VALIDATION.md).
