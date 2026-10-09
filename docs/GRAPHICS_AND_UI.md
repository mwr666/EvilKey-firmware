# Graphics and interface

## Appearance

The device keeps the original black background, mint accent, white faceted
crystal and rounded controls. Changing the accent affects the body, not the
white crystal. LVGL owns readable text, PIN keypad layout, swipe navigation
and touch zones; these are not transformed into a 3D scene.

## Animation in 0.7.5

The **Ghost Signal** screensaver uses native Jet rendering. Its 200×200 mark
moves on the established closed path; the body tilts and the crystal also
turns around its own axis. Orbit lines and short intentional glitch pulses
remain part of the design. The phase loop is 256 × 24 ms (6.144 seconds);
this is animation timing, not a guarantee of 256 displayed frames.

**Apps and Settings** share orbit geometry, highlight, light points and phase
timing. Only the center icon differs: nine app tiles or the original gear.
Both have 24-unit extrusion so their side faces are visible during rotation.
Animation OFF uses a fixed composition.

Other status icons stay frontal and stable. Their surrounding effects convey
state without rapid, chaotic icon rotations. A rendered frame never counts
as FIDO user presence or verification.

## Display and diagnostics

Output is RGB565. Normal mode supports two 64-row draw buffers, using internal
DMA memory when available or PSRAM with DMA staging. BLE mode uses a smaller
buffer to retain controller memory. Allocation fallbacks keep the GUI usable.
Diagnostics reports actual allocation and per-scene Jet timing, distinct from
an app's Scene3D rendering telemetry.

See [native GUI architecture](design/3d-gui/README.md) for memory, timing,
fallback and panel transfer, and [validation](VALIDATION.md) for scope.

## Windows Manager and assets

The small Manager header logo is static. Overview uses an animated 256-frame
sprite sheet beside the device name, independently of the device's Jet renderer.

- [Repository banner](github/hero-lvgl.png)
- [Static mark](https://github.com/mwr666/EvilKey-Manager/blob/main/manager/assets/evilkey_logo_hero.png)
- [Manager sprite sheet](https://github.com/mwr666/EvilKey-Manager/blob/main/manager/assets/evilkey_logo_hero_animated.png)
