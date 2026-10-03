# Graphics and interface

EvilKey retains the black background and mint accent of the original interface. The faceted crystal is white and has its own color mask. Changing the accent changes the mint body, not the crystal. The PIN keypad, touch regions, and swipe gestures retain their established geometry.

The Ghost Signal screensaver is shared by all USB roles. Its 200 × 200 px mark moves over a closed 28 × 20 px path. The mint body tilts in 3D together with the crystal, while the crystal also rotates around its vertical axis. The animation has 256 frames at 24 ms per frame, a 6.144-second loop, and localized 252 × 252 px invalidation. Short glitch pulses and orbit lines remain part of the design.

Indexed frames are decoded one at a time into PSRAM. LVGL uses RGB565 output. Normal/USB modes request two 64-row internal DMA buffers with a smaller single-buffer fallback; BLE modes use a single 16-row buffer to retain controller memory. Stable 8 × 8 dithering improves dark gradients. Flat fills and moving arcs are not dithered. A8 masks soften the logo and Settings icon. Diagnostics displays the actual buffer allocation once per second while that page is open.

In the Windows Manager, the small header logo is static. The animated 3D mark sits beside the device name on Overview. It uses a prebuilt 256-frame sprite sheet and does not change forms, tabs, or USB operations.

Brand assets: [repository banner](github/hero.svg), [static EvilKey mark](../manager/assets/evilkey_logo_hero.png), and the [Manager animation sprite sheet](../manager/assets/evilkey_logo_hero_animated.png). The original display animation remains in the firmware source; graphical validation is documented in [Validation](VALIDATION.md).
