# Native Jet GUI architecture

This describes the GUI shipped in **EvilKey 0.7.4**, compiled with **Os**.
[Graphics and interface](../../GRAPHICS_AND_UI.md) describes its appearance;
[release validation](../../VALIDATION.md) identifies the accepted artifact.

## Responsibilities

- Jet's software rasterizer and the native C++ frontend render the device's
  screensaver and selected icons. Jet is pinned with MIT license/provenance in
  `firmware/third_party/jet/`.
- LVGL retains text, cards, touch, PIN dialogs, layout and navigation. No 3D
  projection changes the input geometry.
- ABI5 apps use a separate bounded native Scene3D rasterizer in the Apps worker.
  They do not reuse Jet GUI state or receive LVGL/native handles.
  See [ABI v5](../../../apps/ABI_V5.md).

Maintained code lives in `firmware/templates/port/ws_gui_3d.cpp` and related
LVGL templates. Preparation copies it into the generated sketch. Change
canonical templates before regeneration; editing generated copies alone is lost.

## Scene behavior

| Scene | Preserved composition |
| --- | --- |
| Screensaver | Perspective body, beveled crystal with its own rotation, orbit/glitch details and localized invalidation |
| Apps | Original nine-tile mark with 24-unit extrusion |
| Settings | Original gear with 24-unit extrusion; same orbit builder and timing as Apps |
| Status icons | Stable frontal icons with state effects, without arbitrary full rotations |

Apps and Settings use the same three arcs and four light points in a
6.144-second phase loop. Their animation-OFF composition also matches.
The screensaver retains its 200×200 mark and 252×252 invalidation region.
Changing the accent changes the body while the crystal stays white.

## Rendering and memory

Rendering runs synchronously in the existing display task. Geometry/material
caches and persistent buffers avoid per-frame heap allocation. GUI render data
is allocated in PSRAM; allocation failure falls back to established 2D artwork.
`FIDO_V1_GUI_3D=0` explicitly selects the legacy path.

Jet uses fixed-capacity geometry queues, clipping, depth tests, cached geometry
and banded color/depth buffers. Geometry overflow rejects rendering before the
raster pass. Supersampling/reconstruction softens edges. LVGL dithering is stable
in screen coordinates for dark gradients; flat fills and moving arcs do not
receive that treatment. Unlike app Scene3D, this GUI path has no cooperative
wall-clock deadline; fixed scenes and per-scene telemetry define its workload.

Optional O2, active-face and SRAM cache experiments remain disabled in the
accepted Os configuration. No acceleration claim is made from a host build alone.

## Display transfer

Normal mode requests two 64-row RGB565 buffers. When internal DMA allocation
cannot accommodate them, two PSRAM draw buffers use two 16-row internal DMA
staging buffers. Smaller fallbacks are supported. BLE mode reduces buffer
allocation to retain radio memory. Startup reserves USB/BLE resources before
large display allocations.

Panel transfers align row windows to even starts and odd ends. LVGL's draw
buffer is released only after its staged DMA transfer completes; queue
ownership prevents reuse while hardware still reads it. These rules apply to
all screens, not only the screensaver.

## Diagnostics and verification

Diagnostics distinguishes GUI scenes and reports P50/P95 times, geometry/
raster/composition timings, submitted triangles, allocation and sampling state.
Display telemetry reports frame/transfer timing, waits, flushes and buffers.
Compare the same workload and configuration when evaluating an optimization.

Host checks cover clipping, depth, reconstruction, geometry/cache bounds and
actual LVGL integration. Apps/Settings comparisons cover the shared orbit,
both accents and animation ON/OFF. Rendering never authorizes FIDO presence,
PIN success or a CTAP response; those come from authenticator state.
Host images do not measure ESP32-S3 speed or panel quality.

The owner accepted the exact 0.7.4 release on PCB V1.0. See
[release evidence](../../RELEASE_0.7.4.md) for software and installation results.
