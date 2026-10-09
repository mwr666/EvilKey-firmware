<!-- SPDX-License-Identifier: MIT -->
# EvilKey Apps ABI v5 — bounded native 3D scenes

ABI v5 extends [ABI v4](ABI_V4.md). Input stays 4160 bytes, commands stay 20
bytes, and package revision stays 5 (320-byte header, icon, Wasm, assets).
The runtime ABI field at header offset 12 is 5 for a native-scene app.
Firmware 0.7.5 accepts ABI4 and ABI5. Existing ABI4 packages receive ABI4
mailboxes and cannot issue the new command. The SDK's legacy VERSION macro
remains 4; LATEST is 5. Pass `abi=5` / `--abi 5` explicitly when packaging.

## Command 7: SCENE3D

Flags zero; x/y/w/h specify an even-sized viewport within 280x456, maximum
280x320. arg0 is the guest byte offset of a fixed 3172-byte `EvilKey3DScene`;
arg1 must be exactly 3172. At most one scene per app call. Follow with 2D HUD
commands and PRESENT. Scene contributes to the existing draw/pixel quotas.
The full output list and scene are validated before any draw, presentation or
save effect. No guest pointer survives the call and no mesh code is executed.

Wire integers are little-endian. See the MIT `evilkey_scene3d.h` declarations.
The scene consists of 16-byte header, 20-byte camera, 8 material slots (8 bytes
each), and 96 object slots (32 bytes each). All unused slots/reserved fields
must be zero. Magic `0x35443345`, scene version 1, flags zero.

| Field | Range / meaning |
| --- | --- |
| objects / materials | 1..96 / 1..8 |
| object model | BOX=1 (12 faces), BALL=2 (32), PLANE=3 (2), PYRAMID=4 (6) |
| material index | Zero-based, less than material_count |
| positions | Signed Q8.8; objects and target -8192..8192, camera -16384..16384 |
| scales | Unsigned Q8.8 full size, 1..8192 per axis |
| rotation | Signed hundredths of degrees, -18000..18000, X then Y then Z |
| materials | RGB565; flag 0 flat-lit or 1 unlit; reserved zero |
| camera | Look at target, world Y up; X right, Z toward viewer |
| projection | 0 orthographic or 1 perspective |
| orthographic span | Vertical world extent, Q8.8, 256..8192 |
| perspective FOV | Degrees, 25..90 |

Camera/target separation must be at least one unit, with nonzero
horizontal component and squared horizontal / total distance >= 0.001.
This excludes unstable vertical look-at poses. Submitted builtin faces <=1280.
No custom vertices, textures, shaders, plugins or native app code in this ABI.

## Budget and presentation

The independent native C rasterizer runs in the existing Apps worker. It
uses a half-resolution viewport (at most 140x160), depth testing, near/screen
clipping, flat lighting and 2x RGB565 reconstruction into the existing app
backbuffer. Orthographic depth is affine camera Z; perspective uses reciprocal
Z. PRESENT follows the current app frontbuffer/display route, including the
firmware-owned exit gesture. GUI Jet state and icons are not reused or changed.

One per-app context is allocated in PSRAM only for ABI5 and freed on exit.
Colour/depth arrays use 134400 bytes plus the scene and small context overhead
(approximately 135 KiB total). No new internal DMA buffer is allocated.
The geometry pass has a cooperative 20000-us deadline checked per triangle and
scanline, plus 300000 bounded pixel tests. Clear/setup and bounded final
reconstruction add overhead; **20000 us is not a hard total-call deadline**.
Timeout/work-limit repeats the previous complete viewport; with no cached frame
of the same dimensions, background is shown. A partial frame is never committed.

ABI5 `input.reserved[0..2]` contains the previous scene status, elapsed
microseconds (including reconstruction) and submitted triangles. Statuses:
NONE=0, OK=1, TIMEOUT=2, WORK_LIMIT=3, NO_MEMORY=4. ABI4 receives zeros.
These are per-scene values, separate from GUI Jet diagnostics. No render means
the last scene result remains available. Failed allocation prevents launch with
`3D memory unavailable`; the launcher continues.

The guest still has zero imports, bounded 2 MiB linear memory, at most 64 KiB Wasm bytecode, 6M weighted gas units
per call, existing asset/draw/save quotas and namespaced microSD saves. This
API supplies no USB, FIDO, key-store, network, arbitrary SD or LVGL handles.
API boundaries do not establish hardware isolation or a complete security audit.

## Verification scope

ABI4 regression, native bounds/clipping/occlusion/abort tests, atomic-invalid
scene cases, package ABI gating, service allocation/cleanup and Wasm fixture
execution are host checks. See [qualification](../docs/ABI5_QUALIFICATION.md). ESP32-S3 smoothness, IMU orientation, concurrent
USB/FIDO and extended device play require physical qualification.
