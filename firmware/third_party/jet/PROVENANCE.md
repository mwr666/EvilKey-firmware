# Jet provenance

- Upstream: https://github.com/CubeCoders/Jet
- Revision: `c56dfc0c012ba7a09a6e49b4123340ec24981441`
- License: MIT; the original `LICENSE` is retained here.
- Imported: all `.hpp` headers and the rasterizer support translation units.
- Excluded: application examples, scene loaders and frontend code.
- Arduino include adaptation: `Camera.cpp` uses `"Shader.hpp"` instead of
  `<Shader.hpp>` so sketch compilation resolves the sibling header.
- Local configuration: `JetConfig.hpp`, native RGB565 with per-pixel depth,
  no half-width, interlaced, checkerboard, picking, textures or postprocessing.
- Preprojected-UI adaptation: `JET_PREPROJECTED_UI=1` bypasses the Camera FOV
  lookup initialization and places rasterizer code in cached flash rather than
  IRAM. This frontend supplies screen-space vertices; it only needs the camera
  near/far depth range. General scene projection must not enable this flag
  without restoring camera projection initialization.
- Local frontend: `firmware/templates/port/ws_gui_3d.cpp` (AGPL-3.0-or-later).
  It supplies perspective transforms, face lighting and spatial antialiasing.
- `OpaqueUI.hpp` is a local MIT-licensed Jet extension for this bounded opaque
  frontend. It prepares exact integer edge/depth planes once, retains odd
  triangle endpoints and reuses that setup across bands. Affine depth is
  interpolated per pixel using a common base and an exact quotient/remainder
  addition/carry recurrence. Division occurs only during face/row setup; wide
  residuals use int64 for the initial row value. Negative slopes use Euclidean
  quotient/remainder so the per-sample result matches direct barycentrics.
  It does not replace the general textured/shader rasterizer.

Arduino copies are generated in `EvilKeyV1/src/engine/jet`. Modify this
directory and run `python firmware/tools/sync_3d_gui.py`, not the generated copy.
