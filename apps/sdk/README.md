<!-- SPDX-License-Identifier: MIT -->
# EvilKey Apps SDK v4 / v5

This small, independently authored header declares the app-facing ABI. It is
licensed under MIT; firmware implementation code is not part of this SDK.
Applications may use these declarations under their own separate licenses.

Compile a freestanding `wasm32` module with no imports or start function,
one memory, and the three exports in `include/evilkey_app_abi.h`. See
[`../ABI_V4.md`](../ABI_V4.md) for the complete wire format and limits.
Package the module in a `.ekapp` file. The `.ekapp` is copied to
`/evilkey/apps/` on FAT microSD. Neither SDK nor firmware requires access to
an application's source to run it.

`pack_ekapp.py` builds one ABI v4 or v5 package from a Wasm module and an optional
JSON manifest of raw RGB565 image assets. Each asset entry supplies `id`,
`width`, `height`, `file`, and optional `transparent_zero`. IDs are increasing.
Package revision 5 requires a display name (up to 63 UTF-8 bytes) and
an opaque 64×64 little-endian RGB565 launcher icon (8192 bytes). The 320-byte
header is followed by the icon; Wasm starts at byte 8512. The icon and
Wasm/assets have separate SHA-256 digests. Runtime ABI is selected explicitly (4 by default, or 5 for native scenes).
The header explicitly declares UI profile 1 (`corner-exit-v1`).

```sh
python pack_ekapp.py --help
```

Pass `--name "Evil Blocks"`, `--icon launcher-icon.rgb565` and
`--ui-profile corner-exit-v1` alongside the
existing required package arguments. PNG conversion belongs to the app's
build process. Keep the package ID unchanged when changing a name or icon;
the ID determines the `<id>.save` sidecar. Legacy package revisions are not
supported by the new launcher.

Before declaring the profile, adapt every app screen to the firmware-owned
top-left 56x56 touch square: no app controls there. The separate 48x48 visual
square is background only; header content remains from x=50.
Use `EVILKEY_APP_SYSTEM_ZONE_*`, `EVILKEY_APP_SYSTEM_VISUAL_ZONE_*` and
`EVILKEY_APP_HEADER_CONTENT_X` constants.
The firmware draws the grip, tracks gesture progress, pauses app time and
shows YES/NO. App-origin touch sequences remain app-owned until all fingers
lift. Read [UI_PROFILE.md](UI_PROFILE.md) for the normative rules and example.
Packing requires an explicit declaration; it cannot inspect artwork or prove
that an app follows the layout rules.

The result contains the metadata, icon, Wasm and assets in one file. The package format is
validated again by firmware before launch.

`package_app_release.py --app-dir <directory>` validates an app package and
creates a binary-only ZIP with its manifest, own license and this SDK's MIT
notice. Pass the app directory explicitly; the SDK has no built-in app bundle.

## Native scenes (ABI5)

Use `include/evilkey_scene3d.h` and command 7 for bounded builtin 3D scenes.
Pass `--abi 5` when packaging; released firmware 0.7.5 supports this API. ABI4 stays
compatible and remains the default. See [ABI v5](../ABI_V5.md).
