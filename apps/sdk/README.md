<!-- SPDX-License-Identifier: MIT -->
# EvilKey Apps SDK v4

This small, independently authored header declares the app-facing ABI. It is
licensed under MIT; firmware implementation code is not part of this SDK.
Applications may use these declarations under their own separate licenses.

Compile a freestanding `wasm32` module with no imports or start function,
one memory, and the three exports in `include/evilkey_app_abi.h`. See
[`../ABI_V4.md`](../ABI_V4.md) for the complete wire format and limits.
Package the module in a `.ekapp` file. The `.ekapp` is copied to
`/evilkey/apps/` on FAT microSD. Neither SDK nor firmware requires access to
an application's source to run it.

`pack_ekapp.py` builds one ABI v4 package from a Wasm module and an optional
JSON manifest of raw RGB565 image assets. Each asset entry supplies `id`,
`width`, `height`, `file`, and optional `transparent_zero`. IDs are increasing.
The result contains the Wasm and assets in one file. The package format is
validated again by firmware before launch.

`package_app_release.py --app-dir <directory>` validates an app package and
creates a binary-only ZIP with its manifest, own license and this SDK's MIT
notice. Pass the app directory explicitly; the SDK has no built-in app bundle.
