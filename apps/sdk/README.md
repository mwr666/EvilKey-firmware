<!-- SPDX-License-Identifier: MIT -->
# EvilKey Apps SDK v3

This small, independently authored header declares the app-facing ABI. It is
licensed under MIT; firmware implementation code is not part of this SDK.
Applications may use these declarations under their own separate licenses.

Compile a freestanding `wasm32` module with no imports or start function,
one memory, and the two exports in `include/evilkey_app_abi.h`. See
[`../ABI_V3.md`](../ABI_V3.md) for the complete wire format and limits.
Package the module in a `.ekapp` file. The `.ekapp` is copied to
`/evilkey/apps/` on FAT microSD. Neither SDK nor firmware requires access to
an application's source to run it.

`package_app_release.py --app-dir <directory>` validates an app package and
creates a binary-only ZIP with its manifest, own license and this SDK's MIT
notice. The app directory is explicit; no app source or package is bundled
with this firmware repository.
