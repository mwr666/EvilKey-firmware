<!-- SPDX-License-Identifier: MIT -->
# EvilKey Apps ABI v3 and `.ekapp` format

Historical release 0.4.0 documentation. Firmware 0.5.0 rejects v3 packages;
see [ABI_V4.md](ABI_V4.md) and the current SDK for new application development.

This records the earlier interface for independent app authors. The current
[`sdk/include/evilkey_app_abi.h`](sdk/include/evilkey_app_abi.h) declares v4
and is licensed under MIT. Each app retains its own owner and license.

## Package on microSD

Place `<id>.ekapp` in `/evilkey/apps/` on a FAT microSD card. Package format
revision 2 consists of a 192-byte header and 8–65,536 bytes of WebAssembly.
All integers are unsigned little-endian. Text fields are NUL-terminated,
zero-padded and nonempty. The filename must match the header ID.

| Bytes | Size | Content |
| --- | ---: | --- |
| 0–7 | 8 | ASCII `EKEYAPP1` |
| 8–9 | 2 | Header size `192` |
| 10–11 | 2 | Package revision `2` |
| 12–13 | 2 | App ABI version `3` |
| 14–15 | 2 | Flags `0` |
| 16–21 | 6 | Version major, minor, patch as three `u16` values |
| 22–53 | 32 | ASCII app ID (`a-z`, `0-9`, `.`, `_`, `-`; no leading/trailing or doubled dot) |
| 54–57 | 4 | Wasm byte length |
| 58–89 | 32 | SHA-256 of Wasm bytes |
| 90–153 | 64 | UTF-8 rights owner |
| 154–185 | 32 | ASCII SPDX license ID or `LicenseRef-...` |
| 186–191 | 6 | Reserved zeros |

The header declares owner, license, version and compatibility. The firmware
checks its structure and digest. These fields are publisher assertions;
SHA-256 detects changes or corruption but does not authenticate an author.
Distributors should supply their full license terms beside the `.ekapp`.
The optional distribution manifest may list informational capabilities such
as `display` and `touch`; firmware derives actual access from ABI v3 and
does not parse the manifest.

## WebAssembly interface

An app package contains a standalone WebAssembly module. The module must have
**zero imports**, one internally defined linear memory, no start function, and
two exported functions:

| Export | Wasm signature | Meaning |
| --- | --- | --- |
| `app_init` | `i32 ()` | Initialize the app and return the offset of its first output list. |
| `app_step` | `i32 (i32 now_ms, i32 x, i32 y, i32 down)` | Advance the app and return the offset of this call's output list. |

`now_ms` is monotonic active-app time and pauses while the firmware's exit
dialog is open. Touch coordinates are pixels on the 280 × 456 display.
On release or invalid touch, `x = y = -1` and `down = 0`. The app owns its
hit regions, controls, rendering decisions, and game state.

Each returned `i32` is an **unsigned byte offset** in the module's own linear
memory, not a host pointer. At that offset is a little-endian `u32 count`,
followed by `count` twelve-byte records. A count of zero means there is no
display update. The memory must remain valid until the call returns; firmware
validates and consumes the complete list before the next call.

| Record byte offset | Type | Rectangle (`kind = 1`) | Present (`kind = 2`) |
| --- | --- | --- | --- |
| 0 | `u16` | kind = 1 | kind = 2 |
| 2 | `u16` | x | zero |
| 4 | `u16` | y | zero |
| 6 | `u16` | width | zero |
| 8 | `u16` | height | zero |
| 10 | `u16` | RGB565 color | zero |

Rectangles must fit the display and have nonzero dimensions. A present record
copies the host's drawing buffer to the visible frame. The host validates the
entire list before applying any command. Per call limits are 512 rectangles,
600,000 painted pixels, two present records, and at most 514 records. Invalid
offsets, lengths, commands, or quotas stop the app.

The VM additionally limits linear memory to 2 MiB and execution to 6 million
Wasm3 gas units per call. It exposes no WASI, filesystem, USB, flash, NVS,
FIDO, or native pointer access. The `.ekapp` header must declare ABI version 3;
earlier ABI and package revisions are rejected. The host currently offers only
display and touch, with no app storage, network, or device-key access.
