<!-- SPDX-License-Identifier: MIT -->
# EvilKey Apps ABI v4

This is the independent app author contract. The small declarations in
[`sdk/include/evilkey_app_abi.h`](sdk/include/evilkey_app_abi.h) are MIT
licensed. Each app retains its own copyright and license. The firmware's
implementation is AGPL-3.0-or-later. An app has no access to FIDO credentials,
USB, NVS, native pointers, filesystem paths, or WASI.

## Single-file package and sidecar

Copy `<id>.ekapp` to `/evilkey/apps/` on FAT microSD. No install command is
needed. The ID must equal the filename stem. The 192-byte `EKEYAPP1` header
uses unsigned little-endian values. Its layout is unchanged through byte 185
from ABI v3, except: package revision at bytes 10–11 is **3**, ABI at bytes
12–13 is **4**, bytes 58–89 are SHA-256 of **Wasm plus asset blob**, bytes
186–189 contain asset blob size (`u32`), and bytes 190–191 are zero. Bytes
54–57 contain Wasm size. Exact file length is `192 + wasm_size + asset_size`.
Wasm size is 8–65,536 bytes; assets are at most 1,048,576 bytes. Older ABI
packages are rejected. SHA-256 detects corruption, not publisher identity.

An app may save up to 4,096 bytes in `/evilkey/apps/<id>.save`. The firmware
derives the path from the validated package ID. It never accepts a guest path
and never writes app data to NVS. The `.save` file contains two CRC-protected,
512-byte-sector-aligned slots; updates alternate slots. A malformed or missing
file yields no save. A valid zero-length record is reported as loaded with
`save_size=0`.
Applications must version their own opaque payload to handle future upgrades.
The card may be removed while powered down; no FAT filesystem can guarantee
recovery after every power or media failure.

## Asset blob

Zero assets means an empty blob. Otherwise its first 12 bytes are ASCII
`EKASSET1`, `u16 count` (0–32), then zero `u16`. The next `count` entries are
20 bytes each:

| Offset | Type | Meaning |
| --- | --- | --- |
| 0 | `u16` | Nonzero ID, strictly increasing |
| 2 | `u16` | Flags: bit 0 makes RGB565 value 0 transparent; all others zero |
| 4, 6 | `u16` each | Width (1–280), height (1–456) |
| 8, 12 | `u32` each | Data offset and exact byte length (`width*height*2`) |
| 16 | `u32` | Zero |

Data is raw, row-major little-endian RGB565, with no per-row padding. Ranges
are ordered, disjoint, begin after the entry table, and end exactly at the
blob end. This permits background images, sprites and pre-rendered animation
frames without decoding in the Wasm guest.

## Wasm and input

The module has exactly one internally defined linear memory, no imports, no
start function, and three exported functions, all returning `i32` with no
arguments: `app_input_ptr`, `app_init`, `app_step`. `app_input_ptr` returns a
byte offset of a 4,160-byte mailbox in guest memory. Firmware writes the
mailbox before `app_init` and before each `app_step`. Guest code must not
change its address. `app_init` and `app_step` return offsets of command lists.
All values are little-endian. Wasm memory is limited to 2 MiB and each call
to 6,000,000 Wasm3 gas units.

Mailbox offsets are: `u32 abi` at 0 (always 4), `u32 now_ms` at 4 (active-app
monotonic time, paused by the firmware exit dialog), `u32 touch_count` at 8
(0–2), `u32 accel_valid` at 12. Contacts at 16 and 24 are each `i16 x`,
`i16 y`, `u16 controller_id`, `u16 zero`; coordinates are display pixels.
`i32 accel_x_mg`, `accel_y_mg`, `accel_z_mg` are at 32, 36, 40; raw board
axes, signed milli-g, valid only when `accel_valid=1`. `u32 save_status` at 44
is 0 (none), 1 (loaded), 2 (write succeeded), or 3 (write failed); `u32
save_size` at 48 is 0–4096. Bytes 52–63 are zero. Save data begins at 64.
On `app_init`, a valid `.save` arrives with status 1. A save result is sent
on the next step. No contact implies a release for contacts absent by ID.

## Output commands

At each returned offset: `u32 count`, followed by `count` 20-byte commands.
Each command has `u16 kind, flags, x, y, width, height; u32 arg0, arg1`.
Unknown kinds or nonzero reserved fields trap the app. All referenced guest
data and the complete list are validated before display or SD side effects.

| Kind | Fields | Action |
| --- | --- | --- |
| 1 RECT | flags=0, positive in-bounds rect, arg0=RGB565, arg1=0 | Fill host back buffer. |
| 2 PRESENT | flags=arg0=arg1=0, positive in-bounds rect | Copy the dirty region to the visible frame. |
| 3 BLIT | flags=width=height=arg1=0, arg0=asset ID | Blit asset at x,y, fully in bounds. |
| 4 TEXT | flags=RGB565, width=scale 1–3, height=0, arg0=guest offset, arg1=1–64 | Draw printable ASCII with the host's compact font. |
| 5 SAVE | flags=x=y=width=height=0, arg0=guest offset, arg1=0–4096 | Ask the host to write a sidecar payload. |
| 6 BLIT_REGION | flags=0, x/y destination, positive width/height, arg0=asset ID, arg1=`source_x | (source_y << 16)` | Draw a cropped part of an asset; source and destination must fit. |

The host accepts at most 512 drawing commands, 600,000 drawn pixels,
2 presents, 1 save, and 515 total commands per call. One full-screen present
is allowed; smaller dirty regions reduce copies. Saving is rate limited to
one write per second. The app should save on meaningful state changes, not
every frame. Touch and IMU samples are snapshots, not guaranteed interrupts.

The firmware's exit gesture and confirmation dialog always take precedence;
while that dialog is visible, app time and calls pause. The host owns all
hardware and can stop a malformed or over-budget guest. Graphics speed and
sensor cadence are device dependent; app physics should use `now_ms` with a
bounded fixed time step rather than assume a specific frame rate.
