<!-- SPDX-License-Identifier: MIT -->
# EvilKey Apps ABI v4

This is the independent app author contract. The small declarations in
[`sdk/include/evilkey_app_abi.h`](sdk/include/evilkey_app_abi.h) are MIT
licensed. Each app retains its own copyright and license. The firmware's
implementation is AGPL-3.0-or-later. An app has no access to FIDO credentials,
USB, NVS, native pointers, filesystem paths, or WASI.

## Single-file package and sidecar

Copy `<id>.ekapp` to `/evilkey/apps/` on FAT microSD. No install command is
needed. The ID must equal the filename stem. Package revision **5** embeds a
mandatory display name, launcher icon and UI profile **corner-exit-v1**.
**Runtime ABI remains v4**: exports, mailbox and commands keep their layout.
The touch routing contract below is mandatory. Older package revisions are
rejected; rebuild their UI before declaring the new profile.

The `EKEYAPP1` header is 320 bytes. Integers are unsigned little endian.
Strings must be nonempty, NUL terminated, and zero padded to their field size.
UTF-8 strings must be valid UTF-8 without control characters.

| Offset | Bytes | Field |
| --- | --- | --- |
| 0 | 8 | Magic `EKEYAPP1` |
| 8 | 2 | Header size: 320 |
| 10 | 2 | Package revision: 5 |
| 12 | 2 | Runtime ABI: 4 |
| 14 | 2 | Flags: zero |
| 16, 18, 20 | 2 each | Major, minor, patch |
| 22 | 32 | ID, restricted ASCII; also the `.save` filename stem |
| 54 | 4 | Wasm size, 8–65,536 bytes |
| 58 | 32 | SHA-256 of Wasm followed by the asset blob |
| 90 | 64 | Copyright owner, UTF-8 |
| 154 | 32 | License identifier, ASCII |
| 186 | 4 | Asset blob size, at most 1,048,576 bytes |
| 190 | 2 | Reserved: zero |
| 192 | 64 | Display name, UTF-8, at most 63 encoded bytes |
| 256 | 32 | SHA-256 of the icon |
| 288 | 2 | Required UI profile: 1 (`corner-exit-v1`) |
| 290 | 30 | Reserved: zero |
| 320 | 8,192 | Mandatory 64×64 opaque RGB565 icon, little endian |
| 8,512 | Wasm size | Wasm module |
| 8,512 + Wasm size | Asset size | Asset blob |

Exact file length is `8512 + wasm_size + asset_size`. The launcher reads only
headers in a single directory pass. It caches up to 64 apps and reads icons
only for the current page of nine. Excess valid apps are reported; navigation
does not silently wrap. Icon hashes are checked before enabling launch, and
the Wasm/asset digest is verified again before executing guest code. SHA-256
detects corruption, not publisher identity. Publisher names and licenses are
metadata, not authentication.

Create packages with `sdk/pack_ekapp.py --wasm program.wasm --output
evil.example.ekapp --id evil.example --owner "Your name" --license MIT
--version 1.0.0 --name "Example" --icon icon.rgb565 --assets assets.json
--ui-profile corner-exit-v1`.
The icon is mandatory even when the app has no sprites. The icon is not an
asset ID and consumes no guest memory or asset slot. A binary distribution
manifest includes `name`, `package_revision: 5`, `ui_profile: "corner-exit-v1"`,
and icon dimensions, format and SHA-256. The per-app copyright/license remain
independent of the firmware. A profile declaration is an author's assertion,
not proof that an arbitrary bitmap contains no important content in the zone.

## System corner and touch ownership (corner-exit-v1)

Display coordinates stay 280x456, with the origin at top left. Reserve
`0 <= x < 56, 0 <= y < 56` for firmware input: no app controls there.
The visible grip is 40x40 at (4,4). Reserve a separate 48x48 visual square
at the origin for background only: no labels, scores or essential artwork.
Noninteractive labels may occupy the outer touch margin. Begin header
content at x=50. Artwork and
full-screen clears may cover the square; firmware composites its grip last,
including after partial app presents. Apps must not implement a second copy
of the exit gesture or handle. See the MIT SDK constants and
[`sdk/UI_PROFILE.md`](sdk/UI_PROFILE.md) for the layout example.

At the beginning of an all-up-to-contact sequence, exactly one fresh contact
in the square belongs to firmware. Its entire sequence is withheld from the
app. Other starts, including initial two-finger contacts, belong to the app
until all fingers lift, even if a slider moves into or through the square.
Contact IDs are respected. Adding a finger to a firmware gesture, replacing
its ID or stale samples cancels it, including after completion. The
remaining contacts stay withheld until a fresh all-up sample; there is no
synthetic app press on cancellation.

After corner capture, the active band expands to the full display width
and upper 160px. Before completion, leaving that band or releasing early
cancels; horizontal backtracking reduces partial progress.
Drag right by 90px to latch 100%, then release, to open LEAVE APP? YES/NO.
Further movement towards the edge, vertical movement or backtracking cannot
erase completion. Zero coordinates in the release sample do not reset it.
Firmware shows a top progress
panel; it temporarily owns the display while dragging and confirming.
The VM and its active-app clock pause for the firmware-owned sequence and
confirmation. NO resumes without a time jump; YES returns to the same Apps
grid page. This does not promise a forced save on exit: apps still use SAVE
and handle its result as specified below. No app data is written to NVS.

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
