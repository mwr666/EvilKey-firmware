<!-- SPDX-License-Identifier: MIT -->
# UI profile corner-exit-v1

Package revision 5 declares numeric profile 1 at header offset 288 (u16 LE).
Runtime ABI stays v4. The packer requires `--ui-profile corner-exit-v1`;
Python `encode_package` and `pack` require the corresponding explicit argument.

## Layout

On the 280x456 display reserve `[0,56) x [0,56)` for system input: no app
controls may react there. The larger hit area surrounds the visible 40x40
grip at (4,4). Reserve `[0,48) x [0,48)` for graphics: draw only background
in that smaller square. Place header labels and statistics at x>=50 or y>=48;
ensure their full bounding boxes clear the visual square. Noninteractive
labels may occupy the outer part of the touch zone. Keep right-hand pause
buttons if desired. Apply the rule to gameplay, menus and overlays alike.
Apps may clear or restore full images: the firmware grip is composited last.
The system owns the top panel during dragging and the confirmation overlay.

Example independent app constants (see `include/evilkey_app_abi.h`):

```c
const unsigned title_x = EVILKEY_APP_HEADER_CONTENT_X; /* 50 */
const unsigned title_y = 8;
/* Draw the app's own title/font at title_x,title_y. */
/* Pause remains on the right, e.g. x=236,y=4,w=40,h=40. */
/* Start gameplay below the header. Do not draw your own exit handle. */
```

## Input and time

A single fresh contact that begins in the 56x56 system touch square is withheld from
the app through release. Firmware pauses both app execution and `now_ms`.
After capture, the active drag region expands to the full display width
and the upper 160px (`0 <= y < 160`). Partial progress follows horizontal
travel and can decrease on backtracking; release below 100% cancels.
The progress bar reaches 100% after 90px rightward travel and then stays
armed through further movement, including the screen edge, vertical movement
and backtracking. Releasing the same contact opens YES/NO; release coordinates
do not erase completion. Before 100%, leaving the upper band cancels.
Another finger, a changed contact ID, or stale input always cancels, even
after 100%, and requires all fingers released before rearming or forwarding
another sequence. Expanding the active region does not reserve more app UI:
only a contact that started in the corner can enter this system gesture.

Touches begun elsewhere remain app-owned until all fingers lift, including
two-finger starts and sliders crossing the reserved square. The square is
not an obstacle to an app-owned drag. Firmware never takes over mid-drag.
NO resumes app time without catch-up; YES returns to the same Apps grid.
Apps retain their SAVE responsibilities; exiting does not guarantee a
pending write has completed. Credentials and NVS remain inaccessible.

## Author checklist

- Inspect every screen with 48x48 visual and 56x56 touch-zone guides.
- Confirm titles/HUD clear the visual zone and controls clear the touch zone.
- Test a slider beginning outside and crossing the corner.
- Test complete, short, vertical, multi-touch and cancelled gestures.
- Check NO, YES, pause/resume and app save/resume on the device.
- Declare the profile in the binary package and distribution manifest.

The declaration is checked by firmware; it is not an automated visual
audit. Private app sources need not be supplied to the firmware or packer.
