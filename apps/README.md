# EvilKey Apps

Copy `<id>.ekapp` to **`/evilkey/apps/`** on a FAT32 microSD card.
Swipe left from Home to Apps, swipe up/down between the introduction and
3×3 icon pages, then tap an icon to launch. Swipe left again for Settings.
The Apps screen is skipped when no compatible packages are present.

Replacing the `.ekapp` updates an app; deleting it removes the app. No separate
installation step is required. `<id>.save` sits beside the package and stores
the app's requested bounded state; deleting the app does not remove its save.
App loading and saves do not access NVS or FIDO credentials.

## Format and SDK

Firmware 0.7.5 supports **ABI v4 and v5**, package revision **5**.
ABI v4 provides the base contract:
Wasm without imports, touch coordinates, accelerometer samples, drawing
commands, RGB565 assets and save requests. Packages require a UTF-8 name,
64×64 icon and `corner-exit-v1`. Older package revisions are rejected.
Firmware validates bounds and SHA-256 before launch.

- [Base ABI v4 specification](ABI_V4.md)
- [ABI v5 native Scene3D extension](ABI_V5.md)
- [MIT SDK and packaging](sdk/README.md)
- [Mandatory UI profile](sdk/UI_PROFILE.md)

The firmware owns the top-left 56×56 touch zone. Drag its grip right and release
at full progress to open YES/NO exit confirmation. After capture, the drag area
expands and completion stays latched. Touches starting elsewhere remain
app-owned, allowing sliders. App time pauses during the system gesture/dialog.



## Application licensing

EvilBlocks, EvilPinball, EvilBreaker, EvilInvaders and EvilRacer are independently licensed applications. Game source, bytecode, artwork and saves are not included in this public firmware repository or its releases. Firmware and GUI are AGPLv3; the ABI and SDK declarations retain MIT terms. Compatible app updates do not require firmware updates.

The ABI supports up to two contacts, but the tested PCB V1 panel currently reports only one. Build controls that remain usable with one finger. Bounds checks and API restrictions are an interpreter boundary, not demonstrated hardware isolation. A package digest detects corruption, not publisher authenticity.
