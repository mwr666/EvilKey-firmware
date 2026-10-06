# EvilKey firmware 0.6.1

Apps and Settings now share identical orbit rings, highlight, light points,
brightness changes and the same 6.144-second cycle. Their original central
icons remain distinct. Animation OFF uses the same fixed composition.
This release retains the LVGL interface; the experimental Jet renderer is
not included. App ABI remains v4, package revision 5. Manager remains 1.1.6.

The owner accepted the exact BIN on PCB V1 on 2026-10-06. Application readback
was verified after installation through EvilKey.cmd on COM5; NVS, wsdev,
part0 and otadata hashes remained unchanged. No partition migration was
required. The changed rings passed 1024 host pixel comparisons; software
checks passed for Manager, GUI, flash installation and Ducky runtime.

BIN size: 2204448 bytes.
SHA-256: `90c0064a5e68e46e083307997374b13c4323d4d07c23c3f69a55a3a046a5c5b5`.

Use EvilKey.cmd for building and storage-preserving installation; see
[Build and flash](BUILD_AND_FLASH.md) and
[installation information](../firmware/INSTALLATION_INFORMATION.md).
Never use whole-flash erase to update a configured key.

**DEVELOPMENT ONLY:** no Secure Boot or encrypted flash/NVS provisioning;
credentials remain in unencrypted NVS. API restrictions are not demonstrated
hardware isolation. Android/console/native XInput compatibility and long-duration
endurance are not established. The 0.6.0 checks remain documented separately.

Firmware/GUI: AGPLv3 with upstream notices; ABI/SDK: MIT. Manager, original
examples, independent games and CAD remain separately licensed.
