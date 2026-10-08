# Manager Drive and microSD

Manager Drive exposes a FAT32 microSD card as USB Mass Storage alongside FIDO
HID. It is **off by default**. When enabled, the default card mode is read/write
so files can be copied without a separate reader.

## Enable storage

1. Insert the card and open **Settings → USB & Storage**.
2. Enable USB Mass Storage. USB restarts with the new profile.
3. Wait for host writes to finish before changing card mode or ejecting it.

From Home, swipe left to Apps, then left to Settings; when Apps is empty,
Home opens Settings directly. Manager Drive and USB Tool are mutually exclusive.

## Read-only protection

| Transition | Authorization |
| --- | --- |
| READ ONLY → READ/WRITE | Current FIDO PIN entered on the device |
| READ/WRITE → READ ONLY | No PIN required |
| Mass Storage on/off | No PIN required |

Invalid PIN, cancellation, timeout or exhausted attempts leave the card
read-only. The local PIN check clears working secrets and does not create a
reusable FIDO UV token. See [on-device PIN](ON_DEVICE_PIN.md).

## Configuration reference

`mdrive_v1` stores MSC enablement; `mdrive_ro1` stores read-only state.
Source defaults are `FIDO_V1_MANAGER_DRIVE_DEFAULT=0` and
`FIDO_V1_MANAGER_DRIVE_READ_ONLY_DEFAULT=0`. USB role changes require
re-enumeration. Finish storage operations before switching roles.
