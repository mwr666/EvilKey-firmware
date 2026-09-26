# Manager Drive and microSD

The optional Manager Drive exposes the onboard microSD card as USB Mass Storage alongside FIDO HID. It is controlled on the device in **SETTINGS → USB & STORAGE**. Manager Drive is off by default; when enabled, the default card mode is read/write so files such as `EvilKeyManager.exe` can be copied without a separate card reader.

To use it, insert a FAT32 microSD card, open Settings from READY or STANDBY with a left swipe, move to USB & Storage, and enable USB Mass Storage. The key restarts USB for the new profile. Wait for host writes to finish before enabling read-only mode or ejecting the volume.

The **READ ONLY → READ/WRITE** transition requires the current FIDO PIN entered on the device. The opposite transition and Mass Storage on/off do not require a PIN. Invalid PIN, cancellation, timeout, or exhausted attempts leave the card read-only. The local PIN operation clears its working secrets and does not create a reusable UV token session.

Configuration keys are `mdrive_v1` for MSC enablement and `mdrive_ro1` for read-only state. The default source settings are `FIDO_V1_MANAGER_DRIVE_DEFAULT=0` and `FIDO_V1_MANAGER_DRIVE_READ_ONLY_DEFAULT=0`. Enabling Manager Drive or USB Tool changes the USB role and requires re-enumeration; they are mutually exclusive.
