/* SPDX-License-Identifier: AGPL-3.0-or-later */
#pragma once
/* User configuration. Change this file, then Verify and Upload.
 * No preparation rerun is needed after changing these settings.
 * This remains the unencrypted-NVS DEVELOPMENT branch, not secure 0.3.x.
 */
#define FIDO_PROFILE_LOCAL_DEV       0
#define FIDO_PROFILE_YK5_FIDO_COMPAT  1
#define FIDO_PROFILE_CUSTOM_USB      2

#ifndef FIDO_V1_USB_PROFILE
#define FIDO_V1_USB_PROFILE FIDO_PROFILE_CUSTOM_USB
#endif
/* YK5_FIDO_COMPAT: local interoperability testing only.
 * USB 1050:0402 (FIDO ONLY), CTAPHID_INIT/management compatibility version 5.4.3.
 * This is NOT Yubico firmware, genuine attestation, or a full YubiKey 5.
 * FIDO GetInfo/AAGUID remain those of the pinned Pico FIDO engine.
 * Authenticator OATH/TOTP, OTP, PIV, OpenPGP, CCID and NFC are NOT implemented.
 */

/* Used only by CUSTOM_USB. Local defaults are not registered distribution IDs. */
#ifndef FIDO_V1_CUSTOM_VID
#define FIDO_V1_CUSTOM_VID          0xFEFF
#endif
#ifndef FIDO_V1_CUSTOM_PID
#define FIDO_V1_CUSTOM_PID          0xFCFD
#endif
#ifndef FIDO_V1_CUSTOM_PRODUCT
#define FIDO_V1_CUSTOM_PRODUCT      "EvilKey Waveshare V1 DEV"
#endif
#ifndef FIDO_V1_CUSTOM_MANUFACTURER
#define FIDO_V1_CUSTOM_MANUFACTURER "EvilKey development"
#endif
#ifndef FIDO_V1_CUSTOM_BCD_DEVICE
#define FIDO_V1_CUSTOM_BCD_DEVICE   0x0100
#endif

/* Optional microSD Manager Drive. The feature is compiled in, but remains OFF
 * by default. Toggling it from the READY screen stores only a non-secret flag
 * and restarts the device so USB can enumerate with/without MSC cleanly.
 *
 * IMPORTANT: the composite FIDO+MSC mode intentionally uses a separate local
 * development VID/PID instead of impersonating the Yubico FIDO-only PID.
 * These defaults are for local development, not registered distribution IDs. */
#ifndef FIDO_V1_MANAGER_DRIVE
#define FIDO_V1_MANAGER_DRIVE            1
#endif
#ifndef FIDO_V1_MANAGER_DRIVE_DEFAULT
#define FIDO_V1_MANAGER_DRIVE_DEFAULT    0
#endif
#ifndef FIDO_V1_MANAGER_DRIVE_READ_ONLY_DEFAULT
#define FIDO_V1_MANAGER_DRIVE_READ_ONLY_DEFAULT 0 /* 0 = read/write by default */
#endif
#ifndef FIDO_V1_MANAGER_DRIVE_SD_HZ
#define FIDO_V1_MANAGER_DRIVE_SD_HZ      20000000UL
#endif
#ifndef FIDO_V1_MANAGER_DRIVE_VID
#define FIDO_V1_MANAGER_DRIVE_VID        0xFEFF
#endif
#ifndef FIDO_V1_MANAGER_DRIVE_PID
#define FIDO_V1_MANAGER_DRIVE_PID        0xFCFC
#endif
#ifndef FIDO_V1_MANAGER_DRIVE_PRODUCT
#define FIDO_V1_MANAGER_DRIVE_PRODUCT    "EvilKey + Manager DEV"
#endif
#ifndef FIDO_V1_MANAGER_DRIVE_MANUFACTURER
#define FIDO_V1_MANAGER_DRIVE_MANUFACTURER "EvilKey development"
#endif
#ifndef FIDO_V1_MANAGER_DRIVE_BCD_DEVICE
#define FIDO_V1_MANAGER_DRIVE_BCD_DEVICE 0x0101
#endif

/* Optional locally-triggered USB automation role. This role is mutually
 * exclusive with FIDO/Manager Drive at enumeration time and uses a distinct
 * local-development USB identity. Payloads never auto-run on cable insertion. */
#ifndef FIDO_V1_USB_TOOL
#define FIDO_V1_USB_TOOL                 1
#endif
#ifndef FIDO_V1_USB_TOOL_DEFAULT
#define FIDO_V1_USB_TOOL_DEFAULT         0
#endif
#ifndef FIDO_V1_USB_TOOL_VARIABLE_EXFIL
#define FIDO_V1_USB_TOOL_VARIABLE_EXFIL  1
#endif
#ifndef FIDO_V1_USB_TOOL_KEYSTROKE_REFLECTION
#define FIDO_V1_USB_TOOL_KEYSTROKE_REFLECTION 1
#endif
#ifndef FIDO_V1_USB_TOOL_LAYOUT_DEFAULT
#define FIDO_V1_USB_TOOL_LAYOUT_DEFAULT  0 /* 0 US, 1 PL Programmer, 2 DE, 3 FR, 4 ES */
#endif
#ifndef FIDO_V1_USB_TOOL_LANGUAGE_DEFAULT
#define FIDO_V1_USB_TOOL_LANGUAGE_DEFAULT "us" /* Hak5 code or built-in pl-programmer */
#endif
#ifndef FIDO_V1_USB_TOOL_SD_HZ
#define FIDO_V1_USB_TOOL_SD_HZ           20000000UL
#endif
#ifndef FIDO_V1_USB_TOOL_MAX_PAYLOAD
#define FIDO_V1_USB_TOOL_MAX_PAYLOAD     262144U
#endif
#ifndef FIDO_V1_USB_TOOL_VID
#define FIDO_V1_USB_TOOL_VID             0xFEFF
#endif
#ifndef FIDO_V1_USB_TOOL_PID
#define FIDO_V1_USB_TOOL_PID             0xFCFB
#endif
#ifndef FIDO_V1_USB_TOOL_PRODUCT
#define FIDO_V1_USB_TOOL_PRODUCT         "EvilKey USB Tool DEV"
#endif
#ifndef FIDO_V1_USB_TOOL_MANUFACTURER
#define FIDO_V1_USB_TOOL_MANUFACTURER    "EvilKey development"
#endif
#ifndef FIDO_V1_USB_TOOL_BCD_DEVICE
#define FIDO_V1_USB_TOOL_BCD_DEVICE      0x0102
#endif

/* Air Mouse is a one-shot software-reset USB role. It is never persisted in
 * NVS and has a distinct local-development identity and mouse-only HID shape. */
#define FIDO_V1_AIR_MOUSE_VID            0xFEFF
#define FIDO_V1_AIR_MOUSE_PID            0xFCFA
#define FIDO_V1_AIR_MOUSE_BCD_DEVICE     0x0103
#define FIDO_V1_AIR_MOUSE_PRODUCT        "EvilKey Air Mouse DEV"
#define FIDO_V1_AIR_MOUSE_MANUFACTURER   "EvilKey development"

/* Management serial: 0 = deterministic existing Pico serial (default).
 * A nonzero value is a LOCAL TEST number, never a genuine Yubico serial.
 * This setting does not change key material or the USB iSerial string.
 */
#ifndef FIDO_V1_MANAGEMENT_SERIAL
#define FIDO_V1_MANAGEMENT_SERIAL 0
#endif

/* Display and user presence. A fresh physical action remains mandatory. */
#ifndef FIDO_V1_DISPLAY
#define FIDO_V1_DISPLAY             1
#endif
#ifndef FIDO_V1_TOUCH_CONFIRM
#define FIDO_V1_TOUCH_CONFIRM       1
#endif
#ifndef FIDO_V1_BRIGHTNESS
#define FIDO_V1_BRIGHTNESS         90  /* 8..255 */
#endif
#ifndef FIDO_V1_DIM_AFTER_SECONDS
#define FIDO_V1_DIM_AFTER_SECONDS  30  /* 0 disables idle dimming */
#endif
#ifndef FIDO_V1_PRESENCE_TIMEOUT_SECONDS
#define FIDO_V1_PRESENCE_TIMEOUT_SECONDS 30  /* 1..120, never auto-approve */
#endif

/* Deliberately no ENABLE_OATH/CCID/PIV/OTP or SECURE_BOOT switches:
 * a #define cannot add missing protocols or provision secure firmware.
 * FIDO PIN and resident credentials are configured with a FIDO client,
 * not by putting passwords, account secrets or private keys in this file.
 */

/* Touch verification: PIN remains the existing FIDO PIN, never put it here.
 * Numeric on-device keypad supports 4..63 digits. Set/change PIN via the host.
 * Host ClientPIN remains available for setup/recovery/older clients. */
#ifndef FIDO_V1_LOCAL_UV
#define FIDO_V1_LOCAL_UV                1
#endif
#ifndef FIDO_V1_BOOT_CONFIRM_FALLBACK
#define FIDO_V1_BOOT_CONFIRM_FALLBACK   0
#endif
#ifndef FIDO_V1_UV_TIMEOUT_SECONDS
#define FIDO_V1_UV_TIMEOUT_SECONDS    120
#endif

/* Visual settings only; neither changes PIN verification nor USB profiles.
 * Mint 0x4DE3C1, ice blue 0x70B8FF, amber 0xF6C46B. */
#ifndef FIDO_V1_GUI_ACCENT_RGB
#define FIDO_V1_GUI_ACCENT_RGB 0x4DE3C1UL
#endif
#ifndef FIDO_V1_GUI_ANIMATION
#define FIDO_V1_GUI_ANIMATION 1
#endif

/* Defaults for the authenticated M1 display settings service. Persisted runtime
 * settings take precedence; changing these values does not erase that record. */
#ifndef FIDO_V1_DIM_BRIGHTNESS
#define FIDO_V1_DIM_BRIGHTNESS 8
#endif
#ifndef FIDO_V1_OFF_AFTER_DIM_SECONDS
#define FIDO_V1_OFF_AFTER_DIM_SECONDS 60
#endif
