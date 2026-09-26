/* SPDX-License-Identifier: AGPL-3.0-or-later */
#pragma once
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "../FidoConfig.h"

#if FIDO_V1_USB_PROFILE == FIDO_PROFILE_YK5_FIDO_COMPAT
#define PF_USB_VID               0x1050
#define PF_USB_PID               0x0402
#define PF_USB_PRODUCT           "YubiKey 5 FIDO (EvilKey DEV)"
#define PF_USB_MANUFACTURER      "Yubico"
#define PF_USB_BCD_DEVICE        0x0543
#define PF_COMPAT_VERSION_MAJOR  5
#define PF_COMPAT_VERSION_MINOR  4
#define PF_COMPAT_VERSION_PATCH  3
#define PF_YK5_FIDO_COMPAT        1
#elif FIDO_V1_USB_PROFILE == FIDO_PROFILE_LOCAL_DEV
#define PF_USB_VID               0xFEFF
#define PF_USB_PID               0xFCFD
#define PF_USB_PRODUCT           "EvilKey Waveshare V1 DEV"
#define PF_USB_MANUFACTURER      "EvilKey development"
#define PF_USB_BCD_DEVICE        0x0100
#define PF_COMPAT_VERSION_MAJOR  8
#define PF_COMPAT_VERSION_MINOR  0
#define PF_COMPAT_VERSION_PATCH  0
#define PF_YK5_FIDO_COMPAT        0
#elif FIDO_V1_USB_PROFILE == FIDO_PROFILE_CUSTOM_USB
#define PF_USB_VID               FIDO_V1_CUSTOM_VID
#define PF_USB_PID               FIDO_V1_CUSTOM_PID
#define PF_USB_PRODUCT           FIDO_V1_CUSTOM_PRODUCT
#define PF_USB_MANUFACTURER      FIDO_V1_CUSTOM_MANUFACTURER
#define PF_USB_BCD_DEVICE        FIDO_V1_CUSTOM_BCD_DEVICE
#define PF_COMPAT_VERSION_MAJOR  8
#define PF_COMPAT_VERSION_MINOR  0
#define PF_COMPAT_VERSION_PATCH  0
#define PF_YK5_FIDO_COMPAT        0
#else
#error "Unknown FIDO_V1_USB_PROFILE"
#endif

#if PF_USB_VID <= 0 || PF_USB_VID >= 0xFFFF || PF_USB_PID <= 0 || PF_USB_PID >= 0xFFFF
#error "VID and PID must be nonzero 16-bit identifiers other than FFFF"
#endif
#if PF_USB_VID == 0x1050 && PF_USB_PID != 0x0402
#error "This FIDO-only port must not use a Yubico composite/CCID/OTP PID; use 0402"
#endif
#if PF_USB_BCD_DEVICE < 0 || PF_USB_BCD_DEVICE > 0x9999 || \
    (PF_USB_BCD_DEVICE & 0xF) > 9 || ((PF_USB_BCD_DEVICE >> 4) & 0xF) > 9 || \
    ((PF_USB_BCD_DEVICE >> 8) & 0xF) > 9 || ((PF_USB_BCD_DEVICE >> 12) & 0xF) > 9
#error "USB bcdDevice must contain four decimal BCD digits"
#endif
#if FIDO_V1_PRESENCE_TIMEOUT_SECONDS < 1 || FIDO_V1_PRESENCE_TIMEOUT_SECONDS > 120
#error "Presence timeout must be 1..120 seconds; zero does not mean auto-approve"
#endif
#if FIDO_V1_MANAGEMENT_SERIAL < 0 || FIDO_V1_MANAGEMENT_SERIAL > 99999999
#error "Management serial must be 0 (automatic) or 1..99999999"
#endif
#if (FIDO_V1_DISPLAY != 0 && FIDO_V1_DISPLAY != 1) || \
    (FIDO_V1_TOUCH_CONFIRM != 0 && FIDO_V1_TOUCH_CONFIRM != 1)
#error "Display and touch switches must be 0 or 1"
#endif
#if FIDO_V1_TOUCH_CONFIRM && !FIDO_V1_DISPLAY
#error "Touch approval requires the display"
#endif
#if FIDO_V1_BRIGHTNESS < 0 || FIDO_V1_BRIGHTNESS > 255
#error "Brightness must be 0..255"
#endif
#if FIDO_V1_DIM_AFTER_SECONDS < 0 || FIDO_V1_DIM_AFTER_SECONDS > 3600
#error "Idle dimming must be 0..3600 seconds"
#endif
#ifdef __cplusplus
static_assert(sizeof(PF_USB_PRODUCT) > 1 && sizeof(PF_USB_PRODUCT) <= 32,
              "Use a nonempty product string of at most 31 ASCII characters");
static_assert(sizeof(PF_USB_MANUFACTURER) > 1 && sizeof(PF_USB_MANUFACTURER) <= 32,
              "Use a nonempty manufacturer string of at most 31 ASCII characters");
#else
_Static_assert(sizeof(PF_USB_PRODUCT) > 1 && sizeof(PF_USB_PRODUCT) <= 32,
               "Use a nonempty product string of at most 31 ASCII characters");
_Static_assert(sizeof(PF_USB_MANUFACTURER) > 1 && sizeof(PF_USB_MANUFACTURER) <= 32,
               "Use a nonempty manufacturer string of at most 31 ASCII characters");
#endif

#define PF_PROFILE_CAPABILITIES 0x0202u /* U2F | FIDO2. No imaginary applets. */
#define PF_PROFILE_INFO_LENGTH 29u

/* Nonsecret ID; preserve the original management serial derivation. */
static inline uint32_t pf_profile_serial(const uint8_t id[4]) {
#if FIDO_V1_MANAGEMENT_SERIAL != 0
    (void)id;
    return (uint32_t)FIDO_V1_MANAGEMENT_SERIAL;
#else
    if (id == NULL) return 0;
    return (((uint32_t)id[0] << 24) | ((uint32_t)id[1] << 16) |
            ((uint32_t)id[2] << 8) | (uint32_t)id[3]) & UINT32_C(0x03FFFFFF);
#endif
}

/* Yubico Management read-info TLV payload (NOT a CTAP CBOR map).
 * No NFC/FIPS/SKY flags, certificates, or unsupported application capabilities.
 * No write-config emulation: applet/USB capabilities remain code-defined.
 */
static inline size_t pf_profile_build_management_info(
        uint8_t *out, size_t capacity, const uint8_t id[4]) {
    if (out == NULL || id == NULL || capacity < PF_PROFILE_INFO_LENGTH) return 0;
    const uint32_t serial = pf_profile_serial(id);
    const uint8_t data[PF_PROFILE_INFO_LENGTH] = {
        28,                              /* remaining payload length */
        0x01, 2, 0x02, 0x02,             /* supported: U2F and FIDO2 */
        0x02, 4, (uint8_t)(serial >> 24), (uint8_t)(serial >> 16),
                 (uint8_t)(serial >> 8), (uint8_t)serial,
        0x04, 1, 0x03,                   /* USB-C keychain; no certification flags */
        0x05, 3, PF_COMPAT_VERSION_MAJOR, PF_COMPAT_VERSION_MINOR, PF_COMPAT_VERSION_PATCH,
        0x03, 2, 0x02, 0x02,             /* enabled: same as supported */
        0x08, 1, 0x00,                   /* no remote wakeup/eject */
        0x0A, 1, 0x00                    /* no simulated configuration lock */
    };
    memcpy(out, data, sizeof(data));
    return sizeof(data);
}

/* Read-config supports page zero only. Return CTAPHID error codes. */
static inline int pf_profile_check_management_page(const uint8_t *data, size_t len) {
    if (len == 0) return 0; /* legacy empty page-zero request */
    if (data == NULL || len != 1) return 0x03; /* INVALID_LEN */
    return data[0] == 0 ? 0 : 0x02; /* INVALID_PARAMETER */
}
