/* SPDX-License-Identifier: AGPL-3.0-or-later */
#pragma once
/* PF_FIRMWARE_VERSION_FIX_R2
 * Canonical EvilKey port version used by CTAP GetInfo and M1 manager replies.
 * CTAP firmwareVersion is vendor-defined uint32. Layout used here:
 *   0xMMmmppbb = major.minor.patch.build
 * The textual M1 value may additionally carry PF_FIRMWARE_VERSION_SUFFIX.
 */
#define PF_FIRMWARE_VERSION_MAJOR  0
#define PF_FIRMWARE_VERSION_MINOR  4
#define PF_FIRMWARE_VERSION_PATCH  0
#define PF_FIRMWARE_VERSION_BUILD  0
#define PF_FIRMWARE_VERSION_SUFFIX ""

#if PF_FIRMWARE_VERSION_MAJOR < 0 || PF_FIRMWARE_VERSION_MAJOR > 255 || \
    PF_FIRMWARE_VERSION_MINOR < 0 || PF_FIRMWARE_VERSION_MINOR > 255 || \
    PF_FIRMWARE_VERSION_PATCH < 0 || PF_FIRMWARE_VERSION_PATCH > 255 || \
    PF_FIRMWARE_VERSION_BUILD < 0 || PF_FIRMWARE_VERSION_BUILD > 255
#error "EvilKey firmware version components must fit in one byte"
#endif

#define PF_FW_STR_INNER(x) #x
#define PF_FW_STR(x) PF_FW_STR_INNER(x)
#define PF_FIRMWARE_VERSION_STRING \
    PF_FW_STR(PF_FIRMWARE_VERSION_MAJOR) "." \
    PF_FW_STR(PF_FIRMWARE_VERSION_MINOR) "." \
    PF_FW_STR(PF_FIRMWARE_VERSION_PATCH) PF_FIRMWARE_VERSION_SUFFIX

#define PF_FIRMWARE_VERSION_U32 \
    ((((PF_FIRMWARE_VERSION_MAJOR) & 0xFFUL) << 24) | \
     (((PF_FIRMWARE_VERSION_MINOR) & 0xFFUL) << 16) | \
     (((PF_FIRMWARE_VERSION_PATCH) & 0xFFUL) << 8)  | \
     (((PF_FIRMWARE_VERSION_BUILD) & 0xFFUL)))
