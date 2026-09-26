/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Minimal reader for the flat Hak5 USB Rubber Ducky language JSON files format.
 * No Hak5 data is embedded here; language files are read from microSD.
 */
#pragma once
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint8_t modifiers;
    uint8_t keycode;
    uint8_t valid;
} pf_hak5_key_t;

/* out_ascii covers U+0020..U+007E (95 printable ASCII characters).  The Hak5
 * language packs can contain additional UTF-8 keys; those are intentionally
 * ignored by this adapter because the pinned s3-ducky STRING engine is
 * byte/US-ASCII based. */
bool pf_hak5_parse_language_json(const char *json,size_t json_len,
                                 pf_hak5_key_t out_ascii[95],size_t *mapped_count,
                                 char *error,size_t error_len);

#ifdef __cplusplus
}
#endif
