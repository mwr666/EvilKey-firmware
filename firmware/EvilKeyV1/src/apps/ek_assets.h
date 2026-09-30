/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef EVILKEY_APPS_ASSETS_H
#define EVILKEY_APPS_ASSETS_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

enum { EK_ASSETS_MAX_COUNT = 32, EK_ASSETS_ENTRY_BYTES = 20 };
typedef struct {
    uint16_t id, flags, width, height;
    const uint8_t *rgb565;
} EkAsset;
typedef struct {
    uint8_t count;
    EkAsset items[EK_ASSETS_MAX_COUNT];
} EkAssets;

/* The backing bytes must outlive the parsed asset table. All offsets and
 * dimensions are checked before any pixels can reach the display. */
int ek_assets_parse(const uint8_t *data, size_t size, EkAssets *out);
const EkAsset *ek_assets_find(const EkAssets *assets, uint16_t id);
#ifdef __cplusplus
}
#endif
#endif
