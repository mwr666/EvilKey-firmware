/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "ek_assets.h"
#include <string.h>

static uint16_t u16(const uint8_t *p) { return (uint16_t)(p[0] | ((uint16_t)p[1] << 8)); }
static uint32_t u32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

int ek_assets_parse(const uint8_t *data, size_t size, EkAssets *out) {
    static const uint8_t magic[8] = {'E','K','A','S','S','E','T','1'};
    if (!out) return 0;
    memset(out, 0, sizeof(*out));
    if (!size) return 1;
    if (!data || size < 12 || memcmp(data, magic, 8) ||
        u16(data + 10) || u16(data + 8) > EK_ASSETS_MAX_COUNT) return 0;
    uint16_t count = u16(data + 8);
    size_t table_end = 12 + (size_t)count * EK_ASSETS_ENTRY_BYTES;
    if (size < table_end || (count == 0 && size != table_end)) return 0;
    uint32_t previous_end = (uint32_t)table_end;
    for (uint16_t i = 0; i < count; ++i) {
        const uint8_t *entry = data + 12 + (size_t)i * EK_ASSETS_ENTRY_BYTES;
        uint16_t id = u16(entry), flags = u16(entry + 2);
        uint16_t width = u16(entry + 4), height = u16(entry + 6);
        uint32_t offset = u32(entry + 8), length = u32(entry + 12);
        if (!id || (i && id <= out->items[i - 1].id) || (flags & ~1u) ||
            !width || !height || width > 280 || height > 456 ||
            (uint32_t)width * height * 2u != length ||
            offset < previous_end || offset > size || length > size - offset ||
            u32(entry + 16) != 0) return 0;
        out->items[i].id = id;
        out->items[i].flags = flags;
        out->items[i].width = width;
        out->items[i].height = height;
        out->items[i].rgb565 = data + offset;
        previous_end = offset + length;
    }
    out->count = (uint8_t)count;
    return previous_end == size;
}

const EkAsset *ek_assets_find(const EkAssets *assets, uint16_t id) {
    if (!assets) return NULL;
    for (uint8_t i = 0; i < assets->count; ++i)
        if (assets->items[i].id == id) return &assets->items[i];
    return NULL;
}
