/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "ek_package.h"
#include <string.h>

static uint16_t read16(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}
static uint32_t read32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

int ek_package_valid_id(const char *id) {
    if (!id) return 0;
    size_t len = 0;
    for (; len < EK_PACKAGE_ID_SIZE; ++len) {
        unsigned char c = (unsigned char)id[len];
        if (c == 0) break;
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
              c == '.' || c == '_' || c == '-')) return 0;
    }
    if (len == 0 || len >= EK_PACKAGE_ID_SIZE || id[0] == '.' ||
        id[len - 1] == '.' || strstr(id, "..")) return 0;
    return 1;
}

int ek_package_parse(const uint8_t *header, size_t header_size,
                     size_t total_size, EkPackageInfo *out) {
    static const uint8_t magic[8] = {'E','K','E','Y','A','P','P','1'};
    if (!header || !out || header_size < EK_PACKAGE_HEADER_SIZE ||
        total_size < EK_PACKAGE_HEADER_SIZE || total_size > EK_PACKAGE_MAX_BYTES ||
        memcmp(header, magic, sizeof(magic)) != 0 ||
        read16(header + 8) != EK_PACKAGE_HEADER_SIZE ||
        read16(header + 10) != 3 ||
        read16(header + 12) != EK_PACKAGE_API_VERSION ||
        read16(header + 14) != 0) return 0;
    for (unsigned i = 190; i < EK_PACKAGE_HEADER_SIZE; ++i)
        if (header[i] != 0) return 0;
    uint32_t wasm_size = read32(header + 54);
    uint32_t asset_size = read32(header + 186);
    if (wasm_size < 8 || wasm_size > EK_PACKAGE_MAX_WASM ||
        asset_size > EK_PACKAGE_MAX_ASSETS ||
        total_size != EK_PACKAGE_HEADER_SIZE + (size_t)wasm_size + asset_size) return 0;
    EkPackageInfo info;
    memcpy(info.id, header + 22, EK_PACKAGE_ID_SIZE);
    if (!memchr(info.id, 0, EK_PACKAGE_ID_SIZE) ||
        !ek_package_valid_id(info.id)) return 0;
    size_t id_len = strlen(info.id);
    for (size_t i = id_len + 1; i < EK_PACKAGE_ID_SIZE; ++i)
        if (info.id[i] != 0) return 0;
    memcpy(info.owner, header + 90, EK_PACKAGE_OWNER_SIZE);
    memcpy(info.license, header + 154, EK_PACKAGE_LICENSE_SIZE);
    /* Metadata is declared by the publisher, never treated as authentication. */
    const char *fields[] = {info.owner, info.license};
    const size_t lengths[] = {EK_PACKAGE_OWNER_SIZE, EK_PACKAGE_LICENSE_SIZE};
    for (size_t field = 0; field < 2; ++field) {
        const uint8_t *raw = header + (field == 0 ? 90 : 154);
        size_t n = 0;
        while (n < lengths[field] && raw[n] != 0) {
            if (raw[n] < 0x20 || raw[n] == 0x7f) return 0;
            if (field == 1 && raw[n] >= 0x80) return 0;
            ++n;
        }
        if (n == 0 || n == lengths[field] ||
            strlen(fields[field]) != n) return 0;
        for (size_t i = n + 1; i < lengths[field]; ++i)
            if (raw[i] != 0) return 0;
    }
    info.major = read16(header + 16);
    info.minor = read16(header + 18);
    info.patch = read16(header + 20);
    info.wasm_size = wasm_size;
    info.asset_size = asset_size;
    memcpy(info.sha256, header + 58, 32);
    *out = info;
    return 1;
}
