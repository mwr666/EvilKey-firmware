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
static int valid_utf8(const uint8_t *p,size_t n) {
    for(size_t i=0;i<n;) {
        uint32_t cp;unsigned more;uint8_t c=p[i++];
        if(c<0x80) {if(c<0x20 || c==0x7f) return 0;continue;}
        if(c>=0xc2 && c<=0xdf) {cp=c&31;more=1;}
        else if(c>=0xe0 && c<=0xef) {cp=c&15;more=2;}
        else if(c>=0xf0 && c<=0xf4) {cp=c&7;more=3;}
        else return 0;
        if(i+more>n) return 0;
        unsigned width=more;
        while(more--) {c=p[i++];if((c&0xc0)!=0x80) return 0;cp=(cp<<6)|(c&63);}
        if((width==1 && cp<0x80) || (width==2 && cp<0x800) ||
           (width==3 && cp<0x10000) || cp>0x10ffff ||
           (cp>=0xd800 && cp<=0xdfff) || (cp>=0x80 && cp<=0x9f)) return 0;
    }
    return 1;
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
        read16(header + 10) != EK_PACKAGE_FORMAT_VERSION ||
        read16(header + 12) != EK_PACKAGE_API_VERSION ||
        read16(header + 14) != 0 ||
        read16(header + 288) != EK_PACKAGE_UI_PROFILE) return 0;
    for (unsigned i = 190; i < 192; ++i)
        if (header[i] != 0) return 0;
    for (unsigned i = 290; i < EK_PACKAGE_HEADER_SIZE; ++i)
        if (header[i] != 0) return 0;
    uint32_t wasm_size = read32(header + 54);
    uint32_t asset_size = read32(header + 186);
    if (wasm_size < 8 || wasm_size > EK_PACKAGE_MAX_WASM ||
        asset_size > EK_PACKAGE_MAX_ASSETS ||
        total_size != EK_PACKAGE_PAYLOAD_OFFSET + (size_t)wasm_size + asset_size) return 0;
    EkPackageInfo info;
    memcpy(info.id, header + 22, EK_PACKAGE_ID_SIZE);
    if (!memchr(info.id, 0, EK_PACKAGE_ID_SIZE) ||
        !ek_package_valid_id(info.id)) return 0;
    size_t id_len = strlen(info.id);
    for (size_t i = id_len + 1; i < EK_PACKAGE_ID_SIZE; ++i)
        if (info.id[i] != 0) return 0;
    memcpy(info.owner, header + 90, EK_PACKAGE_OWNER_SIZE);
    memcpy(info.license, header + 154, EK_PACKAGE_LICENSE_SIZE);
    memcpy(info.name, header + 192, EK_PACKAGE_NAME_SIZE);
    memcpy(info.icon_sha256, header + 256, 32);
    /* Metadata is declared by the publisher, never treated as authentication. */
    const char *fields[] = {info.owner, info.license, info.name};
    const size_t lengths[] = {EK_PACKAGE_OWNER_SIZE, EK_PACKAGE_LICENSE_SIZE, EK_PACKAGE_NAME_SIZE};
    for (size_t field = 0; field < 3; ++field) {
        const uint8_t *raw = header + (field == 0 ? 90 : field == 1 ? 154 : 192);
        size_t n = 0;
        while (n < lengths[field] && raw[n] != 0) {
            if (raw[n] < 0x20 || raw[n] == 0x7f) return 0;
            if (field == 1 && raw[n] >= 0x80) return 0;
            ++n;
        }
        if (n == 0 || n == lengths[field] ||
            strlen(fields[field]) != n) return 0;
        if(!valid_utf8(raw,n)) return 0;
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
