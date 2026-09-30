/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef EVILKEY_APPS_PACKAGE_H
#define EVILKEY_APPS_PACKAGE_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

enum {
    EK_PACKAGE_HEADER_SIZE = 192,
    EK_PACKAGE_ID_SIZE = 32,
    EK_PACKAGE_OWNER_SIZE = 64,
    EK_PACKAGE_LICENSE_SIZE = 32,
    EK_PACKAGE_API_VERSION = 4,
    EK_PACKAGE_MAX_WASM = 65536,
    EK_PACKAGE_MAX_ASSETS = 1024 * 1024,
    EK_PACKAGE_MAX_BYTES = EK_PACKAGE_HEADER_SIZE + EK_PACKAGE_MAX_WASM + EK_PACKAGE_MAX_ASSETS
};

typedef struct {
    char id[EK_PACKAGE_ID_SIZE];
    char owner[EK_PACKAGE_OWNER_SIZE];
    char license[EK_PACKAGE_LICENSE_SIZE];
    uint16_t major, minor, patch;
    uint32_t wasm_size;
    uint32_t asset_size;
    uint8_t sha256[32];
} EkPackageInfo;

/* Header and total length validation. The caller must also verify SHA-256. */
int ek_package_parse(const uint8_t *header, size_t header_size,
                     size_t total_size, EkPackageInfo *out);
int ek_package_valid_id(const char *id);

#ifdef __cplusplus
}
#endif
#endif
