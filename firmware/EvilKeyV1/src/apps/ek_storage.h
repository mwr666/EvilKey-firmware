/* SPDX-License-Identifier: AGPL-3.0-or-later */
#pragma once
#include <stddef.h>
#include <stdint.h>
#include "ek_package.h"
#include "evilkey_app_abi.h"
#ifdef __cplusplus
extern "C" {
#endif

/* Package and per-app sidecar access from the single Apps worker. No NVS or
 * internal flash operations exist in this module. */
int ek_storage_begin(void);
void ek_storage_end(void);
int ek_storage_entry(unsigned index, EkPackageInfo *info);
int ek_storage_load(const char *id, uint8_t **payload, size_t *wasm_size,
                    size_t *asset_size);
/* Returns 1 for a valid record (including an empty payload), 0 otherwise. */
int ek_storage_save_load(const char *id, uint8_t *out, size_t capacity,
                         size_t *out_size);
int ek_storage_save_write(const char *id, const uint8_t *data, size_t size);
const char *ek_storage_error(void);

#ifdef __cplusplus
}
#endif
