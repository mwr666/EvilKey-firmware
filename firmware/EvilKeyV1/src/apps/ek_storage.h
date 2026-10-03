/* SPDX-License-Identifier: AGPL-3.0-or-later */
#pragma once
#include <stddef.h>
#include <stdbool.h>
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
/* One directory pass; step inspects at most one entry. 1=package, 2=skip,
 * 0=end, -1=I/O error. No payloads or saves are read during enumeration. */
int ek_storage_scan_begin(void);
int ek_storage_scan_step(EkPackageInfo *info, bool *header_read);
void ek_storage_scan_end(void);
int ek_storage_icon(const EkPackageInfo *info, uint8_t *rgb565, size_t capacity);
int ek_storage_load(const char *id, uint8_t **payload, size_t *wasm_size,
                    size_t *asset_size);
/* Returns 1 for a valid record (including an empty payload), 0 otherwise. */
int ek_storage_save_load(const char *id, uint8_t *out, size_t capacity,
                         size_t *out_size);
enum { EK_SAVE_PROBE=1, EK_SAVE_CREATE=2, EK_SAVE_ALLOC=3,
       EK_SAVE_OPEN=4, EK_SAVE_SCAN=5, EK_SAVE_PREPARE=6,
       EK_SAVE_WRITE=7, EK_SAVE_FLUSH=8 };
typedef void (*EkStorageSaveTrace)(void *user, unsigned phase);
int ek_storage_save_write(const char *id, const uint8_t *data, size_t size,
                          EkStorageSaveTrace trace, void *trace_user);
const char *ek_storage_error(void);

#ifdef __cplusplus
}
#endif
