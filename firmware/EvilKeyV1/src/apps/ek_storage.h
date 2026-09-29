/* SPDX-License-Identifier: AGPL-3.0-or-later */
#pragma once
#include <stddef.h>
#include <stdint.h>
#include "ek_package.h"
#ifdef __cplusplus
extern "C" {
#endif

/* Read-only package access from the single Apps worker. No NVS or internal
 * flash operations exist in this module. */
int ek_storage_begin(void);
void ek_storage_end(void);
int ek_storage_entry(unsigned index, EkPackageInfo *info);
int ek_storage_load(const char *id, uint8_t **bytecode, size_t *size);
const char *ek_storage_error(void);

#ifdef __cplusplus
}
#endif
