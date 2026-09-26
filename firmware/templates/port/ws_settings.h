/* SPDX-License-Identifier: AGPL-3.0-or-later */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#define WS_SETTINGS_WIRE_SIZE 32U
#define WS_MANAGER_READ_ID UINT64_C(0x50464d3100000001)
#define WS_MANAGER_WRITE_ID UINT64_C(0x50464d3100000002)
#define WS_MANAGER_API_VERSION 1U
/* Fixed network-byte-order record, never a raw compiler struct. No secrets. */
typedef struct {
    uint8_t brightness, dim_brightness;
    bool animation;
    uint16_t dim_seconds, off_seconds, presence_seconds, uv_seconds;
    uint32_t accent_rgb, revision;
} ws_settings_t;
typedef enum {
    WS_SETTINGS_OK=0, WS_SETTINGS_INVALID=1, WS_SETTINGS_STALE=2,
    WS_SETTINGS_STORAGE=3
} ws_settings_result_t;
void ws_settings_defaults(ws_settings_t *out);
bool ws_settings_valid(const ws_settings_t *s);
bool ws_settings_decode(const uint8_t *data,size_t len,ws_settings_t *out);
void ws_settings_encode(const ws_settings_t *s,uint8_t out[WS_SETTINGS_WIRE_SIZE]);
/* Init after wsdev NVS has been initialized by the existing key backend. */
void ws_settings_init(void);
void ws_settings_get(ws_settings_t *out,bool *storage_ok);
/* Single authenticated settings transaction. The record's revision is the
 * expected PREVIOUS revision. A successful commit increments it by one. */
ws_settings_result_t ws_settings_apply(const uint8_t *data,size_t len);
uint32_t ws_settings_presence_timeout_ms(void);
uint32_t ws_settings_uv_timeout_ms(void);
