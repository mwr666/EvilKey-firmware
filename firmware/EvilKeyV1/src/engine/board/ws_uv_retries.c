#include "../../pf_build_config.h"
/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "ws_uv_retries.h"
#include "ws_pinpad.h"
#include "nvs.h"
#include "esp_err.h"
#include <stddef.h>
/* Record holds only a version and attempt budget, NOT a PIN or PIN hash.
 * NVS atomic commit/CRC are used. This does NOT resist external Flash rewrites
 * in the deliberately unsecured 0.2.x development profile. */
static bool store(uint8_t attempts) {
    nvs_handle_t h=0;
    if(nvs_open_from_partition("wsdev","ws_touch_uv",NVS_READWRITE,&h)!=ESP_OK) return false;
    const uint8_t record[3]={1,attempts,(uint8_t)(attempts^0xA5)};
    esp_err_t e=nvs_set_blob(h,"budget",record,sizeof(record));
    if(e==ESP_OK) e=nvs_commit(h);
    nvs_close(h);return e==ESP_OK;
}
int ws_uv_retries_get(void) {
    nvs_handle_t h=0;
    if(nvs_open_from_partition("wsdev","ws_touch_uv",NVS_READWRITE,&h)!=ESP_OK) return -1;
    uint8_t r[3]={0};size_t n=sizeof(r);
    esp_err_t e=nvs_get_blob(h,"budget",r,&n);
    nvs_close(h);
    if(e==ESP_ERR_NVS_NOT_FOUND) return store(WS_PIN_RETRY_MAX)?(int)WS_PIN_RETRY_MAX:-1;
    if(e!=ESP_OK || n!=sizeof(r) || r[0]!=1 || r[1]>WS_PIN_RETRY_MAX || r[2]!=(uint8_t)(r[1]^0xA5)) return -1;
    return r[1];
}
bool ws_uv_retries_reserve(void) {
    int n=ws_uv_retries_get();return n>0 && store((uint8_t)(n-1));
}
bool ws_uv_retries_reset(void) {
    /* Validate existing record: do not silently repair malformed storage. */
    if(ws_uv_retries_get()<0) return false;
    return store(WS_PIN_RETRY_MAX);
}
