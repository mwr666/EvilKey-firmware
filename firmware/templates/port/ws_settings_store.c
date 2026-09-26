/* SPDX-License-Identifier: AGPL-3.0-or-later
 * M1 owns exactly wsdev / pf_manager / ui_v1. Never erases a partition,
 * touches a PIN budget, stores a PIN, or accesses the keystore namespaces. */
#include "ws_settings.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "nvs.h"
#include "esp_err.h"
#include <string.h>
static portMUX_TYPE s_guard=portMUX_INITIALIZER_UNLOCKED;
static SemaphoreHandle_t s_writer;
static ws_settings_t s_settings;
static bool s_initialized,s_storage_ok;
void ws_settings_init(void) {
    if(s_initialized)return;
    ws_settings_defaults(&s_settings);
    s_writer=xSemaphoreCreateMutex();
    nvs_handle_t h=0;
    esp_err_t e=nvs_open_from_partition("wsdev","pf_manager",NVS_READONLY,&h);
    s_storage_ok=e==ESP_ERR_NVS_NOT_FOUND;
    if(e==ESP_OK) {
        uint8_t data[WS_SETTINGS_WIRE_SIZE];size_t n=sizeof(data);
        e=nvs_get_blob(h,"ui_v1",data,&n);nvs_close(h);
        s_storage_ok=e==ESP_ERR_NVS_NOT_FOUND;
        if(e==ESP_OK)s_storage_ok=ws_settings_decode(data,n,&s_settings);
    }
    if(!s_writer)s_storage_ok=false;
    s_initialized=true;
}
void ws_settings_get(ws_settings_t *out,bool *storage_ok) {
    portENTER_CRITICAL(&s_guard);
    if(out)*out=s_settings;
    if(storage_ok)*storage_ok=s_storage_ok;
    portEXIT_CRITICAL(&s_guard);
}
ws_settings_result_t ws_settings_apply(const uint8_t *data,size_t len) {
    ws_settings_t next,current;
    if(!ws_settings_decode(data,len,&next))return WS_SETTINGS_INVALID;
    if(!s_initialized||!s_writer||xSemaphoreTake(s_writer,pdMS_TO_TICKS(500))!=pdTRUE)return WS_SETTINGS_STORAGE;
    ws_settings_get(&current,NULL);
    if(next.revision!=current.revision||current.revision==UINT32_MAX) {
        xSemaphoreGive(s_writer);return WS_SETTINGS_STALE;
    }
    next.revision++;
    uint8_t wire[WS_SETTINGS_WIRE_SIZE],check[WS_SETTINGS_WIRE_SIZE];
    ws_settings_encode(&next,wire);
    nvs_handle_t h=0;
    esp_err_t e=nvs_open_from_partition("wsdev","pf_manager",NVS_READWRITE,&h);
    if(e==ESP_OK) {
        e=nvs_set_blob(h,"ui_v1",wire,sizeof(wire));
        if(e==ESP_OK)e=nvs_commit(h);
        size_t n=sizeof(check);
        if(e==ESP_OK)e=nvs_get_blob(h,"ui_v1",check,&n);
        if(e==ESP_OK&&(n!=sizeof(wire)||memcmp(wire,check,n)))e=ESP_FAIL;
        nvs_close(h);
    }
    portENTER_CRITICAL(&s_guard);
    if(e==ESP_OK){s_settings=next;s_storage_ok=true;}
    else s_storage_ok=false;
    portEXIT_CRITICAL(&s_guard);
    xSemaphoreGive(s_writer);
    return e==ESP_OK?WS_SETTINGS_OK:WS_SETTINGS_STORAGE;
}
uint32_t ws_settings_presence_timeout_ms(void) {
    ws_settings_t s;ws_settings_get(&s,NULL);return (uint32_t)s.presence_seconds*1000U;
}
uint32_t ws_settings_uv_timeout_ms(void) {
    ws_settings_t s;ws_settings_get(&s,NULL);return (uint32_t)s.uv_seconds*1000U;
}
