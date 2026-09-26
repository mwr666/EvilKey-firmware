#include "../../pf_build_config.h"
/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Optional Manager Drive preferences. These records are NOT secrets and never
 * contain FIDO key material, PIN data, credential metadata or card contents.
 */
#include "ws_manager_drive_state.h"
#include "nvs.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include <string.h>

#ifndef FIDO_V1_MANAGER_DRIVE_DEFAULT
#define FIDO_V1_MANAGER_DRIVE_DEFAULT 0
#endif
#ifndef FIDO_V1_MANAGER_DRIVE_READ_ONLY_DEFAULT
#define FIDO_V1_MANAGER_DRIVE_READ_ONLY_DEFAULT 0
#endif

static portMUX_TYPE s_guard=portMUX_INITIALIZER_UNLOCKED;
static SemaphoreHandle_t s_writer;
static bool s_initialized;
static bool s_enabled=FIDO_V1_MANAGER_DRIVE_DEFAULT!=0;
static bool s_read_only=FIDO_V1_MANAGER_DRIVE_READ_ONLY_DEFAULT!=0;
static bool s_storage_ok;

static bool read_flag(nvs_handle_t h,const char *key,bool *value)
{
    uint8_t v=0;esp_err_t e=nvs_get_u8(h,key,&v);
    if(e==ESP_ERR_NVS_NOT_FOUND)return true;
    if(e!=ESP_OK || v>1U)return false;
    *value=v!=0;return true;
}

void ws_manager_drive_state_init(void)
{
    if(s_initialized)return;
    s_writer=xSemaphoreCreateMutex();
    bool enabled=FIDO_V1_MANAGER_DRIVE_DEFAULT!=0;
    bool read_only=FIDO_V1_MANAGER_DRIVE_READ_ONLY_DEFAULT!=0;
    bool storage_ok=false;
    nvs_handle_t h=0;
    esp_err_t e=nvs_open_from_partition("wsdev","pf_manager",NVS_READONLY,&h);
    if(e==ESP_ERR_NVS_NOT_FOUND) {
        storage_ok=true;
    } else if(e==ESP_OK) {
        storage_ok=read_flag(h,"mdrive_v1",&enabled) &&
                   read_flag(h,"mdrive_ro1",&read_only);
        nvs_close(h);
    }
    if(!s_writer)storage_ok=false;
    portENTER_CRITICAL(&s_guard);
    s_enabled=enabled;s_read_only=read_only;s_storage_ok=storage_ok;s_initialized=true;
    portEXIT_CRITICAL(&s_guard);
}

bool ws_manager_drive_enabled(void)
{
    if(!s_initialized)ws_manager_drive_state_init();
    portENTER_CRITICAL(&s_guard);bool v=s_enabled;portEXIT_CRITICAL(&s_guard);
    return v;
}

bool ws_manager_drive_read_only(void)
{
    if(!s_initialized)ws_manager_drive_state_init();
    portENTER_CRITICAL(&s_guard);bool v=s_read_only;portEXIT_CRITICAL(&s_guard);
    return v;
}

bool ws_manager_drive_storage_ok(void)
{
    if(!s_initialized)ws_manager_drive_state_init();
    portENTER_CRITICAL(&s_guard);bool v=s_storage_ok;portEXIT_CRITICAL(&s_guard);
    return v;
}

static bool set_flag(const char *key,bool value,bool *cached)
{
    if(!s_initialized)ws_manager_drive_state_init();
    if(!s_writer || xSemaphoreTake(s_writer,pdMS_TO_TICKS(500))!=pdTRUE)return false;
    nvs_handle_t h=0;esp_err_t e=nvs_open_from_partition("wsdev","pf_manager",NVS_READWRITE,&h);
    if(e==ESP_OK) {
        e=nvs_set_u8(h,key,value?1U:0U);
        if(e==ESP_OK)e=nvs_commit(h);
        uint8_t verify=2U;
        if(e==ESP_OK)e=nvs_get_u8(h,key,&verify);
        if(e==ESP_OK && verify!=(value?1U:0U))e=ESP_FAIL;
        nvs_close(h);
    }
    portENTER_CRITICAL(&s_guard);
    if(e==ESP_OK){*cached=value;s_storage_ok=true;}
    else s_storage_ok=false;
    portEXIT_CRITICAL(&s_guard);
    xSemaphoreGive(s_writer);
    return e==ESP_OK;
}

bool ws_manager_drive_set_enabled(bool enabled)
{
    return set_flag("mdrive_v1",enabled,&s_enabled);
}

bool ws_manager_drive_set_read_only(bool read_only)
{
    return set_flag("mdrive_ro1",read_only,&s_read_only);
}

void ws_manager_drive_encode(uint8_t out[WS_MANAGER_DRIVE_WIRE_SIZE])
{
    if(!out)return;
    memset(out,0,WS_MANAGER_DRIVE_WIRE_SIZE);memcpy(out,"PFM2",4);out[4]=1;
    if(ws_manager_drive_read_only())out[5]=1U;
}

bool ws_manager_drive_decode(const uint8_t *data,size_t len,bool *read_only)
{
    if(!data||!read_only||len!=WS_MANAGER_DRIVE_WIRE_SIZE||memcmp(data,"PFM2",4)||data[4]!=1||data[5]>1U||data[6]||data[7])return false;
    *read_only=data[5]!=0;return true;
}
