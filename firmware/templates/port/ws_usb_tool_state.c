/* SPDX-License-Identifier: AGPL-3.0-or-later
 * PicoFido USB Tool non-secret preferences. No payload contents, FIDO keys,
 * credentials or PIN data are persisted here.
 */
#include "ws_usb_tool_state.h"
#include "nvs.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include <string.h>
#include <ctype.h>

#ifndef FIDO_V1_USB_TOOL_DEFAULT
#define FIDO_V1_USB_TOOL_DEFAULT 0
#endif
#ifndef FIDO_V1_USB_TOOL_LAYOUT_DEFAULT
#define FIDO_V1_USB_TOOL_LAYOUT_DEFAULT WS_USB_LAYOUT_US
#endif
#ifndef FIDO_V1_USB_TOOL_LANGUAGE_DEFAULT
#define FIDO_V1_USB_TOOL_LANGUAGE_DEFAULT "us"
#endif

static portMUX_TYPE s_guard=portMUX_INITIALIZER_UNLOCKED;
static SemaphoreHandle_t s_writer;
static bool s_initialized;
static bool s_enabled=FIDO_V1_USB_TOOL_DEFAULT!=0;
static ws_usb_layout_t s_layout=(ws_usb_layout_t)FIDO_V1_USB_TOOL_LAYOUT_DEFAULT;
static char s_language_code[WS_USB_LANGUAGE_CODE_MAX]=FIDO_V1_USB_TOOL_LANGUAGE_DEFAULT;
static bool s_storage_ok;


static const char *layout_default_code(uint8_t layout)
{
    switch((ws_usb_layout_t)layout) {
    case WS_USB_LAYOUT_PL_PROGRAMMER:return "pl-programmer";
    case WS_USB_LAYOUT_DE:return "de";
    case WS_USB_LAYOUT_FR:return "fr";
    case WS_USB_LAYOUT_ES:return "es";
    case WS_USB_LAYOUT_US:default:return "us";
    }
}

static bool valid_language_code(const char *code)
{
    if(!code||!*code)return false;size_t n=strlen(code);
    if(n>=WS_USB_LANGUAGE_CODE_MAX)return false;
    for(size_t i=0;i<n;++i) {unsigned char c=(unsigned char)code[i];
        if(!(isalnum(c)||c=='-'||c=='_'))return false;
    }
    return true;
}

static bool read_str(nvs_handle_t h,const char *key,char *out,size_t out_len,bool *found)
{
    if(found)*found=false;size_t need=0;esp_err_t e=nvs_get_str(h,key,NULL,&need);
    if(e==ESP_ERR_NVS_NOT_FOUND)return true;
    if(e!=ESP_OK||need==0||need>out_len)return false;
    e=nvs_get_str(h,key,out,&need);if(e!=ESP_OK)return false;
    if(found)*found=true;return valid_language_code(out);
}
static bool read_u8(nvs_handle_t h,const char *key,uint8_t *value)
{
    uint8_t v=0;esp_err_t e=nvs_get_u8(h,key,&v);
    if(e==ESP_ERR_NVS_NOT_FOUND)return true;
    if(e!=ESP_OK)return false;
    *value=v;return true;
}

void ws_usb_tool_state_init(void)
{
    if(s_initialized)return;
    s_writer=xSemaphoreCreateMutex();
    uint8_t enabled=FIDO_V1_USB_TOOL_DEFAULT?1U:0U;
    uint8_t layout=(uint8_t)FIDO_V1_USB_TOOL_LAYOUT_DEFAULT;
    char language[WS_USB_LANGUAGE_CODE_MAX]={0};
    strncpy(language,FIDO_V1_USB_TOOL_LANGUAGE_DEFAULT,sizeof(language)-1U);
    bool language_found=false;
    bool storage_ok=false;
    nvs_handle_t h=0;
    esp_err_t e=nvs_open_from_partition("wsdev","pf_manager",NVS_READONLY,&h);
    if(e==ESP_ERR_NVS_NOT_FOUND) {
        storage_ok=true;
    } else if(e==ESP_OK) {
        storage_ok=read_u8(h,"utool_v1",&enabled) && enabled<=1U &&
                   read_u8(h,"utlay_v1",&layout) && layout<WS_USB_LAYOUT_COUNT &&
                   read_str(h,"utlang_v2",language,sizeof(language),&language_found);
        nvs_close(h);
    }
    if(!s_writer)storage_ok=false;
    /* Corrupt/unreadable role state fails closed. A damaged preference must
     * never make the device enumerate as an automation keyboard unexpectedly. */
    if(!storage_ok) {
        enabled=FIDO_V1_USB_TOOL_DEFAULT?1U:0U;
        layout=(uint8_t)FIDO_V1_USB_TOOL_LAYOUT_DEFAULT;
        strncpy(language,FIDO_V1_USB_TOOL_LANGUAGE_DEFAULT,sizeof(language)-1U);
        language[sizeof(language)-1U]='\0';
    }
    if(layout>=WS_USB_LAYOUT_COUNT)layout=WS_USB_LAYOUT_US;
    if(!valid_language_code(language)){strncpy(language,"us",sizeof(language)-1U);language[sizeof(language)-1U]='\0';}
    portENTER_CRITICAL(&s_guard);
    s_enabled=enabled!=0;s_layout=(ws_usb_layout_t)layout;
    strncpy(s_language_code,language,sizeof(s_language_code)-1U);s_language_code[sizeof(s_language_code)-1U]='\0';
    s_storage_ok=storage_ok;s_initialized=true;
    portEXIT_CRITICAL(&s_guard);
}

bool ws_usb_tool_enabled(void)
{
    if(!s_initialized)ws_usb_tool_state_init();
    portENTER_CRITICAL(&s_guard);bool v=s_enabled;portEXIT_CRITICAL(&s_guard);return v;
}

bool ws_usb_tool_storage_ok(void)
{
    if(!s_initialized)ws_usb_tool_state_init();
    portENTER_CRITICAL(&s_guard);bool v=s_storage_ok;portEXIT_CRITICAL(&s_guard);return v;
}

ws_usb_layout_t ws_usb_tool_layout(void)
{
    if(!s_initialized)ws_usb_tool_state_init();
    portENTER_CRITICAL(&s_guard);ws_usb_layout_t v=s_layout;portEXIT_CRITICAL(&s_guard);return v;
}

static bool write_u8(const char *key,uint8_t value)
{
    if(!s_initialized)ws_usb_tool_state_init();
    if(!s_writer || xSemaphoreTake(s_writer,pdMS_TO_TICKS(500))!=pdTRUE)return false;
    nvs_handle_t h=0;esp_err_t e=nvs_open_from_partition("wsdev","pf_manager",NVS_READWRITE,&h);
    if(e==ESP_OK) {
        e=nvs_set_u8(h,key,value);
        if(e==ESP_OK)e=nvs_commit(h);
        uint8_t verify=0xffU;
        if(e==ESP_OK)e=nvs_get_u8(h,key,&verify);
        if(e==ESP_OK && verify!=value)e=ESP_FAIL;
        nvs_close(h);
    }
    portENTER_CRITICAL(&s_guard);s_storage_ok=e==ESP_OK;portEXIT_CRITICAL(&s_guard);
    xSemaphoreGive(s_writer);return e==ESP_OK;
}

static bool write_str(const char *key,const char *value)
{
    if(!s_initialized)ws_usb_tool_state_init();
    if(!valid_language_code(value)||!s_writer||xSemaphoreTake(s_writer,pdMS_TO_TICKS(500))!=pdTRUE)return false;
    nvs_handle_t h=0;esp_err_t e=nvs_open_from_partition("wsdev","pf_manager",NVS_READWRITE,&h);
    if(e==ESP_OK) {
        e=nvs_set_str(h,key,value);if(e==ESP_OK)e=nvs_commit(h);
        char verify[WS_USB_LANGUAGE_CODE_MAX]={0};size_t len=sizeof(verify);
        if(e==ESP_OK)e=nvs_get_str(h,key,verify,&len);
        if(e==ESP_OK && strcmp(verify,value)!=0)e=ESP_FAIL;nvs_close(h);
    }
    portENTER_CRITICAL(&s_guard);s_storage_ok=e==ESP_OK;portEXIT_CRITICAL(&s_guard);
    xSemaphoreGive(s_writer);return e==ESP_OK;
}

bool ws_usb_tool_set_enabled(bool enabled)
{
    if(!write_u8("utool_v1",enabled?1U:0U))return false;
    portENTER_CRITICAL(&s_guard);s_enabled=enabled;portEXIT_CRITICAL(&s_guard);return true;
}

bool ws_usb_tool_set_layout(ws_usb_layout_t layout)
{
    if(layout>=WS_USB_LAYOUT_COUNT)return false;
    if(!write_u8("utlay_v1",(uint8_t)layout))return false;
    const char *code=layout_default_code((uint8_t)layout);
    if(!write_str("utlang_v2",code))return false;
    portENTER_CRITICAL(&s_guard);s_layout=layout;strncpy(s_language_code,code,sizeof(s_language_code)-1U);s_language_code[sizeof(s_language_code)-1U]='\0';portEXIT_CRITICAL(&s_guard);return true;
}

const char *ws_usb_tool_layout_name(ws_usb_layout_t layout)
{
    switch(layout) {
    case WS_USB_LAYOUT_PL_PROGRAMMER:return "PL Programmer";
    case WS_USB_LAYOUT_DE:return "DE";
    case WS_USB_LAYOUT_FR:return "FR";
    case WS_USB_LAYOUT_ES:return "ES";
    case WS_USB_LAYOUT_US:
    default:return "US";
    }
}

void ws_usb_tool_language_code(char *out,size_t out_len)
{
    if(!out||out_len==0U)return;if(!s_initialized)ws_usb_tool_state_init();
    portENTER_CRITICAL(&s_guard);strncpy(out,s_language_code,out_len-1U);out[out_len-1U]='\0';portEXIT_CRITICAL(&s_guard);
}

bool ws_usb_tool_set_language_code(const char *code)
{
    if(!valid_language_code(code)||!write_str("utlang_v2",code))return false;
    portENTER_CRITICAL(&s_guard);strncpy(s_language_code,code,sizeof(s_language_code)-1U);s_language_code[sizeof(s_language_code)-1U]='\0';portEXIT_CRITICAL(&s_guard);
    return true;
}
