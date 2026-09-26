/* Tests USB Tool's independent, non-secret NVS preferences. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define FIDO_V1_USB_TOOL_DEFAULT 0
#define FIDO_V1_USB_TOOL_LAYOUT_DEFAULT 0
#define FIDO_V1_USB_TOOL_LANGUAGE_DEFAULT "us"
#include "../../templates/port/ws_usb_tool_state.c"

static int critical,held,sets,commits;
static bool exists_enabled,exists_layout,exists_language,open_error,set_error,commit_error,read_error,verify_error,mutex_error;
static uint8_t persisted_enabled,persisted_layout,staged;
static char persisted_language[WS_USB_LANGUAGE_CODE_MAX],staged_language[WS_USB_LANGUAGE_CODE_MAX];
static char staged_key[16];
void test_enter(void){assert(critical==0);++critical;}
void test_exit(void){assert(critical==1);--critical;}
SemaphoreHandle_t xSemaphoreCreateMutex(void){return mutex_error?NULL:(void*)1;}
int xSemaphoreTake(SemaphoreHandle_t s,unsigned t){assert(s && t==500 && !held && !critical);held=1;return 1;}
int xSemaphoreGive(SemaphoreHandle_t s){assert(s && held && !critical);held=0;return 1;}
int nvs_open_from_partition(const char*p,const char*n,int mode,nvs_handle_t*h){
    assert(!critical);assert(!strcmp(p,"wsdev") && !strcmp(n,"pf_manager"));
    if(open_error)return ESP_FAIL;
    if(!exists_enabled && !exists_layout && !exists_language && mode==NVS_READONLY)return ESP_ERR_NVS_NOT_FOUND;
    *h=1;return ESP_OK;
}
int nvs_get_u8(nvs_handle_t h,const char*k,uint8_t*out){
    assert(h==1 && !critical);if(read_error)return ESP_FAIL;
    if(!strcmp(k,"utool_v1")){if(!exists_enabled)return ESP_ERR_NVS_NOT_FOUND;*out=verify_error?0xff:persisted_enabled;return ESP_OK;}
    if(!strcmp(k,"utlay_v1")){if(!exists_layout)return ESP_ERR_NVS_NOT_FOUND;*out=verify_error?0xff:persisted_layout;return ESP_OK;}
    assert(0);return ESP_FAIL;
}
int nvs_get_str(nvs_handle_t h,const char*k,char*out,size_t*len){
    assert(h==1 && !critical && len);if(read_error)return ESP_FAIL;assert(!strcmp(k,"utlang_v2"));
    if(!exists_language)return ESP_ERR_NVS_NOT_FOUND;
    const char *src=verify_error?"mismatch":persisted_language;size_t need=strlen(src)+1U;
    if(!out){*len=need;return ESP_OK;}if(*len<need)return ESP_FAIL;memcpy(out,src,need);*len=need;return ESP_OK;
}
int nvs_set_u8(nvs_handle_t h,const char*k,uint8_t v){
    assert(h==1 && held && !critical);assert(!strcmp(k,"utool_v1")||!strcmp(k,"utlay_v1"));++sets;
    if(set_error)return ESP_FAIL;staged=v;snprintf(staged_key,sizeof(staged_key),"%s",k);return ESP_OK;
}
int nvs_set_str(nvs_handle_t h,const char*k,const char*v){
    assert(h==1 && held && !critical);assert(!strcmp(k,"utlang_v2"));++sets;if(set_error)return ESP_FAIL;
    snprintf(staged_key,sizeof(staged_key),"%s",k);snprintf(staged_language,sizeof(staged_language),"%s",v?v:"");return ESP_OK;
}
int nvs_commit(nvs_handle_t h){
    assert(h==1 && held && !critical);++commits;if(commit_error)return ESP_FAIL;
    if(!strcmp(staged_key,"utool_v1")){persisted_enabled=staged;exists_enabled=true;}
    else if(!strcmp(staged_key,"utlay_v1")){persisted_layout=staged;exists_layout=true;}
    else if(!strcmp(staged_key,"utlang_v2")){snprintf(persisted_language,sizeof(persisted_language),"%s",staged_language);exists_language=true;}
    else assert(0);return ESP_OK;
}
void nvs_close(nvs_handle_t h){assert(h==1 && !critical);}
static void boot(void){s_initialized=false;s_writer=NULL;s_enabled=true;s_layout=WS_USB_LAYOUT_ES;snprintf(s_language_code,sizeof(s_language_code),"es");s_storage_ok=false;ws_usb_tool_state_init();}
static void clean(void){
    exists_enabled=exists_layout=exists_language=open_error=set_error=commit_error=read_error=verify_error=mutex_error=false;
    persisted_enabled=persisted_layout=staged=0;persisted_language[0]=staged_language[0]=0;staged_key[0]=0;sets=commits=0;boot();
}
static void expect_language(const char *expected){char out[WS_USB_LANGUAGE_CODE_MAX]={0};ws_usb_tool_language_code(out,sizeof(out));assert(!strcmp(out,expected));}
int main(void){
    clean();assert(!ws_usb_tool_enabled() && ws_usb_tool_layout()==WS_USB_LAYOUT_US && ws_usb_tool_storage_ok());expect_language("us");
    assert(!strcmp(ws_usb_tool_layout_name(WS_USB_LAYOUT_US),"US"));
    assert(!strcmp(ws_usb_tool_layout_name(WS_USB_LAYOUT_PL_PROGRAMMER),"PL Programmer"));
    puts("PASS USB Tool NVS: safe default OFF, US layout, no write on first boot");

    assert(ws_usb_tool_set_enabled(true));assert(ws_usb_tool_enabled() && persisted_enabled==1);
    assert(ws_usb_tool_set_layout(WS_USB_LAYOUT_DE));assert(ws_usb_tool_layout()==WS_USB_LAYOUT_DE && persisted_layout==WS_USB_LAYOUT_DE);expect_language("de");
    assert(sets==3 && commits==3);boot();assert(ws_usb_tool_enabled() && ws_usb_tool_layout()==WS_USB_LAYOUT_DE);expect_language("de");
    assert(ws_usb_tool_set_language_code("gb"));expect_language("gb");assert(!strcmp(persisted_language,"gb"));
    assert(!ws_usb_tool_set_language_code("../bad"));expect_language("gb");
    assert(!ws_usb_tool_set_layout(WS_USB_LAYOUT_COUNT));assert(ws_usb_tool_layout()==WS_USB_LAYOUT_DE);
    puts("PASS USB Tool NVS: enable/layout/language persist and invalid values are rejected");

    clean();commit_error=true;assert(!ws_usb_tool_set_enabled(true));assert(!ws_usb_tool_enabled() && !ws_usb_tool_storage_ok());
    commit_error=false;boot();assert(!ws_usb_tool_enabled() && ws_usb_tool_storage_ok());
    clean();verify_error=true;assert(!ws_usb_tool_set_layout(WS_USB_LAYOUT_FR));assert(ws_usb_tool_layout()==WS_USB_LAYOUT_US && !ws_usb_tool_storage_ok());
    puts("PASS USB Tool NVS: failed/uncertain writes never update cached role");

    clean();exists_enabled=true;persisted_enabled=2;boot();assert(!ws_usb_tool_enabled() && ws_usb_tool_layout()==WS_USB_LAYOUT_US && !ws_usb_tool_storage_ok());
    clean();exists_layout=true;persisted_layout=99;boot();assert(!ws_usb_tool_enabled() && ws_usb_tool_layout()==WS_USB_LAYOUT_US && !ws_usb_tool_storage_ok());
    clean();read_error=true;exists_enabled=true;persisted_enabled=1;boot();assert(!ws_usb_tool_enabled() && !ws_usb_tool_storage_ok());
    clean();mutex_error=true;boot();assert(!ws_usb_tool_enabled() && !ws_usb_tool_storage_ok() && !ws_usb_tool_set_enabled(true));
    puts("PASS USB Tool NVS: corrupt/unreadable state fails closed to non-HID-tool boot");
    return 0;
}
