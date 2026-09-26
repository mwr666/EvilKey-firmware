/* Tests Manager Drive's independent, non-secret NVS preferences. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define FIDO_V1_MANAGER_DRIVE_DEFAULT 0
#define FIDO_V1_MANAGER_DRIVE_READ_ONLY_DEFAULT 0
#include "../../templates/port/ws_manager_drive_state.c"

static int critical,held,opens,sets,commits;
static bool exists_enabled,exists_ro,open_error,set_error,commit_error,read_error,mutex_error;
static uint8_t persisted_enabled,persisted_ro,staged;
static char staged_key[16];
void test_enter(void){assert(critical==0);++critical;}
void test_exit(void){assert(critical==1);--critical;}
SemaphoreHandle_t xSemaphoreCreateMutex(void){return mutex_error?NULL:(void*)1;}
int xSemaphoreTake(SemaphoreHandle_t s,unsigned t){assert(s && t==500 && !held && !critical);held=1;return 1;}
int xSemaphoreGive(SemaphoreHandle_t s){assert(s && held && !critical);held=0;return 1;}
int nvs_open_from_partition(const char*p,const char*n,int mode,nvs_handle_t*h){
    assert(!critical);assert(!strcmp(p,"wsdev") && !strcmp(n,"pf_manager"));++opens;
    if(open_error)return ESP_FAIL;
    if(!exists_enabled && !exists_ro && mode==NVS_READONLY)return ESP_ERR_NVS_NOT_FOUND;
    *h=1;return ESP_OK;
}
int nvs_get_u8(nvs_handle_t h,const char*k,uint8_t*out){
    assert(h==1 && !critical);if(read_error)return ESP_FAIL;
    if(!strcmp(k,"mdrive_v1")){if(!exists_enabled)return ESP_ERR_NVS_NOT_FOUND;*out=persisted_enabled;return ESP_OK;}
    if(!strcmp(k,"mdrive_ro1")){if(!exists_ro)return ESP_ERR_NVS_NOT_FOUND;*out=persisted_ro;return ESP_OK;}
    assert(0);return ESP_FAIL;
}
int nvs_set_u8(nvs_handle_t h,const char*k,uint8_t v){
    assert(h==1 && held && !critical);assert(!strcmp(k,"mdrive_v1")||!strcmp(k,"mdrive_ro1"));++sets;
    if(set_error)return ESP_FAIL;staged=v;snprintf(staged_key,sizeof(staged_key),"%s",k);return ESP_OK;
}
int nvs_commit(nvs_handle_t h){
    assert(h==1 && held && !critical);++commits;if(commit_error)return ESP_FAIL;
    if(!strcmp(staged_key,"mdrive_v1")){persisted_enabled=staged;exists_enabled=true;}
    else {persisted_ro=staged;exists_ro=true;}return ESP_OK;
}
void nvs_close(nvs_handle_t h){assert(h==1 && !critical);}
static void boot(void){s_initialized=false;s_writer=NULL;s_enabled=false;s_read_only=false;s_storage_ok=false;ws_manager_drive_state_init();}
static void clean(void){exists_enabled=exists_ro=open_error=set_error=commit_error=read_error=mutex_error=false;persisted_enabled=persisted_ro=staged=0;staged_key[0]=0;opens=sets=commits=0;boot();}
int main(void){
    clean();assert(!ws_manager_drive_enabled() && !ws_manager_drive_read_only() && ws_manager_drive_storage_ok() && sets==0);
    puts("PASS Manager Drive NVS: default OFF and default READ/WRITE");
    assert(ws_manager_drive_set_enabled(true));assert(ws_manager_drive_enabled());
    assert(ws_manager_drive_set_read_only(true));assert(ws_manager_drive_read_only());
    assert(persisted_enabled==1 && persisted_ro==1 && sets==2 && commits==2);boot();assert(ws_manager_drive_enabled()&&ws_manager_drive_read_only());
    assert(ws_manager_drive_set_read_only(false));assert(!ws_manager_drive_read_only() && persisted_ro==0);
    uint8_t wire[WS_MANAGER_DRIVE_WIRE_SIZE];bool ro=true;ws_manager_drive_encode(wire);assert(ws_manager_drive_decode(wire,sizeof(wire),&ro)&&!ro);
    wire[6]=1;assert(!ws_manager_drive_decode(wire,sizeof(wire),&ro));
    puts("PASS Manager Drive NVS/API: read-only toggle persists and PFM2 record is strict");

    clean();commit_error=true;assert(!ws_manager_drive_set_read_only(true));assert(!ws_manager_drive_read_only() && !ws_manager_drive_storage_ok());
    commit_error=false;boot();assert(!ws_manager_drive_read_only() && ws_manager_drive_storage_ok());
    clean();read_error=true;exists_ro=true;persisted_ro=1;boot();assert(!ws_manager_drive_read_only() && !ws_manager_drive_storage_ok());
    clean();persisted_ro=2;exists_ro=true;boot();assert(!ws_manager_drive_read_only() && !ws_manager_drive_storage_ok());
    clean();mutex_error=true;boot();assert(!ws_manager_drive_storage_ok() && !ws_manager_drive_set_read_only(true));
    puts("PASS Manager Drive NVS: failed/corrupt storage is never falsely acknowledged");
    return 0;
}
