/* Tests actual M1 storage code with in-memory NVS and RTOS substitutes. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../../templates/port/ws_settings_store.c"
static int critical,held,sets,commits,opens;
static bool exists,open_error,set_error,commit_error,read_error,mutex_error;
static uint8_t persisted[32],staged[32];
void test_enter(void){assert(critical==0);critical++;}
void test_exit(void){assert(critical==1);critical--;}
SemaphoreHandle_t xSemaphoreCreateMutex(void){return mutex_error?NULL:(void*)1;}
int xSemaphoreTake(SemaphoreHandle_t s,unsigned t){assert(s && t==500 && !held && !critical);held=1;return 1;}
int xSemaphoreGive(SemaphoreHandle_t s){assert(s && held && !critical);held=0;return 1;}
int nvs_open_from_partition(const char*p,const char*n,int mode,nvs_handle_t*h){
 assert(!critical);assert(!strcmp(p,"wsdev") && !strcmp(n,"pf_manager"));opens++;
 if(open_error)return ESP_FAIL;if(!exists && mode==NVS_READONLY)return ESP_ERR_NVS_NOT_FOUND;
 *h=1;return 0;
}
int nvs_get_blob(nvs_handle_t h,const char*k,void*out,size_t*n){
 assert(h==1 && !strcmp(k,"ui_v1") && !critical && *n>=32);
 if(read_error)return ESP_FAIL;if(!exists)return ESP_ERR_NVS_NOT_FOUND;
 memcpy(out,persisted,32);*n=32;return 0;
}
int nvs_set_blob(nvs_handle_t h,const char*k,const void*d,size_t n){
 assert(h==1 && !strcmp(k,"ui_v1") && n==32 && held && !critical);sets++;
 if(set_error)return ESP_FAIL;memcpy(staged,d,32);return 0;
}
int nvs_commit(nvs_handle_t h){assert(h==1 && held && !critical);commits++;if(commit_error)return ESP_FAIL;memcpy(persisted,staged,32);exists=true;return 0;}
void nvs_close(nvs_handle_t h){assert(h==1 && !critical);}
static void boot(void){s_initialized=false;ws_settings_init();}
static void defaults(void){exists=open_error=set_error=commit_error=read_error=mutex_error=false;sets=commits=opens=0;boot();}
static ws_settings_t current(bool *ok){ws_settings_t s;ws_settings_get(&s,ok);return s;}
int main(void){
 bool ok;uint8_t wire[32];defaults();ws_settings_t a=current(&ok);assert(ok && a.brightness==90 && a.off_seconds==60 && a.revision==0 && sets==0);
 assert(ws_settings_presence_timeout_ms()==30000 && ws_settings_uv_timeout_ms()==120000);
 a.brightness=140;ws_settings_encode(&a,wire);assert(ws_settings_apply(wire,32)==WS_SETTINGS_OK);
 ws_settings_t b=current(&ok);assert(ok && b.brightness==140 && b.revision==1 && sets==1 && commits==1);
 assert(ws_settings_apply(wire,32)==WS_SETTINGS_STALE && sets==1);boot();b=current(&ok);assert(ok && b.revision==1 && b.brightness==140);
 puts("PASS NVS: defaults without writes, exact namespace, commit/readback, persistence and stale revision rejection");
 ws_settings_encode(&b,wire);wire[24]=1;assert(ws_settings_apply(wire,32)==WS_SETTINGS_INVALID && sets==1);
 assert(ws_settings_apply(wire,31)==WS_SETTINGS_INVALID);ws_settings_encode(&b,wire);wire[5]=0;assert(ws_settings_apply(wire,32)==WS_SETTINGS_INVALID);
 puts("PASS NVS: invalid record, reserved bytes, length and unsafe brightness never write");
 b.brightness=150;ws_settings_encode(&b,wire);commit_error=true;assert(ws_settings_apply(wire,32)==WS_SETTINGS_STORAGE);
 a=current(&ok);assert(!ok && a.brightness==140 && a.revision==1);commit_error=false;boot();a=current(&ok);assert(ok && a.brightness==140);
 ws_settings_encode(&a,wire);wire[5]=160;read_error=true;assert(ws_settings_apply(wire,32)==WS_SETTINGS_STORAGE);
 a=current(&ok);assert(!ok && a.brightness==140);read_error=false;boot();a=current(&ok);assert(ok && a.brightness==160 && a.revision==2);
 puts("PASS NVS: failed commit and uncertain post-commit readback are not falsely acknowledged");
 persisted[0]=0;boot();a=current(&ok);assert(!ok && a.revision==0 && a.brightness==90);defaults();open_error=true;ws_settings_encode(&a,wire);assert(ws_settings_apply(wire,32)==WS_SETTINGS_STORAGE);
 defaults();mutex_error=true;boot();assert(ws_settings_apply(wire,32)==WS_SETTINGS_STORAGE);
 defaults();a=current(&ok);a.revision=UINT32_MAX;ws_settings_encode(&a,persisted);exists=true;boot();ws_settings_encode(&a,wire);assert(ws_settings_apply(wire,32)==WS_SETTINGS_STALE);
 puts("PASS NVS: corrupt record, open/mutex failure and revision overflow fail closed");return 0;
}
