/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Production worker with deterministic RTOS/storage/VM boundaries.
 * Exact guest execution is covered separately by the five app host tests. */
#include <assert.h>
#include <vector>
#include "../../EvilKeyV1/src/apps/ek_service.cpp"
static unsigned clock_ms=1000,scan_index,icon_reads,ends,vm_steps;
static bool role_allowed=true,stop_on_idle,vm_closed;
static int guard_depth;
static unsigned cancel_after;
static std::vector<EkPackageInfo> packages;
struct TaskStopped{};
uint32_t millis(void){return clock_ms;}
SemaphoreHandle_t xSemaphoreCreateMutex(void){return (void *)1;}
int xSemaphoreTake(SemaphoreHandle_t,unsigned){assert(guard_depth==0);++guard_depth;return 1;}
void xSemaphoreGive(SemaphoreHandle_t){assert(guard_depth==1);--guard_depth;}
void vSemaphoreDelete(SemaphoreHandle_t){}
unsigned uxTaskGetStackHighWaterMark(void *){return 12000;}
int xTaskCreate(void (*)(void *),const char *,unsigned,void *,unsigned,void *){return pdPASS;}
void vTaskDelay(unsigned ms){assert(guard_depth==0);clock_ms+=ms;if(stop_on_idle && ms>=16)throw TaskStopped();}
extern "C" bool pf_apps_storage_role_allowed(void){return role_allowed;}
extern "C" int ek_storage_begin(void){assert(!guard_depth);return role_allowed;}
extern "C" void ek_storage_end(void){assert(!guard_depth);++ends;}
extern "C" const char *ek_storage_error(void){return "I/O failure";}
extern "C" int ek_storage_scan_begin(void){assert(!guard_depth);scan_index=0;return 1;}
extern "C" void ek_storage_scan_end(void){assert(!guard_depth);}
extern "C" int ek_storage_scan_step(EkPackageInfo *out,bool *header){
 assert(!guard_depth);*header=false;
 if(scan_index>=packages.size())return 0;
 *out=packages[scan_index++];*header=true;
 if(cancel_after && scan_index==cancel_after)role_allowed=false;
 return 1;
}
extern "C" int ek_storage_icon(const EkPackageInfo *,uint8_t *p,size_t n){
 assert(!guard_depth && n==8192);memset(p,0x29,n);++icon_reads;return 1;
}
extern "C" int ek_storage_load(const char *,uint8_t **p,size_t *w,size_t *a){
 assert(!guard_depth);*p=(uint8_t *)calloc(8,1);*w=8;*a=0;return 1;
}
extern "C" int ek_storage_save_load(const char *,uint8_t *,size_t,size_t *){assert(!guard_depth);return 0;}
extern "C" int ek_storage_save_write(const char *,const uint8_t *,size_t,EkStorageSaveTrace,void *){assert(!guard_depth);return 1;}
extern "C" int ek_vm_open(EkVm *,const uint8_t *,size_t,EkVmHost){vm_closed=false;return 1;}
extern "C" int ek_vm_init(EkVm *,const EvilKeyAppInput *){return 1;}
extern "C" int ek_vm_step(EkVm *,const EvilKeyAppInput *){assert(!vm_closed);++vm_steps;return 1;}
extern "C" void ek_vm_close(EkVm *){vm_closed=true;}
extern "C" const char *ek_vm_error(const EkVm *){return "mock";}
static void once(){stop_on_idle=true;try{task(nullptr);}catch(TaskStopped&){}stop_on_idle=false;}
static void catalog(unsigned n){
 packages.clear();for(unsigned i=0;i<n;++i){EkPackageInfo p={};
 snprintf(p.id,sizeof(p.id),"game.%02u",n-i-1);snprintf(p.name,sizeof(p.name),"Name %02u",n-i-1);packages.push_back(p);}
 scan_catalog();
}
int main(){
 assert(ek_apps_start());s_state.mounted=true;
 for(unsigned n:{0u,1u,5u,9u,10u,70u}){
  catalog(n);EkAppsState state;ek_apps_snapshot(&state);
  assert(state.count==(n>64?64:n) && state.overflow==(n>64) && state.headers_read==n);
  assert(state.catalog_ready && !state.scanning);
 }
 catalog(10);ek_apps_set_visible(true);icon_reads=0;load_page_icons();assert(icon_reads==9 && s_state.icon_valid==511);
 uint8_t pixels[9*8192];uint32_t generation=0;
 assert(ek_apps_copy_icons(pixels,sizeof(pixels),&generation));assert(!ek_apps_copy_icons(pixels,sizeof(pixels),&generation));
 ek_apps_request(EK_APPS_NEXT);once();assert(s_state.page==1 && s_state.icon_valid==0);
 load_page_icons();assert(icon_reads==10 && s_state.icon_valid==1);
 ek_apps_select_page(99);assert(s_state.page==1); /* invalid requests keep the cached page */
 ek_apps_select_page(0);assert(s_state.page==0 && !s_state.icon_valid && icon_reads==10);
 load_page_icons();assert(icon_reads==19 && s_state.icon_valid==511);
 ek_apps_select_page(1);load_page_icons();assert(icon_reads==20 && s_state.icon_valid==1);
 ek_apps_launch(10);assert(s_command==EK_APPS_NONE);ek_apps_launch(9);assert(s_command==EK_APPS_RUN);
 once();assert(s_state.running);unsigned steps=vm_steps;
 uint32_t app_time=s_app_time_ms;
 ek_apps_set_modal(true);clock_ms+=5000;once();
 assert(vm_steps==steps && s_app_time_ms==app_time);
 clock_ms+=7000;once();assert(vm_steps==steps && s_app_time_ms==app_time);
 ek_apps_set_modal(false);once();
 assert(vm_steps==steps+1 && s_app_time_ms-app_time<=16);
 steps=vm_steps;
 ek_apps_select_page(0);assert(s_state.page==1); /* an active app keeps its launch page */
 ek_apps_set_visible(false);once();assert(!s_state.running && vm_closed && vm_steps==steps);
 ek_apps_set_visible(true);ek_apps_launch(9);once();assert(s_state.running);
 role_allowed=false;once();assert(!s_state.running && !s_state.mounted && s_state.count==0 && ends==1);
 role_allowed=true;s_state.mounted=true;cancel_after=2;catalog(10);
 assert(!s_state.catalog_ready && !s_state.count && s_state.headers_read==2);
 puts("PASS worker: 0/1/5/9/10/70 catalog, 64 limit, page-only icons, cache generations, launch bounds, hidden stop, USB role release, scan cancellation, no I/O under guard");
}
