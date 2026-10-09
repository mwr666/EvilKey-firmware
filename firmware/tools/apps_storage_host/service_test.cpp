/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Production worker with deterministic RTOS/storage/VM boundaries.
 * Exact guest execution is covered separately by the five app host tests. */
#include <assert.h>
#include <vector>
#include <thread>
#include <mutex>
#include "../../EvilKeyV1/src/apps/ek_service.cpp"
static unsigned clock_ms=1000,scan_index,icon_reads,ends,vm_steps;
static bool role_allowed=true,stop_on_idle,vm_closed;
static thread_local int guard_depth;
static std::mutex test_guard;
static thread_local uint64_t copy_clock_step,copy_clock_offset;
static unsigned cancel_after,selected_abi=4,scene_allocations,scene_frees;
static bool fail_scene,render_ok;
int64_t esp_timer_get_time(void){uint64_t value=(uint64_t)clock_ms*1000+copy_clock_offset;copy_clock_offset+=copy_clock_step;return (int64_t)value;}
extern "C" uint16_t ek_storage_loaded_abi(void){return selected_abi;}
extern "C" EkScene3D *ek_scene3d_create(void){++scene_allocations;return fail_scene?nullptr:(EkScene3D *)malloc(1);}
extern "C" void ek_scene3d_destroy(EkScene3D *p){if(p)++scene_frees;free(p);}
static unsigned scene_render_calls;
extern "C" EkSceneStats ek_scene3d_render(EkScene3D *,const uint8_t *,uint16_t *,unsigned,unsigned,unsigned,unsigned,unsigned,EkSceneClock,void *){assert(!guard_depth);++scene_render_calls;clock_ms+=24;return {render_ok?1u:2u,24000,132,20000};}
extern "C" EkSceneProfile ek_scene3d_profile(const EkScene3D *){assert(!guard_depth);return {{render_ok?1u:2u,24000,132,20000},1000,500,20000,14000,2500,1500,1000};}
static std::vector<EkPackageInfo> packages;
struct TaskStopped{};
uint32_t millis(void){return clock_ms;}
SemaphoreHandle_t xSemaphoreCreateMutex(void){return (void *)1;}
int xSemaphoreTake(SemaphoreHandle_t,unsigned){test_guard.lock();assert(guard_depth==0);++guard_depth;return 1;}
void xSemaphoreGive(SemaphoreHandle_t){assert(guard_depth==1);--guard_depth;test_guard.unlock();}
void vSemaphoreDelete(SemaphoreHandle_t){}
unsigned uxTaskGetStackHighWaterMark(void *){return 12000;}
int xTaskCreate(void (*)(void *),const char *,unsigned,void *,unsigned,void *){return pdPASS;}
void vTaskDelay(unsigned ms){assert(guard_depth==0);clock_ms+=ms;if(stop_on_idle && ms>=16)throw TaskStopped();}
extern "C" bool pf_apps_storage_role_allowed(void){return role_allowed;}
extern "C" int ek_storage_begin(void){assert(!guard_depth);return role_allowed;}
extern "C" void ek_storage_end(void){assert(!guard_depth);++ends;}
extern "C" const char *ek_storage_error(void){return "I/O failure";}
static bool fail_report;static unsigned report_writes;
static std::vector<uint8_t> written_report;
extern "C" int ek_storage_diagnostics_write(const uint8_t *data,size_t size,char *filename,size_t capacity){
 assert(!guard_depth);++report_writes;
 if(fail_report||!role_allowed||!s_state.mounted)return 0;
 written_report.assign(data,data+size);snprintf(filename,capacity,"diag-00000001-0001.txt");return 1;
}
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
extern "C" int ek_vm_open(EkVm *,const uint8_t *,size_t,EkVmHost host){assert(host.abi_version==selected_abi);assert((host.scene3d!=nullptr)==(selected_abi==5));vm_closed=false;return 1;}
extern "C" int ek_vm_init(EkVm *,const EvilKeyAppInput *){return 1;}
extern "C" int ek_vm_step(EkVm *,const EvilKeyAppInput *){assert(!vm_closed);++vm_steps;
 return 1;}
extern "C" void ek_vm_close(EkVm *){vm_closed=true;}
extern "C" const char *ek_vm_error(const EkVm *){return "mock";}
static void once(){stop_on_idle=true;try{task(nullptr);}catch(TaskStopped&){}stop_on_idle=false;}
static void catalog(unsigned n){
 packages.clear();for(unsigned i=0;i<n;++i){EkPackageInfo p={};
 snprintf(p.id,sizeof(p.id),"game.%02u",n-i-1);snprintf(p.name,sizeof(p.name),"Name %02u",n-i-1);packages.push_back(p);}
 scan_catalog();
}
static void frame_copy_contract(){
 s_back=(uint16_t*)calloc(EK_APPS_PIXELS,2);s_front=(uint16_t*)calloc(EK_APPS_PIXELS,2);
 assert(s_back&&s_front);
 const EkAppsDirty regions[]={{0,0,280,456},{0,0,280,455},{0,1,280,455},{1,0,279,456},{0,0,279,456},{1,1,1,1},{3,65,275,287},{279,455,1,1},{2,0,278,1}};
 for(unsigned offset:{0u,1u})for(auto area:regions){
  std::vector<uint16_t> output(EK_APPS_PIXELS+4,0xa55a);
  for(unsigned i=0;i<EK_APPS_PIXELS;i++)s_front[i]=(uint16_t)(i*13+7);
  s_dirty=area;++s_state.frame;uint32_t generation=s_state.frame-1;EkAppsDirty copied={};
  EkAppsCopyStats before_invalid,after_invalid;ek_apps_copy_stats(&before_invalid);
  assert(!ek_apps_copy_frame_panel(nullptr,EK_APPS_PIXELS,&generation,&copied));
  assert(!ek_apps_copy_frame_panel(output.data()+offset,EK_APPS_PIXELS-1,&generation,&copied));
  assert(!ek_apps_copy_frame_panel(output.data()+offset,EK_APPS_PIXELS,nullptr,&copied));
  assert(!ek_apps_copy_frame_panel(output.data()+offset,EK_APPS_PIXELS,&generation,nullptr));
  assert(generation==s_state.frame-1&&s_dirty.width==area.width);
  ek_apps_copy_stats(&after_invalid);assert(!memcmp(&before_invalid,&after_invalid,sizeof before_invalid));
  assert(ek_apps_copy_frame_panel(output.data()+offset,EK_APPS_PIXELS,&generation,&copied));
  assert(generation==s_state.frame&&!memcmp(&copied,&area,sizeof area));
  EkAppsCopyStats selected;ek_apps_copy_stats(&selected);
  assert(selected.method==((area.x==0&&area.y==0&&area.width==280&&area.height==456)?EK_APPS_COPY_ROW_SWAP:EK_APPS_COPY_FUSED));
  for(unsigned y=0;y<456;y++)for(unsigned x=0;x<280;x++){
   unsigned i=y*280+x;uint16_t c=(uint16_t)(i*13+7);
   bool inside=x>=area.x&&x<area.x+area.width&&y>=area.y&&y<area.y+area.height;
   assert(output[offset+i]==(inside?(uint16_t)((c&255)*256+c/256):0xa55a));
   assert(s_front[i]==c);
  }
  for(unsigned i=0;i<offset;i++)assert(output[i]==0xa55a);
  for(unsigned i=offset+EK_APPS_PIXELS;i<output.size();i++)assert(output[i]==0xa55a);
  assert(!ek_apps_copy_frame_panel(output.data()+offset,EK_APPS_PIXELS,&generation,&copied));
 }
 std::vector<uint16_t> output(EK_APPS_PIXELS);uint32_t generation=0;EkAppsDirty dirty={};
 s_back[0]=0x1234;s_back[1]=0xabcd;present(nullptr,0,0,1,1);present(nullptr,1,0,1,1);
 assert(ek_apps_copy_frame(output.data(),EK_APPS_PIXELS,&generation,&dirty));
 EkAppsCopyStats native_method;ek_apps_copy_stats(&native_method);assert(native_method.method==EK_APPS_COPY_NATIVE);
 assert(output[0]==0x1234&&output[1]==0xabcd&&dirty.width==2&&dirty.height==1);
 s_dirty={};
 for(unsigned i=0;i<EK_APPS_PIXELS;i++)s_back[i]=(uint16_t)(i*13+7);
 present(nullptr,0,0,140,456);present(nullptr,140,0,140,456);
 assert(ek_apps_copy_frame_panel(output.data(),EK_APPS_PIXELS,&generation,&dirty));
 assert(dirty.x==0&&dirty.y==0&&dirty.width==280&&dirty.height==456);
 EkAppsCopyStats coalesced;ek_apps_copy_stats(&coalesced);assert(coalesced.method==EK_APPS_COPY_ROW_SWAP);
 for(unsigned i=0;i<EK_APPS_PIXELS;i++){uint16_t c=(uint16_t)(i*13+7);assert(output[i]==(uint16_t)((c&255)*256+c/256));}
 std::thread producer([](){for(unsigned serial=1;serial<=180;serial++){
  for(unsigned i=0;i<EK_APPS_PIXELS;i++)s_back[i]=(uint16_t)serial;
  present(nullptr,0,0,280,456);
 }});
 for(unsigned k=0;k<180;k++)if(ek_apps_copy_frame_panel(output.data(),EK_APPS_PIXELS,&generation,&dirty)){
  assert(dirty.width==280&&dirty.height==456);
  for(unsigned i=1;i<EK_APPS_PIXELS;i++)assert(output[i]==output[0]);
 }
 producer.join();
 if(ek_apps_copy_frame_panel(output.data(),EK_APPS_PIXELS,&generation,&dirty))
  for(unsigned i=1;i<EK_APPS_PIXELS;i++)assert(output[i]==output[0]);
#ifndef EK_COPY_LEGACY
 EkAppsCopyStats stats;ek_apps_copy_stats(&stats);ek_apps_copy_stats(nullptr);
 assert(sizeof(stats)==28&&stats.copies>=19&&stats.last_bytes==EK_APPS_PIXELS*2&&stats.panel_order==1&&stats.method==EK_APPS_COPY_ROW_SWAP);
 EkAppsCopyStats unchanged=stats;
 assert(!ek_apps_copy_frame_panel(output.data(),EK_APPS_PIXELS,&generation,&dirty));
 ek_apps_copy_stats(&stats);assert(!memcmp(&stats,&unchanged,sizeof stats));
 s_copy_stats.copies=UINT32_MAX;copy_clock_step=42;
 s_dirty={1,0,1,1};++s_state.frame;
 assert(ek_apps_copy_frame_panel(output.data(),EK_APPS_PIXELS,&generation,&dirty));
 ek_apps_copy_stats(&stats);assert(!stats.copies&&stats.last_us==42&&stats.last_bytes==2&&stats.last_width==1&&stats.last_height==1&&stats.method==EK_APPS_COPY_FUSED);
 copy_clock_step=(uint64_t)UINT32_MAX+100;
 s_dirty={2,0,1,1};++s_state.frame;
 assert(ek_apps_copy_frame(output.data(),EK_APPS_PIXELS,&generation,&dirty));
 ek_apps_copy_stats(&stats);assert(stats.copies==1&&stats.last_us==UINT32_MAX&&stats.peak_us==UINT32_MAX&&!stats.panel_order&&stats.method==EK_APPS_COPY_NATIVE);
 copy_clock_step=copy_clock_offset=0;
#endif
 free(s_back);free(s_front);s_back=s_front=nullptr;s_dirty={};
 puts("PASS fused/native copy: all RGB565 values, odd/aligned ranges/guards, nonconsuming invalid/repeat, coalescing and concurrent whole publications");
}
int main(){
 assert(!ek_apps_diagnostics_export_request());
 EkDiagnosticsExport exported;ek_apps_diagnostics_export_snapshot(&exported);assert(exported.status==EK_DIAGNOSTICS_EXPORT_ERROR);
 ek_apps_diagnostics_export_snapshot(nullptr);
 EkSceneProfile native;ek_apps_scene_profile(&native);assert(!native.stats.status);
 assert(ek_apps_start());s_state.mounted=true;
 frame_copy_contract();
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
 EkAppsCopyStats copy_stats;ek_apps_copy_stats(&copy_stats);assert(!copy_stats.copies&&!copy_stats.peak_us&&copy_stats.method==EK_APPS_COPY_NATIVE);
 std::vector<uint16_t> copied_frame(EK_APPS_PIXELS);uint32_t copied_generation=0;EkAppsDirty copied_dirty;
 assert(ek_apps_copy_frame_panel(copied_frame.data(),EK_APPS_PIXELS,&copied_generation,&copied_dirty));
 ek_apps_copy_stats(&copy_stats);assert(copy_stats.copies==1&&copy_stats.panel_order==1);
 uint32_t app_time=s_app_time_ms;
 ek_apps_set_modal(true);clock_ms+=5000;once();
 assert(vm_steps==steps && s_app_time_ms==app_time);
 clock_ms+=7000;once();assert(vm_steps==steps && s_app_time_ms==app_time);
 ek_apps_set_modal(false);once();
 assert(vm_steps==steps+1 && s_app_time_ms-app_time<=16);
 steps=vm_steps;
 ek_apps_select_page(0);assert(s_state.page==1); /* an active app keeps its launch page */
 ek_apps_set_visible(false);once();assert(!s_state.running && vm_closed && vm_steps==steps);
 EkAppsCopyStats retained_copy;ek_apps_copy_stats(&retained_copy);assert(!memcmp(&copy_stats,&retained_copy,sizeof copy_stats));
 ek_apps_set_visible(true);ek_apps_launch(9);once();assert(s_state.running);
 ek_apps_copy_stats(&copy_stats);assert(!copy_stats.copies&&!copy_stats.last_bytes&&copy_stats.method==EK_APPS_COPY_NATIVE);
 role_allowed=false;once();assert(!s_state.running && !s_state.mounted && s_state.count==0 && ends==1);
 role_allowed=true;s_state.mounted=true;selected_abi=5;catalog(1);load_page_icons();fail_scene=true;ek_apps_launch(0);once();assert(!s_state.running && !s_scene3d && !s_back && !s_front);
 fail_scene=false;ek_apps_launch(0);once();assert(s_state.running && s_scene3d);
 EvilKey3DScene scene={};scene.magic=EVILKEY_3D_MAGIC;scene.version=1;scene.object_count=1;scene.material_count=1;
 scene.camera={{0,2048,1536},{0,0,0},50,0,2560,0};
 scene.objects[0]={1,0,{0,0,0},{0,0,0},{512,512,512},0,{0,0}};
 unsigned calls_before=scene_render_calls;
 render_scene(nullptr,(const uint8_t*)&scene,0,64,280,288);ek_apps_scene_profile(&native);
 assert(scene_render_calls==calls_before+1&&native.stats.status==2&&native.raster_us==14000);
 render_ok=true;render_scene(nullptr,(const uint8_t*)&scene,0,64,280,288);ek_apps_scene_profile(&native);
 assert(scene_render_calls==calls_before+2&&native.stats.status==1);
 ek_apps_set_visible(false);once();assert(!s_scene3d&&scene_frees==1&&scene_allocations==2);
 ek_apps_scene_profile(&native);assert(native.stats.status==1);
 ek_apps_set_visible(true);ek_apps_launch(0);once();ek_apps_scene_profile(&native);assert(!native.stats.status);
 ek_apps_set_visible(false);once();
 puts("PASS one native render per request, profile published outside compute guard, exit retention/new app reset");
 s_state.mounted=true;cancel_after=2;catalog(10);
 assert(!s_state.catalog_ready && !s_state.count && s_state.headers_read==2);
 cancel_after=0;role_allowed=true;s_state.mounted=true;
 const char log[]="complete diagnostic report\n";
 auto submit_report=[&](){
  assert(ek_apps_diagnostics_export_request());
  assert(!ek_apps_diagnostics_export_request());
  char *owned=(char *)malloc(sizeof(log));memcpy(owned,log,sizeof(log));
  assert(ek_apps_diagnostics_export(owned,sizeof(log)-1));
  char *duplicate=(char *)malloc(sizeof(log));memcpy(duplicate,log,sizeof(log));
  assert(!ek_apps_diagnostics_export(duplicate,sizeof(log)-1));free(duplicate);
  ek_apps_diagnostics_export_snapshot(&exported);assert(exported.status==EK_DIAGNOSTICS_EXPORT_BUSY);
 };
 submit_report();once();ek_apps_diagnostics_export_snapshot(&exported);
 assert(exported.status==EK_DIAGNOSTICS_EXPORT_SAVED&&!s_diagnostics_report&&report_writes==1);
 assert(written_report.size()==sizeof(log)-1&&!memcmp(written_report.data(),log,sizeof(log)-1));
 assert(!strcmp(exported.filename,"diag-00000001-0001.txt"));
 fail_report=true;submit_report();once();ek_apps_diagnostics_export_snapshot(&exported);
 assert(exported.status==EK_DIAGNOSTICS_EXPORT_ERROR&&!s_diagnostics_report&&report_writes==2);
 fail_report=false;submit_report();role_allowed=false;once();ek_apps_diagnostics_export_snapshot(&exported);
 assert(exported.status==EK_DIAGNOSTICS_EXPORT_ERROR&&!s_diagnostics_report&&report_writes==3);
 role_allowed=true;assert(ek_apps_diagnostics_export_request());
 ek_apps_diagnostics_export_failed("Report memory unavailable");ek_apps_diagnostics_export_snapshot(&exported);
 assert(exported.status==EK_DIAGNOSTICS_EXPORT_ERROR&&report_writes==3);
 puts("PASS worker: 0/1/5/9/10/70 catalog, 64 limit, page-only icons, cache generations, launch bounds, hidden stop, USB role release, scan cancellation, ABI4/5 allocation and failure cleanup, no I/O under guard");
}
