/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Production worker with deterministic RTOS/storage/VM boundaries.
 * Exact guest execution is covered separately by the five app host tests. */
#include <assert.h>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <string.h>
static unsigned full_canvas_copies;
static void *observed_memcpy(void *d,const void *s,size_t n){if(n==280*456*2)++full_canvas_copies;return memcpy(d,s,n);}
#define memcpy observed_memcpy
#include "../../EvilKeyV1/src/apps/ek_service.cpp"
#undef memcpy
static unsigned clock_ms=1000,scan_index,icon_reads,ends,vm_steps;
static bool role_allowed=true,stop_on_idle,vm_closed;
static thread_local int guard_depth;
static std::mutex test_guard;
static thread_local uint64_t copy_clock_step,copy_clock_offset;
static unsigned cancel_after,selected_abi=4,scene_allocations,scene_frees;
static bool fail_scene,render_ok;
int64_t esp_timer_get_time(void){uint64_t value=(uint64_t)clock_ms*1000+copy_clock_offset;copy_clock_offset+=copy_clock_step;return (int64_t)value;}
extern "C" int ek_storage_models_load(const char *,EkAssets *,size_t){return 1;}
extern "C" void ek_storage_models_free(EkAssets *){}
extern "C" void ek_scene3d_set_assets(EkScene3D *,const EkAssets *){}
extern "C" size_t ek_scene3d_allocation_bytes(const EkScene3D *ctx){return ctx?196544:0;}
extern "C" uint16_t ek_storage_loaded_abi(void){return selected_abi;}
extern "C" int ek_storage_loaded_info(EkPackageInfo *out){memset(out,0,sizeof(*out));strcpy(out->id,"loaded.game");out->abi=selected_abi;out->major=1;memset(out->sha256,0xcd,32);return 1;}
extern "C" int ek_storage_loaded_program_sha256(uint8_t out[32]){assert(!guard_depth);memset(out,0xab,32);return 1;}
static uint32_t diagnostic_gate;
extern "C" bool ek_render_diagnostics_enabled(void){return __atomic_load_n(&diagnostic_gate,__ATOMIC_ACQUIRE)!=0;}
extern "C" void ek_render_diagnostics_enable(bool value){__atomic_store_n(&diagnostic_gate,value,__ATOMIC_RELEASE);}
extern "C" void ek_render_frame_stats(EkRenderFrameStats *out){memset(out,0,sizeof(*out));out->wait_last_us[0]=123;}
extern "C" EkScene3D *ek_scene3d_create(void){++scene_allocations;return fail_scene?nullptr:(EkScene3D *)malloc(1);}
extern "C" void ek_scene3d_destroy(EkScene3D *p){if(p)++scene_frees;free(p);}
static unsigned scene_render_calls;static bool paint_scene;
extern "C" EkSceneStats ek_scene3d_render(EkScene3D *,const uint8_t *,uint16_t *pixels,unsigned stride,unsigned x,unsigned y,unsigned w,unsigned h,EkSceneClock,void *){assert(!guard_depth);++scene_render_calls;if(render_ok&&paint_scene)for(unsigned row=y;row<y+h;row++)for(unsigned col=x;col<x+w;col++)pixels[row*stride+col]=(uint16_t)(row*37+col*73);clock_ms+=24;return {render_ok?1u:2u,24000,132,20000};}
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
  assert(selected.method==((area.x==0&&area.y==0&&area.width==280&&area.height==456)?EK_APPS_COPY_BLOCK_SWAP:EK_APPS_COPY_FUSED));
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
 EkAppsCopyStats coalesced;ek_apps_copy_stats(&coalesced);assert(coalesced.method==EK_APPS_COPY_BLOCK_SWAP);
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
 assert(sizeof(stats)==28&&stats.copies>=19&&stats.last_bytes==EK_APPS_PIXELS*2&&stats.panel_order==1&&stats.method==EK_APPS_COPY_BLOCK_SWAP);
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
static void block_copy_contract(){
 unsigned cases=0;
 for(unsigned src_offset:{0u,1u})for(unsigned dst_offset:{0u,1u})
 for(unsigned count:{0u,1u,2u,255u,256u,257u,511u,512u,513u,65536u,65537u,127680u}){
  std::vector<uint16_t> source(count+4,0xbeef),out(count+4,0xa55a);
  for(unsigned i=0;i<count;i++)source[src_offset+i]=(uint16_t)i;
  auto unchanged=source;
  copy_panel_blocks(out.data()+dst_offset,source.data()+src_offset,count);
  assert(source==unchanged);
  for(unsigned i=0;i<out.size();i++){
   bool inside=i>=dst_offset&&i<dst_offset+count;
   uint16_t c=(uint16_t)(i-dst_offset);
   assert(out[i]==(inside?(uint16_t)((c&255)*256+c/256):0xa55a));
  }
  ++cases;
 }
 printf("PASS SRAM block swap: %u boundary/alignment/canary cases, all RGB565 values, immutable source\n",cases);
}
static void mixed_copy_contract(){
 s_front=(uint16_t*)malloc(EK_APPS_PIXELS*2);assert(s_front);
 const EkAppsDirty areas[]={{0,0,280,456},{1,43,279,2},{3,44,277,111},{2,0,276,44},{279,455,1,1},{3,41,17,9}};
 unsigned cases=0;
 for(unsigned offset:{0u,1u})for(unsigned rows:{0u,44u,456u})for(auto area:areas){
  std::vector<uint16_t> out(EK_APPS_PIXELS+4,0xa55a);
  for(unsigned i=0;i<EK_APPS_PIXELS;i++)s_front[i]=(uint16_t)i;
  s_dirty=area;++s_state.frame;uint32_t gen=s_state.frame-1;EkAppsDirty dirty={};
  assert(!ek_apps_copy_frame_transport(out.data()+offset,EK_APPS_PIXELS,&gen,&dirty,457,true));
  assert(gen==s_state.frame-1&&s_dirty.width==area.width);
  assert(ek_apps_copy_frame_transport(out.data()+offset,EK_APPS_PIXELS,&gen,&dirty,rows,false));
  for(unsigned y=0;y<456;y++)for(unsigned x=0;x<280;x++){
   unsigned i=y*280+x;uint16_t c=(uint16_t)i;
   bool inside=x>=area.x&&x<area.x+area.width&&y>=area.y&&y<area.y+area.height;
   assert(out[offset+i]==(inside?(y<rows?(uint16_t)((c&255)*256+c/256):c):0xa55a));
   assert(s_front[i]==c);
  }
  assert(!ek_apps_copy_frame_transport(out.data()+offset,EK_APPS_PIXELS,&gen,&dirty,rows,false));
  assert(ek_apps_copy_frame_transport(out.data()+offset,EK_APPS_PIXELS,&gen,&dirty,rows,true));
  assert(gen==s_state.frame&&dirty.width==280&&dirty.height==456);
  for(unsigned i=0;i<EK_APPS_PIXELS;i++){
   uint16_t c=(uint16_t)i;assert(out[offset+i]==(i/280<rows?(uint16_t)((c&255)*256+c/256):c));
  }
  for(unsigned i=0;i<offset;i++)assert(out[i]==0xa55a);
  for(unsigned i=offset+EK_APPS_PIXELS;i<out.size();i++)assert(out[i]==0xa55a);
  if(rows==44){EkAppsCopyStats st;ek_apps_copy_stats(&st);assert(st.method==4&&st.panel_order==2);}
  ++cases;
 }
 free(s_front);s_front=nullptr;s_dirty={};
 printf("PASS mixed snapshot: %u full/partial/prefix43-44/alignment/canary/native-panel/force/repeat cases; immutable front\n",cases);
}
static void run_metrics_contract(EvilKey3DScene *scene){
 s_step_started_us=esp_timer_get_time();measure_run(nullptr,0x21000001,4321,131072);
 assert(!strcmp(s_run_metrics.identity.version,"1.0.0"));
 assert(!strncmp(s_run_metrics.identity.program_sha256,"abababab",8));
 std::vector<uint16_t> pixels(EK_APPS_PIXELS);uint32_t gen=0;EkAppsDirty dirty={};
 auto consume=[&](bool success){assert(ek_apps_copy_frame_panel(pixels.data(),pixels.size(),&gen,&dirty));
  uint32_t detail[4]={13,17,19,23};
  ek_apps_display_complete_detail(gen,success,72,5,5,detail,8);
  ek_apps_display_complete_detail(gen,success,72,5,5,detail,8);};
 render_ok=true;render_scene(nullptr,(const uint8_t*)scene,0,64,280,288);
 present(nullptr,0,0,280,456);consume(true);
 EkRunMetrics snapshot;ek_apps_run_metrics(&snapshot);assert(snapshot.record[snapshot.current].completed==1);
 assert(snapshot.record[snapshot.current].cadence_8ms_frames==1);
 assert(snapshot.record[snapshot.current].stages[EK_STAGE_STREAM_IO].count==1);
 assert(ek_apps_copy_frame_transport(pixels.data(),pixels.size(),&gen,&dirty,44,true));
 ek_apps_display_complete(gen,true);ek_apps_run_metrics(&snapshot);
 assert(snapshot.record[snapshot.current].completed==1); /* format refresh is not a new frame */
 present(nullptr,0,0,280,456);consume(true); /* HUD-only cannot create a scene */
 render_ok=false;render_scene(nullptr,(const uint8_t*)scene,0,64,280,288);
 present(nullptr,0,0,280,456);consume(true); /* failed/repeated viewport */
 render_ok=true;
 for(unsigned i=0;i<2;i++){render_scene(nullptr,(const uint8_t*)scene,0,64,280,288);present(nullptr,0,0,280,456);}
 consume(true);ek_apps_run_metrics(&snapshot);
 EkRunRecord &r=snapshot.record[snapshot.current];assert(r.completed==2&&r.produced==3&&r.attempts==4&&r.timeouts==1);
 assert(r.cadence_8ms_frames==2&&r.stages[EK_STAGE_STREAM_IO].count==2);
 render_scene(nullptr,(const uint8_t*)scene,0,64,280,288);present(nullptr,0,0,280,456);consume(false);
 ek_apps_run_metrics(&snapshot);assert(snapshot.record[snapshot.current].completed==2&&snapshot.record[snapshot.current].display_failures==1);
 ek_apps_set_modal(true);ek_apps_run_metrics(&snapshot);uint64_t active=snapshot.record[snapshot.current].active_us;
 clock_ms+=20000;ek_apps_run_metrics(&snapshot);assert(snapshot.record[snapshot.current].active_us==active);
 ek_apps_set_modal(false);measure_run(nullptr,0x41000001,12,131072);
 ek_apps_run_metrics(&snapshot);assert(snapshot.record[snapshot.current].phase==4);
 uint64_t final=snapshot.record[snapshot.current].active_us;
 clock_ms+=10000;ek_apps_run_metrics(&snapshot);assert(snapshot.record[snapshot.current].active_us==final);
 puts("PASS measured service:loaded identity,new scene/present/display ACK,HUD-only,repeated timeout,coalescing,duplicate ACK,failed flush,modal,completed retention");
}
static void graphics_pixels_contract(){
 const unsigned N=EK_APPS_PIXELS;std::vector<uint16_t> storage(N+4,0xa55a),expected(N),source_words(N);
 s_back=storage.data()+1; /* Deliberately 2-byte, not4-byte aligned destination. */
 unsigned checks=0;
 for(unsigned colour=0;colour<65536;colour++){
  for(unsigned x=0;x<280;x++)s_back[7*280+x]=0xa55a;
  rect(nullptr,12,7,256,1,(uint16_t)colour);
  for(unsigned x=0;x<280;x++)assert(s_back[7*280+x]==(x>=12&&x<268?colour:0xa55a));
  assert(storage[0]==0xa55a&&storage[N+1]==0xa55a);checks++;
 }
 unsigned random=0x71857263;
 auto next=[&](){random^=random<<13;random^=random>>17;random^=random<<5;return random;};
 const EkAppsDirty edges[]={{0,0,280,456},{1,0,279,456},{0,1,280,455},{279,455,1,1},{13,17,31,9},{13,17,32,7},{13,17,32,8},{0,0,255,1},{0,0,256,1},{0,0,257,1}};
 for(unsigned sample=0;sample<1010;sample++){
  EkAppsDirty a=sample<10?edges[sample]:EkAppsDirty{(uint16_t)(next()%280),(uint16_t)(next()%456),0,0};
  if(sample>=10){a.width=(uint16_t)(1+next()%(280-a.x));a.height=(uint16_t)(1+next()%(456-a.y));}
  uint16_t c=(uint16_t)next();for(unsigned i=0;i<N;i++)expected[i]=s_back[i]=(uint16_t)(i*7+sample);
  for(unsigned y=a.y;y<a.y+a.height;y++)for(unsigned x=a.x;x<a.x+a.width;x++)expected[y*280+x]=c;
  rect(nullptr,a.x,a.y,a.width,a.height,c);assert(!memcmp(s_back,expected.data(),N*2));checks++;
 }
 for(unsigned offset:{0u,1u,2u,3u})for(unsigned transparent:{0u,1u}){
  std::vector<uint8_t> source(N*2+8,0x5a),original;
  for(unsigned i=0;i<N;i++){uint16_t c=(uint16_t)i;source[offset+2*i]=(uint8_t)c;source[offset+2*i+1]=(uint8_t)(c>>8);}
  original=source;EkAsset a={};a.flags=(uint16_t)transparent;a.width=280;a.height=456;a.rgb565=source.data()+offset;a.length=N*2;
  for(auto area:edges){
   for(unsigned i=0;i<N;i++)expected[i]=s_back[i]=(uint16_t)(0x5aa5+i*17);
   for(unsigned y=0;y<area.height;y++)for(unsigned x=0;x<area.width;x++){
    unsigned i=(area.y+y)*280+area.x+x;const uint8_t *p=a.rgb565+2*i;uint16_t c=(uint16_t)(p[0]+256*p[1]);if(!transparent||c)expected[i]=c;
   }
   blit_region(nullptr,area.x,area.y,area.x,area.y,area.width,area.height,&a);assert(!memcmp(s_back,expected.data(),N*2));assert(source==original);checks++;
  }
  for(unsigned i=0;i<N;i++)expected[i]=s_back[i]=0x5aa5;
  for(unsigned i=0;i<N;i++){uint16_t c=(uint16_t)i;if(!transparent||c)expected[i]=c;}
  blit(nullptr,0,0,&a);assert(!memcmp(s_back,expected.data(),N*2));assert(source==original);checks++;
  /* Small source pitch and shifted destination/source must stay independent. */
  a.width=64;a.height=60;
  for(unsigned i=0;i<N;i++)expected[i]=s_back[i]=0x5aa5;
  for(unsigned y=0;y<33;y++)for(unsigned x=0;x<51;x++){
   unsigned i=(y+17)*64+x+9;const uint8_t *p=a.rgb565+2*i;uint16_t c=(uint16_t)(p[0]+256*p[1]);if(!transparent||c)expected[(y+41)*280+x+77]=c;
  }
  blit_region(nullptr,77,41,9,17,51,33,&a);assert(!memcmp(s_back,expected.data(),N*2));assert(source==original);checks++;
 }
 assert(storage[0]==0xa55a);for(unsigned i=N+1;i<N+4;i++)assert(storage[i]==0xa55a);
 unsigned boundaries=0;
 for(unsigned w:{1u,7u,8u,63u,64u,65u,127u,128u,129u,279u,280u})for(unsigned pattern=0;pattern<6;pattern++)for(unsigned offset:{0u,1u,2u,3u}){
  std::vector<uint8_t> raw(280*11*2+8,0xa5);unsigned sx=w<280?1:0,dx=w>267?0:13;
  for(unsigned i=0;i<280*11;i++){
   uint16_t c=pattern==0?0:pattern==1?0xffff:pattern==2?(i&1?0:(uint16_t)(i*37+17)):
    pattern==3?(i%129<65?0x1234:0):pattern==4?(i%64==0?0xf00f:0):(uint16_t)i;
   raw[offset+2*i]=(uint8_t)c;raw[offset+2*i+1]=(uint8_t)(c>>8);
  }
  std::vector<uint8_t> immutable=raw;EkAsset a={};a.flags=1;a.width=280;a.height=11;a.rgb565=raw.data()+offset;a.length=280*11*2;
  std::fill(storage.begin(),storage.end(),0xa55a);for(unsigned i=0;i<N;i++)s_back[i]=expected[i]=(uint16_t)(i*37+0x3141);
  for(unsigned y=0;y<7;y++)for(unsigned x=0;x<w;x++){
   const uint8_t *p=a.rgb565+((y+2)*280+x+sx)*2;uint16_t c=(uint16_t)(p[0]+256*p[1]);if(c)expected[(y+17)*280+x+dx]=c;
  }
  blit_rectangle(dx,17,sx,2,w,7,&a);
  assert(memcmp(s_back,expected.data(),N*2)==0&&raw==immutable&&storage.front()==0xa55a&&storage.back()==0xa55a);++boundaries;
 }
 printf("TRANSPARENT BURSTS PASS %u block63/64/65/127/128/129/279/280,empty/visible/alternating/sparse/runs,crop/pitch/oddsource/target2byte/canary oracle cases\n",boundaries);
 unsigned pairs=0;
 for(unsigned x:{11u,12u,13u,14u})for(unsigned w=1;w<32;w++)for(unsigned h:{1u,2u,5u})for(uint16_t colour:{uint16_t(0),uint16_t(1),uint16_t(0xffff),uint16_t(0x3169)}){
  for(unsigned i=0;i<N;i++)s_back[i]=expected[i]=(uint16_t)(i*31+7);
  for(unsigned y=9;y<9+h;y++)for(unsigned col=x;col<x+w;col++)expected[y*280+col]=colour;
  rect(nullptr,x,9,w,h,colour);assert(!memcmp(s_back,expected.data(),N*2));++pairs;
 }
 printf("SMALL RECT PAIRS PASS %u scalaroracle/4alignments/width1to31/height1,2,5/zero,visible,RGB/canaries\n",pairs);
 s_back=nullptr;printf("GRAPHICS PIXELS PASS %u oracle cases: all RGB565, fill thresholds/edges, opaque/transparent, source pitch/odd-byte alignment, destination2-byte alignment, canaries/immutable source\n",checks);
}


static void exchange_contract(){
 const unsigned N=EK_APPS_PIXELS;
 s_back=(uint16_t*)calloc(N,2);s_front=(uint16_t*)calloc(N,2);uint16_t *ui=(uint16_t*)calloc(N,2);
 assert(s_back&&s_front&&ui);s_back_tiles={};s_back_tiles.enabled=true;
 s_front_reference=nullptr;s_front_reference_rows=0;s_dirty={};
 std::vector<uint16_t> back(N),front(N),held(N),asset(33*29);
 for(unsigned i=0;i<asset.size();i++)asset[i]=i%3?(uint16_t)(i*71):0;
 EkAsset a={};a.width=33;a.height=29;a.length=asset.size()*2;a.rgb565=(const uint8_t*)asset.data();
 unsigned random=0x85269413;auto next=[&](){random^=random<<13;random^=random>>17;random^=random<<5;return random;};
 auto put=[&](unsigned x,unsigned y,unsigned w,unsigned h,uint16_t c){rect(nullptr,x,y,w,h,c);for(unsigned row=y;row<y+h;row++)for(unsigned col=x;col<x+w;col++)back[row*280+col]=c;};
 auto publish=[&](unsigned x,unsigned y,unsigned w,unsigned h){present(nullptr,x,y,w,h);for(unsigned row=y;row<y+h;row++)for(unsigned col=x;col<x+w;col++)front[row*280+col]=back[row*280+col];};
 uint32_t generation=0;EkAppsDirty dirty={};unsigned captures=0,exchanges=0,fallbacks=0,last_rows=44;
 unsigned old=full_canvas_copies;
 // Shipping coverage: HUD, viewport, lower UI cover exact tiles, no clone of old back/front.
 for(unsigned frame=0;frame<24;frame++){
  put(0,0,280,64,(uint16_t)(frame+1));put(0,64,280,288,(uint16_t)(frame+99));put(0,352,280,104,(uint16_t)(frame+177));
  assert(!s_back_tiles.reference&&!stale_back());publish(0,0,280,456);
  uint16_t *previous=ui;assert(ek_apps_exchange_frame_transport(&ui,N,&generation,&dirty,44,false));assert(ui!=previous);
  assert(s_copy_stats.method==5&&s_copy_stats.last_bytes==280*44*2);
  for(unsigned i=0;i<N;i++){uint16_t c=ui[i];if(i<280*44)c=(uint16_t)((c<<8)|(c>>8));assert(c==front[i]);}
  assert(!ek_apps_exchange_frame_transport(&ui,N,&generation,&dirty,44,false));++exchanges;++captures;
 }
 assert(full_canvas_copies==old);
 // Independent byte model; preserve unpublished back edits, partial PRESENT, coalesced publications.
 for(unsigned cycle=0;cycle<480;cycle++){
  held.assign(ui,ui+N);
  for(unsigned j=0;j<5;j++){
   unsigned x=next()%248,y=next()%428;
   if(j%2){a.flags=cycle%2;blit(nullptr,x,y,&a);for(unsigned row=0;row<29;row++)for(unsigned col=0;col<33;col++){uint16_t c=asset[row*33+col];if(!a.flags||c)back[(row+y)*280+x+col]=c;}}
   else put(x,y,1+next()%(280-x),1+next()%(456-y),(uint16_t)next());
  }
  if(cycle%13==0){const uint8_t one='1';text_draw(nullptr,73,91,2,0x5a97,&one,1);const unsigned bits=0x2492;for(unsigned row=0;row<5;row++)for(unsigned col=0;col<3;col++)if(bits&(1u<<(row*3+col)))for(unsigned dy=0;dy<2;dy++)for(unsigned dx=0;dx<2;dx++)back[(91+row*2+dy)*280+73+col*2+dx]=0x5a97;}
  if(cycle%3)publish(0,0,280,456);else publish(13,17,241,391);
  if(cycle%7==0){put(1,1,31,9,(uint16_t)cycle);publish(0,0,35,14);}
  assert(!memcmp(ui,held.data(),N*2)); // GUI/DMA-owned snapshot immutable during all guest writes/PRESENT.
  unsigned rows=cycle%5?44:(cycle%10?0:456);uint16_t *previous=ui;
  bool force=rows!=last_rows||cycle%11==0;last_rows=rows;
  assert(ek_apps_exchange_frame_transport(&ui,N,&generation,&dirty,rows,force));
  if(ui!=previous)++exchanges;else ++fallbacks;
  for(unsigned i=0;i<N;i++){uint16_t c=ui[i];if(i<280*rows)c=(uint16_t)((c<<8)|(c>>8));assert(c==front[i]);}
  assert(!ek_apps_exchange_frame_transport(&ui,N,&generation,&dirty,rows,false));
  assert(ek_apps_exchange_frame_transport(&ui,N,&generation,&dirty,rows,true));
  for(unsigned i=0;i<N;i++){uint16_t c=ui[i];if(i<280*rows)c=(uint16_t)((c<<8)|(c>>8));assert(c==front[i]);}
  ++captures;
 }
 assert(exchanges&&fallbacks);assert(s_back!=ui&&s_front!=ui&&s_back!=s_front);
 // Scene failure materializes underlay but changes neither logical Back nor published GUI snapshot.
 held.assign(ui,ui+N);render_ok=false;s_scene3d=(EkScene3D*)malloc(1);
 EvilKey3DScene scene={};render_scene(nullptr,(const uint8_t*)&scene,0,64,280,288);
 prepare_back(0,0,280,456,false);assert(!memcmp(s_back,back.data(),N*2));assert(!memcmp(ui,held.data(),N*2));
 assert(!ek_apps_exchange_frame_transport(&s_back,N,&generation,&dirty,44,true));
 render_ok=paint_scene=true;render_scene(nullptr,(const uint8_t*)&scene,0,64,280,288);paint_scene=false;
 for(unsigned row=64;row<352;row++)for(unsigned col=0;col<280;col++)back[row*280+col]=(uint16_t)(row*37+col*73);
 publish(0,0,280,456);std::vector<uint16_t> legacy(N);uint32_t legacy_generation=0;
 assert(ek_apps_copy_frame(legacy.data(),N,&legacy_generation,&dirty));assert(legacy==front);
 assert(ek_apps_exchange_frame_transport(&ui,N,&generation,&dirty,44,true));
 for(unsigned i=0;i<N;i++){uint16_t c=ui[i];if(i<280*44)c=(uint16_t)((c<<8)|(c>>8));assert(c==front[i]);}
 held.assign(ui,ui+N);
 stop_vm();assert(!s_back&&!s_front&&!s_front_reference&&!s_back_tiles.reference);assert(!memcmp(ui,held.data(),N*2));
 run_selected("probe");assert(s_back!=ui&&s_front!=ui&&s_back!=s_front);
 assert(ek_apps_exchange_frame_transport(&ui,N,&generation,&dirty,44,true));for(unsigned i=0;i<N;i++)assert(!ui[i]);
 stop_vm();free(ui);scene_allocations=scene_frees=0;render_ok=false;
 printf("EXCHANGE PASS %u captures (%u exchanged,%u fallback): independent byte model, shipping zero full-canvas copies, opaque/transparent, partial/coalesced/repeat/force/0-44-456 rows, immutable GUI/DMA, scene fault underlay, unique ownership/stop cleanup\n",captures,exchanges,fallbacks);
}

static void concurrent_exchange_contract(){
 const unsigned N=EK_APPS_PIXELS;s_back=(uint16_t*)calloc(N,2);s_front=(uint16_t*)calloc(N,2);uint16_t *ui=(uint16_t*)calloc(N,2);
 s_back_tiles={};s_back_tiles.enabled=true;s_front_reference=nullptr;s_front_reference_rows=0;s_dirty={};
 uint32_t generation=s_state.frame;std::atomic<bool> done{false};std::thread publisher([&](){for(unsigned i=1;i<=700;i++){rect(nullptr,0,0,280,456,(uint16_t)i);present(nullptr,0,0,280,456);}done=true;});
 EkAppsDirty dirty={};unsigned captures=0;
 while(!done.load())if(ek_apps_exchange_frame_transport(&ui,N,&generation,&dirty,44,false)){
  uint16_t expected=ui[44*280];for(unsigned i=0;i<N;i++){uint16_t c=ui[i];if(i<44*280)c=(uint16_t)((c<<8)|(c>>8));assert(c==expected);}++captures;
 }
 publisher.join();if(ek_apps_exchange_frame_transport(&ui,N,&generation,&dirty,44,false))++captures;
 assert(captures);for(unsigned i=0;i<N;i++){uint16_t c=ui[i];if(i<44*280)c=(uint16_t)((c<<8)|(c>>8));assert(c==700);}
 stop_vm();for(unsigned i=44*280;i<N;i++)assert(ui[i]==700);free(ui);
 printf("EXCHANGE CONCURRENT PASS 700 full publications, %u immutable snapshots; latest generation and separate owners\n",captures);
}
static void draw_profile_contract(){
 EkRunMetrics saved=s_run_metrics;s_run_metrics={};s_run_metrics.current=0;
 EkRunRecord *r=&s_run_metrics.record[0];r->sequence=1;r->phase=EK_RUN_ACTIVE;
 uint32_t groups[4]={11,34,58,0};profile_draw(nullptr,groups);
 assert(ek_run_draw_count(r)==1&&r->draw_total_us[0]==11&&r->draw_total_us[3]==0);
 r->phase=EK_RUN_PAUSED;profile_draw(nullptr,groups);assert(ek_run_draw_count(r)==1);
 r->phase=EK_RUN_ACTIVE;s_run_metrics.modal=1;profile_draw(nullptr,groups);assert(ek_run_draw_count(r)==1);s_run_metrics.modal=0;
 s_display_generation=123;s_display_run_frame={1,1,1,0};
 uint32_t detail[4]={10,100,20,30};
 ek_apps_display_complete_raster(123,true,160,0,5,detail,8,77,true);
 assert(r->completed==1&&r->draw_total_us[4]==77&&!ek_run_draw_flags(r));assert(r->draw_lvgl_count==1);
 ek_apps_display_complete_raster(123,true,160,0,5,detail,8,77,true);
 assert(r->completed==1&&r->draw_total_us[4]==77);
 s_display_run_frame={1,2,1,0};ek_apps_display_complete_raster(123,true,160,0,5,detail,8,0,false);
 assert(r->completed==2&&r->draw_total_us[4]==77&&r->draw_lvgl_count==1&&!ek_run_draw_flags(r));
 s_display_run_frame={1,3,1,0};ek_apps_display_complete_detail(123,true,160,0,5,detail,8);
 assert(r->completed==3&&r->draw_total_us[4]==77&&ek_run_draw_flags(r)==2);
 s_run_metrics=saved;s_display_run_frame={};s_display_generation=0;
 puts("DRAW SERVICE PASS sampled/unsampled active/paused/modal, zero category, matching final ACK, duplicate ticket no double count, old API no overread and explicit missing measurement");
}
int main(){
 assert(!ek_apps_diagnostics_export_request());
 EkDiagnosticsExport exported;ek_apps_diagnostics_export_snapshot(&exported);assert(exported.status==EK_DIAGNOSTICS_EXPORT_ERROR);
 ek_apps_diagnostics_export_snapshot(nullptr);
 EkSceneProfile native;ek_apps_scene_profile(&native);assert(!native.stats.status);
 assert(ek_apps_start());s_state.mounted=true;
 assert(!ek_apps_diagnostics_enabled());assert(!ek_apps_diagnostics_export_request());
 configure_diagnostics();assert(!s_vm.host.measurement&&!s_vm.host.clock&&!s_vm.host.execution_profile&&!s_vm.host.execution_detail&&!s_vm.host.execution_draw);
 graphics_pixels_contract();concurrent_exchange_contract();
 assert(!s_copy_stats.copies);
 ek_apps_diagnostics_enable(true);configure_diagnostics();draw_profile_contract();
 graphics_pixels_contract();
 frame_copy_contract();
 block_copy_contract();
 mixed_copy_contract();
 exchange_contract();
 concurrent_exchange_contract();
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
 run_metrics_contract(&scene);
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

 // Disable collection while preserving VM execution and an already-owned export.
 submit_report();assert(s_diagnostics_report);unsigned writes_before=report_writes;
 ek_apps_diagnostics_enable(false);assert(!ek_apps_diagnostics_export_request());
 configure_diagnostics();assert(!s_vm.host.measurement&&!s_vm.host.clock&&!s_vm.host.execution_profile&&!s_vm.host.execution_detail&&!s_vm.host.execution_draw);
 assert(s_run_metrics.current==-1&&!s_pending_run_frame.eligible&&!s_display_run_frame.eligible);
 uint32_t counts[4]={9,8,7,6};profile_draw(nullptr,counts);profile_run(nullptr,999,888);measure_run(nullptr,0x23000044,10,20);
 assert(s_run_metrics.current==-1);copy_clock_step=10;copy_clock_offset=0;
 assert(diagnostic_clock(nullptr)==0&&copy_clock_offset==0);
 s_vm.draw_profile_tick=1;s_vm.measurement_function=(IM3Function)1;
 assert(!s_vm.host.execution_draw);once();assert(report_writes==writes_before+1&&!s_diagnostics_report);
 ek_apps_diagnostics_enable(true);configure_diagnostics();
 assert(s_vm.host.measurement&&s_vm.host.clock&&s_vm.host.execution_profile&&s_vm.host.execution_detail&&s_vm.host.execution_draw);
 measure_run(nullptr,0x23000044,10,20);auto *partial=ek_run_current(&s_run_metrics);assert(partial&&partial->partial);
 measure_run(nullptr,0x43000044,10,20);assert(partial->phase==EK_RUN_COMPLETE&&partial->partial&&!partial->telemetry_errors);
 measure_run(nullptr,0x13000045,10,20);auto *full=ek_run_current(&s_run_metrics);assert(full&&!full->partial);
 measure_run(nullptr,0x23000045,10,20);assert(!full->partial&&full->phase==EK_RUN_ACTIVE&&!full->telemetry_errors);
 ek_apps_diagnostics_enable(false);configure_diagnostics();assert(s_run_metrics.current==-1);
 puts("DIAGNOSTIC GATE PASS default OFF; pixels and 700 publications both states; full transport suite ON; no callbacks/optional clocks/tickets OFF; API export rejected OFF; accepted export finished after OFF; partial mid-run; new countdown full; Apps owner callbacks only");
 puts("PASS worker: 0/1/5/9/10/70 catalog, 64 limit, page-only icons, cache generations, launch bounds, hidden stop, USB role release, scan cancellation, ABI4/5 allocation and failure cleanup, no I/O under guard");
}
