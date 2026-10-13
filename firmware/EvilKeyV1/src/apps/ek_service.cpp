/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Apps worker. Only this task touches microSD or executes Wasm. The FIDO
 * task never waits for app I/O or guest code. Display admission serializes
 * only native pre-copy compute, independently of storage and guest execution.
 */
#include "ek_service.h"
#include "ek_storage.h"
#include "ek_vm.h"
#include "ek_render_parallel.h"
#include "ek_pixel_accel.h"
#include <esp_timer.h>
#include <Arduino.h>
#include <esp_heap_caps.h>
#include <esp_attr.h>
#include <esp_log.h>
#include <esp_system.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
#include <freertos/task.h>
#include <string.h>
#include <stdio.h>

static SemaphoreHandle_t s_guard;
static EkAppsState s_state;
static bool s_visible;
extern "C" bool pf_apps_storage_role_allowed(void);
static EkPackageInfo *s_catalog;
static uint8_t *s_icons,*s_icon_scratch;
static uint32_t s_last_scan_at;
static bool s_icons_pending;
static bool s_modal;
static EkAppsCommand s_command;
static EvilKeyAppTouch s_touches[2];
static uint32_t s_touch_count;
static bool s_accel_valid;
static int32_t s_accel_x,s_accel_y,s_accel_z;
static uint16_t *s_back,*s_front;
/* Fixed metadata only. All three pixel allocations keep a single owner. */
struct BackTiles {uint32_t stale[63];const uint16_t *reference;unsigned panel_rows;bool enabled;};
static BackTiles s_back_tiles;
static const uint16_t *s_front_reference;
static unsigned s_front_reference_rows;
static_assert(sizeof(BackTiles)+sizeof(s_front_reference)+sizeof(s_front_reference_rows)<=312,"bounded virtual framebuffer metadata");
static void materialize_front_locked();
static bool stale_back(){for(unsigned i=0;i<63;i++)if(s_back_tiles.stale[i])return true;return false;}
static void rebase_back_locked(const uint16_t *reference,unsigned panel_rows){
    if(s_back_tiles.reference){s_back_tiles.reference=reference;s_back_tiles.panel_rows=panel_rows;}
}
static void prepare_back_locked(unsigned x,unsigned y,unsigned width,unsigned height,bool opaque){
    if(!s_back_tiles.enabled||!s_back_tiles.reference||!width||!height)return;
    const unsigned right=x+width,bottom=y+height;
    for(unsigned ty=y/8;ty<=(bottom-1)/8;ty++)for(unsigned tx=x/8;tx<=(right-1)/8;tx++){
        const unsigned tile=ty*35+tx,mask=1u<<(tile&31);
        if(!(s_back_tiles.stale[tile/32]&mask))continue;
        const unsigned left=tx*8,top=ty*8;
        if(!opaque||x>left||y>top||right<left+8||bottom<top+8){
            for(unsigned row=top;row<top+8;row++)for(unsigned col=left;col<left+8;col++){
                uint16_t value=s_back_tiles.reference[row*EK_APPS_WIDTH+col];
                if(row<s_back_tiles.panel_rows)value=(uint16_t)((value<<8)|(value>>8));
                s_back[row*EK_APPS_WIDTH+col]=value;
            }
        }
        s_back_tiles.stale[tile/32]&=~mask;
    }
    if(!stale_back())s_back_tiles.reference=nullptr;
}
static void prepare_back(unsigned x,unsigned y,unsigned width,unsigned height,bool opaque){
    if(!s_back_tiles.enabled)return;
    xSemaphoreTake(s_guard,portMAX_DELAY);
    prepare_back_locked(x,y,width,height,opaque);
    xSemaphoreGive(s_guard);
}
static EkAppsDirty s_dirty;
static uint8_t *s_payload;
static EkAssets s_assets;
static char s_running_id[32];
static EkVm s_vm;
static EkScene3D *s_scene3d;
static EkAppsCopyStats s_copy_stats;
static_assert(sizeof(EkAppsCopyStats)==28,"bounded app copy snapshot");
static EkSceneProfile s_scene_profile;
static EkRunMetrics s_run_metrics={{},{},0,0,-1,0};
static uint32_t s_diagnostics_epoch;
static uint32_t s_applied_diagnostics_epoch;
static uint32_t s_partial_epoch,s_partial_tag;
static EkRunFrame s_pending_run_frame,s_front_run_frame,s_display_run_frame;
static uint32_t s_scene_sequence,s_display_generation;
static uint64_t s_step_started_us;
static_assert(sizeof(EkRunMetrics)<=3072,"bounded full-run diagnostic RAM");
static EkDiagnosticsExport s_diagnostics_export;
static char *s_diagnostics_report;
static size_t s_diagnostics_report_size;
static_assert(sizeof(s_scene_profile)==44,"fixed native diagnostic snapshot");
/* The 4 KiB save mailbox must not live on the 16 KiB Apps task stack or in
 * internal BSS needed by TinyUSB. Only the Apps worker uses this PSRAM copy. */
static EvilKeyAppInput *s_input;
static bool s_save_queued;
static uint32_t s_save_queued_size;
static bool s_vm_open;
static bool s_started;
static bool s_previous_app_reset;
static uint32_t s_app_time_ms,s_last_wall_ms;
static constexpr uint32_t kCrashMark=0x454B4154U;
enum AppStage : uint32_t { APP_IDLE=0, APP_LOAD=1, APP_FRAMES=2,
                           APP_VM_OPEN=3, APP_INPUT=4, APP_SAVE_LOAD=5,
                           APP_INIT=6, APP_RUNNING=7, APP_SAVE_PROBE=8,
                           APP_SAVE_CREATE=9, APP_SAVE_ALLOC=10,
                           APP_SAVE_OPEN=11, APP_SAVE_SCAN=12,
                           APP_SAVE_PREPARE=13, APP_SAVE_WRITE=14,
                           APP_SAVE_FLUSH=15 };
struct AppCrashMark { uint32_t magic, stage, inverse, stack_free, heap_free; };
RTC_NOINIT_ATTR static AppCrashMark s_crash_mark;

static void mark_stage(AppStage stage) {
    s_crash_mark.magic=kCrashMark;
    s_crash_mark.stage=stage;
    s_crash_mark.inverse=~static_cast<uint32_t>(stage);
    s_crash_mark.stack_free=(uint32_t)uxTaskGetStackHighWaterMark(nullptr);
    s_crash_mark.heap_free=(uint32_t)heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
}
static const char *stage_name(uint32_t stage) {
    switch (stage) {
    case APP_LOAD:return "microSD";
    case APP_FRAMES:return "display memory";
    case APP_VM_OPEN:return "VM open";
    case APP_INPUT:return "input snapshot";
    case APP_SAVE_LOAD:return "save load";
    case APP_INIT:return "app_init";
    case APP_RUNNING:return "app runtime";
    case APP_SAVE_PROBE:return "save probe";
    case APP_SAVE_CREATE:return "save create";
    case APP_SAVE_ALLOC:return "save alloc";
    case APP_SAVE_OPEN:return "save open";
    case APP_SAVE_SCAN:return "save scan";
    case APP_SAVE_PREPARE:return "save prepare";
    case APP_SAVE_WRITE:return "save write";
    case APP_SAVE_FLUSH:return "save flush";
    default:return "unknown";
    }
}
static void log_memory(const char *stage) {
    ESP_LOGI("ek_apps","%s: PSRAM free=%u largest=%u, internal free=%u, stack free=%u",
             stage,
             (unsigned)heap_caps_get_free_size(MALLOC_CAP_SPIRAM),
             (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_SPIRAM),
             (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL),
             (unsigned)uxTaskGetStackHighWaterMark(nullptr));
}

static void state_text(const char *text) {
    xSemaphoreTake(s_guard,portMAX_DELAY);
    snprintf(s_state.status,sizeof(s_state.status),"%s",text);
    xSemaphoreGive(s_guard);
}
/* Use a bounded internal-stack source instead of halfword stores to PSRAM.
 * Keep this frame out of tiny glyph rectangles and out of the caller's frame. */
static __attribute__((noinline)) void fill_rect_blocks(int32_t x,int32_t y,
                                                      int32_t w,int32_t h,uint16_t colour) {
    uint16_t block[256];
    const size_t count=(size_t)w<256u?(size_t)w:256u;
    for(size_t i=0;i<count;++i)block[i]=colour;
    if(x==0 && w==EK_APPS_WIDTH) {
        uint16_t *target=s_back+y*EK_APPS_WIDTH;
        size_t left=(size_t)w*(size_t)h;
        while(left) {
            const size_t n=left<count?left:count;
            memcpy(target,block,n*sizeof(uint16_t));target+=n;left-=n;
        }
    } else {
        for(int32_t row=y;row<y+h;++row) {
            uint16_t *target=s_back+row*EK_APPS_WIDTH+x;
            size_t left=(size_t)w;
            while(left) {
                const size_t n=left<count?left:count;
                memcpy(target,block,n*sizeof(uint16_t));target+=n;left-=n;
            }
        }
    }
}
static void rect(void *,int32_t x,int32_t y,int32_t w,int32_t h,uint16_t colour) {
    if (!s_back) return;
    prepare_back(x,y,w,h,true);
    if(w>0&&h>0&&ek_pixel_accel_rect(s_back+y*EK_APPS_WIDTH+x,EK_APPS_WIDTH,
        nullptr,0,(size_t)w,(size_t)h,colour,false))return;
    if(w>=32 && (size_t)w*(size_t)h>=256u) {
        fill_rect_blocks(x,y,w,h,colour);return;
    }
    typedef uint32_t __attribute__((__may_alias__)) PixelPair;
    const uint32_t pair=(uint32_t)colour|((uint32_t)colour<<16);
    for (int32_t row=y;row<y+h;++row) {
        uint16_t *line=s_back+row*EK_APPS_WIDTH+x;
        int32_t left=w;
        if(left>=2){
            if((uintptr_t)line&3u){*line++=colour;--left;}
            while(left>=2){*(PixelPair *)line=pair;line+=2;left-=2;}
        }
        while(left-->0)*line++=colour;
    }
}
static uint64_t scene_clock(void *) {return (uint64_t)esp_timer_get_time();}
static uint64_t diagnostic_clock(void *){return ek_render_diagnostics_enabled()?scene_clock(nullptr):0;}
static void profile_run(void *,uint32_t guest_us,uint32_t output_us){
    if(!ek_render_diagnostics_enabled())return;
    xSemaphoreTake(s_guard,portMAX_DELAY);
    ek_run_active_stage(&s_run_metrics,EK_STAGE_GUEST,guest_us);
    ek_run_active_stage(&s_run_metrics,EK_STAGE_OUTPUT,output_us);
    xSemaphoreGive(s_guard);
}
static void profile_detail(void *,uint32_t validation,uint32_t draw,uint32_t publishing){
    if(!ek_render_diagnostics_enabled())return;
    xSemaphoreTake(s_guard,portMAX_DELAY);
    ek_run_active_stage(&s_run_metrics,EK_STAGE_OUTPUT_VALIDATE,validation);
    ek_run_active_stage(&s_run_metrics,EK_STAGE_OUTPUT_DRAW,draw);
    ek_run_active_stage(&s_run_metrics,EK_STAGE_OUTPUT_PRESENT,publishing);
    xSemaphoreGive(s_guard);
}
static void profile_draw(void *,const uint32_t groups[4]){
    if(!ek_render_diagnostics_enabled())return;
    xSemaphoreTake(s_guard,portMAX_DELAY);
    ek_run_draw(&s_run_metrics,groups);
    xSemaphoreGive(s_guard);
}
static void measure_run(void *,uint32_t token,uint32_t gas,uint32_t memory){
    if(!ek_render_diagnostics_enabled())return;
    xSemaphoreTake(s_guard,portMAX_DELAY);
    // Enabling during an existing active run cannot produce a complete-run claim.
    if(token){
        uint32_t epoch=token&0x7fffffu,tag=(token>>24)&15,phase=token>>28;
        if(s_run_metrics.current<0&&phase!=EK_RUN_COUNTDOWN){s_partial_epoch=epoch;s_partial_tag=tag;}
        if(epoch==s_partial_epoch&&tag==s_partial_tag)token|=1u<<23;
    }
    ek_run_token(&s_run_metrics,token,gas,memory,scene_clock(nullptr));
    xSemaphoreGive(s_guard);
}
static EkSceneStats render_scene(void *,const uint8_t *scene,unsigned x,unsigned y,unsigned w,unsigned h) {
    const uint64_t wall_start=diagnostic_clock(nullptr);
    prepare_back(x,y,w,h,false);
    EkSceneStats stats=ek_scene3d_render(s_scene3d,scene,s_back,EK_APPS_WIDTH,x,y,w,h,scene_clock,nullptr);
    if(!ek_render_diagnostics_enabled())return stats;
    const uint32_t wall_us=ek_run_sat(scene_clock(nullptr)-wall_start);
    EkSceneProfile profile=ek_scene3d_profile(s_scene3d);
    unsigned faces=0,objects=ek3_u16(scene+6),materials=ek3_u16(scene+8);
    for(unsigned i=0;i<objects;i++){
        unsigned model=ek3_u16(scene+100+32*i);
        if(model&0x8000u){const EkAsset *a=ek3_asset(&s_assets,model&0x7fffu);if(a)faces+=a->mesh_triangles;}
        else faces+=ek3_faces(model);
    }
    EkRenderFrameStats admission;ek_render_frame_stats(&admission);
    xSemaphoreTake(s_guard,portMAX_DELAY);s_scene_profile=profile;
    ek_run_active_stage(&s_run_metrics,EK_STAGE_NATIVE_WALL,wall_us);
    ek_run_active_stage(&s_run_metrics,EK_STAGE_NATIVE_QUEUE,admission.wait_last_us[0]);
    ek_run_active_stage(&s_run_metrics,EK_STAGE_NATIVE_PRECOPY,ek_run_precopy(&profile));
    ek_run_active_stage(&s_run_metrics,EK_STAGE_NATIVE_RECONSTRUCT,profile.reconstruct_us);
    if(!++s_scene_sequence)++s_scene_sequence;
    s_pending_run_frame=ek_run_native(&s_run_metrics,&profile,s_scene_sequence,
        admission.wait_last_us[0],objects,materials,faces,scene_clock(nullptr));
    s_pending_run_frame.started_us=s_step_started_us;
    xSemaphoreGive(s_guard);
    return stats;
}
static void present(void *,int32_t x,int32_t y,int32_t w,int32_t h) {
    if (!s_back || !s_front) return;
    
    xSemaphoreTake(s_guard,portMAX_DELAY);
    prepare_back_locked(x,y,w,h,false);
    if(s_back_tiles.enabled&&x==0&&y==0&&w==EK_APPS_WIDTH&&h==EK_APPS_HEIGHT){
        uint16_t *previous=s_front;s_front=s_back;s_back=previous;
        s_front_reference=nullptr;s_front_reference_rows=0;
        for(unsigned i=0;i<63;i++)s_back_tiles.stale[i]=UINT32_MAX;
        s_back_tiles.stale[62]=(1u<<11)-1u; /* 1995 tiles, no unused bits */
        s_back_tiles.reference=s_front;s_back_tiles.panel_rows=0;
    }else{
    materialize_front_locked();
    if(x==0 && w==EK_APPS_WIDTH)
        memcpy(s_front+y*EK_APPS_WIDTH,s_back+y*EK_APPS_WIDTH,
               (size_t)w*(size_t)h*sizeof(uint16_t));
    else for (int32_t row=y;row<y+h;++row)
        memcpy(s_front+row*EK_APPS_WIDTH+x,s_back+row*EK_APPS_WIDTH+x,
               (size_t)w*sizeof(uint16_t));
    }
    if (!s_dirty.width) s_dirty={(uint16_t)x,(uint16_t)y,(uint16_t)w,(uint16_t)h};
    else {
        int32_t left=s_dirty.x<x?s_dirty.x:x;
        int32_t top=s_dirty.y<y?s_dirty.y:y;
        int32_t right=(s_dirty.x+s_dirty.width)>(x+w)?
            s_dirty.x+s_dirty.width:x+w;
        int32_t bottom=(s_dirty.y+s_dirty.height)>(y+h)?
            s_dirty.y+s_dirty.height:y+h;
        s_dirty={(uint16_t)left,(uint16_t)top,
                 (uint16_t)(right-left),(uint16_t)(bottom-top)};
    }
    ++s_state.frame;
    if(ek_render_diagnostics_enabled())s_front_run_frame=ek_run_present(&s_run_metrics,&s_pending_run_frame,scene_clock(nullptr));
    xSemaphoreGive(s_guard);
    
}
static void blit_rectangle(int32_t x,int32_t y,uint32_t sx,uint32_t sy,
                           uint32_t width,uint32_t height,const EkAsset *asset) {
    if (!s_back || !asset) return;
    prepare_back(x,y,width,height,!(asset->flags&1u));
    if(ek_pixel_accel_rect(s_back+y*EK_APPS_WIDTH+x,EK_APPS_WIDTH,
        asset->rgb565+(sy*asset->width+sx)*2u,asset->width,width,height,0,(asset->flags&1u)!=0))return;
    if(!(asset->flags&1u)) {
        if(x==0 && width==EK_APPS_WIDTH && sx==0 && asset->width==EK_APPS_WIDTH)
            memcpy(s_back+y*EK_APPS_WIDTH,asset->rgb565+sy*asset->width*2u,
                   (size_t)width*height*sizeof(uint16_t));
        else for(uint32_t row=0;row<height;++row) {
            memcpy(s_back+(y+(int32_t)row)*EK_APPS_WIDTH+x,
                   asset->rgb565+((sy+row)*asset->width+sx)*2u,
                   (size_t)width*sizeof(uint16_t));
        }
        return;
    }
    for (uint32_t row=0;row<height;++row) {
        uint16_t *target=s_back+(y+(int32_t)row)*EK_APPS_WIDTH+x;
        const uint8_t *source=asset->rgb565+((sy+row)*asset->width+sx)*2u;
        uint32_t col=0;
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        typedef uint32_t __attribute__((__may_alias__)) PixelPair;
        if(!(((uintptr_t)source|(uintptr_t)target)&3u)){
            for(;col+1<width;col+=2){
                uint32_t pair=*(const PixelPair *)(source+col*2u);
                uint16_t first=(uint16_t)pair,second=(uint16_t)(pair>>16);
                if(first&&second)*(PixelPair *)(target+col)=pair;
                else if(first)target[col]=first;
                else if(second)target[col+1]=second;
            }
        }
#endif
        for (;col<width;++col) {
            uint16_t pixel=(uint16_t)(source[col*2u] |
                                      ((uint16_t)source[col*2u+1]<<8));
            if (pixel) target[col]=pixel;
        }
    }
}
static void blit(void *,int32_t x,int32_t y,const EkAsset *asset) {
    if(asset)blit_rectangle(x,y,0,0,asset->width,asset->height,asset);
}
static void blit_region(void *,int32_t x,int32_t y,uint32_t sx,uint32_t sy,
                        uint32_t width,uint32_t height,const EkAsset *asset) {
    blit_rectangle(x,y,sx,sy,width,height,asset);
}
/* Compact built-in 3x5 glyphs for status and scores. Apps can also bundle
 * detailed lettering as image assets when a specific visual style is needed. */
static uint16_t glyph(char c) {
    if (c>='a' && c<='z') c=(char)(c-'a'+'A');
    switch(c) {
    case 'A':return 0x7bed;case 'B':return 0x7aeb;case 'C':return 0x724f;
    case 'D':return 0x7b6b;case 'E':return 0x72cf;case 'F':return 0x12cf;
    case 'G':return 0x7a4f;case 'H':return 0x5bed;case 'I':return 0x7497;
    case 'J':return 0x3a48;case 'K':return 0x5bad;case 'L':return 0x7249;
    case 'M':return 0x5f7d;case 'N':return 0x5f6d;case 'O':return 0x7b6f;
    case 'P':return 0x13ef;case 'Q':return 0x5f6f;case 'R':return 0x5bef;
    case 'S':return 0x79cf;case 'T':return 0x2497;case 'U':return 0x7b6d;
    case 'V':return 0x2b6d;case 'W':return 0x5f6d;case 'X':return 0x5aad;
    case 'Y':return 0x24ad;case 'Z':return 0x72d7;
    case '0':return 0x7b6f;case '1':return 0x2492;case '2':return 0x73e7;
    case '3':return 0x79e7;case '4':return 0x49ed;case '5':return 0x79cf;
    case '6':return 0x7bcf;case '7':return 0x2497;case '8':return 0x7bef;
    case '9':return 0x79ef;case ':':return 0x0404;case '.':return 0x4000;
    case '-':return 0x01c0;case '/':return 0x1250;case '!':return 0x040e;
    case '?':return 0x04e7;default:return 0;
    }
}
static void text_draw(void *,int32_t x,int32_t y,uint32_t scale,
                      uint16_t colour,const uint8_t *ascii,uint32_t length) {
    if (!s_back) return;
    for (uint32_t i=0;i<length;++i) {
        uint16_t bits=glyph((char)ascii[i]);
        for (uint32_t row=0;row<5;++row)
            for (uint32_t col=0;col<3;++col)
                if (bits & (1u<<(row*3u+col)))
                    rect(nullptr,x+(int32_t)((i*6u+col)*scale),
                         y+(int32_t)(row*scale),(int32_t)scale,
                         (int32_t)scale,colour);
    }
}
static int save_app(void *,const uint8_t *data,uint32_t size) {
    if (!s_input || s_save_queued || size>EVILKEY_APP_MAX_SAVE_BYTES ||
        (!data && size)) return 0;
    if (size) memcpy(s_input->save_data,data,size);
    s_save_queued_size=size;
    s_save_queued=true;
    return 1;
}
static void save_progress(void *,unsigned phase) {
    switch (phase) {
    case EK_SAVE_PROBE:mark_stage(APP_SAVE_PROBE);break;
    case EK_SAVE_CREATE:mark_stage(APP_SAVE_CREATE);break;
    case EK_SAVE_ALLOC:mark_stage(APP_SAVE_ALLOC);break;
    case EK_SAVE_OPEN:mark_stage(APP_SAVE_OPEN);break;
    case EK_SAVE_SCAN:mark_stage(APP_SAVE_SCAN);break;
    case EK_SAVE_PREPARE:mark_stage(APP_SAVE_PREPARE);break;
    case EK_SAVE_WRITE:mark_stage(APP_SAVE_WRITE);break;
    case EK_SAVE_FLUSH:mark_stage(APP_SAVE_FLUSH);break;
    }
}
static void flush_save(void) {
    if (!s_save_queued) return;
    bool ok=ek_storage_save_write(s_running_id,s_input->save_data,
                                  s_save_queued_size,save_progress,nullptr)!=0;
    s_save_queued=false;
    s_vm.save_status=ok?EVILKEY_APP_SAVE_OK:EVILKEY_APP_SAVE_FAILED;
    mark_stage(APP_RUNNING);
}
static void input_snapshot(EvilKeyAppInput *input,uint32_t now_ms) {
    memset(input,0,sizeof(*input));
    input->now_ms=now_ms;
    xSemaphoreTake(s_guard,portMAX_DELAY);
    input->touch_count=s_touch_count;
    memcpy(input->touch,s_touches,sizeof(s_touches));
    input->accel_valid=s_accel_valid?1u:0u;
    input->accel_x_mg=s_accel_x;
    input->accel_y_mg=s_accel_y;
    input->accel_z_mg=s_accel_z;
    xSemaphoreGive(s_guard);
}
/* Caller owns the state guard. Catalog strings are published together. */
static void page_metadata(void) {
    memset(s_state.names,0,sizeof(s_state.names));
    for (unsigned slot=0;slot<EK_APPS_PAGE_SIZE;++slot) {
        unsigned i=s_state.page*EK_APPS_PAGE_SIZE+slot;
        if (i<s_state.count)
            memcpy(s_state.names[slot],s_catalog[i].name,sizeof(s_state.names[slot]));
    }
    s_state.icon_valid=0;
    memset(s_icons,0,EK_APPS_PAGE_SIZE*EK_APPS_ICON_BYTES);
    ++s_state.catalog_generation;
    s_icons_pending=true;
}
static void scan_catalog(void) {
    uint32_t started=ek_render_diagnostics_enabled()?millis():0;
    xSemaphoreTake(s_guard,portMAX_DELAY);
    unsigned previous_page=s_state.page;
    s_state.scanning=true;
    xSemaphoreGive(s_guard);
    unsigned total=0,headers=0;bool overflow=false,cancelled=false;
    int step=ek_storage_scan_begin();
    while (step>0) {
        if (!pf_apps_storage_role_allowed()) {cancelled=true;break;}
        EkPackageInfo info;bool header_read=false;
        step=ek_storage_scan_step(&info,&header_read);
        headers+=header_read?1:0;
        if (step==1) {
            if (total<EK_APPS_CATALOG_MAX) s_catalog[total++]=info;
            else overflow=true;
        }
        vTaskDelay(pdMS_TO_TICKS(1));
    }
    ek_storage_scan_end();
    /* Stable names make page order independent of FAT directory ordering. */
    for (unsigned i=1;i<total;++i) {
        EkPackageInfo value=s_catalog[i];unsigned j=i;
        while (j && strcmp(s_catalog[j-1].id,value.id)>0) {
            s_catalog[j]=s_catalog[j-1];--j;
        }
        s_catalog[j]=value;
    }
    xSemaphoreTake(s_guard,portMAX_DELAY);
    s_state.count=(cancelled || step<0)?0:(uint8_t)total;
    unsigned pages=(s_state.count+EK_APPS_PAGE_SIZE-1)/EK_APPS_PAGE_SIZE;
    s_state.page=(uint8_t)(pages?(previous_page<pages?previous_page:pages-1):0);
    s_state.selected=(uint8_t)(s_state.page*EK_APPS_PAGE_SIZE);
    s_state.scanning=false;s_state.catalog_ready=!cancelled && step==0;
    s_state.overflow=overflow;s_state.headers_read=headers;
    s_state.scan_ms=ek_render_diagnostics_enabled()?millis()-started:0;
    snprintf(s_state.id,sizeof(s_state.id),"%s",s_state.count?s_catalog[s_state.selected].id:"");
    page_metadata();
    if (!s_previous_app_reset)
        snprintf(s_state.status,sizeof(s_state.status),"%s",
            cancelled?"USB role owns microSD":step<0?"microSD scan failed":
            overflow?"First 64 apps shown":total?"Tap an app to run":"No apps on microSD");
    xSemaphoreGive(s_guard);
    if(cancelled || step<0) {
        ek_storage_end();
        xSemaphoreTake(s_guard,portMAX_DELAY);s_state.mounted=false;xSemaphoreGive(s_guard);
    }
    s_previous_app_reset=false;s_last_scan_at=millis();
    ESP_LOGI("ek_apps","catalog: mount=%u ms scan=%u ms headers=%u apps=%u overflow=%u",
        (unsigned)s_state.mount_ms,(unsigned)s_state.scan_ms,headers,total,(unsigned)overflow);
}
static void load_page_icons(void) {
    xSemaphoreTake(s_guard,portMAX_DELAY);
    unsigned page=s_state.page,count=s_state.count;
    xSemaphoreGive(s_guard);
    uint32_t started=ek_render_diagnostics_enabled()?millis():0;
    for (unsigned slot=0;slot<EK_APPS_PAGE_SIZE;++slot) {
        unsigned i=page*EK_APPS_PAGE_SIZE+slot;
        if (i>=count || !pf_apps_storage_role_allowed()) break;
        xSemaphoreTake(s_guard,portMAX_DELAY);
        bool current=s_state.page==page && s_visible && s_command==EK_APPS_NONE;
        xSemaphoreGive(s_guard);
        if (!current) return;
        bool valid=ek_storage_icon(&s_catalog[i],s_icon_scratch,EK_APPS_ICON_BYTES)!=0;
        xSemaphoreTake(s_guard,portMAX_DELAY);
        if (s_state.page==page && valid) {
            memcpy(s_icons+slot*EK_APPS_ICON_BYTES,s_icon_scratch,EK_APPS_ICON_BYTES);
            s_state.icon_valid|=(uint16_t)(1u<<slot);
        }
        if (!valid) snprintf(s_state.status,sizeof(s_state.status),"App icon missing or corrupt");
        ++s_state.catalog_generation;
        xSemaphoreGive(s_guard);
        vTaskDelay(pdMS_TO_TICKS(1));
    }
    xSemaphoreTake(s_guard,portMAX_DELAY);
    s_state.icon_ms=ek_render_diagnostics_enabled()?millis()-started:0;s_icons_pending=false;
    xSemaphoreGive(s_guard);
    ESP_LOGI("ek_apps","page %u icons=%u ms",page,(unsigned)s_state.icon_ms);
}
static void stop_vm(void) {
    if (s_vm_open) {ek_vm_close(&s_vm);s_vm_open=false;}
    ek_scene3d_destroy(s_scene3d);s_scene3d=nullptr;
    s_save_queued=false;s_save_queued_size=0;
    ek_storage_models_free(&s_assets);
    free(s_payload);s_payload=nullptr;
    memset(&s_assets,0,sizeof(s_assets));s_running_id[0]=0;
    xSemaphoreTake(s_guard,portMAX_DELAY);
    s_back_tiles={};
    free(s_back);s_back=nullptr;
    s_state.running=false;
    if(ek_render_diagnostics_enabled())ek_run_stop(&s_run_metrics,0,scene_clock(nullptr));
    s_pending_run_frame={};s_front_run_frame={};s_display_run_frame={};
    s_front_reference=nullptr;s_front_reference_rows=0;
    free(s_front);s_front=nullptr;
    s_dirty={0,0,0,0};
    xSemaphoreGive(s_guard);
    mark_stage(APP_IDLE);
    s_app_time_ms=0;s_last_wall_ms=0;
}
static void configure_diagnostics(){
    const bool enabled=ek_render_diagnostics_enabled();
    const uint32_t epoch=__atomic_load_n(&s_diagnostics_epoch,__ATOMIC_ACQUIRE);
    if(epoch!=s_applied_diagnostics_epoch){
        xSemaphoreTake(s_guard,portMAX_DELAY);
        EkRunIdentity identity=s_run_metrics.identity;
        s_run_metrics={};s_run_metrics.current=-1;s_run_metrics.identity=identity;
        s_run_metrics.modal=s_modal;s_run_metrics.last_wall_us=enabled?scene_clock(nullptr):0;
        s_pending_run_frame=s_front_run_frame=s_display_run_frame={};
        s_scene_profile={};s_copy_stats={};
        s_partial_epoch=s_partial_tag=0;s_applied_diagnostics_epoch=epoch;
        xSemaphoreGive(s_guard);
    }
    s_vm.host.measurement=enabled?measure_run:nullptr;
    s_vm.host.clock=enabled?scene_clock:nullptr;
    s_vm.host.execution_profile=enabled?profile_run:nullptr;
    s_vm.host.execution_detail=enabled?profile_detail:nullptr;
    s_vm.host.execution_draw=enabled?profile_draw:nullptr;
}
extern "C" void ek_apps_diagnostics_enable(bool enabled){
    if(ek_render_diagnostics_enabled()==enabled)return;
    ek_render_diagnostics_enable(enabled);
    __atomic_fetch_add(&s_diagnostics_epoch,1u,__ATOMIC_RELEASE);
}
extern "C" bool ek_apps_diagnostics_enabled(void){return ek_render_diagnostics_enabled();}
static void run_selected(const char *id) {
    uint8_t *bytes=nullptr;size_t wasm_size=0,asset_size=0;
    mark_stage(APP_LOAD);
    log_memory("before load");
    if (!ek_storage_load(id,&bytes,&wasm_size,&asset_size)) {
        state_text(ek_storage_error());
        ek_storage_end();
        xSemaphoreTake(s_guard,portMAX_DELAY);
        s_state.mounted=false;s_state.catalog_ready=false;s_state.count=0;s_state.id[0]=0;
        page_metadata();
        xSemaphoreGive(s_guard);
        mark_stage(APP_IDLE);return;
    }
    mark_stage(APP_FRAMES);
    const size_t frame_bytes=EK_APPS_PIXELS*sizeof(uint16_t);
    uint16_t *back=(uint16_t *)heap_caps_malloc(frame_bytes,MALLOC_CAP_SPIRAM|MALLOC_CAP_8BIT);
    uint16_t *front=(uint16_t *)heap_caps_malloc(frame_bytes,MALLOC_CAP_SPIRAM|MALLOC_CAP_8BIT);
    if (!back || !front) {
        free(back);free(front);free(bytes);
        state_text("Display memory unavailable");mark_stage(APP_IDLE);return;
    }
    memset(back,0,frame_bytes);memset(front,0,frame_bytes);
    xSemaphoreTake(s_guard,portMAX_DELAY);
    s_back=back;
    s_back_tiles={};s_back_tiles.enabled=true;
    s_front=front;s_front_reference=nullptr;s_front_reference_rows=0;s_dirty={0,0,EK_APPS_WIDTH,EK_APPS_HEIGHT};s_copy_stats={};++s_state.frame;
    xSemaphoreGive(s_guard);
    s_payload=bytes;
    if (!ek_assets_parse(bytes+wasm_size,asset_size,&s_assets)) {
        stop_vm();state_text("App assets invalid");return;
    }
    if(!ek_storage_models_load(id,&s_assets,asset_size)){
        char error[80];snprintf(error,sizeof(error),"%s",ek_storage_error());stop_vm();state_text(error);return;
    }
    snprintf(s_running_id,sizeof(s_running_id),"%s",id);
    EkRunIdentity identity={};snprintf(identity.app_id,sizeof(identity.app_id),"%s",id);
    identity.wasm_bytes=(uint32_t)wasm_size;identity.asset_bytes=(uint32_t)asset_size;identity.asset_count=s_assets.count;
    identity.resource_total_bytes=(uint32_t)asset_size;
    for(unsigned i=0;i<s_assets.count;i++)if(s_assets.items[i].owned)
        identity.resource_total_bytes+=s_assets.items[i].length;
    EkPackageInfo info;
    if(ek_storage_loaded_info(&info)){
        snprintf(identity.version,sizeof(identity.version),"%u.%u.%u",info.major,info.minor,info.patch);
        uint8_t program_digest[32];
        if(ek_storage_loaded_program_sha256(program_digest))
            for(unsigned j=0;j<32;j++)snprintf(identity.program_sha256+j*2,3,"%02x",program_digest[j]);
    }
    xSemaphoreTake(s_guard,portMAX_DELAY);
    ek_run_identity(&s_run_metrics,&identity,scene_clock(nullptr));
    xSemaphoreGive(s_guard);
    mark_stage(APP_INPUT);
    input_snapshot(s_input,0);
    mark_stage(APP_SAVE_LOAD);
    log_memory("before save load");
    size_t saved_size=0;
    if (ek_storage_save_load(id,s_input->save_data,sizeof(s_input->save_data),
                             &saved_size)) {
        s_input->save_size=(uint32_t)saved_size;
        s_input->save_status=EVILKEY_APP_SAVE_LOADED;
    }
    EkVmHost host={nullptr,rect,present,blit,text_draw,save_app,&s_assets};
    host.blit_region=blit_region;
    host.clock=nullptr; // Optional telemetry is attached only by the Apps owner.
    if(ek_render_diagnostics_enabled()){host.measurement=measure_run;host.clock=scene_clock;host.execution_profile=profile_run;host.execution_detail=profile_detail;host.execution_draw=profile_draw;}
    host.abi_version=ek_storage_loaded_abi();
    if(host.abi_version==5) {
        xSemaphoreTake(s_guard,portMAX_DELAY);s_scene_profile={};xSemaphoreGive(s_guard);
        s_scene3d=ek_scene3d_create();
        if(!s_scene3d){stop_vm();state_text("3D memory unavailable");return;}
        ek_scene3d_set_assets(s_scene3d,&s_assets);
        xSemaphoreTake(s_guard,portMAX_DELAY);
        s_run_metrics.identity.native_context_bytes=(uint32_t)ek_scene3d_allocation_bytes(s_scene3d);
        xSemaphoreGive(s_guard);
        host.scene3d=render_scene;
    }
    mark_stage(APP_VM_OPEN);
    log_memory("before VM open");
    bool ok=ek_vm_open(&s_vm,bytes,wasm_size,host)!=0;
    if (!ok) {
        char error[80];snprintf(error,sizeof(error),"%s",ek_vm_error(&s_vm));
        stop_vm();state_text(error);return;
    }
    s_vm_open=true;
    mark_stage(APP_INIT);
    log_memory("before app_init");
    configure_diagnostics();
    s_step_started_us=diagnostic_clock(nullptr);
    if (!ek_vm_init(&s_vm,s_input)) {
        char error[80];snprintf(error,sizeof(error),"%s",ek_vm_error(&s_vm));
        stop_vm();state_text(error);return;
    }
    flush_save();
    s_app_time_ms=0;
    s_last_wall_ms=millis();
    xSemaphoreTake(s_guard,portMAX_DELAY);
    s_state.running=true;
    snprintf(s_state.status,sizeof(s_state.status),"Running %s",id);
    xSemaphoreGive(s_guard);
    mark_stage(APP_RUNNING);
    log_memory("app running");
}
static __attribute__((noinline)) void export_diagnostics(void) {
    xSemaphoreTake(s_guard,portMAX_DELAY);
    char *data=s_diagnostics_report;size_t size=s_diagnostics_report_size;
    xSemaphoreGive(s_guard);
    if(!data)return;
    char filename[32]={},error[80]={};
    bool ok=ek_storage_diagnostics_write((const uint8_t *)data,size,filename,sizeof(filename));
    if(!ok)snprintf(error,sizeof(error),"%s",ek_storage_error());
    free(data);
    xSemaphoreTake(s_guard,portMAX_DELAY);
    s_diagnostics_report=nullptr;s_diagnostics_report_size=0;
    s_diagnostics_export.status=ok?EK_DIAGNOSTICS_EXPORT_SAVED:EK_DIAGNOSTICS_EXPORT_ERROR;
    snprintf(s_diagnostics_export.filename,sizeof(s_diagnostics_export.filename),"%s",filename);
    snprintf(s_diagnostics_export.error,sizeof(s_diagnostics_export.error),"%s",error);
    xSemaphoreGive(s_guard);
}
static void task(void *) {
    for (;;) {
        const uint32_t iteration_started=millis();
        xSemaphoreTake(s_guard,portMAX_DELAY);
        bool visible=s_visible;
        bool modal=s_modal;
        EkAppsCommand command=s_command;s_command=EK_APPS_NONE;
        bool mounted=s_state.mounted;
        bool running=s_state.running;
        unsigned selected=s_state.selected;
        char id[32];snprintf(id,sizeof(id),"%s",s_state.id);
        xSemaphoreGive(s_guard);
        if (!visible) {
            if (running || s_vm_open) stop_vm();
            running=false;command=EK_APPS_NONE;
        }
        if (!pf_apps_storage_role_allowed()) {
            export_diagnostics();
            if (running || s_vm_open) stop_vm();
            if (mounted) {
                ek_storage_end();
                xSemaphoreTake(s_guard,portMAX_DELAY);
                s_state.mounted=false;s_state.count=0;s_state.id[0]=0;
                s_state.catalog_ready=false;s_state.scanning=false;
                page_metadata();
                xSemaphoreGive(s_guard);
            }
            vTaskDelay(pdMS_TO_TICKS(50));continue;
        }
        if (!mounted) {
            uint32_t started=ek_render_diagnostics_enabled()?millis():0;
            if (!ek_storage_begin()) {state_text(ek_storage_error());export_diagnostics();vTaskDelay(pdMS_TO_TICKS(1000));continue;}
            xSemaphoreTake(s_guard,portMAX_DELAY);
            s_state.mounted=true;s_state.mount_ms=ek_render_diagnostics_enabled()?millis()-started:0;
            xSemaphoreGive(s_guard);
            scan_catalog();
            /* Do not run a command selected against a previous catalog. */
            command=EK_APPS_NONE;id[0]=0;
        }
        export_diagnostics();
        if (!running && (command==EK_APPS_REFRESH ||
            (!visible && (uint32_t)(millis()-s_last_scan_at)>=15000U))) {
            scan_catalog();command=EK_APPS_NONE;
        }
        if (visible && !running && s_icons_pending) load_page_icons();
        if (command==EK_APPS_STOP) {
            stop_vm();state_text("Tap an app to run");
        } else if (running) {
            uint32_t wall=millis();
            if (modal) {
                s_last_wall_ms=wall;
            } else {
                s_app_time_ms+=wall-s_last_wall_ms;
                s_last_wall_ms=wall;
            }
            input_snapshot(s_input,s_app_time_ms);
            if (!modal) {
                
                
                configure_diagnostics();
                s_step_started_us=diagnostic_clock(nullptr);
                bool step_ok=ek_vm_step(&s_vm,s_input);
                
                if (!step_ok) {
                    xSemaphoreTake(s_guard,portMAX_DELAY);
                    if(ek_render_diagnostics_enabled())ek_run_stop(&s_run_metrics,1,scene_clock(nullptr));xSemaphoreGive(s_guard);
                    char error[80];snprintf(error,sizeof(error),"%s",ek_vm_error(&s_vm));
                    stop_vm();state_text(error);
                } else flush_save();
                
            }
        } else if (command==EK_APPS_PREV || command==EK_APPS_NEXT) {
            xSemaphoreTake(s_guard,portMAX_DELAY);
            unsigned pages=(s_state.count+EK_APPS_PAGE_SIZE-1)/EK_APPS_PAGE_SIZE;
            unsigned page=s_state.page;
            if (command==EK_APPS_NEXT && page+1<pages) ++page;
            if (command==EK_APPS_PREV && page) --page;
            if (page!=s_state.page) {s_state.page=(uint8_t)page;page_metadata();}
            xSemaphoreGive(s_guard);
        } else if (command==EK_APPS_RUN && id[0]) {
            run_selected(id);
        } else if (command==EK_APPS_RUN) {
            state_text("Copy .ekapp to /evilkey/apps");
        }
        
        const uint32_t period=running?16U:80U;
        const uint32_t spent=millis()-iteration_started;
        vTaskDelay(spent<period?pdMS_TO_TICKS(period-spent):1);
    }
}
extern "C" int ek_apps_start(void) {
    if (s_started) return 1;
    s_guard=xSemaphoreCreateMutex();
    if (!s_guard) return 0;
    s_input=(EvilKeyAppInput *)heap_caps_malloc(sizeof(*s_input),
                                                MALLOC_CAP_SPIRAM|MALLOC_CAP_8BIT);
    s_catalog=(EkPackageInfo *)heap_caps_calloc(EK_APPS_CATALOG_MAX,sizeof(*s_catalog),MALLOC_CAP_SPIRAM|MALLOC_CAP_8BIT);
    s_icons=(uint8_t *)heap_caps_calloc(EK_APPS_PAGE_SIZE,EK_APPS_ICON_BYTES,MALLOC_CAP_SPIRAM|MALLOC_CAP_8BIT);
    s_icon_scratch=(uint8_t *)heap_caps_malloc(EK_APPS_ICON_BYTES,MALLOC_CAP_SPIRAM|MALLOC_CAP_8BIT);
    if (!s_input || !s_catalog || !s_icons || !s_icon_scratch) {
        free(s_input);free(s_catalog);free(s_icons);free(s_icon_scratch);
        vSemaphoreDelete(s_guard);s_guard=nullptr;return 0;
    }
    esp_reset_reason_t reason=esp_reset_reason();
    bool unexpected=reason==ESP_RST_PANIC || reason==ESP_RST_INT_WDT ||
                    reason==ESP_RST_TASK_WDT || reason==ESP_RST_WDT ||
                    reason==ESP_RST_BROWNOUT;
    if (unexpected && s_crash_mark.magic==kCrashMark &&
        s_crash_mark.stage>=APP_LOAD && s_crash_mark.stage<=APP_SAVE_FLUSH &&
        s_crash_mark.inverse==~s_crash_mark.stage) {
        s_previous_app_reset=true;
        snprintf(s_state.status,sizeof(s_state.status),"%s R%u S%u H%u",
                 stage_name(s_crash_mark.stage),(unsigned)reason,
                 (unsigned)s_crash_mark.stack_free,
                 (unsigned)s_crash_mark.heap_free);
    } else {
        snprintf(s_state.status,sizeof(s_state.status),"Scanning microSD...");
    }
    mark_stage(APP_IDLE);
    if (xTaskCreate(task,"ek_apps",16384,nullptr,1,nullptr)!=pdPASS) {
        free(s_input);s_input=nullptr;free(s_catalog);free(s_icons);free(s_icon_scratch);
        vSemaphoreDelete(s_guard);s_guard=nullptr;return 0;
    }
    xSemaphoreTake(s_guard,portMAX_DELAY);
    s_state.ready=true;
    xSemaphoreGive(s_guard);
    s_started=true;return 1;
}
extern "C" void ek_apps_set_visible(bool visible) {
    if (!s_guard) return;
    xSemaphoreTake(s_guard,portMAX_DELAY);s_visible=visible;xSemaphoreGive(s_guard);
}
extern "C" void ek_apps_set_modal(bool visible) {
    if (!s_guard) return;
    xSemaphoreTake(s_guard,portMAX_DELAY);s_modal=visible;
    if(ek_render_diagnostics_enabled())ek_run_modal(&s_run_metrics,visible,scene_clock(nullptr));xSemaphoreGive(s_guard);
}
extern "C" void ek_apps_request(EkAppsCommand command) {
    if (!s_guard) return;
    xSemaphoreTake(s_guard,portMAX_DELAY);s_command=command;xSemaphoreGive(s_guard);
}
extern "C" void ek_apps_select_page(unsigned page) {
    if (!s_guard) return;
    xSemaphoreTake(s_guard,portMAX_DELAY);
    unsigned pages=(s_state.count+EK_APPS_PAGE_SIZE-1)/EK_APPS_PAGE_SIZE;
    if (!s_state.running && s_state.catalog_ready && !s_state.scanning &&
        page<pages && page!=s_state.page) {
        s_state.page=(uint8_t)page;
        page_metadata();
    }
    xSemaphoreGive(s_guard);
}
extern "C" void ek_apps_launch(unsigned index) {
    if (!s_guard) return;
    xSemaphoreTake(s_guard,portMAX_DELAY);
    unsigned slot=index%EK_APPS_PAGE_SIZE;
    if (s_visible && !s_state.running && !s_state.scanning && s_state.catalog_ready &&
        index<s_state.count && index/EK_APPS_PAGE_SIZE==s_state.page &&
        (s_state.icon_valid&(1u<<slot))) {
        s_state.selected=(uint8_t)index;
        snprintf(s_state.id,sizeof(s_state.id),"%s",s_catalog[index].id);
        s_command=EK_APPS_RUN;
    }
    xSemaphoreGive(s_guard);
}
extern "C" int ek_apps_copy_icons(uint8_t *pixels,size_t capacity,uint32_t *generation) {
    if (!s_guard || !pixels || !generation || capacity<EK_APPS_PAGE_SIZE*EK_APPS_ICON_BYTES) return 0;
    xSemaphoreTake(s_guard,portMAX_DELAY);
    bool changed=s_state.catalog_generation!=*generation;
    if (changed) {
        memcpy(pixels,s_icons,EK_APPS_PAGE_SIZE*EK_APPS_ICON_BYTES);
        *generation=s_state.catalog_generation;
    }
    xSemaphoreGive(s_guard);return changed?1:0;
}
extern "C" void ek_apps_input(const EvilKeyAppTouch *touch,uint32_t count,
                                bool accel_valid,int32_t ax_mg,int32_t ay_mg,
                                int32_t az_mg) {
    if (!s_guard) return;
    if (count>2 || (count && !touch)) count=0;
    xSemaphoreTake(s_guard,portMAX_DELAY);
    s_touch_count=count;
    memset(s_touches,0,sizeof(s_touches));
    if (count) memcpy(s_touches,touch,count*sizeof(*touch));
    s_accel_valid=accel_valid;
    s_accel_x=ax_mg;s_accel_y=ay_mg;s_accel_z=az_mg;
    xSemaphoreGive(s_guard);
}
extern "C" void ek_apps_snapshot(EkAppsState *out) {
    if (!out) return;
    memset(out,0,sizeof(*out));
    if (!s_guard) return;
    xSemaphoreTake(s_guard,portMAX_DELAY);*out=s_state;xSemaphoreGive(s_guard);
}
extern "C" void ek_apps_scene_profile(EkSceneProfile *out) {
    if(!out)return;
    memset(out,0,sizeof(*out));if(!s_guard)return;
    xSemaphoreTake(s_guard,portMAX_DELAY);*out=s_scene_profile;xSemaphoreGive(s_guard);
}
extern "C" int ek_apps_diagnostics_export(char *data,size_t size) {
    if(!s_guard||!data||!size||size>EK_DIAGNOSTICS_REPORT_CAPACITY)return 0;
    xSemaphoreTake(s_guard,portMAX_DELAY);
    bool accepted=s_diagnostics_export.status==EK_DIAGNOSTICS_EXPORT_BUSY&&!s_diagnostics_report;
    if(accepted){
        s_diagnostics_report=data;s_diagnostics_report_size=size;
    }
    xSemaphoreGive(s_guard);return accepted;
}
extern "C" int ek_apps_diagnostics_export_request(void) {
    if(!s_guard)return 0;
    xSemaphoreTake(s_guard,portMAX_DELAY);
    bool accepted=ek_render_diagnostics_enabled()&&s_diagnostics_export.status!=EK_DIAGNOSTICS_EXPORT_BUSY;
    if(accepted){
        uint32_t request=s_diagnostics_export.request+1;if(!request)request=1;
        s_diagnostics_export={};s_diagnostics_export.request=request;
        s_diagnostics_export.status=EK_DIAGNOSTICS_EXPORT_BUSY;
    }
    xSemaphoreGive(s_guard);return accepted;
}
extern "C" void ek_apps_diagnostics_export_failed(const char *reason) {
    if(!s_guard)return;
    xSemaphoreTake(s_guard,portMAX_DELAY);
    if(!s_diagnostics_report){
        s_diagnostics_export.status=EK_DIAGNOSTICS_EXPORT_ERROR;
        s_diagnostics_export.filename[0]=0;
        snprintf(s_diagnostics_export.error,sizeof(s_diagnostics_export.error),"%s",reason?reason:"Report failed");
    }
    xSemaphoreGive(s_guard);
}
extern "C" void ek_apps_diagnostics_export_snapshot(EkDiagnosticsExport *out) {
    if(!out)return;
    if(!s_guard){
        *out={};out->status=EK_DIAGNOSTICS_EXPORT_ERROR;
        snprintf(out->error,sizeof(out->error),"Report worker unavailable");return;
    }
    xSemaphoreTake(s_guard,portMAX_DELAY);*out=s_diagnostics_export;xSemaphoreGive(s_guard);
}
extern "C" void ek_apps_run_metrics(EkRunMetrics *out){
    if(!out)return;memset(out,0,sizeof(*out));out->current=-1;
    if(!s_guard||!ek_render_diagnostics_enabled())return;
    xSemaphoreTake(s_guard,portMAX_DELAY);*out=s_run_metrics;
    ek_run_advance(out,scene_clock(nullptr));xSemaphoreGive(s_guard);
}
extern "C" void ek_apps_display_complete(uint32_t generation,bool success){
    ek_apps_display_complete_profile(generation,success,0,0,0);
}
extern "C" void ek_apps_display_complete_profile(uint32_t generation,bool success,
    uint32_t display_us,uint32_t copy_us,unsigned method){
    ek_apps_display_complete_detail(generation,success,display_us,copy_us,method,nullptr,0);
}
static void display_complete_detail(uint32_t generation,bool success,
    uint32_t display_us,uint32_t copy_us,unsigned method,const uint32_t detail[4],unsigned cadence,
    const uint32_t *lvgl_us,bool profile_available){
    if(!s_guard||!ek_render_diagnostics_enabled())return;
    xSemaphoreTake(s_guard,portMAX_DELAY);
    EkRunRecord *record=ek_run_current(&s_run_metrics);
    uint32_t before=record?record->completed:0;
    if(generation==s_display_generation)
        ek_run_display_profile(&s_run_metrics,&s_display_run_frame,success,scene_clock(nullptr),
                               display_us,copy_us,method);
    if(record && record==ek_run_current(&s_run_metrics) && record->completed!=before){
        ek_run_display_detail(record,detail,cadence);
        if(lvgl_us){
            ek_run_draw_sum(record,4,*lvgl_us);
            if(record->draw_lvgl_count==UINT32_MAX)record->draw_count_flags|=0x40000000u;
            else ++record->draw_lvgl_count;
        }
        else if(!profile_available)record->draw_count_flags|=0x80000000u;
    }
    xSemaphoreGive(s_guard);
}
extern "C" void ek_apps_display_complete_detail(uint32_t generation,bool success,
    uint32_t display_us,uint32_t copy_us,unsigned method,const uint32_t detail[4],unsigned cadence){
    display_complete_detail(generation,success,display_us,copy_us,method,detail,cadence,nullptr,false);
}
extern "C" void ek_apps_display_complete_raster(uint32_t generation,bool success,
    uint32_t display_us,uint32_t copy_us,unsigned method,const uint32_t detail[4],unsigned cadence,uint32_t lvgl_us,bool sampled){
    display_complete_detail(generation,success,display_us,copy_us,method,detail,cadence,sampled?&lvgl_us:nullptr,true);
}
typedef uint32_t __attribute__((__may_alias__)) CopyWord;
static void copy_panel_row(uint16_t *destination,const uint16_t *source,unsigned width){
    /* Pair stores only when both pointers can use aligned words. Otherwise
     * retain uint16 alignment; never read/write beyond the dirty row. */
    if((((uintptr_t)destination^(uintptr_t)source)&3u)==0){
        if(width&&((uintptr_t)source&3u)){
            uint16_t c=*source++;*destination++=(uint16_t)((c<<8)|(c>>8));--width;
        }
        while(width>=2){
            uint32_t c=*(const CopyWord*)source;
            *(CopyWord*)destination=((c&0x00ff00ffu)<<8)|((c>>8)&0x00ff00ffu);
            source+=2;destination+=2;width-=2;
        }
    }
    while(width--){uint16_t c=*source++;*destination++=(uint16_t)((c<<8)|(c>>8));}
}

static __attribute__((noinline)) void copy_panel_blocks(uint16_t *destination,const uint16_t *source,size_t pixels){
    /* Bulk PSRAM accesses; byte swapping runs solely in bounded stack SRAM.
     * memcpy accepts independent uint16 alignment without aliasing casts. */
    uint32_t block[128];
    while(pixels){
        size_t count=pixels>256?256:pixels;
        memcpy(block,source,count*sizeof(uint16_t));
        for(size_t i=0;i<count/2;i++){
            uint32_t c=block[i];block[i]=((c&0x00ff00ffu)<<8)|((c>>8)&0x00ff00ffu);
        }
        if(count&1){
            unsigned char *p=(unsigned char *)block+(count-1)*2;
            unsigned char c=p[0];p[0]=p[1];p[1]=c;
        }
        memcpy(destination,block,count*sizeof(uint16_t));
        destination+=count;source+=count;pixels-=count;
    }
}

static void materialize_front_locked(){
    if(!s_front_reference)return;
    const size_t prefix=(size_t)s_front_reference_rows*EK_APPS_WIDTH;
    if(prefix)copy_panel_blocks(s_front,s_front_reference,prefix);
    if(prefix<EK_APPS_PIXELS)memcpy(s_front+prefix,s_front_reference+prefix,
        (EK_APPS_PIXELS-prefix)*sizeof(uint16_t));
    s_front_reference=nullptr;s_front_reference_rows=0;
    rebase_back_locked(s_front,0);
}
static int copy_frame(uint16_t *pixels,size_t count,uint32_t *generation,EkAppsDirty *dirty,unsigned panel_rows,bool force){
    if (!s_guard || !pixels || count<EK_APPS_PIXELS || !generation || !dirty || panel_rows>EK_APPS_HEIGHT) return 0;
    
    xSemaphoreTake(s_guard,portMAX_DELAY);
    bool changed=s_front && (force || (s_state.frame!=*generation && s_dirty.width));
    if (changed) {
        uint64_t start=diagnostic_clock(nullptr);
        materialize_front_locked();
        *dirty=force?EkAppsDirty{0,0,EK_APPS_WIDTH,EK_APPS_HEIGHT}:s_dirty;
        const bool full=dirty->x==0&&dirty->y==0&&
            dirty->width==EK_APPS_WIDTH&&dirty->height==EK_APPS_HEIGHT;
        if(full){
            const size_t prefix=(size_t)panel_rows*EK_APPS_WIDTH;
            if(prefix)copy_panel_blocks(pixels,s_front,prefix);
            if(prefix<EK_APPS_PIXELS)memcpy(pixels+prefix,s_front+prefix,
                (EK_APPS_PIXELS-prefix)*sizeof(*pixels));
        }else for (uint32_t row=dirty->y;row<dirty->y+dirty->height;++row){
            uint16_t *target=pixels+row*EK_APPS_WIDTH+dirty->x;
            const uint16_t *source=s_front+row*EK_APPS_WIDTH+dirty->x;
            if(row<panel_rows)copy_panel_row(target,source,dirty->width);
            else memcpy(target,source,dirty->width*sizeof(uint16_t));
        }
        /* Consume generation only after the guarded snapshot is complete. */
        if(ek_render_diagnostics_enabled()){
        uint64_t elapsed=scene_clock(nullptr)-start;
        s_copy_stats.last_us=(uint32_t)(elapsed>UINT32_MAX?UINT32_MAX:elapsed);
        if(s_copy_stats.last_us>s_copy_stats.peak_us)s_copy_stats.peak_us=s_copy_stats.last_us;
        ++s_copy_stats.copies;s_copy_stats.last_bytes=(uint32_t)dirty->width*dirty->height*2;
        s_copy_stats.last_width=dirty->width;s_copy_stats.last_height=dirty->height;
        s_copy_stats.panel_order=panel_rows==EK_APPS_HEIGHT?1u:panel_rows?2u:0u;
        s_copy_stats.method=panel_rows&&panel_rows<EK_APPS_HEIGHT?EK_APPS_COPY_MIXED:
            panel_rows?(full?EK_APPS_COPY_BLOCK_SWAP:EK_APPS_COPY_FUSED):EK_APPS_COPY_NATIVE;
        }
        s_dirty={0,0,0,0};
        /* A format refresh may re-copy a frame already ACKed. Do not
         * replenish its consumed run ticket or count it as a new scene. */
        if(*generation!=s_state.frame){
            s_display_generation=s_state.frame;s_display_run_frame=s_front_run_frame;
        }
        *generation=s_state.frame;
    }
    xSemaphoreGive(s_guard);
    
    return changed?1:0;
}
extern "C" int ek_apps_exchange_frame_transport(uint16_t **pixels,size_t count,uint32_t *generation,
    EkAppsDirty *dirty,unsigned panel_rows,bool force){
    if(!s_guard||!pixels||!*pixels||count<EK_APPS_PIXELS||!generation||!dirty||panel_rows>EK_APPS_HEIGHT)return 0;
    xSemaphoreTake(s_guard,portMAX_DELAY);
    if(*pixels==s_front||*pixels==s_back){xSemaphoreGive(s_guard);return 0;}
    const bool changed=s_front&&(force||(s_state.frame!=*generation&&s_dirty.width));
    const bool full=force||(s_dirty.x==0&&s_dirty.y==0&&s_dirty.width==EK_APPS_WIDTH&&s_dirty.height==EK_APPS_HEIGHT);
    if(changed&&full&&!s_front_reference){
        const uint64_t start=diagnostic_clock(nullptr);
        uint16_t *previous=*pixels;*pixels=s_front;s_front=previous;
        const size_t prefix=(size_t)panel_rows*EK_APPS_WIDTH;
        if(prefix)copy_panel_blocks(*pixels,*pixels,prefix);
        s_front_reference=*pixels;s_front_reference_rows=panel_rows;
        rebase_back_locked(*pixels,panel_rows);
        *dirty={0,0,EK_APPS_WIDTH,EK_APPS_HEIGHT};s_dirty={};
        if(ek_render_diagnostics_enabled()){
        uint64_t elapsed=scene_clock(nullptr)-start;
        s_copy_stats.last_us=ek_run_sat(elapsed);
        if(s_copy_stats.last_us>s_copy_stats.peak_us)s_copy_stats.peak_us=s_copy_stats.last_us;
        ++s_copy_stats.copies;s_copy_stats.last_bytes=(uint32_t)prefix*2u;
        s_copy_stats.last_width=EK_APPS_WIDTH;s_copy_stats.last_height=EK_APPS_HEIGHT;
        s_copy_stats.panel_order=panel_rows==EK_APPS_HEIGHT?1u:panel_rows?2u:0u;
        s_copy_stats.method=panel_rows&&panel_rows<EK_APPS_HEIGHT?EK_APPS_COPY_EXCHANGE_MIXED:EK_APPS_COPY_EXCHANGE_FULL;
        }
        if(*generation!=s_state.frame){s_display_generation=s_state.frame;s_display_run_frame=s_front_run_frame;}
        *generation=s_state.frame;xSemaphoreGive(s_guard);return 1;
    }
    xSemaphoreGive(s_guard);
    return copy_frame(*pixels,count,generation,dirty,panel_rows,force);
}
extern "C" int ek_apps_copy_frame(uint16_t *pixels,size_t count,uint32_t *generation,EkAppsDirty *dirty){
    return copy_frame(pixels,count,generation,dirty,0,false);
}
extern "C" int ek_apps_copy_frame_panel(uint16_t *pixels,size_t count,uint32_t *generation,EkAppsDirty *dirty){
    return copy_frame(pixels,count,generation,dirty,EK_APPS_HEIGHT,false);
}
extern "C" int ek_apps_copy_frame_transport(uint16_t *pixels,size_t count,
    uint32_t *generation,EkAppsDirty *dirty,unsigned panel_rows,bool force){
    return copy_frame(pixels,count,generation,dirty,panel_rows,force);
}
extern "C" void ek_apps_copy_stats(EkAppsCopyStats *out){
    if(!out)return;
    if(!s_guard){*out={};return;}
    xSemaphoreTake(s_guard,portMAX_DELAY);*out=s_copy_stats;xSemaphoreGive(s_guard);
}

