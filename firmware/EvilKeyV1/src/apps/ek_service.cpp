/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Apps worker. Only this task touches microSD or executes Wasm. The FIDO
 * task never waits for app I/O or guest code. Display admission serializes
 * only native pre-copy compute, independently of storage and guest execution.
 */
#include "ek_service.h"
#include "ek_storage.h"
#include "ek_vm.h"
#include "ek_render_parallel.h"
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
static EkAppsDirty s_dirty;
static uint8_t *s_payload;
static EkAssets s_assets;
static char s_running_id[32];
static EkVm s_vm;
static EkScene3D *s_scene3d;
static EkAppsCopyStats s_copy_stats;
static_assert(sizeof(EkAppsCopyStats)==28,"bounded app copy snapshot");
static EkSceneProfile s_scene_profile;
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
static void rect(void *,int32_t x,int32_t y,int32_t w,int32_t h,uint16_t colour) {
    if (!s_back) return;
    for (int32_t row=y;row<y+h;++row) {
        uint16_t *line=s_back+row*EK_APPS_WIDTH+x;
        for (int32_t col=0;col<w;++col) line[col]=colour;
    }
}
static uint64_t scene_clock(void *) {return (uint64_t)esp_timer_get_time();}
static EkSceneStats render_scene(void *,const uint8_t *scene,unsigned x,unsigned y,unsigned w,unsigned h) {
    EkSceneStats stats=ek_scene3d_render(s_scene3d,scene,s_back,EK_APPS_WIDTH,x,y,w,h,scene_clock,nullptr);
    EkSceneProfile profile=ek_scene3d_profile(s_scene3d);
    xSemaphoreTake(s_guard,portMAX_DELAY);s_scene_profile=profile;xSemaphoreGive(s_guard);
    return stats;
}
static void present(void *,int32_t x,int32_t y,int32_t w,int32_t h) {
    if (!s_back || !s_front) return;
    
    xSemaphoreTake(s_guard,portMAX_DELAY);
    for (int32_t row=y;row<y+h;++row)
        memcpy(s_front+row*EK_APPS_WIDTH+x,s_back+row*EK_APPS_WIDTH+x,
               (size_t)w*sizeof(uint16_t));
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
    xSemaphoreGive(s_guard);
    
}
static void blit(void *,int32_t x,int32_t y,const EkAsset *asset) {
    if (!s_back || !asset) return;
    for (uint32_t row=0;row<asset->height;++row) {
        uint16_t *target=s_back+(y+row)*EK_APPS_WIDTH+x;
        const uint8_t *source=asset->rgb565+row*asset->width*2u;
        for (uint32_t col=0;col<asset->width;++col) {
            uint16_t pixel=(uint16_t)(source[col*2u] | ((uint16_t)source[col*2u+1]<<8));
            if (!(asset->flags&1u) || pixel) target[col]=pixel;
        }
    }
}
static void blit_region(void *,int32_t x,int32_t y,uint32_t sx,uint32_t sy,
                        uint32_t width,uint32_t height,const EkAsset *asset) {
    if (!s_back || !asset) return;
    for (uint32_t row=0;row<height;++row) {
        uint16_t *target=s_back+(y+(int32_t)row)*EK_APPS_WIDTH+x;
        const uint8_t *source=asset->rgb565+((sy+row)*asset->width+sx)*2u;
        for (uint32_t col=0;col<width;++col) {
            uint16_t pixel=(uint16_t)(source[col*2u] |
                                      ((uint16_t)source[col*2u+1]<<8));
            if (!(asset->flags&1u) || pixel) target[col]=pixel;
        }
    }
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
    uint32_t started=millis();
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
    s_state.scan_ms=millis()-started;
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
    uint32_t started=millis();
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
    s_state.icon_ms=millis()-started;s_icons_pending=false;
    xSemaphoreGive(s_guard);
    ESP_LOGI("ek_apps","page %u icons=%u ms",page,(unsigned)s_state.icon_ms);
}
static void stop_vm(void) {
    if (s_vm_open) {ek_vm_close(&s_vm);s_vm_open=false;}
    ek_scene3d_destroy(s_scene3d);s_scene3d=nullptr;
    s_save_queued=false;s_save_queued_size=0;
    free(s_payload);s_payload=nullptr;
    memset(&s_assets,0,sizeof(s_assets));s_running_id[0]=0;
    free(s_back);s_back=nullptr;
    xSemaphoreTake(s_guard,portMAX_DELAY);
    s_state.running=false;
    free(s_front);s_front=nullptr;
    s_dirty={0,0,0,0};
    xSemaphoreGive(s_guard);
    mark_stage(APP_IDLE);
    s_app_time_ms=0;s_last_wall_ms=0;
}
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
    s_back=back;
    xSemaphoreTake(s_guard,portMAX_DELAY);
    s_front=front;s_dirty={0,0,EK_APPS_WIDTH,EK_APPS_HEIGHT};s_copy_stats={};++s_state.frame;
    xSemaphoreGive(s_guard);
    s_payload=bytes;
    if (!ek_assets_parse(bytes+wasm_size,asset_size,&s_assets)) {
        stop_vm();state_text("App assets invalid");return;
    }
    snprintf(s_running_id,sizeof(s_running_id),"%s",id);
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
    host.abi_version=ek_storage_loaded_abi();
    if(host.abi_version==5) {
        xSemaphoreTake(s_guard,portMAX_DELAY);s_scene_profile={};xSemaphoreGive(s_guard);
        s_scene3d=ek_scene3d_create();
        if(!s_scene3d){stop_vm();state_text("3D memory unavailable");return;}
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
            uint32_t started=millis();
            if (!ek_storage_begin()) {state_text(ek_storage_error());export_diagnostics();vTaskDelay(pdMS_TO_TICKS(1000));continue;}
            xSemaphoreTake(s_guard,portMAX_DELAY);
            s_state.mounted=true;s_state.mount_ms=millis()-started;
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
                
                
                bool step_ok=ek_vm_step(&s_vm,s_input);
                
                if (!step_ok) {
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
        
        vTaskDelay(pdMS_TO_TICKS(running?16:80));
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
    xSemaphoreTake(s_guard,portMAX_DELAY);s_modal=visible;xSemaphoreGive(s_guard);
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
    bool accepted=s_diagnostics_export.status!=EK_DIAGNOSTICS_EXPORT_BUSY;
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

static int copy_frame(uint16_t *pixels,size_t count,uint32_t *generation,EkAppsDirty *dirty,bool panel){
    if (!s_guard || !pixels || count<EK_APPS_PIXELS || !generation || !dirty) return 0;
    
    xSemaphoreTake(s_guard,portMAX_DELAY);
    bool changed=s_front && s_state.frame!=*generation && s_dirty.width;
    if (changed) {
        uint64_t start=scene_clock(nullptr);
        *dirty=s_dirty;
        const bool full_panel=panel&&dirty->x==0&&dirty->y==0&&
            dirty->width==EK_APPS_WIDTH&&dirty->height==EK_APPS_HEIGHT;
        for (uint32_t row=dirty->y;row<dirty->y+dirty->height;++row){
            uint16_t *target=pixels+row*EK_APPS_WIDTH+dirty->x;
            const uint16_t *source=s_front+row*EK_APPS_WIDTH+dirty->x;
            if(panel&&!full_panel)copy_panel_row(target,source,dirty->width);
            else memcpy(target,source,dirty->width*sizeof(uint16_t));
        }
        /* Keep both passes under the same guard, before acknowledging the
         * generation. Only complete dirty frames use the measured legacy path. */
        if(full_panel)for(unsigned i=0;i<EK_APPS_PIXELS;i++){
            uint16_t c=pixels[i];pixels[i]=(uint16_t)((c<<8)|(c>>8));
        }
        uint64_t elapsed=scene_clock(nullptr)-start;
        s_copy_stats.last_us=(uint32_t)(elapsed>UINT32_MAX?UINT32_MAX:elapsed);
        if(s_copy_stats.last_us>s_copy_stats.peak_us)s_copy_stats.peak_us=s_copy_stats.last_us;
        ++s_copy_stats.copies;s_copy_stats.last_bytes=(uint32_t)dirty->width*dirty->height*2;
        s_copy_stats.last_width=dirty->width;s_copy_stats.last_height=dirty->height;
        s_copy_stats.panel_order=panel?1u:0u;
        s_copy_stats.method=full_panel?EK_APPS_COPY_ROW_SWAP:
            panel?EK_APPS_COPY_FUSED:EK_APPS_COPY_NATIVE;
        s_dirty={0,0,0,0};
        *generation=s_state.frame;
    }
    xSemaphoreGive(s_guard);
    
    return changed?1:0;
}
extern "C" int ek_apps_copy_frame(uint16_t *pixels,size_t count,uint32_t *generation,EkAppsDirty *dirty){
    return copy_frame(pixels,count,generation,dirty,false);
}
extern "C" int ek_apps_copy_frame_panel(uint16_t *pixels,size_t count,uint32_t *generation,EkAppsDirty *dirty){
    return copy_frame(pixels,count,generation,dirty,true);
}
extern "C" void ek_apps_copy_stats(EkAppsCopyStats *out){
    if(!out)return;
    if(!s_guard){*out={};return;}
    xSemaphoreTake(s_guard,portMAX_DELAY);*out=s_copy_stats;xSemaphoreGive(s_guard);
}
