/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Apps worker. Only this task touches microSD or executes Wasm. The FIDO
 * task and the display task never wait for app I/O or guest code.
 */
#include "ek_service.h"
#include "ek_storage.h"
#include "ek_vm.h"
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
static void refresh_list(unsigned requested) {
    EkPackageInfo info;
    unsigned total=0;
    while (total<16 && ek_storage_entry(total,&info)) ++total;
    unsigned selected=total?requested%total:0;
    bool found=total && ek_storage_entry(selected,&info);
    xSemaphoreTake(s_guard,portMAX_DELAY);
    s_state.count=(uint8_t)total;s_state.selected=(uint8_t)selected;
    snprintf(s_state.id,sizeof(s_state.id),"%s",found?info.id:"");
    xSemaphoreGive(s_guard);
}
static void stop_vm(void) {
    if (s_vm_open) {ek_vm_close(&s_vm);s_vm_open=false;}
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
        state_text(ek_storage_error());mark_stage(APP_IDLE);return;
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
    s_front=front;s_dirty={0,0,EK_APPS_WIDTH,EK_APPS_HEIGHT};++s_state.frame;
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
            if (mounted) {
                ek_storage_end();
                xSemaphoreTake(s_guard,portMAX_DELAY);
                s_state.mounted=false;s_state.count=0;s_state.id[0]=0;
                xSemaphoreGive(s_guard);
            }
            vTaskDelay(pdMS_TO_TICKS(50));continue;
        }
        if (!mounted) {
            if (!ek_storage_begin()) {state_text(ek_storage_error());vTaskDelay(pdMS_TO_TICKS(500));continue;}
            xSemaphoreTake(s_guard,portMAX_DELAY);s_state.mounted=true;xSemaphoreGive(s_guard);
            refresh_list(0);
            if (!s_previous_app_reset) state_text("microSD ready");
            s_previous_app_reset=false;
        }
        if (command==EK_APPS_STOP) {
            stop_vm();state_text("Stopped");
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
                if (!ek_vm_step(&s_vm,s_input)) {
                    char error[80];snprintf(error,sizeof(error),"%s",ek_vm_error(&s_vm));
                    stop_vm();state_text(error);
                } else flush_save();
            }
        } else if (command==EK_APPS_PREV || command==EK_APPS_NEXT) {
            unsigned count=s_state.count;
            if (count) refresh_list((selected+count+(command==EK_APPS_NEXT?1:count-1))%count);
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
    if (!s_input) {vSemaphoreDelete(s_guard);s_guard=nullptr;return 0;}
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
        snprintf(s_state.status,sizeof(s_state.status),"Open Apps to mount microSD");
    }
    mark_stage(APP_IDLE);
    if (xTaskCreate(task,"ek_apps",16384,nullptr,1,nullptr)!=pdPASS) {
        free(s_input);s_input=nullptr;
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
extern "C" int ek_apps_copy_frame(uint16_t *pixels,size_t count,
                                    uint32_t *generation,EkAppsDirty *dirty) {
    if (!s_guard || !pixels || count<EK_APPS_PIXELS || !generation || !dirty) return 0;
    xSemaphoreTake(s_guard,portMAX_DELAY);
    bool changed=s_front && s_state.frame!=*generation && s_dirty.width;
    if (changed) {
        *dirty=s_dirty;
        for (uint32_t row=dirty->y;row<dirty->y+dirty->height;++row)
            memcpy(pixels+row*EK_APPS_WIDTH+dirty->x,
                   s_front+row*EK_APPS_WIDTH+dirty->x,
                   dirty->width*sizeof(uint16_t));
        s_dirty={0,0,0,0};
        *generation=s_state.frame;
    }
    xSemaphoreGive(s_guard);
    return changed?1:0;
}
