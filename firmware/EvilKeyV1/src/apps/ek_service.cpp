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
static int32_t s_touch_x=-1,s_touch_y=-1;
static bool s_touch_down;
static uint16_t *s_back,*s_front;
static EkVm s_vm;
static bool s_vm_open;
static bool s_started;
static bool s_previous_app_reset;
static uint32_t s_app_time_ms,s_last_wall_ms;
static constexpr uint32_t kCrashMark=0x454B4150U;
enum AppStage : uint32_t { APP_IDLE=0, APP_LOAD=1, APP_FRAMES=2,
                           APP_VM_OPEN=3, APP_INIT=4, APP_RUNNING=5 };
struct AppCrashMark { uint32_t magic, stage, inverse; };
RTC_NOINIT_ATTR static AppCrashMark s_crash_mark;

static void mark_stage(AppStage stage) {
    s_crash_mark.magic=kCrashMark;
    s_crash_mark.stage=stage;
    s_crash_mark.inverse=~static_cast<uint32_t>(stage);
}
static const char *stage_name(uint32_t stage) {
    switch (stage) {
    case APP_LOAD:return "microSD";
    case APP_FRAMES:return "display memory";
    case APP_VM_OPEN:return "VM open";
    case APP_INIT:return "app_init";
    case APP_RUNNING:return "app runtime";
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
static void present(void *) {
    if (!s_back || !s_front) return;
    xSemaphoreTake(s_guard,portMAX_DELAY);
    memcpy(s_front,s_back,EK_APPS_PIXELS*sizeof(uint16_t));
    ++s_state.frame;
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
    free(s_back);s_back=nullptr;
    xSemaphoreTake(s_guard,portMAX_DELAY);
    s_state.running=false;
    free(s_front);s_front=nullptr;
    xSemaphoreGive(s_guard);
    mark_stage(APP_IDLE);
    s_app_time_ms=0;s_last_wall_ms=0;
}
static void run_selected(const char *id) {
    uint8_t *bytes=nullptr;size_t size=0;
    mark_stage(APP_LOAD);
    log_memory("before load");
    if (!ek_storage_load(id,&bytes,&size)) {
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
    s_front=front;++s_state.frame;
    xSemaphoreGive(s_guard);
    EkVmHost host={nullptr,rect,present};
    mark_stage(APP_VM_OPEN);
    log_memory("before VM open");
    bool ok=ek_vm_open(&s_vm,bytes,size,host)!=0;
    free(bytes);
    if (!ok) {
        char error[80];snprintf(error,sizeof(error),"%s",ek_vm_error(&s_vm));
        stop_vm();state_text(error);return;
    }
    s_vm_open=true;
    mark_stage(APP_INIT);
    log_memory("before app_init");
    if (!ek_vm_init(&s_vm)) {
        char error[80];snprintf(error,sizeof(error),"%s",ek_vm_error(&s_vm));
        stop_vm();state_text(error);return;
    }
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
        int32_t touch_x=s_touch_x,touch_y=s_touch_y;
        bool touch_down=s_touch_down;
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
            if (!modal && !ek_vm_step(&s_vm,s_app_time_ms,
                                       touch_x,touch_y,touch_down?1U:0U)) {
                char error[80];snprintf(error,sizeof(error),"%s",ek_vm_error(&s_vm));
                stop_vm();state_text(error);
            }
        } else if (command==EK_APPS_PREV || command==EK_APPS_NEXT) {
            unsigned count=s_state.count;
            if (count) refresh_list((selected+count+(command==EK_APPS_NEXT?1:count-1))%count);
        } else if (command==EK_APPS_RUN && id[0]) {
            run_selected(id);
        } else if (command==EK_APPS_RUN) {
            state_text("Copy .ekapp to /evilkey/apps");
        }
        vTaskDelay(pdMS_TO_TICKS(running?33:80));
    }
}
extern "C" int ek_apps_start(void) {
    if (s_started) return 1;
    s_guard=xSemaphoreCreateMutex();
    if (!s_guard) return 0;
    esp_reset_reason_t reason=esp_reset_reason();
    bool unexpected=reason==ESP_RST_PANIC || reason==ESP_RST_INT_WDT ||
                    reason==ESP_RST_TASK_WDT || reason==ESP_RST_WDT ||
                    reason==ESP_RST_BROWNOUT;
    if (unexpected && s_crash_mark.magic==kCrashMark &&
        s_crash_mark.stage>=APP_LOAD && s_crash_mark.stage<=APP_RUNNING &&
        s_crash_mark.inverse==~s_crash_mark.stage) {
        s_previous_app_reset=true;
        snprintf(s_state.status,sizeof(s_state.status),"Last reset: %s",
                 stage_name(s_crash_mark.stage));
    } else {
        snprintf(s_state.status,sizeof(s_state.status),"Open Apps to mount microSD");
    }
    mark_stage(APP_IDLE);
    if (xTaskCreate(task,"ek_apps",16384,nullptr,1,nullptr)!=pdPASS) {
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
extern "C" void ek_apps_touch(int32_t x,int32_t y,bool down) {
    if (!s_guard) return;
    if (!down || x<0 || x>=EK_APPS_WIDTH || y<0 || y>=EK_APPS_HEIGHT) {
        x=-1;y=-1;down=false;
    }
    xSemaphoreTake(s_guard,portMAX_DELAY);
    s_touch_x=x;s_touch_y=y;s_touch_down=down;
    xSemaphoreGive(s_guard);
}
extern "C" void ek_apps_snapshot(EkAppsState *out) {
    if (!out) return;
    memset(out,0,sizeof(*out));
    if (!s_guard) return;
    xSemaphoreTake(s_guard,portMAX_DELAY);*out=s_state;xSemaphoreGive(s_guard);
}
extern "C" int ek_apps_copy_frame(uint16_t *pixels,size_t count,uint32_t *generation) {
    if (!s_guard || !pixels || count<EK_APPS_PIXELS || !generation) return 0;
    xSemaphoreTake(s_guard,portMAX_DELAY);
    bool changed=s_front && s_state.frame!=*generation;
    if (changed) {memcpy(pixels,s_front,EK_APPS_PIXELS*sizeof(uint16_t));*generation=s_state.frame;}
    xSemaphoreGive(s_guard);
    return changed?1:0;
}
