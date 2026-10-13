/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "ek_pixel_accel.h"
#include "ek_render_parallel.h"
#include <string.h>
#if defined(ARDUINO_ARCH_ESP32)
#include "sdkconfig.h"
#endif
#if defined(CONFIG_IDF_TARGET_ESP32S3)
#include <esp_attr.h>
#include <esp_system.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#define EK_PIXEL_TARGET 1
RTC_NOINIT_ATTR static EkPixelMark s_mark;
#else
#define EK_PIXEL_TARGET 0
static EkPixelMark s_mark;
#endif
#if defined(EK_PIXEL_ACCEL_HOST_MODEL)
#include <stdlib.h>
#define EK_STRIP_PIE_MODEL 1
#endif
#include "ek_pixel_kernels.h"
static EkPixelStats s_stats={.core=-1};
static uint32_t s_init,s_testing,s_marker_busy;
#define PIXEL_MAGIC 0x454b5049u
#define PIXEL_VERSION 44u
bool ek_pixel_mark_fault(const EkPixelMark *m,bool unexpected){
    return unexpected&&m&&m->magic==PIXEL_MAGIC&&m->version==PIXEL_VERSION&&
           m->inverse==~m->stage&&m->stage>=1&&m->stage<=6;
}
static void marker(uint32_t stage){
    s_mark.magic=0;__atomic_thread_fence(__ATOMIC_RELEASE);
    s_mark.version=PIXEL_VERSION;s_mark.stage=stage;s_mark.inverse=~stage;
    __atomic_thread_fence(__ATOMIC_RELEASE);s_mark.magic=PIXEL_MAGIC;
}
static void initialize(void){
    uint32_t expected=0;
    if(__atomic_compare_exchange_n(&s_init,&expected,1,false,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE)){
#if EK_PIXEL_TARGET
        esp_reset_reason_t reason=esp_reset_reason();s_stats.reset_reason=(uint32_t)reason;
        bool unexpected=reason==ESP_RST_PANIC||reason==ESP_RST_INT_WDT||reason==ESP_RST_TASK_WDT||reason==ESP_RST_WDT||reason==ESP_RST_BROWNOUT;
        if(s_mark.magic==PIXEL_MAGIC&&s_mark.version==PIXEL_VERSION&&s_mark.inverse==~s_mark.stage)
            s_stats.previous_stage=s_mark.stage;
        if(ek_pixel_mark_fault(&s_mark,unexpected)){s_stats.blocked=1;s_stats.selftest=3;}
#endif
        marker(0);__atomic_store_n(&s_init,2,__ATOMIC_RELEASE);
    }
}
static bool pinned(void){
#if EK_PIXEL_TARGET
    BaseType_t core=xTaskGetCoreID(NULL);return core==0||core==1;
#elif defined(EK_PIXEL_ACCEL_HOST_UNPINNED)
    extern bool ek_pixel_test_pinned(void);return ek_pixel_test_pinned();
#elif defined(EK_PIXEL_ACCEL_HOST_UNPINNED)
    extern bool ek_pixel_test_pinned(void);return ek_pixel_test_pinned();
#elif defined(EK_PIXEL_ACCEL_HOST_MODEL)
    return true;
#else
    return false;
#endif
}
bool ek_pixel_accel_ready(void){
#if defined(EK_PIXEL_ACCEL_HOST_MODEL)
    if(getenv("EK_PIXEL_DISABLE"))return false;
#endif
    initialize();if(__atomic_load_n(&s_init,__ATOMIC_ACQUIRE)!=2||!pinned())return false;
    uint32_t expected=0;
    if(__atomic_compare_exchange_n(&s_testing,&expected,1,false,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE)){
        if(!s_stats.blocked){
#if EK_PIXEL_TARGET || defined(EK_PIXEL_ACCEL_HOST_MODEL)
            marker(1);marker(2);bool pass=ek_pixel_kernel_selftest()!=0;
            __atomic_store_n(&s_stats.selftest,pass?1u:2u,__ATOMIC_RELEASE);marker(pass?3:7);
#if EK_PIXEL_TARGET
            __atomic_store_n(&s_stats.core,(int32_t)xTaskGetCoreID(NULL),__ATOMIC_RELEASE);
#else
            __atomic_store_n(&s_stats.core,0,__ATOMIC_RELEASE);
#endif
#endif
        }
        __atomic_store_n(&s_testing,2,__ATOMIC_RELEASE);
    }
    return __atomic_load_n(&s_testing,__ATOMIC_ACQUIRE)==2&&__atomic_load_n(&s_stats.selftest,__ATOMIC_ACQUIRE)==1;
}
void ek_pixel_accel_stage(uint32_t stage){
    /* Only the initial shared session changes RTC. No per-frame writes. */
    if(__atomic_exchange_n(&s_marker_busy,1,__ATOMIC_ACQUIRE))return;
    if(s_mark.stage<6&&stage>s_mark.stage)marker(stage);
    __atomic_store_n(&s_marker_busy,0,__ATOMIC_RELEASE);
}
void ek_pixel_accel_stats(EkPixelStats *out){
    initialize();if(!out)return;
    if(__atomic_load_n(&s_init,__ATOMIC_ACQUIRE)!=2){memset(out,0,sizeof(*out));out->core=-1;return;}
    /* Diagnostic fields may increment concurrently, each read is indivisible. */
    out->selftest=__atomic_load_n(&s_stats.selftest,__ATOMIC_ACQUIRE);
#define SNAP(field) out->field=__atomic_load_n(&s_stats.field,__ATOMIC_RELAXED)
    SNAP(previous_stage);SNAP(reset_reason);SNAP(blocked);SNAP(fill);SNAP(copy);SNAP(key);SNAP(swap);SNAP(worker);SNAP(fallback);SNAP(core);
#undef SNAP
}
typedef struct {uint16_t *dst;const uint8_t *src;size_t ds,ss,w,h;uint16_t colour;bool key,done;} PixelJob;
static void rectangle(void *opaque){
    if(!opaque)return;PixelJob *j=(PixelJob *)opaque;
    if(!ek_pixel_accel_ready())return;
#if EK_PIXEL_TARGET || defined(EK_PIXEL_ACCEL_HOST_MODEL)
    ek_pixel_accel_stage(5);
    for(size_t y=0;y<j->h;y++){
        if(j->src)ek_pixel_copy(j->dst+y*j->ds,j->src+y*j->ss*2,j->w,j->key);
        else ek_pixel_fill(j->dst+y*j->ds,j->w,j->colour);
    }
    if(ek_render_diagnostics_enabled())__atomic_fetch_add(j->src?(j->key?&s_stats.key:&s_stats.copy):&s_stats.fill,1,__ATOMIC_RELAXED);
    j->done=true;ek_pixel_accel_stage(6);
#endif
}
bool ek_pixel_accel_rect(uint16_t *dst,size_t ds,const uint8_t *src,size_t ss,size_t w,size_t h,uint16_t c,bool key){
    if(!dst||!w||!h||ds<w||(src&&ss<w)||h>SIZE_MAX/w||w*h<512)return false;
    if(ds>SIZE_MAX/2||h-1>(SIZE_MAX/2-w)/ds)return false;
    if(src&&(ss>SIZE_MAX/2||h-1>(SIZE_MAX/2-w)/ss))return false;
    bool vector_span=false;
    for(size_t y=0;y<h&&y<8;y++){
        uintptr_t d=(uintptr_t)(dst+y*ds),s=src?(uintptr_t)(src+y*ss*2):d;
        size_t prefix=((16-(d&15))&15)/2;
        if(!((d^s)&15)&&w>=prefix+8){vector_span=true;break;}
    }
    if(!vector_span)return false;
    PixelJob j={dst,src,ds,ss,w,h,c,key,false};
    if(pinned())rectangle(&j);
#if EK_PIXEL_TARGET || defined(EK_PIXEL_ACCEL_HOST_UNPINNED)
    else if(ek_render_workers_ready()){
        bool dispatched=ek_render_parallel(rectangle,NULL,&j);
        if(dispatched&&j.done)if(ek_render_diagnostics_enabled())__atomic_fetch_add(&s_stats.worker,1,__ATOMIC_RELAXED);
    }
#endif
    if(!j.done)if(ek_render_diagnostics_enabled())__atomic_fetch_add(&s_stats.fallback,1,__ATOMIC_RELAXED);
    return j.done;
}
bool ek_pixel_accel_fill(uint16_t *dst,size_t count,uint16_t c){
    if(!dst||count<16||!ek_pixel_accel_ready())return false;
#if EK_PIXEL_TARGET || defined(EK_PIXEL_ACCEL_HOST_MODEL)
    ek_pixel_accel_stage(5);ek_pixel_fill(dst,count,c);
    if(ek_render_diagnostics_enabled())__atomic_fetch_add(&s_stats.fill,1,__ATOMIC_RELAXED);ek_pixel_accel_stage(6);return true;
#else
    return false;
#endif
}
void ek_pixel_accel_swap(uint16_t *dst,size_t count){
#if EK_PIXEL_TARGET || defined(EK_PIXEL_ACCEL_HOST_MODEL)
    ek_pixel_accel_stage(5);ek_strip_pie_swap(dst,count);
    if(ek_render_diagnostics_enabled())__atomic_fetch_add(&s_stats.swap,1,__ATOMIC_RELAXED);ek_pixel_accel_stage(6);
#else
    (void)dst;(void)count;
#endif
}
