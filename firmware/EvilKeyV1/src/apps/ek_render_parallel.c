#include "ek_render_parallel.h"

/* Publish startup and descriptor ownership with explicit release/acquire
 * operations. Completion semaphores never consume caller task notifications. */
static uint32_t started, ready, enabled = 1;
static EkRenderFrameStats frame_stats;
_Static_assert(sizeof(EkRenderFrameStats)==40,"bounded graphics admission snapshot");
#define LOAD(p) __atomic_load_n((p), __ATOMIC_ACQUIRE)
#define STORE(p,v) __atomic_store_n((p), (v), __ATOMIC_RELEASE)

#if defined(ESP_PLATFORM)
#include "esp_attr.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#define EK_WORKER_STACK_BYTES 4096u
typedef struct {
    StackType_t stack[EK_WORKER_STACK_BYTES / sizeof(StackType_t)];
    StaticTask_t tcb;
    StaticSemaphore_t lock_storage, wake_storage, done_storage;
    SemaphoreHandle_t lock, wake, done;
    TaskHandle_t task;
    EkRenderWork work;
    void *arg;
    uint32_t pending, jobs, stack_free;
} Worker;
static DRAM_ATTR Worker workers[2];
static DRAM_ATTR StaticSemaphore_t frame_mutex_storage;
static SemaphoreHandle_t frame_mutex;
_Static_assert(sizeof(workers) + sizeof(started) + sizeof(ready) + sizeof(enabled)
               + sizeof(frame_mutex_storage) + sizeof(frame_mutex) + sizeof(frame_stats)
               <= 10u * 1024u, "render executor internal static budget");
static uint64_t frame_now(void){return (uint64_t)esp_timer_get_time();}
static bool frame_take(bool wait){return xSemaphoreTake(frame_mutex,wait?portMAX_DELAY:0)==pdTRUE;}
static void frame_give(void){xSemaphoreGive(frame_mutex);}

static void worker_loop(void *arg) {
    Worker *w = (Worker *)arg;
    for (;;) {
        if (xSemaphoreTake(w->wake, portMAX_DELAY) != pdTRUE) continue;
        if (!LOAD(&w->pending)) continue;

        
        w->work(w->arg);
        
        __atomic_fetch_add(&w->jobs, 1u, __ATOMIC_RELAXED);
        /* ESP-IDF reports this high-water mark in bytes, unlike vanilla RTOS. */
        STORE(&w->stack_free, (uint32_t)uxTaskGetStackHighWaterMark(NULL));
        STORE(&w->pending, 0);
        
        xSemaphoreGive(w->done);
    }
}
void ek_render_workers_start(void) {
    uint32_t expected = 0;
    if (!__atomic_compare_exchange_n(&started, &expected, 1, false,
                                     __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) return;
    frame_mutex=xSemaphoreCreateMutexStatic(&frame_mutex_storage);
    if(!frame_mutex)return;
    for (unsigned i = 0; i < 2; ++i) {
        Worker *w = &workers[i];
        w->lock = xSemaphoreCreateMutexStatic(&w->lock_storage);
        w->wake = xSemaphoreCreateBinaryStatic(&w->wake_storage);
        w->done = xSemaphoreCreateBinaryStatic(&w->done_storage);
        if (!w->lock || !w->wake || !w->done) return;
    }
    for (unsigned i = 0; i < 2; ++i) {
        Worker *w = &workers[i];
        w->task = xTaskCreateStaticPinnedToCore(worker_loop,
            i ? "render_core1" : "render_core0", EK_WORKER_STACK_BYTES,
            w, 1, w->stack, &w->tcb, (BaseType_t)i);
        if (!w->task) {
            for (unsigned j = 0; j < i; ++j) vTaskDelete(workers[j].task);
            return;
        }
        STORE(&w->stack_free, (uint32_t)uxTaskGetStackHighWaterMark(w->task));
    }
    STORE(&frame_stats.ready,1);
    STORE(&ready, 1);
}
unsigned ek_render_core_id(void) { return (unsigned)xPortGetCoreID(); }
static bool dispatch(EkRenderWork work, void *first, void *second) {
    if (xTaskGetSchedulerState() != taskSCHEDULER_RUNNING) return false;
    Worker *w = &workers[ek_render_core_id() ^ 1u];
    /* Contention means this invocation uses the serial fallback. In particular,
     * two callers on opposite cores never wait for each other's helper lock. */
    if (xSemaphoreTake(w->lock, 0) != pdTRUE) return false;
    w->work = work; w->arg = second;
    STORE(&w->pending, 1);
    if (xSemaphoreGive(w->wake) != pdTRUE) {
        STORE(&w->pending, 0);
        xSemaphoreGive(w->lock);
        return false;
    }
    work(first);
    /* No timeout after dispatch: caller descriptors cannot be released until
     * helper completion. Both helpers remain persistent throughout firmware. */
    while (xSemaphoreTake(w->done, portMAX_DELAY) != pdTRUE) {}
    (void)LOAD(&w->pending);
    xSemaphoreGive(w->lock);
    return true;
}

#elif defined(EK_RENDER_HOST_THREADS) && defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
typedef struct {
    CRITICAL_SECTION lock;
    HANDLE wake, done, thread;
    EkRenderWork work;
    void *arg;
    uint32_t pending, jobs, stack_free, stopping;
    unsigned core;
} Worker;
static Worker workers[2];
static CRITICAL_SECTION frame_mutex;
static LARGE_INTEGER frame_frequency;
static uint64_t frame_now(void){LARGE_INTEGER t;QueryPerformanceCounter(&t);return (uint64_t)t.QuadPart*1000000u/(uint64_t)frame_frequency.QuadPart;}
static bool frame_take(bool wait){if(wait){EnterCriticalSection(&frame_mutex);return true;}return TryEnterCriticalSection(&frame_mutex)!=0;}
static void frame_give(void){LeaveCriticalSection(&frame_mutex);}
static uint32_t next_core;
static __thread int local_core = -1;
unsigned ek_render_core_id(void) {
    if (local_core < 0)
        local_core = (int)(__atomic_fetch_add(&next_core, 1u, __ATOMIC_RELAXED) & 1u);
    return (unsigned)local_core;
}
static DWORD WINAPI worker_loop(LPVOID arg) {
    Worker *w = (Worker *)arg;local_core = (int)w->core;
    for (;;) {
        if (WaitForSingleObject(w->wake, INFINITE) != WAIT_OBJECT_0) return 1;
        if (LOAD(&w->stopping)) return 0;
        if (!LOAD(&w->pending)) continue;

        
        w->work(w->arg);
        
        __atomic_fetch_add(&w->jobs, 1u, __ATOMIC_RELAXED);
        STORE(&w->pending, 0);
        
        ReleaseSemaphore(w->done, 1, NULL);
    }
}
void ek_render_workers_start(void) {
    uint32_t expected = 0;
    if (!__atomic_compare_exchange_n(&started, &expected, 1, false,
                                     __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) return;
    InitializeCriticalSection(&frame_mutex);QueryPerformanceFrequency(&frame_frequency);
    unsigned initialized = 0;
    for (unsigned i = 0; i < 2; ++i) {
        Worker *w = &workers[i];w->core = i;
        InitializeCriticalSection(&w->lock);++initialized;
        w->wake = CreateSemaphore(NULL, 0, 1, NULL);
        w->done = CreateSemaphore(NULL, 0, 1, NULL);
        if (!w->wake || !w->done) goto fail;
        w->thread = CreateThread(NULL, 0, worker_loop, w, 0, NULL);
        if (!w->thread) goto fail;
    }
    STORE(&frame_stats.ready,1);STORE(&ready, 1);return;
fail:
    DeleteCriticalSection(&frame_mutex);
    for (unsigned i = 0; i < initialized; ++i) {
        Worker *w = &workers[i];
        if (w->thread) {
            STORE(&w->stopping, 1);ReleaseSemaphore(w->wake, 1, NULL);
            WaitForSingleObject(w->thread, INFINITE);CloseHandle(w->thread);
        }
        if (w->wake) CloseHandle(w->wake);
        if (w->done) CloseHandle(w->done);
        DeleteCriticalSection(&w->lock);
    }
}
static bool dispatch(EkRenderWork work, void *first, void *second) {
    Worker *w = &workers[ek_render_core_id() ^ 1u];
    if (!TryEnterCriticalSection(&w->lock)) return false;
    w->work = work;w->arg = second;STORE(&w->pending, 1);
    if (!ReleaseSemaphore(w->wake, 1, NULL)) {
        STORE(&w->pending, 0);LeaveCriticalSection(&w->lock);return false;
    }
    work(first);
    while (WaitForSingleObject(w->done, INFINITE) != WAIT_OBJECT_0) {}
    (void)LOAD(&w->pending);
    LeaveCriticalSection(&w->lock);return true;
}

#elif defined(EK_RENDER_HOST_THREADS)
#error EK_RENDER_HOST_THREADS currently requires the Windows OS thread backend
#else
void ek_render_workers_start(void) { STORE(&started, 1); }
unsigned ek_render_core_id(void) { return 0; }
static uint64_t frame_now(void){return 0;}
static bool frame_take(bool wait){(void)wait;return false;}
static void frame_give(void){}
#endif

bool ek_render_workers_ready(void) { return LOAD(&ready) != 0; }
void ek_render_parallel_enable(bool value) { STORE(&enabled, value ? 1u : 0u); }
bool ek_render_parallel(EkRenderWork work, void *first, void *second) {
    if (!work) return false;
#if defined(ESP_PLATFORM) || (defined(EK_RENDER_HOST_THREADS) && defined(_WIN32))
    if (LOAD(&ready) && LOAD(&enabled) && dispatch(work, first, second)) return true;
#endif
    work(first);work(second);return false;
}
void ek_render_worker_stats(EkRenderWorkerStats *out) {
    if (!out) return;
    out->ready = LOAD(&ready);out->enabled = LOAD(&enabled);
    for (unsigned i = 0; i < 2; ++i) {
#if defined(ESP_PLATFORM) || (defined(EK_RENDER_HOST_THREADS) && defined(_WIN32))
        out->jobs[i] = LOAD(&workers[i].jobs);
        out->stack_free[i] = LOAD(&workers[i].stack_free);
#else
        out->jobs[i] = 0;out->stack_free[i] = 0;
#endif
    }
}
bool ek_render_frame_begin(unsigned client){
    if(client>1||!LOAD(&frame_stats.ready))return false;
    uint64_t begin=frame_now();
    if(!frame_take(false)){
        __atomic_fetch_add(&frame_stats.contentions[client],1u,__ATOMIC_RELAXED);
        while(!frame_take(true)){}
    }
    uint64_t elapsed=frame_now()-begin;
    uint32_t wait=(uint32_t)(elapsed>UINT32_MAX?UINT32_MAX:elapsed);
    __atomic_fetch_add(&frame_stats.acquisitions[client],1u,__ATOMIC_RELAXED);
    STORE(&frame_stats.wait_last_us[client],wait);
    if(wait>LOAD(&frame_stats.wait_peak_us[client]))STORE(&frame_stats.wait_peak_us[client],wait);
    STORE(&frame_stats.owner,client+1);
    return true;
}
void ek_render_frame_end(bool owned){
    if(!owned)return;
    STORE(&frame_stats.owner,0);frame_give();
}
void ek_render_frame_stats(EkRenderFrameStats *out){
    if(!out)return;
    out->ready=LOAD(&frame_stats.ready);out->owner=LOAD(&frame_stats.owner);
    for(unsigned i=0;i<2;i++){
        out->acquisitions[i]=LOAD(&frame_stats.acquisitions[i]);
        out->contentions[i]=LOAD(&frame_stats.contentions[i]);
        out->wait_last_us[i]=LOAD(&frame_stats.wait_last_us[i]);
        out->wait_peak_us[i]=LOAD(&frame_stats.wait_peak_us[i]);
    }
}
