#ifndef EK_RENDER_PARALLEL_H
#define EK_RENDER_PARALLEL_H
#include <stdbool.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef void (*EkRenderWork)(void *);
typedef struct {
    uint32_t ready, enabled, jobs[2], stack_free[2];
} EkRenderWorkerStats;
void ek_render_workers_start(void);
bool ek_render_workers_ready(void);
void ek_render_parallel_enable(bool enabled);
/* Descriptors remain caller-owned until both jobs have completed. Kernels must
 * not dispatch recursively. NULL work is a no-op returning false. */
bool ek_render_parallel(EkRenderWork work, void *first, void *second);
unsigned ek_render_core_id(void);
void ek_render_worker_stats(EkRenderWorkerStats *out);
enum { EK_RENDER_FRAME_NATIVE=0, EK_RENDER_FRAME_DISPLAY=1 };
typedef struct {
    uint32_t ready, owner, acquisitions[2], contentions[2], wait_last_us[2], wait_peak_us[2];
} EkRenderFrameStats;
/* Coordinators only; never call from helper jobs or while holding Apps/board
 * guards. Queue time is separate from the native pre-copy compute deadline. */
bool ek_render_frame_begin(unsigned client);
void ek_render_frame_end(bool owned);
void ek_render_frame_stats(EkRenderFrameStats *out);
#ifdef __cplusplus
}
#endif
#endif
