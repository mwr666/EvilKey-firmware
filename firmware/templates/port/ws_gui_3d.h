/* SPDX-License-Identifier: AGPL-3.0-or-later */
#pragma once
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Display-owner task only. Sources stay alive through LVGL composition.
 * No input events, NVS, USB calls, worker tasks or DMA ownership here. */
enum { WS_3D_SAVER, WS_3D_GEAR, WS_3D_HERO, WS_3D_APPS, WS_3D_CHANNELS };
typedef struct { const uint8_t *pixels; uint16_t width, height; uint32_t generation; } ws_gui_3d_frame_t;
typedef struct { size_t psram_bytes; uint32_t frames, last_us, peak_us, triangles; bool ready; } ws_gui_3d_stats_t;
typedef struct {
    uint32_t frames,cache_hits,geometry_us,raster_us,convert_us,last_us,peak_us,p50_us,p95_us;
    uint32_t triangles,converted_samples,detail_samples; bool detail_sample;
} ws_gui_3d_channel_stats_t;
typedef struct {
    uint32_t compose_us,panel_wait_us,peak_compose_us,peak_panel_wait_us,p50_us,p95_us;
    uint32_t frame_us,peak_frame_us,frames,flushes,bytes,failed_frames;
    uint16_t tile_rows,face_cache_bytes; bool internal_tiles;
} ws_gui_3d_presentation_stats_t;
bool ws_gui_3d_init(void);
void ws_gui_3d_profile(bool enabled);
bool ws_gui_3d_render(unsigned channel, uint16_t phase, uint32_t accent,
                      unsigned icon, ws_gui_3d_frame_t *out);
ws_gui_3d_stats_t ws_gui_3d_stats(void);
ws_gui_3d_channel_stats_t ws_gui_3d_channel_stats(unsigned channel);
ws_gui_3d_presentation_stats_t ws_gui_3d_presentation_stats(void);
/* Same display-owner task; panel wait is a subset of compose wall time. */
/* begin/end are display-owner only; complete is a tiny ISR-safe timestamp.
 * Wait is already contained in compose. Percentiles and frames count only completed frames with a flush; idle ticks
 * update compose timing without replacing the last transfer counters. */
uint32_t ws_gui_3d_frame_begin(uint32_t start_us);
void ws_gui_3d_frame_flush(uint32_t id,uint32_t bytes);
void ws_gui_3d_frame_complete(uint32_t id,uint32_t end_us);
void ws_gui_3d_frame_end(uint32_t id,uint32_t end_us,uint32_t wait_us,bool success);
void ws_gui_3d_record_panel_wait(uint32_t wait_us);
uint32_t ws_gui_3d_take_panel_wait(void);
/* Call after LVGL/DMA allocations. Never consumes the reserved USB margin. */
void ws_gui_3d_configure_tiles(void);
/* Decorative perspective only; zero at either end of a navigation transition. */
void ws_gui_3d_transition(int16_t depth);
#ifdef WS_3D_HOST
/* Frontal pose for comparison with original LVGL icons; never built on device. */
int ws_gui_3d_project_round(float x);
bool ws_gui_3d_reference(unsigned channel,unsigned icon,uint32_t accent,ws_gui_3d_frame_t *out);
#endif
#ifdef __cplusplus
}
#endif
