/* SPDX-License-Identifier: AGPL-3.0-or-later */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "evilkey_app_abi.h"
#include "ek_scene3d.h"
#include "ek_run_metrics.h"
#include "ek_storage.h"
#ifdef __cplusplus
extern "C" {
#endif

enum { EK_APPS_WIDTH=280, EK_APPS_HEIGHT=456, EK_APPS_PIXELS=EK_APPS_WIDTH*EK_APPS_HEIGHT,
       EK_APPS_PAGE_SIZE=9, EK_APPS_CATALOG_MAX=64, EK_APPS_ICON_BYTES=8192 };
typedef enum {
    EK_APPS_NONE=0, EK_APPS_PREV, EK_APPS_NEXT, EK_APPS_RUN, EK_APPS_STOP, EK_APPS_REFRESH
} EkAppsCommand;
typedef struct {
    bool ready, mounted, running;
    bool scanning, catalog_ready, overflow;
    uint8_t count, selected;
    uint8_t page;
    uint16_t icon_valid;
    uint32_t catalog_generation;
    uint32_t mount_ms, scan_ms, icon_ms, headers_read;
    char names[EK_APPS_PAGE_SIZE][64];
    uint32_t frame;
    char id[32];
    char status[80];
} EkAppsState;

int ek_apps_start(void);
void ek_apps_set_visible(bool visible);
void ek_apps_set_modal(bool visible);
void ek_apps_request(EkAppsCommand command);
/* Cached metadata only; icon I/O remains on the worker. */
void ek_apps_select_page(unsigned page);
void ek_apps_launch(unsigned index);
/* Cached page only. No SD operation and no borrowed storage pointers. */
int ek_apps_copy_icons(uint8_t *rgb565, size_t capacity, uint32_t *generation);
/* Samples are copied into the worker mailbox. All I2C stays on the board task. */
void ek_apps_input(const EvilKeyAppTouch *touch, uint32_t count,
                   bool accel_valid, int32_t ax_mg, int32_t ay_mg,
                   int32_t az_mg);
void ek_apps_snapshot(EkAppsState *out);
/* Last native scene profile, retained after exit; copied under worker guard. */
void ek_apps_scene_profile(EkSceneProfile *out);
void ek_apps_run_metrics(EkRunMetrics *out);
/* ACK only the copied generation after the display owner's flush completes. */
void ek_apps_display_complete(uint32_t generation,bool success);
void ek_apps_display_complete_detail(uint32_t generation,bool success,
    uint32_t display_us,uint32_t copy_us,unsigned method,const uint32_t detail[4],unsigned cadence);
void ek_apps_display_complete_raster(uint32_t generation,bool success,
    uint32_t display_us,uint32_t copy_us,unsigned method,const uint32_t detail[4],unsigned cadence,uint32_t lvgl_us,bool sampled);
void ek_apps_display_complete_profile(uint32_t generation,bool success,
    uint32_t display_us,uint32_t copy_us,unsigned method);
enum {EK_DIAGNOSTICS_EXPORT_IDLE,EK_DIAGNOSTICS_EXPORT_BUSY,
      EK_DIAGNOSTICS_EXPORT_SAVED,EK_DIAGNOSTICS_EXPORT_ERROR,
      EK_DIAGNOSTICS_REPORT_CAPACITY=EK_STORAGE_DIAGNOSTICS_MAX_BYTES};
typedef struct {uint32_t status,request;char filename[32],error[80];} EkDiagnosticsExport;
/* Reserve one export; the display owner captures it on its next snapshot. */
void ek_apps_diagnostics_enable(bool enabled);
bool ek_apps_diagnostics_enabled(void);
int ek_apps_diagnostics_export_request(void);
/* On success the worker owns/frees data; failure leaves ownership with caller. */
int ek_apps_diagnostics_export(char *data,size_t size);
void ek_apps_diagnostics_export_failed(const char *reason);
void ek_apps_diagnostics_export_snapshot(EkDiagnosticsExport *out);
typedef struct { uint16_t x,y,width,height; } EkAppsDirty;
int ek_apps_copy_frame(uint16_t *pixels,size_t count,uint32_t *generation,
                       EkAppsDirty *dirty);
/* Private display path: same consumption contract, destination in panel order. */
int ek_apps_copy_frame_panel(uint16_t *pixels,size_t count,uint32_t *generation,
                             EkAppsDirty *dirty);
/* Private transport snapshot: panel prefix, native suffix; force re-snapshots
 * one guarded generation during a display format change. Not a guest ABI. */
int ek_apps_copy_frame_transport(uint16_t *pixels,size_t count,uint32_t *generation,
    EkAppsDirty *dirty,unsigned panel_rows,bool force);
/* Sole display owner exchanges its heap PSRAM canvas on full snapshots. Returned
 * pointer is caller-owned; previous pointer becomes service-owned. Stop never
 * frees the caller canvas. Partial/no-new use the ordinary copy contract. */
int ek_apps_exchange_frame_transport(uint16_t **pixels,size_t count,uint32_t *generation,
    EkAppsDirty *dirty,unsigned panel_rows,bool force);
typedef struct {
    uint32_t copies,last_bytes,last_us,peak_us;
    uint16_t last_width,last_height;
    uint32_t panel_order;
    uint32_t method;
} EkAppsCopyStats;
enum {EK_APPS_COPY_NATIVE=0,EK_APPS_COPY_FUSED=1,EK_APPS_COPY_ROW_SWAP=2,EK_APPS_COPY_BLOCK_SWAP=3,EK_APPS_COPY_MIXED=4,EK_APPS_COPY_EXCHANGE_MIXED=5,EK_APPS_COPY_EXCHANGE_FULL=6};
void ek_apps_copy_stats(EkAppsCopyStats *out);
#ifdef __cplusplus
}
#endif
