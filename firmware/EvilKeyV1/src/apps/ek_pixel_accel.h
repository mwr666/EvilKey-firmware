/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef EK_PIXEL_ACCEL_H
#define EK_PIXEL_ACCEL_H
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct {uint32_t magic,version,stage,inverse;} EkPixelMark;
typedef struct {uint32_t selftest,previous_stage,reset_reason,blocked,fill,copy,key,swap,worker,fallback;int32_t core;} EkPixelStats;
/* Independent pure recovery policy, also used by the target RTC reader. */
bool ek_pixel_mark_fault(const EkPixelMark *mark,bool unexpected);
bool ek_pixel_accel_ready(void);
void ek_pixel_accel_stage(uint32_t stage);
void ek_pixel_accel_stats(EkPixelStats *out);
/* false means no writes. Strides are pixels. Fill has NULL source. */
bool ek_pixel_accel_rect(uint16_t *dst,size_t dst_stride,const uint8_t *src,
                         size_t src_stride,size_t width,size_t height,uint16_t colour,bool key);
bool ek_pixel_accel_fill(uint16_t *dst,size_t count,uint16_t colour);
void ek_pixel_accel_swap(uint16_t *dst,size_t count);
#ifdef __cplusplus
}
#endif
#endif
