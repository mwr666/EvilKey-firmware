/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Original byte-order kernel. Caller supplies aligned SRAM and count of
 * complete 8-pixel blocks, in task context already pinned by its prior work.
 * CP3 and SAR use the ordinary IDF context handling; no IRQ/CPENABLE edits. */
#include "sdkconfig.h"
#if defined(CONFIG_IDF_TARGET_ESP32S3)
    .text
    .align 4
    .global ek_strip_pie_swap_blocks
    .type ek_strip_pie_swap_blocks,@function
ek_strip_pie_swap_blocks:
    entry a1, 32
    /* a2=aligned data, a3=positive number of 16-byte blocks */
    beqz a3, 2f
    movi a4, 0x00ff00ff
    /* ENTRY32 is entirely register-window save space. Never store locals
     * there: R26 SP+16 corrupted a saved return context. */
    ee.movi.32.q q3, a4, 0
    ee.movi.32.q q3, a4, 1
    ee.movi.32.q q3, a4, 2
    ee.movi.32.q q3, a4, 3
    movi a4, 8
    wsr a4, SAR
1:
    ee.vld.128.ip q0, a2, 0
    ee.andq q1, q0, q3
    ee.vsl.32 q1, q1
    ee.vsr.32 q2, q0
    /* VSR is arithmetic: remove sign extension AND cross-pixel bits. */
    ee.andq q2, q2, q3
    ee.orq q0, q1, q2
    ee.vst.128.ip q0, a2, 16
    addi a3, a3, -1
    bnez a3, 1b
2:
    retw.n
    .size ek_strip_pie_swap_blocks, .-ek_strip_pie_swap_blocks
    .align 4
    .global ek_pixel_pie_fill_blocks
    .type ek_pixel_pie_fill_blocks,@function
ek_pixel_pie_fill_blocks:
    entry a1, 32
    /* a2=out, a3=blocks, a4=repeated two-pixel word */
    beqz a3, 2f
    ee.movi.32.q q0, a4, 0
    ee.movi.32.q q0, a4, 1
    ee.movi.32.q q0, a4, 2
    ee.movi.32.q q0, a4, 3
1:
    ee.vst.128.ip q0, a2, 16
    addi a3, a3, -1
    bnez a3, 1b
2:
    retw.n
    .size ek_pixel_pie_fill_blocks, .-ek_pixel_pie_fill_blocks
    .align 4
    .global ek_pixel_pie_copy_blocks
    .type ek_pixel_pie_copy_blocks,@function
ek_pixel_pie_copy_blocks:
    entry a1, 32
    /* a2=out, a3=source, a4=blocks; disjoint caller-owned buffers */
    beqz a4, 2f
1:
    ee.vld.128.ip q0, a3, 16
    ee.vst.128.ip q0, a2, 16
    addi a4, a4, -1
    bnez a4, 1b
2:
    retw.n
    .size ek_pixel_pie_copy_blocks, .-ek_pixel_pie_copy_blocks
    .align 4
    .global ek_pixel_pie_key_blocks
    .type ek_pixel_pie_key_blocks,@function
ek_pixel_pie_key_blocks:
    entry a1, 32
    /* S3 compares bytes. Combine both byte results into a whole RGB565 mask. */
    beqz a4, 2f
    ee.zero.q q7
    movi a5, 0x00ff00ff
    ee.movi.32.q q6, a5, 0
    ee.movi.32.q q6, a5, 1
    ee.movi.32.q q6, a5, 2
    ee.movi.32.q q6, a5, 3
    movi a5, 8
    wsr a5, SAR
1:
    ee.vld.128.ip q0, a3, 16
    ee.vld.128.ip q1, a2, 0
    ee.vcmp.eq.s8 q2, q0, q7
    ee.vsr.32 q3, q2
    ee.andq q2, q2, q3
    ee.andq q2, q2, q6
    ee.vsl.32 q3, q2
    ee.orq q2, q2, q3
    ee.andq q1, q1, q2
    ee.notq q2, q2
    ee.andq q0, q0, q2
    ee.orq q0, q0, q1
    ee.vst.128.ip q0, a2, 16
    addi a4, a4, -1
    bnez a4, 1b
2:
    retw.n
    .size ek_pixel_pie_key_blocks, .-ek_pixel_pie_key_blocks
#endif
