/* SPDX-License-Identifier: AGPL-3.0-or-later */
#pragma once

#include <stdint.h>

#define PF_LOOT_INDEX_MAGIC "PFLOOTI1"
#define PF_LOOT_INDEX_MAGIC_SIZE 8U
#define PF_LOOT_INDEX_VERSION 1U
#define PF_LOOT_INDEX_HEADER_SIZE 64U
#define PF_LOOT_INDEX_RECORD_SIZE 12U
#define PF_LOOT_INDEX_MAX_SEGMENTS 256U

typedef enum {
    PF_LOOT_KIND_VARIABLE_EXFIL_LE16 = 1,
    PF_LOOT_KIND_REFLECTION_RAW = 2,
    PF_LOOT_KIND_LEGACY_UNKNOWN = 3
} pf_loot_kind_t;

typedef struct {
    uint32_t offset;
    uint32_t length;
    uint8_t kind;
} pf_loot_segment_t;

static inline void pf_loot_put_u16(uint8_t *out,uint16_t value)
{
    out[0]=(uint8_t)(value&0xffU);out[1]=(uint8_t)(value>>8);
}

static inline void pf_loot_put_u32(uint8_t *out,uint32_t value)
{
    out[0]=(uint8_t)(value&0xffU);out[1]=(uint8_t)((value>>8)&0xffU);
    out[2]=(uint8_t)((value>>16)&0xffU);out[3]=(uint8_t)(value>>24);
}

static inline uint16_t pf_loot_get_u16(const uint8_t *in)
{
    return (uint16_t)((uint16_t)in[0]|((uint16_t)in[1]<<8));
}

static inline uint32_t pf_loot_get_u32(const uint8_t *in)
{
    return (uint32_t)in[0]|((uint32_t)in[1]<<8)|
           ((uint32_t)in[2]<<16)|((uint32_t)in[3]<<24);
}
