/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "LootIndexFormat.h"

int main(void)
{
    uint8_t header[PF_LOOT_INDEX_HEADER_SIZE]={0};
    memcpy(header,PF_LOOT_INDEX_MAGIC,PF_LOOT_INDEX_MAGIC_SIZE);
    header[8]=PF_LOOT_INDEX_VERSION;
    header[9]=PF_LOOT_INDEX_HEADER_SIZE;
    header[10]=PF_LOOT_INDEX_RECORD_SIZE;
    pf_loot_put_u32(header+12,0x00040102U);
    pf_loot_put_u16(header+16,3U);

    assert(memcmp(header,"PFLOOTI1",8U)==0);
    assert(pf_loot_get_u32(header+12)==0x00040102U);
    assert(pf_loot_get_u16(header+16)==3U);
    assert(PF_LOOT_KIND_VARIABLE_EXFIL_LE16==1);
    assert(PF_LOOT_KIND_REFLECTION_RAW==2);
    assert(PF_LOOT_KIND_LEGACY_UNKNOWN==3);
    assert(PF_LOOT_INDEX_HEADER_SIZE==64U);
    assert(PF_LOOT_INDEX_RECORD_SIZE==12U);
    return 0;
}
