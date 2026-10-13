/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef EK_STRIP_PIE_H
#define EK_STRIP_PIE_H
#include <stdint.h>
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Uses the S3 assembly only on target. Host model is explicitly not hardware
 * verification; hardware exhaustiveness is checked before enabling the path. */
#if defined(CONFIG_IDF_TARGET_ESP32S3)
void ek_strip_pie_swap_blocks(uint16_t *aligned,size_t blocks);
#elif defined(EK_STRIP_PIE_MODEL)
static inline void ek_strip_pie_swap_blocks(uint16_t *aligned,size_t blocks){
    typedef uint32_t __attribute__((__may_alias__)) Word;
    Word *words=(Word *)aligned;
    for(size_t i=0;i<blocks*4;++i){
        uint32_t value=words[i];
        uint32_t signed_shift=(value>>8)|((value&0x80000000u)?0xff000000u:0);
        words[i]=((value&0x00ff00ffu)<<8)|(signed_shift&0x00ff00ffu);
    }
}
#endif
#if defined(CONFIG_IDF_TARGET_ESP32S3) || defined(EK_STRIP_PIE_MODEL)
static inline void ek_strip_pie_swap(uint16_t *out,size_t count){
    while(count&&((uintptr_t)out&15u)){
        uint16_t c=*out;*out++=(uint16_t)((c<<8)|(c>>8));--count;
    }
    size_t blocks=count/8;
    if(blocks)ek_strip_pie_swap_blocks(out,blocks);
    out+=blocks*8;count-=blocks*8;
    while(count--){uint16_t c=*out;*out++=(uint16_t)((c<<8)|(c>>8));}
}
static inline int ek_strip_pie_selftest(void){
    uint16_t sample[24] __attribute__((aligned(16)));
    for(uint32_t first=0;first<65536;first+=8){
        for(unsigned i=0;i<24;++i)sample[i]=0xa55a;
        for(unsigned i=0;i<8;++i)sample[8+i]=(uint16_t)(first+i);
        ek_strip_pie_swap_blocks(sample+8,1);
        for(unsigned i=0;i<24;++i){
            uint16_t c=(uint16_t)(first+i-8);
            uint16_t want=i>=8&&i<16?(uint16_t)((c<<8)|(c>>8)):0xa55a;
            if(sample[i]!=want)return 0;
        }
    }
    return 1;
}
#endif
#ifdef __cplusplus
}
#endif
#endif
