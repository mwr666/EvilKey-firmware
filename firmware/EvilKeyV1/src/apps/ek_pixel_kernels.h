/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef EK_PIXEL_KERNELS_H
#define EK_PIXEL_KERNELS_H
#include "ek_strip_pie.h"
#include <string.h>
#ifdef __cplusplus
extern "C" {
#endif
#if defined(CONFIG_IDF_TARGET_ESP32S3)
void ek_pixel_pie_fill_blocks(uint16_t *,size_t,uint32_t);
void ek_pixel_pie_copy_blocks(uint16_t *,const void *,size_t);
void ek_pixel_pie_key_blocks(uint16_t *,const void *,size_t);
#elif defined(EK_STRIP_PIE_MODEL)
static inline void ek_pixel_pie_fill_blocks(uint16_t *d,size_t n,uint32_t c){
    for(size_t i=0;i<n*8;i++)d[i]=(uint16_t)c;
}
static inline void ek_pixel_pie_copy_blocks(uint16_t *d,const void *s,size_t n){memcpy(d,s,n*16);}
static inline void ek_pixel_pie_key_blocks(uint16_t *d,const void *s,size_t n){
    /* Model the actual byte comparison, arithmetic shift and whole-pixel mask. */
    for(size_t i=0;i<n*4;i++){
        uint32_t x,y;memcpy(&x,(const uint8_t *)s+i*4,4);memcpy(&y,(uint8_t *)d+i*4,4);
        uint32_t eq=0;for(unsigned b=0;b<4;b++)if(!((x>>(b*8))&255))eq|=255u<<(b*8);
        uint32_t shifted=(eq>>8)|((eq&0x80000000u)?0xff000000u:0);
        uint32_t low=eq&shifted&0x00ff00ffu,mask=low|(low<<8);
        y=(y&mask)|(x&~mask);memcpy((uint8_t *)d+i*4,&y,4);
    }
}
#endif
#if defined(CONFIG_IDF_TARGET_ESP32S3) || defined(EK_STRIP_PIE_MODEL)
static inline void ek_pixel_fill(uint16_t *d,size_t n,uint16_t c){
    while(n&&((uintptr_t)d&15)){*d++=c;--n;}
    size_t blocks=n/8;if(blocks)ek_pixel_pie_fill_blocks(d,blocks,(uint32_t)c|((uint32_t)c<<16));
    d+=blocks*8;n-=blocks*8;while(n--)*d++=c;
}
static inline void ek_pixel_copy(uint16_t *d,const uint8_t *s,size_t n,int key){
    if(!key&&(((uintptr_t)d^(uintptr_t)s)&15)){memcpy(d,s,n*2);return;}
    while(n&&((((uintptr_t)d&15)||((uintptr_t)s&15)))){
        uint16_t c=(uint16_t)(s[0]|((uint16_t)s[1]<<8));if(!key||c)*d=c;
        d++;s+=2;--n;
        /* Differently aligned key sources stay scalar, without overread. */
    }
    size_t blocks=n/8;if(blocks){if(key)ek_pixel_pie_key_blocks(d,s,blocks);else ek_pixel_pie_copy_blocks(d,s,blocks);}
    d+=blocks*8;s+=blocks*16;n-=blocks*8;
    while(n--){uint16_t c=(uint16_t)(s[0]|((uint16_t)s[1]<<8));if(!key||c)*d=c;d++;s+=2;}
}
static inline int ek_pixel_kernel_selftest(void){
    uint16_t src[24] __attribute__((aligned(16))),dst[24] __attribute__((aligned(16)));
    if(!ek_strip_pie_selftest())return 0;
    for(uint32_t first=0;first<65536;first+=8){
        for(unsigned i=0;i<24;i++){src[i]=0xa55a;dst[i]=0x5aa5;}
        for(unsigned i=0;i<8;i++)src[i+8]=(uint16_t)(first+i);
        ek_pixel_pie_copy_blocks(dst+8,src+8,1);
        for(unsigned i=0;i<24;i++)if(dst[i]!=(i>=8&&i<16?src[i]:0x5aa5))return 0;
        for(unsigned i=0;i<24;i++)dst[i]=0x5aa5;
        ek_pixel_pie_key_blocks(dst+8,src+8,1);
        for(unsigned i=0;i<24;i++)if(dst[i]!=(i>=8&&i<16&&src[i]?src[i]:0x5aa5))return 0;
        /* Every colour also appears in every broadcast lane across eight cases. */
        for(unsigned c=0;c<8;c++){
            uint16_t value=(uint16_t)(first+c);
            ek_pixel_pie_fill_blocks(dst+8,1,(uint32_t)value|((uint32_t)value<<16));
            for(unsigned i=0;i<24;i++)if(dst[i]!=(i>=8&&i<16?value:0x5aa5))return 0;
        }
        for(unsigned i=0;i<24;i++)if(src[i]!=(i>=8&&i<16?(uint16_t)(first+i-8):0xa55a))return 0;
    }
    return 1;
}
#endif
#ifdef __cplusplus
}
#endif
#endif
