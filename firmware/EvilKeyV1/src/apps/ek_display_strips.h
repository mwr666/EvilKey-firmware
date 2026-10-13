/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef EK_DISPLAY_STRIPS_H
#define EK_DISPLAY_STRIPS_H
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "ek_strip_pie.h"
/* Existing display-owner SRAM strips only. The source is a complete,
 * immutable panel-order snapshot; top rows remain owned by LVGL overlays. */
/* Convert only the display-owned SRAM destination, never the snapshot. */
static inline void ek_display_native_copy(uint16_t *out,const uint16_t *source,size_t count){
    memcpy(out,source,count*sizeof(*out));
    if(count&&((uintptr_t)out&3u)){
        uint16_t c=*out;*out++=(uint16_t)((c<<8)|(c>>8));--count;
    }
    typedef uint32_t __attribute__((__may_alias__)) EkStripWord;
    while(count>=2){
        uint32_t c=*(EkStripWord *)out;
        *(EkStripWord *)out=((c&0x00ff00ffu)<<8)|((c>>8)&0x00ff00ffu);
        out+=2;count-=2;
    }
    if(count){uint16_t c=*out;*out=(uint16_t)((c<<8)|(c>>8));}
}
#if defined(CONFIG_IDF_TARGET_ESP32S3) || defined(EK_STRIP_PIE_MODEL)
static inline void ek_display_native_copy_pie(uint16_t *out,const uint16_t *source,size_t count){
    memcpy(out,source,count*sizeof(*out));
    ek_strip_pie_swap(out,count);
}
#endif
typedef int (*EkStripWait)(void *);
typedef int (*EkStripSubmit)(void *,unsigned,unsigned,const uint16_t *,size_t,int);
typedef int (*EkStripCopy)(void *,uint16_t *,const uint16_t *,size_t);
static inline int ek_display_strips_with_copy(const uint16_t *source,uint16_t *first,
    uint16_t *second,unsigned width,unsigned height,unsigned strip_rows,
    unsigned top,unsigned dirty_y,unsigned dirty_height,
    EkStripWait wait,EkStripSubmit submit,EkStripCopy copy,void *user){
    if(!source||!first||!second||first==second||!width||(width&1)||!height||
       (height&1)||!strip_rows||(strip_rows&1)||top>height||(top&1)||
       dirty_y>height||dirty_height>height-dirty_y||!wait||!submit)return -1;
    unsigned end=(dirty_y+dirty_height+1u)&~1u;
    unsigned row=dirty_y&~1u;if(row<top)row=top;
    int status=wait(user);if(status)return status;
    if(!dirty_height)return 0;
    for(unsigned slot=0;row<end;slot^=1u){
        unsigned n=end-row;if(n>strip_rows)n=strip_rows;
        uint16_t *out=slot?second:first;
        if(copy){
            status=copy(user,out,source+(size_t)row*width,(size_t)n*width);
            if(status)return status;
        }else memcpy(out,source+(size_t)row*width,(size_t)n*width*sizeof(*out));
        status=submit(user,row,n,out,(size_t)n*width,row+n==end);
        if(status)return status;
        row+=n;
    }
    /* ACK is forbidden until the final DMA consumed its source buffer. */
    return wait(user);
}
static inline int ek_display_strips(const uint16_t *source,uint16_t *first,
    uint16_t *second,unsigned width,unsigned height,unsigned strip_rows,
    unsigned top,unsigned dirty_y,unsigned dirty_height,
    EkStripWait wait,EkStripSubmit submit,void *user){
    return ek_display_strips_with_copy(source,first,second,width,height,strip_rows,
        top,dirty_y,dirty_height,wait,submit,NULL,user);
}
#endif
