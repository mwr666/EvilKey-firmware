#define EK_STRIP_PIE_MODEL 1
#include "ek_display_strips.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
int main(void){
 const size_t cap=65568;
 uint16_t *src=malloc(cap*2),*copy=malloc(cap*2),*dst=malloc(cap*2),*ref=malloc(cap*2);
 assert(src&&copy&&dst&&ref);assert(ek_strip_pie_selftest());
 unsigned cases=0;
 for(unsigned pattern=0;pattern<4;++pattern)for(unsigned sa=0;sa<8;++sa)for(unsigned da=0;da<8;++da){
  for(size_t i=0;i<cap;++i)src[i]=pattern==0?(uint16_t)i:pattern==1?0:pattern==2?0xffff:(uint16_t)(i*73+17);
  memcpy(copy,src,cap*2);
  for(unsigned ci=0;ci<75;++ci){
   size_t n=ci<66?ci:ci==66?271:ci==67?279:ci==68?280:ci==69?4479:ci==70?4480:ci==71?4481:ci==72?65535:ci==73?65536:65537;
   for(size_t i=0;i<cap;++i)dst[i]=ref[i]=0xa55a;
   const uint16_t *in=src+8+sa;uint16_t *out=dst+8+da;
   ek_display_native_copy_pie(out,in,n);
   ek_display_native_copy(ref+8+da,in,n);
   for(size_t i=0;i<cap;++i){
    uint16_t want=0xa55a;
    if(i>=8+da&&i<8+da+n){uint16_t c=in[i-8-da];want=(uint16_t)((c<<8)|(c>>8));}
    assert(dst[i]==want&&ref[i]==want);
   }
   assert(memcmp(src,copy,cap*2)==0);++cases;
  }
 }
 free(src);free(copy);free(dst);free(ref);
 printf("PIE HOST MODEL PASS %u cases/all16B offsets/all65536 values/canary/immutable/r22 exact; hardware instructions NOT EXECUTED\n",cases);
}
