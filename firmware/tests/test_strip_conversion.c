#include "ek_display_strips.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
int main(void){
 const size_t cap=65544;uint16_t *src=malloc(cap*2),*copy=malloc(cap*2),*dst=malloc(cap*2);
 assert(src&&copy&&dst);unsigned cases=0;
 for(unsigned pattern=0;pattern<4;pattern++)for(unsigned sa=0;sa<2;sa++)for(unsigned da=0;da<2;da++){
  for(size_t i=0;i<cap;i++)src[i]=pattern==0?(uint16_t)i:pattern==1?0:pattern==2?0xffff:(uint16_t)(i*73+17);
  memcpy(copy,src,cap*2);
  for(unsigned ci=0;ci<75;ci++){
   size_t n=ci<66?ci:ci==66?271:ci==67?279:ci==68?280:ci==69?4479:ci==70?4480:ci==71?4481:ci==72?65535:ci==73?65536:65537;
   for(size_t i=0;i<cap;i++)dst[i]=0xa55a;
   uint16_t *out=dst+2+da;const uint16_t *in=src+2+sa;
   ek_display_native_copy(out,in,n);
   for(size_t i=0;i<cap;i++){
    uint16_t want=0xa55a;if(i>=2+da&&i<2+da+n){uint16_t c=in[i-2-da];want=(uint16_t)((c<<8)|(c>>8));}
    assert(dst[i]==want);
   }
   assert(memcmp(src,copy,cap*2)==0);++cases;
  }
 }
 free(src);free(copy);free(dst);printf("STRIP CONVERSION PASS %u cases: allRGB565/0/ones/random,0..65/280/4480/65536 boundaries,independent alignment,canaries,immutable source\n",cases);
}
