/* Independent pixel oracle; host instruction model is not MCU proof. */
#define EK_STRIP_PIE_MODEL 1
#include "../EvilKeyV1/src/apps/ek_pixel_kernels.h"
#include "../EvilKeyV1/src/apps/ek_pixel_accel.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
static uint8_t source[132000] __attribute__((aligned(16)));
static uint16_t result[66064] __attribute__((aligned(16))),expected[66064];
int main(void){
 assert(ek_pixel_kernel_selftest());unsigned cases=0;
 const unsigned counts[]={0,1,2,7,8,9,15,16,17,31,32,33,63,64,65,128,129,280,4480,65536};
 for(unsigned pattern=0;pattern<4;pattern++)for(unsigned da=0;da<8;da++)for(unsigned sa=0;sa<16;sa++)for(unsigned ci=0;ci<sizeof(counts)/sizeof(*counts);ci++){
  unsigned n=counts[ci];uint8_t *src=source+32+sa;uint16_t *dst=result+16+da;
  for(unsigned i=0;i<sizeof source;i++)source[i]=0x99;
  for(unsigned i=0;i<n;i++){uint16_t c=pattern==0?(uint16_t)i:pattern==1?0:pattern==2?0xffff:(uint16_t)(i*257u+0x100u);src[2*i]=(uint8_t)c;src[2*i+1]=(uint8_t)(c>>8);}
  uint32_t hash=0;for(unsigned i=0;i<sizeof source;i++)hash=hash*33+source[i];
  for(unsigned op=0;op<5;op++){
   for(unsigned i=0;i<66064;i++)result[i]=expected[i]=(uint16_t)(i*73+0x55aa);
   uint16_t colour=(uint16_t)(sa*0x1234+ci*29);
   for(unsigned i=0;i<n;i++){
    uint16_t c=(uint16_t)(src[2*i]|((uint16_t)src[2*i+1]<<8));
    if(op==0)expected[16+da+i]=colour;
    if(op==1)expected[16+da+i]=c;
    if((op==2||op==4)&&c)expected[16+da+i]=c;
    if(op==3){c=expected[16+da+i];expected[16+da+i]=(uint16_t)((c<<8)|(c>>8));}
   }
   if(op==0)ek_pixel_fill(dst,n,colour);
   if(op==1||op==2)ek_pixel_copy(dst,src,n,op==2);
   if(op==3)ek_strip_pie_swap(dst,n);
   if(op==4)ek_pixel_key_staged(dst,src,n);
   assert(!memcmp(result,expected,sizeof result));cases++;
  }
  uint32_t after=0;for(unsigned i=0;i<sizeof source;i++)after=after*33+source[i];assert(after==hash);
 }
 EkPixelMark mark={0x454b5049,44,0,~0u};
 for(unsigned stage=0;stage<10;stage++){mark.stage=stage;mark.inverse=~stage;assert(ek_pixel_mark_fault(&mark,true)==(stage>=1&&stage<=6));assert(!ek_pixel_mark_fault(&mark,false));}
 mark.stage=2;mark.inverse=~2u;mark.version=43;assert(!ek_pixel_mark_fault(&mark,true));mark.version=44;mark.magic=0;assert(!ek_pixel_mark_fault(&mark,true));mark.magic=0x454b5049;mark.inverse=0;assert(!ek_pixel_mark_fault(&mark,true));
 assert(!ek_pixel_accel_rect(result,100,NULL,0,10,10,5,false));
 for(unsigned i=0;i<66064;i++)result[i]=0x55aa;
 assert(ek_pixel_accel_rect(result+20,100,NULL,0,64,9,0x1234,false));
 for(unsigned y=0;y<9;y++)for(unsigned x=0;x<100;x++)assert(result[20+y*100+x]==(x<64?0x1234:0x55aa));
 EkPixelStats stats;ek_pixel_accel_stats(&stats);assert(stats.selftest==1&&stats.fill==1);

 for(unsigned width=8;width<=14;width+=6){
  unsigned height=width==8?16:24;
  for(unsigned i=0;i<66064;i++)result[i]=expected[i]=(uint16_t)(i*73+0x55aa);
  uint8_t *src=source+33;
  for(unsigned y=0;y<height;y++)for(unsigned x=0;x<width;x++){
   uint16_t c=(x+y)%3?(uint16_t)((y*37+x*257)&65535):0;
   src[(y*23+x)*2]=(uint8_t)c;src[(y*23+x)*2+1]=(uint8_t)(c>>8);
   if(c)expected[20+y*100+x]=c;
  }
  assert(ek_pixel_accel_rect(result+20,100,src,23,width,height,0,true));
  assert(!memcmp(result,expected,sizeof result));
 }
 ek_pixel_accel_stats(&stats);assert(stats.key==2);
 printf("PASS %u independent pixel cases; all65536 selftest; recovery policy; shared region bounds;8x16/14x24 misaligned SIMD glyphs\n",cases);
}
