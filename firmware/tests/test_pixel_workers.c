#include "../EvilKeyV1/src/apps/ek_pixel_accel.h"
#include "../EvilKeyV1/src/apps/ek_render_parallel.h"
#include <assert.h>
#include <stdio.h>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
static DWORD main_id;
bool ek_pixel_test_pinned(void){return GetCurrentThreadId()!=main_id;}
int main(void){
 main_id=GetCurrentThreadId();uint16_t pixels[1024];for(unsigned i=0;i<1024;i++)pixels[i]=0xa55a;
 assert(!ek_pixel_accel_rect(pixels,32,NULL,0,32,32,0x55aa,false));
 for(unsigned i=0;i<1024;i++)assert(pixels[i]==0xa55a);
 ek_render_workers_start();assert(ek_render_workers_ready());ek_render_parallel_enable(false);
 assert(!ek_pixel_accel_rect(pixels,32,NULL,0,32,32,0x55aa,false));
 for(unsigned i=0;i<1024;i++)assert(pixels[i]==0xa55a);
 ek_render_parallel_enable(true);
 for(unsigned n=0;n<100;n++){
  assert(ek_pixel_accel_rect(pixels,32,NULL,0,32,32,(uint16_t)n,false));
  for(unsigned i=0;i<1024;i++)assert(pixels[i]==n);
 }
 uint8_t source[2050];for(unsigned i=0;i<1024;i++){
  uint16_t c=i%3?(uint16_t)(i*257+1):0;source[1+i*2]=(uint8_t)c;source[2+i*2]=(uint8_t)(c>>8);
 }
 assert(ek_pixel_accel_rect(pixels,32,source+1,32,32,32,0,true));
 for(unsigned i=0;i<1024;i++){uint16_t c=i%3?(uint16_t)(i*257+1):0;assert(pixels[i]==(c?c:99));}
 EkPixelStats s;ek_pixel_accel_stats(&s);assert(s.worker==101&&s.key==1&&s.selftest==1&&s.fallback==2);
 puts("PASS unpinned caller: unavailable/disabled no writes;101 joined worker regions including misaligned zero-key; caller remains unpinned");
}
