#include "ek_display_strips.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
static uint16_t image[280*456],screen[280*456],a[280*16],b[280*16],saved[280*16];
typedef struct{const uint16_t *pending;size_t count;unsigned y,n,calls,fail,done,submits;unsigned last_y,copies,copy_fail;} State;
static int copy(void *u,uint16_t *out,const uint16_t *in,size_t n){State*s=u;
 if(++s->copies==s->copy_fail)return 9;
 assert(out==a||out==b);assert(out!=s->pending);assert(n<=280*16);
 memcpy(out,in,n*2);return 0;}
static int wait(void *u){State*s=u;if(++s->calls==s->fail)return 7;
 if(s->pending){assert(!memcmp(saved,s->pending,s->count*2));memcpy(screen+s->y*280,s->pending,s->count*2);s->pending=NULL;s->done++;}return 0;}
static int submit(void *u,unsigned y,unsigned n,const uint16_t *p,size_t count,int last){State*s=u;
 /* The real transport waits N-1 inside submit after filling alternate N. */
 int e=wait(s);if(e)return e;
 assert(p==a||p==b);assert(!(y&1)&&!(n&1)&&count==280*n&&n<=16);
 assert(y>=44&&y+n<=456);s->pending=p;s->count=count;s->y=y;s->n=n;
 memcpy(saved,p,count*2);s->submits++;if(last)s->last_y=y+n;return 0;}
static void native_copy_test(void){
 uint16_t *source=malloc((65536+4)*2),*out=malloc((65536+4)*2);assert(source&&out);
 const unsigned counts[]={0,1,2,255,256,257,4480,65536};unsigned cases=0;
 for(unsigned a=0;a<2;a++)for(unsigned b=0;b<2;b++)for(unsigned n=0;n<8;n++){
  unsigned count=counts[n];for(unsigned i=0;i<65540;i++){source[i]=0xbeef;out[i]=0xa55a;}
  for(unsigned i=0;i<count;i++)source[a+i]=(uint16_t)i;
  ek_display_native_copy(out+b,source+a,count);
  for(unsigned i=0;i<65540;i++){
   uint16_t c=(uint16_t)(i-b);assert(out[i]==(i>=b&&i<b+count?(uint16_t)((c&255)*256+c/256):0xa55a));
   assert(source[i]==(i>=a&&i<a+count?(uint16_t)(i-a):0xbeef));
  }++cases;
 }free(source);free(out);printf("PASS native-to-SRAM strip conversion: %u all-RGB565/alignment/boundary/canary cases\n",cases);
}
int main(void){native_copy_test();for(unsigned i=0;i<280*456;i++)image[i]=(uint16_t)(i*73+9);
 unsigned cases=0;
 for(unsigned y=0;y<=456;y+=3)for(unsigned n=0;n<=456-y;n+=7){
  for(unsigned i=0;i<280*456;i++)screen[i]=0xbeef;
  State s={0};assert(!ek_display_strips(image,a,b,280,456,16,44,y,n,wait,submit,&s));assert(!s.pending&&s.done==s.submits);
  unsigned lo=y&~1u;if(lo<44)lo=44;unsigned hi=n?(y+n+1)&~1u:lo;
  for(unsigned row=0;row<456;row++)for(unsigned x=0;x<280;x++)assert(screen[row*280+x]==(row>=lo&&row<hi?image[row*280+x]:0xbeef));cases++;
 }
 for(unsigned fail=1;fail<=28;fail++){State s={0};s.fail=fail;assert(ek_display_strips(image,a,b,280,456,16,44,0,456,wait,submit,&s)==7);}
 for(unsigned fail=1;fail<=26;fail++){State s={0};s.copy_fail=fail;
  assert(ek_display_strips_with_copy(image,a,b,280,456,16,44,0,456,wait,submit,copy,&s)==9);
  assert(s.copies==fail&&s.submits==fail-1);assert(!wait(&s));
 }
 {State s={0};assert(!ek_display_strips_with_copy(image,a,b,280,456,16,44,0,456,wait,submit,copy,&s));
  assert(s.copies==26&&s.done==26&&!s.pending);
  assert(!memcmp(screen+44*280,image+44*280,(456-44)*280*2));
 }
 State s={0};assert(ek_display_strips(image,a,a,280,456,16,44,0,456,wait,submit,&s)==-1);
 assert(ek_display_strips(image,a,b,280,456,16,44,455,2,wait,submit,&s)==-1);
 printf("STRIPS PASS %u partial/even exact-image cases;28 wait/submit and26 copy faults;immutable pending DMA;final completion before success\n",cases);
}
