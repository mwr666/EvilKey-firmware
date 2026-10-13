/* Real production reconstruction against frozen, independent per-cell oracle.
 * Host correctness only: no ESP32 timing claim. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../EvilKeyV1/src/apps/ek_scene3d.c"
static uint16_t expected[384*456+16],actual[384*456+16];
static uint32_t scratch[143*160+32],saved[143*160+32];
static uint32_t noise=27;
static uint32_t next(void){noise^=noise<<13;noise^=noise>>17;noise^=noise<<5;return noise;}
static void legacy(const uint32_t *p,uint16_t *d,unsigned stride,unsigned x,unsigned y,unsigned w,unsigned h,unsigned rw,int cached){
 if(!cached)return;
 for(unsigned line=0;line<h;line+=2)for(unsigned col=0;col<w/2;col++){
  uint32_t cell=p[(line/2)*rw+col];if(!(cell>>16))continue;
  uint16_t c=cell;unsigned at=(y+line)*stride+x+col*2;
  d[at]=d[at+1]=d[at+stride]=d[at+stride+1]=c;
 }
}
int main(void){
 unsigned widths[]={2,4,6,66,126,128,130,278,280},heights[]={2,4,18,288,320},strides[]={280,282,384};unsigned cases=0;
 for(unsigned wi=0;wi<9;wi++)for(unsigned hi=0;hi<5;hi++)for(unsigned si=0;si<3;si++)
 for(unsigned placement=0;placement<3;placement++)for(unsigned pattern=0;pattern<7;pattern++)for(int cached=0;cached<2;cached++){
  unsigned w=widths[wi],h=heights[hi],stride=strides[si],x=placement==0?0:placement==1?1:280-w,y=placement==0?0:placement==1?1:456-h;
  if(x+w>280||y+h>456)continue;
  unsigned rw=w/2+3;assert(rw*(h/2)+8<sizeof scratch/sizeof *scratch);
  for(unsigned i=0;i<sizeof expected/sizeof *expected;i++)expected[i]=actual[i]=(uint16_t)(i*7919u+cases*17u);
  for(unsigned i=0;i<sizeof scratch/sizeof *scratch;i++)scratch[i]=next();
  for(unsigned row=0;row<h/2;row++)for(unsigned col=0;col<w/2;col++){
   uint32_t v=next();int visible=pattern==0?0:pattern==1?1:pattern==2?((row+col)&1):pattern==3?(col==63||col==64||col==65):pattern==4?(col%65<64):pattern==5?((v&7)!=0):((v&7)==0);
   scratch[row*rw+col]=visible?(1u<<16)|(pattern==1||col%5==0?0:v&65535):(v&65535);
  }
  memcpy(saved,scratch,sizeof scratch);legacy(scratch+0,expected,stride,x,y,w,h,rw,cached);
  reconstruct(scratch,actual,stride,x,y,w,h,rw,cached,0xffff,1);
  assert(!memcmp(expected,actual,sizeof actual));assert(!memcmp(saved,scratch,sizeof scratch));cases++;
 }
 printf("TRANSPARENT RECONSTRUCT PASS cases=%u;independent legacy oracle,black/depth0/runs63/64/65/random/holes,oddXY/alignment,strides,full280x320,cached=false,source/destination canaries;no device timing\n",cases);
}
