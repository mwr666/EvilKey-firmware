/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Independent 64-bit half-space coverage oracle, not span intersections. */
#include "../EvilKeyV1/src/apps/ek_scene3d.c"
#include <assert.h>
#include <stdio.h>
static uint32_t rng=0x316b3c31;
static uint32_t next(void){rng=rng*1664525u+1013904223u;return rng;}
static int64_t oracle_edge(int ax,int ay,int bx,int by,int x,int y){
    return (int64_t)(bx-ax)*(y-ay)-(int64_t)(by-ay)*(x-ax);
}
int main(void){
    uint32_t pixels[140*160+2];unsigned covered=0;
    for(unsigned k=0;k<12000;k++){
        unsigned w=1+next()%140,h=1+next()%160,step=k%3?2:1,parity=step==2?k%2:0;
        P p[3];for(unsigned v=0;v<3;v++)p[v]=(P){
            (float)(next()%((w+1)*16))/16,(float)(next()%((h+1)*16))/16,1000};
        if(k%8==0){p[0]=(P){0,0,1000};p[1]=(P){w,h,1000};p[2]=(P){0,h,1000};}
        if(k%8==1)p[1]=p[0];
        if(k%8==2)p[1].y=p[0].y;
        if(k%8==3)p[1].x=p[0].x;
        /* Mixed lower depth, tie and nearer depth, plus untouched guards. */
        for(unsigned i=0;i<w*h+2;i++)pixels[i]=((i%3==0?1001:i%3==1?1000:999)<<16)|0x1234;
        uint32_t left=pixels[0],right=pixels[w*h+1];
        Frame f={0};EkSceneProfile profile={0};f.profile=&profile;
        f.rw=w;f.rh=h;f.row_step=step;f.first_row=parity;f.pixels=pixels+1;f.stats.status=EVILKEY_3D_OK;
        raster_pixels(&f,p[0],p[1],p[2],0x47d8);
        int ax=(int)(p[0].x*16),ay=(int)(p[0].y*16),bx=(int)(p[1].x*16),by=(int)(p[1].y*16),cx=(int)(p[2].x*16),cy=(int)(p[2].y*16);
        int64_t area=oracle_edge(ax,ay,bx,by,cx,cy);unsigned count=0;
        for(unsigned y=0;y<h;y++)for(unsigned x=0;x<w;x++){
            int px=x*16+8,py=y*16+8;
            int64_t a=oracle_edge(bx,by,cx,cy,px,py),b=oracle_edge(cx,cy,ax,ay,px,py),c=oracle_edge(ax,ay,bx,by,px,py);
            bool inside=area&&((area>0&&a>=0&&b>=0&&c>=0)||(area<0&&a<=0&&b<=0&&c<=0));
            inside=inside&&(step==1||y%2==parity);
            count+=inside;
            unsigned index=1+y*w+x,depth=index%3==0?1001:index%3==1?1000:999;
            uint32_t expected=inside&&depth<1000?(1000u<<16)|0x47d8:(depth<<16)|0x1234;
            assert(pixels[index]==expected);
        }
        assert(f.stats.status==EVILKEY_3D_OK&&f.stats.pixel_tests==count);
        assert(pixels[0]==left&&pixels[w*h+1]==right);covered+=count;
    }
    printf("PASS 12000 independent coverage/depth/tie/parity/guard cases; %u covered pixels\n",covered);
    return 0;
}
