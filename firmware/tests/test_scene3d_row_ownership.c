/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Include the production kernel to inspect row ownership without adding a
 * public/native/guest diagnostic API or firmware storage. */
#include "../EvilKeyV1/src/apps/ek_scene3d.c"
#include <assert.h>
#include <stdio.h>
int main(void){
    for(unsigned height=1;height<=17;height++)for(unsigned parity=0;parity<2;parity++){
        uint32_t pixels[32*17];for(unsigned i=0;i<32*17;i++)pixels[i]=0x1234;
        RasterPrimitive items[2]={
            {{0,0,1000},{0,height,1000},{32,height,1000},0xf800},
            {{0,0,1000},{32,height,1000},{32,0,1000},0xf800}};
        RasterBatch batch={items,2};
        Frame f={0};EkSceneProfile p={0};f.profile=&p;f.rw=32;f.rh=height;f.row_step=1;
        f.pixels=pixels;f.stats.status=EVILKEY_3D_OK;
        RasterJob job={&f,&batch,parity,{0}};raster_band(&job);
        assert(job.profile.stats.status==EVILKEY_3D_OK);
        unsigned touched=0;
        for(unsigned y=0;y<height;y++)for(unsigned x=0;x<32;x++){
            if(y%2!=parity)assert(pixels[y*32+x]==0x1234);
            else if(pixels[y*32+x]!=0x1234)touched++;
        }
        assert(touched==((height+1-parity)/2)*32);
        /* Inclusive shared triangle edges can test a pixel twice. */
        assert(job.profile.stats.pixel_tests>=touched);
    }
    puts("PASS native geometry ownership: even/odd rows, scratch heights1..17, no cross-band writes");return 0;
}
