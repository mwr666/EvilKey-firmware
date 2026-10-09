/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "ek_scene3d.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
static uint64_t clock_tick(void *u){uint64_t *n=u;*n+=500;return *n;}
static unsigned hash(const uint16_t *p){unsigned h=2166136261u;for(unsigned i=0;i<280*456;i++){h^=p[i];h*=16777619u;}return h;}
int main(void){
    EvilKey3DScene s={0};s.magic=EVILKEY_3D_MAGIC;s.version=1;s.object_count=1;s.material_count=2;
    s.background=0x0842;s.camera=(EvilKey3DCamera){{0,2048,1536},{0,0,0},50,0,2560,0};
    s.materials[0]=(EvilKey3DMaterial){0x47d8,0,0};s.materials[1]=(EvilKey3DMaterial){0xf277,0,0};
    s.objects[0]=(EvilKey3DObject){1,0,{0,0,0},{0,0,0},{512,512,512},0,{0,0}};
    assert(ek_scene3d_validate((const uint8_t*)&s,sizeof(s)));
    uint16_t *memory=malloc((280*456+2)*2),*dst=memory+1;memory[0]=memory[280*456+1]=0xbeef;
    for(unsigned i=0;i<280*456;i++)dst[i]=0xabcd;
    EkScene3D *r=ek_scene3d_create();assert(r);
    EkSceneStats stats=ek_scene3d_render(r,(const uint8_t*)&s,dst,280,0,64,280,288,NULL,NULL);assert(stats.status==1&&stats.triangles==12);
    unsigned h=hash(dst),ink=0;for(unsigned i=64*280;i<352*280;i++)ink+=dst[i]!=s.background;assert(ink>100);
    for(unsigned i=0;i<64*280;i++)assert(dst[i]==0xabcd);for(unsigned i=352*280;i<456*280;i++)assert(dst[i]==0xabcd);
    uint64_t time=0;stats=ek_scene3d_render(r,(const uint8_t*)&s,dst,280,0,64,280,288,clock_tick,&time);assert(stats.status==2 && hash(dst)==h);
    s.object_count=96;for(unsigned i=0;i<96;i++){s.objects[i]=s.objects[0];s.objects[i].scale[0]=s.objects[i].scale[1]=s.objects[i].scale[2]=2048;}
    stats=ek_scene3d_render(r,(const uint8_t*)&s,dst,280,0,64,280,288,NULL,NULL);assert(stats.status==3 && hash(dst)==h);
    s.object_count=1;memset(s.objects+1,0,95*sizeof(s.objects[0]));
    /* Perspective, near-plane intersections, entirely behind eye, extreme
     * transforms, all builtins. Canary and finite work in every view. */
    for(unsigned model=1;model<=4;model++)for(unsigned pose=0;pose<36;pose++){
        s.objects[0].model=model;s.objects[0].rotation[0]=(int16_t)(pose*500-9000);s.objects[0].rotation[1]=pose*400;
        s.objects[0].position[1]=pose>20?2000:0;s.objects[0].scale[0]=pose>30?8192:512;s.camera.projection=pose&1;
        stats=ek_scene3d_render(r,(const uint8_t*)&s,dst,280,0,64,280,288,NULL,NULL);
        assert(stats.status==1||stats.status==3);assert(stats.pixel_tests<=300000);
        assert(memory[0]==0xbeef&&memory[280*456+1]==0xbeef);
    }
    memset(s.objects,0,sizeof(s.objects));s.object_count=2;s.camera.projection=1;
    s.objects[0]=(EvilKey3DObject){1,0,{0,0,0},{0,0,0},{512,512,512},0,{0,0}};
    s.objects[1]=(EvilKey3DObject){1,1,{0,512,384},{0,0,0},{256,256,256},0,{0,0}};
    stats=ek_scene3d_render(r,(const uint8_t*)&s,dst,280,0,64,280,288,NULL,NULL);assert(stats.status==1);h=hash(dst);
    EvilKey3DObject tmp=s.objects[0];s.objects[0]=s.objects[1];s.objects[1]=tmp;
    stats=ek_scene3d_render(r,(const uint8_t*)&s,dst,280,0,64,280,288,NULL,NULL);assert(stats.status==1&&hash(dst)==h);
    /* Large floor must not hide a raised cube in orthographic projection.
     * Orthographic depth is affine camera Z, not reciprocal perspective Z. */
    s.camera.projection=0;s.materials[0].flags=s.materials[1].flags=1;
    s.objects[0]=(EvilKey3DObject){1,0,{0,-54,0},{0,0,0},{2460,64,2460},0,{0,0}};
    s.objects[1]=(EvilKey3DObject){1,1,{0,60,0},{0,0,0},{256,160,256},0,{0,0}};
    stats=ek_scene3d_render(r,(const uint8_t*)&s,dst,280,0,64,280,288,NULL,NULL);assert(stats.status==1);
    unsigned raised=0;for(unsigned i=64*280;i<352*280;i++)raised+=dst[i]==s.materials[1].rgb565;assert(raised>200);
    ek_scene3d_destroy(r);free(memory);puts("Native scene3D PASS: bounds, 144 clipped poses, occlusion order, cooperative deadline and quota preserve completed frame");
}
