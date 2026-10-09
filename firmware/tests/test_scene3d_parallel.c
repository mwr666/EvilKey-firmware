/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "ek_scene3d.h"
#include "ek_render_parallel.h"
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
static uint64_t tick(void *user){return __atomic_add_fetch((uint64_t*)user,1000,__ATOMIC_RELAXED);}
typedef struct {uint64_t now;unsigned target,calls[2];} CoreClock;
static uint64_t core_tick(void *user){
    CoreClock *c=user;unsigned core=ek_render_core_id();__atomic_fetch_add(&c->calls[core],1,__ATOMIC_RELAXED);
    return __atomic_add_fetch(&c->now,core==c->target?1000:0,__ATOMIC_RELAXED);
}
int main(void){
    ek_render_workers_start();assert(ek_render_workers_ready());
    EkScene3D *serial=ek_scene3d_create(),*dual=ek_scene3d_create();assert(serial&&dual);
    uint16_t *a=malloc(280*456*2),*b=malloc(280*456*2);assert(a&&b);
    EvilKey3DScene s={0};s.magic=EVILKEY_3D_MAGIC;s.version=1;s.material_count=2;s.object_count=2;
    s.background=0x0842;s.camera=(EvilKey3DCamera){{0,2048,1536},{0,0,0},50,0,2560,0};
    s.materials[0]=(EvilKey3DMaterial){0x47d8,0,0};s.materials[1]=(EvilKey3DMaterial){0xf277,1,0};
    s.objects[0]=(EvilKey3DObject){1,0,{0,0,0},{0,0,0},{512,512,512},0,{0,0}};s.objects[1]=s.objects[0];s.objects[1].material=1;
    EkRenderWorkerStats before,after;ek_render_worker_stats(&before);
    for(unsigned pose=0;pose<480;pose++){
        s.camera.projection=pose&1;s.objects[0].model=1+(pose%4);s.objects[1].model=s.objects[0].model;
        s.objects[0].rotation[0]=(int16_t)(pose%36*500-9000);s.objects[0].rotation[1]=(int16_t)(pose%36*400);s.objects[1].rotation[0]=s.objects[0].rotation[0];s.objects[1].rotation[1]=s.objects[0].rotation[1];
        s.objects[0].position[1]=s.objects[1].position[1]=pose%36>20?2000:0;
        unsigned w=pose%3?280:126,h=pose%5?288:2,x=(280-w)/2,y=64;
        memset(a,0xcd,280*456*2);memset(b,0xcd,280*456*2);
        ek_render_parallel_enable(false);EkSceneStats one=ek_scene3d_render(serial,(uint8_t*)&s,a,280,x,y,w,h,NULL,NULL);
        ek_render_parallel_enable(true);EkSceneStats two=ek_scene3d_render(dual,(uint8_t*)&s,b,280,x,y,w,h,NULL,NULL);
        assert(one.status==1&&two.status==1&&one.triangles==two.triangles&&one.pixel_tests==two.pixel_tests);assert(!memcmp(a,b,280*456*2));
    }
    ek_render_worker_stats(&after);assert(after.jobs[1]>before.jobs[1]); /* RED: native never dispatches yet. */
    /* An abort in either band must join and repeat the previous committed image. */
    uint16_t *saved=malloc(280*456*2);memcpy(saved,b,280*456*2);uint64_t now=0;
    EkSceneStats st=ek_scene3d_render(dual,(uint8_t*)&s,b,280,0,64,280,288,tick,&now);assert(st.status==2&&st.pixel_tests<=300000);assert(!memcmp(saved,b,280*456*2));
    for(unsigned core=0;core<2;core++){
        CoreClock c={0};c.target=core;
        st=ek_scene3d_render(dual,(uint8_t*)&s,b,280,0,64,280,288,core_tick,&c);
        assert(st.status==2&&c.calls[core]>0&&!memcmp(saved,b,280*456*2));
        EkSceneProfile p=ek_scene3d_profile(dual);
        assert(p.clear_us+p.setup_us+p.geometry_us+p.reconstruct_us==st.elapsed_us);
        assert(p.raster_us<=p.geometry_us&&p.clock_calls==c.calls[0]+c.calls[1]);
    }
    s.object_count=96;for(unsigned i=0;i<96;i++){s.objects[i]=s.objects[0];s.objects[i].scale[0]=s.objects[i].scale[1]=s.objects[i].scale[2]=2048;}
    st=ek_scene3d_render(dual,(uint8_t*)&s,b,280,0,64,280,288,NULL,NULL);assert(st.status==3&&st.pixel_tests<=300000);assert(!memcmp(saved,b,280*456*2));
    ek_scene3d_destroy(serial);ek_scene3d_destroy(dual);free(a);free(b);free(saved);
    puts("Native multicore PASS: 480 exact frames, helper used, shared quota and timeout rollback");return 0;
}
