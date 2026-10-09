/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "ek_scene3d.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
typedef struct { uint64_t value; unsigned step,calls; } Clock;
static uint64_t tick(void *p){Clock *c=p;++c->calls;return c->value+=c->step;}
static void check(EkScene3D *r,EkSceneStats s,Clock c){
    EkSceneProfile p=ek_scene3d_profile(r);
    assert(!memcmp(&s,&p.stats,sizeof s));
    assert(p.clear_us+p.setup_us+p.geometry_us+p.reconstruct_us==s.elapsed_us);
    assert(p.raster_us<=p.geometry_us);
    assert(p.clock_calls==c.calls&&p.max_clock_gap_us==c.step);
}
int main(void){
    _Static_assert(sizeof(EkSceneProfile)==44,"fixed native diagnostic size");
    EkScene3D *r=ek_scene3d_create();assert(r);
    assert(!ek_scene3d_profile(r).stats.status);
    assert(!ek_scene3d_profile(NULL).stats.status);
    uint16_t *out=calloc(280*456,2),*saved=malloc(280*456*2);assert(out&&saved);
    EvilKey3DScene s={0};s.magic=EVILKEY_3D_MAGIC;s.version=1;s.object_count=1;s.material_count=1;
    s.camera=(EvilKey3DCamera){{0,2048,1536},{0,0,0},50,0,2560,0};
    s.materials[0]=(EvilKey3DMaterial){0x47d8,0,0};
    s.objects[0]=(EvilKey3DObject){1,0,{0,0,0},{0,0,0},{512,512,512},0,{0,0}};
    Clock c={0,1,0};
    EkSceneStats st=ek_scene3d_render(r,(const uint8_t*)&s,out,280,0,64,280,288,tick,&c);
    assert(st.status==EVILKEY_3D_OK);check(r,st,c);
    EkSceneProfile p=ek_scene3d_profile(r);assert(p.clear_us&&p.setup_us&&p.geometry_us&&p.raster_us&&p.reconstruct_us);
    memcpy(saved,out,280*456*2);
    c=(Clock){0,500,0};st=ek_scene3d_render(r,(const uint8_t*)&s,out,280,0,64,280,288,tick,&c);
    assert(st.status==EVILKEY_3D_TIMEOUT);check(r,st,c);assert(!memcmp(out,saved,280*456*2));
    st=ek_scene3d_render(r,(const uint8_t*)&s,out,280,0,64,280,288,NULL,NULL);
    p=ek_scene3d_profile(r);assert(st.status==EVILKEY_3D_OK&&p.stats.status==st.status);
    assert(!p.clear_us&&!p.setup_us&&!p.geometry_us&&!p.raster_us&&!p.reconstruct_us&&!p.clock_calls&&!p.max_clock_gap_us);
    s.object_count=40;for(unsigned i=0;i<40;i++)s.objects[i]=(EvilKey3DObject){.model=3,.scale={8192,1,8192},.position={0,(int16_t)i,0}};
    c=(Clock){0,1,0};st=ek_scene3d_render(r,(const uint8_t*)&s,out,280,0,64,280,288,tick,&c);
    assert(st.status==EVILKEY_3D_WORK_LIMIT);check(r,st,c);assert(!memcmp(out,saved,280*456*2));
    ek_scene3d_destroy(r);free(out);free(saved);
    puts("PASS native profile: partitioned elapsed, raster subset, clock accounting, timeout/work rollback, NULL clock/context");
}
