/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include <math.h>
static unsigned sin_calls,cos_calls;
static float counted_sinf(float x){__atomic_fetch_add(&sin_calls,1,__ATOMIC_RELAXED);return sinf(x);}
static float counted_cosf(float x){__atomic_fetch_add(&cos_calls,1,__ATOMIC_RELAXED);return cosf(x);}
#define sinf counted_sinf
#define cosf counted_cosf
#include "../EvilKeyV1/src/apps/ek_scene3d.c"
#undef sinf
#undef cosf
#include <assert.h>
#include <stdio.h>
int main(void){
    ek_render_workers_start();assert(ek_render_workers_ready());
    EvilKey3DScene s={0};s.magic=EVILKEY_3D_MAGIC;s.version=1;s.material_count=1;s.object_count=1;
    s.camera=(EvilKey3DCamera){{0,2048,1536},{0,0,0},50,0,2560,0};
    s.materials[0]=(EvilKey3DMaterial){0x47d8,0,0};
    s.objects[0]=(EvilKey3DObject){.model=1,.scale={512,512,512},.rotation={1000,2000,3000}};
    EkScene3D *r=ek_scene3d_create();uint16_t *out=calloc(280*456,2);assert(r&&out);
    EkSceneStats st=ek_scene3d_render(r,(uint8_t*)&s,out,280,0,64,280,288,NULL,NULL);
    assert(st.status==EVILKEY_3D_OK);
    printf("Rotated object sin/cos calls: %u/%u\n",sin_calls,cos_calls);fflush(stdout);
    assert(sin_calls==3&&cos_calls==3);
    /* Many small visible boxes force several joins/reuses without a work abort. */
    s.object_count=96;
    for(unsigned i=0;i<96;i++)s.objects[i]=(EvilKey3DObject){
        .model=EVILKEY_3D_BOX,.position={(int)(i%12)*128-704,0,(int)(i/12)*128-448},
        .scale={64,64,64},.rotation={1000,2000,3000}};
    uint16_t *reference=calloc(280*456,2);EkScene3D *serial=ek_scene3d_create();assert(reference&&serial);
    ek_render_parallel_enable(false);
    EkSceneStats one=ek_scene3d_render(serial,(uint8_t*)&s,reference,280,0,64,280,288,NULL,NULL);
    ek_render_parallel_enable(true);sin_calls=cos_calls=0;
    EkRenderWorkerStats before,after;ek_render_worker_stats(&before);
    st=ek_scene3d_render(r,(uint8_t*)&s,out,280,0,64,280,288,NULL,NULL);
    ek_render_worker_stats(&after);
    assert(one.status==EVILKEY_3D_OK&&st.status==EVILKEY_3D_OK);
    assert(st.triangles==1152&&one.triangles==st.triangles&&one.pixel_tests==st.pixel_tests);
    assert(!memcmp(reference,out,280*456*2));assert(sin_calls==288&&cos_calls==288);
    /* Clear and copy consume two helper jobs; >=4 proves multiple raster batches. */
    assert(after.jobs[1]-before.jobs[1]>=4);
    printf("Multi-batch helper jobs: %u, pixels: %u, context: %zu bytes\n",after.jobs[1]-before.jobs[1],st.pixel_tests,sizeof(*r));
    /* Defensive full-queue append must publish cancellation and preserve guards. */
    RasterPrimitive guarded[RASTER_BATCH_CAPACITY+1];memset(guarded,0xa5,sizeof(guarded));
    RasterPrimitive saved=guarded[RASTER_BATCH_CAPACITY];RasterBatch full={guarded,RASTER_BATCH_CAPACITY};
    Frame f={0};EkSceneProfile profile={0};SharedWork shared={0,EVILKEY_3D_OK};
    f.batch=&full;f.shared=&shared;f.profile=&profile;f.stats.status=EVILKEY_3D_OK;
    raster(&f,(P){0},(P){0},(P){0},0);
    assert(full.count==RASTER_BATCH_CAPACITY&&f.stats.status==EVILKEY_3D_WORK_LIMIT);
    assert(shared.status==EVILKEY_3D_WORK_LIMIT&&!memcmp(&saved,&guarded[RASTER_BATCH_CAPACITY],sizeof(saved)));
    free(reference);ek_scene3d_destroy(serial);
    free(out);ek_scene3d_destroy(r);
    puts("PASS parallel preparation once, multiple joined batches, exact pixels/totals and bounded append");return 0;
}
