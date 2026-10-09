/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "../EvilKeyV1/src/apps/ek_scene3d.c"
#include <assert.h>
#include <stdio.h>
typedef struct {unsigned calls,trip;uint64_t now;SharedWork *cancel;} Clock;
static uint64_t clock_read(void *user){
    Clock *c=user;unsigned n=__atomic_add_fetch(&c->calls,1,__ATOMIC_RELAXED);
    if(c->cancel&&n==1)__atomic_store_n(&c->cancel->status,EVILKEY_3D_TIMEOUT,__ATOMIC_RELEASE);
    return n>=c->trip&&c->trip?EK_SCENE_BUDGET_US:c->now;
}
static void rows(unsigned trip,int cancel){
    uint32_t pixels[32*64]={0};EkSceneProfile p={0};SharedWork work={0,EVILKEY_3D_OK};
    Clock c={0,trip,0,cancel?&work:NULL};Frame f={0};
    f.rw=32;f.rh=64;f.row_step=1;f.pixels=pixels;f.profile=&p;
    f.stats.status=EVILKEY_3D_OK;f.clock=clock_read;f.clock_user=&c;f.shared=&work;
    raster_pixels(&f,(P){0,0,1000},(P){0,64,1000},(P){32,64,1000},0xf800);
    if(cancel){assert(c.calls==1&&f.stats.status==EVILKEY_3D_TIMEOUT);assert(pixels[32]==0);}
    else if(trip){assert(c.calls==2&&f.stats.status==EVILKEY_3D_TIMEOUT);assert(pixels[7*32]!=0&&pixels[8*32]==0);}
    else {printf("64 raster rows: %u clock reads\n",c.calls);fflush(stdout);assert(c.calls==8&&f.stats.status==EVILKEY_3D_OK);}
    assert(p.clock_calls==c.calls);
}
static void late_commit(void){
    ek_render_workers_start();ek_render_parallel_enable(true);
    EvilKey3DScene s={0};s.magic=EVILKEY_3D_MAGIC;s.version=1;s.material_count=1;s.object_count=1;
    s.background=0x0842;s.camera=(EvilKey3DCamera){{0,2048,1536},{0,0,0},50,0,2560,0};
    s.materials[0]=(EvilKey3DMaterial){0x47d8,0,0};
    s.objects[0]=(EvilKey3DObject){.model=1,.scale={512,512,512}};
    EkScene3D *r=ek_scene3d_create();uint16_t *out=calloc(280*456,2),*saved=malloc(280*456*2);assert(r&&out&&saved);
    Clock c={0};EkSceneStats a=ek_scene3d_render(r,(uint8_t*)&s,out,280,0,64,280,288,clock_read,&c);assert(a.status==EVILKEY_3D_OK);
    memcpy(saved,out,280*456*2);unsigned total=c.calls;
    /* The final pre-commit check precedes geometry/copy endpoints by two reads.
     * Deterministic zero-time callbacks let this inject the deadline there. */
    c=(Clock){0,total-2,0,NULL};s.background=0x001f;
    EkSceneStats b=ek_scene3d_render(r,(uint8_t*)&s,out,280,0,64,280,288,clock_read,&c);
    assert(b.status==EVILKEY_3D_TIMEOUT&&b.pixel_tests==a.pixel_tests);
    assert(!memcmp(saved,out,280*456*2));
    free(out);free(saved);ek_scene3d_destroy(r);
}
static void batch_timing(void){
    RasterPrimitive items[12];for(unsigned i=0;i<12;i++)items[i]=(RasterPrimitive){{0,10,1000},{0,12,1000},{8,12,1000},0xf800};
    RasterBatch batch={items,12};uint32_t pixels[8*8]={0};Clock c={0};Frame f={0};EkSceneProfile p={0};SharedWork work={0,EVILKEY_3D_OK};
    f.rw=f.rh=8;f.pixels=pixels;f.profile=&p;f.shared=&work;f.stats.status=EVILKEY_3D_OK;f.clock=clock_read;f.clock_user=&c;
    RasterJob job={&f,&batch,0,{0}};raster_band(&job);
    printf("12 no-row primitives: %u clock reads\n",c.calls);fflush(stdout);
    assert(c.calls==15&&job.profile.clock_calls==15&&job.profile.raster_us==0&&job.profile.stats.status==EVILKEY_3D_OK);
}
int main(int argc,char **argv){(void)argv;if(argc>1){batch_timing();return 0;}rows(0,0);rows(2,0);rows(0,1);batch_timing();late_commit();puts("PASS bounded row polling, shared cancellation and late pre-commit timeout rollback");return 0;}
