/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "ek_scene3d.h"
#include "ek_render_parallel.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
extern EkScene3D *baseline_create(void);
extern void baseline_destroy(EkScene3D *);
extern void baseline_assets(EkScene3D *,const EkAssets *);
extern EkSceneStats baseline_render(EkScene3D *,const uint8_t *,uint16_t *,unsigned,unsigned,unsigned,unsigned,unsigned,EkSceneClock,void *);
extern void ek_scene3d_test_cache_stats(unsigned *,unsigned *);
extern void ek_scene3d_test_cache_wrap(EkScene3D *);
extern size_t ek_scene3d_test_context_size(void);
static void put16(uint8_t *p,unsigned n){p[0]=n;p[1]=n>>8;}
static unsigned pairs;
static void compare(EkScene3D *a,EkScene3D *b,EvilKey3DScene *scene,uint16_t *old,uint16_t *fresh){
    for(unsigned parallel=0;parallel<2;parallel++){
        ek_render_parallel_enable(parallel!=0);
        EkSceneStats x=baseline_render(a,(void*)scene,old+1,280,0,64,280,288,NULL,NULL);
        EkSceneStats y=ek_scene3d_render(b,(void*)scene,fresh+1,280,0,64,280,288,NULL,NULL);
        assert(x.status==1&&y.status==x.status&&x.triangles==y.triangles&&x.pixel_tests==y.pixel_tests);
        assert(!memcmp(old,fresh,(280*456+2)*2));assert(old[0]==0xbeef&&old[280*456+1]==0xbeef);pairs++;
    }
}
int main(int argc,char **argv){
    assert(argc==3);uint8_t data[65536];
    EkScene3D *a=baseline_create(),*b=ek_scene3d_create();assert(a&&b);
    assert(ek_scene3d_test_context_size()<=192*1024);
    uint16_t *old=calloc(280*456+2,2),*fresh=calloc(280*456+2,2);assert(old&&fresh);
    old[0]=fresh[0]=old[280*456+1]=fresh[280*456+1]=0xbeef;
    EkAssets assets={0};assets.count=1;baseline_assets(a,&assets);ek_scene3d_set_assets(b,&assets);
    EvilKey3DScene scene={0};scene.magic=EVILKEY_3D_MAGIC;scene.version=2;scene.object_count=1;scene.material_count=8;
    scene.camera=(EvilKey3DCamera){{0,640,-1536},{0,0,0},45,1,2048,0};
    for(unsigned i=0;i<8;i++)scene.materials[i]=(EvilKey3DMaterial){(uint16_t)(0x47d8+i*1234),i&1,0};
    scene.objects[0]=(EvilKey3DObject){.model=0x8000|23,.scale={768,512,1024},.reserved2={0x7654321,0}};
    ek_render_workers_start();assert(ek_render_workers_ready());
    for(unsigned model=0;model<2;model++){
        FILE *f=fopen(argv[1+model],"rb");assert(f);size_t n=fread(data,1,sizeof data,f);fclose(f);
        EkMeshInfo info;assert(ek_mesh_validate(data,n,&info));
        assets.items[0]=(EkAsset){.id=23,.flags=2,.rgb565=data,.length=n,.mesh_vertices=info.vertices,.mesh_triangles=info.triangles};
        unsigned hits,misses;ek_scene3d_test_cache_stats(&hits,&misses);
        ek_render_parallel_enable(false);
        assert(ek_scene3d_render(b,(void*)&scene,fresh+1,280,0,64,280,288,NULL,NULL).status==1);
        ek_scene3d_test_cache_stats(&hits,&misses);
        assert(misses>=info.vertices&&hits>0&&hits+misses==3u*info.triangles);
        printf("CACHE TRACE model%u hits=%u misses=%u previous_transforms=%u\n",model,hits,misses,3u*info.triangles);
        for(unsigned pose=0;pose<72;pose++){
            scene.objects[0].rotation[1]=pose*500-18000;scene.objects[0].rotation[0]=pose%9*1000-4000;
            scene.objects[0].position[2]=pose<48?0:-1400;scene.camera.projection=pose&1;
            if(pose==36)ek_scene3d_test_cache_wrap(b);
            compare(a,b,&scene,old,fresh);
        }
    }
    /* Independent1024-vertex mesh: corners0/64 collide in the same triangle.
     * Store each corner value immediately, not a pointer overwritten later. */
    memset(data,0,sizeof data);memcpy(data,"EKMESH1\0",8);put16(data+8,1);put16(data+10,1024);put16(data+12,96);
    unsigned n=20+1024*6+96*8;data[16]=n;data[17]=n>>8;
    for(unsigned i=0;i<1024;i++){
        put16(data+20+i*6,(i%32)*256-4096);put16(data+22+i*6,(i/32)*256-4096);put16(data+24+i*6,(i&3)*128);
    }
    for(unsigned i=0;i<96;i++){
        uint8_t *t=data+20+1024*6+i*8;put16(t,i*37%1024);put16(t+2,(i*37+33)%1024);put16(t+4,(i*37+64)%1024);t[6]=i%8;
    }
    EkMeshInfo info;assert(ek_mesh_validate(data,n,&info));
    assets.items[0]=(EkAsset){.id=23,.flags=2,.rgb565=data,.length=n,.mesh_vertices=1024,.mesh_triangles=96};
    scene.object_count=2;scene.objects[1]=scene.objects[0];
    scene.objects[1].position[0]=256;scene.objects[1].rotation[2]=1000;scene.objects[1].scale[1]=1024;
    for(unsigned pose=0;pose<24;pose++){
        scene.objects[0].position[2]=scene.objects[1].position[2]=0;scene.objects[0].rotation[1]=pose*500;
        scene.objects[1].rotation[1]=-pose*500;scene.camera.projection=pose&1;scene.camera.target[0]=pose*16;
        if(pose%3==0)ek_scene3d_test_cache_wrap(b);
        compare(a,b,&scene,old,fresh);
    }
    printf("MESH CACHE PASS %u old/new serial/helper exact image+quota pairs;32slots;1024vertices; collisions/instance/camera/wrap; context=%zu\n",pairs,ek_scene3d_test_context_size());
    baseline_destroy(a);ek_scene3d_destroy(b);free(old);free(fresh);return 0;
}
