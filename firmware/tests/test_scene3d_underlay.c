/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "ek_scene3d.h"
#include "ek_render_parallel.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
extern void ek_scene3d_test_fail_cache(unsigned);
extern unsigned ek_scene3d_test_live_contexts(void);
static uint64_t tick;
static uint64_t clock_fast(void *u){(void)u;return __atomic_add_fetch(&tick,10000,__ATOMIC_RELAXED);}
enum {N=280*456};
static void fill(uint16_t *p,unsigned seed){for(unsigned i=0;i<N;i++)p[i]=(uint16_t)(0x2000+(i+seed)%0x1000);}
int main(void){
 ek_scene3d_test_fail_cache(1);assert(!ek_scene3d_create());assert(!ek_scene3d_test_live_contexts());ek_scene3d_test_fail_cache(0);
 EvilKey3DScene s={0};s.magic=EVILKEY_3D_MAGIC;s.version=2;s.object_count=1;s.material_count=1;s.background=0x1357;
 s.camera=(EvilKey3DCamera){{0,640,-1536},{0,0,0},45,1,2048,0};s.materials[0].flags=1;
 s.objects[0]=(EvilKey3DObject){.model=1,.scale={384,384,384}};
 s.flags=2;assert(!ek_scene3d_validate((void*)&s,sizeof s));s.flags=1;s.version=1;assert(!ek_scene3d_validate((void*)&s,sizeof s));s.version=2;assert(ek_scene3d_validate((void*)&s,sizeof s));
 uint16_t *opaque=malloc(N*2),*under=malloc(N*2),*dst=malloc(N*2),*expected=malloc(N*2);assert(opaque&&under&&dst&&expected);
 for(unsigned parallel=0;parallel<2;parallel++){
  ek_render_parallel_enable(parallel);EkScene3D *r=ek_scene3d_create();assert(r);
  fill(opaque,0);s.flags=0;assert(ek_scene3d_render(r,(void*)&s,opaque,280,0,64,280,288,NULL,NULL).status==1);
  unsigned black=0,clear=0;
  for(unsigned seed=1;seed<4;seed++){
   fill(under,seed*137);memcpy(dst,under,N*2);memcpy(expected,under,N*2);
   for(unsigned y=64;y<352;y++)for(unsigned x=0;x<280;x++){
    unsigned i=y*280+x;if(opaque[i]!=s.background){assert(opaque[i]==0);expected[i]=0;black++;}else clear++;
   }
   s.flags=1;assert(ek_scene3d_render(r,(void*)&s,dst,280,0,64,280,288,NULL,NULL).status==1);assert(!memcmp(dst,expected,N*2));
   /* Failed opaque request must reconstruct the committed transparent scene. */
   fill(dst,seed*137);s.flags=0;tick=0;assert(ek_scene3d_render(r,(void*)&s,dst,280,0,64,280,288,clock_fast,NULL).status==2);assert(!memcmp(dst,expected,N*2));
  }
  assert(black&&clear);
  s.flags=0;fill(dst,7);assert(ek_scene3d_render(r,(void*)&s,dst,280,0,64,280,288,NULL,NULL).status==1);memcpy(expected,dst,N*2);
  fill(dst,7);s.flags=1;tick=0;assert(ek_scene3d_render(r,(void*)&s,dst,280,0,64,280,288,clock_fast,NULL).status==2);assert(!memcmp(dst,expected,N*2));
  ek_scene3d_destroy(r);
  r=ek_scene3d_create();assert(r);fill(dst,11);memcpy(expected,dst,N*2);s.flags=1;tick=0;
  assert(ek_scene3d_render(r,(void*)&s,dst,280,0,64,280,288,clock_fast,NULL).status==2);assert(!memcmp(dst,expected,N*2));ek_scene3d_destroy(r);
 }
 assert(!ek_scene3d_test_live_contexts());free(opaque);free(under);free(dst);free(expected);
 puts("UNDERLAY PASS serial/helper patterned background, black geometry, invalid flags, cached mode rollback, first timeout, cache allocation failure cleanup");
}
