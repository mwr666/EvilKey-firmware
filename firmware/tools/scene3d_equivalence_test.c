/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Host exact-pixel regression oracle against the frozen accepted baseline. */
#include "ek_scene3d.h"
#include "ek_render_parallel.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
EkScene3D *baseline_create(void);
void baseline_destroy(EkScene3D *);
EkSceneStats baseline_render(EkScene3D *,const uint8_t *,uint16_t *,unsigned,unsigned,unsigned,unsigned,unsigned,EkSceneClock,void *);
static uint32_t seed=0x734;
static unsigned random_u(void){seed=seed*1664525u+1013904223u;return seed;}
static uint64_t fake;
static uint64_t clock_step(void *u){(void)u;return __atomic_add_fetch(&fake,250,__ATOMIC_RELAXED);}
static uint16_t a[280*456],b[280*456],saved[280*456];
int main(void){
 ek_render_workers_start();
 EkScene3D *old=baseline_create(),*now=ek_scene3d_create();assert(old&&now);
 unsigned checked=0;uint64_t before=0,after=0;double old_ms=0,new_ms=0;
 for(unsigned test=0;test<480;test++){
  EvilKey3DScene sc={0};sc.magic=EVILKEY_3D_MAGIC;sc.version=1;sc.object_count=24;sc.material_count=4;sc.background=0x0945;
  sc.camera=(EvilKey3DCamera){{1700,2500,1900},{0,0,0},50,(uint16_t)(test%2),1850,0};
  if(test%5==0)sc.camera=(EvilKey3DCamera){{256,512,1024},{0,0,0},65,(uint16_t)(test%2),1024,0};
  for(unsigned i=0;i<4;i++)sc.materials[i]=(EvilKey3DMaterial){(uint16_t)(0x3210+i*0x2222),(uint16_t)(i%2),0};
  for(unsigned i=0;i<sc.object_count;i++){
   EvilKey3DObject *o=sc.objects+i;o->model=1+random_u()%4;o->material=random_u()%4;
   for(unsigned k=0;k<3;k++){o->position[k]=(int)(random_u()%4001)-2000;o->rotation[k]=(int)(random_u()%36001)-18000;o->scale[k]=64+random_u()%1100;}
   if(test%7==0)for(unsigned k=0;k<3;k++)o->rotation[k]=0;
  }
  assert(ek_scene3d_validate((const uint8_t*)&sc,sizeof sc));
  for(unsigned i=0;i<280*456;i++)a[i]=b[i]=0xdead;
  unsigned w=(test%3)?280:140,h=(test%3)?288:160,x=0,y=64;
  clock_t t=clock();EkSceneStats r0=baseline_render(old,(const uint8_t*)&sc,a,280,x,y,w,h,NULL,NULL);old_ms+=(double)(clock()-t)*1000/CLOCKS_PER_SEC;
  t=clock();EkSceneStats r1=ek_scene3d_render(now,(const uint8_t*)&sc,b,280,x,y,w,h,NULL,NULL);new_ms+=(double)(clock()-t)*1000/CLOCKS_PER_SEC;
  assert(r0.status==1&&r1.status==1);assert(r0.triangles==r1.triangles);assert(r1.pixel_tests<=r0.pixel_tests);
  if(memcmp(a,b,sizeof a)){fprintf(stderr,"image mismatch case %u\n",test);return 1;}
  checked++;before+=r0.pixel_tests;after+=r1.pixel_tests;
 }
 EvilKey3DScene sc={0};sc.magic=EVILKEY_3D_MAGIC;sc.version=1;sc.object_count=1;sc.material_count=1;sc.background=0x0945;
 sc.camera=(EvilKey3DCamera){{1700,2500,1900},{0,0,0},50,0,1850,0};
 sc.materials[0]=(EvilKey3DMaterial){0xf800,1,0};sc.objects[0]=(EvilKey3DObject){.model=1,.scale={1000,1000,1000}};
 assert(ek_scene3d_render(now,(const uint8_t*)&sc,b,280,0,64,280,288,NULL,NULL).status==1);memcpy(saved,b,sizeof b);
 fake=0;EkSceneStats r=ek_scene3d_render(now,(const uint8_t*)&sc,b,280,0,64,280,288,clock_step,NULL);
 assert(r.status==EVILKEY_3D_TIMEOUT&&r.elapsed_us>=20000);assert(!memcmp(saved,b,sizeof b));
 sc.object_count=40;for(unsigned i=0;i<40;i++)sc.objects[i]=(EvilKey3DObject){.model=3,.scale={8192,1,8192},.position={0,(int16_t)i,0}};
 r=ek_scene3d_render(now,(const uint8_t*)&sc,b,280,0,64,280,288,NULL,NULL);
 assert(r.status==EVILKEY_3D_WORK_LIMIT&&r.pixel_tests<=300000);assert(!memcmp(saved,b,sizeof b));
 EkScene3D *fresh=ek_scene3d_create();fake=0;r=ek_scene3d_render(fresh,(const uint8_t*)&sc,b,280,0,64,280,288,clock_step,NULL);assert(r.status==EVILKEY_3D_TIMEOUT);
 for(unsigned y=64;y<352;y++)for(unsigned x=0;x<280;x++)assert(b[y*280+x]==sc.background);
 /* Packed transfer must work for 2-byte alignment, odd stride, tiny/max rows,
  * resizing, and failed frames whose dimensions differ from the last commit. */
 uint16_t *guard0=malloc((283*456+2)*2),*guard1=malloc((283*456+2)*2);
 assert(guard0&&guard1);unsigned boundaries=0;
 const unsigned widths[]={2,6,138,278},heights[]={2,10,318,320};
 memset(sc.objects,0,sizeof sc.objects);sc.object_count=1;sc.objects[0]=(EvilKey3DObject){.model=1,.scale={1000,1000,1000}};
 for(unsigned wi=0;wi<4;wi++)for(unsigned hi=0;hi<4;hi++){
  for(unsigned i=0;i<283*456+2;i++)guard0[i]=guard1[i]=0xbeef;
  unsigned w=widths[wi],h=heights[hi];sc.background=(uint16_t)(0x1234+boundaries*77);
  EkSceneStats x0=baseline_render(old,(const uint8_t*)&sc,guard0+1,283,1,3,w,h,NULL,NULL);
  EkSceneStats x1=ek_scene3d_render(now,(const uint8_t*)&sc,guard1+1,283,1,3,w,h,NULL,NULL);
  assert(x0.status==1&&x1.status==1&&!memcmp(guard0,guard1,(283*456+2)*2));
  fake=0;x1=ek_scene3d_render(now,(const uint8_t*)&sc,guard1+1,283,1,3,w,h,clock_step,NULL);
  if(x1.status==EVILKEY_3D_TIMEOUT)assert(!memcmp(guard0,guard1,(283*456+2)*2));
  assert(guard1[0]==0xbeef&&guard1[283*456+1]==0xbeef);boundaries++;
 }
 /* A size-change timeout must present the new background, not stale pixels. */
 fake=0;r=ek_scene3d_render(now,(const uint8_t*)&sc,guard1+1,283,1,3,140,160,clock_step,NULL);
 assert(r.status==EVILKEY_3D_TIMEOUT);
 for(unsigned y=3;y<163;y++)for(unsigned x=1;x<141;x++)assert(guard1[1+y*283+x]==sc.background);
 free(guard0);free(guard1);printf("PASS %u odd-stride/alignment/size boundary comparisons and resized timeout\n",boundaries);
 ek_scene3d_destroy(fresh);baseline_destroy(old);ek_scene3d_destroy(now);
 printf("PASS %u byte-identical scenes, all models/projections/clipping/depth/viewport guard; tests %llu -> %llu; host CPU %.3f -> %.3f ms (not device). Deadline/work rollback and first-failure background PASS.\n",checked,(unsigned long long)before,(unsigned long long)after,old_ms,new_ms);
 return 0;
}
