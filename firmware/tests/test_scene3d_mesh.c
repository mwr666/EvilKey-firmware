/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "ek_scene3d.h"
#include "ek_render_parallel.h"
#include "ek_package.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
static uint64_t now;
/* Force a deadline independently of optimization-dependent poll counts. */
static uint64_t clock_tick(void *u){(void)u;return __atomic_add_fetch(&now,10000,__ATOMIC_RELAXED);}
static void put16(uint8_t *p,unsigned n){p[0]=n;p[1]=n>>8;}
int main(int argc,char **argv){
 assert(argc==3);FILE *file=fopen(argv[1],"rb");assert(file);uint8_t data[65536];size_t n=fread(data,1,sizeof data,file);fclose(file);
 EkMeshInfo mesh;assert(ek_mesh_validate(data,n,&mesh));
 for(size_t length=0;length<n;length++)assert(!ek_mesh_validate(data,length,&mesh));
 uint8_t bad[65536];memcpy(bad,data,n);bad[0]^=1;assert(!ek_mesh_validate(bad,n,&mesh));
 memcpy(bad,data,n);put16(bad+20,16385);assert(!ek_mesh_validate(bad,n,&mesh));
 memcpy(bad,data,n);put16(bad+20+mesh.vertices*6,mesh.vertices);assert(!ek_mesh_validate(bad,n,&mesh));
 memcpy(bad,data,n);bad[20+mesh.vertices*6+6]=8;assert(!ek_mesh_validate(bad,n,&mesh));
 memcpy(bad,data,n);bad[14]=1;assert(!ek_mesh_validate(bad,n,&mesh));
 EkAssets assets={0};assets.count=1;assets.items[0]=(EkAsset){.id=23,.flags=2,.rgb565=data,.length=n,.mesh_vertices=mesh.vertices,.mesh_triangles=mesh.triangles};
 EvilKey3DScene scene={0};scene.magic=EVILKEY_3D_MAGIC;scene.version=2;scene.object_count=1;scene.material_count=8;scene.background=0x0843;
 scene.camera=(EvilKey3DCamera){{0,640,-1536},{0,0,0},45,1,2048,0};
 for(unsigned i=0;i<8;i++)scene.materials[i]=(EvilKey3DMaterial){(uint16_t)(0x47d8+i*1234),i==3,0};
 scene.objects[0]=(EvilKey3DObject){.model=0x8000|23,.material=0,.scale={768,768,768},.reserved2={0x7654321,0}};
 assert(ek_scene3d_validate_assets((void*)&scene,sizeof scene,&assets));assert(!ek_scene3d_validate((void*)&scene,sizeof scene));
 scene.version=1;assert(!ek_scene3d_validate_assets((void*)&scene,sizeof scene,&assets));scene.version=2;
 scene.objects[0].model++;assert(!ek_scene3d_validate_assets((void*)&scene,sizeof scene,&assets));scene.objects[0].model--;
 scene.objects[0].reserved2[0]|=0x80000000u;assert(!ek_scene3d_validate_assets((void*)&scene,sizeof scene,&assets));scene.objects[0].reserved2[0]&=0x0fffffff;
 scene.material_count=7;assert(!ek_scene3d_validate_assets((void*)&scene,sizeof scene,&assets));scene.material_count=8;
 scene.object_count=EVILKEY_3D_MAX_TRIANGLES/mesh.triangles+1;assert(scene.object_count<=96);
 for(unsigned i=1;i<scene.object_count;i++)scene.objects[i]=scene.objects[0];assert(!ek_scene3d_validate_assets((void*)&scene,sizeof scene,&assets));
 scene.object_count=1;memset(scene.objects+1,0,95*sizeof(scene.objects[0]));
 uint16_t *serial=calloc(280*456+2,2),*parallel=calloc(280*456+2,2);assert(serial&&parallel);serial[0]=parallel[0]=serial[280*456+1]=parallel[280*456+1]=0xbeef;
 EkScene3D *a=ek_scene3d_create(),*b=ek_scene3d_create();assert(a&&b);ek_scene3d_set_assets(a,&assets);ek_scene3d_set_assets(b,&assets);ek_render_workers_start();assert(ek_render_workers_ready());
 unsigned pairs=0;
 for(unsigned pose=0;pose<72;pose++){
  scene.objects[0].rotation[1]=(int16_t)(pose*500-18000);scene.objects[0].rotation[0]=(int16_t)(pose%9*1000-4000);
  scene.objects[0].position[2]=pose<48?0:-1400;scene.camera.projection=pose&1;
  ek_render_parallel_enable(false);EkSceneStats x=ek_scene3d_render(a,(void*)&scene,serial+1,280,0,64,280,288,NULL,NULL);
  ek_render_parallel_enable(true);EkSceneStats y=ek_scene3d_render(b,(void*)&scene,parallel+1,280,0,64,280,288,NULL,NULL);
  assert(x.status==1&&y.status==x.status&&x.triangles==mesh.triangles&&y.triangles==x.triangles&&y.pixel_tests==x.pixel_tests);
  assert(!memcmp(serial,parallel,(280*456+2)*2));assert(serial[0]==0xbeef&&serial[280*456+1]==0xbeef);pairs++;
 }
 uint16_t *snapshot=malloc(280*456*2);memcpy(snapshot,parallel+1,280*456*2);now=0;
 EkSceneStats fail=ek_scene3d_render(b,(void*)&scene,parallel+1,280,0,64,280,288,clock_tick,NULL);assert(fail.status==2&&!memcmp(snapshot,parallel+1,280*456*2));
 /* Aggregate work remains global across repeated instances/chunks. */
 uint8_t dense[20+24+1280*8]={0};memcpy(dense,"EKMESH1\0",8);put16(dense+8,1);put16(dense+10,4);put16(dense+12,1280);unsigned dn=sizeof dense;dense[16]=dn;dense[17]=dn>>8;
 int16_t points[12]={-16384,-16384,0,16384,-16384,0,16384,16384,0,-16384,16384,0};memcpy(dense+20,points,sizeof points);
 for(unsigned i=0;i<1280;i++){uint8_t *t=dense+44+i*8;put16(t,0);put16(t+2,1);put16(t+4,2);}
 EkMeshInfo dense_info;assert(ek_mesh_validate(dense,sizeof dense,&dense_info));assets.items[0].rgb565=dense;assets.items[0].length=sizeof dense;assets.items[0].mesh_vertices=4;assets.items[0].mesh_triangles=1280;
 scene.object_count=1;scene.camera.projection=0;scene.objects[0].rotation[0]=scene.objects[0].rotation[1]=0;scene.objects[0].position[2]=0;scene.objects[0].scale[0]=scene.objects[0].scale[1]=scene.objects[0].scale[2]=8192;
 fail=ek_scene3d_render(b,(void*)&scene,parallel+1,280,0,64,280,288,NULL,NULL);assert(fail.status==3&&fail.pixel_tests<=300000&&!memcmp(snapshot,parallel+1,280*456*2));
 file=fopen(argv[2],"rb");assert(file);uint8_t header[320];assert(fread(header,1,320,file)==320);fseek(file,0,SEEK_END);long total=ftell(file);fclose(file);EkPackageInfo info;
 assert(header[14]==3&&ek_package_parse(header,320,total,&info));header[14]=4;assert(!ek_package_parse(header,320,total,&info));header[14]=1;header[12]=4;assert(!ek_package_parse(header,320,total,&info));header[14]=0;assert(ek_package_parse(header,320,total,&info));
 printf("MESH PASS %u vertices/%u triangles; %zu truncated inputs; %u exact serial/helper clipped poses; unknown IDs/materials/version/quota; timeout/work rollback; feature ABI4/5\n",mesh.vertices,mesh.triangles,n,pairs);
 ek_scene3d_destroy(a);ek_scene3d_destroy(b);free(serial);free(parallel);free(snapshot);return 0;
}
