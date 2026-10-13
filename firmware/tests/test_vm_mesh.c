/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "ek_vm.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
static unsigned effects;
static void rect(void *u,int32_t x,int32_t y,int32_t w,int32_t h,uint16_t c){effects++;}
static void present(void *u,int32_t x,int32_t y,int32_t w,int32_t h){effects++;}
static void blit(void *u,int32_t x,int32_t y,const EkAsset *a){effects++;}
static void region(void *u,int32_t x,int32_t y,uint32_t sx,uint32_t sy,uint32_t w,uint32_t h,const EkAsset *a){effects++;}
static void text(void *u,int32_t x,int32_t y,uint32_t scale,uint16_t c,const uint8_t *ascii,uint32_t n){effects++;}
static int save(void *u,const uint8_t *data,uint32_t n){effects++;return 1;}
static EkSceneStats scene(void *u,const uint8_t *p,unsigned x,unsigned y,unsigned w,unsigned h){effects++;return (EkSceneStats){1,0,188,0};}
static unsigned load(const char *name,uint8_t *dst,unsigned capacity){FILE *f=fopen(name,"rb");assert(f);unsigned n=fread(dst,1,capacity,f);assert(fgetc(f)==EOF);fclose(f);return n;}
int main(int argc,char **argv){assert(argc==3);uint8_t mesh_data[65536],wasm[65536];unsigned n=load(argv[1],mesh_data,sizeof mesh_data),wn=load(argv[2],wasm,sizeof wasm);EkMeshInfo mesh;assert(ek_mesh_validate(mesh_data,n,&mesh));
 EkAssets assets={0};assets.count=1;assets.items[0]=(EkAsset){.id=23,.flags=2,.rgb565=mesh_data,.length=n,.mesh_vertices=mesh.vertices,.mesh_triangles=mesh.triangles};
 EkVmHost host={0};host.text=text;host.save=save;host.rect=rect;host.present=present;host.blit=blit;host.blit_region=region;host.scene3d=scene;host.assets=&assets;host.abi_version=5;
 EvilKeyAppInput input={0};input.accel_valid=1;
 for(unsigned fault=0;fault<=8;fault++){
  EkVm vm;if(!ek_vm_open(&vm,wasm,wn,host)){fprintf(stderr,"%s\n",ek_vm_error(&vm));abort();}assert(ek_vm_init(&vm,&input));
  IM3Function f;assert(!m3_FindFunction(&f,vm.runtime,"probe_fault_next"));for(unsigned i=0;i<fault;i++)assert(!m3_CallV(f));
  effects=0;int ok=ek_vm_step(&vm,&input);assert(fault?(!ok&&effects==0):(ok&&effects==3));ek_vm_close(&vm);
 }
 puts("VM MESH PASS valid custom scene and eight malformed model/version/material/bitmap/scene-flag command lists rejected before first callback");
}
