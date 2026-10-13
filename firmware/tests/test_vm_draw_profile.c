/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "ek_vm.c"
#include <assert.h>
#include <stdio.h>
static uint64_t tick;
static unsigned effects,profiles,clock_reads;
static void measurement_host(void *u,uint32_t token,uint32_t gas,uint32_t size){}
static uint32_t measured[4];
static uint64_t clock_now(void *u){++clock_reads;return tick;}
static void rect_draw(void *u,int32_t x,int32_t y,int32_t w,int32_t h,uint16_t c){tick+=11;++effects;}
static void present_draw(void *u,int32_t x,int32_t y,int32_t w,int32_t h){tick+=43;++effects;}
static void blit_draw(void *u,int32_t x,int32_t y,const EkAsset *a){tick+=a->flags?29:17;++effects;}
static void region_draw(void *u,int32_t x,int32_t y,uint32_t sx,uint32_t sy,uint32_t w,uint32_t h,const EkAsset *a){blit_draw(u,x,y,a);}
static void text_draw(void *u,int32_t x,int32_t y,uint32_t s,uint16_t c,const uint8_t *p,uint32_t n){tick+=37;++effects;}
static int save_draw(void *u,const uint8_t *p,uint32_t n){tick+=53;++effects;return 1;}
static void draw_profile(void *u,const uint32_t groups[4]){memcpy(measured,groups,sizeof measured);++profiles;}
static void put16(uint8_t *p,unsigned n){p[0]=n;p[1]=n>>8;}
static void put32(uint8_t *p,unsigned n){for(unsigned b=0;b<4;b++)p[b]=n>>(b*8);}
static void command(uint8_t *p,unsigned k,unsigned w,unsigned h,unsigned a,unsigned b){memset(p,0,20);put16(p,k);put16(p+8,w);put16(p+10,h);put32(p+12,a);put32(p+16,b);}
int main(int argc,char **argv){
 assert(argc==2);FILE *f=fopen(argv[1],"rb");assert(f);uint8_t bytes[65536];unsigned n=fread(bytes,1,sizeof bytes,f);fclose(f);
 EkAssets assets={0};assets.count=2;assets.items[0]=(EkAsset){.id=1,.flags=0,.width=4,.height=4};assets.items[1]=(EkAsset){.id=2,.flags=1,.width=4,.height=4};
 EkVmHost host={0};host.rect=rect_draw;host.present=present_draw;host.blit=blit_draw;host.blit_region=region_draw;host.text=text_draw;host.save=save_draw;host.assets=&assets;host.measurement=measurement_host;
 EkVm vm;assert(ek_vm_open(&vm,bytes,n,host));assert(vm.measurement_function);
 size_t size;uint8_t *memory=m3_GetMemory(vm.module,&size,0);assert(size>=1024);const unsigned off=512;uint8_t *out=memory+off;put32(out,8);memory[900]='A';
 command(out+4,EVILKEY_APP_RECT,4,4,0x1234,0);
 command(out+24,EVILKEY_APP_BLIT,0,0,1,0);
 command(out+44,EVILKEY_APP_BLIT_REGION,2,2,2,0);
 command(out+64,EVILKEY_APP_BLIT,0,0,2,0);
 command(out+84,EVILKEY_APP_BLIT_REGION,2,2,1,0);
 command(out+104,EVILKEY_APP_TEXT,1,0,900,1);
 command(out+124,EVILKEY_APP_PRESENT,4,4,0,0);
 command(out+144,EVILKEY_APP_SAVE,0,0,900,1);
 IM3Function measurement=vm.measurement_function;
 for(unsigned mode=0;mode<4;mode++){
  vm.host.clock=mode==1?NULL:clock_now;vm.host.execution_draw=mode==2?NULL:draw_profile;vm.measurement_function=mode==3?NULL:measurement;
  effects=profiles=0;tick=5000000000ULL;memset(measured,0,sizeof measured);
  assert(apply_output(&vm,off));assert(effects==8);assert(tick==5000000000ULL+11+17*2+29*2+37+43+53);
  assert(profiles==(mode==0));if(mode==0){assert(measured[0]==11&&measured[1]==34&&measured[2]==58&&measured[3]==37);}
 }
 vm.host.clock=clock_now;vm.host.execution_draw=draw_profile;vm.measurement_function=measurement;
 command(out+144,99,0,0,0,0);effects=profiles=0;uint32_t before_tick=vm.draw_profile_tick;assert(!apply_output(&vm,off));assert(!effects&&!profiles&&vm.draw_profile_tick==before_tick);
 command(out+144,EVILKEY_APP_SAVE,0,0,900,1);vm.error[0]=0;put32(out,1);effects=profiles=0;vm.draw_profile_tick=0;
 assert(apply_output(&vm,off));assert(effects==1&&profiles==1&&measured[0]==11&&!measured[1]&&!measured[2]&&!measured[3]);
 put32(out,8);effects=profiles=clock_reads=0;vm.draw_profile_tick=0;
 for(unsigned i=0;i<32;i++)assert(apply_output(&vm,off));
 assert(effects==256&&profiles==1&&vm.draw_profile_tick==32&&clock_reads==14);
 effects=profiles=0;vm.draw_profile_tick=UINT32_MAX;
 assert(apply_output(&vm,off));assert(vm.draw_profile_tick==0&&!profiles&&effects==8);
 assert(apply_output(&vm,off));assert(vm.draw_profile_tick==1&&profiles==1&&effects==16);
 ek_vm_close(&vm);puts("DRAW VM PASS sample32/wrap/invalidtick actual validated dispatch; independent clock and eight callback effects; rect/opaque/key/text exact, zero categories, SAVE/PRESENT excluded; missing clock/callback/export and invalid list protected");
}
