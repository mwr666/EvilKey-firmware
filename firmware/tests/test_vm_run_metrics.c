/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "ek_vm.h"
#include "wasm3/m3_env.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
static unsigned calls,last_token,last_gas;
static unsigned profiles;static uint64_t profile_clock;
static uint64_t clock_profile(void *u){return ++profile_clock;}
static void execution_profile(void *u,uint32_t guest,uint32_t output){
    assert(guest==1&&output==1&&calls==profiles+1);++profiles;
}
static void rect(void *u,int32_t x,int32_t y,int32_t w,int32_t h,uint16_t c){}
static void present(void *u,int32_t x,int32_t y,int32_t w,int32_t h){}
static void blit(void *u,int32_t x,int32_t y,const EkAsset *a){}
static void text(void *u,int32_t x,int32_t y,uint32_t s,uint16_t c,const uint8_t *p,uint32_t n){}
static int save(void *u,const uint8_t *p,uint32_t n){return 1;}
static void measure(void *u,uint32_t token,uint32_t gas,uint32_t memory){
    ++calls;last_token=token;last_gas=gas;assert(memory==65536);assert(gas<1000);
}
int main(int argc,char **argv){
    assert(argc==7);
    for(unsigned mode=0;mode<6;mode++){
        FILE *f=fopen(argv[mode+1],"rb");assert(f);fseek(f,0,SEEK_END);size_t n=ftell(f);rewind(f);
        uint8_t *bytes=malloc(n);assert(fread(bytes,1,n,f)==n);fclose(f);
        EkVm vm;EkVmHost host={0};host.rect=rect;host.present=present;host.blit=blit;host.text=text;host.save=save;host.abi_version=5;host.measurement=measure;
        assert(ek_vm_open(&vm,bytes,n,host));free(bytes);EvilKeyAppInput input={0};
        vm.host.clock=clock_profile;vm.host.execution_profile=execution_profile;
        calls=profiles=0;profile_clock=0;assert(ek_vm_init(&vm,&input));
        for(unsigned i=0;i<3;i++){
            assert(ek_vm_step(&vm,&input));assert(vm.error[0]==0);
            assert(vm.last_call_gas==m3_GetResourceUsage(vm.runtime,c_m3Limit_GasUnits));
            if(mode==0)assert(last_token==0x21000001);
            else if(mode==5)assert(last_token==0);
            else assert(last_token==UINT32_MAX);
        }
        assert(calls==4&&profiles==4&&last_gas>0);IM3Function probe;assert(!m3_FindFunctionIn(&probe,vm.module,"probe_steps"));
        assert(!m3_Call(probe,0,NULL));uint32_t steps;const void *out[]={&steps};assert(!m3_GetResults(probe,1,out));assert(steps==3);
        ek_vm_close(&vm);
    }
    puts("VM RUN METRICS PASS:valid/absent/wrong type/trap/gas/invalid token exports;original gas restored and gameplay continues");
}
