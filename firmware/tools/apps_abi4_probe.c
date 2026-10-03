/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "../EvilKeyV1/src/apps/ek_vm.h"
#include "../EvilKeyV1/src/apps/ek_package.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { unsigned rects,presents,blits,crops,texts,saves; } Counters;
static void rect(void *u,int32_t x,int32_t y,int32_t w,int32_t h,uint16_t c) {
    (void)x;(void)y;(void)w;(void)h;(void)c;++((Counters *)u)->rects;
}
static void present(void *u,int32_t x,int32_t y,int32_t w,int32_t h) {
    (void)x;(void)y;(void)w;(void)h;++((Counters *)u)->presents;
}
static void blit(void *u,int32_t x,int32_t y,const EkAsset *asset) {
    (void)x;(void)y;if(asset->id==1)++((Counters *)u)->blits;
}
static void blit_region(void *u,int32_t x,int32_t y,uint32_t sx,uint32_t sy,
                        uint32_t w,uint32_t h,const EkAsset *asset) {
    (void)x;(void)y;
    if(asset->id==1 && sx==1 && sy==1 && w==1 && h==1)
        ++((Counters *)u)->crops;
}
static void text(void *u,int32_t x,int32_t y,uint32_t scale,uint16_t c,
                 const uint8_t *bytes,uint32_t length) {
    (void)x;(void)y;(void)scale;(void)c;
    if(length==2 && !memcmp(bytes,"V4",2)) ++((Counters *)u)->texts;
}
static int save(void *u,const uint8_t *bytes,uint32_t length) {
    if(length==4 && bytes[0]==4) ++((Counters *)u)->saves;
    return 1;
}
static uint8_t *file(const char *path,size_t *length) {
    FILE *f=fopen(path,"rb");if(!f || fseek(f,0,SEEK_END)) return NULL;
    long end=ftell(f);if(end<0 || fseek(f,0,SEEK_SET)) return NULL;
    uint8_t *data=(uint8_t *)malloc((size_t)end);
    if(!data || fread(data,1,(size_t)end,f)!=(size_t)end) return NULL;
    fclose(f);*length=(size_t)end;return data;
}
static int observed(EkVm *vm) {
    IM3Function f=NULL;int32_t value=0;
    const void *results[]={&value};
    return !m3_FindFunctionIn(&f,vm->module,"app_probe_input") &&
        !m3_Call(f,0,NULL) && !m3_GetResults(f,1,results) && value==1;
}
int main(int argc,char **argv) {
    if(argc!=3) return 2;
    size_t package_size, bad_size;
    uint8_t *package=file(argv[1],&package_size);
    uint8_t *bad=file(argv[2],&bad_size);
    if(!package || !bad || package_size<EK_PACKAGE_HEADER_SIZE) return 1;
    EkPackageInfo info;
    if(!ek_package_parse(package,EK_PACKAGE_HEADER_SIZE,package_size,&info) ||
       info.wasm_size+info.asset_size+EK_PACKAGE_PAYLOAD_OFFSET!=package_size ||
       info.asset_size<12) return 1;
    EkAssets assets;
    if(!ek_assets_parse(package+EK_PACKAGE_PAYLOAD_OFFSET+info.wasm_size,info.asset_size,&assets) ||
       assets.count!=1 || assets.items[0].id!=1) return 1;
    uint8_t *corrupt=(uint8_t *)malloc(info.asset_size);
    memcpy(corrupt,package+EK_PACKAGE_PAYLOAD_OFFSET+info.wasm_size,info.asset_size);
    corrupt[12+12]=0; /* corrupt exact asset pixel byte length */
    if(ek_assets_parse(corrupt,info.asset_size,&assets)) return 1;
    free(corrupt);
    if(ek_package_parse(package,EK_PACKAGE_HEADER_SIZE,package_size-1,&info)) return 1;
    uint8_t header[EK_PACKAGE_HEADER_SIZE];memcpy(header,package,EK_PACKAGE_HEADER_SIZE);header[12]=3;
    if(ek_package_parse(header,EK_PACKAGE_HEADER_SIZE,package_size,&info)) return 1;
    Counters counts={0};
    EkVmHost host={&counts,rect,present,blit,text,save,&assets};
    host.blit_region=blit_region;
    /* Reparse because malformed parser calls clear the table. */
    if(!ek_assets_parse(package+EK_PACKAGE_PAYLOAD_OFFSET+info.wasm_size,info.asset_size,&assets)) return 1;
    EkVm vm;
    if(!ek_vm_open(&vm,package+EK_PACKAGE_PAYLOAD_OFFSET,info.wasm_size,host)) {
        fprintf(stderr,"open: %s\n",ek_vm_error(&vm));return 1;
    }
    EvilKeyAppInput input={0};
    input.touch_count=2;input.touch[0].id=3;input.touch[1].id=7;
    input.accel_valid=1;input.accel_x_mg=-250;
    if(!ek_vm_init(&vm,&input) || !ek_vm_step(&vm,&input) || !observed(&vm) ||
       counts.rects!=1 || counts.presents!=2 || counts.blits!=1 ||
       counts.crops!=1 ||
       counts.texts!=1 || counts.saves!=1) {
        fprintf(stderr,"VM behavior: %s\n",ek_vm_error(&vm));return 1;
    }
    ek_vm_close(&vm);
    if(!ek_vm_open(&vm,bad,bad_size,host)) return 1;
    memset(&counts,0,sizeof(counts));
    if(!ek_vm_init(&vm,&input) || ek_vm_step(&vm,&input) ||
       counts.blits || counts.crops || counts.texts || counts.saves ||
       counts.presents!=1) {
        fprintf(stderr,"invalid command affected host\n");return 1;
    }
    ek_vm_close(&vm);
    free(package);free(bad);
    puts("ABI v4 package, assets, dual touch, IMU, graphics, save and atomic command validation OK");
    return 0;
}
