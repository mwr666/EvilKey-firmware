/* SPDX-License-Identifier: AGPL-3.0-or-later
 * EvilBlocks ABI v4 integration smoke test; no hardware or SD writes.
 */
#include "../EvilKeyV1/src/apps/ek_vm.h"
#include "../EvilKeyV1/src/apps/ek_package.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    unsigned rects,presents,saves,blits;
    uint8_t saved[4096];
    uint32_t saved_size;
} Screen;
static void rect(void *u,int32_t x,int32_t y,int32_t w,int32_t h,uint16_t c) {
    (void)x;(void)y;(void)w;(void)h;(void)c;++((Screen *)u)->rects;
}
static void present(void *u,int32_t x,int32_t y,int32_t w,int32_t h) {
    (void)x;(void)y;(void)w;(void)h;++((Screen *)u)->presents;
}
static void blit(void *u,int32_t x,int32_t y,const EkAsset *asset) {
    (void)x;(void)y;(void)asset;++((Screen *)u)->blits;
}
static void blit_region(void *u,int32_t x,int32_t y,uint32_t sx,uint32_t sy,
                        uint32_t w,uint32_t h,const EkAsset *asset) {
    (void)x;(void)y;(void)sx;(void)sy;(void)w;(void)h;(void)asset;
    ++((Screen *)u)->blits;
}
static void draw_text(void *u,int32_t x,int32_t y,uint32_t scale,uint16_t color,
                      const uint8_t *ascii,uint32_t length) {
    (void)u;(void)x;(void)y;(void)scale;(void)color;(void)ascii;(void)length;
}
static int save(void *u,const uint8_t *data,uint32_t length) {
    Screen *s=(Screen *)u;
    if(!length || length>sizeof(s->saved))return 0;
    memcpy(s->saved,data,length);s->saved_size=length;++s->saves;
    return 1;
}
static int exported_i32(EkVm *vm,const char *name,int32_t *out) {
    IM3Function f=NULL;const void *returns[]={out};
    return !m3_FindFunctionIn(&f,vm->module,name) &&
        !m3_Call(f,0,NULL) && !m3_GetResults(f,1,returns);
}
static int step(EkVm *vm,uint32_t now,int x,int y,int down) {
    EvilKeyAppInput input={0};
    input.now_ms=now;
    if(down) {
        input.touch_count=1;
        input.touch[0].x=(int16_t)x;
        input.touch[0].y=(int16_t)y;
        input.touch[0].id=2;
    }
    return ek_vm_step(vm,&input);
}
int main(int argc,char **argv) {
    if(argc!=2) return 2;
    FILE *f=fopen(argv[1],"rb");
    if(!f || fseek(f,0,SEEK_END)) return 1;
    long length=ftell(f);
    if(length<EK_PACKAGE_HEADER_SIZE || fseek(f,0,SEEK_SET)) return 1;
    uint8_t *bytes=(uint8_t *)malloc((size_t)length);
    if(!bytes || fread(bytes,1,(size_t)length,f)!=(size_t)length) return 1;
    fclose(f);
    EkPackageInfo info;
    if(!ek_package_parse(bytes,EK_PACKAGE_HEADER_SIZE,(size_t)length,&info) ||
       strcmp(info.id,"evil.blocks") ||
       info.wasm_size+info.asset_size+EK_PACKAGE_PAYLOAD_OFFSET!=(size_t)length) return 1;
    EkAssets assets;
    if(!ek_assets_parse(bytes+EK_PACKAGE_PAYLOAD_OFFSET+info.wasm_size,
                        info.asset_size,&assets)) return 1;
    Screen screen={0};
    EkVmHost host={&screen,rect,present,blit,draw_text,save,&assets};
    host.blit_region=blit_region;
    EkVm vm;
    if(!ek_vm_open(&vm,bytes+EK_PACKAGE_PAYLOAD_OFFSET,info.wasm_size,host)) {
        fprintf(stderr,"open: %s\n",ek_vm_error(&vm));return 1;
    }
    EvilKeyAppInput input={0};
    if(!ek_vm_init(&vm,&input)) {
        fprintf(stderr,"init: %s\n",ek_vm_error(&vm));return 1;
    }
    if(!step(&vm,32,-1,-1,0) || !step(&vm,64,100,330,1)) return 1;
    int32_t mode=0;
    if(!exported_i32(&vm,"app_mode",&mode) || !mode) return 1;
    for(uint32_t frame=3;frame<100;++frame)
        if(!step(&vm,frame*32u,220,355,frame==5)) {
            fprintf(stderr,"step: %s\n",ek_vm_error(&vm));return 1;
        }
    int32_t score=0,resumed_score=0;
    if(!exported_i32(&vm,"app_score",&score) || screen.presents<4 ||
       !screen.blits || screen.saves<1 || screen.saved_size!=512) return 1;
    ek_vm_close(&vm);
    memset(&input,0,sizeof(input));
    input.save_status=EVILKEY_APP_SAVE_LOADED;
    input.save_size=screen.saved_size;
    memcpy(input.save_data,screen.saved,screen.saved_size);
    if(!ek_vm_open(&vm,bytes+EK_PACKAGE_PAYLOAD_OFFSET,info.wasm_size,host) ||
       !ek_vm_init(&vm,&input))return 1;
    if(!exported_i32(&vm,"app_mode",&mode) || mode!=0 ||
       !step(&vm,3200,100,405,1) ||
       !exported_i32(&vm,"app_mode",&mode) || !mode ||
       !exported_i32(&vm,"app_score",&resumed_score) || resumed_score!=score) return 1;
    printf("EvilBlocks ABI v4: mode=%d, frames=%u, rects=%u, saves=%u, assets/save/resume OK\n",
           mode,screen.presents,screen.rects,screen.saves);
    ek_vm_close(&vm);free(bytes);return 0;
}
