/* SPDX-License-Identifier: AGPL-3.0-or-later
 * ABI v4 EvilPinball host simulation. Reads a package path supplied by test.
 */
#include "../EvilKeyV1/src/apps/ek_vm.h"
#include "../EvilKeyV1/src/apps/ek_package.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { W=280,H=456,PIXELS=W*H };
typedef struct {
    uint16_t *back,*front;
    unsigned frames,rects,blits,texts,saves,partial_frames;
    uint8_t save[4096];uint32_t save_size;
} Screen;
static void rect(void *u,int32_t x,int32_t y,int32_t w,int32_t h,uint16_t color) {
    Screen *s=(Screen *)u;++s->rects;
    for(int row=y;row<y+h;++row)
        for(int col=x;col<x+w;++col)s->back[row*W+col]=color;
}
static void present(void *u,int32_t x,int32_t y,int32_t w,int32_t h) {
    Screen *s=(Screen *)u;++s->frames;
    if(h<H)++s->partial_frames;
    for(int row=y;row<y+h;++row)
        memcpy(s->front+row*W+x,s->back+row*W+x,(size_t)w*2u);
}
static void blit(void *u,int32_t x,int32_t y,const EkAsset *asset) {
    Screen *s=(Screen *)u;++s->blits;
    for(unsigned row=0;row<asset->height;++row)
        for(unsigned col=0;col<asset->width;++col) {
            size_t at=(row*asset->width+col)*2u;
            uint16_t pixel=(uint16_t)(asset->rgb565[at] |
                                      ((uint16_t)asset->rgb565[at+1]<<8));
            if(!(asset->flags&1u) || pixel)s->back[(y+(int)row)*W+x+(int)col]=pixel;
        }
}
static void blit_region(void *u,int32_t x,int32_t y,uint32_t sx,uint32_t sy,
                        uint32_t width,uint32_t height,const EkAsset *asset) {
    Screen *s=(Screen *)u;++s->blits;
    for(uint32_t row=0;row<height;++row)
        for(uint32_t col=0;col<width;++col) {
            size_t at=((sy+row)*asset->width+sx+col)*2u;
            uint16_t pixel=(uint16_t)(asset->rgb565[at] |
                                      ((uint16_t)asset->rgb565[at+1]<<8));
            if(!(asset->flags&1u) || pixel)
                s->back[(y+(int32_t)row)*W+x+(int32_t)col]=pixel;
        }
}
static uint16_t glyph(char c) {
    if(c>='a' && c<='z')c=(char)(c-'a'+'A');
    switch(c) {
    case 'A':return 0x7bed;case 'B':return 0x7aeb;case 'C':return 0x724f;
    case 'D':return 0x7b6b;case 'E':return 0x72cf;case 'F':return 0x12cf;
    case 'G':return 0x7a4f;case 'H':return 0x5bed;case 'I':return 0x7497;
    case 'J':return 0x3a48;case 'K':return 0x5bad;case 'L':return 0x7249;
    case 'M':return 0x5f7d;case 'N':return 0x5f6d;case 'O':return 0x7b6f;
    case 'P':return 0x13ef;case 'Q':return 0x5f6f;case 'R':return 0x5bef;
    case 'S':return 0x79cf;case 'T':return 0x2497;case 'U':return 0x7b6d;
    case 'V':return 0x2b6d;case 'W':return 0x5f6d;case 'X':return 0x5aad;
    case 'Y':return 0x24ad;case 'Z':return 0x72d7;
    case '0':return 0x7b6f;case '1':return 0x2492;case '2':return 0x73e7;
    case '3':return 0x79e7;case '4':return 0x49ed;case '5':return 0x79cf;
    case '6':return 0x7bcf;case '7':return 0x2497;case '8':return 0x7bef;
    case '9':return 0x79ef;case ':':return 0x0404;case '.':return 0x4000;
    case '-':return 0x01c0;case '/':return 0x1250;case '!':return 0x040e;
    case '?':return 0x04e7;default:return 0;
    }
}
static void draw_text(void *u,int32_t x,int32_t y,uint32_t scale,
                      uint16_t color,const uint8_t *text,uint32_t length) {
    Screen *s=(Screen *)u;++s->texts;
    for(uint32_t i=0;i<length;++i) {
        uint16_t bits=glyph((char)text[i]);
        for(uint32_t row=0;row<5;++row)
            for(uint32_t col=0;col<3;++col)
                if(bits&(1u<<(row*3u+col)))
                    rect(u,x+(int32_t)((i*6u+col)*scale),
                         y+(int32_t)(row*scale),(int32_t)scale,
                         (int32_t)scale,color);
    }
}
static int save(void *u,const uint8_t *data,uint32_t length) {
    Screen *s=(Screen *)u;
    if(length>sizeof(s->save))return 0;
    memcpy(s->save,data,length);s->save_size=length;++s->saves;
    return 1;
}
static int export_i32(EkVm *vm,const char *name,int32_t *out) {
    IM3Function f=NULL;const void *results[]={out};
    return !m3_FindFunctionIn(&f,vm->module,name) &&
           !m3_Call(f,0,NULL) && !m3_GetResults(f,1,results);
}
static int ppm(const char *path,const Screen *s) {
    FILE *f=fopen(path,"wb");if(!f)return 0;
    fprintf(f,"P6\n%d %d\n255\n",W,H);
    for(int i=0;i<PIXELS;++i){
        uint16_t c=s->front[i];
        uint8_t rgb[3]={
            (uint8_t)((((c>>11)&31u)*255u)/31u),
            (uint8_t)((((c>>5)&63u)*255u)/63u),
            (uint8_t)(((c&31u)*255u)/31u)
        };
        if(fwrite(rgb,1,3,f)!=3){fclose(f);return 0;}
    }
    return fclose(f)==0;
}
int main(int argc,char **argv) {
    if(argc!=4)return 2;
    FILE *f=fopen(argv[1],"rb");if(!f || fseek(f,0,SEEK_END))return 1;
    long length=ftell(f);if(length<EK_PACKAGE_HEADER_SIZE || fseek(f,0,SEEK_SET))return 1;
    uint8_t *data=(uint8_t *)malloc((size_t)length);
    if(!data || fread(data,1,(size_t)length,f)!=(size_t)length)return 1;
    fclose(f);
    EkPackageInfo info;
    if(!ek_package_parse(data,EK_PACKAGE_HEADER_SIZE,(size_t)length,&info) ||
       strcmp(info.id,"evil.pinball") || info.asset_size<200000u)return 1;
    EkAssets assets;
    if(!ek_assets_parse(data+EK_PACKAGE_PAYLOAD_OFFSET+info.wasm_size,info.asset_size,&assets) ||
       assets.count!=11)return 1;
    Screen screen={0};
    screen.back=(uint16_t *)calloc(PIXELS,sizeof(uint16_t));
    screen.front=(uint16_t *)calloc(PIXELS,sizeof(uint16_t));
    if(!screen.back || !screen.front)return 1;
    EkVmHost host={&screen,rect,present,blit,draw_text,save,&assets};
    host.blit_region=blit_region;
    EkVm vm;
    if(!ek_vm_open(&vm,data+EK_PACKAGE_PAYLOAD_OFFSET,info.wasm_size,host)) {
        fprintf(stderr,"open: %s\n",ek_vm_error(&vm));return 1;
    }
    EvilKeyAppInput input={0};
    if(!ek_vm_init(&vm,&input)) {
        fprintf(stderr,"init: %s\n",ek_vm_error(&vm));return 1;
    }
    if(!ppm(argv[3],&screen))return 1;
    int32_t mode=0,score=0,lives=0;
    if(!export_i32(&vm,"app_debug_mode",&mode) || mode!=0)return 1;
    uint64_t max_gas=0;
    int32_t min_camera=10000,max_camera=-1;
    for(unsigned frame=1;frame<=750;++frame) {
        input.now_ms=frame*16u;
        input.touch_count=0;
        input.accel_valid=1;
        input.accel_x_mg=(frame%120u==0)?800:0;
        input.accel_y_mg=0;input.accel_z_mg=1000;
        input.save_status=screen.saves?EVILKEY_APP_SAVE_OK:EVILKEY_APP_SAVE_NONE;
        if(frame==1){input.touch_count=1;
                     input.touch[0].x=120;input.touch[0].y=311;}
        else if(frame>2 && (frame/22)%2==0) {
            input.touch_count=2;
            input.touch[0].x=45;input.touch[0].y=420;input.touch[0].id=3;
            input.touch[1].x=233;input.touch[1].y=420;input.touch[1].id=7;
        }
        if(!ek_vm_step(&vm,&input)) {
            fprintf(stderr,"step %u: %s\n",frame,ek_vm_error(&vm));return 1;
        }
        uint64_t gas=m3_GetResourceUsage(vm.runtime,c_m3Limit_GasUnits);
        if(gas>max_gas)max_gas=gas;
        int32_t camera=0;
        if(!export_i32(&vm,"app_debug_camera",&camera))return 1;
        if(camera<min_camera)min_camera=camera;
        if(camera>max_camera)max_camera=camera;
        if(frame==60 && !ppm(argv[2],&screen))return 1;
    }
    if(!export_i32(&vm,"app_debug_mode",&mode) ||
       !export_i32(&vm,"app_debug_score",&score) ||
       !export_i32(&vm,"app_debug_lives",&lives) ||
       screen.frames<100 || screen.partial_frames<100 ||
       screen.blits<100 || screen.saves<1 ||
       screen.save_size!=48 || max_gas>=EK_VM_GAS_PER_CALL ||
       max_camera-min_camera<150)return 1;
    printf("EvilPinball ABI v4: mode=%d score=%d lives=%d camera=%d..%d frames=%u partial=%u blits=%u saves=%u max_gas=%llu\n",
           mode,score,lives,min_camera,max_camera,screen.frames,screen.partial_frames,screen.blits,screen.saves,
           (unsigned long long)max_gas);
    ek_vm_close(&vm);free(screen.back);free(screen.front);free(data);
    return 0;
}
