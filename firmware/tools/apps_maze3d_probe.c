/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Exact app bytecode + firmware VM + native renderer integration probe. */
#define main unused_pinball_probe_main
#include "apps_pinball_probe.c"
#undef main
#include "../EvilKeyV1/src/apps/ek_scene3d.h"
#include <assert.h>
static EkScene3D *renderer;
static unsigned scenes,aborts,triangles,pixel_tests;
static EkSceneStats scene_draw(void *u,const uint8_t *data,unsigned x,unsigned y,unsigned w,unsigned h){
    Screen *s=u;EkSceneStats stats=ek_scene3d_render(renderer,data,s->back,W,x,y,w,h,NULL,NULL);
    scenes++;aborts+=stats.status!=1;if(stats.triangles>triangles)triangles=stats.triangles;if(stats.pixel_tests>pixel_tests)pixel_tests=stats.pixel_tests;return stats;
}
static uint8_t *read_file(const char *name,size_t *len){FILE *f=fopen(name,"rb");assert(f);assert(!fseek(f,0,SEEK_END));*len=(size_t)ftell(f);rewind(f);uint8_t *p=malloc(*len);assert(p);assert(fread(p,1,*len,f)==*len);fclose(f);return p;}
static int query(EkVm *vm,const char *name){int32_t out=0;assert(!m3_SetResourceLimit(vm->runtime,c_m3Limit_GasUnits,EK_VM_GAS_PER_CALL));assert(export_i32(vm,name,&out));return out;}
static void connected(EkVm *vm){
    unsigned offset=(unsigned)query(vm,"app_grid");size_t size;uint8_t *memory=m3_GetMemory(vm->module,&size,0);
    assert(offset<=size && size-offset>=81);const uint8_t *grid=memory+offset;
    unsigned queue[81],count=1,head=0;bool visited[81]={0};queue[0]=10;visited[10]=true;
    while(head<count){unsigned c=queue[head++];int neighbors[4]={(int)c-1,(int)c+1,(int)c-9,(int)c+9};
        for(unsigned i=0;i<4;i++){int n=neighbors[i];if(n>=0&&n<81&&!grid[n]&&!visited[n]){visited[n]=true;queue[count++]=n;}}
    }
    assert(count==31 && visited[16] && visited[64] && visited[52] && visited[70]);
}
static uint64_t peak_gas;
static void step(EkVm *vm,EvilKeyAppInput *in,Screen *s){
    in->now_ms+=16;in->save_status=s->saves?EVILKEY_APP_SAVE_OK:EVILKEY_APP_SAVE_NONE;
    if(!ek_vm_step(vm,in)){fprintf(stderr,"STEP %u: %s\n",in->now_ms,ek_vm_error(vm));abort();}
    uint64_t gas=m3_GetResourceUsage(vm->runtime,c_m3Limit_GasUnits);if(gas>peak_gas)peak_gas=gas;
}
static void tap(EkVm *vm,EvilKeyAppInput *in,Screen *s,int x,int y){in->touch_count=0;step(vm,in,s);in->touch_count=1;in->touch[0]=(EvilKeyAppTouch){x,y,1,0};step(vm,in,s);in->touch_count=0;step(vm,in,s);}
static void picture(const char *folder,const char *name,Screen *s){char p[2048];snprintf(p,sizeof p,"%s/%s.ppm",folder,name);assert(ppm(p,s));}
int main(int argc,char **argv){
    if(argc!=5)return 2;
    Screen s={0};s.back=calloc(PIXELS,2);s.front=calloc(PIXELS,2);renderer=ek_scene3d_create();assert(s.back&&s.front&&renderer);
    EkVmHost host={&s,rect,present,blit,draw_text,save,NULL};host.blit_region=blit_region;host.abi_version=5;host.scene3d=scene_draw;
    /* Adversarial zero-import scene guest: invalid list has no effects. */
    size_t size;uint8_t *guest=read_file(argv[3],&size);EkVm vm;EvilKeyAppInput in={0};
    if(!ek_vm_open(&vm,guest,size,host)||!ek_vm_init(&vm,&in)){fprintf(stderr,"PROBE INIT: %s\n",ek_vm_error(&vm));abort();}step(&vm,&in,&s);step(&vm,&in,&s);assert(query(&vm,"probe_feedback"));
    for(int f=1;f<=17;f++){
        assert(query(&vm,"probe_fault_next")==f);unsigned draws=s.rects,frames=s.frames,save_count=s.saves,render_count=scenes;
        assert(!ek_vm_step(&vm,&in));assert(s.rects==draws&&s.frames==frames&&s.saves==save_count&&scenes==render_count);
    }
    ek_vm_close(&vm);host.abi_version=4;assert(ek_vm_open(&vm,guest,size,host)&&ek_vm_init(&vm,&in));assert(!ek_vm_step(&vm,&in));ek_vm_close(&vm);free(guest);
    host.abi_version=5;
    for(unsigned variant=0;variant<2;variant++){
        uint8_t *data=read_file(argv[1+variant],&size);EkPackageInfo info;EkAssets assets;
        assert(ek_package_parse(data,320,size,&info)&&info.abi==5);
        uint8_t header[320];memcpy(header,data,320);header[12]=6;assert(!ek_package_parse(header,320,size,&info));assert(ek_package_parse(data,320,size,&info));
        assert(ek_assets_parse(data+8512+info.wasm_size,info.asset_size,&assets));host.assets=&assets;
        in=(EvilKeyAppInput){0};s.saves=0;s.save_size=0;assert(ek_vm_open(&vm,data+8512,info.wasm_size,host));
        if(!ek_vm_init(&vm,&in)){fprintf(stderr,"INIT: %s\n",ek_vm_error(&vm));abort();}
        step(&vm,&in,&s);if(!variant)picture(argv[4],"preview-menu",&s);
        tap(&vm,&in,&s,140,305);tap(&vm,&in,&s,205,430); /* start, touch control */
        for(unsigned f=0;f<420;f++){
            in.touch_count=1;in.touch[0]=(EvilKeyAppTouch){f<160?240:45,380,2,0};step(&vm,&in,&s);
            if(variant){assert(!query(&vm,"app_collision"));assert(!query(&vm,"app_overflow"));assert(query(&vm,"app_level")==1);}
            if(!variant&&f==90)picture(argv[4],"preview-game",&s);
        }
        in.touch_count=0;
        for(unsigned f=0;f<24;f++){in.now_ms+=80;step(&vm,&in,&s);} /* max clamped 96ms */
        tap(&vm,&in,&s,60,430);if(variant)assert(query(&vm,"app_paused"));if(!variant)picture(argv[4],"preview-pause",&s);
        for(unsigned f=0;f<160;f++)step(&vm,&in,&s); /* wait for checkpoint write */
        assert(s.saves&&s.save_size==64);uint8_t checkpoint[64];memcpy(checkpoint,s.save,64);
        if(variant){int x=query(&vm,"app_x");for(int f=0;f<60;f++)step(&vm,&in,&s);assert(query(&vm,"app_x")==x);}
        tap(&vm,&in,&s,140,171);
        if(variant){
            for(int level=1;level<=12;level++){
                assert(query(&vm,"app_level")==level);assert(query(&vm,"app_rooms")==16);connected(&vm);
                for(int k=0;k<4;k++){query(&vm,"app_test_route");step(&vm,&in,&s);}
                if(level==2)picture(argv[4],"preview-level3",&s);
            }
            picture(argv[4],"preview-victory",&s);assert(query(&vm,"app_level")==12);
        }
        ek_vm_close(&vm);
        /* Real checkpoint reload via same mailbox; Continue starts there. */
        in=(EvilKeyAppInput){0};in.save_status=EVILKEY_APP_SAVE_LOADED;in.save_size=64;memcpy(in.save_data,checkpoint,64);
        assert(ek_vm_open(&vm,data+8512,info.wasm_size,host));if(!ek_vm_init(&vm,&in)){fprintf(stderr,"RELOAD: %s\n",ek_vm_error(&vm));abort();}step(&vm,&in,&s);tap(&vm,&in,&s,140,360);
        if(variant){assert(query(&vm,"app_mode")==1);assert(query(&vm,"app_x")==((int32_t *)checkpoint)[11]);assert(query(&vm,"app_z")==((int32_t *)checkpoint)[12]);}
        tap(&vm,&in,&s,60,430);tap(&vm,&in,&s,140,342);for(int f=0;f<200;f++)step(&vm,&in,&s);
        if(variant)assert(query(&vm,"app_mode")==0);
        ek_vm_close(&vm);
        /* Corrupt saves must fall back to a fresh menu with no VM trap. */
        in=(EvilKeyAppInput){0};in.save_status=EVILKEY_APP_SAVE_LOADED;in.save_size=64;memcpy(in.save_data,checkpoint,64);in.save_data[8]^=1;
        assert(ek_vm_open(&vm,data+8512,info.wasm_size,host)&&ek_vm_init(&vm,&in));step(&vm,&in,&s);
        if(variant)assert(query(&vm,"app_mode")==0);
        ek_vm_close(&vm);free(data);
    }
    assert(!aborts);assert(peak_gas<EK_VM_GAS_PER_CALL);
    printf("ABI5 EvilMaze PASS: scenes=%u frames=%u max_triangles=%u max_pixels=%u max_gas=%llu, 17 atomic invalid scene cases, ABI4 gate, collision, pause, saves/reload, 12 levels and victory\n",scenes,s.frames,triangles,pixel_tests,(unsigned long long)peak_gas);
    ek_scene3d_destroy(renderer);free(s.back);free(s.front);return 0;
}
