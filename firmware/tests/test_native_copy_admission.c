/* Historical r24 experiment: compile against frozen r24 sources only.
 * COPY admission was withdrawn after device qualification; current
 * r25 gates are test_render_frame.cpp/test_scene3d_clock_poll.c. */
#include "ek_scene3d.h"
#include "ek_render_parallel.h"
#include <assert.h>
#include <stdio.h>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
static bool observed_parallel(EkRenderWork,void *,void *);
#define ek_render_parallel observed_parallel
#ifndef EK_COPY_ADMISSION_SOURCE
#define EK_COPY_ADMISSION_SOURCE "../EvilKeyV1/src/apps/ek_scene3d.c"
#endif
#include EK_COPY_ADMISSION_SOURCE
#undef ek_render_parallel
static HANDLE attempted,acquired,display_thread;
static unsigned copy_checks;
static DWORD WINAPI display_probe(void *arg){
    (void)arg;SetEvent(attempted);
    bool owned=ek_render_frame_begin(EK_RENDER_FRAME_DISPLAY);assert(owned);
    SetEvent(acquired);ek_render_frame_end(owned);return 0;
}
static bool observed_parallel(EkRenderWork work,void *first,void *second){
    if(work==copy_band){
        EkRenderFrameStats stats;ek_render_frame_stats(&stats);
        assert(stats.owner==3); /* old renderer MUST fail: it released before copy */
        attempted=CreateEvent(NULL,TRUE,FALSE,NULL);acquired=CreateEvent(NULL,TRUE,FALSE,NULL);
        assert(attempted&&acquired);display_thread=CreateThread(NULL,0,display_probe,NULL,0,NULL);assert(display_thread);
        assert(WaitForSingleObject(attempted,1000)==WAIT_OBJECT_0);
        assert(WaitForSingleObject(acquired,20)==WAIT_TIMEOUT);
    }
    bool parallel=ek_render_parallel(work,first,second);
    if(work==copy_band){
        EkRenderFrameStats stats;ek_render_frame_stats(&stats);assert(stats.owner==3);
        assert(WaitForSingleObject(acquired,0)==WAIT_TIMEOUT);++copy_checks;
    }
    return parallel;
}
int main(void){
    ek_render_workers_start();assert(ek_render_workers_ready());
    EkScene3D *r=ek_scene3d_create();assert(r);
    EvilKey3DScene scene={0};scene.magic=EVILKEY_3D_MAGIC;scene.version=2;
    scene.object_count=1;scene.material_count=1;scene.materials[0].rgb565=0x47d8;
    scene.camera=(EvilKey3DCamera){{0,640,-1536},{0,0,0},45,1,2048,0};
    scene.objects[0]=(EvilKey3DObject){.model=EVILKEY_3D_BOX,.scale={512,512,512}};
    uint16_t *pixels=calloc(280*456+2,2);assert(pixels);pixels[0]=pixels[280*456+1]=0xbeef;
    EkSceneStats result=ek_scene3d_render(r,(const uint8_t*)&scene,pixels+1,280,0,64,280,288,NULL,NULL);
    assert(result.status==EVILKEY_3D_OK&&copy_checks==1);
    assert(WaitForSingleObject(display_thread,1000)==WAIT_OBJECT_0&&WaitForSingleObject(acquired,0)==WAIT_OBJECT_0);
    CloseHandle(display_thread);CloseHandle(attempted);CloseHandle(acquired);
    EkRenderFrameStats stats;ek_render_frame_stats(&stats);assert(stats.owner==0);
    assert(pixels[0]==0xbeef&&pixels[280*456+1]==0xbeef);
    ek_scene3d_destroy(r);free(pixels);
    puts("COPY ADMISSION PASS actual renderer:owner3 across joined PSRAMcopy;real Displaythread blocked before/after jobs and acquired afterrelease;canaries/no leaked lock;not device timing");
}
