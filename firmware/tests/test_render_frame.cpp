#include "ek_render_parallel.h"
#include "ek_scene3d.h"
#include <atomic>
#include <cassert>
#include <chrono>
#include <cstdio>
#include <thread>
#include <vector>
static std::atomic<unsigned> clocks{0},jobs{0};
static std::atomic<bool> saw_native_owner{false},saw_copy_unowned{false};
static uint64_t fake_clock(void *){
    EkRenderFrameStats phase{};ek_render_frame_stats(&phase);
    if(phase.owner==1)saw_native_owner=true;else if(phase.owner==0)saw_copy_unowned=true;
    return clocks.fetch_add(1)*10;
}
static void helper(void *){++jobs;}
int main(int argc,char **){
    EkRenderFrameStats initial{};ek_render_frame_stats(&initial);ek_render_frame_stats(nullptr);
    assert(!initial.ready&&!ek_render_frame_begin(0));ek_render_frame_end(false);
    ek_render_workers_start();ek_render_workers_start();
    if(argc>1){ek_render_frame_stats(&initial);assert(!initial.ready&&!ek_render_frame_begin(0));puts("PASS admission startup failure fallback");return 0;}
    assert(ek_render_workers_ready());
    assert(!ek_render_frame_begin(2));ek_render_frame_end(false);
    EvilKey3DScene scene{};scene.magic=EVILKEY_3D_MAGIC;scene.version=1;scene.material_count=1;scene.object_count=1;
    scene.camera={{0,2048,1536},{0,0,0},50,0,2560,0};
    scene.objects[0].model=EVILKEY_3D_BOX;scene.objects[0].scale[0]=scene.objects[0].scale[1]=scene.objects[0].scale[2]=256;
    assert(ek_scene3d_validate((uint8_t*)&scene,sizeof scene));
    std::vector<uint16_t> pixels(280*456);EkScene3D *native=ek_scene3d_create();assert(native);
    bool held=ek_render_frame_begin(EK_RENDER_FRAME_DISPLAY);assert(held);
    auto invalid=ek_scene3d_render(native,(uint8_t*)&scene,pixels.data(),280,0,64,1,288,fake_clock,nullptr);
    assert(invalid.status==EVILKEY_3D_NO_MEMORY&&clocks==0); // invalid input cannot wait on owned display
    std::atomic<bool> started{false},finished{false};
    std::thread worker([&]{started=true;
        auto stats=ek_scene3d_render(native,(uint8_t*)&scene,pixels.data(),280,0,64,280,288,fake_clock,nullptr);
        assert(stats.status==EVILKEY_3D_OK&&stats.elapsed_us<20000);finished=true;
    });
    while(!started)std::this_thread::yield();
    std::this_thread::sleep_for(std::chrono::milliseconds(40));
    assert(!finished&&clocks==0); // render timer/work cannot enter occupied display pass
    assert(ek_render_parallel(helper,nullptr,nullptr));assert(jobs==2); // helpers never acquire admission
    ek_render_frame_end(held);worker.join();assert(finished);
    assert(saw_native_owner&&saw_copy_unowned); // copy/end sampling runs after compute admission release
    EkRenderFrameStats stats{};ek_render_frame_stats(&stats);
    assert(stats.ready&&stats.acquisitions[0]==1&&stats.contentions[0]==1);
    assert(stats.wait_last_us[0]>=20000&&stats.wait_peak_us[0]>=stats.wait_last_us[0]);
    assert(!stats.owner);
    // A native owner blocks display; disabled parallel execution retains admission.
    ek_render_parallel_enable(false);held=ek_render_frame_begin(EK_RENDER_FRAME_NATIVE);assert(held);
    started=false;finished=false;
    std::thread display([&]{started=true;bool owned=ek_render_frame_begin(EK_RENDER_FRAME_DISPLAY);
        assert(owned);finished=true;ek_render_frame_end(owned);});
    while(!started)std::this_thread::yield();std::this_thread::sleep_for(std::chrono::milliseconds(30));assert(!finished);
    ek_render_frame_end(held);display.join();ek_render_parallel_enable(true);
    std::atomic<unsigned> active{0};std::vector<std::thread> callers;
    for(unsigned i=0;i<6;i++)callers.emplace_back([&,i]{for(unsigned n=0;n<30;n++){
        bool owned=ek_render_frame_begin(i%2);assert(owned&&active.fetch_add(1)==0);
        std::this_thread::yield();assert(active.fetch_sub(1)==1);ek_render_frame_end(owned);
    }});
    for(auto &caller:callers)caller.join();
    // Pre-copy timeout releases admission before returning/copying.
    clocks=3000; // zero slope clock still returns elapsed small, so use a fast clock below
    auto timeout_clock=[](void *)->uint64_t{return clocks.fetch_add(1)*25000;};
    auto aborted=ek_scene3d_render(native,(uint8_t*)&scene,pixels.data(),280,0,64,280,288,timeout_clock,nullptr);
    assert(aborted.status==EVILKEY_3D_TIMEOUT);held=ek_render_frame_begin(EK_RENDER_FRAME_DISPLAY);assert(held);ek_render_frame_end(held);
    ek_render_frame_stats(&stats);assert(!stats.owner&&stats.contentions[1]>=1);
    ek_scene3d_destroy(native);
    puts("PASS reciprocal admission, pre-timer queue, separate waits, helpers,180 clients, disable, timeout release, invalid/NULL");
}
