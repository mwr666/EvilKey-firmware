/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "ws_gui_3d.h"
#include <cassert>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <initializer_list>
#include <cmath>
#include <limits>
#include "../third_party/jet/OpaqueUI.hpp"

static void raster_contract() {
    using namespace Renderer;
    // Exhaustive oracle on small triangles: odd endpoints, shared edges,
    // thin faces and clipping. Edge coverage/depth come from direct int64
    // barycentrics, independent of the optimized scanline range/recurrence.
    constexpr int W=32;uint16_t colors[W*W],depth[W*W];
    unsigned cases=0;
    for(int bx=-3;bx<36;bx+=3)for(int by=-3;by<36;by+=3) {
        OpaqueUIFace t{};t.v[0]={1,1,19001};t.v[1]={int16_t(bx),3,20003};t.v[2]={7,int16_t(by),21007};t.color=0x5ff0;
        if((bx-1)*(by-1)-2*6<0)std::swap(t.v[1],t.v[2]);
        if(!prepareOpaqueUI(t))continue;
        memset(depth,255,sizeof depth);memset(colors,0,sizeof colors);
        OpaqueUICursor cursor{};
        for(int band=0;band<W;band+=8)drawOpaqueUIContinued(t,cursor,colors+band*W,depth+band*W,W,8,band);
        for(int y=0;y<W;y++)for(int x=0;x<W;x++) {
            auto a=t.v[0],b=t.v[1],c=t.v[2];
            int64_t w0=int64_t(b.y-c.y)*(x-c.x)+int64_t(c.x-b.x)*(y-c.y);
            int64_t w1=int64_t(c.y-a.y)*(x-c.x)+int64_t(a.x-c.x)*(y-c.y),w2=t.area-w0-w1;
            bool inside=w0>=0 && w1>=0 && w2>=0;
            assert((depth[y*W+x]!=65535)==inside);
            if(inside){assert(depth[y*W+x]==(a.z*w0+b.z*w1+c.z*w2)/t.area);assert(colors[y*W+x]==t.color);}
        }
        cases++;
    }
    // Two triangles must fill a square completely, including odd boundaries.
    memset(depth,255,sizeof depth);
    for(int i=0;i<2;i++) {
        OpaqueUIFace t{};t.color=1;t.v[0]={3,3,20000};t.v[1]=i?UIVertex{27,27,20000}:UIVertex{27,3,20000};t.v[2]=i?UIVertex{3,27,20000}:UIVertex{27,27,20000};
        assert(prepareOpaqueUI(t));drawOpaqueUI(t,colors,depth,W,W,0);
    }
    for(int y=3;y<=27;y++)for(int x=3;x<=27;x++)assert(depth[y*W+x]==20000);
    // Large projected faces exercise the wide residual and both depth-slope
    // signs. The oracle still uses direct barycentrics for every sample.
    for(int flip=0;flip<2;flip++) {
        OpaqueUIFace t{};t.color=0xa71f;
        t.v[0]={-2048,-2048,uint16_t(flip?60000:1)};
        t.v[1]={2048,-2048,uint16_t(flip?1:60000)};
        t.v[2]={0,2048,30001};
        assert(prepareOpaqueUI(t));assert(!t.narrow);
        memset(depth,255,sizeof depth);
        OpaqueUICursor cursor{};
        for(int band=0;band<W;band+=8)drawOpaqueUIContinued(t,cursor,colors+band*W,depth+band*W,W,8,band);
        for(int y=0;y<W;y++)for(int x=0;x<W;x++){
            auto a=t.v[0],b=t.v[1],c=t.v[2];
            int64_t w0=int64_t(b.y-c.y)*(x-c.x)+int64_t(c.x-b.x)*(y-c.y);
            int64_t w1=int64_t(c.y-a.y)*(x-c.x)+int64_t(a.x-c.x)*(y-c.y),w2=t.area-w0-w1;
            assert(w0>=0&&w1>=0&&w2>=0);
            assert(depth[y*W+x]==(a.z*w0+b.z*w1+c.z*w2)/t.area);
            assert(colors[y*W+x]==t.color);
        }
        cases++;
    }
    uint32_t seed=0x4512a1;unsigned fast_cases=0;
    auto random=[&](){seed=seed*1664525U+1013904223U;return seed;};
    for(unsigned attempt=0;attempt<5000;++attempt){
        OpaqueUIFace t{};t.color=0x1245;
        for(auto &v:t.v){v.x=int16_t(int(random()%161)-64);v.y=int16_t(int(random()%161)-64);v.z=uint16_t(1+random()%59999);}
        if((t.v[1].x-t.v[0].x)*(t.v[2].y-t.v[0].y)-(t.v[1].y-t.v[0].y)*(t.v[2].x-t.v[0].x)<0)std::swap(t.v[1],t.v[2]);
        if(!prepareOpaqueUI(t))continue;
        memset(depth,255,sizeof depth);OpaqueUICursor cursor{};
        for(int band=0;band<W;band+=4)drawOpaqueUIContinued(t,cursor,colors+band*W,depth+band*W,W,4,band);
        fast_cases+=cursor.fast;
        for(int y=0;y<W;++y)for(int x=0;x<W;++x){auto a=t.v[0],b=t.v[1],c=t.v[2];
            int64_t w0=int64_t(b.y-c.y)*(x-c.x)+int64_t(c.x-b.x)*(y-c.y);
            int64_t w1=int64_t(c.y-a.y)*(x-c.x)+int64_t(a.x-c.x)*(y-c.y),w2=t.area-w0-w1;
            const bool inside=w0>=0 && w1>=0 && w2>=0;assert((depth[y*W+x]!=65535)==inside);
            if(inside)assert(depth[y*W+x]==(a.z*w0+b.z*w1+c.z*w2)/t.area);
        }++cases;
    }
    assert(fast_cases>50);
    printf("PASS: %u independent edge/depth oracle cases and watertight odd-boundary square\n",cases);
}

static void ppm(const char *path,const ws_gui_3d_frame_t &frame) {
    FILE *f=fopen(path,"wb");assert(f);fprintf(f,"P6\n%u %u\n255\n",frame.width,frame.height);
    for(unsigned i=0;i<frame.width*frame.height;i++) {
        const uint8_t *p=frame.pixels+i*3;uint16_t c=uint16_t(p[0]<<8|p[1]);
        uint8_t rgb[]={uint8_t(((c>>11)&31)*255/31*p[2]/255),
            uint8_t(((c>>5)&63)*255/63*p[2]/255),uint8_t((c&31)*255/31*p[2]/255)};
        assert(fwrite(rgb,1,3,f)==3);
    }assert(fclose(f)==0);
}
int main() {
    raster_contract();
    for(int i=-60000;i<=60000;++i)for(float offset:{-.5f,.5f}){
        float x=i+offset;
        for(float v:{x,std::nextafter(x,-INFINITY),std::nextafter(x,INFINITY)})
            assert(ws_gui_3d_project_round(v)==std::lround(v));
    }
    puts("PASS: exact projection rounding at 720006 positive/negative half and adjacent float boundaries");
    assert(ws_gui_3d_init());assert(ws_gui_3d_init());
    assert(ws_gui_3d_stats().psram_bytes==238400+1536*(sizeof(Renderer::OpaqueUIFace)+sizeof(Renderer::OpaqueUICursor)+sizeof(uint16_t))+1024*sizeof(Renderer::UIVertex)+512*2*sizeof(float)+512*2*sizeof(uint16_t)+4*200*4+65*3*sizeof(float));
    if(getenv("EVILKEY_TEST_3D_LOW_INTERNAL") || getenv("EVILKEY_TEST_3D_ALLOC_FAIL")){
        auto before=ws_gui_3d_stats().psram_bytes;ws_gui_3d_configure_tiles();
        assert(!ws_gui_3d_presentation_stats().internal_tiles);
        assert(ws_gui_3d_presentation_stats().tile_rows==8);assert(ws_gui_3d_stats().psram_bytes==before);
        ws_gui_3d_frame_t fallback{};assert(ws_gui_3d_render(0,63,0x4DE3C1,0,&fallback));
        puts("PASS: low internal memory / failed allocation retains PSRAM tiles and renderability");return 0;
    }
    ws_gui_3d_frame_t frame{};
    assert(!ws_gui_3d_render(WS_3D_CHANNELS,0,0,0,&frame));assert(!ws_gui_3d_render(0,0,0,0,nullptr));
    assert(ws_gui_3d_render(0,0,0x4DE3C1,0,&frame));
    uint8_t *first=(uint8_t*)malloc(200*200*3);assert(first);memcpy(first,frame.pixels,200*200*3);
    auto count=ws_gui_3d_stats().frames;
    auto generation=frame.generation;
    assert(ws_gui_3d_render(0,256,0x4DE3C1,0,&frame));assert(ws_gui_3d_stats().frames==count);
    assert(memcmp(first,frame.pixels,200*200*3)==0);
    assert(frame.generation==generation);assert(ws_gui_3d_channel_stats(0).cache_hits>0);
    for(unsigned channel=0;channel<WS_3D_CHANNELS;channel++)for(unsigned phase=0;phase<256;phase++) {
        assert(ws_gui_3d_render(channel,phase,0x4DE3C1,0,&frame));
        unsigned visible=0,soft=0;
        for(unsigned i=0;i<frame.width*frame.height;i++){unsigned a=frame.pixels[i*3+2];visible+=a!=0;soft+=a>0&&a<255;}
        assert(visible>150);assert(soft>5);
        // No perspective geometry is silently clipped by the image boundary.
        for(unsigned i=0;i<frame.width;i++){assert(!frame.pixels[i*3+2]);assert(!frame.pixels[((frame.height-1)*frame.width+i)*3+2]);}
        for(unsigned i=0;i<frame.height;i++){assert(!frame.pixels[(i*frame.width)*3+2]);assert(!frame.pixels[(i*frame.width+frame.width-1)*3+2]);}
        if(phase%32==0 || phase==63){char path[100];snprintf(path,sizeof path,"firmware/build/jet-%u-%03u.ppm",channel,phase);ppm(path,frame);}
    }
    for(unsigned icon=0;icon<10;icon++) {
        assert(ws_gui_3d_reference(2,icon,0x4DE3C1,&frame));char path[100];
        uint8_t anchored[80*80*3];memcpy(anchored,frame.pixels,sizeof anchored);
        auto status_count=ws_gui_3d_stats().frames;
        snprintf(path,sizeof path,"firmware/build/jet-reference-%u.ppm",icon);ppm(path,frame);
        for(unsigned phase=0;phase<256;phase++) {
            ws_gui_3d_transition(phase%3==0?-160:phase%3==1?160:0);
            assert(ws_gui_3d_render(2,phase,0x4DE3C1,icon,&frame));
            assert(memcmp(anchored,frame.pixels,sizeof anchored)==0);
            assert(ws_gui_3d_stats().frames==status_count+1);
            for(unsigned i=0;i<frame.width;i++) {
                assert(!frame.pixels[i*3+2]);assert(!frame.pixels[((frame.height-1)*frame.width+i)*3+2]);
            }
            for(unsigned i=0;i<frame.height;i++) {
                assert(!frame.pixels[(i*frame.width)*3+2]);assert(!frame.pixels[(i*frame.width+frame.width-1)*3+2]);
            }
        }
        assert(ws_gui_3d_render(2,127,0xFF405A,icon,&frame));
        assert(memcmp(anchored,frame.pixels,sizeof anchored)!=0);
        assert(ws_gui_3d_stats().frames==status_count+2);
        assert(ws_gui_3d_render(2,0,0x4DE3C1,icon,&frame));
        assert(memcmp(anchored,frame.pixels,sizeof anchored)==0);
        snprintf(path,sizeof path,"firmware/build/jet-icon-%u.ppm",icon);ppm(path,frame);
    }
    ws_gui_3d_transition(0);
    // Exercise SRAM tiles after the full PSRAM sweep. Same sparse/full oracle
    // verifies both band sizes, including stale pixels after a glitch frame.
    ws_gui_3d_configure_tiles();assert(ws_gui_3d_presentation_stats().internal_tiles);
    for(unsigned channel=0;channel<WS_3D_CHANNELS;channel++)for(unsigned phase:{0U,63U,70U,127U,192U,198U,255U})
        assert(ws_gui_3d_render(channel,phase,0x4DE3C1,0,&frame));
    ws_gui_3d_record_panel_wait(37);assert(ws_gui_3d_take_panel_wait()==37);assert(ws_gui_3d_take_panel_wait()==0);
    auto fid=ws_gui_3d_frame_begin(1000);ws_gui_3d_frame_flush(fid,280*64*2);
    ws_gui_3d_frame_end(fid,3000,37,true);assert(ws_gui_3d_presentation_stats().frames==0);
    ws_gui_3d_frame_complete(fid,4000);auto ps=ws_gui_3d_presentation_stats();
    assert(ps.frame_us==3000 && ps.compose_us==2000 && ps.panel_wait_us==37 && ps.p95_us==3000);
    assert(ps.flushes==1 && ps.bytes==280*64*2);
    fid=ws_gui_3d_frame_begin(UINT32_MAX-50);ws_gui_3d_frame_flush(fid,8);
    ws_gui_3d_frame_complete(fid,49);ws_gui_3d_frame_end(fid,29,0,true);
    ps=ws_gui_3d_presentation_stats();assert(ps.frame_us==100 && ps.compose_us==80);
    fid=ws_gui_3d_frame_begin(5000);ws_gui_3d_frame_end(fid,5020,0,true);
    ps=ws_gui_3d_presentation_stats();
    assert(ps.compose_us==20 && ps.frame_us==100 && ps.frames==2 && ps.flushes==1 && ps.bytes==8);
    const auto transfer_p95=ps.p95_us;
    // Diagnostics can sit idle for hundreds of ticks between dirty refreshes.
    for(unsigned i=0;i<100;i++){
        fid=ws_gui_3d_frame_begin(8000+i*100);ws_gui_3d_frame_end(fid,8020+i*100,0,true);
    }
    ps=ws_gui_3d_presentation_stats();
    assert(ps.p95_us==transfer_p95 && ps.frames==2 && ps.flushes==1 && ps.bytes==8);
    fid=ws_gui_3d_frame_begin(20000);ws_gui_3d_frame_flush(fid,32);
    ws_gui_3d_frame_end(fid,20030,5,true);ws_gui_3d_frame_complete(fid,20050);
    ps=ws_gui_3d_presentation_stats();
    assert(ps.frames==3 && ps.frame_us==50 && ps.flushes==1 && ps.bytes==32 && ps.panel_wait_us==5);
    fid=ws_gui_3d_frame_begin(6000);ws_gui_3d_frame_flush(fid,8);ws_gui_3d_frame_end(fid,6010,0,false);
    auto failures=ws_gui_3d_presentation_stats().failed_frames;assert(failures==1);
    ws_gui_3d_frame_complete(fid,7000);assert(ws_gui_3d_presentation_stats().failed_frames==failures);
    puts("PASS: async/synchronous DMA completion, no-flush frame, error and 32-bit timer wrap; wait not double-counted");
    for(unsigned channel=0;channel<WS_3D_CHANNELS;channel++){
        auto cs=ws_gui_3d_channel_stats(channel);assert(cs.frames>0);assert(cs.p50_us<=cs.p95_us);
        if(channel==WS_3D_GEAR || channel==WS_3D_APPS)assert(cs.triangles<=1200);
    }
    // The three accepted animated channels must still move.
    for(unsigned channel:{WS_3D_SAVER,WS_3D_GEAR,WS_3D_APPS}) {
        assert(ws_gui_3d_render(channel,0,0x4DE3C1,0,&frame));
        size_t bytes=size_t(frame.width)*frame.height*3;
        uint8_t *still=(uint8_t*)malloc(bytes);assert(still);memcpy(still,frame.pixels,bytes);
        assert(ws_gui_3d_render(channel,32,0x4DE3C1,0,&frame));
        assert(memcmp(still,frame.pixels,bytes)!=0);free(still);
    }
    puts("PASS: all 10 status icons remain frontal across phase/transition changes, cache hits and recolouring; saver/Settings/Apps still animate");
    assert(ws_gui_3d_reference(1,0,0x4DE3C1,&frame));ppm("firmware/build/jet-reference-gear.ppm",frame);
    assert(ws_gui_3d_reference(WS_3D_APPS,0,0x4DE3C1,&frame));ppm("firmware/build/jet-reference-apps.ppm",frame);
    for(int tilt:{-160,160}) {
        ws_gui_3d_transition(tilt);
        for(unsigned channel=0;channel<WS_3D_CHANNELS;channel++)for(unsigned phase=0;phase<256;phase++) {
            assert(ws_gui_3d_render(channel,phase,0x4DE3C1,0,&frame));
            for(unsigned i=0;i<frame.width;i++){
                assert(!frame.pixels[i*3+2]);assert(!frame.pixels[((frame.height-1)*frame.width+i)*3+2]);
            }
            for(unsigned i=0;i<frame.height;i++){
                assert(!frame.pixels[(i*frame.width)*3+2]);assert(!frame.pixels[(i*frame.width+frame.width-1)*3+2]);
            }
        }
    }
    ws_gui_3d_transition(0);
    assert(ws_gui_3d_render(0,0,0x4DE3C1,0,&frame));assert(memcmp(first,frame.pixels,200*200*3)==0);free(first);
    auto stats=ws_gui_3d_stats();printf("PASS: 3072 phase/tilt combinations, closed loop, cache, AA, unclipped geometry; %zu PSRAM bytes; host peak %u us\n",stats.psram_bytes,stats.peak_us);
}
