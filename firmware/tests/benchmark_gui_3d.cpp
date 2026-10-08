/* SPDX-License-Identifier: AGPL-3.0-or-later */
// PC regression/visual comparison only: not an ESP32/PSRAM FPS benchmark.
#include "ws_gui_3d.h"
#include <cstdio>
#include <cstdlib>
#include <cassert>
#include <algorithm>
#include <iterator>
int main(int argc,char **argv){
    assert(argc==2);assert(ws_gui_3d_init());
    const char *names[]={"saver","settings","status","apps"};
    const unsigned phases[]={0,32,63,64,69,70,96,128,160,190,192,197,198,224,255};
    for(unsigned channel:{WS_3D_SAVER,WS_3D_GEAR,WS_3D_APPS}){
        unsigned times[256];
        for(unsigned phase=0;phase<256;phase++){
            ws_gui_3d_frame_t frame{};assert(ws_gui_3d_render(channel,phase,0x4DE3C1,0,&frame));
            times[phase]=ws_gui_3d_stats().last_us;
            if(std::find(std::begin(phases),std::end(phases),phase)!=std::end(phases)){
                char path[1024];snprintf(path,sizeof path,"%s/%s-%03u.raw",argv[1],names[channel],phase);
                FILE *out=fopen(path,"wb");assert(out);
                assert(fwrite(frame.pixels,3,frame.width*frame.height,out)==unsigned(frame.width*frame.height));fclose(out);
            }
        }
        std::sort(times,times+256);
        printf("%s,p50_us=%u,p95_us=%u,peak_us=%u,triangles=%u,psram=%zu\n",names[channel],times[127],times[243],times[255],ws_gui_3d_stats().triangles,ws_gui_3d_stats().psram_bytes);
    }
}
