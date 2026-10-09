#include "../../pf_build_config.h"
/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Jet software triangles + bounded, native-resolution LVGL image sources.
 * Flat face lighting and 2x spatial sampling; no temporal reconstruction.
 */
#include "ws_gui_3d.h"
#include "ws_gui_3d_geometry.h"
#include "ws_gui_3d_meshes.h"
#include "../jet/Renderer.hpp"
#include "../jet/OpaqueUI.hpp"
#include "../../apps/ek_render_parallel.h"
#include "esp_heap_caps.h"
#ifndef WS_3D_HOST
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/portmacro.h"
#else
#include <chrono>
#endif
#include <cmath>
#include <cstring>
#include <algorithm>
#ifdef WS_3D_HOST
#include <cstdlib>
#include <cassert>
#endif

namespace {
constexpr int MAX_SIDE=200, SAMPLE=2, STRIDE=MAX_SIDE*SAMPLE;
constexpr int TILE_ROWS=8, MAX_TRIANGLES=1536;
constexpr int MAX_BANDS=(STRIDE+3)/4;
constexpr float PI=3.14159265358979323846f;
constexpr float LANDING_ICON_DEPTH=24.f;
const int sizes[WS_3D_CHANNELS]={200,120,80,120};
uint16_t *color_buffer, *depth_buffer;
using ProjectedTriangle=Renderer::OpaqueUIFace;
ProjectedTriangle *triangles;
uint16_t *band_next;
Renderer::OpaqueUICursor *scan_states;
constexpr unsigned MAX_SHADES=512,MAX_NORMALS=512;
float *normal_light;
uint16_t *shade_colors;
struct ParallelStorage {
    uint16_t colors[STRIDE*TILE_ROWS],depths[STRIDE*TILE_ROWS];
    Renderer::OpaqueUICursor cursors[MAX_TRIANGLES];
};
static_assert(sizeof(ParallelStorage)<=256*1024,"GUI parallel PSRAM budget");
ParallelStorage *parallel_storage;
bool detail_profile;
bool frame_detail;
struct RowRange { int16_t first,last; };
RowRange *previous_rows;
Renderer::UIVertex *projected_vertices;
constexpr unsigned MAX_MESH_VERTICES=1024;
int tile_rows=TILE_ROWS;
ws_gui_3d_channel_stats_t channel_stats[WS_3D_CHANNELS]{};
ws_gui_3d_presentation_stats_t presentation_stats{};
uint32_t timings[WS_3D_CHANNELS][32]{},presentation_timings[32]{};
uint32_t generations[WS_3D_CHANNELS]{};
uint32_t panel_wait_accumulated,lvgl_wait_accumulated,presentation_count;
struct FrameStamp { uint32_t id,start,end,compose,wait,flushes,bytes,lvgl_wait; bool closed,complete,success; };
FrameStamp frame_stamps[4]{};
uint32_t next_frame_id;
#ifndef WS_3D_HOST
portMUX_TYPE frame_mux=portMUX_INITIALIZER_UNLOCKED;
#define FRAME_LOCK() portENTER_CRITICAL(&frame_mux)
#define FRAME_UNLOCK() portEXIT_CRITICAL(&frame_mux)
#define FRAME_ISR_LOCK() portENTER_CRITICAL_ISR(&frame_mux)
#define FRAME_ISR_UNLOCK() portEXIT_CRITICAL_ISR(&frame_mux)
#else
#define FRAME_LOCK() ((void)0)
#define FRAME_UNLOCK() ((void)0)
#define FRAME_ISR_LOCK() ((void)0)
#define FRAME_ISR_UNLOCK() ((void)0)
#endif
unsigned rendering_channel;
struct Bounds { int x0=MAX_SIDE,y0=MAX_SIDE,x1=-1,y1=-1; };
Bounds previous_bounds[WS_3D_CHANNELS];
unsigned triangle_count;
bool triangle_overflow;
uint8_t *images[WS_3D_CHANNELS];
ws_gui_3d_stats_t stats{};
uint16_t last_phase[WS_3D_CHANNELS];
uint32_t last_accent[WS_3D_CHANNELS];
unsigned last_icon[WS_3D_CHANNELS];
bool valid[WS_3D_CHANNELS];
int16_t transition_depth;
int16_t last_depth[WS_3D_CHANNELS];
struct V { float x,y,z; V operator-(V b) const { return {x-b.x,y-b.y,z-b.z}; } };
V *transformed_tile;
uint64_t micros_now() {
#ifndef WS_3D_HOST
    return esp_timer_get_time();
#else
    return std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
#endif
}
void percentiles(const uint32_t *samples,unsigned count,uint32_t &p50,uint32_t &p95) {
    uint32_t sorted[32];count=std::min(count,32U);
    if(!count){p50=p95=0;return;}
    std::copy_n(samples,count,sorted);std::sort(sorted,sorted+count);
    p50=sorted[(count-1)/2];p95=sorted[(count*95+99)/100-1];
}
int projection_round(float x) {
    const int n=int(x);const float fraction=x-float(n);
    return n+(fraction>=.5f)-(fraction<=-.5f);
}
Renderer::UIVertex project(V p,int side,float scale) {
    const float perspective=620.f/(620.f+p.z);
    return {int16_t(projection_round((side/2.f+p.x*scale*perspective)*SAMPLE)),
        int16_t(projection_round((side/2.f+p.y*scale*perspective)*SAMPLE)),
        uint16_t(projection_round((620.f+p.z)*32.f))};
}
void enqueue(Renderer::UIVertex a,Renderer::UIVertex b,Renderer::UIVertex c,uint16_t color) {
    int32_t area=int32_t(b.x-a.x)*(c.y-a.y)-int32_t(b.y-a.y)*(c.x-a.x);
    if(!area)return;
    if(area<0)std::swap(b,c);
    if(triangle_count==MAX_TRIANGLES){triangle_overflow=true;return;}
    auto &t=triangles[triangle_count++];t.color=color;t.v[0]=a;t.v[1]=b;t.v[2]=c;
    if(!Renderer::prepareOpaqueUI(t)){triangle_count--;triangle_overflow=true;}
}
uint16_t shade(uint32_t rgb,float light) {
    unsigned r=std::min(255U,unsigned(((rgb>>16)&255)*light));
    unsigned g=std::min(255U,unsigned(((rgb>>8)&255)*light));
    unsigned b=std::min(255U,unsigned((rgb&255)*light));
    return uint16_t((r>>3)<<11 | (g>>2)<<5 | (b>>3));
}
struct Painter {
    float yaw,pitch,roll,scale;
    V basis[3];
    bool preserve_style=false;
    bool solid_sides=false;
    float icon_units=200.f/80.f,icon_center=35.f;
    int side;
    Painter(int n,float y,float p,float r): yaw(y),pitch(p),roll(r),scale(float(n)/200.f),side(n) {
        // Trigonometry once per frame, never for each projected vertex.
        static float last_pose[3];static V last_basis[3];static bool cached;
        if(cached && yaw==last_pose[0] && pitch==last_pose[1] && roll==last_pose[2]){memcpy(basis,last_basis,sizeof basis);return;}
        const float cy=cosf(yaw),sy=sinf(yaw),cp=cosf(pitch),sp=sinf(pitch),cr=cosf(roll),sr=sinf(roll);
        basis[0]={cr*cy-sr*sp*sy,sr*cy+cr*sp*sy,-cp*sy};
        basis[1]={-sr*cp,cr*cp,sp};
        basis[2]={cr*sy+sr*sp*cy,sr*sy-cr*sp*cy,cp*cy};
        last_pose[0]=yaw;last_pose[1]=pitch;last_pose[2]=roll;memcpy(last_basis,basis,sizeof basis);cached=true;
    }
    V pose(V p) {return {p.x*basis[0].x+p.y*basis[1].x+p.z*basis[2].x,
        p.x*basis[0].y+p.y*basis[1].y+p.z*basis[2].y,
        p.x*basis[0].z+p.y*basis[1].z+p.z*basis[2].z};}
    void tri(V a,V b,V c,uint32_t rgb,bool posed=false) {
        if(!posed){a=pose(a);b=pose(b);c=pose(c);}
        float light=1.f;
        if(!preserve_style){
        V u=b-a,v=c-a;
        V normal={u.y*v.z-u.z*v.y,u.z*v.x-u.x*v.z,u.x*v.y-u.y*v.x};
        float len=sqrtf(normal.x*normal.x+normal.y*normal.y+normal.z*normal.z);
        if(len<0.001f)return;
        // Meshes are double-sided; depth resolves occlusion. Light follows the
        // visible face, including backs at large crystal yaw angles.
        if(normal.z>0){normal.x=-normal.x;normal.y=-normal.y;normal.z=-normal.z;}
        float lambert=std::max(0.f,(-.34f*normal.x-.46f*normal.y-.82f*normal.z)/len);
        float shine=std::max(0.f,-normal.z/len);
        float shine2=shine*shine,shine4=shine2*shine2,shine8=shine4*shine4;
        light=solid_sides?
            .42f+.48f*lambert+.10f*shine8*shine4:.23f+.70f*lambert+.14f*shine8*shine4;
        }
        enqueue(project(a,side,scale),project(b,side,scale),project(c,side,scale),shade(rgb,light));
    }
    void quad(V a,V b,V c,V d,uint32_t rgb) {tri(a,b,c,rgb);tri(a,c,d,rgb);}
    void lit_quad(V a,V b,V c,V d,uint32_t rgb) {
        // Keep the original front colours; light only bevels and solid sides.
        const bool original=preserve_style;preserve_style=false;solid_sides=true;
        quad(a,b,c,d,rgb);preserve_style=original;solid_sides=false;
    }
    const WsMesh *lit_mesh=nullptr;
    uint32_t cached_colors[2][3]{};bool colors_valid[2]{};
    void mesh(const WsMesh &m,uint32_t accent,float units=1,float x=0,float y=0,uint32_t border=0,uint32_t fill=0,unsigned style=0) {
        if(m.vertex_count>MAX_MESH_VERTICES || m.normal_count>MAX_NORMALS || m.shade_count>MAX_SHADES){triangle_overflow=true;return;}
        if(lit_mesh!=&m){
            lit_mesh=&m;colors_valid[0]=colors_valid[1]=false;
            if(&m==&WS_APP_TILE_MESH){
                if(m.vertex_count>65){triangle_overflow=true;return;}
                for(unsigned i=0;i<m.vertex_count;++i){const auto &v=m.vertices[i];transformed_tile[i]=pose({v.x*units,v.y*units,v.z*units});}
            }
            for(unsigned i=0;i<m.normal_count;++i){
                const auto &f=m.normals[i];
                V n={basis[0].x*f.nx+basis[1].x*f.ny+basis[2].x*f.nz,
                     basis[0].y*f.nx+basis[1].y*f.ny+basis[2].y*f.nz,
                     basis[0].z*f.nx+basis[1].z*f.ny+basis[2].z*f.nz};
                if(n.z>0)n={-n.x,-n.y,-n.z};
                float lambert=std::max(0.f,-.34f*n.x-.46f*n.y-.82f*n.z);
                float shine=std::max(0.f,-n.z),p2=shine*shine,p4=p2*p2,p8=p4*p4;
                normal_light[i*2]=.23f+.70f*lambert+.14f*p8*p4;
                normal_light[i*2+1]=.42f+.48f*lambert+.10f*p8*p4;
            }
        }
        style&=1;
        if(!colors_valid[style] || cached_colors[style][0]!=accent || cached_colors[style][1]!=border || cached_colors[style][2]!=fill){
            for(unsigned i=0;i<m.shade_count;++i){const auto &g=m.shades[i];
                uint32_t base=g.material==1?border:g.material==2?fill:accent;
                const float light=g.light?normal_light[g.normal*2+(g.light==2)]:1.f;
                shade_colors[style*MAX_SHADES+i]=shade(tone(base,g.tone),light);
            }
            colors_valid[style]=true;cached_colors[style][0]=accent;cached_colors[style][1]=border;cached_colors[style][2]=fill;
        }
        const V offset=pose({x*units,y*units,0});
        for(unsigned i=0;i<m.vertex_count;++i){const auto &v=m.vertices[i];
            if(&m==&WS_APP_TILE_MESH){const V local=transformed_tile[i];projected_vertices[i]=project({local.x+offset.x,local.y+offset.y,local.z+offset.z},side,scale);}
            else projected_vertices[i]=project(pose({(v.x+x)*units,(v.y+y)*units,v.z*units}),side,scale);
        }
        for(unsigned i=0;i<m.face_count;++i){const auto &f=m.faces[i];
            enqueue(projected_vertices[f.a],projected_vertices[f.b],projected_vertices[f.c],shade_colors[style*MAX_SHADES+f.shade]);
        }
    }
    void logo(uint32_t rgb,float crystal_yaw) {
        mesh(WS_LOGO_MESH,rgb);
        V top=pose({0,27,0}),bottom=pose({0,95,0}),belt[4];
        const float cy=cosf(crystal_yaw),sy=sinf(crystal_yaw);
        for(int i=0;i<4;i++){const auto c=WS_ICON_CIRCLE[i*16];
            belt[i]=pose({18*(cy*c.x+sy*c.y),67,18*(-sy*c.x+cy*c.y)});}
        for(int i=0;i<4;i++){tri(top,belt[i],belt[(i+1)%4],0xF7F9FA,true);tri(bottom,belt[(i+1)%4],belt[i],0xF7F9FA,true);}
    }
    static uint32_t tone(uint32_t rgb,unsigned alpha) {
        return ((((rgb>>16)&255)*alpha/255)<<16)|((((rgb>>8)&255)*alpha/255)<<8)|((rgb&255)*alpha/255);
    }
    V ip(float x,float y,float z=0) {
        return {(x-icon_center)*icon_units,(y-icon_center)*icon_units,z*icon_units};
    }
    void ring(float x,float y,float outer,float inner,uint32_t rgb,float z=0) {
        const int step=outer<=3?8:outer<=10?4:2;
        for(int i=0;i<64;i+=step) {
            auto a=WS_ICON_CIRCLE[i],b=WS_ICON_CIRCLE[(i+step)%64];
            V p=ip(x+outer*a.x,y+outer*a.y,z),q=ip(x+outer*b.x,y+outer*b.y,z);
            if(inner>0)quad(p,q,ip(x+inner*b.x,y+inner*b.y,z),ip(x+inner*a.x,y+inner*a.y,z),rgb);
            else tri(ip(x,y,z),p,q,rgb);
            quad(p,q,ip(x+outer*b.x,y+outer*b.y,z+1.2f),ip(x+outer*a.x,y+outer*a.y,z+1.2f),tone(rgb,100));
        }
    }
    void stroke(float x,float y,float x2,float y2,float width,uint32_t rgb,float z=0) {
        float dx=x2-x,dy=y2-y,len=sqrtf(dx*dx+dy*dy);
        if(len<.001f)return;
        float nx=-dy*width/(2*len),ny=dx*width/(2*len);
        quad(ip(x+nx,y+ny,z),ip(x2+nx,y2+ny,z),ip(x2-nx,y2-ny,z),ip(x-nx,y-ny,z),rgb);
        ring(x,y,width/2,0,rgb,z);ring(x2,y2,width/2,0,rgb,z);
    }
    void panel(float x,float y,float w,float h,float radius,float width,
               uint32_t rgb,unsigned fill,float z=0,uint32_t fill_rgb=0xFFFFFFFF) {
        float cx[4]={x+radius,x+w-radius,x+w-radius,x+radius};
        float cy[4]={y+radius,y+radius,y+h-radius,y+h-radius};
        for(int i=0;i<64;i++) {
            auto vertex=[&](int k,float r){int corner=k/16;auto c=WS_ICON_CIRCLE[(k+32)%64];
                return ip(cx[corner]+r*c.x,cy[corner]+r*c.y,z);};
            V a=vertex(i,radius),b=vertex((i+1)%64,radius);
            V c=vertex((i+1)%64,std::max(0.f,radius-width)),d=vertex(i,std::max(0.f,radius-width));
            if(width>0)quad(a,b,c,d,rgb);
            if(fill)tri(ip(x+w/2,y+h/2,z),c,d,fill_rgb==0xFFFFFFFF?tone(rgb,fill):fill_rgb);
        }
    }
    void arc(float x,float y,float radius,float width,float start,float degrees,uint32_t rgb,float z) {
        // Recurrence rotates each segment without per-vertex trigonometry.
        int count=int(std::ceil(degrees/5.625f));
        float step=degrees*PI/(180*count),cs=cosf(step),sn=sinf(step);
        float ax=cosf(start),ay=sinf(start);
        for(int i=0;i<count;i++) {
            float bx=ax*cs-ay*sn,by=ax*sn+ay*cs;
            quad(ip(x+radius*ax,y+radius*ay,z),ip(x+radius*bx,y+radius*by,z),
                 ip(x+(radius-width)*bx,y+(radius-width)*by,z),ip(x+(radius-width)*ax,y+(radius-width)*ay,z),rgb);
            ax=bx;ay=by;
        }
        float mid=radius-width/2;
        ring(x+mid*cosf(start),y+mid*sinf(start),width/2,0,rgb,z);
        ring(x+mid*ax,y+mid*ay,width/2,0,rgb,z);
    }
    void gear(uint32_t rgb) {
        mesh(WS_GEAR_MESH,rgb,200.f/120.f);
    }
    void apps(uint32_t rgb,unsigned phase=0) {
        // Original 3x3 grid: 26px rounded tiles, 29px pitch, bright diagonal.
        preserve_style=false;icon_units=200.f/120.f;icon_center=60;
        static const uint8_t wave[]={0,1,3,6,11,18,25,33,41,52,62,73,84,96,109,121,
            133,145,158,170,181,192,202,213,221,229,237,243,248,252,254,255,
            255,254,252,248,243,237,229,221,213,202,192,181,170,158,145,133,
            121,109,96,84,73,62,52,41,33,25,18,11,6,3,1,0};
        const unsigned alpha=100+wave[(phase>>2)&63]/3;
        for(int tile=0;tile<9;tile++) {
            float x=18+(tile%3)*29,y=18+(tile/3)*29;
            const uint32_t fill=(tile==0 || tile==4 || tile==8)?rgb:0x18282C;
            const uint32_t border=(tile==0 || tile==4 || tile==8)?rgb:
                tone(rgb,alpha)+tone(fill,255-alpha);
            mesh(WS_APP_TILE_MESH,rgb,200.f/120.f,x-60,y-60,border,fill,(tile==0 || tile==4 || tile==8)?0:1);
        }
    }
    void icon(unsigned id,uint32_t rgb,float spin) {
        if(id==0){logo(rgb,spin);return;}
        // Source coordinates, radii, stroke widths and cut-outs match the
        // original build_*_icon functions in ws_lvgl.c (70px icon surface).
        preserve_style=true;
        switch(id) {
        case 1:
            ring(35,35,27,26,tone(rgb,51));ring(35,35,20,19,tone(rgb,51));
            arc(35,35,27,4,spin/2,92,rgb,-.2f);
            arc(35,35,20,2,-spin*3/8,58,tone(rgb,153),-.2f);break;
        case 2:
            ring(35,35,23,21,rgb);ring(35,35,7,0,rgb);
            stroke(52,48,61,55,2,rgb);stroke(58,35,68,35,2,rgb);stroke(47,57,49,67,2,rgb);break;
        case 3:stroke(16,35,29,49,5,rgb);stroke(29,49,55,18,5,rgb);break;
        case 4:stroke(18,18,52,52,4,rgb);stroke(52,18,18,52,4,rgb);break;
        case 5:ring(35,35,22,19,rgb);stroke(35,35,35,20,3,rgb);stroke(35,35,47,43,3,rgb);break;
        case 6:
            ring(35,19,12,9,rgb);panel(17,23,36,31,6,2,rgb,51,-2);
            ring(35,37,3,0,0,-3);stroke(35,40,35,51,3,0,-3);break;
        case 7:ring(34,35,22,0,rgb);ring(48,25,20,0,0,-2);break;
        case 8:stroke(35,15,35,43,4,rgb);ring(35,55,4,0,rgb);break;
        case 9:
            panel(21,10,28,36,5,2,rgb,51);
            panel(27,18,5,10,1,0,rgb,255,-1);panel(38,18,5,10,1,0,rgb,255,-1);
            stroke(35,46,35,61,3,rgb);break;
        default:break;
        }
    }
};
unsigned average(unsigned sum,unsigned n) {
    sum+=n/2;
    switch(n){case 1:return sum;case 2:return sum>>1;case 3:return (sum*21846U)>>16;default:return sum>>2;}
}
void convert(int side,int rows,uint8_t *out,const uint16_t *colors=color_buffer,const uint16_t *depths=depth_buffer,int first=0,int last=-1) {
    int wide=side*SAMPLE;
    if(last<0)last=side-1;
    for(int y=0;y<rows;y++)for(int x=first;x<=last;x++){
        const int base=y*SAMPLE*wide+x*SAMPLE;
        const int dest=(y*side+x)*3;
        if(depths[base]==65535 && depths[base+1]==65535 &&
           depths[base+wide]==65535 && depths[base+wide+1]==65535){
            out[dest]=out[dest+1]=out[dest+2]=0;continue;
        }
        if(depths[base]!=65535 && depths[base+1]!=65535 &&
           depths[base+wide]!=65535 && depths[base+wide+1]!=65535 &&
           colors[base]==colors[base+1] && colors[base]==colors[base+wide] && colors[base]==colors[base+wide+1]){
            out[dest]=uint8_t(colors[base]>>8);out[dest+1]=uint8_t(colors[base]);out[dest+2]=255;continue;
        }
        unsigned r=0,g=0,b=0,n=0;
        for(int yy=0;yy<SAMPLE;yy++)for(int xx=0;xx<SAMPLE;xx++){
            int k=(y*SAMPLE+yy)*wide+x*SAMPLE+xx;
            if(depths[k]==65535)continue;uint16_t c=colors[k];
            r+=(c>>11)&31;g+=(c>>5)&63;b+=c&31;n++;
        }
        uint16_t c=n?uint16_t((average(r,n)<<11)|(average(g,n)<<5)|average(b,n)):0;
        int k=(y*side+x)*3;
        // LV_COLOR_16_SWAP=1: memory byte order is panel RGB565 MSB first.
        out[k]=uint8_t(c>>8);out[k+1]=uint8_t(c);out[k+2]=uint8_t((n*255+2)/4);
    }
}
struct RasterBand {
    int side,first,end,rows;
    uint8_t *out;
    RowRange *old_rows;
    uint16_t *colors,*depths;
    Renderer::OpaqueUICursor *cursors;
    const uint16_t *starts;
    bool detail;
    uint32_t raster_us=0,convert_us=0,converted_samples=0;
};
void rasterize_band(void *opaque) {
    auto &cs=*static_cast<RasterBand*>(opaque);
    const int side=cs.side,tile_rows=cs.rows;
    auto *out=cs.out;auto *old_rows=cs.old_rows;
    auto *color_buffer=cs.colors,*depth_buffer=cs.depths;
    auto *scan_states=cs.cursors;
    const auto *starts=cs.starts;const bool frame_detail=cs.detail;
    const int wide=side*SAMPLE;
    // Conversion overwrites every pixel in its current row span. Only old
    // pixels outside that span need a separate PSRAM write.
    auto clear_old=[&](int y,int first,int last){
        auto old=old_rows[y];
        if(old.last>=old.first){
            if(first>last){memset(out+(y*side+old.first)*3,0,(old.last-old.first+1)*3);old_rows[y]={int16_t(first),int16_t(last)};return;}
            const int left=std::min<int>(old.last,first-1),right=std::max<int>(old.first,last+1);
            if(left>=old.first)memset(out+(y*side+old.first)*3,0,(left-old.first+1)*3);
            if(right<=old.last)memset(out+(y*side+right)*3,0,(old.last-right+1)*3);
        }
        old_rows[y]={int16_t(first),int16_t(last)};
    };
    uint32_t active[(MAX_TRIANGLES+31)/32]{};
    for(unsigned i=0;i<triangle_count;i++){
        scan_states[i].initialized=false;
        const auto &t=triangles[i];
        if(t.max_y<0 || t.min_y>=wide || t.max_x<0 || t.min_x>=wide)continue;
        // Faces beginning above this band are already active. A fresh cursor
        // replays the integer recurrence from min_y to its first owned tile;
        // assigning cursor.y=first would discard edge/depth residuals.
        if(std::max(0,int(t.min_y))/tile_rows<cs.first/tile_rows && t.max_y>=cs.first)
            active[i/32]|=uint32_t(1)<<(i%32);
    }
    for(int top=cs.first;top<cs.end;top+=tile_rows) {
        const uint64_t raster_start=frame_detail?micros_now():0;
        for(unsigned i=starts[top/tile_rows];i!=UINT16_MAX;i=band_next[i])
            active[i/32]|=uint32_t(1)<<(i%32);
        int left=wide,right=-1;
        for(unsigned word=0;word<(triangle_count+31)/32;word++){
            uint32_t pending=active[word];
            while(pending){
                const unsigned bit=unsigned(__builtin_ctz(pending)),mask=uint32_t(1)<<bit;pending&=~mask;
                const auto &t=triangles[word*32+bit];
                if(t.max_y<top){active[word]&=~mask;continue;}
                left=std::min(left,std::max(0,int(t.min_x)));right=std::max(right,std::min(wide-1,int(t.max_x)));
            }
        }
        if(left>right){for(int y=top/SAMPLE;y<(top+tile_rows)/SAMPLE;++y)clear_old(y,side,-1);continue;}
        for(int y=top/SAMPLE;y<(top+tile_rows)/SAMPLE;++y)clear_old(y,left/SAMPLE,right/SAMPLE);
        left=(left/SAMPLE)*SAMPLE;right=std::min(wide-1,(right/SAMPLE+1)*SAMPLE-1);
        for(int y=0;y<tile_rows;y++)memset(depth_buffer+y*wide+left,255,(right-left+1)*sizeof(uint16_t));
        for(unsigned word=0;word<(triangle_count+31)/32;word++){
            uint32_t pending=active[word];
            while(pending){const unsigned bit=unsigned(__builtin_ctz(pending));pending&=~(uint32_t(1)<<bit);const unsigned i=word*32+bit;
                Renderer::drawOpaqueUIContinued(triangles[i],scan_states[i],color_buffer,depth_buffer,wide,tile_rows,top);
            }
        }
        const uint64_t convert_start=frame_detail?micros_now():0;if(frame_detail)cs.raster_us+=uint32_t(convert_start-raster_start);
        convert(side,tile_rows/SAMPLE,out+(top/SAMPLE)*side*3,color_buffer,depth_buffer,left/SAMPLE,right/SAMPLE);
        if(frame_detail)cs.convert_us+=uint32_t(micros_now()-convert_start);
        cs.converted_samples+=(right-left+1)*tile_rows;
    }
}
bool rasterize(int side,uint8_t *out) {
    if(triangle_overflow)return false;
    const int wide=side*SAMPLE;
    Bounds current;
    uint16_t starts[MAX_BANDS];std::fill_n(starts,MAX_BANDS,UINT16_MAX);
    // The owner prepares immutable face membership once. Both jobs traverse
    // faces in the original primitive order and write only their image rows.
    for(unsigned i=0;i<triangle_count;++i){
        const auto &t=triangles[i];
        if(t.max_y<0 || t.min_y>=wide || t.max_x<0 || t.min_x>=wide)continue;
        const int first=std::max(0,int(t.min_y))/tile_rows;
        band_next[i]=starts[first];starts[first]=uint16_t(i);
        current.x0=std::min(current.x0,std::max(0,int(t.min_x))/SAMPLE);
        current.x1=std::max(current.x1,std::min(wide-1,int(t.max_x))/SAMPLE);
        current.y0=std::min(current.y0,std::max(0,int(t.min_y))/SAMPLE);
        current.y1=std::max(current.y1,std::min(wide-1,int(t.max_y))/SAMPLE);
    }
    RasterBand first{side,0,wide,tile_rows,out,previous_rows+rendering_channel*MAX_SIDE,
        color_buffer,depth_buffer,scan_states,starts,frame_detail};
    EkRenderWorkerStats pool{};ek_render_worker_stats(&pool);
    RasterBand second{};
    if(parallel_storage && pool.ready && pool.enabled){
        first.end=((wide/tile_rows+1)/2)*tile_rows;
        second={side,first.end,wide,tile_rows,out,first.old_rows,
            parallel_storage->colors,parallel_storage->depths,
            parallel_storage->cursors,starts,frame_detail};
        ek_render_parallel(rasterize_band,&first,&second);
    }else rasterize_band(&first);
    // All jobs have joined before owner metadata, effects or publication.
    previous_bounds[rendering_channel]=current;stats.triangles=triangle_count;
    auto &cs=channel_stats[rendering_channel];
    if(frame_detail){cs.raster_us=std::max(first.raster_us,second.raster_us);
        cs.convert_us=std::max(first.convert_us,second.convert_us);}
    cs.converted_samples=first.converted_samples+second.converted_samples;
#ifdef WS_3D_HOST
    if(std::getenv("EVILKEY_VERIFY_TILED")) {
        // Host-only full-frame reference: same Jet kernel and projected faces.
        // Verify band clipping preserves depth/coverage/color at every boundary.
        static uint16_t colors[STRIDE*STRIDE],depths[STRIDE*STRIDE];
        static uint8_t reference[MAX_SIDE*MAX_SIDE*3];
        memset(depths,255,wide*wide*sizeof(uint16_t));
        for(unsigned i=0;i<triangle_count;i++) {
            Renderer::drawOpaqueUI(triangles[i],colors,depths,wide,wide,0);
        }
        convert(side,side,reference,colors,depths);
        assert(memcmp(reference,out,side*side*3)==0);
    }
#endif
    return true;
}
}
extern "C" bool ws_gui_3d_init(void) {
    if(stats.ready)return true;
#ifdef WS_3D_HOST
    if(std::getenv("EVILKEY_TEST_3D_FALLBACK"))return false;
#endif
    // PSRAM only: never compete with internal TinyUSB/DMA allocations.
    color_buffer=(uint16_t*)heap_caps_malloc(STRIDE*TILE_ROWS*2,MALLOC_CAP_SPIRAM|MALLOC_CAP_8BIT);
    depth_buffer=(uint16_t*)heap_caps_malloc(STRIDE*TILE_ROWS*2,MALLOC_CAP_SPIRAM|MALLOC_CAP_8BIT);
    triangles=(ProjectedTriangle*)heap_caps_malloc(MAX_TRIANGLES*sizeof(ProjectedTriangle),MALLOC_CAP_SPIRAM|MALLOC_CAP_8BIT);
    band_next=(uint16_t*)heap_caps_malloc(MAX_TRIANGLES*sizeof(uint16_t),MALLOC_CAP_SPIRAM|MALLOC_CAP_8BIT);
    projected_vertices=(Renderer::UIVertex*)heap_caps_malloc(MAX_MESH_VERTICES*sizeof(Renderer::UIVertex),MALLOC_CAP_SPIRAM|MALLOC_CAP_8BIT);
    scan_states=(Renderer::OpaqueUICursor*)heap_caps_malloc(MAX_TRIANGLES*sizeof(Renderer::OpaqueUICursor),MALLOC_CAP_SPIRAM|MALLOC_CAP_8BIT);
    normal_light=(float*)heap_caps_malloc(MAX_NORMALS*2*sizeof(float),MALLOC_CAP_SPIRAM|MALLOC_CAP_8BIT);
    shade_colors=(uint16_t*)heap_caps_malloc(MAX_SHADES*2*sizeof(uint16_t),MALLOC_CAP_SPIRAM|MALLOC_CAP_8BIT);
    transformed_tile=(V*)heap_caps_malloc(65*sizeof(V),MALLOC_CAP_SPIRAM|MALLOC_CAP_8BIT);
    previous_rows=(RowRange*)heap_caps_malloc(WS_3D_CHANNELS*MAX_SIDE*sizeof(RowRange),MALLOC_CAP_SPIRAM|MALLOC_CAP_8BIT);
    if(previous_rows)for(unsigned i=0;i<WS_3D_CHANNELS*MAX_SIDE;++i)previous_rows[i]={MAX_SIDE,-1};
    bool ok=color_buffer&&depth_buffer&&triangles&&band_next&&projected_vertices&&scan_states&&normal_light&&shade_colors&&previous_rows&&transformed_tile;
    for(unsigned i=0;i<WS_3D_CHANNELS;i++){images[i]=(uint8_t*)heap_caps_malloc(sizes[i]*sizes[i]*3,MALLOC_CAP_SPIRAM|MALLOC_CAP_8BIT);ok=ok&&images[i];if(images[i])memset(images[i],0,sizes[i]*sizes[i]*3);}
    if(!ok){heap_caps_free(transformed_tile);transformed_tile=nullptr;heap_caps_free(previous_rows);previous_rows=nullptr;heap_caps_free(scan_states);heap_caps_free(normal_light);heap_caps_free(shade_colors);scan_states=nullptr;normal_light=nullptr;shade_colors=nullptr;heap_caps_free(projected_vertices);projected_vertices=nullptr;heap_caps_free(color_buffer);heap_caps_free(depth_buffer);heap_caps_free(triangles);heap_caps_free(band_next);color_buffer=depth_buffer=nullptr;triangles=nullptr;band_next=nullptr;
        for(auto &p:images){heap_caps_free(p);p=nullptr;}return false;}
    stats.psram_bytes=STRIDE*TILE_ROWS*4+MAX_TRIANGLES*(sizeof(ProjectedTriangle)+sizeof(uint16_t))+MAX_MESH_VERTICES*sizeof(Renderer::UIVertex);
    stats.psram_bytes+=MAX_TRIANGLES*(sizeof(Renderer::OpaqueUICursor))+MAX_NORMALS*2*sizeof(float)+MAX_SHADES*2*sizeof(uint16_t)+WS_3D_CHANNELS*MAX_SIDE*sizeof(RowRange)+65*sizeof(V);
    for(int side:sizes)stats.psram_bytes+=side*side*3;
    // One optional private helper set, allocated once. Failure keeps the
    // original complete serial renderer and its existing allocation contract.
#ifdef WS_3D_HOST
    if(!std::getenv("EVILKEY_TEST_3D_PARALLEL_ALLOC_FAIL"))
#endif
    parallel_storage=(ParallelStorage*)heap_caps_malloc(sizeof(ParallelStorage),MALLOC_CAP_SPIRAM|MALLOC_CAP_8BIT);
    if(parallel_storage)stats.psram_bytes+=sizeof(ParallelStorage);
    presentation_stats.tile_rows=tile_rows;stats.ready=true;
    return true;
}
extern "C" bool ws_gui_3d_render(unsigned channel,uint16_t phase,uint32_t accent,unsigned icon,ws_gui_3d_frame_t *out) {
    if(channel>=WS_3D_CHANNELS||!out||!stats.ready)return false;
    int side=sizes[channel];phase&=255;
    // Status symbols must remain readable, including during page transitions.
    // Only the saver, Settings and Apps use the animated 3D pose.
    const bool status_icon=channel==WS_3D_HERO;
    if(status_icon)phase=0;
    const int16_t pose_depth=status_icon?0:transition_depth;
    *out={images[channel],uint16_t(side),uint16_t(side),generations[channel]};
    if(valid[channel]&&last_phase[channel]==phase&&last_accent[channel]==accent&&last_icon[channel]==icon&&last_depth[channel]==pose_depth){channel_stats[channel].cache_hits++;return true;}
    uint64_t start=micros_now();stats.triangles=0;rendering_channel=channel;
    frame_detail=detail_profile || (channel_stats[channel].frames%8==0);
    triangle_count=0;triangle_overflow=false;
    float t=phase*2*PI/256;
    Painter p(side,status_icon?0:.40f*sinf(t)+pose_depth*.001f,
        status_icon?0:.24f*sinf(2*t+PI/3),status_icon?0:.11f*sinf(t+PI/5));
    if(channel==WS_3D_HERO && icon==0)p.scale=68.f/200.f;
    if(channel==WS_3D_GEAR)p.gear(accent);else if(channel==WS_3D_APPS)p.apps(accent,phase);
    else p.icon(channel==WS_3D_SAVER?0:icon,accent,t*2);
    if(frame_detail)channel_stats[channel].geometry_us=uint32_t(micros_now()-start);
    if(!rasterize(side,images[channel]))return false;
    if(channel==WS_3D_SAVER && ((phase>=62&&phase<70)||(phase>=190&&phase<198))){
        uint8_t row[MAX_SIDE*3];
        int shift=((phase&7)<4)?3:-3;
        for(int y=58;y<73;y++){uint8_t *dst=images[channel]+y*side*3;memcpy(row,dst,side*3);memset(dst,0,side*3);
            for(int x=0;x<side;x++){int from=x-shift;if(from>=0&&from<side)memcpy(dst+x*3,row+from*3,3);}
            if(y==58)for(int x=37;x<164;x++){dst[x*3]=0xF8;dst[x*3+1]=0x0A;dst[x*3+2]=180;}}
        for(int y=58;y<73;++y)previous_rows[channel*MAX_SIDE+y]={0,int16_t(side-1)};
        auto &bounds=previous_bounds[channel];bounds.x0=0;bounds.x1=side-1;
        bounds.y0=std::min(bounds.y0,58);bounds.y1=std::max(bounds.y1,72);
    }
    last_phase[channel]=phase;last_accent[channel]=accent;last_icon[channel]=icon;last_depth[channel]=pose_depth;valid[channel]=true;
    stats.frames++;stats.last_us=uint32_t(micros_now()-start);stats.peak_us=std::max(stats.peak_us,stats.last_us);
    auto &cs=channel_stats[channel];cs.last_us=stats.last_us;cs.peak_us=std::max(cs.peak_us,cs.last_us);
    cs.detail_sample=frame_detail;if(frame_detail)++cs.detail_samples;
    cs.triangles=triangle_count;timings[channel][cs.frames%32]=cs.last_us;cs.frames++;
    ++generations[channel];out->generation=generations[channel];
    return true;
}
extern "C" void ws_gui_3d_profile(bool enabled){detail_profile=enabled;}
extern "C" ws_gui_3d_stats_t ws_gui_3d_stats(void){return stats;}
extern "C" ws_gui_3d_channel_stats_t ws_gui_3d_channel_stats(unsigned channel){
    if(channel>=WS_3D_CHANNELS)return {};
    auto result=channel_stats[channel];percentiles(timings[channel],result.frames,result.p50_us,result.p95_us);return result;
}
static void collect_frames(){
    // Consume completed mailboxes only on the display owner. ISR never sorts
    // samples, touches renderer buffers or calls LVGL beyond flush_ready.
    for(auto &f:frame_stamps){
        FRAME_LOCK();FrameStamp finished=f;
        if(f.closed && f.complete)f={};else finished.id=0;
        FRAME_UNLOCK();
        if(!finished.id)continue;
        if(!finished.success){++presentation_stats.failed_frames;continue;}
        presentation_stats.compose_us=finished.compose;
        presentation_stats.peak_compose_us=std::max(presentation_stats.peak_compose_us,finished.compose);
        // A display-owner tick with no dirty pixels is not a presented frame.
        // Keep CPU timing, but do not dilute DMA percentiles or erase the last
        // completed transfer's byte/flush counters with idle ticks.
        if(!finished.flushes)continue;
        presentation_stats.panel_wait_us=finished.wait;
        presentation_stats.lvgl_wait_us=finished.lvgl_wait;
        presentation_stats.peak_lvgl_wait_us=std::max(presentation_stats.peak_lvgl_wait_us,finished.lvgl_wait);
        presentation_stats.peak_panel_wait_us=std::max(presentation_stats.peak_panel_wait_us,finished.wait);
        presentation_stats.frame_us=finished.end-finished.start;
        presentation_stats.peak_frame_us=std::max(presentation_stats.peak_frame_us,presentation_stats.frame_us);
        presentation_stats.flushes=finished.flushes;presentation_stats.bytes=finished.bytes;
        presentation_timings[presentation_count%32]=presentation_stats.frame_us;++presentation_count;
        ++presentation_stats.frames;
    }
}
extern "C" ws_gui_3d_presentation_stats_t ws_gui_3d_presentation_stats(void){
    collect_frames();auto result=presentation_stats;percentiles(presentation_timings,presentation_count,result.p50_us,result.p95_us);return result;
}
extern "C" uint32_t ws_gui_3d_frame_begin(uint32_t start){
    collect_frames();
    if(++next_frame_id==0)++next_frame_id;
    FRAME_LOCK();frame_stamps[next_frame_id%4]={next_frame_id,start,0,0,0,0,0,0,false,false,true};FRAME_UNLOCK();
    (void)ws_gui_3d_take_lvgl_wait();
    (void)ws_gui_3d_take_panel_wait();return next_frame_id;
}
extern "C" void ws_gui_3d_frame_flush(uint32_t id,uint32_t bytes){
    if(!id)return;
    FRAME_LOCK();auto &f=frame_stamps[id%4];if(f.id==id){++f.flushes;f.bytes+=bytes;}FRAME_UNLOCK();
}
extern "C" void ws_gui_3d_frame_complete(uint32_t id,uint32_t end){
    if(!id)return;
    FRAME_ISR_LOCK();auto &f=frame_stamps[id%4];if(f.id==id){f.end=end;f.complete=true;}FRAME_ISR_UNLOCK();
}
extern "C" void ws_gui_3d_frame_end(uint32_t id,uint32_t end,uint32_t wait,bool success){
    if(!id)return;
    FRAME_LOCK();auto &f=frame_stamps[id%4];if(f.id==id){
        f.compose=end-f.start;f.wait=wait;f.lvgl_wait=ws_gui_3d_take_lvgl_wait();f.closed=true;f.success=success;
        if(!f.flushes || !success){f.complete=true;f.end=end;}
        // A synchronous completion can precede composition finishing.
        if(f.complete && uint32_t(f.end-f.start)<f.compose)f.end=end;
    }FRAME_UNLOCK();
    collect_frames();
}
extern "C" void ws_gui_3d_record_panel_wait(uint32_t wait){panel_wait_accumulated+=wait;}
extern "C" uint32_t ws_gui_3d_take_panel_wait(void){uint32_t result=panel_wait_accumulated;panel_wait_accumulated=0;return result;}
extern "C" void ws_gui_3d_record_lvgl_wait(uint32_t wait){lvgl_wait_accumulated+=wait;ws_gui_3d_record_panel_wait(wait);}
extern "C" uint32_t ws_gui_3d_take_lvgl_wait(void){uint32_t value=lvgl_wait_accumulated;lvgl_wait_accumulated=0;return value;}
extern "C" void ws_gui_3d_configure_tiles(void){
    if(!stats.ready || presentation_stats.internal_tiles)return;
    // Optional 4-row SRAM tiles; leave >=40KiB free and a >=24KiB block.
    constexpr size_t bytes=STRIDE*4*sizeof(uint16_t),reserve=40*1024,block=24*1024;
    const int caps=MALLOC_CAP_INTERNAL|MALLOC_CAP_8BIT;
    if(heap_caps_get_free_size(caps)<reserve+2*bytes || heap_caps_get_largest_free_block(caps)<block+2*bytes)return;
    auto a=(uint16_t*)heap_caps_malloc(bytes,caps),b=(uint16_t*)heap_caps_malloc(bytes,caps);
    if(!a || !b || heap_caps_get_free_size(caps)<reserve || heap_caps_get_largest_free_block(caps)<block){heap_caps_free(a);heap_caps_free(b);return;}
    heap_caps_free(color_buffer);heap_caps_free(depth_buffer);color_buffer=a;depth_buffer=b;tile_rows=4;
    stats.psram_bytes-=STRIDE*TILE_ROWS*4;presentation_stats.internal_tiles=true;presentation_stats.tile_rows=4;
}
extern "C" void ws_gui_3d_transition(int16_t depth){transition_depth=std::clamp<int16_t>(depth,-160,160);}
#ifdef WS_3D_HOST
extern "C" int ws_gui_3d_project_round(float x){return projection_round(x);}
extern "C" bool ws_gui_3d_reference(unsigned channel,unsigned icon,uint32_t accent,ws_gui_3d_frame_t *out) {
    if(channel>=WS_3D_CHANNELS || !stats.ready || !out)return false;
    int side=sizes[channel];
    triangle_count=0;triangle_overflow=false;
    Painter p(side,0,0,0);
    if(channel==WS_3D_HERO && icon==0)p.scale=68.f/200.f;
    if(channel==WS_3D_GEAR)p.gear(accent);else if(channel==WS_3D_APPS)p.apps(accent);
    else p.icon(icon,accent,0);
    rendering_channel=channel;if(!rasterize(side,images[channel]))return false;valid[channel]=false;
    *out={images[channel],uint16_t(side),uint16_t(side),generations[channel]};return true;
}
#endif
