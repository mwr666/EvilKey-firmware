/* SPDX-License-Identifier: MIT
 * EvilKey extension to Jet: bounded, preprojected opaque RGB565 triangles.
 * Exact integer edge coverage and affine per-pixel depth; no material dispatch
 * or pixel-wise barycentric multiplication. Geometry setup is reused by bands.
 */
#pragma once
#include <algorithm>
#include <cstdint>
#include <climits>
#include <cstdlib>

#if WS_GUI_3D_LOCAL_O2 && defined(__GNUC__)
#pragma GCC push_options
#pragma GCC optimize ("O2")
#endif

namespace Renderer {
struct UIVertex { int16_t x,y; uint16_t z; };
struct OpaqueUIFace {
    UIVertex v[3]; uint16_t color;
    int16_t min_x,max_x,min_y,max_y;
    int32_t area,base_z,dz_dx,dz_dy;
    int32_t edge_dx[3],edge_dy[3],step,step_rem;
    bool narrow;
};

inline bool prepareOpaqueUI(OpaqueUIFace &t) {
    const auto &a=t.v[0], &b=t.v[1], &c=t.v[2];
    // The frontend bounds projected coordinates to this range. Products fit
    // int32; depth setup uses int64 to retain exact slopes.
    for(const auto &v:t.v) if(v.x < -2048 || v.x > 2048 || v.y < -2048 || v.y > 2048 || !v.z || v.z > 60000) return false;
    t.area=(b.x-a.x)*(c.y-a.y)-(b.y-a.y)*(c.x-a.x);
    if(t.area<=0)return false;
    t.min_x=std::min({a.x,b.x,c.x});t.max_x=std::max({a.x,b.x,c.x});
    t.min_y=std::min({a.y,b.y,c.y});t.max_y=std::max({a.y,b.y,c.y});
    t.base_z=std::min({a.z,b.z,c.z});
    const int32_t za=a.z-t.base_z,zb=b.z-t.base_z,zc=c.z-t.base_z;
    const int64_t dx=int64_t(za)*(b.y-c.y)+int64_t(zb)*(c.y-a.y)+int64_t(zc)*(a.y-b.y);
    const int64_t dy=int64_t(za)*(c.x-b.x)+int64_t(zb)*(a.x-c.x)+int64_t(zc)*(b.x-a.x);
    if(dx<INT32_MIN || dx>INT32_MAX || dy<INT32_MIN || dy>INT32_MAX)return false;
    t.dz_dx=int32_t(dx);t.dz_dy=int32_t(dy);
    t.edge_dx[0]=b.y-c.y;t.edge_dx[1]=c.y-a.y;t.edge_dx[2]=a.y-b.y;
    t.edge_dy[0]=c.x-b.x;t.edge_dy[1]=a.x-c.x;t.edge_dy[2]=b.x-a.x;
    t.step=t.dz_dx/t.area;t.step_rem=t.dz_dx%t.area;
    if(t.step_rem<0){t.step--;t.step_rem+=t.area;}
    const int32_t range=std::max({za,zb,zc});
    // A covered sample has nonnegative weights summing to area. Every term
    // and partial sum therefore fits this bound; clipping is checked first.
    t.narrow=int64_t(range)*t.area<=INT32_MAX;
    return true;
}

inline void drawOpaqueUI(const OpaqueUIFace &t,uint16_t *colors,uint16_t *depths,
                         int width,int height,int band_top) {
    const int x0=std::max(0,int(t.min_x)),x1=std::min(width-1,int(t.max_x));
    const int y0=std::max(band_top,int(t.min_y)),y1=std::min(band_top+height-1,int(t.max_y));
    if(x0>x1 || y0>y1)return;
    const auto &a=t.v[0], &b=t.v[1], &c=t.v[2];
    const auto &dx=t.edge_dx;const auto &dy=t.edge_dy;
    int w[3]={dx[0]*(x0-c.x)+dy[0]*(y0-c.y),
              dx[1]*(x0-c.x)+dy[1]*(y0-c.y),0};
    w[2]=t.area-w[0]-w[1];
    // Euclidean depth increment: one quotient/remainder per face, then exact
    // addition/carry per sample. A negative slope needs floor division here.
    const int32_t step=t.step,step_rem=t.step_rem;
    int64_t row_residual=0;
    if(!t.narrow) row_residual=int64_t(a.z-t.base_z)*w[0]+
        int64_t(b.z-t.base_z)*w[1]+int64_t(c.z-t.base_z)*w[2];
    for(int y=y0;y<=y1;y++,w[0]+=dy[0],w[1]+=dy[1],w[2]+=dy[2]) {
        const int64_t row_start=row_residual;if(!t.narrow)row_residual+=t.dz_dy;
        int first=0,last=x1-x0;
        for(int k=0;k<3 && first<=last;k++) {
            if(dx[k]>0 && w[k]<0) first=std::max(first,int((-w[k]+dx[k]-1)/dx[k]));
            else if(dx[k]<0) { if(w[k]<0)last=-1;else last=std::min(last,int(w[k]/-dx[k])); }
            else if(dx[k]==0 && w[k]<0)last=-1;
        }
        if(first>last)continue;
        int index=(y-band_top)*width+x0+first;
        int32_t quotient,remainder;
        if(t.narrow) {
            const int32_t n=(a.z-t.base_z)*(w[0]+first*dx[0])+
                (b.z-t.base_z)*(w[1]+first*dx[1])+
                (c.z-t.base_z)*(w[2]+first*dx[2]);
            quotient=n/t.area;remainder=n-quotient*t.area;
        } else {
            const int64_t residual=row_start+int64_t(first)*t.dz_dx;
            quotient=int32_t(residual/t.area);
            remainder=int32_t(residual-int64_t(quotient)*t.area);
        }
        int32_t z=t.base_z+quotient;
        for(int x=first;x<=last;x++,index++) {
            if(z<=depths[index]) {depths[index]=uint16_t(z);colors[index]=t.color;}
            z+=step;remainder+=step_rem;
            if(remainder>=t.area){remainder-=t.area;z++;}
        }
    }
}

// Persistent Euclidean scan state. The display frontend allocates one per
// queued face in PSRAM, never on the display task's small stack.
struct UIQuotient { int32_t q,r,dq,dr; };
struct OpaqueUICursor {
    UIQuotient edge[3],depth;
    int32_t y,x0,x1,depth_x;
    bool initialized,fast;
};
inline void uiFloor(int64_t n,int32_t d,int32_t &q,int32_t &r) {
    q=int32_t(n/d);r=int32_t(n-int64_t(q)*d);
    if(r<0){--q;r+=d;}
}
inline void uiAdvance(UIQuotient &s,int32_t d) {
    s.q+=s.dq;s.r+=s.dr;
    if(s.r>=d){s.r-=d;++s.q;}
}
inline void uiOffset(int32_t &q,int32_t &r,int32_t dq,int32_t dr,int32_t d,int count) {
    // Small changes of the left endpoint are usual. Binary doubling also
    // handles a clipped thin face without per-row division or a long loop.
    if(count<0){count=-count;dq=-dq;if(dr){--dq;dr=d-dr;}}
    while(count){
        if(count&1){q+=dq;r+=dr;if(r>=d){r-=d;++q;}}
        count>>=1;if(!count)break;
        dq+=dq;dr+=dr;if(dr>=d){dr-=d;++dq;}
    }
}
inline void beginOpaqueUI(const OpaqueUIFace &t,OpaqueUICursor &s,int width) {
    s={};s.initialized=true;s.y=std::max(0,int(t.min_y));
    s.x0=std::max(0,int(t.min_x));s.x1=std::min(width-1,int(t.max_x));s.depth_x=0;
    // Bound every intermediate of the 32-bit DDA, including extrapolation at
    // clipped endpoints. General steep/wide geometry retains the old path.
    s.fast=(int64_t(std::abs(int64_t(t.dz_dx)))+std::abs(int64_t(t.dz_dy)))*8192<=INT32_MAX;
    if(!s.fast || s.x0>s.x1)return;
    int32_t w[3];
    w[0]=t.edge_dx[0]*(s.x0-t.v[2].x)+t.edge_dy[0]*(s.y-t.v[2].y);
    w[1]=t.edge_dx[1]*(s.x0-t.v[2].x)+t.edge_dy[1]*(s.y-t.v[2].y);w[2]=t.area-w[0]-w[1];
    for(int k=0;k<3;++k){
        auto &e=s.edge[k];const int dx=t.edge_dx[k],dy=t.edge_dy[k];
        if(dx){const int d=std::abs(dx),sign=dx>0?-1:1;
            uiFloor(sign*w[k],d,e.q,e.r);uiFloor(sign*dy,d,e.dq,e.dr);
        }else{e.q=w[k];e.dq=dy;}
    }
    int64_t n=0;
    if(t.narrow && w[0]>=0 && w[1]>=0 && w[2]>=0){
        const int32_t covered=(t.v[0].z-t.base_z)*w[0]+(t.v[1].z-t.base_z)*w[1]+(t.v[2].z-t.base_z)*w[2];
        n=covered;
    }else n=int64_t(t.v[0].z-t.base_z)*w[0]+int64_t(t.v[1].z-t.base_z)*w[1]+int64_t(t.v[2].z-t.base_z)*w[2];
    uiFloor(n,t.area,s.depth.q,s.depth.r);
    uiFloor(t.dz_dy,t.area,s.depth.dq,s.depth.dr);
}
inline void drawOpaqueUIContinued(const OpaqueUIFace &t,OpaqueUICursor &s,
                                  uint16_t *colors,uint16_t *depths,int width,int height,int band_top) {
    if(!s.initialized)beginOpaqueUI(t,s,width);
    if(!s.fast){drawOpaqueUI(t,colors,depths,width,height,band_top);return;}
    if(s.x0>s.x1)return;
    const int end=std::min(band_top+height-1,int(t.max_y));
    for(;s.y<=end;++s.y){
        int first=0,last=s.x1-s.x0;
        for(int k=0;k<3;++k){const auto &e=s.edge[k];const int dx=t.edge_dx[k];
            if(dx>0)first=std::max(first,int(e.q+(e.r!=0)));
            else if(dx<0)last=std::min(last,int(e.q));
            else if(e.q<0)last=-1;
        }
        if(s.y>=band_top && first<=last){
            uiOffset(s.depth.q,s.depth.r,t.step,t.step_rem,t.area,first-s.depth_x);s.depth_x=first;
            int q=s.depth.q,r=s.depth.r,index=(s.y-band_top)*width+s.x0+first;
            for(int x=first;x<=last;++x,++index){
                const int z=t.base_z+q;
                if(z<=depths[index]){depths[index]=uint16_t(z);colors[index]=t.color;}
                q+=t.step;r+=t.step_rem;if(r>=t.area){r-=t.area;++q;}
            }
        }
        uiAdvance(s.depth,t.area);
        for(int k=0;k<3;++k){if(t.edge_dx[k])uiAdvance(s.edge[k],std::abs(t.edge_dx[k]));else s.edge[k].q+=s.edge[k].dq;}
    }
}
}
#if WS_GUI_3D_LOCAL_O2 && defined(__GNUC__)
#pragma GCC pop_options
#endif
