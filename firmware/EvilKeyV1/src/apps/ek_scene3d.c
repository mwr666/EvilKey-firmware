/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Bounded native rasterizer for ABI5 builtin scenes, independent of GUI Jet.
 * Native triangles with flat lighting, near clipping, screen clipping, depth
 * test and deterministic 2x reconstruction. No guest geometry or addresses. */
#include "ek_scene3d.h"
#include <math.h>
#include <stdlib.h>
#if defined(ARDUINO_ARCH_ESP32)
#include <esp_heap_caps.h>
#endif
typedef struct {float x,y,z;} V;
typedef struct {float x,y,d;} P;
struct EkScene3D {
    EvilKey3DScene scene;
    uint16_t colours[2][EK_SCENE_SCRATCH_PIXELS];
    uint16_t depth[EK_SCENE_SCRATCH_PIXELS];
    unsigned committed,cached_w,cached_h,rw,rh;
    V eye,right,up,forward;float factor;
    EkSceneClock clock;void *clock_user;uint64_t started;
    EkSceneStats stats;
};
static V v(float x,float y,float z){V a={x,y,z};return a;}
static V sub(V a,V b){return v(a.x-b.x,a.y-b.y,a.z-b.z);}
static V add(V a,V b){return v(a.x+b.x,a.y+b.y,a.z+b.z);}
static V mul(V a,float s){return v(a.x*s,a.y*s,a.z*s);}
static float dot(V a,V b){return a.x*b.x+a.y*b.y+a.z*b.z;}
static V cross(V a,V b){return v(a.y*b.z-a.z*b.y,a.z*b.x-a.x*b.z,a.x*b.y-a.y*b.x);}
static V unit(V a){return mul(a,1.f/sqrtf(dot(a,a)));}
static int expired(EkScene3D *r){
    if(r->clock && r->clock(r->clock_user)-r->started>=EK_SCENE_BUDGET_US)
        r->stats.status=EVILKEY_3D_TIMEOUT;
    return r->stats.status!=EVILKEY_3D_OK;
}
EkScene3D *ek_scene3d_create(void){
#if defined(ARDUINO_ARCH_ESP32)
    return (EkScene3D*)heap_caps_calloc(1,sizeof(EkScene3D),MALLOC_CAP_SPIRAM|MALLOC_CAP_8BIT);
#else
    return (EkScene3D*)calloc(1,sizeof(EkScene3D));
#endif
}
void ek_scene3d_destroy(EkScene3D *r){free(r);}
static uint16_t shade(uint16_t c,float k){
    unsigned red=(unsigned)(((c>>11)&31)*k),green=(unsigned)(((c>>5)&63)*k),blue=(unsigned)((c&31)*k);
    return (uint16_t)((red<<11)|(green<<5)|blue);
}
static int edge(int ax,int ay,int bx,int by,int x,int y){return (bx-ax)*(y-ay)-(by-ay)*(x-ax);}
static void raster(EkScene3D *r,P a,P b,P c,uint16_t colour){
    int ax=(int)(a.x*16),ay=(int)(a.y*16),bx=(int)(b.x*16),by=(int)(b.y*16),cx=(int)(c.x*16),cy=(int)(c.y*16);
    int area=edge(ax,ay,bx,by,cx,cy);if(!area)return;
    if(area<0){P t=b;b=c;c=t;int s=bx;bx=cx;cx=s;s=by;by=cy;cy=s;area=-area;}
    int x0=ax<bx?ax:bx;x0=x0<cx?x0:cx;x0=x0/16;if(x0<0)x0=0;
    int y0=ay<by?ay:by;y0=y0<cy?y0:cy;y0=y0/16;if(y0<0)y0=0;
    int x1=ax>bx?ax:bx;x1=x1>cx?x1:cx;x1=x1/16;if(x1>=(int)r->rw)x1=r->rw-1;
    int y1=ay>by?ay:by;y1=y1>cy?y1:cy;y1=y1/16;if(y1>=(int)r->rh)y1=r->rh-1;
    float inv=1.f/area;
    float da=(b.d-a.d)*inv,db=(c.d-a.d)*inv;
    uint16_t *pixels=r->colours[1-r->committed];
    for(int y=y0;y<=y1;y++){
        if(expired(r))return;
        unsigned tests=(unsigned)(x1-x0+1);
        if(x1<x0)continue;
        if(tests>EK_SCENE_MAX_PIXEL_TESTS-r->stats.pixel_tests){r->stats.status=EVILKEY_3D_WORK_LIMIT;return;}
        r->stats.pixel_tests+=tests;
        int ea=edge(bx,by,cx,cy,x0*16+8,y*16+8),eb=edge(cx,cy,ax,ay,x0*16+8,y*16+8),ec=edge(ax,ay,bx,by,x0*16+8,y*16+8);
        int sa=-(cy-by)*16,sb=-(ay-cy)*16,sc=-(by-ay)*16;
        float d=a.d+eb*da+ec*db,sd=sb*da+sc*db;
        unsigned index=(unsigned)y*r->rw+x0;
        for(int x=x0;x<=x1;x++,index++,ea+=sa,eb+=sb,ec+=sc,d+=sd){
            if(ea>=0 && eb>=0 && ec>=0){
                unsigned depth=(unsigned)(d<1?1:d>65535?65535:d);
                if(depth>r->depth[index]){r->depth[index]=(uint16_t)depth;pixels[index]=colour;}
            }
        }
    }
}
static float distance(P p,unsigned side,float bound){return side==0?p.x:side==1?bound-p.x:side==2?p.y:bound-p.y;}
static void clipped_screen(EkScene3D *r,P a,P b,P c,uint16_t colour){
    P storage[2][12];storage[0][0]=a;storage[0][1]=b;storage[0][2]=c;
    unsigned n=3,src=0;
    for(unsigned side=0;side<4;side++){
        unsigned count=0;float bound=side<2?(float)r->rw:(float)r->rh;
        P previous=storage[src][n-1];float pd=distance(previous,side,bound);
        for(unsigned i=0;i<n;i++){
            P q=storage[src][i];float qd=distance(q,side,bound);
            if((pd>=0)!=(qd>=0)){
                float t=pd/(pd-qd);P at={previous.x+(q.x-previous.x)*t,previous.y+(q.y-previous.y)*t,previous.d+(q.d-previous.d)*t};
                storage[1-src][count++]=at;
            }
            if(qd>=0)storage[1-src][count++]=q;
            previous=q;pd=qd;
        }
        if(count<3)return;src=1-src;n=count;
    }
    for(unsigned i=1;i+1<n && !expired(r);i++)raster(r,storage[src][0],storage[src][i],storage[src][i+1],colour);
}
static void triangle(EkScene3D *r,V a,V b,V c,EvilKey3DMaterial mat){
    if(expired(r))return;
    V normal=cross(sub(b,a),sub(c,a));float length=dot(normal,normal);
    if(length<1e-12f)return;
    V light=v(-.35f,.86f,.37f);float intensity=dot(normal,light)/sqrtf(length);
    /* Two-sided solids, stable brighter roof and visible walls. */
    intensity=fabsf(intensity);uint16_t colour=mat.flags?mat.rgb565:shade(mat.rgb565,.34f+.66f*intensity);
    V world[3]={a,b,c},near_poly[4];unsigned n=0;
    for(unsigned i=0;i<3;i++){
        V d=sub(world[i],r->eye);world[i]=v(dot(d,r->right),dot(d,r->up),dot(d,r->forward));
    }
    V prev=world[2];float pd=prev.z-.25f;
    for(unsigned i=0;i<3;i++){
        V q=world[i];float qd=q.z-.25f;
        if((pd>=0)!=(qd>=0))near_poly[n++]=add(prev,mul(sub(q,prev),pd/(pd-qd)));
        if(qd>=0)near_poly[n++]=q;prev=q;pd=qd;
    }
    if(n<3)return;
    P p[4];
    for(unsigned i=0;i<n;i++){
        V q=near_poly[i];float scale=r->scene.camera.projection?r->factor/q.z:r->factor;
        p[i]=(P){r->rw*.5f+q.x*scale,r->rh*.5f-q.y*scale,r->scene.camera.projection?16384.f/q.z:65535.f-q.z*256.f};
    }
    for(unsigned i=1;i+1<n;i++)clipped_screen(r,p[0],p[i],p[i+1],colour);
}
static V transformed(V a,const EvilKey3DObject *o,const float *cs){
    a=v(a.x*o->scale[0]/256.f,a.y*o->scale[1]/256.f,a.z*o->scale[2]/256.f);
    a=v(a.x,a.y*cs[0]-a.z*cs[1],a.y*cs[1]+a.z*cs[0]);
    a=v(a.x*cs[2]+a.z*cs[3],a.y,-a.x*cs[3]+a.z*cs[2]);
    a=v(a.x*cs[4]-a.y*cs[5],a.x*cs[5]+a.y*cs[4],a.z);
    return add(a,v(o->position[0]/256.f,o->position[1]/256.f,o->position[2]/256.f));
}
static void face(EkScene3D *r,const EvilKey3DObject *o,const float *cs,V a,V b,V c){
    triangle(r,transformed(a,o,cs),transformed(b,o,cs),transformed(c,o,cs),r->scene.materials[o->material]);
}
static void object(EkScene3D *r,const EvilKey3DObject *o){
    float cs[6];for(unsigned k=0;k<3;k++){float angle=o->rotation[k]*.0001745329252f;cs[2*k]=cosf(angle);cs[2*k+1]=sinf(angle);}
    if(o->model==EVILKEY_3D_BALL){
        V points[6]={v(.5f,0,0),v(-.5f,0,0),v(0,.5f,0),v(0,-.5f,0),v(0,0,.5f),v(0,0,-.5f)};
        static const uint8_t indices[8][3]={{2,4,0},{2,1,4},{2,5,1},{2,0,5},{3,0,4},{3,4,1},{3,1,5},{3,5,0}};
        for(unsigned i=0;i<8 && !expired(r);i++){
            V a=points[indices[i][0]],b=points[indices[i][1]],c=points[indices[i][2]];
            V ab=mul(unit(add(a,b)),.5f),bc=mul(unit(add(b,c)),.5f),ca=mul(unit(add(c,a)),.5f);
            face(r,o,cs,a,ab,ca);face(r,o,cs,ab,b,bc);face(r,o,cs,ca,bc,c);face(r,o,cs,ab,bc,ca);
        }
    }else{
        V p[8]={v(-.5f,-.5f,-.5f),v(.5f,-.5f,-.5f),v(.5f,-.5f,.5f),v(-.5f,-.5f,.5f),v(-.5f,.5f,-.5f),v(.5f,.5f,-.5f),v(.5f,.5f,.5f),v(-.5f,.5f,.5f)};
        static const uint8_t faces[12][3]={{4,7,6},{4,6,5},{0,1,2},{0,2,3},{0,4,5},{0,5,1},{1,5,6},{1,6,2},{2,6,7},{2,7,3},{3,7,4},{3,4,0}};
        if(o->model==EVILKEY_3D_PLANE){face(r,o,cs,v(-.5f,0,-.5f),v(-.5f,0,.5f),v(.5f,0,.5f));face(r,o,cs,v(-.5f,0,-.5f),v(.5f,0,.5f),v(.5f,0,-.5f));}
        else if(o->model==EVILKEY_3D_PYRAMID){for(unsigned i=0;i<4;i++)face(r,o,cs,p[i],v(0,.5f,0),p[(i+1)%4]);face(r,o,cs,p[0],p[2],p[1]);face(r,o,cs,p[0],p[3],p[2]);}
        else for(unsigned i=0;i<12 && !expired(r);i++)face(r,o,cs,p[faces[i][0]],p[faces[i][1]],p[faces[i][2]]);
    }
}
EkSceneStats ek_scene3d_render(EkScene3D *r,const uint8_t *scene,uint16_t *dst,
    unsigned stride,unsigned x,unsigned y,unsigned w,unsigned h,EkSceneClock clock,void *user){
    EkSceneStats bad={EVILKEY_3D_NO_MEMORY,0,0,0};
    if(!r || !dst || !scene || w<2 || h<2 || w>280 || h>320 || (w&1) || (h&1) ||
       stride<280 || x+w>280 || y+h>456 || !ek_scene3d_validate(scene,sizeof(EvilKey3DScene)))return bad;
    r->clock=clock;r->clock_user=user;r->started=clock?clock(user):0;
    r->stats=(EkSceneStats){EVILKEY_3D_OK,0,0,0};
    memcpy(&r->scene,scene,sizeof(r->scene));r->rw=w/2;r->rh=h/2;
    unsigned pixels=r->rw*r->rh;
    for(unsigned i=0;i<pixels;i++){r->depth[i]=0;r->colours[1-r->committed][i]=r->scene.background;}
    EvilKey3DCamera *c=&r->scene.camera;
    r->eye=v(c->position[0]/256.f,c->position[1]/256.f,c->position[2]/256.f);
    r->forward=unit(sub(v(c->target[0]/256.f,c->target[1]/256.f,c->target[2]/256.f),r->eye));
    r->right=unit(cross(r->forward,v(0,1,0)));r->up=cross(r->right,r->forward);
    r->factor=c->projection?r->rh*.5f/tanf(c->fov*.00872664626f):r->rh*256.f/c->span;
    for(unsigned i=0;i<r->scene.object_count && !expired(r);i++){
        r->stats.triangles+=ek3_faces(r->scene.objects[i].model);object(r,&r->scene.objects[i]);
    }
    if(!expired(r)){r->committed=1-r->committed;r->cached_w=r->rw;r->cached_h=r->rh;}
    /* Commit is bounded by viewport size, at most 89,600 RGB565 writes.
     * The reported duration includes this copy; deadline applies to geometry. */
    for(unsigned row=0;row<h;row++)for(unsigned col=0;col<w;col++)
        dst[(y+row)*stride+x+col]=(r->cached_w==r->rw && r->cached_h==r->rh)?
            r->colours[r->committed][(row/2)*r->rw+col/2]:r->scene.background;
    if(clock){uint64_t elapsed=clock(user)-r->started;r->stats.elapsed_us=(uint32_t)(elapsed>UINT32_MAX?UINT32_MAX:elapsed);}
    return r->stats;
}
