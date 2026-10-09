/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Bounded native rasterizer for ABI5 builtin scenes, independent of GUI Jet.
 * Native triangles with flat lighting, near clipping, screen clipping, depth
 * test and deterministic 2x reconstruction. No guest geometry or addresses. */
#include "ek_scene3d.h"
#include "ek_render_parallel.h"
#include <math.h>
#include <stdlib.h>
#if defined(ARDUINO_ARCH_ESP32)
#include <esp_heap_caps.h>
#endif
typedef struct {float x,y,z;} V;
typedef struct {float x,y,d;} P;
typedef struct {P a,b,c;uint16_t colour;} RasterPrimitive;
_Static_assert(sizeof(RasterPrimitive)==40,"bounded prepared primitive");
enum {RASTER_BATCH_CAPACITY=320};
typedef struct {RasterPrimitive *items;unsigned count;} RasterBatch;
struct EkScene3D {
    EvilKey3DScene scene;
    /* Depth and colour share one aligned PSRAM transaction/cache line. */
    uint32_t pixels[2][EK_SCENE_SCRATCH_PIXELS];
    RasterPrimitive prepared[RASTER_BATCH_CAPACITY];
    unsigned committed,cached_w,cached_h,rw,rh;
    EkSceneProfile profile;
};
_Static_assert(sizeof(EkScene3D)<=192*1024,"bounded packed PSRAM context");
/* Hot state is on the existing Apps stack, not repeatedly fetched from PSRAM. */
typedef struct {uint32_t used,status;} SharedWork;
typedef struct {uint16_t rgb565,flags;} HotMaterial;
typedef struct {
    uint64_t started,last_clock;
    unsigned rw,rh;
    V eye,right,up,forward;float factor;
    EkSceneClock clock;void *clock_user;
    EkSceneStats stats;
    uint32_t *pixels;
    HotMaterial materials[8];
    EkSceneProfile *profile;
    SharedWork *shared;RasterBatch *batch;uint8_t first_row,row_step,projection,row_clock_phase;
} Frame;
_Static_assert(sizeof(Frame)<=256,"Scene3D hot frame stack bound");
static V v(float x,float y,float z){V a={x,y,z};return a;}
static V sub(V a,V b){return v(a.x-b.x,a.y-b.y,a.z-b.z);}
static V add(V a,V b){return v(a.x+b.x,a.y+b.y,a.z+b.z);}
static V mul(V a,float s){return v(a.x*s,a.y*s,a.z*s);}
static float dot(V a,V b){return a.x*b.x+a.y*b.y+a.z*b.z;}
static V cross(V a,V b){return v(a.y*b.z-a.z*b.y,a.z*b.x-a.x*b.z,a.x*b.y-a.y*b.x);}
static V unit(V a){return mul(a,1.f/sqrtf(dot(a,a)));}
static uint64_t sample_clock(Frame *r){
    if(!r->clock)return 0;
    uint64_t now=r->clock(r->clock_user),gap=now-r->last_clock;
    r->last_clock=now;++r->profile->clock_calls;
    uint32_t bounded=(uint32_t)(gap>UINT32_MAX?UINT32_MAX:gap);
    if(bounded>r->profile->max_clock_gap_us)r->profile->max_clock_gap_us=bounded;
    return now;
}
static uint32_t duration(uint64_t end,uint64_t start){
    uint64_t elapsed=end-start;return (uint32_t)(elapsed>UINT32_MAX?UINT32_MAX:elapsed);
}
static int cancelled(Frame *r){
    if(r->shared){
        uint32_t status=__atomic_load_n(&r->shared->status,__ATOMIC_ACQUIRE);
        if(status!=EVILKEY_3D_OK){r->stats.status=status;return 1;}
    }
    return 0;
}
static int expired(Frame *r){
    if(cancelled(r))return 1;
    if(r->clock && sample_clock(r)-r->started>=EK_SCENE_BUDGET_US)
        r->stats.status=EVILKEY_3D_TIMEOUT;
    if(r->shared&&r->stats.status!=EVILKEY_3D_OK){
        uint32_t expected=EVILKEY_3D_OK;
        __atomic_compare_exchange_n(&r->shared->status,&expected,r->stats.status,0,__ATOMIC_RELEASE,__ATOMIC_RELAXED);
        r->stats.status=__atomic_load_n(&r->shared->status,__ATOMIC_ACQUIRE);
    }
    return r->stats.status!=EVILKEY_3D_OK;
}
static int raster_row_expired(Frame *r){
    /* At most eight bounded rows between clock polls; cancellation every row.
     * Object/primitive/batch/final commit gates still read the actual clock. */
    if((r->row_clock_phase++&7u)==0)return expired(r);
    return cancelled(r)||r->stats.status!=EVILKEY_3D_OK;
}
static int reserve_span(Frame *r,unsigned tests){
    if(r->shared){
        uint32_t used=__atomic_load_n(&r->shared->used,__ATOMIC_RELAXED);
        for(;;){
            if(tests>EK_SCENE_MAX_PIXEL_TESTS-used){
                uint32_t expected=EVILKEY_3D_OK;
                __atomic_compare_exchange_n(&r->shared->status,&expected,EVILKEY_3D_WORK_LIMIT,0,__ATOMIC_RELEASE,__ATOMIC_RELAXED);
                r->stats.status=__atomic_load_n(&r->shared->status,__ATOMIC_ACQUIRE);return 0;
            }
            if(__atomic_compare_exchange_n(&r->shared->used,&used,used+tests,0,__ATOMIC_RELAXED,__ATOMIC_RELAXED))break;
        }
    }else if(tests>EK_SCENE_MAX_PIXEL_TESTS-r->stats.pixel_tests){r->stats.status=EVILKEY_3D_WORK_LIMIT;return 0;}
    r->stats.pixel_tests+=tests;return 1;
}
EkScene3D *ek_scene3d_create(void){
#if defined(ARDUINO_ARCH_ESP32)
    return (EkScene3D*)heap_caps_calloc(1,sizeof(EkScene3D),MALLOC_CAP_SPIRAM|MALLOC_CAP_8BIT);
#else
    return (EkScene3D*)calloc(1,sizeof(EkScene3D));
#endif
}
void ek_scene3d_destroy(EkScene3D *r){free(r);}
EkSceneProfile ek_scene3d_profile(const EkScene3D *r){
    EkSceneProfile empty={0};return r?r->profile:empty;
}
static uint16_t shade(uint16_t c,float k){
    unsigned red=(unsigned)(((c>>11)&31)*k),green=(unsigned)(((c>>5)&63)*k),blue=(unsigned)((c&31)*k);
    return (uint16_t)((red<<11)|(green<<5)|blue);
}
static int edge(int ax,int ay,int bx,int by,int x,int y){return (bx-ax)*(y-ay)-(by-ay)*(x-ax);}
static void raster_pixels(Frame *r,P a,P b,P c,uint16_t colour){
    int ax=(int)(a.x*16),ay=(int)(a.y*16),bx=(int)(b.x*16),by=(int)(b.y*16),cx=(int)(c.x*16),cy=(int)(c.y*16);
    int area=edge(ax,ay,bx,by,cx,cy);if(!area)return;
    if(area<0){P t=b;b=c;c=t;int s=bx;bx=cx;cx=s;s=by;by=cy;cy=s;area=-area;}
    int x0=ax<bx?ax:bx;x0=x0<cx?x0:cx;x0=x0/16;if(x0<0)x0=0;
    int y0=ay<by?ay:by;y0=y0<cy?y0:cy;y0=y0/16;if(y0<0)y0=0;
    int x1=ax>bx?ax:bx;x1=x1>cx?x1:cx;x1=x1/16;if(x1>=(int)r->rw)x1=r->rw-1;
    int y1=ay>by?ay:by;y1=y1>cy?y1:cy;y1=y1/16;if(y1>=(int)r->rh)y1=r->rh-1;
    if(y0<(int)r->first_row)y0=r->first_row;
    /* Align to this core's row parity without changing per-row arithmetic. */
    if(r->row_step==2 && ((y0^(int)r->first_row)&1))y0++;
    float inv=1.f/area;
    float da=(b.d-a.d)*inv,db=(c.d-a.d)*inv;
    uint32_t *pixels=r->pixels;
    for(int y=y0;y<=y1;y+=(int)r->row_step){
        if(raster_row_expired(r))return;
        if(x1<x0)continue;
        int ea=edge(bx,by,cx,cy,x0*16+8,y*16+8),eb=edge(cx,cy,ax,ay,x0*16+8,y*16+8),ec=edge(ax,ay,bx,by,x0*16+8,y*16+8);
        int sa=-(cy-by)*16,sb=-(ay-cy)*16,sc=-(by-ay)*16;
        float d=a.d+eb*da+ec*db,sd=sb*da+sc*db;
        /* Exact inclusive edge spans; prefix depth additions preserve rounding. */
        int first=0,last=x1-x0;
        const int ev[3]={ea,eb,ec},step[3]={sa,sb,sc};
        for(unsigned k=0;k<3;k++){
            if(step[k]>0){if(ev[k]<0){int n=(-ev[k]+step[k]-1)/step[k];if(n>first)first=n;}}
            else if(step[k]<0){if(ev[k]<0){last=-1;break;}int n=ev[k]/(-step[k]);if(n<last)last=n;}
            else if(ev[k]<0){last=-1;break;}
        }
        if(first>last)continue;
        unsigned tests=(unsigned)(last-first+1);
        if(!reserve_span(r,tests))return;
        for(int i=0;i<first;i++)d+=sd;
        /* The inclusive integer span already proves all three edge tests.
         * Keep prefix additions and the depth recurrence exactly ordered. */
        unsigned index=(unsigned)y*r->rw+x0+first;
        for(int x=first;x<=last;x++,index++,d+=sd){
            unsigned depth=(unsigned)(d<1?1:d>65535?65535:d);
            if(depth>(pixels[index]>>16))pixels[index]=(depth<<16)|colour;
        }
    }
}
static void raster(Frame *r,P a,P b,P c,uint16_t colour){
    if(r->batch){
        if(r->batch->count>=RASTER_BATCH_CAPACITY){
            r->stats.status=EVILKEY_3D_WORK_LIMIT;expired(r);return;
        }
        r->batch->items[r->batch->count++]=(RasterPrimitive){a,b,c,colour};
        return;
    }
    uint64_t start=sample_clock(r);
    raster_pixels(r,a,b,c,colour);
    r->profile->raster_us+=duration(sample_clock(r),start);
}
static float distance(P p,unsigned side,float bound){return side==0?p.x:side==1?bound-p.x:side==2?p.y:bound-p.y;}
static void clipped_screen(Frame *r,P a,P b,P c,uint16_t colour){
    if((a.x<0&&b.x<0&&c.x<0)||(a.y<0&&b.y<0&&c.y<0)||
       (a.x>r->rw&&b.x>r->rw&&c.x>r->rw)||(a.y>r->rh&&b.y>r->rh&&c.y>r->rh))return;
    if(a.x>=0&&a.x<=r->rw&&b.x>=0&&b.x<=r->rw&&c.x>=0&&c.x<=r->rw&&
       a.y>=0&&a.y<=r->rh&&b.y>=0&&b.y<=r->rh&&c.y>=0&&c.y<=r->rh){raster(r,a,b,c,colour);return;}
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
static void triangle(Frame *r,V a,V b,V c,HotMaterial mat){
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
        V q=near_poly[i];float scale=r->projection?r->factor/q.z:r->factor;
        p[i]=(P){r->rw*.5f+q.x*scale,r->rh*.5f-q.y*scale,r->projection?16384.f/q.z:65535.f-q.z*256.f};
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
static void face(Frame *r,const EvilKey3DObject *o,const float *cs,V a,V b,V c){
    triangle(r,transformed(a,o,cs),transformed(b,o,cs),transformed(c,o,cs),r->materials[o->material]);
}
static void object(Frame *r,const EvilKey3DObject *o){
    float cs[6];for(unsigned k=0;k<3;k++){if(!o->rotation[k]){cs[2*k]=1;cs[2*k+1]=0;}else{float angle=o->rotation[k]*.0001745329252f;cs[2*k]=cosf(angle);cs[2*k+1]=sinf(angle);}}
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
        else {
            for(unsigned i=0;i<8;i++)p[i]=transformed(p[i],o,cs);
            for(unsigned i=0;i<12 && !expired(r);i++)triangle(r,p[faces[i][0]],p[faces[i][1]],p[faces[i][2]],r->materials[o->material]);
        }
    }
}
/* Burst copies use the SDK's aligned memory routines; separate helpers keep
 * these bounded rows off the stack during geometry/raster recursion. */
static void __attribute__((noinline)) clear_pixels(uint32_t *pixels,unsigned count,uint16_t background){
    uint32_t block[32];for(unsigned i=0;i<32;i++)block[i]=background;
    while(count){unsigned n=count<32?count:32;memcpy(pixels,block,n*sizeof(*pixels));pixels+=n;count-=n;}
}
static void __attribute__((noinline)) reconstruct(const uint32_t *front,uint16_t *dst,
    unsigned stride,unsigned x,unsigned y,unsigned w,unsigned h,unsigned rw,int cached,uint16_t background){
    uint32_t row[140];
    if(!cached)for(unsigned col=0;col<w/2;col++)row[col]=background|((uint32_t)background<<16);
    for(unsigned line=0;line<h;line+=2){
        if(cached){
            const uint32_t *in=front+(line/2)*rw;
            for(unsigned col=0;col<w/2;col++){uint32_t colour=in[col]&0xffff;row[col]=colour|(colour<<16);}
        }
        uint16_t *out=dst+(y+line)*stride+x;
        memcpy(out,row,w*sizeof(*dst));memcpy(out+stride,row,w*sizeof(*dst));
    }
}
typedef struct {uint32_t *pixels;unsigned count;uint16_t background;} ClearJob;
static void clear_band(void *data){ClearJob *j=data;clear_pixels(j->pixels,j->count,j->background);}
typedef struct {
    const Frame *prepared;const RasterBatch *batch;
    unsigned first;EkSceneProfile profile;
} RasterJob;
static void raster_band(void *data){
    RasterJob *j=data;Frame f=*j->prepared;
    f.first_row=j->first;f.row_step=2;f.profile=&j->profile;f.batch=NULL;
    f.stats.pixel_tests=0;f.stats.triangles=0;
    /* Private clock and counters; only row-disjoint pixels are shared. */
    f.row_clock_phase=0;
    uint64_t start=sample_clock(&f);
    for(unsigned i=0;i<j->batch->count&&!expired(&f);i++){
        const RasterPrimitive *p=&j->batch->items[i];raster_pixels(&f,p->a,p->b,p->c,p->colour);
    }
    expired(&f);j->profile.raster_us=duration(sample_clock(&f),start);j->profile.stats=f.stats;
}
/* Only the outer object loop calls this: no dispatch on the clipping stack. */
static void __attribute__((noinline)) flush_batch(Frame *f){
    if(!f->batch->count)return;
    
    RasterJob jobs[2]={{f,f->batch,0,{0}},{f,f->batch,1,{0}}};
    ek_render_parallel(raster_band,&jobs[0],&jobs[1]);
    f->stats.status=__atomic_load_n(&f->shared->status,__ATOMIC_ACQUIRE);
    f->stats.pixel_tests+=jobs[0].profile.stats.pixel_tests+jobs[1].profile.stats.pixel_tests;
    uint32_t raster_us=0;
    for(unsigned i=0;i<2;i++){
        EkSceneProfile *p=&jobs[i].profile;f->profile->clock_calls+=p->clock_calls;
        if(p->max_clock_gap_us>f->profile->max_clock_gap_us)f->profile->max_clock_gap_us=p->max_clock_gap_us;
        if(p->raster_us>raster_us)raster_us=p->raster_us;
    }
    f->profile->raster_us+=raster_us;
    expired(f);f->batch->count=0; /* Both jobs joined before storage reuse. */
    
}

typedef struct {
    const uint32_t *front;uint16_t *dst;unsigned stride,x,y,w,h,rw;
    int cached;uint16_t background;
} CopyJob;
static void copy_band(void *data){
    CopyJob *j=data;reconstruct(j->front,j->dst,j->stride,j->x,j->y,j->w,j->h,j->rw,j->cached,j->background);
}
static inline EkSceneStats __attribute__((always_inline)) render_private(EkScene3D *r,const uint8_t *scene,uint16_t *dst,
    unsigned stride,unsigned x,unsigned y,unsigned w,unsigned h,EkSceneClock clock,void *user){
    EkSceneStats bad={EVILKEY_3D_NO_MEMORY,0,0,0};
    if(!r || w<2 || h<2 || w>280 || h>320 || (w&1) || (h&1))return bad;
    if((!dst || !scene || stride<280 || x+w>280 || y+h>456 ||
       !ek_scene3d_validate(scene,sizeof(EvilKey3DScene))))return bad;
    /* Queue admission precedes the unchanged timed compute window. Helpers
     * never acquire this mutex; release after joined pre-copy completion. */
    
    bool admitted=ek_render_frame_begin(EK_RENDER_FRAME_NATIVE);
    
    Frame frame={0};Frame *f=&frame;EkSceneProfile profile={0};f->profile=&profile;
    EkRenderWorkerStats workers;ek_render_worker_stats(&workers);
    int parallel=workers.ready&&workers.enabled;
    f->clock=clock;f->clock_user=user;f->started=clock?clock(user):0;
    f->last_clock=f->started;profile.clock_calls=clock?1:0;
    f->stats=(EkSceneStats){EVILKEY_3D_OK,0,0,0};
    memcpy(&r->scene,scene,sizeof(r->scene));f->rw=w/2;f->rh=h/2;f->row_step=1;
    f->pixels=r->pixels[1-r->committed];
    for(unsigned i=0;i<8;i++)f->materials[i]=(HotMaterial){r->scene.materials[i].rgb565,r->scene.materials[i].flags};
    unsigned pixels=f->rw*f->rh;uint16_t background=r->scene.background;
    unsigned middle=f->rh/2;
    if(parallel){
        ClearJob jobs[2]={{f->pixels,middle*f->rw,background},{f->pixels+middle*f->rw,pixels-middle*f->rw,background}};
        
        ek_render_parallel(clear_band,&jobs[0],&jobs[1]);
    }else {clear_pixels(f->pixels,pixels,background);}
    uint64_t cleared=sample_clock(f);profile.clear_us=duration(cleared,f->started);
    EvilKey3DCamera camera=r->scene.camera;EvilKey3DCamera *c=&camera;
    f->projection=c->projection;
    f->eye=v(c->position[0]/256.f,c->position[1]/256.f,c->position[2]/256.f);
    f->forward=unit(sub(v(c->target[0]/256.f,c->target[1]/256.f,c->target[2]/256.f),f->eye));
    f->right=unit(cross(f->forward,v(0,1,0)));f->up=cross(f->right,f->forward);
    f->factor=c->projection?f->rh*.5f/tanf(c->fov*.00872664626f):f->rh*256.f/c->span;
    uint64_t setup=sample_clock(f);profile.setup_us=duration(setup,cleared);
    unsigned count=r->scene.object_count;
    
    if(parallel){
        /* Atomics stay on the internal caller stack; Xtensa CAS cannot use PSRAM. */
        SharedWork shared={0,EVILKEY_3D_OK};f->shared=&shared;
        RasterBatch batch={r->prepared,0};f->batch=&batch;
        for(unsigned i=0;i<count&&!expired(f);i++){
            EvilKey3DObject o=r->scene.objects[i];unsigned faces=ek3_faces(o.model);
            /* Near clip <=2 fans, each screen clip <=5 fans per source face. */
            unsigned reservation=faces*10;
            if(batch.count>RASTER_BATCH_CAPACITY-reservation)flush_batch(f);
            if(expired(f))break;
            f->stats.triangles+=faces;object(f,&o);
        }
        if(!expired(f))flush_batch(f);
        expired(f);f->batch=NULL;f->shared=NULL;
    }else for(unsigned i=0;i<count && !expired(f);i++){
        EvilKey3DObject o=r->scene.objects[i];
        f->stats.triangles+=ek3_faces(o.model);object(f,&o);
    }
    if(!expired(f)){r->committed=1-r->committed;r->cached_w=f->rw;r->cached_h=f->rh;}
    uint64_t geometry=sample_clock(f);profile.geometry_us=duration(geometry,setup);
    ek_render_frame_end(admitted);
    /* Reconstruct once per pair of rows; last completed frame on abort. */
    int cached=r->cached_w==f->rw&&r->cached_h==f->rh;
    
    if(parallel){
        CopyJob jobs[2]={{r->pixels[r->committed],dst,stride,x,y,w,middle*2,f->rw,cached,background},
            {r->pixels[r->committed]+middle*f->rw,dst,stride,x,y+middle*2,w,h-middle*2,f->rw,cached,background}};
        
        ek_render_parallel(copy_band,&jobs[0],&jobs[1]);
    }else reconstruct(r->pixels[r->committed],dst,stride,x,y,w,h,f->rw,cached,background);
    uint64_t end=sample_clock(f);profile.reconstruct_us=duration(end,geometry);
    if(clock)f->stats.elapsed_us=duration(end,f->started);
    profile.stats=f->stats;r->profile=profile;
    
    return f->stats;
}
EkSceneStats ek_scene3d_render(EkScene3D *r,const uint8_t *scene,uint16_t *dst,
    unsigned stride,unsigned x,unsigned y,unsigned w,unsigned h,EkSceneClock clock,void *user){
    return render_private(r,scene,dst,stride,x,y,w,h,clock,user);
}
