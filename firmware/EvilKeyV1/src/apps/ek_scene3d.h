/* SPDX-License-Identifier: AGPL-3.0-or-later */
#pragma once
#include "evilkey_scene3d.h"
#include <stddef.h>
#include <string.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Validate guest bytes before *any* output command has effects. No alignment
 * assumptions. Sizes are fixed; caller checks guest offset before this call. */
static inline uint16_t ek3_u16(const uint8_t *p) {return p[0]|((uint16_t)p[1]<<8);}
static inline uint32_t ek3_u32(const uint8_t *p) {return ek3_u16(p)|((uint32_t)ek3_u16(p+2)<<16);}
static inline int ek3_zero(const uint8_t *p,size_t n) {while(n--)if(*p++)return 0;return 1;}
static inline unsigned ek3_faces(unsigned model) {
    return model==1?12:model==2?32:model==3?2:model==4?6:0;
}
static inline int ek_scene3d_validate(const uint8_t *p,size_t size) {
    if(!p || size!=sizeof(EvilKey3DScene) || sizeof(EvilKey3DScene)!=3172 ||
       sizeof(EvilKey3DObject)!=32 || ek3_u32(p)!=EVILKEY_3D_MAGIC ||
       ek3_u16(p+4)!=1 || ek3_u32(p+12)) return 0;
    unsigned n=ek3_u16(p+6),m=ek3_u16(p+8),faces=0;
    if(!n || n>96 || !m || m>8) return 0;
    int32_t delta[3];
    for(unsigned k=0;k<3;k++) {
        int a=(int16_t)ek3_u16(p+16+k*2),b=(int16_t)ek3_u16(p+22+k*2);
        if(a < -16384 || a > 16384 || b < -8192 || b > 8192) return 0;
        delta[k]=b-a;
    }
    int64_t horizontal=(int64_t)delta[0]*delta[0]+(int64_t)delta[2]*delta[2];
    int64_t length=horizontal+(int64_t)delta[1]*delta[1];
    if(length<65536 || horizontal<256 || horizontal*1000<length ||
       ek3_u16(p+28)<25 || ek3_u16(p+28)>90 || ek3_u16(p+30)>1 ||
       ek3_u16(p+32)<256 || ek3_u16(p+32)>8192 || ek3_u16(p+34)) return 0;
    for(unsigned i=0;i<m;i++) {
        const uint8_t *a=p+36+8*i;
        if(ek3_u16(a+2)>1 || ek3_u32(a+4)) return 0;
    }
    if(!ek3_zero(p+36+8*m,8*(8-m))) return 0;
    for(unsigned i=0;i<n;i++) {
        const uint8_t *o=p+100+32*i;unsigned f=ek3_faces(ek3_u16(o));
        if(!f || ek3_u16(o+2)>=m || ek3_u16(o+22) || ek3_u32(o+24) || ek3_u32(o+28))return 0;
        faces+=f;
        for(unsigned k=0;k<3;k++) {
            int pos=(int16_t)ek3_u16(o+4+k*2),angle=(int16_t)ek3_u16(o+10+k*2);
            unsigned scale=ek3_u16(o+16+k*2);
            if(pos < -8192 || pos > 8192 || angle < -18000 || angle > 18000 ||
               !scale || scale>8192) return 0;
        }
    }
    return faces<=EVILKEY_3D_MAX_TRIANGLES && ek3_zero(p+100+32*n,32*(96-n));
}
typedef struct EkScene3D EkScene3D;
/* A supplied clock must be monotonic and safe to call concurrently from both
 * cores. Firmware uses esp_timer_get_time; NULL disables time checks in tests. */
typedef uint64_t (*EkSceneClock)(void *user);
typedef struct {uint32_t status,elapsed_us,triangles,pixel_tests;} EkSceneStats;
/* Native diagnostics only; never added to the guest ABI. Geometry includes
 * raster, timings are wall microseconds including profiling/preemption. */
typedef struct {
    EkSceneStats stats;
    uint32_t clear_us,setup_us,geometry_us,raster_us,reconstruct_us;
    uint32_t clock_calls,max_clock_gap_us;
} EkSceneProfile;
enum { EK_SCENE_BUDGET_US=20000, EK_SCENE_MAX_PIXEL_TESTS=300000,
       EK_SCENE_SCRATCH_PIXELS=140*160 };
/* Per app, PSRAM on ESP32. Never touches LVGL, DMA, SD, USB or GUI Jet. */
EkScene3D *ek_scene3d_create(void);
void ek_scene3d_destroy(EkScene3D *ctx);
EkSceneProfile ek_scene3d_profile(const EkScene3D *ctx);
/* Writes a complete frame or repeats the last completed viewport. No partial
 * frame on quota/clock abort. Budget is cooperative, checked per scanline. */
EkSceneStats ek_scene3d_render(EkScene3D *ctx,const uint8_t *scene,
    uint16_t *destination,unsigned stride,unsigned x,unsigned y,unsigned w,
    unsigned h,EkSceneClock clock,void *clock_user);
#ifdef __cplusplus
}
#endif
