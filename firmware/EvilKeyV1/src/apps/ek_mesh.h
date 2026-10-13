/* SPDX-License-Identifier: AGPL-3.0-or-later */
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <string.h>
typedef struct {unsigned vertices,triangles,roles;} EkMeshInfo;
static inline unsigned ekm_u16(const uint8_t *p){return p[0]|((unsigned)p[1]<<8);}
static inline uint32_t ekm_u32(const uint8_t *p){return ekm_u16(p)|((uint32_t)ekm_u16(p+2)<<16);}
static inline int ek_mesh_validate(const uint8_t *p,size_t size,EkMeshInfo *out){
    if(!p||!out||size<20||size>65536||memcmp(p,"EKMESH1\0",8)||
       ekm_u16(p+8)!=1||ekm_u16(p+14)||ekm_u32(p+16)!=size)return 0;
    unsigned v=ekm_u16(p+10),t=ekm_u16(p+12),roles=0;
    if(!v||v>1024||!t||t>1280||size!=20+v*6+t*8)return 0;
    for(unsigned i=0;i<v*3;i++){int n=(int16_t)ekm_u16(p+20+i*2);if(n< -16384||n>16384)return 0;}
    const uint8_t *a=p+20+v*6;
    for(unsigned i=0;i<t;i++,a+=8){unsigned x=ekm_u16(a),y=ekm_u16(a+2),z=ekm_u16(a+4);
        if(x>=v||y>=v||z>=v||x==y||y==z||x==z||a[6]>7||a[7])return 0;
        roles|=1u<<a[6];}
    *out=(EkMeshInfo){v,t,roles};return 1;
}
