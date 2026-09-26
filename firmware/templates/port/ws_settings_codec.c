/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "ws_settings.h"
#include <string.h>
#ifndef FIDO_V1_BRIGHTNESS
#define FIDO_V1_BRIGHTNESS 90
#endif
#ifndef FIDO_V1_DIM_BRIGHTNESS
#define FIDO_V1_DIM_BRIGHTNESS 8
#endif
#ifndef FIDO_V1_DIM_AFTER_SECONDS
#define FIDO_V1_DIM_AFTER_SECONDS 30
#endif
#ifndef FIDO_V1_OFF_AFTER_DIM_SECONDS
#define FIDO_V1_OFF_AFTER_DIM_SECONDS 60
#endif
#ifndef FIDO_V1_PRESENCE_TIMEOUT_SECONDS
#define FIDO_V1_PRESENCE_TIMEOUT_SECONDS 30
#endif
#ifndef FIDO_V1_UV_TIMEOUT_SECONDS
#define FIDO_V1_UV_TIMEOUT_SECONDS 120
#endif
#ifndef FIDO_V1_GUI_ACCENT_RGB
#define FIDO_V1_GUI_ACCENT_RGB 0x4DE3C1UL
#endif
#ifndef FIDO_V1_GUI_ANIMATION
#define FIDO_V1_GUI_ANIMATION 1
#endif
static uint16_t read16(const uint8_t *p){return (uint16_t)(((uint16_t)p[0]<<8)|p[1]);}
static uint32_t read32(const uint8_t *p){return (uint32_t)p[0]<<24|(uint32_t)p[1]<<16|(uint32_t)p[2]<<8|p[3];}
static void put16(uint8_t *p,uint16_t v){p[0]=(uint8_t)(v>>8);p[1]=(uint8_t)v;}
static void put32(uint8_t *p,uint32_t v){p[0]=(uint8_t)(v>>24);p[1]=(uint8_t)(v>>16);p[2]=(uint8_t)(v>>8);p[3]=(uint8_t)v;}
bool ws_settings_valid(const ws_settings_t *s) {
    if(!s || s->brightness<8 || s->dim_brightness<1 || s->dim_brightness>32 ||
       s->dim_brightness>s->brightness || s->dim_seconds>3600 ||
       (s->dim_seconds && s->dim_seconds<5) || s->off_seconds>3600 ||
       (s->off_seconds && s->off_seconds<5) || s->presence_seconds<1 ||
       s->presence_seconds>120 || s->uv_seconds<15 || s->uv_seconds>120 ||
       s->accent_rgb>0xFFFFFFU) return false;
    unsigned r=(s->accent_rgb>>16)&255U,g=(s->accent_rgb>>8)&255U,b=s->accent_rgb&255U;
    return (299U*r+587U*g+114U*b)>=128000U;
}
void ws_settings_defaults(ws_settings_t *out) {
    if(!out)return;
    *out=(ws_settings_t){.brightness=FIDO_V1_BRIGHTNESS,
        .dim_brightness=FIDO_V1_DIM_BRIGHTNESS,.animation=FIDO_V1_GUI_ANIMATION!=0,
        .dim_seconds=FIDO_V1_DIM_AFTER_SECONDS,.off_seconds=FIDO_V1_OFF_AFTER_DIM_SECONDS,
        .presence_seconds=FIDO_V1_PRESENCE_TIMEOUT_SECONDS,.uv_seconds=FIDO_V1_UV_TIMEOUT_SECONDS,
        .accent_rgb=FIDO_V1_GUI_ACCENT_RGB,.revision=0};
    /* Invalid defaults must not make the on-device PIN permanently invisible. */
    if(!ws_settings_valid(out)) *out=(ws_settings_t){90,8,true,30,60,30,120,0x4DE3C1U,0};
}
void ws_settings_encode(const ws_settings_t *s,uint8_t out[WS_SETTINGS_WIRE_SIZE]) {
    if(!s||!out)return;
    memset(out,0,WS_SETTINGS_WIRE_SIZE);memcpy(out,"PFM1",4);
    out[4]=1;out[5]=s->brightness;out[6]=s->dim_brightness;out[7]=s->animation?1:0;
    put16(out+8,s->dim_seconds);put16(out+10,s->off_seconds);
    put16(out+12,s->presence_seconds);put16(out+14,s->uv_seconds);
    put32(out+16,s->accent_rgb);put32(out+20,s->revision);
}
bool ws_settings_decode(const uint8_t *data,size_t len,ws_settings_t *out) {
    if(!data||!out||len!=WS_SETTINGS_WIRE_SIZE||memcmp(data,"PFM1",4)||data[4]!=1||data[7]>1)return false;
    for(unsigned i=24;i<WS_SETTINGS_WIRE_SIZE;i++)if(data[i])return false;
    ws_settings_t s={.brightness=data[5],.dim_brightness=data[6],.animation=data[7]!=0,
        .dim_seconds=read16(data+8),.off_seconds=read16(data+10),
        .presence_seconds=read16(data+12),.uv_seconds=read16(data+14),
        .accent_rgb=read32(data+16),.revision=read32(data+20)};
    if(!ws_settings_valid(&s))return false;
    *out=s;return true;
}
