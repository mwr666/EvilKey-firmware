#include "../../pf_build_config.h"
/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "ws_controls.h"
#include "ws_gamepad_layout.h"
#include <string.h>
#include <math.h>

bool ws_controls_is_ble(PfControlMode mode) {
    return mode==PF_CONTROL_BLE_MOUSE || mode==PF_CONTROL_BLE_PAD;
}
uint16_t ws_controls_hid_buttons(uint16_t buttons,bool xbox) {
    buttons&=0xFFU;
    // Xbox reserves buttons 7/8 for stick clicks; Select/Start are 9/10.
    return xbox?(uint16_t)((buttons&0x3FU)|((buttons&0xC0U)<<2)):buttons;
}

PfControlMode ws_controls_boot_mode(uint32_t token,uint32_t check,bool software_reset) {
    if(software_reset && check==~token && token>=WS_CONTROLS_BOOT_MAGIC && token<=WS_CONTROLS_BOOT_MAGIC+2U)
        return (PfControlMode)(token-WS_CONTROLS_BOOT_MAGIC+1U);
    return PF_CONTROL_NORMAL;
}

void ws_controls_defaults(WsControlPrefs *p) {
    *p=(WsControlPrefs){1,0,1,1,1,18};
}
bool ws_controls_valid(const WsControlPrefs *p) {
    return p && p->version==1 && p->transport<=1 && p->profile<=1 &&
        p->analog<=1 && p->orientation<=1 && p->deadzone>=5 && p->deadzone<=35;
}
bool ws_controls_decode(WsControlPrefs *p,const uint8_t *data,unsigned length) {
    if(!p || !data || length!=sizeof(*p))return false;
    WsControlPrefs decoded;memcpy(&decoded,data,length);
    if(!ws_controls_valid(&decoded))return false;
    *p=decoded;return true;
}
void ws_mouse_latch_reset(WsMouseLatch *m) {memset(m,0,sizeof(*m));}
void ws_mouse_latch_touch(WsMouseLatch *m,bool valid,bool down,uint8_t zone,bool enabled) {
    if(!valid || !enabled){ws_mouse_latch_reset(m);return;}
    m->buttons=0;m->move=false;
    if(!down){m->armed=true;m->previous_down=false;m->move=m->drag;m->buttons=m->drag?1:0;return;}
    if(!m->armed)return;
    bool fresh=!m->previous_down;m->previous_down=true;
    if(zone==6) {
        // MOVE is momentary. Taking manual control also releases a latched drag.
        m->drag=false;
    } else if(fresh && zone==16) {
        m->drag=!m->drag;
    } else if(fresh && zone==4)m->drag=false;
    m->move=m->drag || zone==6;
    m->buttons=m->drag || zone==3?1:zone==4?2:0;
}
void ws_controls_rotate(uint8_t orientation,int16_t px,int16_t py,int16_t *x,int16_t *y) {
    if(orientation) {*x=(int16_t)(455-py);*y=px;}
    else {*x=py;*y=(int16_t)(279-px);}
}
void ws_gamepad_init(WsGamepad *p) {
    memset(p,0,sizeof(*p)); p->report.hat=8;
}
static bool box(int x,int y,int left,int top,int w,int h) {
    return x>=left && y>=top && x<left+w && y<top+h;
}
static bool pad_box(int x,int y,WsPadArea area) {
    const WsPadRect *r=&ws_pad_layout[area];
    return box(x,y,r->x,r->y,r->w,r->h);
}
void ws_gamepad_calibrate(WsGamepad *p) {
    memset(&p->imu,0,sizeof(p->imu));p->report=(WsPadReport){.hat=8};
}
void ws_gamepad_imu_sample(WsGamepad *p,float ax,float ay,float az,uint32_t now) {
    WsPadImu *imu=&p->imu;
    float g[3]={ax,ay,az},length=sqrtf(ax*ax+ay*ay+az*az);
    if(!isfinite(length) || length<1000.0f || length>32000.0f) {imu->valid=false;return;}
    for(unsigned i=0;i<3;++i)g[i]/=length;
    if(!imu->valid || (uint32_t)(now-imu->sampled_at)>80U) {
        memcpy(imu->filtered,g,sizeof(g));
        if(!imu->ready){imu->samples=0;memset(imu->sum,0,sizeof(imu->sum));}
    } else for(unsigned i=0;i<3;++i)imu->filtered[i]+=0.25f*(g[i]-imu->filtered[i]);
    imu->valid=true;imu->sampled_at=now;
    if(imu->ready)return;
    // Require a stationary one-second sample; movement starts calibration again.
    if(imu->samples) {
        float error=0;
        for(unsigned i=0;i<3;++i){float d=g[i]-imu->sum[i]/imu->samples;error+=d*d;}
        if(error>0.012f){imu->samples=0;memset(imu->sum,0,sizeof(imu->sum));}
    }
    for(unsigned i=0;i<3;++i)imu->sum[i]+=g[i];
    if(++imu->samples<50)return;
    length=sqrtf(imu->sum[0]*imu->sum[0]+imu->sum[1]*imu->sum[1]+imu->sum[2]*imu->sum[2]);
    for(unsigned i=0;i<3;++i)imu->neutral[i]=imu->sum[i]/length;
    // Same gravity-plane basis as the device-tested AirMouse; rotate the
    // corrected portrait vector into the selected landscape orientation.
    float dot=imu->neutral[0];
    for(unsigned i=0;i<3;++i)imu->right[i]=(i==0?1.0f:0.0f)-dot*imu->neutral[i];
    length=sqrtf(imu->right[0]*imu->right[0]+imu->right[1]*imu->right[1]+imu->right[2]*imu->right[2]);
    if(length<0.25f) {
        dot=imu->neutral[1];
        for(unsigned i=0;i<3;++i)imu->right[i]=(i==1?1.0f:0.0f)-dot*imu->neutral[i];
        length=sqrtf(imu->right[0]*imu->right[0]+imu->right[1]*imu->right[1]+imu->right[2]*imu->right[2]);
    }
    for(unsigned i=0;i<3;++i)imu->right[i]/=length;
    imu->down[0]=imu->neutral[1]*imu->right[2]-imu->neutral[2]*imu->right[1];
    imu->down[1]=imu->neutral[2]*imu->right[0]-imu->neutral[0]*imu->right[2];
    imu->down[2]=imu->neutral[0]*imu->right[1]-imu->neutral[1]*imu->right[0];
    imu->ready=true;
}
void ws_gamepad_apply_imu(WsGamepad *p,const WsControlPrefs *prefs,bool connected,uint32_t now) {
    p->report.x=p->report.y=0;p->report.hat=8;
    if(!connected || !p->imu.valid || (uint32_t)(now-p->imu.sampled_at)>80U) {
        p->report=(WsPadReport){.hat=8};return;
    }
    if(!p->armed || p->modal || p->ui_capture || p->hold_step || !p->imu.ready || !p->imu.valid ||
       (uint32_t)(now-p->imu.sampled_at)>80U)return;
    float x=0,y=0;
    for(unsigned i=0;i<3;++i) {
        float tilt=p->imu.filtered[i]-p->imu.neutral[i];
        x+=tilt*p->imu.right[i];y-=tilt*p->imu.down[i];
    }
    x=-x; // Correct horizontal direction; the device-tested vertical axis stays unchanged.
    if(!prefs->orientation){x=-x;y=-y;}
    float radius=sqrtf(x*x+y*y),dead=0.42f*prefs->deadzone/100.0f;
    if(radius<=dead)return;
    float active=fminf(radius,0.42f);
    float gain=(active-dead)*32767.0f/((0.42f-dead)*radius);
    if(prefs->analog){p->report.x=(int16_t)(x*gain);p->report.y=(int16_t)(y*gain);}
    else {
        // Eight directions; dead zone prevents neutral tremor.
        float angle=atan2f(x,y);
        int sector=(int)floorf(angle*4.0f/3.14159265f+0.5f);
        p->report.hat=(uint8_t)((sector+8)%8);
    }
}
static bool ui_rect(int x,int y,const WsPadRect *r) {
    return box(x,y,r->x,r->y,r->w,r->h);
}
static uint8_t ui_hit(uint8_t modal,int x,int y) {
    if(modal==1 || modal==3) {
        for(unsigned i=0;i<2;++i)if(ui_rect(x,y,&ws_pad_confirm_layout[i]))return WS_PAD_UI_YES+i;
    } else if(modal==2) {
        for(unsigned i=0;i<8;++i)if(ui_rect(x,y,&ws_pad_menu_layout[i]))return WS_PAD_UI_MODE+i;
    } else {
        const WsPadRect *r=&ws_pad_layout[WS_PAD_CENTER];
        // The four-pixel margin fits in the unused gaps around CENTER.
        if(box(x,y,r->x-4,r->y-4,r->w+8,r->h+8))return WS_PAD_UI_CENTER;
        if(pad_box(x,y,WS_PAD_IMU))return WS_PAD_UI_IMU;
        if(pad_box(x,y,WS_PAD_SETTINGS))return WS_PAD_UI_SETTINGS;
        if(pad_box(x,y,WS_PAD_EXIT_AREA))return WS_PAD_UI_EXIT;
    }
    return WS_PAD_UI_NONE;
}
static WsPadAction ui_activate(WsGamepad *p,WsControlPrefs *prefs,uint8_t control) {
    switch(control) {
        case WS_PAD_UI_CENTER:case WS_PAD_UI_IMU:case WS_PAD_UI_CALIBRATE:return WS_PAD_CALIBRATE;
        case WS_PAD_UI_SETTINGS:p->modal=2;break;
        case WS_PAD_UI_MODE:prefs->analog^=1;break;
        case WS_PAD_UI_ROTATE:prefs->orientation^=1;break;
        case WS_PAD_UI_PAIR:return WS_PAD_PAIR;
        case WS_PAD_UI_FORGET:p->modal=3;break;
        case WS_PAD_UI_MINUS:prefs->deadzone=prefs->deadzone<=10?5:prefs->deadzone-5;break;
        case WS_PAD_UI_PLUS:prefs->deadzone=prefs->deadzone>=30?35:prefs->deadzone+5;break;
        case WS_PAD_UI_BACK:p->modal=0;return WS_PAD_SAVE;
        case WS_PAD_UI_YES:
            if(p->modal==1)return WS_PAD_EXIT;
            p->modal=2;return WS_PAD_FORGET;
        case WS_PAD_UI_NO:p->modal=p->modal==3?2:0;break;
        default:break;
    }
    return WS_PAD_NONE;
}
WsPadAction ws_gamepad_touch(WsGamepad *p,WsControlPrefs *prefs,bool valid,
    const WsControlPoint *points,unsigned count,uint32_t now) {
    p->report=(WsPadReport){.hat=8};
    if(!p->ui_capture && (uint32_t)(now-p->ui_feedback_at)>=160U)p->ui_pressed=0;
    if(!valid || count>2 || (count && !points)) {
        p->armed=false;p->previous_down=false;p->ui_capture=0;p->ui_pressed=0;
        p->hold_at=0;p->hold_step=0;return WS_PAD_NONE;
    }
    if(!count) {
        uint8_t control=p->ui_capture;
        p->ui_capture=0;p->armed=true;p->previous_down=false;
        p->hold_at=0;p->hold_step=0;
        if(control) {
            // Keep a short acknowledgement visible even after a quick tap.
            p->ui_feedback_at=now;
            return ui_activate(p,prefs,control);
        }
        return WS_PAD_NONE;
    }
    if(!p->armed)return WS_PAD_NONE;
    p->previous_down=true;
    int x[2],y[2];
    for(unsigned i=0;i<count;++i) {
        int16_t rx,ry;ws_controls_rotate(prefs->orientation,points[i].x,points[i].y,&rx,&ry);
        x[i]=rx;y[i]=ry;
    }
    uint8_t control=count==1?ui_hit(p->modal,x[0],y[0]):WS_PAD_UI_NONE;
    if(p->ui_capture) {
        if(control!=p->ui_capture || p->ui_modal!=p->modal) {
            // Sliding out cancels the action until a fresh lift.
            p->ui_capture=0;p->ui_pressed=0;p->armed=false;
        } else p->ui_feedback_at=now;
        return WS_PAD_NONE;
    }
    if(control && control!=WS_PAD_UI_EXIT) {
        p->ui_capture=control;p->ui_pressed=control;p->ui_modal=p->modal;p->ui_feedback_at=now;
        p->hold_at=0;p->hold_step=0;return WS_PAD_NONE;
    }
    if(p->modal)return WS_PAD_NONE;
    bool exit_held=control==WS_PAD_UI_EXIT;
    for(unsigned i=0;i<count;++i) {
        if(pad_box(x[i],y[i],WS_PAD_A))p->report.buttons|=1U;
        if(pad_box(x[i],y[i],WS_PAD_B))p->report.buttons|=2U;
        if(pad_box(x[i],y[i],WS_PAD_X))p->report.buttons|=4U;
        if(pad_box(x[i],y[i],WS_PAD_Y))p->report.buttons|=8U;
        if(pad_box(x[i],y[i],WS_PAD_LB))p->report.buttons|=16U;
        if(pad_box(x[i],y[i],WS_PAD_RB))p->report.buttons|=32U;
        if(pad_box(x[i],y[i],WS_PAD_SELECT))p->report.buttons|=64U;
        if(pad_box(x[i],y[i],WS_PAD_START))p->report.buttons|=128U;
        if(pad_box(x[i],y[i],WS_PAD_LT))p->report.lt=255;
        if(pad_box(x[i],y[i],WS_PAD_RT))p->report.rt=255;
    }
    if(exit_held) {
        p->report=(WsPadReport){.hat=8};
        p->ui_pressed=WS_PAD_UI_EXIT;p->ui_modal=0;p->ui_feedback_at=now;
        if(!p->hold_at)p->hold_at=now;
        uint32_t elapsed=now-p->hold_at;
        p->hold_step=(uint8_t)(elapsed>=1200U?100U:elapsed/12U);
        if(elapsed>=1200U){p->modal=1;p->armed=false;p->hold_at=0;p->hold_step=0;}
    } else {p->hold_at=0;p->hold_step=0;}
    return WS_PAD_NONE;
}
