/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "ws_controls.h"
#include "ws_gamepad_layout.h"
#include <assert.h>
#include <math.h>
#include <stdio.h>
#include <string.h>
static uint32_t now=10;
static WsControlPoint point(int x,int y,unsigned id,unsigned orientation) {
    return orientation?(WsControlPoint){(int16_t)y,(int16_t)(455-x),(uint16_t)id}:
        (WsControlPoint){(int16_t)(279-y),(int16_t)x,(uint16_t)id};
}
static void up(WsGamepad *g,WsControlPrefs *p){ws_gamepad_touch(g,p,true,0,0,++now);}
static WsPadAction tap(WsGamepad *g,WsControlPrefs *p,int x,int y) {
    up(g,p);WsControlPoint q=point(x,y,1,p->orientation);
    return ws_gamepad_touch(g,p,true,&q,1,++now);
}
static WsPadAction click(WsGamepad *g,WsControlPrefs *p,int x,int y) {
    assert(tap(g,p,x,y)==WS_PAD_NONE);
    assert(g->ui_capture && g->ui_pressed==g->ui_capture);
    assert(!g->report.buttons && !g->report.lt && !g->report.rt);
    return ws_gamepad_touch(g,p,true,0,0,++now);
}
static void utility_regression(unsigned o) {
    WsGamepad g;WsControlPrefs p;ws_gamepad_init(&g);ws_controls_defaults(&p);p.orientation=o;
    up(&g,&p);
    WsControlPoint gap=point(104,243,1,o),edge=point(5,243,1,o);
    ws_gamepad_touch(&g,&p,true,&gap,1,++now);assert(!g.ui_capture);
    ws_gamepad_touch(&g,&p,true,&edge,1,++now);assert(g.ui_pressed==WS_PAD_UI_CENTER);
    for(unsigned i=0;i<20;++i)assert(ws_gamepad_touch(&g,&p,true,&edge,1,++now)==WS_PAD_NONE);
    assert(ws_gamepad_touch(&g,&p,true,0,0,++now)==WS_PAD_CALIBRATE);
    assert(g.ui_pressed==WS_PAD_UI_CENTER && !g.ui_capture);
    assert(ws_gamepad_touch(&g,&p,true,0,0,++now)==WS_PAD_NONE);
    now+=160;up(&g,&p);assert(!g.ui_pressed);
    tap(&g,&p,54,243);ws_gamepad_touch(&g,&p,true,&gap,1,++now);
    assert(!g.ui_capture && !g.ui_pressed && !g.armed);
    assert(ws_gamepad_touch(&g,&p,true,0,0,++now)==WS_PAD_NONE);
    tap(&g,&p,54,243);ws_gamepad_touch(&g,&p,false,0,0,++now);
    assert(!g.ui_capture && !g.ui_pressed);
    up(&g,&p);tap(&g,&p,54,243);
    WsControlPoint two[]={edge,point(420,60,2,o)};
    ws_gamepad_touch(&g,&p,true,two,2,++now);assert(!g.ui_capture && !g.armed);
    assert(ws_gamepad_touch(&g,&p,true,0,0,++now)==WS_PAD_NONE);
    now=UINT32_MAX-40;click(&g,&p,54,243);now+=159;
    ws_gamepad_touch(&g,&p,true,0,0,now);assert(g.ui_pressed);
    now+=1;ws_gamepad_touch(&g,&p,true,0,0,now);assert(!g.ui_pressed);
    click(&g,&p,378,243);assert(g.modal==2);
    unsigned old=p.analog;tap(&g,&p,100,80);
    assert(p.analog==old && g.ui_pressed==WS_PAD_UI_MODE);
    up(&g,&p);assert(p.analog!=old);
    unsigned orientation=p.orientation;click(&g,&p,300,80);assert(p.orientation!=orientation);
    assert(click(&g,&p,100,168)==WS_PAD_PAIR);
    click(&g,&p,300,168);assert(g.modal==3);
    click(&g,&p,300,190);assert(g.modal==2); // cancel forget
    click(&g,&p,300,210);assert(g.modal==0);
}
static void sample(WsGamepad *g,float x,float y,float z) {
    now+=20;ws_gamepad_imu_sample(g,x,y,z,now);
}
static void mouse(void) {
    WsMouseLatch m={0};
    ws_mouse_latch_touch(&m,true,true,6,true);assert(!m.move); // lift after entry
    ws_mouse_latch_touch(&m,true,false,0,true);
    ws_mouse_latch_touch(&m,true,true,6,true);assert(m.move && !m.drag);
    for(int i=0;i<100;++i)ws_mouse_latch_touch(&m,true,true,6,true);
    assert(m.move); // movement remains active throughout the hold
    ws_mouse_latch_touch(&m,true,false,0,true);assert(!m.move);
    ws_mouse_latch_touch(&m,true,true,6,true);assert(m.move); // next hold works immediately
    ws_mouse_latch_touch(&m,true,true,0,true);assert(!m.move); // sliding outside stops
    ws_mouse_latch_touch(&m,true,true,6,true);assert(m.move);
    ws_mouse_latch_touch(&m,true,false,0,true);assert(!m.move);
    ws_mouse_latch_touch(&m,true,true,3,true);assert(m.buttons==1 && !m.move);
    ws_mouse_latch_touch(&m,true,false,0,true);assert(!m.buttons && !m.move);
    ws_mouse_latch_touch(&m,true,true,16,true);assert(m.drag && m.move && m.buttons==1);
    ws_mouse_latch_touch(&m,true,false,0,true);assert(m.drag && m.move && m.buttons==1);
    ws_mouse_latch_touch(&m,true,true,16,true);assert(!m.drag && !m.move && !m.buttons);
    ws_mouse_latch_touch(&m,true,false,0,true);
    ws_mouse_latch_touch(&m,true,true,16,true);
    ws_mouse_latch_touch(&m,true,false,0,true);
    ws_mouse_latch_touch(&m,true,true,6,true);assert(m.move && !m.drag && !m.buttons);
    ws_mouse_latch_touch(&m,true,false,0,true);assert(!m.move && !m.drag && !m.buttons);
    ws_mouse_latch_touch(&m,true,true,16,true);assert(m.move && m.drag); // drag starts movement
    ws_mouse_latch_touch(&m,true,false,0,true);
    ws_mouse_latch_touch(&m,true,true,4,true);assert(!m.drag && m.buttons==2 && !m.move);
    ws_mouse_latch_touch(&m,true,false,0,true);
    ws_mouse_latch_touch(&m,true,true,16,true);
    ws_mouse_latch_touch(&m,true,false,0,true);
    ws_mouse_latch_touch(&m,false,false,0,true);assert(!m.move && !m.drag && !m.buttons && !m.armed);
    ws_mouse_latch_touch(&m,true,true,16,true);assert(!m.drag);
    ws_mouse_latch_touch(&m,true,false,0,true);
    ws_mouse_latch_touch(&m,true,true,16,true);
    ws_mouse_latch_touch(&m,true,false,0,false);assert(!m.move && !m.drag && !m.buttons && !m.armed);
}
int main(void) {
    mouse();utility_regression(0);utility_regression(1);
    for(int mode=-1;mode<=4;++mode)
        assert(ws_controls_is_ble((PfControlMode)mode)==(mode==2 || mode==3));
    assert(ws_controls_hid_buttons(0xFFFF,false)==0xFF);
    assert(ws_controls_hid_buttons(0xFFFF,true)==0x33F);
    assert(ws_controls_hid_buttons(1U<<6,true)==1U<<8);
    assert(ws_controls_hid_buttons(1U<<7,true)==1U<<9);
    for(uint32_t i=0;i<3;++i) {
        uint32_t token=WS_CONTROLS_BOOT_MAGIC+i;
        assert(ws_controls_boot_mode(token,~token,true)==(PfControlMode)(i+1));
        assert(ws_controls_boot_mode(token,~token,false)==PF_CONTROL_NORMAL);
        assert(ws_controls_boot_mode(token,~token^1,true)==PF_CONTROL_NORMAL);
    }
    WsControlPrefs prefs;ws_controls_defaults(&prefs);assert(ws_controls_valid(&prefs));
    assert(sizeof(prefs)==6); // existing wsdev record is unchanged
    uint8_t legacy[]={1,1,0,0,0,23};
    assert(ws_controls_decode(&prefs,legacy,sizeof legacy) && prefs.deadzone==23 && !prefs.analog);
    legacy[5]=255;assert(!ws_controls_decode(&prefs,legacy,sizeof legacy) && prefs.deadzone==23);
    assert(!ws_controls_decode(&prefs,legacy,5));ws_controls_defaults(&prefs);
    for(unsigned o=0;o<2;++o) {
        WsGamepad g;ws_gamepad_init(&g);prefs.orientation=o;prefs.analog=1;
        WsControlPoint q=point(228,228,4,o);
        ws_gamepad_touch(&g,&prefs,true,&q,1,++now);assert(!g.report.buttons);
        up(&g,&prefs);ws_gamepad_touch(&g,&prefs,true,&q,1,++now);assert(g.report.buttons==1);
        up(&g,&prefs);assert(!g.report.buttons);
        static const unsigned masks[]={1,2,4,8,16,32,64,128,0,0};
        for(unsigned area=0;area<WS_PAD_AREA_COUNT;++area) {
            const WsPadRect *r=&ws_pad_layout[area];
            assert(r->x>=0 && r->y>=0 && r->x+r->w<=456 && r->y+r->h<=280);
            for(unsigned other=area+1;other<WS_PAD_AREA_COUNT;++other) {
                const WsPadRect *t=&ws_pad_layout[other];
                assert(r->x+r->w<=t->x || t->x+t->w<=r->x || r->y+r->h<=t->y || t->y+t->h<=r->y);
            }
            if(area>=WS_PAD_IMU)continue;
            tap(&g,&prefs,r->x+r->w/2,r->y+r->h/2);
            assert(g.report.buttons==masks[area]);
            assert(g.report.lt==(area==WS_PAD_LT?255:0));
            assert(g.report.rt==(area==WS_PAD_RT?255:0));
            up(&g,&prefs);assert(!g.report.buttons && !g.report.lt && !g.report.rt);
        }
        tap(&g,&prefs,228,184);assert(!g.report.buttons && !g.modal);up(&g,&prefs);
        assert(click(&g,&prefs,54,243)==WS_PAD_CALIBRATE && g.armed);
        up(&g,&prefs);
        // Stationary calibration works in flat and upright holding positions.
        for(int i=0;i<50;++i)sample(&g,0,0,16384);
        assert(g.imu.ready && g.imu.valid);
        ws_gamepad_apply_imu(&g,&prefs,true,now);assert(!g.report.x && !g.report.y);
        for(int i=0;i<20;++i)sample(&g,300,0,16384);
        ws_gamepad_apply_imu(&g,&prefs,true,now);assert(!g.report.x); // tremor/dead zone
        float sign=o?1.0f:-1.0f;
        for(int i=0;i<25;++i)sample(&g,sign*8000,-sign*8000,14000);
        ws_gamepad_touch(&g,&prefs,true,&q,1,++now);
        ws_gamepad_apply_imu(&g,&prefs,true,now);
        assert(g.report.x< -23000 && g.report.y>23000 && g.report.buttons==1);
        assert(hypot(g.report.x,g.report.y)<=32768); // saturated diagonal
        prefs.analog=0;ws_gamepad_apply_imu(&g,&prefs,true,now);assert(g.report.hat==7);
        ws_gamepad_apply_imu(&g,&prefs,false,now);assert(g.report.hat==8 && !g.report.buttons);
        sample(&g,NAN,0,1);assert(!g.imu.valid);
        ws_gamepad_apply_imu(&g,&prefs,true,now);assert(g.report.hat==8);
        for(int i=0;i<10;++i)sample(&g,0,0,16384);
        ws_gamepad_apply_imu(&g,&prefs,true,now+81);assert(g.report.hat==8); // stale sensor
        assert(click(&g,&prefs,228,148)==WS_PAD_CALIBRATE && g.armed);
        ws_gamepad_calibrate(&g);assert(!g.imu.ready && !g.report.buttons);
        for(int i=0;i<10;++i)sample(&g,0,16384,0);
        sample(&g,5000,15000,0);assert(g.imu.samples==1 && !g.imu.ready); // movement restarts
        for(int i=0;i<50;++i)sample(&g,0,16384,0);
        assert(g.imu.ready);up(&g,&prefs);
        for(int i=0;i<20;++i)sample(&g,sign*8000,14000,0);
        prefs.analog=1;ws_gamepad_apply_imu(&g,&prefs,true,now);assert(g.report.x< -30000);
        click(&g,&prefs,378,243);assert(g.modal==2 && !g.report.buttons);
        ws_gamepad_apply_imu(&g,&prefs,true,now);assert(!g.report.x && !g.report.y);
        assert(click(&g,&prefs,145,126)==WS_PAD_CALIBRATE);
        click(&g,&prefs,300,165);assert(g.modal==3);
        assert(click(&g,&prefs,145,190)==WS_PAD_FORGET && g.modal==2);
        for(int i=0;i<10;++i)click(&g,&prefs,80,210);
        assert(prefs.deadzone==5);
        for(int i=0;i<10;++i)click(&g,&prefs,180,210);
        assert(prefs.deadzone==35 && ws_controls_valid(&prefs));
        assert(click(&g,&prefs,300,210)==WS_PAD_SAVE && !g.modal && g.armed);
        tap(&g,&prefs,426,243);now+=1201;WsControlPoint exit=point(426,243,6,o);
        ws_gamepad_touch(&g,&prefs,true,&exit,1,now);assert(g.modal==1);
        assert(click(&g,&prefs,280,190)==WS_PAD_NONE && !g.modal);
        up(&g,&prefs);ws_gamepad_touch(&g,&prefs,false,&q,1,++now);
        ws_gamepad_apply_imu(&g,&prefs,true,now);assert(!g.report.x && !g.report.buttons && !g.armed);
    }
    puts("PASS: momentary MOVE, single-contact DRAG toggle, releases, unchanged prefs, IMU calibration/rotation/deadzone/digital/analog, button with tilt, utility press/release feedback, cancellation, expanded CENTER, neutral modals and guarded exit");
}
