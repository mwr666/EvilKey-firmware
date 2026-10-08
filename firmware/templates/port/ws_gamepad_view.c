/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "ws_gamepad_view.h"
#include "ws_panel.h"
#include "ws_gamepad_layout.h"
#include "ws_control_style.h"
#include <stdio.h>
#include <string.h>

#define BG WS_CONTROL_BG
#define PANEL WS_CONTROL_PANEL
#define TEXT WS_CONTROL_TEXT
#define MUTE WS_CONTROL_MUTED
#define BORDER WS_CONTROL_BORDER
#define INK WS_CONTROL_INK
#define AMBER WS_CONTROL_WARN
#define BAD WS_CONTROL_BAD
static uint32_t accent=WS_CONTROL_ACCENT_DEFAULT;
static lv_disp_t *display;
static uint8_t orientation;
static lv_obj_t *screen,*brand,*status,*mode,*settings_btn,*menu_back,*exit_btn,*exit_fill;
static lv_obj_t *shoulder[4],*face[4],*start,*select,*stick_base,*knob,*center;
static lv_obj_t *overlay,*modal_title,*modal_note,*options[7],*option_text[7],*yes,*no;
static lv_obj_t *deadzone_note,*imu_note,*lift_note;

static void caption(lv_obj_t *obj,const char *value) {
    if(strcmp(lv_label_get_text(obj),value))lv_label_set_text(obj,value);
}
static void visible(lv_obj_t *obj,bool show) {
    if(show)lv_obj_clear_flag(obj,LV_OBJ_FLAG_HIDDEN);else lv_obj_add_flag(obj,LV_OBJ_FLAG_HIDDEN);
}
static lv_obj_t *box(lv_obj_t *parent,int x,int y,int w,int h,int radius,uint32_t fill,uint32_t edge) {
    lv_obj_t *o=lv_obj_create(parent);lv_obj_remove_style_all(o);
    lv_obj_set_pos(o,x,y);lv_obj_set_size(o,w,h);
    lv_obj_set_style_radius(o,radius,0);lv_obj_set_style_bg_color(o,lv_color_hex(fill),0);
    if(fill==PANEL){lv_obj_set_style_bg_grad_color(o,lv_color_hex(0x0C1518),0);lv_obj_set_style_bg_grad_dir(o,LV_GRAD_DIR_VER,0);}
    lv_obj_set_style_bg_opa(o,LV_OPA_COVER,0);lv_obj_set_style_border_width(o,1,0);
    lv_obj_set_style_border_color(o,lv_color_hex(edge),0);
    lv_obj_clear_flag(o,LV_OBJ_FLAG_SCROLLABLE|LV_OBJ_FLAG_CLICKABLE);return o;
}
static lv_obj_t *text(lv_obj_t *parent,const char *s,int x,int y,int w,uint32_t color,const lv_font_t *font) {
    lv_obj_t *o=lv_label_create(parent);lv_obj_set_pos(o,x,y);lv_obj_set_width(o,w);
    lv_label_set_text(o,s);lv_obj_set_style_text_color(o,lv_color_hex(color),0);
    lv_obj_set_style_text_font(o,font,0);lv_obj_set_style_text_align(o,LV_TEXT_ALIGN_CENTER,0);
    return o;
}
static lv_obj_t *button(lv_obj_t *parent,const char *s,int x,int y,int w,int h,uint32_t color) {
    (void)color;
    lv_obj_t *o=box(parent,x,y,w,h,14,PANEL,BORDER);
    text(o,s,0,(h-20)/2,w,TEXT,&lv_font_montserrat_18);return o;
}
static lv_obj_t *pad_button(const char *s,WsPadArea area,uint32_t color) {
    const WsPadRect *r=&ws_pad_layout[area];
    return button(screen,s,r->x,r->y,r->w,r->h,color);
}
static void pressed(lv_obj_t *o,bool down,uint32_t color) {
    lv_obj_set_style_bg_grad_dir(o,down?LV_GRAD_DIR_NONE:LV_GRAD_DIR_VER,0);
    lv_color_t fill=lv_color_hex(down?color:PANEL),edge=lv_color_hex(down?color:BORDER);
    if(lv_color_to32(lv_obj_get_style_bg_color(o,0))!=lv_color_to32(fill))
        lv_obj_set_style_bg_color(o,fill,0);
    if(lv_color_to32(lv_obj_get_style_border_color(o,0))!=lv_color_to32(edge))
        lv_obj_set_style_border_color(o,edge,0);
    lv_obj_t *label=lv_obj_get_child(o,0);
    lv_color_t ink=lv_color_hex(down?INK:TEXT);
    if(lv_color_to32(lv_obj_get_style_text_color(label,0))!=lv_color_to32(ink))
        lv_obj_set_style_text_color(label,ink,0);
}
static bool ui_down(const ws_ui_snapshot_t *v,uint8_t control) {
    return v->gamepad.ui_modal==v->gamepad.modal && v->gamepad.ui_pressed==control;
}
void ws_gamepad_view_init(lv_disp_t *disp,const WsControlPrefs *prefs) {
    display=disp;orientation=prefs->orientation;
    lv_disp_set_rotation(disp,orientation?LV_DISP_ROT_90:LV_DISP_ROT_270);
    screen=lv_disp_get_scr_act(disp);lv_obj_remove_style_all(screen);
    lv_obj_set_style_bg_color(screen,lv_color_hex(BG),0);
    lv_obj_set_style_bg_opa(screen,LV_OPA_COVER,0);
    lv_obj_clear_flag(screen,LV_OBJ_FLAG_SCROLLABLE);
    brand=text(screen,"EVIL",8,4,38,accent,&lv_font_montserrat_14);
    text(screen,"GAMEPAD",48,2,100,TEXT,&lv_font_montserrat_18);
    status=text(screen,"Starting BLE...",180,5,268,accent,&lv_font_montserrat_12);
    lv_obj_set_style_text_align(status,LV_TEXT_ALIGN_RIGHT,0);
    box(screen,8,23,440,1,0,BORDER,BORDER);
    settings_btn=pad_button(LV_SYMBOL_SETTINGS,WS_PAD_SETTINGS,accent);
    exit_btn=pad_button("EXIT",WS_PAD_EXIT_AREA,AMBER);
    lv_obj_set_style_text_font(lv_obj_get_child(exit_btn,0),&lv_font_montserrat_14,0);
    lv_obj_set_y(lv_obj_get_child(exit_btn,0),15);
    exit_fill=box(exit_btn,4,41,1,3,1,AMBER,AMBER);visible(exit_fill,false);
    static const char *names[]={"LB","LT","RT","RB"};
    static const WsPadArea areas[]={WS_PAD_LB,WS_PAD_LT,WS_PAD_RT,WS_PAD_RB};
    for(unsigned i=0;i<4;++i)shoulder[i]=pad_button(names[i],areas[i],accent);
    const WsPadRect *imu=&ws_pad_layout[WS_PAD_IMU];
    stick_base=box(screen,imu->x,imu->y,imu->w,imu->h,32,PANEL,BORDER);
    text(stick_base,"TILT / IMU",0,4,64,MUTE,&lv_font_montserrat_12);
    knob=box(stick_base,26,26,12,12,6,accent,accent);
    mode=text(stick_base,"",0,48,64,MUTE,&lv_font_montserrat_12);
    center=pad_button("CENTER",WS_PAD_CENTER,accent);
    face[0]=pad_button("A",WS_PAD_A,accent);
    face[1]=pad_button("B",WS_PAD_B,accent);
    face[2]=pad_button("X",WS_PAD_X,accent);
    face[3]=pad_button("Y",WS_PAD_Y,accent);
    for(unsigned i=0;i<4;++i) {
        lv_obj_t *label=lv_obj_get_child(face[i],0);
        lv_obj_set_style_text_font(label,&lv_font_montserrat_28,0);
        lv_obj_set_y(label,22);
        lv_obj_set_style_radius(face[i],16,0);
    }
    start=pad_button("START",WS_PAD_START,accent);
    select=pad_button("SELECT",WS_PAD_SELECT,accent);
    overlay=box(screen,0,24,456,256,0,BG,BORDER);
    lv_obj_set_style_border_width(overlay,0,0);
    modal_title=text(overlay,"CONTROLLER",30,18,396,accent,&lv_font_montserrat_20);
    modal_note=text(overlay,"",30,78,396,MUTE,&lv_font_montserrat_18);
    for(unsigned i=0;i<7;++i) {
        const WsPadRect *r=&ws_pad_menu_layout[i];
        options[i]=button(overlay,"",r->x,r->y-24,r->w,r->h,accent);
        option_text[i]=lv_obj_get_child(options[i],0);
    }
    const WsPadRect *back=&ws_pad_menu_layout[7];
    menu_back=button(overlay,"BACK / SAVE",back->x,back->y-24,back->w,back->h,accent);
    deadzone_note=text(overlay,"",48,215,170,MUTE,&lv_font_montserrat_14);
    imu_note=text(overlay,"",238,215,170,MUTE,&lv_font_montserrat_14);
    const WsPadRect *confirm=ws_pad_confirm_layout;
    yes=button(overlay,"YES",confirm[0].x,confirm[0].y-24,confirm[0].w,confirm[0].h,BAD);
    no=button(overlay,"NO",confirm[1].x,confirm[1].y-24,confirm[1].w,confirm[1].h,accent);
    lift_note=text(overlay,"Lift your finger between selections",36,222,384,MUTE,&lv_font_montserrat_14);
    visible(overlay,false);
}
void ws_gamepad_view_render(const ws_ui_snapshot_t *v) {
    if(orientation!=v->controls.orientation) {
        if(ws_panel_wait_idle(500U)!=ESP_OK)return;
        orientation=v->controls.orientation;
        lv_disp_set_rotation(display,orientation?LV_DISP_ROT_90:LV_DISP_ROT_270);
        lv_obj_invalidate(screen);
    }
    accent=v->accent_rgb?v->accent_rgb:WS_CONTROL_ACCENT_DEFAULT;
    lv_obj_set_style_text_color(brand,lv_color_hex(accent),0);
    lv_obj_set_style_text_color(modal_title,lv_color_hex(accent),0);
    lv_obj_set_style_bg_color(knob,lv_color_hex(accent),0);
    lv_obj_set_style_border_color(knob,lv_color_hex(accent),0);
    caption(status,v->ble_failed?"BLE unavailable":v->ble_connected?"BLE CONNECTED":
        v->ble_ready?"PAIR ON HOST":"Starting BLE...");
    lv_obj_set_style_text_color(status,lv_color_hex(v->ble_failed?BAD:accent),0);
    caption(mode,v->gamepad.imu.ready && v->gamepad.imu.valid?
        (v->controls.analog?"ANALOG":"D-PAD"):
        !v->gamepad.imu.valid?"NO IMU":"WAIT...");
    const WsPadReport *r=&v->gamepad.report;
    for(unsigned i=0;i<4;++i)pressed(face[i],(r->buttons&(1U<<i))!=0,accent);
    pressed(shoulder[0],(r->buttons&16U)!=0,accent);pressed(shoulder[1],r->lt!=0,accent);
    pressed(shoulder[2],r->rt!=0,accent);pressed(shoulder[3],(r->buttons&32U)!=0,accent);
    pressed(start,(r->buttons&128U)!=0,accent);pressed(select,(r->buttons&64U)!=0,accent);
    pressed(center,ui_down(v,WS_PAD_UI_CENTER),accent);
    pressed(settings_btn,ui_down(v,WS_PAD_UI_SETTINGS),accent);
    pressed(exit_btn,ui_down(v,WS_PAD_UI_EXIT),accent);
    lv_obj_set_pos(knob,26+r->x*14/32767,26-r->y*9/32767);
    if(!v->controls.analog && r->hat!=8) {
        static const int dx[]={0,10,14,10,0,-10,-14,-10},dy[]={-9,-6,0,6,9,6,0,-6};
        lv_obj_set_pos(knob,26+dx[r->hat%8],26+dy[r->hat%8]);
    }
    visible(exit_fill,v->gamepad.hold_step!=0);
    lv_obj_set_width(exit_fill,1+v->gamepad.hold_step*(ws_pad_layout[WS_PAD_EXIT_AREA].w-9)/100);
    unsigned modal=v->gamepad.modal;
    visible(overlay,modal!=0);bool menu=modal==2;
    for(unsigned i=0;i<7;++i)visible(options[i],menu);
    visible(menu_back,menu);visible(yes,modal==1 || modal==3);visible(no,modal==1 || modal==3);
    visible(deadzone_note,menu);
    visible(imu_note,menu);visible(lift_note,!menu);
    visible(modal_note,!menu);
    caption(modal_title,menu?"CONTROLLER SETTINGS":modal==3?"FORGET PAIRING?":"RETURN TO EVILKEY?");
    caption(modal_note,modal==3?"Remove this profile's BLE bonds?":"Disconnect controller and restore FIDO?");
    for(unsigned i=0;i<7;++i)pressed(options[i],ui_down(v,WS_PAD_UI_MODE+i),accent);
    pressed(menu_back,ui_down(v,WS_PAD_UI_BACK),accent);
    pressed(yes,ui_down(v,WS_PAD_UI_YES),BAD);pressed(no,ui_down(v,WS_PAD_UI_NO),accent);
    if(menu) {
        caption(option_text[0],v->controls.analog?"IMU ANALOG":"IMU D-PAD");
        caption(option_text[1],"ROTATE 180");
        caption(option_text[2],"CALIBRATE - HOLD STILL");
        caption(option_text[3],"PAIR / CONNECT");
        caption(option_text[4],"FORGET PAIRING");
        caption(imu_note,!v->gamepad.imu.valid?"IMU NOT READY":
            v->gamepad.imu.ready?"CENTER SET":"HOLD STILL...");
        char zone[24];snprintf(zone,sizeof(zone),"DEAD ZONE: %u%%",v->controls.deadzone);
        caption(deadzone_note,zone);
        caption(option_text[5],"-");caption(option_text[6],"+");
    }
}
