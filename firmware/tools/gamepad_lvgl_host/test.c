/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "ws_gamepad_view.c"
uint64_t host_time_us;
static uint16_t frame[280*456];
static unsigned flushes;
esp_err_t ws_panel_wait_idle(uint32_t t){(void)t;return ESP_OK;}
static void flush(lv_disp_drv_t *driver,const lv_area_t *area,lv_color_t *pixels) {
    assert(area->x1>=0 && area->x2<280 && area->y1>=0 && area->y2<456);
    unsigned width=area->x2-area->x1+1;
    for(int y=area->y1;y<=area->y2;++y)memcpy(frame+y*280+area->x1,pixels+(y-area->y1)*width,width*2);
    ++flushes;lv_disp_flush_ready(driver);
}
static void render(ws_ui_snapshot_t *v) {
    host_time_us+=16000;ws_gamepad_view_render(v);lv_refr_now(NULL);
    lv_mem_monitor_t m;lv_mem_monitor(&m);assert(m.free_size>40000);
}
static void ppm(const char *name) {
    char path[160];snprintf(path,sizeof(path),"firmware/build/%s.ppm",name);
    FILE *f=fopen(path,"wb");assert(f);fprintf(f,"P6\n280 456\n255\n");
    for(unsigned i=0;i<280*456;++i) {
        uint16_t c=frame[i];c=(uint16_t)((c<<8)|(c>>8));
        unsigned char rgb[3]={((c>>11)&31)*255/31,((c>>5)&63)*255/63,(c&31)*255/31};
        assert(fwrite(rgb,1,3,f)==3);
    }
    fclose(f);
}
int main(void) {
    lv_init();static lv_color_t pixels_a[280*64],pixels_b[280*64];
    lv_disp_draw_buf_t buffer;lv_disp_draw_buf_init(&buffer,pixels_a,pixels_b,280*64);
    lv_disp_drv_t driver;lv_disp_drv_init(&driver);driver.hor_res=280;driver.ver_res=456;
    driver.draw_buf=&buffer;driver.sw_rotate=1;driver.flush_cb=flush;
    lv_disp_t *disp=lv_disp_drv_register(&driver);assert(disp);
    ws_ui_snapshot_t v={0};ws_controls_defaults(&v.controls);v.gamepad.report.hat=8;
    ws_gamepad_view_init(disp,&v.controls);render(&v);
    assert(lv_disp_get_hor_res(disp)==456 && lv_disp_get_ver_res(disp)==280);
    lv_obj_t *targets[]={face[0],face[1],face[2],face[3],shoulder[0],shoulder[3],select,start,shoulder[1],shoulder[2],stick_base,center,settings_btn,exit_btn};
    for(unsigned i=0;i<sizeof(targets)/sizeof(targets[0]);++i) {
        lv_area_t area;lv_obj_get_coords(targets[i],&area);
        const WsPadRect *r=&ws_pad_layout[i];
        assert(area.x1==r->x && area.y1==r->y && area.x2==r->x+r->w-1 && area.y2==r->y+r->h-1);
    }
    lv_area_t status_area;lv_obj_get_coords(status,&status_area);assert(status_area.y2<24);
    v.ble_ready=true;render(&v);ppm("gamepad-dpad");
    v.ble_connected=true;v.gamepad.report.buttons=1|16|128;v.gamepad.report.hat=1;
    v.controls_touch_count=2;v.controls_touch_raw=2;v.controls_touch_max=2;v.controls_touch_valid=true;
    render(&v);ppm("gamepad-pressed");
    assert(strcmp(lv_label_get_text(mode),"NO IMU")==0);
    v.gamepad.imu.ready=v.gamepad.imu.valid=true;render(&v);
    assert(strcmp(lv_label_get_text(mode),"ANALOG")==0);
    uint16_t reference[280*456];memcpy(reference,frame,sizeof(frame));
    lv_obj_invalidate(screen);render(&v);assert(memcmp(reference,frame,sizeof(frame))==0);
    v.controls.analog=1;v.gamepad.report.x=18000;v.gamepad.report.y=22000;
    render(&v);ppm("gamepad-analog");
    for(int x=-32767;x<=32767;x+=32767)for(int y=-32767;y<=32767;y+=32767) {
        v.gamepad.report.x=x;v.gamepad.report.y=y;render(&v);
        lv_area_t area;lv_obj_get_coords(knob,&area);
        assert(area.x1>=196 && area.x2<260 && area.y1>=132 && area.y2<164);
    }
    v.gamepad.report.x=18000;v.gamepad.report.y=22000;
    v.controls_touch_probe=(WsFT3168Probe){.value={3,0,0,0,1,0},.valid_mask=63};
    uint8_t raw[15]={0,0,1,0x80,112,0,38,0,0,0xff,0xff,0xff,0xff,0,0};
    ws_ft3168_frame_observe(&v.controls_touch_frame,raw,sizeof(raw),true,1,true);
    for(unsigned modal=1;modal<=3;++modal){v.gamepad.modal=modal;render(&v);ppm(modal==1?"gamepad-exit":modal==2?"gamepad-settings":"gamepad-forget");
        if(modal==2) {
            assert(strcmp(lv_label_get_text(option_text[2]),"CALIBRATE - HOLD STILL")==0);
            assert(strcmp(lv_label_get_text(imu_note),"CENTER SET")==0);
            lv_area_t area;lv_obj_get_coords(imu_note,&area);assert(area.y2<280 && area.x2<456);
            for(unsigned i=0;i<7;++i){lv_obj_get_coords(options[i],&area);assert(area.y2<280 && area.x2<456);}

        }
    }
    // Utility feedback uses the same palette as AirMouse and never shifts labels.
    v.gamepad.report=(WsPadReport){.hat=8};v.gamepad.modal=0;v.gamepad.ui_modal=0;
    v.gamepad.ui_pressed=WS_PAD_UI_CENTER;v.accent_rgb=0x4DE3C1;render(&v);ppm("gamepad-center");
    assert(lv_color_to32(lv_obj_get_style_bg_color(center,0))==lv_color_to32(lv_color_hex(v.accent_rgb)));
    assert(lv_obj_get_style_border_width(center,0)==1);
    v.gamepad.ui_pressed=0;render(&v);
    assert(lv_color_to32(lv_obj_get_style_bg_color(center,0))==lv_color_to32(lv_color_hex(WS_CONTROL_PANEL)));
    v.gamepad.modal=2;v.gamepad.ui_modal=2;
    for(unsigned i=0;i<8;++i) {
        lv_obj_t *o=i<7?options[i]:menu_back;
        v.gamepad.ui_pressed=WS_PAD_UI_MODE+i;render(&v);
        lv_area_t area;lv_obj_get_coords(o,&area);const WsPadRect *r=&ws_pad_menu_layout[i];
        assert(area.x1==r->x && area.y1==r->y && area.x2==r->x+r->w-1 && area.y2==r->y+r->h-1);
        assert(lv_color_to32(lv_obj_get_style_bg_color(o,0))==lv_color_to32(lv_color_hex(v.accent_rgb)));
        memcpy(reference,frame,sizeof(frame));lv_obj_invalidate(screen);render(&v);
        assert(memcmp(reference,frame,sizeof(frame))==0);
        v.gamepad.ui_pressed=0;render(&v);
        assert(lv_color_to32(lv_obj_get_style_bg_color(o,0))==lv_color_to32(lv_color_hex(WS_CONTROL_PANEL)));
    }
    v.gamepad.ui_pressed=WS_PAD_UI_MODE;render(&v);ppm("gamepad-settings-pressed");
    for(unsigned modal=1;modal<=3;modal+=2) {
        v.gamepad.modal=modal;v.gamepad.ui_modal=modal;
        for(unsigned i=0;i<2;++i) {
            v.gamepad.ui_pressed=WS_PAD_UI_YES+i;render(&v);
            lv_area_t area;lv_obj_get_coords(i?no:yes,&area);
            assert(area.x1==ws_pad_confirm_layout[i].x && area.y1==ws_pad_confirm_layout[i].y);
        }
    }
    v.gamepad.ui_pressed=0;v.controls.orientation=0;render(&v);ppm("gamepad-rotated");
    v.gamepad.modal=0;v.gamepad.hold_step=100;render(&v);
    v.ble_failed=true;render(&v);assert(strcmp(lv_label_get_text(status),"BLE unavailable")==0);
    assert(flushes>10);puts("PASS: actual LVGL landscape rotation, bounded physical flushes, modals, clean partial redraw and memory margin");
}
