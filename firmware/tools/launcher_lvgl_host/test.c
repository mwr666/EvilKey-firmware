/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "launcher-renderer.c"
PfControlMode pf_control_mode(void){return getenv("EVILKEY_TEST_BLE_PAD")?PF_CONTROL_BLE_PAD:getenv("EVILKEY_TEST_BLE_MOUSE")?PF_CONTROL_BLE_MOUSE:getenv("EVILKEY_TEST_USB_MOUSE")?PF_CONTROL_USB_MOUSE:PF_CONTROL_NORMAL;}
const char *pf_ble_last_status(void){return "";}
void pf_controls_preferences(WsControlPrefs *p){ws_controls_defaults(p);}
uint64_t host_time_us;
static uint16_t frame[280*456];
static uint8_t icons[9*8192];
static uint16_t app_pixels[280*456];
static uint32_t app_generation=1;
int ek_apps_copy_icons(uint8_t *p,size_t n,uint32_t *g){assert(n>=sizeof icons);if(*g==1)return 0;memcpy(p,icons,sizeof icons);*g=1;return 1;}
int ek_apps_copy_frame(uint16_t *p,size_t n,uint32_t *g,EkAppsDirty *d){assert(n>=280*456);if(*g==app_generation)return 0;memcpy(p,app_pixels,sizeof(app_pixels));*g=app_generation;d->x=0;d->y=0;d->width=280;d->height=456;return 1;}
esp_err_t ws_panel_wait_idle(uint32_t t){(void)t;return ESP_OK;}
esp_err_t ws_panel_flush_async(uint16_t x,uint16_t y,uint16_t x2,uint16_t y2,const uint16_t *p,size_t n,ws_panel_flush_done_cb_t done,void *ctx){
assert(x2<280 && y2<456);
if(pf_control_mode()==PF_CONTROL_USB_MOUSE || pf_control_mode()==PF_CONTROL_BLE_MOUSE){
 if((x&1)||(y&1)||!(x2&1)||!(y2&1))fprintf(stderr,"Unaligned mouse panel window: %u,%u..%u,%u\n",x,y,x2,y2);
 assert(!(x&1) && !(y&1) && (x2&1) && (y2&1));
}
if(pf_control_mode()==PF_CONTROL_BLE_PAD){
 assert(p==(const uint16_t *)s_rotation_dma);assert(n*2<=s_rotation_bytes);
 /* CO5300 windows start on even coordinates and end on odd coordinates.
    RAM-only rasterization previously accepted transfers the panel cannot. */
 if((x&1)||(y&1)||!(x2&1)||!(y2&1))fprintf(stderr,"Unaligned panel window: %u,%u..%u,%u\n",x,y,x2,y2);
 assert(!(x&1) && !(y&1) && (x2&1) && (y2&1));
}
assert(n==(size_t)(x2-x+1)*(y2-y+1));for(unsigned r=y;r<=y2;++r)memcpy(frame+r*280+x,p+(r-y)*(x2-x+1),(x2-x+1)*2);done(ctx);return ESP_OK;}
static void memory(const char *stage){lv_mem_monitor_t m;lv_mem_monitor(&m);printf("%s free=%u largest=%u used=%u%% peak=%u\n",stage,(unsigned)m.free_size,(unsigned)m.free_biggest_size,(unsigned)m.used_pct,(unsigned)m.max_used);fflush(stdout);}

static void render(ws_ui_snapshot_t *v){host_time_us+=16000;assert(ws_lvgl_render(v)==ESP_OK);lv_mem_monitor_t m;lv_mem_monitor(&m);assert(m.free_size>20000);assert(m.total_size-m.max_used>20000);}
static void mouse_redraw(ws_ui_snapshot_t *v){
 render(v);uint16_t *reference=malloc(sizeof frame);assert(reference);memcpy(reference,frame,sizeof frame);
 lv_obj_invalidate(ui.screen);render(v);assert(memcmp(reference,frame,sizeof frame)==0);free(reference);
}
static void ppm(const char *path){FILE *f=fopen(path,"wb");assert(f);fprintf(f,"P6\n280 456\n255\n");for(unsigned i=0;i<280*456;++i){uint16_t c=frame[i];c=(uint16_t)((c<<8)|(c>>8));unsigned char rgb[3]={((c>>11)&31)*255/31,((c>>5)&63)*255/63,(c&31)*255/31};assert(fwrite(rgb,1,3,f)==3);}assert(fclose(f)==0);}
static void launcher_dots(const ws_ui_snapshot_t *v){
 unsigned n=(v->apps_count+8)/9+1;assert(n<=9);
 for(unsigned i=0;i<9;++i){
  assert(lv_obj_has_flag(ui.launcher_dot[i],LV_OBJ_FLAG_HIDDEN)==(i>=n));
  if(i<n){
   assert(lv_obj_get_x(ui.launcher_dot[i])==(280-(int)((n-1)*18+6))/2+(int)i*18);
   assert(lv_obj_get_y(ui.launcher_dot[i])>=446);
   assert(lv_obj_get_y(ui.launcher_dot[i])+lv_obj_get_height(ui.launcher_dot[i])<=456);
   bool active=i==v->launcher_page;
   assert(lv_color_to32(lv_obj_get_style_bg_color(ui.launcher_dot[i],0))==lv_color_to32(color(active?v->accent_rgb:COL_FAINT)));
   assert(lv_obj_get_style_bg_opa(ui.launcher_dot[i],0)==(active?LV_OPA_COVER:LV_OPA_40));
  }
 }
}
static void test_launcher_dots(ws_ui_snapshot_t *v){
 v->apps_count=5;v->launcher_page=0;v->apps_catalog_generation=1;render(v);
 /* Keep icon generation, status, page and motion unchanged: catalog size
    alone must refresh both the number of dots and the introductory count. */
 v->apps_count=10;render(v);
 assert(!lv_obj_has_flag(ui.launcher_dot[2],LV_OBJ_FLAG_HIDDEN));
 assert(strcmp(lv_label_get_text(ui.launcher_count),"10 apps on microSD")==0);
 const unsigned counts[]={0,1,5,9,10,64};
 for(unsigned c=0;c<sizeof(counts)/sizeof(counts[0]);++c){
  v->apps_count=counts[c];unsigned pages=(counts[c]+8)/9;
  for(unsigned page=0;page<=pages;++page){
   v->launcher_page=page;render(v);launcher_dots(v);
  }
 }
 v->apps_count=5;v->launcher_page=0;render(v);
 uint16_t *dirty=malloc(sizeof(frame));assert(dirty);memcpy(dirty,frame,sizeof(frame));
 lv_obj_invalidate(ui.screen);render(v);
 assert(memcmp(dirty,frame,sizeof(frame))==0);free(dirty);
 uint16_t *reference=malloc(sizeof(frame));assert(reference);memcpy(reference,frame,sizeof(frame));
 for(unsigned t=0;t<=255;++t){v->launcher_transition=255-t;v->settings_transition=t;v->settings_open=true;render(v);launcher_dots(v);}
 for(unsigned t=0;t<=255;++t){v->launcher_transition=t;v->settings_transition=255-t;v->settings_open=false;render(v);launcher_dots(v);}
 unsigned mismatch=0;for(unsigned p=0;p<280*456;++p)if(frame[p]!=reference[p])++mismatch;
 assert(mismatch==0);
 free(reference);ppm("firmware/build/launcher-dots-intro.ppm");
 v->launcher_page=1;render(v);launcher_dots(v);ppm("firmware/build/launcher-dots-grid.ppm");
 puts("PASS Apps dots: count-only updates, centered/unclipped row, one active marker, intro/1..8 grids and all horizontal transition phases");
}
static void apps_settings_slide(ws_ui_snapshot_t *v,bool to_settings){
v->settings_open=to_settings;
for(unsigned i=0;i<=255;++i){
    v->settings_transition=to_settings?i:255-i;
    v->launcher_transition=to_settings?255-i:i;
    render(v);
    assert(lv_obj_has_flag(ui.main_group,LV_OBJ_FLAG_HIDDEN));
    if(i && i<255){
        assert(lv_obj_is_visible(ui.launcher_group) && lv_obj_is_visible(ui.settings_group));
        lv_coord_t left=lv_obj_get_x(ui.launcher_group);
        lv_coord_t right=lv_obj_get_x(ui.settings_group);
        if(!(left<=0 && right>=0 && left+WS_LCD_WIDTH==right))fprintf(stderr,"phase %u target %u left %d right %d width %u\n",i,to_settings,left,right,WS_LCD_WIDTH);
        assert(left<=0 && right>=0 && left+WS_LCD_WIDTH==right);
    }
    if(i==128)ppm(to_settings?"firmware/build/launcher-to-settings.ppm":"firmware/build/settings-to-launcher.ppm");
}}
/* Compare actual landing-page raster output outside the distinct icon area.
 * Exercise normal rendering, phase wrap, accent changes and animation OFF. */
static int test_landing_rings(void){
 assert(ws_lvgl_init()==ESP_OK);
 ws_ui_snapshot_t v={0};v.state=WS_UI_READY;v.apps_catalog_ready=true;v.apps_count=5;
 v.settings_storage_ok=v.manager_drive_storage_ok=v.usb_tool_storage_ok=true;
 uint16_t *reference=malloc(sizeof frame);assert(reference);
 const uint32_t accents[]={0x4de3c1,0xff8855};
 for(unsigned c=0;c<2;++c)for(unsigned animated=0;animated<2;++animated)
 for(unsigned phase=0;phase<256;++phase){
  v.accent_rgb=accents[c];v.settings_animation=animated;v.settings_motion_phase=phase;
  v.settings_open=true;v.settings_transition=255;v.launcher_transition=0;render(&v);
  memcpy(reference,frame,sizeof frame);
  if(c==0 && animated && phase==64)ppm("firmware/build/rings-settings.ppm");
  v.settings_open=false;v.settings_transition=0;v.launcher_transition=255;render(&v);
  if(c==0 && animated && phase==64)ppm("firmware/build/rings-apps.ppm");
  for(unsigned y=50;y<222;++y)for(unsigned x=54;x<226;++x){
   if(x>=80 && x<200 && y>=76 && y<196)continue;
   if(frame[y*280+x]!=reference[y*280+x]){
    fprintf(stderr,"Ring mismatch accent=%u animated=%u phase=%u at %u,%u\n",c,animated,phase,x,y);
    abort();
   }
  }
 }
 free(reference);memory("rings parity");
 puts("PASS: Apps/Settings ring pixels match at all 256 phases, 2 accents, animation ON/OFF; >20 KiB LVGL headroom");return 0;
}
int main(int argc,char **argv){if(argc==2 && strcmp(argv[1],"--rings-only")==0)return test_landing_rings();assert(argc==7);FILE *app=fopen(argv[6],"rb");assert(app);assert(fread(app_pixels,1,sizeof(app_pixels),app)==sizeof(app_pixels));fclose(app);assert(ws_lvgl_init()==ESP_OK);memory("init");ws_ui_snapshot_t v={0};v.state=WS_UI_READY;v.settings_animation=true;v.accent_rgb=0x4de3c1;
if(pf_control_mode()==PF_CONTROL_BLE_PAD) {
 assert(!s_pixels_b && s_draw_pixels==280*16 && s_rotation_bytes==LV_DISP_ROT_MAX_BUF);
 v.gamepad_active=true;ws_controls_defaults(&v.controls);v.gamepad.report.hat=8;
 for(unsigned orientation=0;orientation<2;++orientation){
  v.controls.orientation=orientation;
  for(unsigned modal=0;modal<4;++modal){
   v.gamepad.modal=modal;render(&v);
   uint16_t *reference=malloc(sizeof(frame));assert(reference);memcpy(reference,frame,sizeof(frame));
   lv_obj_invalidate(lv_scr_act());render(&v);assert(memcmp(reference,frame,sizeof(frame))==0);free(reference);
  }
 }
 ppm("firmware/build/gamepad-dma.ppm");
 puts("PASS: production Gamepad flush uses persistent DMA staging, small BLE buffers, both rotations and partial redraw");return 0;
}
if(pf_control_mode()==PF_CONTROL_BLE_MOUSE || pf_control_mode()==PF_CONTROL_USB_MOUSE) {
    bool ble=pf_control_mode()==PF_CONTROL_BLE_MOUSE;
    v.controls.transport=ble;v.air_mouse_active=true;v.air_mouse_sensor_ok=true;v.air_mouse_sensitivity=3;
    v.state=WS_UI_DISCONNECTED;render(&v);assert(strcmp(lv_label_get_text(ui.air_mouse_status),ble?"Pair BLE on host":"Connect USB")==0);
    v.ble_connected=true;v.ble_ready=true;v.state=WS_UI_READY;render(&v);
    assert(strcmp(lv_label_get_text(ui.air_mouse_title),"HOLD TO MOVE")==0);
    lv_area_t status_area,hint_area;lv_obj_get_coords(ui.air_mouse_status,&status_area);lv_obj_get_coords(ui.air_mouse_hint,&hint_area);
    assert(status_area.y2<hint_area.y1);
    for(unsigned i=0;i<10;++i){
     v.air_mouse_move_held=true;mouse_redraw(&v);assert(strcmp(lv_label_get_text(ui.air_mouse_title),"MOVING")==0);
     v.air_mouse_move_held=false;mouse_redraw(&v);assert(strcmp(lv_label_get_text(ui.air_mouse_title),"HOLD TO MOVE")==0);
    }
    v.air_mouse_move_held=true;v.air_mouse_drag_latched=true;v.air_mouse_buttons=1;mouse_redraw(&v);
    assert(strcmp(lv_label_get_text(ui.air_mouse_title),"DRAG ACTIVE")==0);
    assert(strcmp(lv_label_get_text(ui.air_mouse_drag_label),"DRAG ON")==0);
    ppm("firmware/build/airmouse-latched.ppm");
    v.air_mouse_move_held=false;v.air_mouse_drag_latched=false;v.air_mouse_buttons=0;mouse_redraw(&v);
    assert(strcmp(lv_label_get_text(ui.air_mouse_drag_label),"DRAG OFF")==0);
    assert(ws_ui_air_mouse_hit_test(false,50,200)==16);
    assert(ws_ui_air_mouse_hit_test(false,50,90)==3);
    if(!ble){puts("PASS USB mouse render");return 0;}
    v.air_mouse_settings_open=true;render(&v);
    assert(lv_obj_is_visible(ui.air_mouse_pair) && lv_obj_is_visible(ui.air_mouse_forget));
    assert(!lv_obj_is_visible(ui.air_mouse_group));
    lv_area_t area;lv_obj_get_coords(ui.air_mouse_settings_calibrate,&area);
    assert(area.x1==20 && area.y1==286 && area.y2==329);
    lv_obj_get_coords(ui.air_mouse_pair,&area);assert(area.x1==20 && area.y1==336 && area.x2==135 && area.y2==379);
    lv_obj_get_coords(ui.air_mouse_forget,&area);assert(area.x1==144 && area.y1==336 && area.x2==259 && area.y2==379);
    ppm("firmware/build/airmouse-ble-settings.ppm");
    v.air_mouse_ble_modal=1;render(&v);assert(lv_obj_is_visible(ui.air_mouse_ble_dialog));
    lv_obj_get_coords(lv_obj_get_child(ui.air_mouse_ble_dialog,2),&area);
    printf("BLE confirm YES coordinates %d %d %d %d\n",area.x1,area.y1,area.x2,area.y2);fflush(stdout);
    /* The modal's one-pixel border insets child coordinates. Its touch zone
       remains 20,250..135,307; the centers must agree within that border. */
    assert(area.x1==21 && area.y1==251 && area.x2==136 && area.y2==308);
    ppm("firmware/build/airmouse-ble-forget.ppm");
    v.air_mouse_ble_modal=0;render(&v);assert(!lv_obj_is_visible(ui.air_mouse_ble_dialog));
    uint16_t *reference=malloc(sizeof frame);assert(reference);memcpy(reference,frame,sizeof frame);
    lv_obj_invalidate(ui.screen);render(&v);assert(memcmp(reference,frame,sizeof frame)==0);free(reference);
    memory("BLE mouse");puts("PASS BLE mouse LVGL: pairing status, settings/confirmation geometry, dialog closes cleanly, partial redraw");return 0;
}
for(unsigned i=0;i<20;++i){v.animation_phase=i;render(&v);}memory("home");
for(unsigned i=0;i<=255;i+=15){v.settings_transition=i;v.settings_open=true;render(&v);}memory("settings transition");
v.settings_storage_ok=v.manager_drive_storage_ok=v.usb_tool_storage_ok=true;render(&v);ppm("firmware/build/settings-intro.ppm");
for(unsigned page=0;page<WS_SETTINGS_PAGE_COUNT;++page){v.settings_page=page;for(unsigned phase=0;phase<64;phase+=8){v.settings_motion_phase=phase;render(&v);}}memory("all Settings pages");
v.settings_page=WS_SETTINGS_PAGE_DIAGNOSTICS;v.diagnostics_enabled=true;v.apps_mount_ms=220;v.apps_scan_ms=38;v.apps_icon_ms=15;v.ui_poll_gap_ms=24;v.ui_render_ms=43;for(unsigned section=0;section<3;++section){v.diagnostics_tick=section*3;render(&v);}memory("Diagnostics three sections");
for(unsigned i=0;i<=255;i+=15){v.settings_transition=255-i;v.screensaver_transition=i;v.screensaver_open=true;render(&v);}memory("screensaver transition (inflater mocked)");
for(unsigned i=0;i<=255;i+=15){v.screensaver_transition=255-i;v.settings_transition=i;render(&v);}v.screensaver_open=false;
v.apps_catalog_generation=1;v.apps_catalog_ready=true;v.apps_count=5;v.apps_icon_valid=31;strcpy(v.apps_status,"Tap an app to run");
for(unsigned i=0;i<5;++i){FILE *f=fopen(argv[i+1],"rb");assert(f);assert(fseek(f,192,SEEK_SET)==0);assert(fread(v.apps_names[i],1,64,f)==64);assert(fseek(f,320,SEEK_SET)==0);assert(fread(icons+i*8192,1,8192,f)==8192);fclose(f);}
v.launcher_page=1;apps_settings_slide(&v,false);memory("launcher five icons");ppm("firmware/build/launcher-five.ppm");
v.settings_page=WS_SETTINGS_PAGE_HOME;
for(unsigned repeat=0;repeat<3;++repeat){apps_settings_slide(&v,true);apps_settings_slide(&v,false);}
puts("PASS Apps/Settings: every phase in both directions hides Home and shares a gap-free edge");
v.launcher_page=0;for(unsigned phase=0;phase<=255;++phase){v.settings_motion_phase=phase;render(&v);assert(lv_obj_is_visible(ui.launcher_intro));assert(!lv_obj_is_visible(ui.launcher_content));}ppm("firmware/build/launcher-intro.ppm");
apps_settings_slide(&v,true);apps_settings_slide(&v,false);
test_launcher_dots(&v);
for(unsigned count=0;count<=10;++count){v.apps_count=count;v.launcher_page=count?1:0;v.apps_icon_valid=(1u<<(count>9?9:count))-1;v.apps_catalog_generation=2+count;for(unsigned i=5;i<9;++i)snprintf(v.apps_names[i],64,"Fixture %u",i+1);render(&v);}
v.launcher_page=2;v.apps_icon_valid=1;render(&v);memory("launcher fixtures 0..10 and page 2");
v.apps_running=true;v.launcher_transition=255;render(&v);
assert(lv_obj_is_visible(ui.apps_exit_grip) && !lv_obj_is_visible(ui.apps_exit_pull));
assert(lv_obj_get_width(ui.apps_exit_grip)==40 && lv_obj_get_height(ui.apps_exit_grip)==40);
ppm("firmware/build/app-exit-idle.ppm");
v.apps_exit_dragging=true;v.apps_exit_progress=55;render(&v);
assert(lv_obj_is_visible(ui.apps_exit_pull) && lv_obj_is_visible(ui.apps_exit_dim));
assert(lv_obj_get_width(ui.apps_exit_fill)==94);
ppm("firmware/build/app-exit-drag.ppm");
v.apps_exit_progress=100;render(&v);assert(lv_obj_get_width(ui.apps_exit_fill)==172);
assert(strcmp(lv_label_get_text(ui.apps_exit_caption),"RELEASE TO CONFIRM")==0);
ppm("firmware/build/app-exit-ready.ppm");
v.apps_exit_dragging=false;v.apps_exit_confirm=true;render(&v);
assert(lv_obj_is_visible(ui.apps_exit_overlay) && !lv_obj_is_visible(ui.apps_exit_grip));
lv_area_t button;lv_obj_get_coords(ui.apps_exit_no,&button);
printf("NO coordinates %d %d %d %d\n",button.x1,button.y1,button.x2,button.y2);fflush(stdout);
assert(button.x1==EK_EXIT_NO_X && button.y1==EK_EXIT_Y && button.x2-button.x1+1==EK_EXIT_BUTTON_W);
lv_obj_get_coords(ui.apps_exit_yes,&button);assert(button.x1==EK_EXIT_YES_X && button.y1==EK_EXIT_Y);
ppm("firmware/build/app-exit-confirm.ppm");
v.apps_exit_confirm=false;render(&v);uint16_t grip_pixel=frame[22*280+22];
memset(app_pixels,0,sizeof(app_pixels));++app_generation;render(&v);
assert(frame[22*280+22]==grip_pixel); /* An app repaint cannot erase system chrome. */
assert(!lv_obj_is_visible(ui.apps_exit_overlay) && lv_obj_is_visible(ui.apps_exit_grip));
memory("app exit overlay");
v.apps_running=false;render(&v);assert(!lv_obj_is_visible(ui.apps_group));
puts("PASS actual LVGL: corner grip, progress 55/100, modal hit geometry, NO redraw, app repaint keeps grip, Apps return");
v.launcher_transition=0;v.state=WS_UI_PIN;render(&v);memory("PIN eviction");
puts("PASS actual LVGL: Home/Settings/Saver/Apps transitions, 10 Settings pages, 0..10 app layouts, PIN eviction, >20KiB free (panel/inflater mocked)");return 0;}
