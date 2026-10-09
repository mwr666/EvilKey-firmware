/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <windows.h>
#define EK_LVGL_TEST_CLOCK 1
#include "ek_render_parallel.h"
static bool override_core_stats;
static EkRenderWorkerStats core_stats;
static void ui_worker_stats(EkRenderWorkerStats *out){
 if(override_core_stats)*out=core_stats;else ek_render_worker_stats(out);
}
#define ek_render_worker_stats ui_worker_stats
static bool override_frame_stats;
static EkRenderFrameStats admission_stats;
static void ui_frame_stats(EkRenderFrameStats *out){if(override_frame_stats)*out=admission_stats;else ek_render_frame_stats(out);}
#define ek_render_frame_stats ui_frame_stats
#include "launcher-renderer.c"
#undef ek_render_worker_stats
#undef ek_render_frame_stats
PfControlMode pf_control_mode(void){return getenv("EVILKEY_TEST_BLE_PAD")?PF_CONTROL_BLE_PAD:getenv("EVILKEY_TEST_BLE_MOUSE")?PF_CONTROL_BLE_MOUSE:getenv("EVILKEY_TEST_USB_MOUSE")?PF_CONTROL_USB_MOUSE:PF_CONTROL_NORMAL;}
const char *pf_ble_last_status(void){return "";}
void pf_controls_preferences(WsControlPrefs *p){ws_controls_defaults(p);}
uint64_t host_time_us;
static bool real_timer;static uint64_t real_timer_start;
uint64_t host_test_time(void){return host_time_us+(real_timer?(GetTickCount64()-real_timer_start)*1000:0);}
static uint16_t frame[280*456];
static uint8_t icons[9*8192];
static uint16_t app_pixels[280*456];
static uint32_t app_generation=1;
static EkSceneProfile native_profile;
static char *submitted_report;static size_t submitted_report_size;
static unsigned report_submissions;static bool report_accept=true;
static char report_error[80];
int ek_apps_diagnostics_export(char *data,size_t size){
 if(!report_accept)return 0;
 assert(!submitted_report&&size<EK_DIAGNOSTICS_REPORT_CAPACITY);submitted_report=data;submitted_report_size=size;
 ++report_submissions;return 1;
}
void ek_apps_diagnostics_export_failed(const char *reason){snprintf(report_error,sizeof(report_error),"%s",reason);}
void ek_apps_scene_profile(EkSceneProfile *p){*p=native_profile;}
int ek_apps_copy_icons(uint8_t *p,size_t n,uint32_t *g){assert(n>=sizeof icons);if(*g==1)return 0;memcpy(p,icons,sizeof icons);*g=1;return 1;}
int ek_apps_copy_frame(uint16_t *p,size_t n,uint32_t *g,EkAppsDirty *d){assert(n>=280*456);if(*g==app_generation)return 0;memcpy(p,app_pixels,sizeof(app_pixels));*g=app_generation;d->x=0;d->y=0;d->width=280;d->height=456;return 1;}
int ek_apps_copy_frame_panel(uint16_t *p,size_t n,uint32_t *g,EkAppsDirty *d){
 if(!ek_apps_copy_frame(p,n,g,d))return 0;
 for(unsigned i=0;i<280*456;i++){uint16_t c=p[i];p[i]=(uint16_t)((c<<8)|(c>>8));}return 1;
}
static EkAppsCopyStats copy_stats;
void ek_apps_copy_stats(EkAppsCopyStats *p){if(p)*p=copy_stats;}
static const uint16_t *pending_dma;
static uint16_t pending_copy[280*64];
static size_t pending_pixels;
static bool direct_async;
static ws_panel_flush_done_cb_t pending_done;
static void *pending_context;
static bool panel_idle_fail,panel_submit_fail;
static void ppm(const char *path);
esp_err_t ws_panel_wait_idle(uint32_t t){(void)t;
 if(panel_idle_fail)return ESP_ERR_TIMEOUT;
 if(pending_dma){assert(memcmp(pending_dma,pending_copy,pending_pixels*2)==0);pending_dma=NULL;
  if(pending_done){ws_panel_flush_done_cb_t done=pending_done;void *ctx=pending_context;pending_done=NULL;done(ctx);
  }
 }
 return ESP_OK;}
esp_err_t ws_panel_flush_async(uint16_t x,uint16_t y,uint16_t x2,uint16_t y2,const uint16_t *p,size_t n,ws_panel_flush_done_cb_t done,void *ctx){
if(panel_submit_fail)return ESP_FAIL;
assert(ws_panel_wait_idle(500)==ESP_OK);
assert(x2<280 && y2<456);
assert(!(x&1) && !(y&1) && (x2&1) && (y2&1));
if(s_staging[0]) {
 assert(p==(const uint16_t *)s_staging[0] || p==(const uint16_t *)s_staging[1]);
 assert(n<=280*16);assert(!pending_dma);
 if(done==staging_done){pending_dma=p;pending_pixels=n;memcpy(pending_copy,p,n*2);}
}
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
assert(n==(size_t)(x2-x+1)*(y2-y+1));for(unsigned r=y;r<=y2;++r)memcpy(frame+r*280+x,p+(r-y)*(x2-x+1),(x2-x+1)*2);
if(direct_async&&!s_staging[0]){
 assert(p==(const uint16_t*)s_pixels_a||p==(const uint16_t*)s_pixels_b);
 assert(!pending_dma&&n<=280*64);pending_dma=p;pending_pixels=n;memcpy(pending_copy,p,n*2);
 pending_done=done;pending_context=ctx;
}else done(ctx);return ESP_OK;}
static void host_dma_wait(lv_disp_drv_t *drv){(void)drv;assert(ws_panel_wait_idle(500)==ESP_OK);}
static void memory(const char *stage){lv_mem_monitor_t m;lv_mem_monitor(&m);printf("%s free=%u largest=%u used=%u%% peak=%u\n",stage,(unsigned)m.free_size,(unsigned)m.free_biggest_size,(unsigned)m.used_pct,(unsigned)m.max_used);fflush(stdout);}

static void render(ws_ui_snapshot_t *v){host_time_us+=16000;assert(ws_lvgl_render(v)==ESP_OK);lv_mem_monitor_t m;lv_mem_monitor(&m);assert(m.free_size>20000);assert(m.total_size-m.max_used>20000);}
static void mouse_redraw(ws_ui_snapshot_t *v){
 render(v);uint16_t *reference=malloc(sizeof frame);assert(reference);memcpy(reference,frame,sizeof frame);
 lv_obj_invalidate(ui.screen);render(v);assert(memcmp(reference,frame,sizeof frame)==0);free(reference);
}
static void ppm(const char *path){FILE *f=fopen(path,"wb");assert(f);fprintf(f,"P6\n280 456\n255\n");for(unsigned i=0;i<280*456;++i){uint16_t c=frame[i];c=(uint16_t)((c<<8)|(c>>8));unsigned char rgb[3]={((c>>11)&31)*255/31,((c>>5)&63)*255/63,(c&31)*255/31};assert(fwrite(rgb,1,3,f)==3);}assert(fclose(f)==0);}
static void test_landing_halo(ws_ui_snapshot_t *v) {
 const ws_ui_snapshot_t saved=*v;
 v->settings_page=WS_SETTINGS_PAGE_HOME;v->launcher_page=0;
 v->screensaver_transition=0;v->screensaver_open=false;
 uint16_t *reference=malloc(sizeof frame);assert(reference);
 for(unsigned enabled=0;enabled<2;enabled++)for(unsigned phase=0;phase<256;phase+=17) {
  v->settings_animation=enabled;v->settings_motion_phase=phase;
  v->settings_open=true;v->settings_transition=255;v->launcher_transition=0;render(v);
  hidden(ui.settings_gear.root,true);lv_obj_invalidate(ui.screen);lv_refr_now(NULL);
  memcpy(reference,frame,sizeof frame);
  v->settings_open=false;v->settings_transition=0;v->launcher_transition=255;render(v);
  if(s_3d_available)hidden(s_3d_objects[WS_3D_APPS],true);
  for(unsigned i=0;i<9;i++)hidden(ui.launcher_tiles[i],true);
  lv_obj_invalidate(ui.screen);lv_refr_now(NULL);
  for(unsigned y=46;y<222;y++)for(unsigned x=50;x<230;x++)
   assert(reference[y*280+x]==frame[y*280+x]);
  hidden(ui.settings_gear.root,false);
  if(s_3d_available)hidden(s_3d_objects[WS_3D_APPS],false);
  else for(unsigned i=0;i<9;i++)hidden(ui.launcher_tiles[i],false);
 }
 free(reference);*v=saved;render(v);
 puts("PASS: Apps/Settings landing halos are pixel-identical at 16 phases, animation on/off, including classic fallback");
}

static void export_classic_icons(ws_ui_snapshot_t *v) {
 render(v);hidden(ui.hero_outer,true);hidden(ui.hero_mid,true);hidden(ui.hero_inner,true);
 hidden(ui.hero_orbit,true);hidden(ui.hero_glint,true);
 for(unsigned i=1;i<ICON_COUNT;i++) {
  icon_show_only((hero_icon_id_t)i);icon_tint(&ui.icons[i],0x4de3c1);
  lv_obj_set_style_opa(ui.icons[i].root,LV_OPA_COVER,0);
  for(unsigned j=0;j<ui.icons[i].count;j++)lv_obj_set_style_bg_grad_dir(ui.icons[i].part[j],LV_GRAD_DIR_NONE,0);
  if(i==HERO_SPINNER)update_spinner(0,0x4de3c1);
  lv_obj_invalidate(ui.screen);lv_refr_now(NULL);
  char path[100];snprintf(path,sizeof(path),"firmware/build/classic-icon-%u.ppm",i);ppm(path);
 }
 v->settings_transition=255;v->settings_open=true;v->settings_page=WS_SETTINGS_PAGE_HOME;render(v);
 hidden(ui.settings_glow,true);hidden(ui.settings_orbit,true);hidden(ui.settings_orbit_inner,true);hidden(ui.settings_glint,true);
 for(unsigned i=0;i<4;i++)hidden(ui.settings_spark[i],true);
 lv_obj_invalidate(ui.screen);lv_refr_now(NULL);ppm("firmware/build/classic-gear.ppm");
 v->settings_open=false;v->settings_transition=0;v->launcher_transition=255;
 v->launcher_page=0;v->apps_count=5;v->apps_catalog_ready=true;render(v);
 hidden(ui.launcher_glow,true);hidden(ui.launcher_orbit,true);hidden(ui.launcher_orbit_inner,true);
 lv_obj_invalidate(ui.screen);lv_refr_now(NULL);ppm("firmware/build/classic-apps.ppm");
 puts("PASS: exported original LVGL icon references without decorative surroundings");
}
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
static void jet_cadence_contract(void){
 if(!s_3d_available || pf_control_mode()!=PF_CONTROL_NORMAL)return;
 ws_ui_snapshot_t view={0};view.state=WS_UI_READY;view.accent_rgb=0x4de3c1;view.settings_animation=true;
 view.settings_open=true;view.settings_transition=255;view.settings_page=WS_SETTINGS_PAGE_HOME;
 host_time_us+=100000;assert(ws_lvgl_render(&view)==ESP_OK);
 unsigned before=ws_gui_3d_channel_stats(WS_3D_GEAR).frames;
 for(unsigned i=1;i<=125;++i){host_time_us+=8000;view.settings_motion_phase=(uint8_t)(i*8/24);assert(ws_lvgl_render(&view)==ESP_OK);}
 unsigned made=ws_gui_3d_channel_stats(WS_3D_GEAR).frames-before;
 assert(made>=28 && made<=31);
 assert(((lv_arc_t *)ui.settings_orbit)->rotation==(int)view.settings_motion_phase*360/256);
 printf("PASS: independent JET deadline makes %u frames per simulated second with 8ms LVGL ticks and 24ms phases; halo keeps its phase\n",made);
}
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
static unsigned label_failures;
static void label_fits(lv_obj_t *label){
 lv_point_t sz;lv_txt_get_size(&sz,lv_label_get_text(label),lv_obj_get_style_text_font(label,0),
   lv_obj_get_style_text_letter_space(label,0),lv_obj_get_style_text_line_space(label,0),
   lv_obj_get_content_width(label),LV_TEXT_FLAG_NONE);
 if(sz.y>lv_obj_get_content_height(label))fprintf(stderr,"Label exceeds height: %s (%d > %d)\n",lv_label_get_text(label),sz.y,lv_obj_get_content_height(label));
 if(sz.y>lv_obj_get_content_height(label))++label_failures;
}
static int test_native_profile_card(void){
 assert(ws_lvgl_init()==ESP_OK);
 ws_ui_snapshot_t v={0};v.state=WS_UI_READY;v.accent_rgb=0x4de3c1;
 v.settings_open=true;v.settings_transition=255;v.settings_page=WS_SETTINGS_PAGE_DIAGNOSTICS;v.diagnostics_enabled=true;
 v.diagnostics_tick=12;render(&v);assert(!strcmp(lv_label_get_text(ui.diagnostics_value),"No scene sample"));
 native_profile=(EkSceneProfile){{2,29874,132,20375},1200,300,20001,14500,8373,2400,1400};
 v.diagnostics_tick=13;render(&v);assert(strstr(lv_label_get_text(ui.diagnostics_memory),"Geom 20001 (raster 14500)"));
 for(unsigned card=0;card<7;card++){v.diagnostics_tick=card*3;render(&v);label_fits(ui.diagnostics_value);label_fits(ui.diagnostics_memory);}
 v.diagnostics_tick=18;render(&v);assert(!strcmp(lv_label_get_text(ui.diagnostics_title),"RENDER CORES"));
 override_core_stats=true;core_stats=(EkRenderWorkerStats){1,1,{UINT32_MAX,UINT32_MAX},{4096,4096}};
 render(&v);label_fits(ui.diagnostics_value);label_fits(ui.diagnostics_memory);
 native_profile=(EkSceneProfile){{2,UINT32_MAX,UINT32_MAX,UINT32_MAX},UINT32_MAX,UINT32_MAX,UINT32_MAX,UINT32_MAX,UINT32_MAX,UINT32_MAX,UINT32_MAX};
 copy_stats=(EkAppsCopyStats){UINT32_MAX,UINT32_MAX,UINT32_MAX,UINT32_MAX,UINT16_MAX,UINT16_MAX,1,2};
 override_frame_stats=true;memset(&admission_stats,255,sizeof admission_stats);
 v.diagnostics_export_status=EK_DIAGNOSTICS_EXPORT_BUSY;v.diagnostics_export_request=1;render(&v);
 assert(submitted_report&&report_submissions==1&&submitted_report_size<8192);
 const char *sections[]={"[draw_buffer]","[apps_catalog]","[ui_latency]","[app_frame_copy]","[gui_renderer]","[gui.Saver]","[gui.Settings]","[gui.Status]","[gui.Apps]","[native.last]","[render_cores]","[graphics_admission]"};
 for(unsigned i=0;i<sizeof sections/sizeof sections[0];i++)assert(strstr(submitted_report,sections[i]));
 const char *removed[]={"[previous_boot]","[copy_ab]","[display_ab]","[memory_probe]","[owner_task_probe]","[clock_probe]","[scene_comparison]","[native.first_timeout]"};
 for(unsigned i=0;i<sizeof removed/sizeof removed[0];i++)assert(!strstr(submitted_report,removed[i]));
 assert(strstr(submitted_report,"spec_revision=22")&&strstr(submitted_report,"report_end=complete")&&strstr(submitted_report,"native_wait_peak_us=4294967295"));
 FILE *report=fopen("firmware/build/diagnostics-report-max.txt","wb");assert(report);assert(fwrite(submitted_report,1,submitted_report_size,report)==submitted_report_size);fclose(report);
 free(submitted_report);submitted_report=NULL;render(&v);assert(report_submissions==1);
 for(unsigned state=0;state<4;state++){
  v.diagnostics_export_status=(uint8_t)state;v.diagnostics_enabled=state!=0;
  snprintf(v.diagnostics_export_message,sizeof v.diagnostics_export_message,"%s",state==2?"diag-FFFFFFFF-9999.txt":state==3?"SD report verify failed":"");
  render(&v);label_fits(ui.diagnostics_save_label);label_fits(ui.settings_subtitle);
  assert(ws_ui_settings_hit_test(WS_SETTINGS_PAGE_DIAGNOSTICS,20,378)==WS_SETTINGS_ACTION_DIAGNOSTICS_SAVE);
  assert(ws_ui_settings_hit_test(WS_SETTINGS_PAGE_DIAGNOSTICS,259,423)==WS_SETTINGS_ACTION_DIAGNOSTICS_SAVE);
  assert(ws_ui_settings_hit_test(WS_SETTINGS_PAGE_DIAGNOSTICS,260,423)==WS_SETTINGS_ACTION_NONE);
  char path[96];snprintf(path,sizeof path,"firmware/build/diagnostics-export-%u.ppm",state);ppm(path);
 }
 char tiny[8];size_t used=0;assert(!diagnostics_append(tiny,sizeof tiny,&used,"12345678")&&used==sizeof tiny);
 putenv("EVILKEY_TEST_DIAGNOSTICS_ALLOC_FAIL=1");diagnostics_report(&v);assert(!strcmp(report_error,"Report memory unavailable")&&!submitted_report);
 putenv("EVILKEY_TEST_DIAGNOSTICS_ALLOC_FAIL=");report_accept=false;diagnostics_report(&v);assert(!strcmp(report_error,"Report worker unavailable")&&!submitted_report);
 assert(!label_failures);puts("PASS ordinary Diagnostics: seven cards, full-width Save, complete bounded report, duplicate/allocation/worker errors and captures");return 0;
}
static DWORD WINAPI finish_test_flush(void *p){(void)p;Sleep(10);lv_disp_flush_ready(&s_disp_drv);return 0;}
static int wait_contract(){
 assert(ws_lvgl_init()==ESP_OK);assert(s_disp_drv.wait_cb);
 uint32_t id=ws_gui_3d_frame_begin((uint32_t)host_time_us);ws_gui_3d_frame_flush(id,2);
 s_draw_buf.flushing=1;real_timer_start=GetTickCount64();real_timer=true;
 HANDLE thread=CreateThread(NULL,0,finish_test_flush,NULL,0,NULL);assert(thread);
 s_disp_drv.wait_cb(&s_disp_drv);assert(!s_draw_buf.flushing);assert(WaitForSingleObject(thread,1000)==WAIT_OBJECT_0);CloseHandle(thread);
 uint32_t waited=ws_gui_3d_take_panel_wait();assert(waited>=5000);
 ws_gui_3d_frame_complete(id,(uint32_t)host_test_time());ws_gui_3d_frame_end(id,(uint32_t)host_test_time(),waited,true);
 ws_gui_3d_presentation_stats_t stats=ws_gui_3d_presentation_stats();assert(stats.lvgl_wait_us==waited&&stats.panel_wait_us==waited&&stats.peak_lvgl_wait_us==waited);
 host_time_us=host_test_time();real_timer=false;
 puts("PASS production LVGL wait callback: threaded completion, measured once, total/subset/peak attribution");return 0;
}
static int buffer_frames(){
 const char *failure=getenv("EVILKEY_TEST_DIRECT_FAIL");unsigned fail=failure?(unsigned)atoi(failure):0;
 esp_err_t init=ws_lvgl_init();
 if(fail==5){assert(init==ESP_ERR_NO_MEM);puts("PASS no DMA memory failure");return 0;}
 assert(init==ESP_OK);
 if(fail>=1&&fail<=3)assert(s_pixels_b&&s_draw_pixels==280*64&&s_staging[0]&&s_staging[1]);
 if(fail==4)assert(s_pixels_a&&!s_pixels_b&&!s_staging[0]&&s_draw_pixels==280*16);
 direct_async=true;s_disp_drv.wait_cb=host_dma_wait;
 if(getenv("EVILKEY_EXPECT_DIRECT16"))assert(s_pixels_b&&s_draw_pixels==280*16&&!s_staging[0]&&!s_staging[1]);
 FILE *out=fopen(getenv("EVILKEY_BUFFER_FRAMES"),"wb");assert(out);
 ws_ui_snapshot_t v={0};v.state=WS_UI_READY;v.accent_rgb=0x4de3c1;v.settings_animation=true;
 unsigned frames=0;
 for(unsigned sample=0;sample<100;sample++){
  v.launcher_transition=v.settings_transition=v.screensaver_transition=0;
  v.settings_open=v.screensaver_open=v.apps_running=v.apps_exit_dragging=v.apps_exit_confirm=false;
  v.state=WS_UI_READY;v.settings_motion_phase=sample*13;v.animation_phase=sample;
  if(sample<16){v.apps_running=true;v.launcher_transition=255;
   for(unsigned i=0;i<280*456;i++)app_pixels[i]=(uint16_t)(i*13+sample*1709);++app_generation;
   v.apps_exit_dragging=sample>=4&&sample<9;v.apps_exit_progress=(sample*19)%101;
   v.apps_exit_confirm=sample>=9;v.apps_exit_pressed=sample%3;
  }else if(sample<32){v.launcher_transition=255;v.apps_count=9;v.launcher_page=sample%2;v.apps_catalog_ready=true;}
  else if(sample<60){v.settings_open=true;v.settings_transition=255;v.settings_page=sample%WS_SETTINGS_PAGE_COUNT;
   if(v.settings_page==WS_SETTINGS_PAGE_DIAGNOSTICS)v.settings_page=WS_SETTINGS_PAGE_HOME;
   v.settings_storage_ok=true;v.brightness=70;v.dim_brightness=8;
  }else if(sample<80){v.screensaver_open=true;v.screensaver_transition=255;v.screensaver_phase=sample*3;v.screensaver_text_phase=sample;}
  else if(sample<90){v.state=WS_UI_PIN;v.pin_length=sample%7;v.uv_retries=3;v.touch_enabled=v.touch_available=true;v.seconds_left=90;}
  else {v.state=WS_UI_WAITING;v.seconds_left=30;v.touch_available=v.touch_enabled=true;}
  render(&v);assert(ws_panel_wait_idle(500)==ESP_OK);assert(fwrite(frame,1,sizeof frame,out)==sizeof frame);++frames;
  uint16_t reference[280*456];memcpy(reference,frame,sizeof frame);
  /* Hold the clock fixed: a full refresh must compare the same animation
     instant, including the production 33 ms Jet update gate. */
  lv_obj_invalidate(ui.screen);assert(ws_lvgl_render(&v)==ESP_OK);assert(ws_panel_wait_idle(500)==ESP_OK);
  if(memcmp(reference,frame,sizeof frame)){
   unsigned differences=0,first=280*456;for(unsigned i=0;i<280*456;i++)if(reference[i]!=frame[i]){if(first==280*456)first=i;++differences;}
   fprintf(stderr,"buffer parity sample=%u differences=%u first=%u,%u old=%04x new=%04x\n",sample,differences,first%280,first/280,reference[first],frame[first]);
  }
  assert(!memcmp(reference,frame,sizeof frame));
 }
 assert(!fclose(out));printf("PASS buffer assembled frames=%u, incremental/full identical\n",frames);return 0;
}
int main(int argc,char **argv){if(argc==2&&strcmp(argv[1],"--wait-contract")==0)return wait_contract();if(argc==2&&strcmp(argv[1],"--buffer-frames")==0)return buffer_frames();if(argc==2 && strcmp(argv[1],"--scene-profile-only")==0)return test_native_profile_card();if(argc==2 && strcmp(argv[1],"--rings-only")==0)return test_landing_rings();assert(argc==7);FILE *app=fopen(argv[6],"rb");assert(app);assert(fread(app_pixels,1,sizeof(app_pixels),app)==sizeof(app_pixels));fclose(app);assert(ws_lvgl_init()==ESP_OK);assert(pf_control_mode()==PF_CONTROL_BLE_PAD || s_3d_available==!getenv("EVILKEY_TEST_3D_FALLBACK"));memory("init");ws_ui_snapshot_t v={0};v.state=WS_UI_READY;v.settings_animation=true;v.accent_rgb=0x4de3c1;
if(getenv("EVILKEY_TEST_STAGING")&&!getenv("EVILKEY_TEST_DIRECT_FAIL")){assert(s_pixels_b&&s_draw_pixels==280*16&&!s_staging[0]);}
if(getenv("EVILKEY_EXPORT_CLASSIC_ICONS")){assert(!s_3d_available);export_classic_icons(&v);return 0;}
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
for(unsigned i=0;i<20;++i){v.animation_phase=i;render(&v);}memory("home");ppm("firmware/build/3d-ready.ppm");jet_cadence_contract();
test_landing_halo(&v);
for(unsigned i=0;i<=255;i+=15){v.settings_transition=i;v.settings_open=true;render(&v);}memory("settings transition");
v.settings_storage_ok=v.manager_drive_storage_ok=v.usb_tool_storage_ok=true;render(&v);ppm("firmware/build/settings-intro.ppm");
for(unsigned page=0;page<WS_SETTINGS_PAGE_COUNT;++page){v.settings_page=page;for(unsigned phase=0;phase<64;phase+=8){v.settings_motion_phase=phase;render(&v);}}memory("all Settings pages");
v.settings_page=WS_SETTINGS_PAGE_DIAGNOSTICS;v.diagnostics_enabled=true;v.apps_mount_ms=220;v.apps_scan_ms=38;v.apps_icon_ms=15;v.ui_poll_gap_ms=24;v.ui_render_ms=43;for(unsigned section=0;section<4;++section){v.diagnostics_tick=section*3;render(&v);
 if(section==2)assert(strstr(lv_label_get_text(ui.diagnostics_memory),"Frame P95"));
 if(section==3){assert(strstr(lv_label_get_text(ui.diagnostics_memory),"samples"));assert(strstr(lv_label_get_text(ui.diagnostics_memory),"live"));assert(!strstr(lv_label_get_text(ui.diagnostics_memory),"PSRAM"));}
}memory("Diagnostics four sections");ppm("firmware/build/3d-diagnostics.ppm");
v.settings_page=WS_SETTINGS_PAGE_HOME;
for(unsigned i=0;i<=255;i+=15){v.settings_transition=255-i;v.screensaver_transition=i;v.screensaver_open=true;render(&v);}
v.screensaver_phase=32;v.screensaver_text_phase=100;render(&v);ppm("firmware/build/3d-saver.ppm");
v.screensaver_phase=63;render(&v);ppm("firmware/build/3d-glitch.ppm");memory("screensaver transition (inflater mocked)");
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
v.launcher_transition=0;v.state=WS_UI_PIN;v.touch_enabled=v.touch_available=true;v.uv_retries=8;v.seconds_left=105;render(&v);memory("PIN eviction");ppm("firmware/build/3d-pin.ppm");
puts("PASS actual LVGL: Home/Settings/Saver/Apps transitions, 10 Settings pages, 0..10 app layouts, PIN eviction, >20KiB free (panel/inflater mocked)");return 0;}
