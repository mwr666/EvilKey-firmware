/* Deterministic test of real board adapter + real display step; SPI/I2C/RTOS mocks. */
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#define FIDO_V1_MANAGER_DRIVE 1
#define FIDO_V1_USB_TOOL 1
#include "../../templates/port/ws_board.c"
#include "../../EvilKeyV1/src/apps/ek_exit_dialog.c"
static EkAppsState fake_apps;
static unsigned fake_apps_launches;
static unsigned fake_app_contacts;
static bool fake_app_modal;
static EkDiagnosticsExport fake_export;
static unsigned fake_export_calls;
static int critical_depth;
static unsigned admission_depth,admission_begins,admission_ends;
bool ek_render_frame_begin(unsigned client){assert(client==EK_RENDER_FRAME_DISPLAY&&!admission_depth&&critical_depth==0);++admission_begins;++admission_depth;return true;}
void ek_render_frame_end(bool owned){assert(owned&&admission_depth==1&&critical_depth==0);--admission_depth;++admission_ends;}
int ek_apps_diagnostics_export_request(void){
 ++fake_export_calls;if(fake_export.status==EK_DIAGNOSTICS_EXPORT_BUSY)return 0;
 ++fake_export.request;fake_export.status=EK_DIAGNOSTICS_EXPORT_BUSY;return 1;
}
void ek_apps_diagnostics_export_snapshot(EkDiagnosticsExport *out){*out=fake_export;}
/* This adapter test exercises NORMAL mode; BLE controls have a native suite. */
static PfControlMode fake_control_mode=PF_CONTROL_NORMAL;
PfControlMode pf_control_mode(void){return fake_control_mode;}
void pf_control_restart(PfControlMode mode){(void)mode;}
void pf_controls_preferences(WsControlPrefs *out){ws_controls_defaults(out);}
bool pf_controls_save(const WsControlPrefs *prefs){return ws_controls_valid(prefs);}
bool pf_ble_connected(void){return false;}
bool pf_ble_ready(void){return false;}
bool pf_ble_failed(void){return false;}
bool pf_ble_pad_report(const WsPadReport *report){(void)report;return false;}
void pf_ble_release(void){}
void pf_ble_pair(void){}
void pf_ble_forget(void){}
int ek_apps_start(void){return 1;}
void ek_apps_set_visible(bool visible){if(!visible)fake_apps.running=false;}
void ek_apps_set_modal(bool visible){fake_app_modal=visible;}
void ek_apps_snapshot(EkAppsState *out){*out=fake_apps;}
void ek_apps_input(const EvilKeyAppTouch *t,uint32_t count,bool valid,int32_t x,int32_t y,int32_t z)
{if(t)fake_app_contacts+=count;(void)valid;(void)x;(void)y;(void)z;}
void ek_apps_launch(unsigned i){if(i<fake_apps.count){++fake_apps_launches;fake_apps.running=true;}}
void ek_apps_select_page(unsigned page){if(!fake_apps.running && page*9<fake_apps.count)fake_apps.page=(uint8_t)page;}
void ek_apps_request(EkAppsCommand c){
 if(c==EK_APPS_STOP)fake_apps.running=false;
 else if(c==EK_APPS_NEXT && (unsigned)(fake_apps.page+1)*9<fake_apps.count)++fake_apps.page;
 else if(c==EK_APPS_PREV && fake_apps.page)--fake_apps.page;
}
bool pf_air_mouse_role(void){return false;}
bool pf_air_mouse_report(uint8_t b,int8_t x,int8_t y,int8_t w){(void)b;(void)x;(void)y;(void)w;return true;}
void pf_air_mouse_exit(void){}
void pf_air_mouse_restart_into(void){}
bool pf_usb_tool_confirmation_pending(void){return false;}
bool pf_usb_tool_confirm_stage8(void){return false;}
uint8_t pf_usb_tool_ducky_led(void){return 0;}
bool pf_usb_tool_storage_present(void){return false;}
uint32_t pf_usb_tool_storage_activity_age_ms(void){return 0;}
uint32_t pf_usb_tool_storage_activity_timeout_ms(void){return 0;}
bool cancel_button;
static ws_settings_t fake_settings;
static bool fake_drive_enabled=true,fake_drive_ro=true,fake_drive_ok=true,fake_media_ready=true;
static bool fake_tool_enabled=false,fake_tool_ok=true,fake_tool_media=true,fake_tool_running;
static ws_usb_layout_t fake_tool_layout=WS_USB_LAYOUT_US;
static char fake_tool_language[WS_USB_LANGUAGE_CODE_MAX]="us";
static uint16_t fake_tool_language_index=0;
static const char *fake_tool_languages[]={"us","de","fr"};
static uint16_t fake_tool_count=3,fake_tool_selected;
static unsigned fake_tool_run_calls,fake_tool_stop_calls,fake_tool_select_calls;
static bool fake_uv_ready=true;
static int fake_uv_retries=8,fake_supplied_result=0;
static bool fake_eject;static unsigned fake_drive_writes;
bool pf_manager_drive_take_eject(void){bool event=fake_eject;fake_eject=false;return event;}
static unsigned fake_supplied_calls,fake_drive_ro_writes,fake_drive_applies,fake_restarts;
static char fake_supplied_pin[WS_PIN_MAX_BYTES+1U];
static size_t fake_supplied_len;
void ws_manager_drive_state_init(void){}
bool ws_manager_drive_enabled(void){return fake_drive_enabled;}
bool ws_manager_drive_read_only(void){return fake_drive_ro;}
bool ws_manager_drive_storage_ok(void){return fake_drive_ok;}
bool ws_manager_drive_set_enabled(bool enabled){++fake_drive_writes;if(!fake_drive_ok)return false;fake_drive_enabled=enabled;return true;}
bool ws_manager_drive_set_read_only(bool ro){fake_drive_ro_writes++;if(!fake_drive_ok)return false;fake_drive_ro=ro;return true;}
bool pf_manager_drive_media_ready(void){return fake_media_ready;}
void pf_manager_drive_apply_read_only(bool ro){fake_drive_applies++;assert(ro==fake_drive_ro);}
void ws_usb_tool_state_init(void){}
bool ws_usb_tool_enabled(void){return fake_tool_enabled;}
bool ws_usb_tool_storage_ok(void){return fake_tool_ok;}
ws_usb_layout_t ws_usb_tool_layout(void){return fake_tool_layout;}
bool ws_usb_tool_set_enabled(bool enabled){if(!fake_tool_ok)return false;fake_tool_enabled=enabled;return true;}
bool ws_usb_tool_set_layout(ws_usb_layout_t layout){if(!fake_tool_ok||layout>=WS_USB_LAYOUT_COUNT)return false;fake_tool_layout=layout;return true;}
void ws_usb_tool_language_code(char *out,size_t n){if(out&&n)snprintf(out,n,"%s",fake_tool_language);}
bool ws_usb_tool_set_language_code(const char *code){if(!fake_tool_ok||!code||!*code)return false;snprintf(fake_tool_language,sizeof(fake_tool_language),"%s",code);return true;}
const char *ws_usb_tool_layout_name(ws_usb_layout_t l){(void)l;return "mock";}
bool pf_usb_tool_media_ready(void){return fake_tool_media;}
uint8_t pf_usb_tool_status(void){return fake_tool_running?3U:2U;}
bool pf_usb_tool_running(void){return fake_tool_running;}
uint16_t pf_usb_tool_script_count(void){return fake_tool_count;}
uint16_t pf_usb_tool_selected_index(void){return fake_tool_selected;}
void pf_usb_tool_selected_name(char *out,size_t n){if(out&&n){snprintf(out,n,"demo%u.duck",(unsigned)fake_tool_selected);}}
bool pf_usb_tool_select_delta(int delta){if(fake_tool_running||!fake_tool_count)return false;++fake_tool_select_calls;int n=(int)fake_tool_selected+delta;while(n<0)n+=fake_tool_count;while(n>=fake_tool_count)n-=fake_tool_count;fake_tool_selected=(uint16_t)n;return true;}
uint16_t pf_usb_tool_language_count(void){return 3U;}
uint16_t pf_usb_tool_language_index(void){return fake_tool_language_index;}
void pf_usb_tool_language_name(char *out,size_t n){if(out&&n)snprintf(out,n,"%s",fake_tool_languages[fake_tool_language_index]);}
bool pf_usb_tool_select_language_delta(int delta){if(fake_tool_running)return false;int n=(int)fake_tool_language_index+delta;while(n<0)n+=3;while(n>=3)n-=3;fake_tool_language_index=(uint16_t)n;snprintf(fake_tool_language,sizeof(fake_tool_language),"%s",fake_tool_languages[fake_tool_language_index]);return true;}
bool pf_usb_tool_run_selected(void){if(fake_tool_running||!fake_tool_media||!fake_tool_count)return false;++fake_tool_run_calls;fake_tool_running=true;return true;}
void pf_usb_tool_stop(void){if(fake_tool_running){++fake_tool_stop_calls;fake_tool_running=false;}}
uint32_t pf_usb_tool_error_line(void){return 0;}
void pf_usb_tool_status_text(char *out,size_t n){if(out&&n)snprintf(out,n,"%s",fake_tool_running?"Running":"Ready");}
void esp_restart(void){fake_restarts++;}
bool pf_local_uv_ready(void){return fake_uv_ready;}
int ws_uv_retries_get(void){return fake_uv_retries;}
bool ws_uv_retries_reserve(void){return true;}
bool ws_uv_retries_reset(void){return true;}
int pf_local_uv_verify_supplied_pin(const char *pin,size_t length){
 fake_supplied_calls++;fake_supplied_len=length;memset(fake_supplied_pin,0,sizeof(fake_supplied_pin));
 if(pin&&length<sizeof(fake_supplied_pin))memcpy(fake_supplied_pin,pin,length);return fake_supplied_result;
}
void ws_settings_init(void){ws_settings_defaults(&fake_settings);}
void ws_settings_get(ws_settings_t *s,bool *ok){if(s)*s=fake_settings;if(ok)*ok=true;}
ws_settings_result_t ws_settings_apply(const uint8_t *data,size_t len){
 ws_settings_t next;
 if(!ws_settings_decode(data,len,&next))return WS_SETTINGS_INVALID;
 if(next.revision!=fake_settings.revision || fake_settings.revision==UINT32_MAX)return WS_SETTINGS_STALE;
 next.revision++;fake_settings=next;return WS_SETTINGS_OK;
}
uint32_t ws_settings_uv_timeout_ms(void){return (uint32_t)fake_settings.uv_seconds*1000U;}
uint32_t ws_settings_presence_timeout_ms(void){return (uint32_t)fake_settings.presence_seconds*1000U;}

static uint32_t clock_ms, fake_mode;
static unsigned fake_points, renders, brightness_calls, enable_calls;
static uint16_t fake_x,fake_y;
static bool io_ok=true,render_ok=true,hold_boot,abort_now,display_running;
static unsigned delay_calls;
static uint8_t physical_brightness;
static bool physical_on;
static char operations[20000];static size_t operation_n;
static ws_display_cache_t display_cache;
static void op(char c){assert(critical_depth==0);assert(operation_n+1<sizeof(operations));operations[operation_n++]=c;operations[operation_n]=0;}
void test_enter(void){assert(critical_depth==0);++critical_depth;}
void test_exit(void){assert(critical_depth==1);--critical_depth;}
int64_t esp_timer_get_time(void){return (int64_t)clock_ms*1000;}
const char *esp_err_to_name(esp_err_t e){(void)e;return "mock";}
int gpio_get_level(int pin){(void)pin;return hold_boot?0:1;}
uint32_t led_get_mode(void){return fake_mode;}
esp_err_t ws_panel_init(void){physical_on=true;physical_brightness=0;return 0;}
esp_err_t ws_lvgl_init(void){return 0;}
esp_err_t ws_lvgl_render(const ws_ui_snapshot_t *v){assert(!v->screen_off&&admission_depth==1);op('R');++renders;return render_ok?0:-1;}
esp_err_t ws_panel_brightness(uint8_t n){assert(!admission_depth);op(n==0?'0':n==8?'D':'B');physical_brightness=n;++brightness_calls;return 0;}
esp_err_t ws_panel_set_enabled(bool b){assert(!admission_depth);op(b?'N':'F');physical_on=b;++enable_calls;return 0;}
esp_err_t i2c_param_config(int n,const i2c_config_t *c){(void)n;(void)c;return 0;}
esp_err_t i2c_driver_install(int a,int b,int c,int d,int e){(void)a;(void)b;(void)c;(void)d;(void)e;return 0;}
esp_err_t i2c_master_write_to_device(int a,uint8_t b,const uint8_t*c,size_t d,unsigned e){(void)a;(void)b;(void)c;(void)d;(void)e;return 0;}
esp_err_t i2c_master_write_read_device(int a,uint8_t b,const uint8_t*c,size_t d,uint8_t*o,size_t n,unsigned e){
 (void)a;(void)c;(void)d;(void)e;assert(critical_depth==0);
 if(b!=WS_TOUCH_ADDR)return -1;
 /* This NORMAL-mode fixture has no diagnostic register model. */
 if(n==1)return -1;
 assert(n==5 || n==11);memset(o,0,n);
 if(!io_ok)return -1;o[0]=fake_points;o[1]=fake_x>>8;o[2]=fake_x;o[3]=fake_y>>8;o[4]=fake_y;return 0;
}
void vTaskDelete(void*p){(void)p;}
int xTaskCreate(void(*f)(void*),const char*n,unsigned s,void*a,unsigned p,void*h){(void)f;(void)n;(void)s;(void)a;(void)p;(void)h;return pdPASS;}
static void tick(unsigned delta){clock_ms+=delta;ws_board_poll();if(display_running)(void)ws_display_step(&display_cache);}
void vTaskDelay(unsigned t){
 assert(critical_depth==0);++delay_calls;
 if(abort_now){ws_board_pin_abort();return;}
 tick(t*1000); /* Accelerated timeout simulation for the blocking PIN worker. */
}
static void reset(void){
 s_initialized=false;s_touch_available=false;s_panel_ok=false;s_pending=false;s_pin_active=false;s_pin_owner=WS_PIN_OWNER_NONE;
 s_touch_errors=0;s_touch_polled=0;s_feedback_pending=false;s_show_result=false;s_displayed_epoch=0;
 s_settings_open=false;s_settings_touch_was_down=false;s_settings_page=0;s_settings_transition=0;
 s_poll_at=s_poll_gap_max=s_render_ms_max=0;
 s_root_page=WS_ROOT_HOME;s_launcher_open=false;s_launcher_transition=s_launcher_from=s_launcher_to=0;
 s_launcher_page_offset=s_launcher_page_from=0;s_launcher_page=0;s_launcher_intro=true;s_launcher_page_direction=0;
 s_apps_touch_mode=false;s_apps_sensor_ok=false;memset(&fake_apps,0,sizeof(fake_apps));fake_apps_launches=0;
 fake_app_contacts=0;fake_app_modal=false;ek_exit_dialog_reset(&s_app_exit_dialog);
 s_settings_transition_from=0;s_settings_transition_to=0;s_settings_touch_action=0;
 s_settings_feedback=0;s_settings_page_offset=0;s_settings_page_offset_from=0;
 s_settings_transition_at=0;s_settings_page_transition_at=0;s_settings_feedback_at=0;s_settings_opened_at=0;
 s_screensaver_open=false;s_screensaver_transition=0;s_screensaver_transition_from=0;s_screensaver_transition_to=0;s_screensaver_transition_at=0;s_screensaver_opened_at=0;
 s_manager_restart_pending=false;s_usb_tool_restart_pending=false;s_usb_role_restart_at=0;
 memset(&s_touch,0,sizeof(s_touch));memset(&s_pinpad,0,sizeof(s_pinpad));memset(&s_presence,0,sizeof(s_presence));
 memset(&display_cache,0,sizeof(display_cache));
 clock_ms=100;fake_points=0;fake_eject=false;io_ok=render_ok=display_running=true;hold_boot=abort_now=cancel_button=false;
 fake_drive_enabled=true;fake_drive_ro=true;fake_drive_ok=true;fake_media_ready=true;fake_uv_ready=true;fake_uv_retries=8;fake_supplied_result=0;
 fake_tool_enabled=false;fake_tool_ok=true;fake_tool_media=true;fake_tool_running=false;fake_tool_layout=WS_USB_LAYOUT_US;snprintf(fake_tool_language,sizeof(fake_tool_language),"us");fake_tool_language_index=0;fake_tool_count=3;fake_tool_selected=0;fake_tool_run_calls=fake_tool_stop_calls=fake_tool_select_calls=0;
 fake_supplied_calls=fake_drive_ro_writes=fake_drive_applies=fake_restarts=0;fake_supplied_len=0;memset(fake_supplied_pin,0,sizeof(fake_supplied_pin));
 delay_calls=renders=brightness_calls=enable_calls=0;operation_n=0;operations[0]=0;fake_mode=MODE_MOUNTED;
 ws_board_init();ws_board_start_display();
 /* Synthetic resets share one host process: the real one-time startup
  * latch remains set, so reinitialize the mocked panel for each fixture. */
 s_panel_ok=ws_panel_init()==ESP_OK && ws_lvgl_init()==ESP_OK;
 tick(20);
}
static void sample(unsigned points,unsigned x,unsigned y,unsigned ms){fake_points=points;fake_x=x;fake_y=y;tick(ms);}
static void tap(unsigned x,unsigned y){sample(0,0,0,20);sample(0,0,0,80);sample(1,x,y,20);sample(1,x,y,60);sample(0,0,0,20);sample(0,0,0,80);}
static void swipe_next_root(void){sample(0,0,0,20);sample(1,244,220,20);sample(1,190,220,30);sample(1,126,220,30);sample(0,0,0,20);}
static void swipe_prev_root(void){sample(0,0,0,20);sample(1,42,220,20);sample(1,98,220,30);sample(1,166,220,30);sample(0,0,0,20);}
static void open_saver(void){swipe_prev_root();tick(WS_SCREENSAVER_TRANSITION_MS);}
static void swipe_up_settings(void){sample(0,0,0,20);sample(1,80,342,20);sample(1,80,292,30);sample(1,80,238,30);sample(0,0,0,20);}
static void swipe_down_settings(void){sample(0,0,0,20);sample(1,80,180,20);sample(1,80,236,30);sample(1,80,300,30);sample(0,0,0,20);}
static void page_up(void){swipe_up_settings();tick(WS_SETTINGS_PAGE_TRANSITION_MS);assert(s_view.settings_page_offset==0);}
static void make_off(void){tick(30000);assert(s_view.dim && physical_brightness==8);tick(59999);assert(physical_on);tick(1);assert(s_view.screen_off && !physical_on);}
static void begin_pin(void){s_pin_active=true;s_pin_owner=WS_PIN_OWNER_FIDO;s_pin_epoch=(s_pin_epoch+1U)|0x80000000U;s_pin_retries=8;s_pin_permissions=2;s_displayed_epoch=0;ws_pinpad_begin(&s_pinpad,clock_ms,120000);tick(20);}
static void open_usb_settings(void){swipe_next_root();tick(WS_SETTINGS_TRANSITION_MS);assert(s_view.settings_transition==255);for(unsigned i=0;i<WS_SETTINGS_PAGE_USB;++i)page_up();assert(s_view.settings_page==WS_SETTINGS_PAGE_USB);}
static void swipe_app_exit(void){
 sample(0,0,0,20);unsigned delivered=fake_app_contacts;
 sample(1,20,20,20);assert(s_app_exit_dialog.dragging && fake_app_modal);
 sample(1,65,100,30);assert(s_view.apps_exit_dragging && s_view.apps_exit_progress==50);
 sample(1,120,150,30);assert(s_view.apps_exit_progress==100 && !s_view.apps_exit_confirm);
 sample(1,279,220,30);assert(s_view.apps_exit_progress==100 && !s_view.apps_exit_confirm && fake_app_modal);
 sample(0,0,0,20);assert(s_view.apps_exit_confirm && fake_app_contacts==delivered);
}
static void test_exit_display_invalidation(void){
 reset();s_view.apps_running=true;s_view.launcher_transition=255;
 s_view.apps_frame=123;ws_display_cache_t cache={0};
 assert(ws_display_step(&cache));unsigned r=renders;
 assert(ws_display_step(&cache) && renders==r);
 s_view.apps_exit_dragging=true;
 assert(ws_display_step(&cache) && renders==++r);
 const unsigned progress[]={1,25,50,75,100,35,0};
 for(unsigned i=0;i<sizeof(progress)/sizeof(progress[0]);++i){
  s_view.apps_exit_progress=progress[i];
  assert(ws_display_step(&cache) && renders==++r);
  assert(cache.last.apps_frame==123); /* VM is paused: no new game frame. */
  assert(ws_display_step(&cache) && renders==r);
 }
 s_view.apps_exit_dragging=false;
 assert(ws_display_step(&cache) && renders==++r);
 assert(ws_display_step(&cache) && renders==r);
 puts("PASS exit display: start/progress/backtrack/cancel redraw a frozen app frame without redundant renders");
}
static void test_launcher(void){
 reset();fake_apps.ready=fake_apps.catalog_ready=fake_apps.mounted=true;
 fake_apps.count=10;fake_apps.icon_valid=0x1ff;tick(20);
 swipe_next_root();tick(WS_SETTINGS_TRANSITION_MS);
 assert(s_view.launcher_transition==255 && s_root_page==WS_ROOT_APPS && !s_settings_open);
 assert(s_view.launcher_page==0);
 tap(50,110);assert(fake_apps_launches==0); /* introduction has no launch targets */
 swipe_down_settings();tick(20);assert(s_view.launcher_page==2 && s_view.launcher_page_offset<0);
 tick(WS_SETTINGS_PAGE_TRANSITION_MS+100);assert(s_view.launcher_page==2);
 swipe_up_settings();tick(20);assert(s_view.launcher_page==0 && s_view.launcher_page_offset>0);
 tick(WS_SETTINGS_PAGE_TRANSITION_MS+100);
 swipe_up_settings();tick(20);tick(WS_SETTINGS_PAGE_TRANSITION_MS+100);
 assert(s_view.launcher_page==1 && fake_apps_launches==0);
 swipe_up_settings();tick(20);tick(WS_SETTINGS_PAGE_TRANSITION_MS+100);
 assert(s_view.launcher_page==2 && fake_apps_launches==0);
 tap(150,110);assert(fake_apps_launches==0); /* empty cell on the last page */
 swipe_up_settings();tick(20);tick(WS_SETTINGS_PAGE_TRANSITION_MS+100);assert(s_view.launcher_page==0);
 swipe_down_settings();tick(20);tick(WS_SETTINGS_PAGE_TRANSITION_MS+100);assert(s_view.launcher_page==2);
 tap(50,110);assert(fake_apps_launches==1 && fake_apps.running);
 unsigned delivered=fake_app_contacts;
 swipe_prev_root();tick(20);assert(!s_app_exit_dialog.visible && fake_apps.running);
 assert(fake_app_contacts>delivered && !fake_app_modal); /* ordinary horizontal app gesture */
 sample(1,80,20,20);sample(1,20,20,30);sample(1,180,20,30);sample(0,0,0,20);
 assert(!s_view.apps_exit_confirm && !fake_app_modal); /* slider crosses corner */
 sample(1,20,20,20);delivered=fake_app_contacts;
 sample(1,50,20,30);sample(0,0,0,20);
 assert(!s_view.apps_exit_confirm && !fake_app_modal && fake_app_contacts==delivered);
 sample(1,20,20,20);sample(2,110,20,30);sample(1,20,20,30);sample(1,120,20,30);
 assert(!s_view.apps_exit_confirm && fake_app_modal);sample(0,0,0,20);assert(!fake_app_modal);
 delivered=fake_app_contacts;
 sample(1,55,55,20);assert(s_view.apps_exit_dragging && fake_app_modal);
 sample(1,100,55,30);assert(s_view.apps_exit_progress==50);
 sample(0,0,0,20);assert(!s_view.apps_exit_confirm && !fake_app_modal && fake_app_contacts==delivered);
 swipe_app_exit();tick(20);assert(s_app_exit_dialog.visible && fake_apps.running);
 tap(EK_EXIT_NO_X+40,EK_EXIT_Y+20);assert(!s_app_exit_dialog.visible && fake_apps.running);
 assert(!fake_app_modal);swipe_app_exit();tick(20);assert(s_app_exit_dialog.visible);
 tap(EK_EXIT_YES_X+40,EK_EXIT_Y+20);tick(20);
 assert(!fake_apps.running && s_view.launcher_page==2 && s_root_page==WS_ROOT_APPS);
 swipe_down_settings();tick(20);tick(WS_SETTINGS_PAGE_TRANSITION_MS+100);assert(s_view.launcher_page==1);
 swipe_down_settings();tick(20);tick(WS_SETTINGS_PAGE_TRANSITION_MS+100);assert(s_view.launcher_page==0);
 swipe_prev_root();tick(WS_SETTINGS_TRANSITION_MS);assert(s_root_page==WS_ROOT_HOME);
 swipe_next_root();tick(WS_SETTINGS_TRANSITION_MS);assert(s_view.launcher_page==0);
 fake_apps.count=5;fake_apps.page=0;tick(20);
 swipe_down_settings();tick(20);tick(WS_SETTINGS_PAGE_TRANSITION_MS+100);assert(s_view.launcher_page==1);
 swipe_down_settings();tick(20);tick(WS_SETTINGS_PAGE_TRANSITION_MS+100);assert(s_view.launcher_page==0);
 swipe_up_settings();tick(20);tick(WS_SETTINGS_PAGE_TRANSITION_MS+100);assert(s_view.launcher_page==1);
 swipe_up_settings();tick(20);tick(WS_SETTINGS_PAGE_TRANSITION_MS+100);assert(s_view.launcher_page==0);
 swipe_next_root();tick(WS_SETTINGS_TRANSITION_MS);assert(s_root_page==WS_ROOT_SETTINGS);
 swipe_next_root();tick(WS_SETTINGS_TRANSITION_MS);assert(s_root_page==WS_ROOT_SETTINGS); /* end clamps */
 swipe_prev_root();tick(WS_SETTINGS_TRANSITION_MS);assert(s_root_page==WS_ROOT_APPS);
 ws_board_presence_begin(30000);tick(20);
 assert(s_view.state==WS_UI_WAITING && !s_view.launcher_transition && s_root_page==WS_ROOT_HOME);
 puts("PASS launcher: root gestures, cyclic intro/grid navigation (1/2 grids), finger-direction wrap, last-page gaps, swipe/tap exclusion, 56px corner, Yes/No return, security eviction");
}
int main(void){
 reset();fake_eject=true;unsigned writes=fake_drive_writes;bool ro=fake_drive_ro;tick(20);
 assert(!fake_drive_enabled&&s_manager_restart_pending&&!fake_restarts&&fake_drive_writes==writes+1&&fake_drive_ro==ro);
 fake_eject=true;tick(20);assert(fake_drive_writes==writes+1&&!fake_restarts);
 tick(679);assert(!fake_restarts);tick(1);assert(fake_restarts==1);
 reset();fake_drive_ok=false;fake_eject=true;writes=fake_drive_writes;tick(20);
 assert(fake_drive_enabled&&!s_manager_restart_pending&&!fake_restarts&&fake_drive_writes==writes+1);
 assert(s_settings_feedback==WS_SETTINGS_FEEDBACK_ERROR);tick(1000);assert(!fake_restarts&&fake_drive_writes==writes+1);
 puts("PASS completed host eject: one persistence, 700ms deferred restart, read-only unchanged, duplicate/error behavior");
 reset();ws_board_presence_begin(30000);fake_eject=true;tick(20);
 assert(cancel_button&&ws_board_presence_poll()==BUTTON_EV_CANCELLED);
 reset();begin_pin();fake_eject=true;tick(20);assert(!ws_board_pin_pending()&&s_pinpad.status==WS_PIN_CANCELLED);
 puts("PASS eject aborts pending presence and PIN without UP/UV approval");


 /* Board submits changed snapshots; the real LVGL suite separately checks
  * cache/deadline behavior and anchored Home/status icons. */
 reset();unsigned r=renders,b=brightness_calls;tick(1000);tick(1000);assert(renders>r && brightness_calls==b);
    fake_settings.animation=false;tick(20);r=renders;b=brightness_calls;tick(1000);tick(1000);assert(renders==r && brightness_calls==b);
    fake_settings.animation=true;tick(20);
 fake_mode=MODE_SUSPENDED;tick(20);assert(!s_view.dim && s_display_bright);
 make_off();r=renders;b=brightness_calls;unsigned e=enable_calls;tick(10000);tick(10000);
 assert(renders==r && brightness_calls==b && enable_calls==e);
 operation_n=0;operations[0]=0;sample(1,140,320,20);
 assert(!s_view.screen_off && !s_view.dim && physical_on && physical_brightness==90);
 assert(strcmp(operations,"RNB")==0 && !s_touch.valid && s_screen.block_touch);
 tick(5000);assert(!s_view.dim && s_screen.block_touch);
 sample(0,0,0,20);sample(0,0,0,60);assert(!s_screen.block_touch);
 puts("PASS board: animated snapshots submitted only while enabled; USB suspend independent; exact dim/off; off has no traffic; touch wake R->ON->brightness");
 reset();tick(30000);assert(s_view.dim);sample(1,140,320,20);assert(!s_view.dim && !s_touch.valid);
 tick(1000);assert(!s_view.dim);sample(0,0,0,20);sample(0,0,0,80);
 puts("PASS board: dimmed touch restores brightness without redimming");
 reset();make_off();fake_mode=MODE_PROCESSING;tick(20);assert(!s_view.screen_off && s_display_bright);
 puts("PASS board: processing request automatically wakes display");
 reset();make_off();begin_pin();assert(s_view.state==WS_UI_PIN && !s_view.screen_off && s_displayed_epoch==s_pin_epoch);
 tap(40,152);assert(s_pinpad.length==1 && s_pinpad.digits[0]=='1');
 puts("PASS board: new PIN prompt wakes; deliberately entered fresh digit accepted");
 reset();make_off();sample(1,40,152,20);begin_pin();sample(1,40,152,80);sample(0,0,0,20);sample(0,0,0,100);
 assert(s_pinpad.length==0);tap(40,152);assert(s_pinpad.length==1);
 puts("PASS board: wake touch carried into PIN never enters a digit");
 reset();make_off();sample(1,140,320,20);ws_board_presence_begin(30000);tick(20);
 sample(1,140,320,80);assert(ws_board_presence_poll()==BUTTON_EV_NONE);
 sample(0,0,0,20);assert(ws_board_presence_poll()==BUTTON_EV_NONE);
 sample(0,0,0,80);assert(ws_board_presence_poll()==BUTTON_EV_NONE);
 sample(0,0,0,80);assert(ws_board_presence_poll()==BUTTON_EV_NONE);
 sample(1,140,320,20);assert(ws_board_presence_poll()==BUTTON_EV_NONE);
 sample(1,140,320,80);assert(ws_board_presence_poll()==BUTTON_EV_NONE);
 sample(0,0,0,20);assert(ws_board_presence_poll()==BUTTON_EV_NONE);
 sample(0,0,0,80);assert(ws_board_presence_poll()==BUTTON_EV_PRESSED);
 puts("PASS board: wake gesture cannot approve; separate fresh approve can");
 reset();make_off();display_running=false;begin_pin();tap(40,152);assert(s_pinpad.length==0);
 display_running=true;tick(20);tap(40,152);assert(s_pinpad.length==1);
 puts("PASS board: no PIN input before completed visible prompt");
 reset();abort_now=true;char out[64];size_t len=999;
 assert(ws_board_get_pin(out,sizeof(out),&len,8,2)==1 && !ws_board_pin_pending());assert(len==0 && delay_calls==1);
 for(int i=0;i<64;++i)assert(out[i]==0);
 reset();hold_boot=true;len=999;assert(ws_board_get_pin(out,sizeof(out),&len,8,2)==2 && !ws_board_pin_pending());assert(len==0);
 reset();io_ok=false;for(int i=0;i<10;++i)tick(20);assert(!s_touch_available);tick(100000);assert(!s_view.screen_off && !s_view.dim);
 reset();render_ok=false;begin_pin();assert(!s_panel_ok && s_displayed_epoch==0);tick(20);assert(s_pinpad.status==WS_PIN_IO_ERROR);
 reset();ws_board_pin_feedback(0x3f);tick(20);assert(s_view.state==WS_UI_PIN_BAD);
 puts("PASS board: resync abort, zeroized PIN, no BOOT PIN bypass, timeout, I2C failure, render failure, bad-PIN feedback");
 reset();begin_pin();uint32_t stale_epoch=s_pin_epoch;ws_board_pin_abort();
 assert(!ws_board_pin_pending() && s_pin_epoch!=stale_epoch && s_pinpad.status==WS_PIN_CANCELLED);
 puts("PASS board hardening: PIN abort invalidates ownership immediately");
 reset();begin_pin();stale_epoch=s_pin_epoch;ws_board_presence_begin(30000);
 assert(!ws_board_pin_pending() && s_pin_epoch!=stale_epoch && s_pending && s_presence.active);
 puts("PASS board hardening: fresh presence supersedes an abandoned PIN request");
 reset();s_pending=true;s_presence.active=false;abort_now=true;len=999;
 assert(ws_board_get_pin(out,sizeof(out),&len,8,2)==1 && !s_pending && !ws_board_pin_pending());
 puts("PASS board hardening: terminal stale presence flag is recovered before local UV");
 reset();ws_presence_start(&s_presence,clock_ms,30000);s_pending=true;len=999;
 assert(ws_board_get_pin(out,sizeof(out),&len,8,2)==3 && s_pending && s_presence.active);
 puts("PASS board hardening: live presence request is never stolen by local UV");
 reset();assert(s_view.state==WS_UI_READY && s_view.screensaver_transition==0 && !s_view.screensaver_open);
 open_saver();assert(s_screensaver_open);
 assert(s_view.screensaver_transition==255 && s_view.screensaver_open && s_view.settings_transition==0);
 uint16_t saver_phase=s_view.screensaver_phase;
 uint16_t saver_text_phase=s_view.screensaver_text_phase;
 assert(saver_text_phase<16U); /* entry-relative R25 fade clock */
 tick(64);
 assert(s_view.screensaver_phase!=saver_phase && s_view.screensaver_text_phase!=saver_text_phase);
 swipe_next_root();tick(WS_SCREENSAVER_TRANSITION_MS);
 assert(!s_screensaver_open && s_view.screensaver_transition==0);
 puts("PASS board R20: READY swipe-right opens animated logo screensaver; swipe-left returns to idle");
 reset();fake_mode=MODE_SUSPENDED;tick(20);open_saver();
 assert(s_view.state==WS_UI_SUSPENDED && s_view.screensaver_transition==255);
 puts("PASS board R20: STANDBY exposes the same premium screensaver");
 reset();open_saver();assert(s_view.screensaver_transition==255);
 ws_board_presence_begin(30000);tick(20);
 assert(s_view.state==WS_UI_WAITING && s_view.screensaver_transition==0 && !s_screensaver_open);
 puts("PASS board R20 security: authentication state immediately evicts screensaver");
reset();assert(s_view.state==WS_UI_READY && s_view.settings_transition==0);
 swipe_next_root();assert(s_settings_open);tick(WS_SETTINGS_TRANSITION_MS);
 assert(s_view.settings_transition==255 && s_view.settings_page==WS_SETTINGS_PAGE_HOME && s_view.settings_open);
 /* R24: fully-open Settings stops the hidden main 62.5 Hz phase and advances
  * only its dedicated 64 ms / 256-step slow motion clock. */
 uint8_t settings_phase=s_view.settings_motion_phase;
 assert(s_view.animation_phase==0U);tick(64);
 assert(s_view.settings_motion_phase!=settings_phase && s_view.animation_phase==0U);
 puts("PASS board R25: Settings uses a dedicated seamless slow phase while hidden main motion is quiescent");
 /* No invisible tap target remains on READY; Settings opens only by swipe. */
 swipe_prev_root();tick(WS_SETTINGS_TRANSITION_MS);assert(!s_settings_open);
 tap(250,20);assert(!s_settings_open && s_view.settings_transition==0);
 swipe_next_root();tick(WS_SETTINGS_TRANSITION_MS);page_up();
 assert(s_view.settings_page==WS_SETTINGS_PAGE_DISPLAY);
 uint32_t rev=fake_settings.revision;uint8_t old_brightness=fake_settings.brightness;
 tap(230,204);assert(fake_settings.brightness>old_brightness && fake_settings.revision==rev+1);
 assert(s_view.settings_feedback==WS_SETTINGS_FEEDBACK_SAVED);
 page_up();assert(s_view.settings_page==WS_SETTINGS_PAGE_APPEARANCE);
 page_up();assert(s_view.settings_page==WS_SETTINGS_PAGE_POWER);
 uint16_t old_dim=fake_settings.dim_seconds;rev=fake_settings.revision;tap(230,204);
 assert(fake_settings.dim_seconds>old_dim && fake_settings.revision==rev+1);
 page_up();assert(s_view.settings_page==WS_SETTINGS_PAGE_AUTH);
 page_up();assert(s_view.settings_page==WS_SETTINGS_PAGE_DIAGNOSTICS);
 rev=fake_settings.revision;unsigned pin_calls=fake_supplied_calls,ro_writes=fake_drive_ro_writes;
 bool live=s_diagnostics_enabled;tap(80,400);
 assert(fake_export_calls==1&&fake_export.request==1&&s_view.diagnostics_export_status==EK_DIAGNOSTICS_EXPORT_BUSY);
 tap(80,400);assert(fake_export_calls==2&&fake_export.request==1);
 tap(200,400);assert(fake_export_calls==3&&fake_export.request==1); /* Full-width Save; busy worker rejects duplicate. */
 assert(fake_settings.revision==rev&&fake_supplied_calls==pin_calls&&fake_drive_ro_writes==ro_writes&&s_diagnostics_enabled==live);
 fake_export.status=EK_DIAGNOSTICS_EXPORT_SAVED;strcpy(fake_export.filename,"diag-00000001-0001.txt");tick(20);
 assert(!strcmp(s_view.diagnostics_export_message,fake_export.filename));
 fake_export.status=EK_DIAGNOSTICS_EXPORT_ERROR;strcpy(fake_export.error,"SD report verify failed");tick(20);
 assert(!strcmp(s_view.diagnostics_export_message,fake_export.error));
 puts("PASS Diagnostics export: release tap queues once, busy tap ignored, feedback propagated, live status/settings/PIN/USB policy preserved");
 page_up();assert(s_view.settings_page==WS_SETTINGS_PAGE_GAMEPAD);
 page_up();assert(s_view.settings_page==WS_SETTINGS_PAGE_AIR_MOUSE);
 page_up();assert(s_view.settings_page==WS_SETTINGS_PAGE_USB);
 page_up();assert(s_view.settings_page==WS_SETTINGS_PAGE_USB_TOOL);
 page_up();assert(s_view.settings_page==WS_SETTINGS_PAGE_HOME);
 swipe_down_settings();tick(WS_SETTINGS_PAGE_TRANSITION_MS);assert(s_view.settings_page==WS_SETTINGS_PAGE_USB_TOOL);
 swipe_prev_root();tick(WS_SETTINGS_TRANSITION_MS);
 assert(!s_settings_open && s_view.settings_transition==0);
 puts("PASS board: ten Settings pages cycle up/down and persist values");
 reset();fake_mode=MODE_SUSPENDED;tick(20);swipe_next_root();tick(WS_SETTINGS_TRANSITION_MS);
 assert(s_view.state==WS_UI_SUSPENDED && s_view.settings_transition==255);
 puts("PASS board R15: STANDBY exposes the same swipe-only Settings surface");
 reset();swipe_next_root();tick(WS_SETTINGS_TRANSITION_MS);assert(s_view.settings_transition==255);
 ws_board_presence_begin(30000);assert(s_view.state==WS_UI_WAITING && s_view.settings_transition==0 && !s_settings_open);
 sample(1,250,110,20);sample(0,0,0,20);assert(ws_board_presence_poll()==BUTTON_EV_NONE);
 puts("PASS board R15 security: authentication state immediately evicts Settings; setting coordinates cannot approve");
reset();open_usb_settings();assert(fake_drive_ro);
 /* R18 regression: a previous transport/CTAP cancellation can leave the
  * level flag asserted while the device is otherwise READY/STANDBY. Starting
  * this independent Settings PIN must establish a fresh cancellation scope. */
 cancel_button=true;
 tap(140,330);assert(!cancel_button);assert(ws_board_settings_pin_busy());assert(s_view.state==WS_UI_PIN);
 assert(s_view.pin_purpose==WS_PIN_PURPOSE_ENABLE_RW && fake_drive_ro && fake_supplied_calls==0);
 tap(40,152);tap(130,152);tap(220,152);tap(40,218);tap(220,350);
 assert(!ws_board_settings_pin_busy() && fake_supplied_calls==1 && fake_supplied_len==4);
 assert(!memcmp(fake_supplied_pin,"1234",4) && !fake_drive_ro && fake_drive_ro_writes==1 && fake_drive_applies==1);
 tick(WS_SETTINGS_TRANSITION_MS);assert(s_view.settings_transition==255 && s_view.settings_page==WS_SETTINGS_PAGE_USB);
 puts("PASS board R15: READ ONLY -> READ/WRITE requires fresh local FIDO PIN and applies only after success");
 reset();open_usb_settings();fake_supplied_result=0x3f;
 tap(140,330);tap(40,152);tap(130,152);tap(220,152);tap(40,218);tap(220,350);
 assert(fake_supplied_calls==1 && fake_drive_ro && fake_drive_ro_writes==0 && fake_drive_applies==0);
 assert(s_settings_feedback==WS_SETTINGS_FEEDBACK_PIN_BAD);
 puts("PASS board R15: wrong PIN leaves microSD READ ONLY");
 reset();fake_drive_ro=false;tick(20);open_usb_settings();tap(140,330);
 assert(fake_drive_ro && fake_drive_ro_writes==1 && fake_drive_applies==1 && fake_supplied_calls==0 && !ws_board_settings_pin_busy());
 puts("PASS board R15: READ/WRITE -> READ ONLY is immediate and PIN-free");
 reset();fake_uv_ready=false;open_usb_settings();tap(140,330);
 assert(fake_drive_ro && fake_supplied_calls==0 && !ws_board_settings_pin_busy());
 assert(s_settings_feedback==WS_SETTINGS_FEEDBACK_PIN_REQUIRED);
 puts("PASS board R15: write access cannot be enabled when no FIDO PIN is configured");
 reset();swipe_next_root();tick(WS_SETTINGS_TRANSITION_MS);for(unsigned i=0;i<WS_SETTINGS_PAGE_USB_TOOL;++i)page_up();
 assert(s_view.settings_page==WS_SETTINGS_PAGE_USB_TOOL && fake_drive_enabled && !fake_tool_enabled);
 tap(140,204);assert(fake_tool_enabled && !fake_drive_enabled && s_usb_tool_restart_pending && !s_manager_restart_pending && fake_restarts==0);
 assert(s_view.usb_tool_restarting && s_view.usb_tool_enabled);tick(700);assert(fake_restarts==1);
 puts("PASS board R26: enabling USB Tool disables Manager Drive first and restarts descriptor role");
 reset();fake_drive_enabled=false;fake_tool_enabled=true;tick(20);assert(s_view.usb_tool_enabled && s_view.usb_tool_script_count==3);
 tap(48,350);assert(fake_tool_selected==2 && fake_tool_select_calls==1);
 tap(232,350);assert(fake_tool_selected==0 && fake_tool_select_calls==2);
 tap(140,350);assert(fake_tool_running && fake_tool_run_calls==1 && fake_tool_stop_calls==0);
 tap(140,350);assert(!fake_tool_running && fake_tool_run_calls==1 && fake_tool_stop_calls==1);
 puts("PASS board R26: USB Tool PREV/NEXT and explicit local RUN/STOP actions drive only the runtime adapter");
 reset();fake_settings.brightness=130;fake_settings.dim_brightness=12;
 fake_settings.dim_seconds=5;fake_settings.off_seconds=6;fake_settings.accent_rgb=0x70B8FF;fake_settings.revision=9;
 tick(20);assert(s_view.brightness==130 && physical_brightness==130);
 assert(s_view.accent_rgb==0x70B8FF && s_view.settings_revision==9);
 tick(5000);assert(s_view.dim && physical_brightness==12);tick(6000);assert(s_view.screen_off);
 sample(1,50,300,20);assert(!s_view.screen_off && physical_brightness==130 && !s_touch.valid);
 puts("PASS board M1: runtime brightness, dim/off timing, palette, revision and consumed wake gesture");test_exit_display_invalidation();test_launcher();return 0;
 }
