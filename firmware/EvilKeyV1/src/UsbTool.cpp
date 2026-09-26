/* SPDX-License-Identifier: AGPL-3.0-or-later
 * PicoFido USB Tool runtime adapter.
 *
 * DuckyScript parsing is supplied by the exact pinned s3-ducky revision during
 * prepare_arduino.py. This file owns only PicoFido integration: explicit local
 * launch, microSD payload selection, TinyUSB reports and keyboard layouts.
 *
 * Printable ASCII layout tables are adapted from Arduino Keyboard 1.0.7
 * (arduino-libraries/Keyboard commit 3f7bad0a41839689684e3b46ce9deb0232f8ec2d,
 * LGPL-3.0). See data/upstream-licenses/arduino_keyboard_LICENSE.
 */
#include "pf_build_config.h"
#include "UsbTool.h"
#include "UsbToolHidOut.h"
#include "pf_engine_api.h"
#include "LootIndexFormat.h"
#include "Hak5Language.h"
#include <Arduino.h>
#include <SPI.h>
#include <SD.h>
#include "esp32-hal-tinyusb.h"
#include "esp_heap_caps.h"
#include "esp_random.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "engine/board/ws_pins.h"
#include "engine/board/ws_usb_tool_state.h"
#include "engine/ducky/components/ducky/include/ducky.h"
#include "engine/ducky/components/ducky/include/ducky_hid_codes.h"
#include "mbedtls/sha256.h"
#include <cstring>
#include <strings.h>
#include <cstdlib>

#ifndef FIDO_V1_USB_TOOL_SD_HZ
#define FIDO_V1_USB_TOOL_SD_HZ 20000000UL
#endif
#ifndef FIDO_V1_USB_TOOL_MAX_PAYLOAD
#define FIDO_V1_USB_TOOL_MAX_PAYLOAD (256U*1024U)
#endif
#ifndef FIDO_V1_USB_TOOL_VARIABLE_EXFIL
#define FIDO_V1_USB_TOOL_VARIABLE_EXFIL 0
#endif
#ifndef FIDO_V1_USB_TOOL_KEYSTROKE_REFLECTION
#define FIDO_V1_USB_TOOL_KEYSTROKE_REFLECTION 0
#endif
#define PF_STAGE8_SESSION_LIMIT (64U*1024U)
#define PF_STAGE8_LOOT_LIMIT (256U*1024U)
#define PF_STAGE8_CONFIRM_WINDOW_MS 15000U
#define PF_STAGE8_REFLECTION_MAX_MS 120000U
#define PF_STORAGE_AUTO_DETACH_IDLE_MS 10000U

static const char *TAG="pf_usb_tool";
static SPIClass s_sd_spi(HSPI);
static bool s_sd_ready;
#define PF_DUCKY_WORKER_STACK_BYTES 8192U
static TaskHandle_t s_worker;
static StaticTask_t s_worker_tcb;
static StackType_t s_worker_stack[PF_DUCKY_WORKER_STACK_BYTES];
static volatile bool s_script_running;
static volatile bool s_stop;
static volatile uint8_t s_leds;
static volatile bool s_received_led_report;
static volatile uint16_t s_host_configuration_request_count;
static volatile uint8_t s_attackmode=1U;
static volatile bool s_attackmode_identity_custom;
static volatile bool s_storage_was_exposed;
static bool s_storage_view_stale;
static bool s_storage_auto_detach_pending;
static uint32_t s_storage_auto_detach_last_second=UINT32_MAX;
static bool s_button_was_down;
static bool s_button_event_seen;
static uint32_t s_button_last_event_ms;
static volatile uint8_t s_ducky_led=PF_USB_TOOL_LED_OFF;
static volatile bool s_ducky_led_command_seen;
static volatile uint8_t s_ducky_led_options=DUCKY_LED_OPT_SYSTEM|DUCKY_LED_OPT_STORAGE|
    DUCKY_LED_OPT_CONTINUOUS_STORAGE|DUCKY_LED_OPT_INJECTING|DUCKY_LED_OPT_EXFIL;
static volatile uint32_t s_storage_activity_timeout_ms=1000U;
static portMUX_TYPE s_guard=portMUX_INITIALIZER_UNLOCKED;
static pf_usb_tool_status_t s_status=PF_USB_TOOL_DISABLED;
static uint32_t s_error_line;
static char s_status_detail[96];
static constexpr uint16_t MAX_SCRIPTS=320;
static constexpr size_t MAX_PATH=192;
static constexpr size_t MAX_NAME=80;
static constexpr uint16_t MAX_LANGUAGES=40;
static constexpr size_t MAX_LANGUAGE_CODE=20;
static constexpr size_t MAX_LANGUAGE_PATH=128;
static char **s_scripts;
static uint16_t s_script_count;
static uint16_t s_selected;
static bool s_script_index_truncated;

typedef struct {
    char code[MAX_LANGUAGE_CODE];
    char path[MAX_LANGUAGE_PATH];
    uint8_t builtin_layout;
    bool external;
} pf_language_entry_t;

static pf_language_entry_t *s_languages;
static uint16_t s_language_count;
static uint16_t s_language_selected;
static pf_hak5_key_t s_active_ascii[95];
static File s_loot_file;
static volatile bool s_loot_open;
static uint32_t s_loot_writer_size;
static pf_loot_segment_t *s_loot_segments;
static uint16_t s_loot_segment_count;
static bool s_loot_index_loaded;
static bool s_loot_index_dirty;
static bool s_loot_index_fault;
static volatile bool s_exfil_mode;
static volatile bool s_reflection_receiving;
static uint32_t s_stage8_session_bytes;
static uint32_t s_stage8_authorized_caps;
static volatile uint8_t s_stage8_fault;
static uint32_t s_reflection_started_ms;
static uint8_t s_reflection_last_leds;
static uint8_t s_reflection_accumulator;
static uint8_t s_reflection_bit_count;
static uint8_t s_reflection_ring[256];
static uint16_t s_reflection_head,s_reflection_tail,s_reflection_count;
static uint8_t s_pending_digest[32];
static uint32_t s_pending_caps;
static uint32_t s_pending_deadline_ms;
static uint16_t s_pending_index;
static bool s_confirmed_run;

/* Report IDs are shared with the descriptor in PicoFidoArduino.cpp. */
enum {
    PF_RID_KEYBOARD=1,
    PF_RID_MOUSE=2,
    PF_RID_CONSUMER=3,
    PF_RID_SYSTEM=4,
    PF_RID_ABS_MOUSE=5
};

extern "C" bool pf_usb_tool_storage_set_present(bool present);
extern "C" bool pf_usb_tool_storage_present(void);
extern "C" uint32_t pf_usb_tool_storage_activity_age_ms(void);
extern "C" void pf_usb_tool_storage_arm_auto_detach(void);
extern "C" void pf_usb_tool_storage_cancel_auto_detach(void);
extern "C" uint8_t pf_usb_tool_storage_auto_detach_state(uint32_t idle_ms);
extern "C" uint32_t pf_usb_tool_storage_auto_detach_remaining_ms(uint32_t idle_ms);
extern "C" bool pf_usb_tool_storage_host_write_seen(void);
extern "C" bool pf_usb_tool_storage_claim_auto_detach(uint32_t idle_ms);

/* Installed by the reversible Arduino core S2 hook. TinyUSB invokes this for
 * every GET CONFIGURATION DESCRIPTOR, the exact signal used by Hak5's
 * $_HOST_CONFIGURATION_REQUEST_COUNT fingerprint. The saturating counter is
 * collected from enumeration onward, before a payload is selected. */
extern "C" void pf_usb_configuration_descriptor_requested(void)
{
    uint16_t value=s_host_configuration_request_count;
    if(value<UINT16_MAX)s_host_configuration_request_count=(uint16_t)(value+1U);
}

/* Arduino Keyboard layout encoding: bits 0..5 = HID usage, 0x80 = Shift,
 * 0xC0 = Right Alt (AltGr). Tables cover printable ASCII 0x20..0x7e.
 * US is also the PL Programmer mapping for printable ASCII. */
static constexpr uint8_t S=0x80U, AG=0xC0U;
static const uint8_t MAP_US[95]={
0x2c,0x1e|S,0x34|S,0x20|S,0x21|S,0x22|S,0x24|S,0x34,0x26|S,0x27|S,0x25|S,0x2e|S,0x36,0x2d,0x37,0x38,
0x27,0x1e,0x1f,0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x33|S,0x33,0x36|S,0x2e,0x37|S,0x38|S,0x1f|S,
0x04|S,0x05|S,0x06|S,0x07|S,0x08|S,0x09|S,0x0a|S,0x0b|S,0x0c|S,0x0d|S,0x0e|S,0x0f|S,0x10|S,0x11|S,0x12|S,0x13|S,0x14|S,0x15|S,0x16|S,0x17|S,0x18|S,0x19|S,0x1a|S,0x1b|S,0x1c|S,0x1d|S,
0x2f,0x31,0x30,0x23|S,0x2d|S,0x35,
0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,
0x2f|S,0x31|S,0x30|S,0x35|S
};
static const uint8_t MAP_DE[95]={
0x2c,0x1e|S,0x1f|S,0x31,0x21|S,0x22|S,0x23|S,0x31|S,0x25|S,0x26|S,0x30|S,0x30,0x36,0x38,0x37,0x24|S,
0x27,0x1e,0x1f,0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x37|S,0x36|S,0x32,0x27|S,0x32|S,0x2d|S,0x14|AG,
0x04|S,0x05|S,0x06|S,0x07|S,0x08|S,0x09|S,0x0a|S,0x0b|S,0x0c|S,0x0d|S,0x0e|S,0x0f|S,0x10|S,0x11|S,0x12|S,0x13|S,0x14|S,0x15|S,0x16|S,0x17|S,0x18|S,0x19|S,0x1a|S,0x1b|S,0x1d|S,0x1c|S,
0x25|AG,0x2d|AG,0x26|AG,0x00,0x38|S,0x00,
0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1d,0x1c,
0x24|AG,0x32|AG,0x27|AG,0x30|AG
};
static const uint8_t MAP_FR[95]={
0x2c,0x38,0x20,0x20|AG,0x30,0x34|S,0x1e,0x21,0x22,0x2d,0x31,0x2e|S,0x10,0x23,0x36|S,0x37|S,
0x27|S,0x1e|S,0x1f|S,0x20|S,0x21|S,0x22|S,0x23|S,0x24|S,0x25|S,0x26|S,0x37,0x36,0x32,0x2e,0x32|S,0x10|S,0x27|AG,
0x14|S,0x05|S,0x06|S,0x07|S,0x08|S,0x09|S,0x0a|S,0x0b|S,0x0c|S,0x0d|S,0x0e|S,0x0f|S,0x33|S,0x11|S,0x12|S,0x13|S,0x04|S,0x15|S,0x16|S,0x17|S,0x18|S,0x19|S,0x1d|S,0x1b|S,0x1c|S,0x1a|S,
0x22|AG,0x25|AG,0x2d|AG,0x26|AG,0x25,0x24|AG,
0x14,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x33,0x11,0x12,0x13,0x04,0x15,0x16,0x17,0x18,0x19,0x1d,0x1b,0x1c,0x1a,
0x21|AG,0x23|AG,0x2e|AG,0x1f|AG
};
static const uint8_t MAP_ES[95]={
0x2c,0x1e|S,0x1f|S,0x20|AG,0x21|S,0x22|S,0x23|S,0x2d,0x25|S,0x26|S,0x30|S,0x30,0x36,0x38,0x37,0x24|S,
0x27,0x1e,0x1f,0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x37|S,0x36|S,0x32,0x27|S,0x32|S,0x2d|S,0x1f|AG,
0x04|S,0x05|S,0x06|S,0x07|S,0x08|S,0x09|S,0x0a|S,0x0b|S,0x0c|S,0x0d|S,0x0e|S,0x0f|S,0x10|S,0x11|S,0x12|S,0x13|S,0x14|S,0x15|S,0x16|S,0x17|S,0x18|S,0x19|S,0x1a|S,0x1b|S,0x1c|S,0x1d|S,
0x2f|AG,0x35|AG,0x30|AG,0x00,0x38|S,0x00,
0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,
0x34|AG,0x1e|AG,0x31|AG,0x00
};

static const uint8_t *builtin_layout_map(uint8_t layout)
{
    switch((ws_usb_layout_t)layout) {
    case WS_USB_LAYOUT_DE:return MAP_DE;
    case WS_USB_LAYOUT_FR:return MAP_FR;
    case WS_USB_LAYOUT_ES:return MAP_ES;
    case WS_USB_LAYOUT_PL_PROGRAMMER:
    case WS_USB_LAYOUT_US:
    default:return MAP_US;
    }
}

static void load_builtin_ascii(uint8_t layout)
{
    const uint8_t *map=builtin_layout_map(layout);
    memset(s_active_ascii,0,sizeof(s_active_ascii));
    for(unsigned i=0;i<95U;++i) {
        const uint8_t e=map[i];
        if(e==0U)continue;
        uint8_t key=(uint8_t)(e&0x3fU);
        if(key==0x32U)key=0x64U; /* Arduino ISO replacement -> HID ISO usage. */
        uint8_t mod=0U;
        if((e&0xC0U)==AG)mod=DUCKY_MOD_RIGHT_ALT;
        else if(e&S)mod=DUCKY_MOD_LEFT_SHIFT;
        s_active_ascii[i].modifiers=mod;
        s_active_ascii[i].keycode=key;
        s_active_ascii[i].valid=1U;
    }
}

static bool us_report_to_ascii(uint8_t key,uint8_t modifiers,char *out)
{
    if(!out)return false;
    const bool shifted=(modifiers & DUCKY_MOD_LEFT_SHIFT)!=0 ||
                       (modifiers & DUCKY_MOD_RIGHT_SHIFT)!=0;
    for(unsigned i=0;i<95U;++i) {
        uint8_t e=MAP_US[i];
        bool es=(e&S)!=0U;
        if((e&0x3fU)==key && es==shifted) {*out=(char)(0x20U+i);return true;}
    }
    return false;
}

static bool map_printable(uint8_t key,uint8_t modifiers,uint8_t *mapped_key,uint8_t *mapped_mod,
                          bool *recognized)
{
    if(recognized)*recognized=false;
    if(!mapped_key||!mapped_mod)return false;
    char ch=0;
    if(!us_report_to_ascii(key,modifiers,&ch))return false;
    if(recognized)*recognized=true;
    const pf_hak5_key_t &entry=s_active_ascii[(uint8_t)ch-0x20U];
    if(!entry.valid || entry.keycode==0U)return false;
    /* The selected language supplies Shift/AltGr. Preserve unrelated modifiers
     * (Ctrl/GUI/left Alt) already present in a DuckyScript chord. */
    uint8_t keep=(uint8_t)(modifiers & ~(DUCKY_MOD_LEFT_SHIFT|DUCKY_MOD_RIGHT_SHIFT|DUCKY_MOD_RIGHT_ALT));
    *mapped_key=entry.keycode;
    *mapped_mod=(uint8_t)(keep|entry.modifiers);
    return true;
}

static bool wait_hid_ready(uint32_t timeout_ms)
{
    uint32_t start=millis();
    while(!tud_hid_n_ready(0)) {
        if(s_stop || (uint32_t)(millis()-start)>=timeout_ms)return false;
        vTaskDelay(pdMS_TO_TICKS(1));
    }
    return !s_stop;
}

static bool io_keyboard(void *,uint8_t modifiers,const uint8_t keycodes[6])
{
    if(s_stop || !keycodes || !(s_attackmode&1U))return false;
    uint8_t keys[6];memcpy(keys,keycodes,sizeof(keys));
    unsigned count=0,index=0;
    for(unsigned i=0;i<6U;++i)if(keys[i]){++count;index=i;}
    /* Translate a single logical printable key from s3-ducky's US map into the
     * selected host layout. Named navigation/function keys remain physical HID
     * usages and pass through unchanged. */
    if(count==1U && !(modifiers&DUCKY_MOD_RIGHT_ALT)) {
        uint8_t mk=0,mm=0;bool printable=false;
        if(map_printable(keys[index],modifiers,&mk,&mm,&printable)) {keys[index]=mk;modifiers=mm;}
        else if(printable) return false;
    }
    if(!wait_hid_ready(250U))return false;
    return tud_hid_n_keyboard_report(0,PF_RID_KEYBOARD,modifiers,keys);
}

static bool io_mouse(void *,uint8_t buttons,int8_t x,int8_t y,int8_t wheel,int8_t pan)
{
    if(s_stop || !(s_attackmode&1U) || !wait_hid_ready(250U))return false;
    return tud_hid_n_mouse_report(0,PF_RID_MOUSE,buttons,x,y,wheel,pan);
}

static bool io_absolute_mouse(void *,uint8_t buttons,int16_t x,int16_t y,int8_t wheel,int8_t pan)
{
    if(s_stop || !(s_attackmode&1U) || !wait_hid_ready(250U))return false;
    return tud_hid_n_abs_mouse_report(0,PF_RID_ABS_MOUSE,buttons,x,y,wheel,pan);
}

static bool io_consumer(void *,uint16_t usage)
{
    if(s_stop || !(s_attackmode&1U) || !wait_hid_ready(250U))return false;
    return tud_hid_n_report(0,PF_RID_CONSUMER,&usage,sizeof(usage));
}

static bool io_system(void *,uint8_t usage)
{
    if(s_stop || !(s_attackmode&1U) || usage>3U || !wait_hid_ready(250U))return false;
    return tud_hid_n_report(0,PF_RID_SYSTEM,&usage,sizeof(usage));
}

static void stage8_close_writer(void)
{
    if(s_loot_open){s_loot_file.flush();s_loot_file.close();s_loot_open=false;}
    s_loot_writer_size=0U;
}

static void loot_index_reset(void)
{
    if(s_loot_segments)
        memset(s_loot_segments,0,PF_LOOT_INDEX_MAX_SEGMENTS*sizeof(*s_loot_segments));
    s_loot_segment_count=0U;s_loot_index_loaded=false;
    s_loot_index_dirty=false;s_loot_index_fault=false;
}

static bool loot_index_kind_valid(uint8_t kind)
{
    return kind==PF_LOOT_KIND_VARIABLE_EXFIL_LE16 ||
           kind==PF_LOOT_KIND_REFLECTION_RAW ||
           kind==PF_LOOT_KIND_LEGACY_UNKNOWN;
}

static uint32_t loot_index_tracked_size(void)
{
    if(s_loot_segment_count==0U)return 0U;
    const pf_loot_segment_t &last=s_loot_segments[s_loot_segment_count-1U];
    return last.offset+last.length;
}

static bool loot_hash_file(uint8_t digest[32],uint32_t *size_out)
{
    if(!digest || !size_out || !SD.exists("/loot.bin"))return false;
    File input=SD.open("/loot.bin",FILE_READ);
    if(!input)return false;
    const uint32_t expected=(uint32_t)input.size();
    if(expected>PF_STAGE8_LOOT_LIMIT){input.close();return false;}
    mbedtls_sha256_context context;
    mbedtls_sha256_init(&context);
    bool ok=mbedtls_sha256_starts(&context,0)==0;
    uint8_t buffer[512];uint32_t total=0U;
    while(ok && total<expected) {
        const size_t wanted=(expected-total)>sizeof(buffer)?sizeof(buffer):(size_t)(expected-total);
        const int got=input.read(buffer,wanted);
        if(got<=0){ok=false;break;}
        total+=(uint32_t)got;
        ok=mbedtls_sha256_update(&context,buffer,(size_t)got)==0;
    }
    if(ok)ok=total==expected && mbedtls_sha256_finish(&context,digest)==0;
    mbedtls_sha256_free(&context);input.close();
    if(ok)*size_out=total;
    return ok;
}

static bool loot_index_records_cover(uint32_t loot_size)
{
    if(loot_size==0U)return s_loot_segment_count==0U;
    if(s_loot_segment_count==0U || s_loot_segment_count>PF_LOOT_INDEX_MAX_SEGMENTS)return false;
    uint32_t cursor=0U;
    for(uint16_t i=0U;i<s_loot_segment_count;++i) {
        const pf_loot_segment_t &segment=s_loot_segments[i];
        if(segment.offset!=cursor || cursor>loot_size || segment.length==0U ||
           !loot_index_kind_valid(segment.kind) || segment.length>loot_size-cursor)return false;
        cursor+=segment.length;
    }
    return cursor==loot_size;
}

static bool loot_index_write(void)
{
    if(!s_sd_ready || !s_loot_index_loaded || s_loot_index_fault ||
       !SD.exists("/loot.bin"))return false;
    stage8_close_writer();
    uint8_t digest[32];uint32_t loot_size=0U;
    if(!loot_hash_file(digest,&loot_size) || !loot_index_records_cover(loot_size))return false;

    uint8_t header[PF_LOOT_INDEX_HEADER_SIZE]={0};
    memcpy(header,PF_LOOT_INDEX_MAGIC,PF_LOOT_INDEX_MAGIC_SIZE);
    header[8]=PF_LOOT_INDEX_VERSION;header[9]=PF_LOOT_INDEX_HEADER_SIZE;
    header[10]=PF_LOOT_INDEX_RECORD_SIZE;
    pf_loot_put_u32(header+12,loot_size);
    pf_loot_put_u16(header+16,s_loot_segment_count);
    memcpy(header+20,digest,sizeof(digest));

    if(SD.exists("/loot.idx.tmp") && !SD.remove("/loot.idx.tmp"))return false;
    File output=SD.open("/loot.idx.tmp",FILE_WRITE);
    if(!output)return false;
    bool ok=output.write(header,sizeof(header))==sizeof(header);
    for(uint16_t i=0U;ok && i<s_loot_segment_count;++i) {
        uint8_t record[PF_LOOT_INDEX_RECORD_SIZE]={0};
        pf_loot_put_u32(record,s_loot_segments[i].offset);
        pf_loot_put_u32(record+4,s_loot_segments[i].length);
        record[8]=s_loot_segments[i].kind;
        ok=output.write(record,sizeof(record))==sizeof(record);
    }
    output.flush();output.close();
    if(!ok){(void)SD.remove("/loot.idx.tmp");return false;}

    if(SD.exists("/loot.idx.bak") && !SD.remove("/loot.idx.bak")){
        (void)SD.remove("/loot.idx.tmp");return false;
    }
    const bool had_index=SD.exists("/loot.idx");
    if(had_index && !SD.rename("/loot.idx","/loot.idx.bak")){
        (void)SD.remove("/loot.idx.tmp");return false;
    }
    if(!SD.rename("/loot.idx.tmp","/loot.idx")){
        if(had_index)(void)SD.rename("/loot.idx.bak","/loot.idx");
        (void)SD.remove("/loot.idx.tmp");return false;
    }
    (void)SD.remove("/loot.idx.bak");
    s_loot_index_dirty=false;s_loot_index_fault=false;return true;
}

static bool loot_index_load(void)
{
    stage8_close_writer();loot_index_reset();
    if(!s_sd_ready)return false;
    if(!SD.exists("/loot.bin")) {
        (void)SD.remove("/loot.idx");(void)SD.remove("/loot.idx.tmp");
        (void)SD.remove("/loot.idx.bak");s_loot_index_loaded=true;return true;
    }

    uint8_t actual_digest[32];uint32_t actual_size=0U;
    if(!loot_hash_file(actual_digest,&actual_size)){s_loot_index_loaded=true;s_loot_index_fault=true;return false;}
    if(!SD.exists("/loot.idx") && SD.exists("/loot.idx.bak") &&
       !SD.rename("/loot.idx.bak","/loot.idx")){
        s_loot_index_loaded=true;s_loot_index_fault=true;return false;
    }
    if(!SD.exists("/loot.idx") && SD.exists("/loot.idx.tmp") &&
       !SD.rename("/loot.idx.tmp","/loot.idx")){
        s_loot_index_loaded=true;s_loot_index_fault=true;return false;
    }
    if(!SD.exists("/loot.idx")) {
        if(actual_size>0U) {
            s_loot_segments[0].offset=0U;s_loot_segments[0].length=actual_size;
            s_loot_segments[0].kind=PF_LOOT_KIND_LEGACY_UNKNOWN;s_loot_segment_count=1U;
        }
        s_loot_index_loaded=true;s_loot_index_dirty=true;return true;
    }

    File input=SD.open("/loot.idx",FILE_READ);
    uint8_t header[PF_LOOT_INDEX_HEADER_SIZE];
    bool ok=(bool)input && (uint32_t)input.size()>=PF_LOOT_INDEX_HEADER_SIZE &&
            input.read(header,sizeof(header))==(int)sizeof(header);
    uint16_t count=0U;
    if(ok) {
        count=pf_loot_get_u16(header+16);
        ok=memcmp(header,PF_LOOT_INDEX_MAGIC,PF_LOOT_INDEX_MAGIC_SIZE)==0 &&
           header[8]==PF_LOOT_INDEX_VERSION && header[9]==PF_LOOT_INDEX_HEADER_SIZE &&
           header[10]==PF_LOOT_INDEX_RECORD_SIZE && header[11]==0U &&
           pf_loot_get_u32(header+12)==actual_size && count<=PF_LOOT_INDEX_MAX_SEGMENTS &&
           (uint32_t)input.size()==PF_LOOT_INDEX_HEADER_SIZE+(uint32_t)count*PF_LOOT_INDEX_RECORD_SIZE &&
           header[18]==0U && header[19]==0U && memcmp(header+20,actual_digest,32U)==0;
        for(unsigned i=52U;ok && i<sizeof(header);++i)ok=header[i]==0U;
    }
    uint32_t cursor=0U;
    for(uint16_t i=0U;ok && i<count;++i) {
        uint8_t record[PF_LOOT_INDEX_RECORD_SIZE];
        ok=input.read(record,sizeof(record))==(int)sizeof(record);
        if(!ok)break;
        const uint32_t offset=pf_loot_get_u32(record);
        const uint32_t length=pf_loot_get_u32(record+4);
        const uint8_t kind=record[8];
        ok=offset==cursor && length>0U && cursor<=actual_size &&
           length<=actual_size-cursor && loot_index_kind_valid(kind) &&
           record[9]==0U && record[10]==0U && record[11]==0U;
        if(ok) {
            s_loot_segments[i].offset=offset;s_loot_segments[i].length=length;
            s_loot_segments[i].kind=kind;cursor+=length;
        }
    }
    if(input)input.close();
    ok=ok && cursor==actual_size && ((actual_size==0U && count==0U) ||
                                     (actual_size>0U && count>0U));
    s_loot_index_loaded=true;
    if(!ok){s_loot_segment_count=0U;s_loot_index_fault=true;return false;}
    s_loot_segment_count=count;(void)SD.remove("/loot.idx.tmp");
    (void)SD.remove("/loot.idx.bak");return true;
}

static bool loot_index_commit(void)
{
    if(!s_loot_index_loaded || s_loot_index_fault)return false;
    if(!s_loot_index_dirty)return true;
    if(!loot_index_write()){s_loot_index_fault=true;return false;}
    return true;
}

static bool loot_index_remount(void)
{
    stage8_close_writer();SD.end();s_sd_ready=false;
    s_sd_ready=SD.begin(WS_SD_CS,s_sd_spi,FIDO_V1_USB_TOOL_SD_HZ,"/usb-tool",4,false);
    if(!s_sd_ready){s_loot_index_fault=true;return false;}
    if(!loot_index_load())return false;
    if(s_loot_index_dirty && !loot_index_commit())return false;
    s_storage_view_stale=false;return true;
}

static bool loot_index_can_record(uint8_t kind,uint32_t offset)
{
    if(!s_loot_index_loaded || s_loot_index_fault || !loot_index_kind_valid(kind))return false;
    if(offset!=loot_index_tracked_size())return false;
    if(s_loot_segment_count==0U)return true;
    const pf_loot_segment_t &last=s_loot_segments[s_loot_segment_count-1U];
    return (last.kind==kind && last.offset+last.length==offset) ||
           s_loot_segment_count<PF_LOOT_INDEX_MAX_SEGMENTS;
}

static bool loot_index_record(uint8_t kind,uint32_t offset,uint32_t length)
{
    if(length==0U)return true;
    if(!loot_index_can_record(kind,offset))return false;
    if(s_loot_segment_count>0U) {
        pf_loot_segment_t &last=s_loot_segments[s_loot_segment_count-1U];
        if(last.kind==kind && last.offset+last.length==offset) {
            last.length+=length;s_loot_index_dirty=true;return true;
        }
    }
    pf_loot_segment_t &segment=s_loot_segments[s_loot_segment_count++];
    segment.offset=offset;segment.length=length;segment.kind=kind;
    s_loot_index_dirty=true;return true;
}

static bool stage8_open_writer(void)
{
    if(s_loot_open)return true;
    if(!s_sd_ready || (s_attackmode&2U)!=0U || !s_loot_index_loaded || s_loot_index_fault)return false;
    s_loot_file=SD.open("/loot.bin",FILE_APPEND);
    if(!s_loot_file)return false;
    const uint32_t size=(uint32_t)s_loot_file.size();
    if(size>PF_STAGE8_LOOT_LIMIT || size!=loot_index_tracked_size()){
        s_loot_file.close();s_loot_index_fault=true;return false;
    }
    s_loot_writer_size=size;s_loot_open=true;return true;
}

static bool stage8_write(const uint8_t *data,size_t length,uint8_t kind)
{
    if(!data || length==0U)return true;
    if(length>PF_STAGE8_SESSION_LIMIT-s_stage8_session_bytes || !stage8_open_writer())return false;
    const uint32_t current=s_loot_writer_size;
    if(current>PF_STAGE8_LOOT_LIMIT || length>PF_STAGE8_LOOT_LIMIT-current ||
       !loot_index_can_record(kind,current))return false;
    if(s_loot_file.write(data,length)!=length){s_loot_index_fault=true;return false;}
    if(!loot_index_record(kind,current,(uint32_t)length)){s_loot_index_fault=true;return false;}
    s_loot_writer_size+=(uint32_t)length;
    s_stage8_session_bytes+=(uint32_t)length;return true;
}

static bool reflection_drain(void)
{
    uint8_t local[64];
    for(;;){
        size_t count=0U;
        portENTER_CRITICAL(&s_guard);
        while(count<sizeof(local) && s_reflection_count){
            local[count++]=s_reflection_ring[s_reflection_tail];
            s_reflection_tail=(uint16_t)((s_reflection_tail+1U)%sizeof(s_reflection_ring));
            --s_reflection_count;
        }
        portEXIT_CRITICAL(&s_guard);
        if(count==0U)break;
        if(!stage8_write(local,count,PF_LOOT_KIND_REFLECTION_RAW)){s_stage8_fault=2U;s_stop=true;return false;}
    }
    if(s_stage8_fault){s_stop=true;return false;}
    if(s_exfil_mode && (uint32_t)(millis()-s_reflection_started_ms)>PF_STAGE8_REFLECTION_MAX_MS){
        s_stage8_fault=3U;s_stop=true;return false;
    }
    return true;
}

static void stage8_cleanup(void)
{
    (void)reflection_drain();
    s_exfil_mode=false;s_reflection_receiving=false;
    stage8_close_writer();
    if(s_loot_index_dirty && !loot_index_commit())s_stage8_fault=5U;
    s_stage8_authorized_caps=0U;
}

static bool io_variable_exfil(void *,uint16_t value)
{
    if((s_stage8_authorized_caps&DUCKY_CAP_VARIABLE_EXFIL)==0U || (s_attackmode&2U)!=0U)return false;
    const uint8_t bytes[2]={(uint8_t)(value&0xffU),(uint8_t)(value>>8)};
    if(!stage8_write(bytes,sizeof(bytes),PF_LOOT_KIND_VARIABLE_EXFIL_LE16)){s_stage8_fault=2U;return false;}
    return true;
}

static bool io_set_exfil_mode(void *,bool enabled)
{
    if(!enabled){
        s_reflection_receiving=false;
        bool ok=reflection_drain() && s_reflection_bit_count==0U;
        if(!ok && !s_stage8_fault)s_stage8_fault=4U;
        s_exfil_mode=false;stage8_close_writer();
        if(ok && s_loot_index_dirty && !loot_index_commit()){s_stage8_fault=5U;ok=false;}
        return ok;
    }
    if((s_stage8_authorized_caps&DUCKY_CAP_KEYSTROKE_REFLECTION)==0U ||
       (s_attackmode&2U)!=0U || !s_sd_ready)return false;
    portENTER_CRITICAL(&s_guard);
    s_reflection_head=s_reflection_tail=s_reflection_count=0U;
    s_reflection_accumulator=0U;s_reflection_bit_count=0U;
    s_reflection_last_leds=s_leds;
    portEXIT_CRITICAL(&s_guard);
    s_reflection_started_ms=millis();s_exfil_mode=true;s_reflection_receiving=true;return true;
}

static bool io_exfil_mode_enabled(void *){return s_exfil_mode;}

static void io_delay(void *,uint32_t ms)
{
    while(ms && !s_stop) {uint32_t chunk=ms>20U?20U:ms;vTaskDelay(pdMS_TO_TICKS(chunk));ms-=chunk;if(!reflection_drain())break;}
}

static bool io_button_pressed(void *,uint16_t debounce_ms)
{
    if(s_stop)return false;
    const bool down=digitalRead(0)==LOW;
    if(!down){s_button_was_down=false;return false;}
    if(s_button_was_down)return false;
    s_button_was_down=true;
    const uint32_t now=millis();
    if(s_button_event_seen && (uint32_t)(now-s_button_last_event_ms)<debounce_ms)return false;
    s_button_event_seen=true;s_button_last_event_ms=now;
    return true;
}

static bool io_wait_button(void *,uint32_t timeout_ms)
{
    uint32_t start=millis();
    do {
        if(s_stop)return false;
        if(digitalRead(0)==LOW) {while(digitalRead(0)==LOW && !s_stop)vTaskDelay(pdMS_TO_TICKS(10));return !s_stop;}
        vTaskDelay(pdMS_TO_TICKS(10));
    } while(timeout_ms==0U || (uint32_t)(millis()-start)<timeout_ms);
    return false;
}

static uint8_t io_leds(void *) {return s_leds;}
static void io_status_led(void *,uint8_t state)
{
    if(state>PF_USB_TOOL_LED_GREEN)state=PF_USB_TOOL_LED_OFF;
    s_ducky_led=state;
    s_ducky_led_command_seen=true;
}
static void io_runtime_options(void *,uint8_t led_options,uint16_t storage_timeout_ms)
{
    s_ducky_led_options=led_options;
    s_storage_activity_timeout_ms=storage_timeout_ms;
}
static uint32_t io_storage_activity_age_ms(void *)
{
    return pf_usb_tool_storage_activity_age_ms();
}
static uint32_t io_random(void *) {return esp_random();}
static bool io_attackmode(void *,uint8_t mode)
{
    if(mode>3U)return false;
    const bool storage=(mode&2U)!=0U;
    const bool leaving_storage=(s_attackmode&2U)!=0U && !storage;
    if(storage && !s_sd_ready)return false;
    if(storage){
        s_reflection_receiving=false;if(!reflection_drain())return false;
        s_exfil_mode=false;stage8_close_writer();
        if(s_loot_index_dirty && !loot_index_commit()){s_stage8_fault=5U;return false;}
    }
    if(!pf_usb_tool_apply_attackmode_profile(mode,false,0U,0U,nullptr,nullptr,nullptr))return false;
    s_attackmode=mode;
    s_attackmode_identity_custom=false;
    if(storage){s_storage_was_exposed=true;s_storage_view_stale=true;}
    else if(leaving_storage) {
        pf_usb_tool_storage_cancel_auto_detach();
        if(!loot_index_remount()){s_stage8_fault=5U;return false;}
    }
    return true;
}
static bool io_attackmode_profile(void *,const ducky_attackmode_t *profile)
{
    if(!profile || profile->mode>3U)return false;
    const bool storage=(profile->mode&2U)!=0U;
    const bool leaving_storage=(s_attackmode&2U)!=0U && !storage;
    if(storage && !s_sd_ready)return false;
    if(storage){
        s_reflection_receiving=false;if(!reflection_drain())return false;
        s_exfil_mode=false;stage8_close_writer();
        if(s_loot_index_dirty && !loot_index_commit()){s_stage8_fault=5U;return false;}
    }
    if(!pf_usb_tool_apply_attackmode_profile(profile->mode,profile->custom_identity,
        profile->vid,profile->pid,profile->manufacturer,profile->product,
        profile->serial))return false;
    s_attackmode=profile->mode;
    s_attackmode_identity_custom=profile->custom_identity;
    if(storage){s_storage_was_exposed=true;s_storage_view_stale=true;}
    else if(leaving_storage) {
        pf_usb_tool_storage_cancel_auto_detach();
        if(!loot_index_remount()){s_stage8_fault=5U;return false;}
    }
    return true;
}
static uint8_t io_current_attackmode(void *) {return s_attackmode;}
static uint16_t io_current_vid(void *) {return pf_usb_tool_current_vid();}
static uint16_t io_current_pid(void *) {return pf_usb_tool_current_pid();}
static bool io_host_lock_reply(void *) {return s_received_led_report;}
static uint16_t io_host_config_count(void *)
{
    return s_host_configuration_request_count;
}
static bool io_reset_host_config_count(void *)
{
    s_host_configuration_request_count=0U;
    return true;
}
static uint16_t io_host_os_guess(void *)
{
    /* Same default decision tree as Hak5 OS_DETECTION 1.1, evaluated from the
     * passive enumeration snapshot: Windows asks for the configuration
     * descriptor more than twice; another host with lock-LED feedback is
     * classified Linux; lack of that feedback is classified macOS. */
    if(s_host_configuration_request_count>2U)return 1U; /* WINDOWS */
    return s_received_led_report?2U:3U;                 /* LINUX : MACOS */
}

static void set_status(pf_usb_tool_status_t st,const char *detail,uint32_t line=0)
{
    portENTER_CRITICAL(&s_guard);
    s_status=st;s_error_line=line;
    if(detail) {strncpy(s_status_detail,detail,sizeof(s_status_detail)-1U);s_status_detail[sizeof(s_status_detail)-1U]='\0';}
    else s_status_detail[0]='\0';
    portEXIT_CRITICAL(&s_guard);
}

/* Arduino's filesystem view must never be used while the host owns the same
 * card through MSC.  After Windows ejects the medium, return to HID-only and
 * remount the card before any local file access. */
static bool prepare_local_sd_access(const char *action)
{
    if(pf_usb_tool_storage_present()) {
        char detail[96];
        snprintf(detail,sizeof(detail),"Eject DUCKY before %s",action?action:"local access");
        set_status(PF_USB_TOOL_IDLE,detail);
        return false;
    }
    if((s_attackmode&2U)!=0U || s_attackmode_identity_custom) {
        if(!io_attackmode(nullptr,1U)) {
            set_status(PF_USB_TOOL_ERROR,"Cannot restore HID/local SD access");
            return false;
        }
    }
    s_storage_was_exposed=false;
    s_storage_view_stale=false;
    return true;
}

static bool ends_with_ci(const char *text,const char *suffix)
{
    if(!text||!suffix)return false;size_t a=strlen(text),b=strlen(suffix);
    return a>=b && strcasecmp(text+a-b,suffix)==0;
}

static const char *base_name(const char *path)
{
    if(!path)return "";const char *p=strrchr(path,'/');return p?p+1:path;
}

static bool is_language_dir(const char *path)
{
    const char *b=base_name(path);
    return !strcasecmp(b,"languages") || !strcasecmp(b,".git");
}

static bool is_script_path(const char *path)
{
    const char *base=base_name(path);
    if(!base||!*base)return false;
    if(!strcasecmp(base,"payload.txt"))return true;
    if(!strncasecmp(base,"readme",6U))return false;
    if(ends_with_ci(base,".duck") || ends_with_ci(base,".ds"))return true;
    if(ends_with_ci(base,".txt")) {
        /* In a Hak5 payload tree only payload.txt is executable source.  Keep
         * arbitrary .txt support for native /duckyscripts files, but do not
         * index extension/readme/example text from /payloads. */
        return strstr(path,"/payloads/")==nullptr;
    }
    return false;
}

static void clear_script_index(void)
{
    for(uint16_t i=0;i<s_script_count;++i) {
        free(s_scripts[i]);
        s_scripts[i]=nullptr;
    }
    s_script_count=0U;
    s_selected=0U;
    s_script_index_truncated=false;
}

static void *alloc_tool_memory(size_t bytes)
{
    if(bytes==0U)return nullptr;
    /* ESP32-S3-Touch-AMOLED-1.64 has PSRAM.  If the Arduino board menu has
     * PSRAM enabled, keep variable USB Tool data (path index, JSON language
     * file, payload source) out of internal SRAM.  ps_malloc() safely returns
     * NULL when PSRAM is disabled, so the existing board profile falls back
     * to normal heap allocation. */
    void *p=nullptr;
    if(psramFound())p=ps_malloc(bytes);
    if(!p)p=malloc(bytes);
    return p;
}

static bool ensure_psram_tables(void)
{
    if(s_scripts && s_languages && s_loot_segments)return true;

    const uint32_t caps=MALLOC_CAP_SPIRAM|MALLOC_CAP_8BIT;
    char **scripts=(char **)heap_caps_calloc(MAX_SCRIPTS,sizeof(*scripts),caps);
    pf_language_entry_t *languages=(pf_language_entry_t *)heap_caps_calloc(
        MAX_LANGUAGES,sizeof(*languages),caps);
    pf_loot_segment_t *segments=(pf_loot_segment_t *)heap_caps_calloc(
        PF_LOOT_INDEX_MAX_SEGMENTS,sizeof(*segments),caps);
    if(!scripts || !languages || !segments) {
        free(scripts);free(languages);free(segments);
        return false;
    }
    s_scripts=scripts;s_languages=languages;s_loot_segments=segments;
    return true;
}

static char *alloc_script_path(const char *path)
{
    if(!path)return nullptr;
    const size_t n=strlen(path);
    if(n==0U || n>=MAX_PATH)return nullptr;
    char *copy=(char *)alloc_tool_memory(n+1U);
    if(!copy)return nullptr;
    memcpy(copy,path,n+1U);
    return copy;
}

static bool script_exists(const char *path)
{
    for(uint16_t i=0;i<s_script_count;++i)
        if(s_scripts[i] && !strcasecmp(s_scripts[i],path))return true;
    return false;
}

static void add_script_path(const char *path)
{
    if(!path||!*path||strlen(path)>=MAX_PATH||script_exists(path))return;
    if(s_script_count>=MAX_SCRIPTS){s_script_index_truncated=true;return;}
    char *copy=alloc_script_path(path);
    if(!copy){s_script_index_truncated=true;return;}
    uint16_t pos=s_script_count;
    while(pos>0U && s_scripts[pos-1U] && strcasecmp(s_scripts[pos-1U],path)>0) {
        s_scripts[pos]=s_scripts[pos-1U];--pos;
    }
    s_scripts[pos]=copy;++s_script_count;
}

static void scan_script_dir(const char *path,unsigned depth)
{
    if(!path||depth>10U||s_script_count>=MAX_SCRIPTS)return;
    File dir=SD.open(path);if(!dir||!dir.isDirectory()){if(dir)dir.close();return;}
    File f;
    while((f=dir.openNextFile()) && s_script_count<MAX_SCRIPTS) {
        const char *full=f.path();
        if(f.isDirectory()) {
            if(full && !is_language_dir(full))scan_script_dir(full,depth+1U);
        } else if(full && is_script_path(full) && f.size()>0U && f.size()<=FIDO_V1_USB_TOOL_MAX_PAYLOAD) {
            add_script_path(full);
        }
        f.close();
    }
    dir.close();
}

static void scan_scripts(void)
{
    /* Scanning runs before the USB Tool is exposed to the UI, so free the old
     * variable-length index outside the critical section.  This avoids a
     * permanent 320 x 192-byte SRAM reservation from R27. */
    clear_script_index();
    if(!s_sd_ready)return;
    if(!SD.exists("/duckyscripts"))SD.mkdir("/duckyscripts");
    scan_script_dir("/duckyscripts",0U);
    /* Also accept a Hak5 repository copied directly to the card root. */
    if(SD.exists("/payloads"))scan_script_dir("/payloads",0U);
    if(SD.exists("/hak5/payloads"))scan_script_dir("/hak5/payloads",0U);
}

static int builtin_for_code(const char *code)
{
    if(!code)return -1;
    if(!strcasecmp(code,"us"))return WS_USB_LAYOUT_US;
    if(!strcasecmp(code,"pl")||!strcasecmp(code,"pl-programmer"))return WS_USB_LAYOUT_PL_PROGRAMMER;
    if(!strcasecmp(code,"de"))return WS_USB_LAYOUT_DE;
    if(!strcasecmp(code,"fr"))return WS_USB_LAYOUT_FR;
    if(!strcasecmp(code,"es"))return WS_USB_LAYOUT_ES;
    return -1;
}

static int find_language(const char *code)
{
    if(!code)return -1;
    for(uint16_t i=0;i<s_language_count;++i)if(!strcasecmp(s_languages[i].code,code))return (int)i;
    return -1;
}

static void add_language(const char *code,const char *path,int builtin,bool external)
{
    if(!code||!*code||strlen(code)>=MAX_LANGUAGE_CODE)return;
    int found=find_language(code);
    pf_language_entry_t *e=nullptr;
    if(found>=0)e=&s_languages[found];
    else {
        if(s_language_count>=MAX_LANGUAGES)return;
        e=&s_languages[s_language_count++];memset(e,0,sizeof(*e));
        strncpy(e->code,code,sizeof(e->code)-1U);e->builtin_layout=builtin>=0?(uint8_t)builtin:0xffU;
    }
    if(builtin>=0)e->builtin_layout=(uint8_t)builtin;
    if(external && path && strlen(path)<sizeof(e->path)) {
        strncpy(e->path,path,sizeof(e->path)-1U);e->path[sizeof(e->path)-1U]='\0';e->external=true;
    }
}

static void scan_language_dir(const char *path)
{
    File dir=SD.open(path);if(!dir||!dir.isDirectory()){if(dir)dir.close();return;}
    File f;
    while((f=dir.openNextFile()) && s_language_count<MAX_LANGUAGES) {
        if(!f.isDirectory() && f.path() && ends_with_ci(f.path(),".json") && f.size()>0U && f.size()<=16384U) {
            char code[MAX_LANGUAGE_CODE]={0};const char *b=base_name(f.path());size_t n=strlen(b);
            if(n>5U && n-5U<sizeof(code)) {memcpy(code,b,n-5U);code[n-5U]='\0';add_language(code,f.path(),builtin_for_code(code),true);}
        }
        f.close();
    }
    dir.close();
}

static int language_cmp(const void *a,const void *b)
{
    const pf_language_entry_t *la=(const pf_language_entry_t *)a,*lb=(const pf_language_entry_t *)b;
    return strcasecmp(la->code,lb->code);
}

static bool load_external_language(const char *path)
{
    File f=SD.open(path,FILE_READ);if(!f)return false;size_t len=(size_t)f.size();
    if(len==0U||len>16384U){f.close();return false;}
    char *json=(char *)alloc_tool_memory(len+1U);if(!json){f.close();return false;}
    size_t got=f.readBytes(json,len);f.close();json[got]='\0';
    pf_hak5_key_t candidate[95];size_t mapped=0U;char error[80]={0};
    bool ok=got==len && pf_hak5_parse_language_json(json,len,candidate,&mapped,error,sizeof(error));free(json);
    if(!ok)return false;memcpy(s_active_ascii,candidate,sizeof(candidate));return true;
}

static bool load_language_index(uint16_t index)
{
    if(index>=s_language_count)return false;pf_language_entry_t &e=s_languages[index];
    if(e.external && load_external_language(e.path))return true;
    if(e.builtin_layout!=0xffU){load_builtin_ascii(e.builtin_layout);return true;}
    return false;
}

static void scan_languages(void)
{
    s_language_count=0U;s_language_selected=0U;
    add_language("us",nullptr,WS_USB_LAYOUT_US,false);
    add_language("pl-programmer",nullptr,WS_USB_LAYOUT_PL_PROGRAMMER,false);
    add_language("de",nullptr,WS_USB_LAYOUT_DE,false);
    add_language("fr",nullptr,WS_USB_LAYOUT_FR,false);
    add_language("es",nullptr,WS_USB_LAYOUT_ES,false);
    scan_language_dir("/languages");
    scan_language_dir("/hak5/languages");
    scan_language_dir("/duckyscripts/languages");
    scan_language_dir("/duckyscripts/hak5/languages");
    qsort(s_languages,s_language_count,sizeof(s_languages[0]),language_cmp);
    char preferred[WS_USB_LANGUAGE_CODE_MAX]={0};ws_usb_tool_language_code(preferred,sizeof(preferred));
    int idx=find_language(preferred);if(idx<0)idx=find_language("us");if(idx<0)idx=0;
    if(!load_language_index((uint16_t)idx)) {idx=find_language("us");if(idx<0)idx=0;load_builtin_ascii(WS_USB_LAYOUT_US);}
    s_language_selected=(uint16_t)idx;
}

static void friendly_script_name(const char *path,char *out,size_t out_len)
{
    if(!out||out_len==0U)return;out[0]='\0';if(!path)return;
    const char *base=base_name(path);
    if(!strcasecmp(base,"payload.txt")) {
        char tmp[MAX_PATH];strncpy(tmp,path,sizeof(tmp)-1U);tmp[sizeof(tmp)-1U]='\0';
        char *last=strrchr(tmp,'/');if(last)*last='\0';
        char *parent=strrchr(tmp,'/');const char *name=parent?parent+1:tmp;
        if(parent){*parent='\0';char *category=strrchr(tmp,'/');category=category?category+1:tmp;
            if(*category && strcasecmp(category,"library"))snprintf(out,out_len,"%s/%s",category,name);
            else snprintf(out,out_len,"%s",name);
        } else snprintf(out,out_len,"%s",name);
    } else snprintf(out,out_len,"%s",base);
}

extern "C" int (*hid_set_report_cb)(uint8_t,uint8_t,hid_report_type_t,uint8_t const *,uint16_t);
static int tool_set_report(uint8_t itf,uint8_t report_id,hid_report_type_t report_type,
                           uint8_t const *buffer,uint16_t bufsize)
{
    if(itf!=0)return 0;
    uint8_t current=0U;
    if(pf_usb_tool_decode_keyboard_led_report(
           PF_RID_KEYBOARD,report_id,(uint8_t)report_type,
           (uint8_t)HID_REPORT_TYPE_OUTPUT,buffer,bufsize,&current)) {
        portENTER_CRITICAL(&s_guard);
        s_leds=current;s_received_led_report=true;
        if(s_exfil_mode && s_reflection_receiving){
            const uint8_t changed=(uint8_t)(current^s_reflection_last_leds);
            s_reflection_last_leds=current;
            if(changed&DUCKY_LED_SCROLL_LOCK){s_reflection_receiving=false;}
            else {
                const bool caps=(changed&DUCKY_LED_CAPS_LOCK)!=0U;
                const bool num=(changed&DUCKY_LED_NUM_LOCK)!=0U;
                if(caps!=num){
                    s_reflection_accumulator=(uint8_t)((s_reflection_accumulator<<1)|(num?1U:0U));
                    if(++s_reflection_bit_count==8U){
                        if(s_reflection_count<sizeof(s_reflection_ring)){
                            s_reflection_ring[s_reflection_head]=s_reflection_accumulator;
                            s_reflection_head=(uint16_t)((s_reflection_head+1U)%sizeof(s_reflection_ring));++s_reflection_count;
                        } else s_stage8_fault=1U;
                        s_reflection_accumulator=0U;s_reflection_bit_count=0U;
                    }
                } else if(caps&&num)s_stage8_fault=4U;
            }
        }
        portEXIT_CRITICAL(&s_guard);
        return 1;
    }
    return 0;
}

static void clear_pending_stage8(void)
{
    memset(s_pending_digest,0,sizeof(s_pending_digest));s_pending_caps=0U;
    s_pending_deadline_ms=0U;s_pending_index=UINT16_MAX;s_confirmed_run=false;
}

static bool payload_digest(const char *script,size_t length,uint8_t out[32])
{
    return mbedtls_sha256((const unsigned char *)script,length,out,0)==0;
}

static void script_task_complete(void)
{
    s_stop=false;
    s_script_running=false;
}

static void run_task(void *)
{
    char path[MAX_PATH]={0},name[MAX_NAME]={0};
    uint16_t selected=0U;
    portENTER_CRITICAL(&s_guard);
    selected=s_selected;
    if(s_script_count && s_selected<s_script_count && s_scripts[s_selected])strncpy(path,s_scripts[s_selected],sizeof(path)-1U);
    portEXIT_CRITICAL(&s_guard);
    friendly_script_name(path,name,sizeof(name));
    File f=SD.open(path,FILE_READ);
    if(!f) {set_status(PF_USB_TOOL_ERROR,"Cannot open payload");script_task_complete();return;}
    size_t len=(size_t)f.size();
    if(len==0U || len>FIDO_V1_USB_TOOL_MAX_PAYLOAD) {f.close();set_status(PF_USB_TOOL_ERROR,"Payload size rejected");script_task_complete();return;}
    char *script=(char *)alloc_tool_memory(len+1U);
    if(!script) {f.close();set_status(PF_USB_TOOL_ERROR,"Not enough memory");script_task_complete();return;}
    size_t got=f.readBytes(script,len);f.close();script[got]='\0';
    if(got!=len) {free(script);set_status(PF_USB_TOOL_ERROR,"microSD read error");script_task_complete();return;}

    const uint32_t caps=ducky_inspect_capabilities(script,len);
    uint8_t digest[32];
    if(!payload_digest(script,len,digest)){free(script);set_status(PF_USB_TOOL_ERROR,"Payload hash failed");script_task_complete();return;}
    if(caps&DUCKY_CAP_PAYLOAD_HIDING){free(script);clear_pending_stage8();set_status(PF_USB_TOOL_ERROR,"HIDE/RESTORE payload blocked (8C)");script_task_complete();return;}
#if !FIDO_V1_USB_TOOL_VARIABLE_EXFIL
    if(caps&DUCKY_CAP_VARIABLE_EXFIL){free(script);clear_pending_stage8();set_status(PF_USB_TOOL_ERROR,"Variable EXFIL disabled in build");script_task_complete();return;}
#endif
#if !FIDO_V1_USB_TOOL_KEYSTROKE_REFLECTION
    if(caps&DUCKY_CAP_KEYSTROKE_REFLECTION){free(script);clear_pending_stage8();set_status(PF_USB_TOOL_ERROR,"Reflection disabled in build");script_task_complete();return;}
#endif
    const bool confirmed=s_confirmed_run;s_confirmed_run=false;
    if(confirmed){
        const bool expired=(int32_t)(millis()-s_pending_deadline_ms)>0;
        if(expired || selected!=s_pending_index || caps!=s_pending_caps || memcmp(digest,s_pending_digest,sizeof(digest))!=0){
            free(script);clear_pending_stage8();set_status(PF_USB_TOOL_ERROR,"Payload changed or approval expired");script_task_complete();return;
        }
        clear_pending_stage8();
    } else if(caps){
        memcpy(s_pending_digest,digest,sizeof(digest));s_pending_caps=caps;s_pending_index=selected;
        s_pending_deadline_ms=millis()+PF_STAGE8_CONFIRM_WINDOW_MS;
        char detail[96];const char *kind=(caps&(DUCKY_CAP_VARIABLE_EXFIL|DUCKY_CAP_KEYSTROKE_REFLECTION))==(DUCKY_CAP_VARIABLE_EXFIL|DUCKY_CAP_KEYSTROKE_REFLECTION)?"EXFIL+REFLECT":(caps&DUCKY_CAP_KEYSTROKE_REFLECTION)?"REFLECT":"EXFIL";
        snprintf(detail,sizeof(detail),"Hold RUN 1.5s %s SHA %02X%02X%02X%02X",kind,digest[0],digest[1],digest[2],digest[3]);
        free(script);set_status(PF_USB_TOOL_CONFIRM_STAGE8,detail);script_task_complete();return;
    }

    set_status(PF_USB_TOOL_RUNNING,name);
    s_ducky_led=PF_USB_TOOL_LED_OFF;s_ducky_led_command_seen=false;
    s_storage_auto_detach_pending=false;
    s_storage_auto_detach_last_second=UINT32_MAX;
    pf_usb_tool_storage_cancel_auto_detach();
    s_stop=false;s_attackmode=1U;s_attackmode_identity_custom=false;s_storage_was_exposed=false;
    s_storage_view_stale=false;
    s_stage8_authorized_caps=caps;s_stage8_session_bytes=0U;s_stage8_fault=0U;
    s_exfil_mode=false;s_reflection_receiving=false;s_loot_open=false;
    s_button_was_down=digitalRead(0)==LOW;s_button_event_seen=false;s_button_last_event_ms=0U;
    pf_usb_tool_storage_set_present(false);
    ducky_io_t io{};
    io.context=nullptr;
    io.keyboard=io_keyboard;
    io.mouse=io_mouse;
    io.absolute_mouse=io_absolute_mouse;
    io.consumer=io_consumer;
    io.system=io_system;
    io.delay_ms=io_delay;
    io.wait_for_button=io_wait_button;
    io.button_pressed=io_button_pressed;
    io.keyboard_leds=io_leds;
    io.status_led=io_status_led;
    io.random_u32=io_random;
    io.runtime_options=io_runtime_options;
    io.storage_activity_age_ms=io_storage_activity_age_ms;
    io.attackmode=io_attackmode;
    io.attackmode_profile=io_attackmode_profile;
    io.current_attackmode=io_current_attackmode;
    io.current_vid=io_current_vid;
    io.current_pid=io_current_pid;
    io.host_lock_reply_received=io_host_lock_reply;
    io.host_configuration_request_count=io_host_config_count;
    io.reset_host_configuration_request_count=io_reset_host_config_count;
    io.host_os_guess=io_host_os_guess;
#if FIDO_V1_USB_TOOL_VARIABLE_EXFIL
    io.variable_exfil=io_variable_exfil;
#endif
#if FIDO_V1_USB_TOOL_KEYSTROKE_REFLECTION
    io.set_exfil_mode=io_set_exfil_mode;
    io.exfil_mode_enabled=io_exfil_mode_enabled;
#endif

    // Avoid s3-ducky's C99 designated-initializer macro in this C++ TU so
    // the Arduino target remains compatible with older GNU++ modes.
    ducky_config_t cfg{};
    cfg.key_press_ms=8U;
    cfg.button_timeout_ms=0U;
    /* WAIT_FOR_SCROLL_CHANGE is the framing wait used by Keystroke Reflection.
       It must not expire before the receiver's own 120 s session limit, or the
       host can continue toggling lock keys after the payload has already been
       aborted and its writer closed. */
    cfg.lock_wait_timeout_ms=PF_STAGE8_REFLECTION_MAX_MS+5000U;
    cfg.max_execution_steps=100000U;
    cfg.max_lines=8192U;
    ducky_result_t r=ducky_run(script,len,&io,&cfg);
    stage8_cleanup();
    const bool storage_retained=(s_attackmode&2U)!=0U &&
                                pf_usb_tool_storage_present();
    if(storage_retained) {
        /* A fresh ten-second quiet window begins only after the payload and
         * all local loot/index writers have completed. Any later READ10 or
         * WRITE10 restarts it. WRITE10 additionally requires a successful
         * SYNCHRONIZE CACHE after the last write, or a host eject. */
        pf_usb_tool_storage_arm_auto_detach();
        s_storage_auto_detach_pending=true;
        s_storage_auto_detach_last_second=UINT32_MAX;
    } else {
        pf_usb_tool_storage_cancel_auto_detach();
        s_storage_auto_detach_pending=false;
        if(s_attackmode!=1U || s_attackmode_identity_custom)
            (void)io_attackmode(nullptr,1U);
        else
            pf_usb_tool_storage_set_present(false);
        if(s_storage_was_exposed) {
            /* The host may have changed FAT metadata. With STORAGE detached,
             * drop Arduino SD's stale filesystem view before indexing it. */
            if(s_storage_view_stale && !loot_index_remount())s_stage8_fault=5U;
            if(s_sd_ready){scan_languages();scan_scripts();}
        }
        s_attackmode=1U;s_attackmode_identity_custom=false;
        s_storage_was_exposed=false;s_storage_view_stale=false;
    }
    s_ducky_led=PF_USB_TOOL_LED_OFF;s_ducky_led_command_seen=false;
    free(script);
    uint8_t empty[6]={0};
    if(tud_hid_n_ready(0))tud_hid_n_keyboard_report(0,PF_RID_KEYBOARD,0,empty);
    if(s_stage8_fault==1U) set_status(PF_USB_TOOL_ERROR,"Reflection buffer overflow",(uint32_t)r.line);
    else if(s_stage8_fault==2U) set_status(PF_USB_TOOL_ERROR,"loot.bin write/size limit failed",(uint32_t)r.line);
    else if(s_stage8_fault==3U) set_status(PF_USB_TOOL_ERROR,"Reflection time limit exceeded",(uint32_t)r.line);
    else if(s_stage8_fault==4U) set_status(PF_USB_TOOL_ERROR,"Invalid Reflection LED stream",(uint32_t)r.line);
    else if(s_stage8_fault==5U) set_status(PF_USB_TOOL_ERROR,"loot.idx validation/update failed",(uint32_t)r.line);
    else if(s_stop) set_status(PF_USB_TOOL_CANCELLED,"Stopped by user",(uint32_t)r.line);
    else if(r.status==DUCKY_OK) {
        if(!storage_retained)set_status(PF_USB_TOOL_OK,"Completed",0);
        else if(pf_usb_tool_storage_host_write_seen())
            set_status(PF_USB_TOOL_OK,"Completed - waiting for flush/eject",0);
        else
            set_status(PF_USB_TOOL_OK,"Completed - auto detach in 10s",0);
    }
    else set_status(PF_USB_TOOL_ERROR,r.message,(uint32_t)r.line);
    script_task_complete();
}

static void handle_storage_auto_detach(void)
{
    if(s_script_running || !s_storage_auto_detach_pending)return;
    if(!pf_usb_tool_storage_present()) {
        s_storage_auto_detach_pending=false;
        pf_usb_tool_storage_cancel_auto_detach();
        return;
    }
    const uint8_t state=pf_usb_tool_storage_auto_detach_state(
        PF_STORAGE_AUTO_DETACH_IDLE_MS);
    if(state==PF_USB_TOOL_AUTO_DETACH_WAIT_SYNC) {
        if(s_storage_auto_detach_last_second!=UINT32_MAX) {
            s_storage_auto_detach_last_second=UINT32_MAX;
            set_status(PF_USB_TOOL_OK,"Completed - waiting for flush/eject");
        }
        return;
    }
    if(state==PF_USB_TOOL_AUTO_DETACH_WAIT_IDLE) {
        const uint32_t remaining=pf_usb_tool_storage_auto_detach_remaining_ms(
            PF_STORAGE_AUTO_DETACH_IDLE_MS);
        const uint32_t seconds=(remaining+999U)/1000U;
        if(seconds!=s_storage_auto_detach_last_second) {
            s_storage_auto_detach_last_second=seconds;
            char detail[96];
            snprintf(detail,sizeof(detail),
                pf_usb_tool_storage_host_write_seen()
                    ?"Flushed - auto detach in %lus"
                    :"Completed - auto detach in %lus",
                (unsigned long)seconds);
            set_status(PF_USB_TOOL_OK,detail);
        }
        return;
    }
    if(state!=PF_USB_TOOL_AUTO_DETACH_READY)return;
    if(!pf_usb_tool_storage_claim_auto_detach(PF_STORAGE_AUTO_DETACH_IDLE_MS))return;

    s_storage_auto_detach_pending=false;
    if(!io_attackmode(nullptr,1U)) {
        set_status(PF_USB_TOOL_ERROR,"Automatic storage detach failed");
        return;
    }
    if(s_sd_ready){scan_languages();scan_scripts();}
    s_storage_was_exposed=false;
    s_storage_view_stale=false;
    set_status(PF_USB_TOOL_OK,"Completed - storage detached");
}

static void handle_storage_eject(void)
{
    if(s_script_running || !s_storage_was_exposed || pf_usb_tool_storage_present())return;
    s_storage_auto_detach_pending=false;
    pf_usb_tool_storage_cancel_auto_detach();
    if(!prepare_local_sd_access("post-eject refresh"))return;
    if(s_sd_ready){scan_languages();scan_scripts();}
    if(s_script_count)
        set_status(PF_USB_TOOL_IDLE,s_script_index_truncated?"Ready - index truncated":"Ready");
    else
        set_status(PF_USB_TOOL_IDLE,"No payloads found");
}

static void script_worker_task(void *)
{
    while(true) {
        const uint32_t notified=ulTaskNotifyTake(pdTRUE,pdMS_TO_TICKS(100U));
        if(notified)run_task(nullptr);
        handle_storage_auto_detach();
        handle_storage_eject();
    }
}

static bool script_worker_start_run(void)
{
    if(!s_worker) {
        s_worker=xTaskCreateStaticPinnedToCore(
            script_worker_task,"ducky",PF_DUCKY_WORKER_STACK_BYTES,nullptr,
            CONFIG_TINYUSB_TASK_PRIORITY-2,s_worker_stack,&s_worker_tcb,1);
    }
    if(!s_worker)return false;
    s_script_running=true;
    xTaskNotifyGive(s_worker);
    return true;
}

extern "C" bool pf_usb_tool_begin(void)
{
    clear_pending_stage8();stage8_close_writer();
    if(!ensure_psram_tables()) {
        set_status(PF_USB_TOOL_ERROR,"Cannot allocate USB Tool PSRAM");return false;
    }
    s_stop=false;s_leds=0;s_received_led_report=false;s_host_configuration_request_count=0U;
    s_ducky_led=PF_USB_TOOL_LED_OFF;s_ducky_led_command_seen=false;
    s_ducky_led_options=DUCKY_LED_OPT_SYSTEM|DUCKY_LED_OPT_STORAGE|
        DUCKY_LED_OPT_CONTINUOUS_STORAGE|DUCKY_LED_OPT_INJECTING|DUCKY_LED_OPT_EXFIL;
    s_storage_activity_timeout_ms=1000U;
    s_button_was_down=digitalRead(0)==LOW;s_button_event_seen=false;s_button_last_event_ms=0U;
    s_attackmode=1U;s_attackmode_identity_custom=false;s_storage_was_exposed=false;
    s_storage_view_stale=false;s_storage_auto_detach_pending=false;
    s_storage_auto_detach_last_second=UINT32_MAX;
    pf_usb_tool_storage_cancel_auto_detach();loot_index_reset();
    s_stage8_authorized_caps=0U;s_stage8_session_bytes=0U;s_stage8_fault=0U;
    s_exfil_mode=false;s_reflection_receiving=false;
    if(!s_sd_spi.begin(WS_SD_SCLK,WS_SD_MISO,WS_SD_MOSI,WS_SD_CS)) {
        set_status(PF_USB_TOOL_NO_SD,"Cannot start SD bus");return false;
    }
    if(!SD.begin(WS_SD_CS,s_sd_spi,FIDO_V1_USB_TOOL_SD_HZ,"/usb-tool",4,false)) {
        s_sd_spi.end();set_status(PF_USB_TOOL_NO_SD,"Insert microSD");return false;
    }
    s_sd_ready=true;
    const bool index_ok=loot_index_load() && (!s_loot_index_dirty || loot_index_commit());
    scan_languages();scan_scripts();hid_set_report_cb=tool_set_report;
    if(!index_ok)set_status(PF_USB_TOOL_ERROR,"loot.idx does not match loot.bin");
    else if(s_script_count)set_status(PF_USB_TOOL_IDLE,s_script_index_truncated?"Ready - index truncated":"Ready");
    else set_status(PF_USB_TOOL_IDLE,"No payloads found");
    return true;
}

extern "C" void pf_usb_tool_end(void)
{
    s_stop=true;hid_set_report_cb=nullptr;
    clear_pending_stage8();stage8_cleanup();
    s_storage_auto_detach_pending=false;
    pf_usb_tool_storage_cancel_auto_detach();
    /* Leaving USB Tool is an explicit local action. Withdraw the medium before
     * releasing the SD driver so TinyUSB cannot service MSC from a dead bus. */
    if(pf_usb_tool_storage_present()) {
        (void)pf_usb_tool_storage_set_present(false);
        delay(250U);
    }
    if(s_sd_ready){SD.end();s_sd_spi.end();s_sd_ready=false;}
    /* A running task copies its selected path before opening the file.  Avoid
     * freeing the index underneath a task that has not been scheduled yet; it
     * will be reclaimed on the next begin(). */
    if(!s_script_running)clear_script_index();
    set_status(PF_USB_TOOL_DISABLED,"Disabled");
    s_ducky_led=PF_USB_TOOL_LED_OFF;s_ducky_led_command_seen=false;
}
extern "C" bool pf_usb_tool_media_ready(void){return s_sd_ready;}
extern "C" uint8_t pf_usb_tool_status(void){portENTER_CRITICAL(&s_guard);uint8_t v=(uint8_t)s_status;portEXIT_CRITICAL(&s_guard);return v;}
extern "C" bool pf_usb_tool_running(void){return s_script_running;}
extern "C" uint16_t pf_usb_tool_script_count(void){portENTER_CRITICAL(&s_guard);uint16_t v=s_script_count;portEXIT_CRITICAL(&s_guard);return v;}
extern "C" uint16_t pf_usb_tool_selected_index(void){portENTER_CRITICAL(&s_guard);uint16_t v=s_selected;portEXIT_CRITICAL(&s_guard);return v;}
extern "C" void pf_usb_tool_selected_name(char *out,size_t out_len)
{
    if(!out||out_len==0U)return;out[0]='\0';char path[MAX_PATH]={0};
    portENTER_CRITICAL(&s_guard);
    if(s_script_count && s_selected<s_script_count && s_scripts[s_selected]){strncpy(path,s_scripts[s_selected],sizeof(path)-1U);}
    portEXIT_CRITICAL(&s_guard);
    friendly_script_name(path,out,out_len);
}
extern "C" bool pf_usb_tool_select_delta(int delta)
{
    if(s_script_running)return false;portENTER_CRITICAL(&s_guard);
    if(!s_script_count){portEXIT_CRITICAL(&s_guard);return false;}
    int n=(int)s_selected+delta;while(n<0)n+=(int)s_script_count;while(n>=(int)s_script_count)n-=(int)s_script_count;
    s_selected=(uint16_t)n;portEXIT_CRITICAL(&s_guard);clear_pending_stage8();set_status(PF_USB_TOOL_IDLE,"Ready");return true;
}
extern "C" uint16_t pf_usb_tool_language_count(void){return s_language_count;}
extern "C" uint16_t pf_usb_tool_language_index(void){return s_language_selected;}
extern "C" void pf_usb_tool_language_name(char *out,size_t out_len)
{
    if(!out||out_len==0U)return;out[0]='\0';
    if(s_language_count && s_language_selected<s_language_count) {
        const pf_language_entry_t &e=s_languages[s_language_selected];
        if(!strcasecmp(e.code,"pl-programmer"))snprintf(out,out_len,"PL Programmer");
        else if(e.external)snprintf(out,out_len,"%s [Hak5]",e.code);
        else snprintf(out,out_len,"%s",e.code);
    } else ws_usb_tool_language_code(out,out_len);
}
extern "C" bool pf_usb_tool_select_language_delta(int delta)
{
    if(s_script_running||s_language_count==0U)return false;
    if(!prepare_local_sd_access("changing language"))return false;
    int start=(int)s_language_selected;
    for(uint16_t attempt=0;attempt<s_language_count;++attempt) {
        int n=start+delta*(int)(attempt+1U);
        while(n<0)n+=(int)s_language_count;while(n>=(int)s_language_count)n-=(int)s_language_count;
        if(load_language_index((uint16_t)n) && ws_usb_tool_set_language_code(s_languages[n].code)) {
            s_language_selected=(uint16_t)n;clear_pending_stage8();set_status(PF_USB_TOOL_IDLE,"Ready");return true;
        }
    }
    set_status(PF_USB_TOOL_ERROR,"No usable language map");return false;
}

extern "C" bool pf_usb_tool_run_selected(void)
{
    if(!s_sd_ready||s_script_running||pf_usb_tool_script_count()==0U)return false;
    char selected_path[MAX_PATH]={0};
    portENTER_CRITICAL(&s_guard);
    if(s_selected<s_script_count && s_scripts[s_selected])
        strncpy(selected_path,s_scripts[s_selected],sizeof(selected_path)-1U);
    portEXIT_CRITICAL(&s_guard);
    const bool refresh=s_storage_was_exposed || s_storage_view_stale ||
                       (s_attackmode&2U)!=0U;
    if(!prepare_local_sd_access("RUN"))return false;
    if(refresh) {
        scan_languages();scan_scripts();
        if(selected_path[0]) {
            for(uint16_t i=0U;i<s_script_count;++i) {
                if(s_scripts[i] && !strcasecmp(s_scripts[i],selected_path)) {
                    s_selected=i;break;
                }
            }
        }
    }
    if(!pf_usb_tool_script_count()) {
        set_status(PF_USB_TOOL_IDLE,"No payloads found");return false;
    }
    s_stop=false;
    if(!script_worker_start_run()) {set_status(PF_USB_TOOL_ERROR,"Cannot start script task");return false;}
    return true;
}
extern "C" bool pf_usb_tool_confirmation_pending(void)
{
    if(!s_pending_caps)return false;
    if((int32_t)(millis()-s_pending_deadline_ms)>0){clear_pending_stage8();set_status(PF_USB_TOOL_IDLE,"Approval expired");return false;}
    return true;
}
extern "C" bool pf_usb_tool_confirm_stage8(void)
{
    if(s_script_running || !pf_usb_tool_confirmation_pending())return false;
    s_confirmed_run=true;
    if(!pf_usb_tool_run_selected()){s_confirmed_run=false;return false;}
    return true;
}
extern "C" bool pf_usb_tool_stage8_active(void){return s_loot_open||s_exfil_mode||s_reflection_receiving;}
extern "C" void pf_usb_tool_stop(void){if(s_script_running)s_stop=true;}
extern "C" uint32_t pf_usb_tool_error_line(void){portENTER_CRITICAL(&s_guard);uint32_t v=s_error_line;portEXIT_CRITICAL(&s_guard);return v;}
extern "C" void pf_usb_tool_status_text(char *out,size_t out_len)
{
    if(!out||out_len==0U)return;portENTER_CRITICAL(&s_guard);strncpy(out,s_status_detail,out_len-1U);out[out_len-1U]='\0';portEXIT_CRITICAL(&s_guard);
}
extern "C" uint8_t pf_usb_tool_ducky_led(void)
{
    if(pf_usb_tool_stage8_active())return PF_USB_TOOL_LED_RED;
    if(s_ducky_led_command_seen)return s_ducky_led;
    const uint8_t options=s_ducky_led_options;
    const uint8_t locks=s_leds;
    if((options&DUCKY_LED_OPT_SHOW_NUM) && (locks&DUCKY_LED_NUM_LOCK))
        return PF_USB_TOOL_LED_RED;
    if(((options&DUCKY_LED_OPT_SHOW_CAPS) && (locks&DUCKY_LED_CAPS_LOCK)) ||
       ((options&DUCKY_LED_OPT_SHOW_SCROLL) && (locks&DUCKY_LED_SCROLL_LOCK)))
        return PF_USB_TOOL_LED_GREEN;
    if((options&DUCKY_LED_OPT_STORAGE) && pf_usb_tool_storage_present()) {
        const uint32_t age=pf_usb_tool_storage_activity_age_ms();
        if(age<=s_storage_activity_timeout_ms)
            return ((age/80U)&1U)?PF_USB_TOOL_LED_GREEN:PF_USB_TOOL_LED_RED;
        if(options&DUCKY_LED_OPT_CONTINUOUS_STORAGE)return PF_USB_TOOL_LED_GREEN;
    }
    if((options&DUCKY_LED_OPT_INJECTING) && s_script_running)return PF_USB_TOOL_LED_GREEN;
    return PF_USB_TOOL_LED_OFF;
}
extern "C" uint32_t pf_usb_tool_storage_activity_timeout_ms(void){return s_storage_activity_timeout_ms;}
