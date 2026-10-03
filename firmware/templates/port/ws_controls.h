/* SPDX-License-Identifier: AGPL-3.0-or-later */
#pragma once
#include <stdbool.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef enum { PF_CONTROL_NORMAL=0, PF_CONTROL_USB_MOUSE=1,
    PF_CONTROL_BLE_MOUSE=2, PF_CONTROL_BLE_PAD=3 } PfControlMode;
#define WS_CONTROLS_BOOT_MAGIC 0xE71A0320UL
PfControlMode ws_controls_boot_mode(uint32_t token,uint32_t check,bool software_reset);
bool ws_controls_is_ble(PfControlMode mode);
uint16_t ws_controls_hid_buttons(uint16_t buttons,bool xbox);
typedef struct {
    uint8_t version, transport, profile, analog, orientation, deadzone;
} WsControlPrefs;
typedef struct { int16_t x,y; uint16_t id; } WsControlPoint;
typedef struct { uint16_t buttons; int16_t x,y; uint8_t hat,lt,rt; } WsPadReport;
typedef struct {
    float filtered[3],sum[3],neutral[3],right[3],down[3];
    uint32_t sampled_at;
    uint8_t samples;
    bool ready,valid;
} WsPadImu;
typedef struct {
    bool move,drag,armed,previous_down;
    uint8_t buttons;
} WsMouseLatch;
void ws_mouse_latch_reset(WsMouseLatch *mouse);
void ws_mouse_latch_touch(WsMouseLatch *mouse,bool valid,bool down,uint8_t zone,bool enabled);
typedef struct {
    WsPadReport report;
    uint32_t hold_at;
    uint8_t hold_step, modal;
    uint8_t ui_pressed, ui_modal, ui_capture;
    uint32_t ui_feedback_at;
    bool armed, previous_down;
    WsPadImu imu;
} WsGamepad;
typedef enum { WS_PAD_NONE=0,WS_PAD_EXIT,WS_PAD_PAIR,WS_PAD_FORGET,WS_PAD_SAVE,WS_PAD_CALIBRATE } WsPadAction;
void ws_controls_defaults(WsControlPrefs *prefs);
bool ws_controls_valid(const WsControlPrefs *prefs);
bool ws_controls_decode(WsControlPrefs *prefs,const uint8_t *data,unsigned length);
void ws_controls_rotate(uint8_t orientation,int16_t px,int16_t py,int16_t *x,int16_t *y);
void ws_gamepad_init(WsGamepad *pad);
void ws_gamepad_calibrate(WsGamepad *pad);
void ws_gamepad_imu_sample(WsGamepad *pad,float ax,float ay,float az,uint32_t now);
void ws_gamepad_apply_imu(WsGamepad *pad,const WsControlPrefs *prefs,bool connected,uint32_t now);
WsPadAction ws_gamepad_touch(WsGamepad *pad,WsControlPrefs *prefs,bool valid,
    const WsControlPoint *points,unsigned count,uint32_t now);
PfControlMode pf_control_mode(void);
void pf_control_restart(PfControlMode mode);
bool pf_ble_start(void);
bool pf_ble_connected(void);
bool pf_ble_ready(void);
bool pf_ble_failed(void);
void pf_ble_checkpoint(unsigned phase,int error);
const char *pf_ble_last_status(void);
bool pf_ble_mouse_report(uint8_t buttons,int8_t dx,int8_t dy,int8_t wheel);
bool pf_ble_pad_report(const WsPadReport *report);
void pf_ble_pair(void);
void pf_ble_forget(void);
void pf_ble_release(void);
const char *pf_ble_store_namespace(void);
void pf_controls_preferences(WsControlPrefs *out);
bool pf_controls_save(const WsControlPrefs *prefs);
#ifdef __cplusplus
}
#endif
