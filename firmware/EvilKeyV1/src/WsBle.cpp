/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "engine/board/ws_controls.h"
#include <Arduino.h>
#include <NimBLEDevice.h>
#include <NimBLEHIDDevice.h>
#include <BleGamepad.h>
#include <atomic>
#include "esp_mac.h"
#include "esp_log.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "freertos/queue.h"
#include "esp_attr.h"
#include "esp_heap_caps.h"
#include "esp_system.h"
#include <cstdio>
#include "pf_ble_bootstrap.h"

struct BleDiagnostic { uint32_t magic,phase,heap,largest; int32_t error; };
RTC_NOINIT_ATTR static BleDiagnostic last_ble;
extern "C" void pf_ble_checkpoint(unsigned phase,int error) {
    last_ble.magic=0;
    last_ble.phase=phase;last_ble.error=error;
    last_ble.heap=heap_caps_get_free_size(MALLOC_CAP_INTERNAL|MALLOC_CAP_8BIT);
    last_ble.largest=heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL|MALLOC_CAP_8BIT);
    last_ble.magic=0xE71AB1E1;
    ESP_LOGI("ek_ble","phase %u error %d internal heap %u",phase,error,last_ble.heap);
}
extern "C" const char *pf_ble_last_status(void) {
    static char status[64];
    const char *names[]={"","worker","NVS","ctrl init","ctrl on","HCI","host","sync","HID","advertise","running","HCI buffers","HCI callback","HCI semaphore","bootstrap","GATT","adv data","adv start","adv response","GATT service"};
    if(pf_control_mode()!=PF_CONTROL_NORMAL || last_ble.magic!=0xE71AB1E1 ||
       !last_ble.phase || last_ble.phase>19 ||
       (last_ble.phase==10 && !last_ble.error && esp_reset_reason()!=ESP_RST_PANIC))return "";
    snprintf(status,sizeof(status),"BLE %s %c%d H%uK L%uK",names[last_ble.phase],
        last_ble.error?'E':'R',last_ble.error?last_ble.error:(int)esp_reset_reason(),last_ble.heap/1024U,last_ble.largest/1024U);
    return status;
}

static std::atomic<bool> ready{false}, connected{false}, failed{false};
static std::atomic<uint8_t> pending_command{0};
static WsControlPrefs prefs;
static QueueHandle_t queue;
static NimBLECharacteristic *mouse_input;
static BleGamepad *gamepad;
static std::atomic<TaskHandle_t> bootstrap_task{nullptr};
struct Message { uint8_t kind, buttons; int8_t x,y,wheel; WsPadReport pad; };

extern "C" const char *pf_ble_store_namespace(void) {
    if(pf_control_mode()==PF_CONTROL_BLE_MOUSE)return "ek_ble_mouse";
    return prefs.profile?"ek_ble_xbox":"ek_ble_generic";
}
extern "C" void pf_controls_preferences(WsControlPrefs *out) {
    ws_controls_defaults(out);
    nvs_handle_t h;
    if(nvs_open_from_partition("wsdev","ws_controls",NVS_READONLY,&h)!=ESP_OK)return;
    uint8_t saved[sizeof(WsControlPrefs)]={0};size_t size=sizeof(saved);
    if(nvs_get_blob(h,"prefs_v1",saved,&size)==ESP_OK)
        (void)ws_controls_decode(out,saved,(unsigned)size);
    nvs_close(h);
}
extern "C" bool pf_controls_save(const WsControlPrefs *p) {
    if(!ws_controls_valid(p))return false;
    nvs_handle_t h;
    if(nvs_open_from_partition("wsdev","ws_controls",NVS_READWRITE,&h)!=ESP_OK)return false;
    esp_err_t result=nvs_set_blob(h,"prefs_v1",p,sizeof(*p));
    if(result==ESP_OK)result=nvs_commit(h);
    nvs_close(h);return result==ESP_OK;
}
static bool identity() {
    uint8_t address[6];
    if(esp_read_mac(address,ESP_MAC_BT)!=ESP_OK)return false;
    // NimBLE expects least-significant byte first. Profile-specific static random
    // identities keep host HID caches and bonds separate across descriptor changes.
    uint8_t reversed[6];for(unsigned i=0;i<6;++i)reversed[i]=address[5-i];
    reversed[0]^=pf_control_mode()==PF_CONTROL_BLE_MOUSE?0x41:prefs.profile?0x42:0x43;
    reversed[5]|=0xC0;
    return NimBLEDevice::setOwnAddr(reversed) && NimBLEDevice::setOwnAddrType(BLE_OWN_ADDR_RANDOM);
}
class Pad:public BleGamepad {
public:
    Pad():BleGamepad("EvilKey Gamepad","EvilKey",100,true) {}
    void onStarted(NimBLEServer *server) override {
        pf_ble_checkpoint(8,0);
        if(!identity()){pf_ble_checkpoint(8,ESP_FAIL);failed=true;return;}
        NimBLEDevice::setSecurityAuth(true,false,true);
        server->advertiseOnDisconnect(true);
        bootstrap_task=xTaskGetCurrentTaskHandle();
        ready=true;
    }
};
class MouseCallbacks:public NimBLEServerCallbacks {
    void onConnect(NimBLEServer *s,NimBLEConnInfo &info) override {
        s->updateConnParams(info.getConnHandle(),6,12,0,400);
        connected=info.isEncrypted();
    }
    void onAuthenticationComplete(NimBLEConnInfo &info) override {
        connected=info.isEncrypted();
    }
    void onDisconnect(NimBLEServer *,NimBLEConnInfo &,int) override { connected=false; }
};
static MouseCallbacks mouse_callbacks;
static uint8_t mouse_descriptor[]={
    0x05,0x01,0x09,0x02,0xA1,0x01,0x85,0x01,0x09,0x01,0xA1,0x00,
    0x05,0x09,0x19,0x01,0x29,0x03,0x15,0x00,0x25,0x01,0x95,0x03,
    0x75,0x01,0x81,0x02,0x95,0x01,0x75,0x05,0x81,0x03,
    0x05,0x01,0x09,0x30,0x09,0x31,0x09,0x38,0x15,0x81,0x25,0x7F,
    0x75,0x08,0x95,0x03,0x81,0x06,0xC0,0xC0};
static bool mouse_start() {
    if(!NimBLEDevice::init("EvilKey AirMouse"))return false;
    pf_ble_checkpoint(8,0);
    if(!identity()){pf_ble_checkpoint(8,ESP_FAIL);return false;}
    NimBLEDevice::setSecurityAuth(true,false,true);
    NimBLEServer *server=NimBLEDevice::createServer();
    if(!server)return false;
    server->setCallbacks(&mouse_callbacks,false);
    server->advertiseOnDisconnect(true);
    auto *hid=new(std::nothrow) NimBLEHIDDevice(server);
    if(!hid)return false;
    mouse_input=hid->getInputReport(1);
    if(!mouse_input)return false;
    hid->setManufacturer("EvilKey");hid->setHidInfo(0,1);
    hid->setPnp(2,0xFEFF,0xFCFA,0x0600);
    hid->setReportMap(mouse_descriptor,sizeof(mouse_descriptor));
    if(!server->start())return false;
    auto *ad=NimBLEDevice::getAdvertising();
    ad->setAppearance(HID_MOUSE);ad->setName("EvilKey AirMouse");
    ad->addServiceUUID(hid->getHidService()->getUUID());
    pf_ble_checkpoint(9,0);
    return ad->start();
}
static void send(const Message &m) {
    if(gamepad) {
        uint16_t buttons=ws_controls_hid_buttons(m.pad.buttons,prefs.profile!=0);
        for(unsigned b=0;b<(prefs.profile?10U:8U);++b) {
            if(buttons&(1U<<b))gamepad->press(b+1);else gamepad->release(b+1);
        }
        gamepad->setLeftThumb(m.pad.x,prefs.profile?m.pad.y:(int16_t)-m.pad.y);
        gamepad->setHat1(m.pad.hat==8?0:m.pad.hat+1);
        int16_t lt=(int16_t)((uint32_t)m.pad.lt*32767U/255U);
        int16_t rt=(int16_t)((uint32_t)m.pad.rt*32767U/255U);
        if(prefs.profile){gamepad->setLeftTrigger(lt);gamepad->setRightTrigger(rt);}
        else {gamepad->setBrake(lt);gamepad->setAccelerator(rt);}
        gamepad->sendReport();
    } else if(mouse_input && connected) {
        uint8_t report[]={m.buttons,(uint8_t)m.x,(uint8_t)m.y,(uint8_t)m.wheel};
        mouse_input->setValue(report,sizeof(report));mouse_input->notify();
    }
}
static void startup_failed() {
    ready=false;connected=false;failed=true;
    // Always return to the normal one-shot boot role. Even a partially
    // initialized controller is reset; the next Arduino startup releases its
    // RAM and never starts NimBLE. No NVS recovery/erase is attempted.
    ESP_LOGE("ek_ble","BLE startup failed; returning to FIDO with radio off");
    pf_control_restart(PF_CONTROL_NORMAL);
}
static void worker(void *) {
    if(pf_control_mode()==PF_CONTROL_BLE_MOUSE) {
        if(!mouse_start()){startup_failed();vTaskDelete(nullptr);return;}
        ready=true;
    } else {
        gamepad=new(std::nothrow) Pad;
        if(!gamepad){startup_failed();vTaskDelete(nullptr);return;}
        BleGamepadConfiguration config;
        config.setGamepadMode(prefs.profile?GamepadMode::XInputSeriesX:GamepadMode::Generic);
        config.setAutoReport(false);config.setButtonCount(prefs.profile?10:8);config.setHatSwitchCount(1);
        config.setAxesMin(-32767);config.setAxesMax(32767);
        if(!prefs.profile) {
            config.setWhichAxes(true,true,false,false,false,false,false,false);
            config.setWhichSimulationControls(false,false,true,true,false);
        }
        gamepad->begin(&config);
        uint32_t start=millis();
        while(!ready && !failed && millis()-start<5000U)vTaskDelay(pdMS_TO_TICKS(10));
        if(!ready || failed){startup_failed();vTaskDelete(nullptr);return;}
        pf_ble_checkpoint(14,0);
        if(!pf_ble_retire_bootstrap(bootstrap_task.load(),pdMS_TO_TICKS(1000))) {
            pf_ble_checkpoint(14,ESP_ERR_TIMEOUT);startup_failed();vTaskDelete(nullptr);return;
        }
        bootstrap_task=nullptr;
        pf_ble_checkpoint(9,0);
        if(!NimBLEDevice::getAdvertising()->start()){startup_failed();vTaskDelete(nullptr);return;}
    }
    pf_ble_checkpoint(10,0);
    bool previous=false;
    for(;;) {
        if(gamepad)connected=gamepad->isConnected();
        bool current=connected;
        if(current!=previous) {
            xQueueReset(queue);Message neutral{};neutral.pad.hat=8;
            if(current)send(neutral);
            previous=current;
        }
        uint8_t command=pending_command.exchange(0);
        if(command) {
            xQueueReset(queue);
            Message neutral{};neutral.pad.hat=8;
            if(connected)send(neutral);
            auto *server=NimBLEDevice::getServer();
            if(server)for(auto handle:server->getPeerDevices())server->disconnect(handle);
            if(command==4 && !NimBLEDevice::deleteAllBonds())ESP_LOGW("ek_ble","BLE bond removal failed; storage was not erased");
            NimBLEDevice::getAdvertising()->start();
        }
        Message m{};
        if(xQueueReceive(queue,&m,pdMS_TO_TICKS(8))==pdPASS && connected)send(m);
    }
}
extern "C" bool pf_ble_start(void) {
    if(!ws_controls_is_ble(pf_control_mode()))return false;
    pf_ble_checkpoint(1,0);
    if(queue)return false;
    pf_controls_preferences(&prefs);
    queue=xQueueCreate(16,sizeof(Message));
    if(!queue)return false;
    if(xTaskCreate(worker,"ek_ble",6144,nullptr,1,nullptr)!=pdPASS){vQueueDelete(queue);queue=nullptr;failed=true;return false;}
    return true;
}
extern "C" bool pf_ble_connected(void){return connected;}
extern "C" bool pf_ble_ready(void){return ready;}
extern "C" bool pf_ble_failed(void){return failed;}
static bool post(const Message &m) {
    if(!queue || failed)return false;
    if(xQueueSend(queue,&m,0)==pdPASS)return true;
    // Preserve prompt releases rather than replaying a long backlog of held inputs.
    xQueueReset(queue);Message neutral{};neutral.pad.hat=8;
    xQueueSend(queue,&neutral,0);return xQueueSend(queue,&m,0)==pdPASS;
}
extern "C" bool pf_ble_mouse_report(uint8_t buttons,int8_t x,int8_t y,int8_t wheel) {
    if(!connected)return false;
    Message m{};m.kind=1;m.buttons=buttons;m.x=x;m.y=y;m.wheel=wheel;return post(m);
}
extern "C" bool pf_ble_pad_report(const WsPadReport *report) {
    if(!report || !connected)return false;
    Message m{};m.kind=2;m.pad=*report;return post(m);
}
extern "C" void pf_ble_pair(void){if(!ready)return;uint8_t empty=0;pending_command.compare_exchange_strong(empty,3);}
extern "C" void pf_ble_forget(void){if(ready)pending_command=4;}
extern "C" void pf_ble_release(void){Message m{};m.pad.hat=8;post(m);}
