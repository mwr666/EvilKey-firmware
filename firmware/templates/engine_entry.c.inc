/* Arduino startup replaces app_main and the ESP-IDF TinyUSB driver install. */
#include "../../board/ws_controls.h"
#include "../../../apps/ek_render_parallel.h"
#include "nvs_flash.h"
TaskHandle_t hcore0 = NULL, hcore1 = NULL;
static portMUX_TYPE pf_event_lock = portMUX_INITIALIZER_UNLOCKED;
static int pf_usb_event = 0;
static bool pf_usb_event_pending = false;
static bool pf_abort_pending = false;

void pf_engine_usb_state(int state) {
    portENTER_CRITICAL(&pf_event_lock);
    pf_usb_event = state;
    pf_usb_event_pending = true;
    if (state != 1) pf_abort_pending = true;
    portEXIT_CRITICAL(&pf_event_lock);
}

static void pf_service_usb_state(void) {
    portENTER_CRITICAL(&pf_event_lock);
    int state = pf_usb_event;
    bool pending = pf_usb_event_pending;
    bool cancel = pf_abort_pending;
    pf_usb_event_pending = false;
    pf_abort_pending = false;
    portEXIT_CRITICAL(&pf_event_lock);
    if (cancel) {
        cancel_button = true;
        ws_board_pin_abort();
    }
    if (pending) led_set_mode(state == 1 ? MODE_MOUNTED :
                              state == 2 ? MODE_SUSPENDED : MODE_NOT_MOUNTED);
}

static void pf_controls_loop(void *arg) {
    (void)arg;
    for(;;){ws_board_poll();vTaskDelay(pdMS_TO_TICKS(5));}
}

int pf_engine_start(void) {
    if(pf_control_mode()==PF_CONTROL_BLE_MOUSE || pf_control_mode()==PF_CONTROL_BLE_PAD) {
        // No CTAP/USB/keystore engine is started in a BLE controller role.
        if(nvs_flash_init_partition("wsdev")!=ESP_OK)return -5;
        const gpio_config_t boot={.pin_bit_mask=1ULL<<GPIO_NUM_0,.mode=GPIO_MODE_INPUT,
            .pull_up_en=GPIO_PULLUP_ENABLE,.pull_down_en=GPIO_PULLDOWN_DISABLE,.intr_type=GPIO_INTR_DISABLE};
        if(gpio_config(&boot)!=ESP_OK)return -2;
        led_init();ws_board_init();
        // Establish touch/BOOT servicing before any radio worker can start.
        if(xTaskCreatePinnedToCore(pf_controls_loop,"ek_controls",8192,NULL,1,&hcore0,ESP32_CORE0)!=pdPASS) {
            pf_control_restart(PF_CONTROL_NORMAL);return -3;
        }
        if(!pf_ble_start()){pf_control_restart(PF_CONTROL_NORMAL);return -6;}
        ws_board_start_display();
        ek_render_workers_start();
        return 0;
    }
    serial_init();
    random_init();
    otp_init();
    low_flash_init();
    file_scan_flash();
    if (rescue_migrate_keydev() != PICOKEYS_OK) return -1;
    init_rtc();
    phy_init();
    led_init();
    usb_init();
#if FIDO_V1_USB_TOOL
    ws_usb_tool_state_init();
#endif
    const gpio_config_t boot = {
        .pin_bit_mask = 1ULL << GPIO_NUM_0,
        .mode = GPIO_MODE_INPUT,
        .pull_up_en = GPIO_PULLUP_ENABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE,
    };
    if (gpio_config(&boot) != ESP_OK) return -2;
    force_button_wait = true;
    ws_board_init();
    picokey_init();
    if (xTaskCreatePinnedToCore(core0_loop, "fido_core", 8192, NULL,
        CONFIG_TINYUSB_TASK_PRIORITY - 1, &hcore0, ESP32_CORE0) != pdPASS) return -3;
    if (!pf_arduino_usb_start()) {
        vTaskDelete(hcore0);
        hcore0 = NULL;
        return -4;
    }
    // TinyUSB's contiguous stack/endpoints must exist before display DMA strips.
    // Board/PIN state and the FIDO worker are already initialized; UI stays
    // fail-closed until the display owner commits a visible authorization frame.
    ws_board_start_display();
    ek_render_workers_start();
    return 0;
}
