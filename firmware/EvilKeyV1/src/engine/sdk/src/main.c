#include "../../../pf_build_config.h"
/*
 * This file is part of the Pico Keys SDK distribution (https://github.com/polhenarejos/pico-keys-sdk).
 * Copyright (c) 2022 Pol Henarejos.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#include "picokeys.h"
#include "../../board/ws_board.h"
#include "../../board/ws_usb_tool_state.h"
#include "../../../pf_engine_api.h"
static void pf_service_usb_state(void);
#include "button.h"
#include <stdio.h>
#if !defined(ENABLE_EMULATION)
#include "tusb.h"
#endif
#if defined(ENABLE_EMULATION)
#include "emulation.h"
#elif defined(ESP_PLATFORM)
#include "driver/gpio.h"
#include "rom/gpio.h"
#elif defined(PICO_PLATFORM)
#include "bsp/board.h"
#include "hardware/structs/ioqspi.h"
#include "pico/stdio.h"
#endif

#include "rng/random.h"
#include "rng/hwrng.h"
#include "apdu.h"
#include "usb/usb.h"
#include "fs/flash.h"
#include "otp/otp.h"
#include "led/led.h"
#include "pico_time.h"
#include "serial.h"
#include "../../crypto/include/mbedtls/sha256.h"

extern int rescue_migrate_keydev(void);

app_t apps[16];
uint8_t num_apps = 0;

app_t *current_app = NULL;

const uint8_t *ccid_atr = NULL;

bool app_exists(const_byte_array_t aid) {
    for (int a = 0; a < num_apps; a++) {
        if (aid.len >= apps[a].aid[0] && !memcmp(apps[a].aid + 1, aid.data, apps[a].aid[0])) {
            return true;
        }
    }
    return false;
}

int register_app(int (*select_aid)(app_t *, uint8_t), const uint8_t *aid) {
    if (app_exists(CONST_BYTE_ARRAY(aid + 1, aid[0]))) {
        return 1;
    }
    if (num_apps < sizeof(apps) / sizeof(app_t)) {
        apps[num_apps].select_aid = select_aid;
        apps[num_apps].aid = aid;
        num_apps++;
        return 1;
    }
    return 0;
}

int select_app(const_byte_array_t aid) {
    if (current_app && current_app->aid && (current_app->aid + 1 == aid.data || (aid.len >= current_app->aid[0] && !memcmp(current_app->aid + 1, aid.data, current_app->aid[0])))) {
        current_app->select_aid(current_app, 0);
        return PICOKEYS_OK;
    }
    for (int a = 0; a < num_apps; a++) {
        if (aid.len >= apps[a].aid[0] && !memcmp(apps[a].aid + 1, aid.data, apps[a].aid[0])) {
            if (current_app) {
                if (current_app->aid && aid.len >= current_app->aid[0] && !memcmp(current_app->aid + 1, aid.data, current_app->aid[0])) {
                    current_app->select_aid(current_app, 1);
                    return PICOKEYS_OK;
                }
                if (current_app->unload) {
                    current_app->unload();
                }
            }
            current_app = &apps[a];
            if (current_app->select_aid(current_app, 1) == PICOKEYS_OK) {
                return PICOKEYS_OK;
            }
        }
    }
    return PICOKEYS_ERR_FILE_NOT_FOUND;
}


WEAK int picokey_init(void) {
    return 0;
}

void execute_tasks(void);
void execute_tasks(void) {
#if !defined(ENABLE_EMULATION) && !defined(ESP_PLATFORM)
    tud_task(); // tinyusb device task
#endif
#ifdef USB_ITF_LWIP
#if !defined(ENABLE_EMULATION)
    service_traffic();
#endif
    rest_task();
#endif
    usb_task();
    led_blinking_task();
    ws_board_poll();
#ifdef ENABLE_LVGL_UI
    platform_ui_task();
#endif
}

static void core0_loop(void *arg) {
    (void)arg;
#if defined(ESP_PLATFORM) && defined(USB_ITF_LWIP)
    if (ITF_LWIP_TOTAL > 0) {
        lwip_itf_init();
    }
#endif
    while (1) {
        pf_service_usb_state();
        execute_tasks();
        hwrng_task();
        flash_task();
        button_task();
#ifdef PICO_PLATFORM
        // Avoid a pure busy loop on core0; gives the system a scheduling hint.
        tight_loop_contents();
#endif
#ifdef ESP_PLATFORM
        vTaskDelay(pdMS_TO_TICKS(10));
#endif
    }
}

/* Arduino startup replaces app_main and the ESP-IDF TinyUSB driver install. */
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

int pf_engine_start(void) {
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
    return 0;
}
