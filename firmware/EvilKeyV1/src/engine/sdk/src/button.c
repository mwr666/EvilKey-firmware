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
#include "button.h"
#include "../../board/ws_board.h"
#include "../../board/ws_settings.h"
#include "led/led.h"
#include "pico_time.h"
#if defined(PICO_PLATFORM)
#include "pico/multicore.h"
#include "hardware/sync.h"
#include "hardware/structs/ioqspi.h"
#include "hardware/gpio.h"
#elif defined(ESP_PLATFORM)
#include "driver/gpio.h"
#endif
#include "usb/usb.h"
#include "signal.h"

extern void execute_tasks(void);

int (*button_pressed_cb)(uint8_t) = NULL;

static bool req_button_pending = false;
#ifndef ENABLE_EMULATION
static bool async_button_wait = false;
static button_event_t ws_pending_result = BUTTON_EV_NONE;
static uint32_t async_button_led_mode = MODE_MOUNTED;
#endif

bool is_req_button_pending(void) {
    return req_button_pending;
}

volatile bool cancel_button = false;
bool touch_accept_button = false;
volatile bool force_button_wait = false;

#if !defined(ENABLE_EMULATION)
#ifdef ESP_PLATFORM
static bool picok_board_button_read(void) {
    int boot_state = gpio_get_level(BOOT_PIN);
    return boot_state == 0;
}
#elif defined(PICO_PLATFORM)
static bool __no_inline_not_in_flash_func(picok_get_bootsel_button)(void) {
    const uint CS_PIN_INDEX = 1;

    // Must disable interrupts, as interrupt handlers may be in flash, and we
    // are about to temporarily disable flash access!
    uint32_t flags = save_and_disable_interrupts();

    // Set chip select to Hi-Z
    hw_write_masked(&ioqspi_hw->io[CS_PIN_INDEX].ctrl,
                    GPIO_OVERRIDE_LOW << IO_QSPI_GPIO_QSPI_SS_CTRL_OEOVER_LSB,
                    IO_QSPI_GPIO_QSPI_SS_CTRL_OEOVER_BITS);

    // Note we can't call into any sleep functions in flash right now
    for (volatile int i = 0; i < 1000; ++i);

    // The HI GPIO registers in SIO can observe and control the 6 QSPI pins.
    // Note the button pulls the pin *low* when pressed.
#ifdef PICO_RP2040
    #define CS_BIT (1u << 1)
#else
    #define CS_BIT SIO_GPIO_HI_IN_QSPI_CSN_BITS
#endif
    bool button_state = !(sio_hw->gpio_hi_in & CS_BIT);

    // Need to restore the state of chip select, else we are going to have a
    // bad time when we return to code in flash!
    hw_write_masked(&ioqspi_hw->io[CS_PIN_INDEX].ctrl,
                    GPIO_OVERRIDE_NORMAL << IO_QSPI_GPIO_QSPI_SS_CTRL_OEOVER_LSB,
                    IO_QSPI_GPIO_QSPI_SS_CTRL_OEOVER_BITS);

    restore_interrupts(flags);

    return button_state;
}
static bool picok_board_button_read(void) {
  return picok_get_bootsel_button();
}
#else
static bool picok_board_button_read(void) {
    return true; // always unpressed
}
#endif
static bool button_pressed_state = false;
static uint32_t button_pressed_time = 0;
static uint8_t button_press = 0;
static bool button_hold_state = false;
static uint32_t button_hold_started = 0;
static uint32_t button_last_poll = 0;
volatile uint32_t button_pressed_duration = 0;

void button_wait_start(void) {
    /* Waveshare V1: physical presence is never automatically commissioned away. */
    /* PF_PROFILE_PATCH_023: configurable deadline, never automatic approval. */
    const uint32_t button_timeout = ws_settings_presence_timeout_ms();
    cancel_button = false;
    async_button_wait = true;
    ws_pending_result = BUTTON_EV_NONE;
    async_button_led_mode = led_get_mode();
    req_button_pending = true;
    led_set_mode(MODE_BUTTON);
    ws_board_presence_begin(button_timeout);
    signal_user_presence_request_data_t data = {
        .timeout = button_timeout / 1000,
    };
    signal_emit_param(SIGNAL_USER_PRESENCE_REQUEST, &data);
}

void button_wait_poll(void) {
    if (!async_button_wait) {
        return;
    }
    if (ws_pending_result == BUTTON_EV_NONE) {
        ws_pending_result = ws_board_presence_poll();
    }
    if (cancel_button) {
        ws_pending_result = BUTTON_EV_CANCELLED;
    }
    if (ws_pending_result == BUTTON_EV_NONE) {
        return;
    }
    button_event_t result = ws_pending_result;
    uint32_t flag = result == BUTTON_EV_PRESSED ? EV_BUTTON_PRESSED :
                    result == BUTTON_EV_TIMEOUT ? EV_BUTTON_TIMEOUT : EV_BUTTON_CANCELLED;
    /* Retry on a full queue instead of silently losing a one-shot decision. */
    if (!queue_try_add(&usb_to_card_q, &flag)) {
        return;
    }
    async_button_wait = false;
    req_button_pending = false;
    ws_pending_result = BUTTON_EV_NONE;
    ws_board_presence_end(result);
    led_set_mode(async_button_led_mode);
    if (result == BUTTON_EV_PRESSED) {
        signal_emit(SIGNAL_USER_PRESENCE_COMPLETED);
    } else if (result == BUTTON_EV_TIMEOUT) {
        signal_emit(SIGNAL_USER_PRESENCE_TIMEOUT);
    } else {
        signal_emit(SIGNAL_USER_PRESENCE_CANCELLED);
    }
}

#endif

void button_task(void) {
#ifndef ENABLE_EMULATION
    uint32_t now = board_millis();
    if (now > 1000 && now - button_last_poll >= 10 && (async_button_wait || !is_busy())) { // wait 1 second to boot up
#ifdef PICO_PLATFORM
        if (!multicore_lockout_start_timeout_us(1000)) {
            return;
        }
#endif
        bool current_button_state = picok_board_button_read();
#ifdef PICO_PLATFORM
        multicore_lockout_end_timeout_us(1000);
#endif
        button_last_poll = now;
        if (async_button_wait) {
            button_wait_poll();
            return;
        }
        if (current_button_state && !button_hold_state) {
            button_hold_started = now;
            button_pressed_duration = 0;
        }
        else if (!current_button_state && button_hold_state) {
            button_pressed_duration = button_hold_started == 0 ? 0 : now - button_hold_started;
            button_hold_started = 0;
        }
        else if (current_button_state && button_hold_state && button_hold_started != 0) {
            button_pressed_duration = now - button_hold_started;
        }
        button_hold_state = current_button_state;
        if (button_pressed_cb) {
            if (current_button_state != button_pressed_state) {
                if (current_button_state == false) { // unpressed
                    if (button_pressed_time == 0 || button_pressed_time + 1000 > now) {
                        button_press++;
                    }
                    button_pressed_time = now;
                }
                button_pressed_state = current_button_state;
            }
            if (button_pressed_time > 0 && button_press > 0 && button_pressed_time + 1000 < now && button_pressed_state == false) {
                if (button_pressed_cb != NULL) {
                    (*button_pressed_cb)(button_press);
                }
                button_pressed_time = button_press = 0;
            }
        }
    }
#endif
}
