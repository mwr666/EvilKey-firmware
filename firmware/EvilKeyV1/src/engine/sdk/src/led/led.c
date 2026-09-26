#include "../../../../pf_build_config.h"
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

#include "../picokeys.h"
#include "led.h"
#include "../pico_time.h"
#if defined(ESP_PLATFORM)
#include "driver/gpio.h"
#elif defined(ENABLE_EMULATION)
#include "emulation.h"
#endif

led_driver_t *led_driver = NULL;

static uint32_t led_mode = MODE_NOT_MOUNTED;

static volatile bool blink_pending = false;
static volatile uint8_t blink_count = 0;
static volatile uint8_t blink_color = LED_COLOR_GREEN;
static volatile uint32_t blink_on_ms = 0;
static volatile uint32_t blink_off_ms = 0;

void led_set_mode(uint32_t mode) {
    led_mode = mode;
}

uint32_t led_get_mode(void) {
    return led_mode;
}

void led_blink_n_times(uint8_t count, uint8_t color, uint32_t on_ms, uint32_t off_ms) {
    if (count == 0 || on_ms == 0 || off_ms == 0) {
        return;
    }
    blink_count = count;
    blink_color = color;
    blink_on_ms = on_ms;
    blink_off_ms = off_ms;
    blink_pending = true;
}

void led_blinking_task(void) {
#if defined(PICO_PLATFORM) || defined(ESP_PLATFORM)
    static uint32_t start_ms = 0;
    static uint32_t stop_ms = 0;
    static uint32_t last_led_update_ms = 0;
    static uint8_t led_state = false;
    static bool blink_active = false;
    static bool blink_on = false;
    static uint8_t blinks_remaining = 0;
    static uint8_t active_blink_color = LED_COLOR_GREEN;
    static uint32_t active_blink_on_ms = 0;
    static uint32_t active_blink_off_ms = 0;
    static uint32_t blink_deadline_ms = 0;

    uint32_t now = board_millis();
    if (blink_pending) {
        blink_pending = false;
        blink_active = true;
        blink_on = true;
        blinks_remaining = blink_count;
        active_blink_color = blink_color;
        active_blink_on_ms = blink_on_ms;
        active_blink_off_ms = blink_off_ms;
        blink_deadline_ms = now + active_blink_on_ms;
        led_driver->set_color(active_blink_color, MAX_BTNESS, 1.0f);
        return;
    }
    if (blink_active) {
        if (now < blink_deadline_ms) {
            return;
        }
        if (blink_on) {
            blink_on = false;
            blink_deadline_ms = now + active_blink_off_ms;
            led_driver->set_color(LED_COLOR_OFF, 0, 0.0f);
            return;
        }
        if (--blinks_remaining == 0) {
            blink_active = false;
        }
        else {
            blink_on = true;
            blink_deadline_ms = now + active_blink_on_ms;
            led_driver->set_color(active_blink_color, MAX_BTNESS, 1.0f);
            return;
        }
    }
    uint8_t state = led_state;
#ifdef PICO_DEFAULT_LED_PIN_INVERTED
    state = !state;
#endif
    uint32_t led_brightness = (led_mode & LED_BTNESS_MASK) >> LED_BTNESS_SHIFT;
    uint32_t led_color = (led_mode & LED_COLOR_MASK) >> LED_COLOR_SHIFT;
    uint32_t led_off = (led_mode & LED_OFF_MASK) >> LED_OFF_SHIFT;
    uint32_t led_on = (led_mode & LED_ON_MASK) >> LED_ON_SHIFT;

    float progress = 0;

    if (stop_ms > start_ms) {
        progress = (float)(now - start_ms) / (stop_ms - start_ms);
    }

    if (!state) {
        progress = 1. - progress;
    }
    if (phy_data.opts & PHY_OPT_LED_STEADY) {
        progress = 1;
    }

    // limit the frequency of LED status updates
    if (now - last_led_update_ms > 2) {
        led_driver->set_color(led_color, led_brightness, progress);
        last_led_update_ms = now;
    }

    if (now >= stop_ms){
        start_ms = stop_ms;
        led_state ^= 1; // toggle
        stop_ms = start_ms + (led_state ? led_on : led_off);
    }
#endif
}

void led_off_all(void) {
#if defined(PICO_PLATFORM) || defined(ESP_PLATFORM)
    led_driver->set_color(LED_COLOR_OFF, 0, 0);
#endif
}

extern led_driver_t led_driver_pico;
extern led_driver_t led_driver_cyw43;
extern led_driver_t led_driver_ws2812;
extern led_driver_t led_driver_neopixel;
extern led_driver_t led_driver_pimoroni;

static void led_driver_init_dummy(void) {
    // Do nothing
}

static void led_driver_color_dummy(uint8_t color, uint32_t led_brightness, float progress) {
    (void)color;
    (void)led_brightness;
    (void)progress;
    // Do nothing
}

led_driver_t led_driver_dummy = {
    .init = led_driver_init_dummy,
    .set_color = led_driver_color_dummy,
};

void led_init(void) {
    /* GPIO48 is I2C SCL on V1, not a NeoPixel output. Ignore host LED config. */
    led_driver = &led_driver_dummy;
    led_driver->init();
    led_set_mode(MODE_NOT_MOUNTED);
}
