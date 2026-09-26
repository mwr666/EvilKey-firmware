#include "../../../../pf_build_config.h"
#include "../../../board/ws_local_uv.h"
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
#include "usb.h"
#include "../led/led.h"
#include "../button.h"
#include "../pico_time.h"
#if defined(PICO_PLATFORM)
#include "pico/bootrom.h"
#include "pico/multicore.h"
#include "hardware/sync.h"
#define multicore_launch_func_core1(a) multicore_launch_core1((void (*) (void))a)
#endif
#include "../apdu.h"
#ifndef ENABLE_EMULATION
#include "tusb.h"
#else
#include "emulation.h"
#endif

// Device specific functions
static uint32_t *timeout_counter = NULL;
static uint8_t card_locked_itf = 0; // no locked
static void *(*card_locked_func)(void *) = NULL;
#ifndef ENABLE_EMULATION
static mutex_t mutex;
#endif
#if !defined(PICO_PLATFORM) && !defined(ENABLE_EMULATION) && !defined(ESP_PLATFORM)
#ifdef _MSC_VER
#include "../compat/pthread_win32.h"
#endif
pthread_t hcore0, hcore1;
#endif

#ifdef USB_ITF_HID
    uint8_t ITF_HID_CTAP = ITF_INVALID, ITF_HID_KB = ITF_INVALID;
    uint8_t ITF_HID = ITF_INVALID, ITF_KEYBOARD = ITF_INVALID;
    uint8_t ITF_HID_TOTAL = 0;
    extern void hid_init(void);
#endif

#ifdef USB_ITF_CCID
    uint8_t ITF_SC_CCID = ITF_INVALID, ITF_SC_WCID = ITF_INVALID;
    uint8_t ITF_CCID = ITF_INVALID, ITF_WCID = ITF_INVALID;
    uint8_t ITF_SC_TOTAL = 0;
    extern void ccid_init(void);
#endif

#ifdef USB_ITF_LWIP
    uint8_t ITF_LWIP_NET = ITF_INVALID, ITF_LWIP = ITF_INVALID;
    uint8_t ITF_LWIP_TOTAL = 0;
    extern void lwip_init(void);
#endif
uint8_t ITF_TOTAL = 0;

void usb_set_timeout_counter(uint8_t itf, uint32_t v) {
    timeout_counter[itf] = v;
}

queue_t usb_to_card_q = {0};
queue_t card_to_usb_q = {0};

#ifndef ENABLE_EMULATION
extern tusb_desc_device_t desc_device;
extern char *string_desc_itf[5], *string_desc_arr[];
#endif
void usb_init(void) {
    /* Arduino owns USB device/configuration descriptors; only CTAPHID is exposed. */
    mutex_init(&mutex);
    queue_init(&card_to_usb_q, sizeof(uint32_t), 64);
    queue_init(&usb_to_card_q, sizeof(uint32_t), 64);
    if (!mutex || !card_to_usb_q || !usb_to_card_q) abort();
    ITF_HID_CTAP = ITF_HID = 0;
    ITF_HID_KB = ITF_KEYBOARD = ITF_INVALID;
    ITF_HID_TOTAL = ITF_TOTAL = 1;
    card_locked_itf = ITF_TOTAL;
    timeout_counter = calloc(ITF_TOTAL, sizeof(uint32_t));
    if (!timeout_counter) abort();
    hid_init();
    set_atr();
}

#ifdef PICO_PLATFORM
extern char __end__, __HeapLimit;
extern char __StackBottom, __StackTop;
extern char __StackOneBottom, __StackOneTop;
static uint8_t reboot_temp_stack[1024] __attribute__((aligned(8)));

static inline void secure_bzero(void *ptr, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *) ptr;
    while (len--) {
        *p++ = 0xFF;
    }
}

static void __attribute__((noreturn, noinline)) usb_secure_reboot_now(void) {
    uintptr_t heap_start = (uintptr_t) &__end__;
    uintptr_t heap_end = (uintptr_t) &__HeapLimit;
    uintptr_t stack0_start = (uintptr_t) &__StackBottom;
    uintptr_t stack0_end = (uintptr_t) &__StackTop;
    uintptr_t stack1_start = (uintptr_t) &__StackOneBottom;
    uintptr_t stack1_end = (uintptr_t) &__StackOneTop;

    (void) save_and_disable_interrupts();
    multicore_reset_core1();

    if (stack1_end > stack1_start) {
        secure_bzero((void *) stack1_start, stack1_end - stack1_start);
    }

    uintptr_t new_sp = (((uintptr_t) reboot_temp_stack) + sizeof(reboot_temp_stack)) & ~(uintptr_t)0x7;
#if defined(__arm__) || defined(__thumb__)
    __asm volatile ("msr msp, %0" :: "r"(new_sp) : "memory");
#endif

    if (heap_end > heap_start) {
        secure_bzero((void *) heap_start, heap_end - heap_start);
    }
    if (stack0_end > stack0_start) {
        secure_bzero((void *) stack0_start, stack0_end - stack0_start);
    }
    secure_bzero(reboot_temp_stack, sizeof(reboot_temp_stack));

    reset_usb_boot(0, 0);
    while (true) {
        tight_loop_contents();
    }
}
#endif

uint32_t timeout = 0;
void timeout_stop(void) {
    timeout = 0;
}

void timeout_start(void) {
    timeout = board_millis();
}

bool is_busy(void) {
    return timeout > 0;
}

void usb_send_event(uint32_t flag) {
#ifndef ENABLE_EMULATION
    mutex_enter_blocking(&mutex);
#endif
    queue_add_blocking(&usb_to_card_q, &flag);
    if (flag == EV_CMD_AVAILABLE) {
        timeout_start();
    }
#ifndef ENABLE_EMULATION
    mutex_exit(&mutex);
#endif

    if (flag != EV_CMD_AVAILABLE) {
        uint32_t m;
        queue_remove_blocking(&card_to_usb_q , &m);
    }
}

void card_init_core1(void) {
    low_flash_init_core1();
}

volatile uint16_t finished_data_size = 0;

#ifdef ESP_PLATFORM
/* Keep the CTAP worker independent of the fragmented runtime heap.  LVGL and
 * optional UI objects are constructed before the first host command arrives;
 * allocating the 16 KiB worker stack only then can fail and leave CTAPHID
 * emitting KEEPALIVE_PROCESSING forever.  A persistent statically-backed
 * dispatcher owns the stack once and runs either the CTAP1 or CTAP2 loop. */
#define PF_CARD_WORKER_STACK_BYTES 16384U
static StaticTask_t s_card_worker_tcb;
static StackType_t s_card_worker_stack[PF_CARD_WORKER_STACK_BYTES];
static void *(*s_card_worker_func)(void *);

static void card_worker_task(void *arg) {
    (void)arg;
    while (true) {
        (void)ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
        void *(*func)(void *) = s_card_worker_func;
        if (func) {
            (void)func(NULL);
        }
    }
}

static bool card_worker_launch(void *(*func)(void *)) {
    if (!hcore1) {
        hcore1 = xTaskCreateStaticPinnedToCore(
            card_worker_task, "fido_card", PF_CARD_WORKER_STACK_BYTES, NULL,
            CONFIG_TINYUSB_TASK_PRIORITY - 2, s_card_worker_stack,
            &s_card_worker_tcb, ESP32_CORE1);
    }
    if (!hcore1) {
        return false;
    }
    s_card_worker_func = func;
    xTaskNotifyGive(hcore1);
    return true;
}
#endif

bool card_start(uint8_t itf, void *(*func)(void *)) {
    timeout_start();
    if (card_locked_itf != itf || card_locked_func != func) {
        if (card_locked_itf != ITF_TOTAL || card_locked_func != NULL) {
            card_exit();
        }
        if (func) {
#ifdef ESP_PLATFORM
            if (!card_worker_launch(func)) {
                timeout_stop();
                card_locked_itf = ITF_TOTAL;
                card_locked_func = NULL;
                return false;
            }
#else
            multicore_reset_core1();
            multicore_launch_func_core1(func);
#endif
        }
        led_set_mode(MODE_MOUNTED);
        card_locked_itf = itf;
        card_locked_func = func;
    }
    return true;
}

void card_exit(void) {
    ws_board_pin_abort(); /* PF_LOCAL_UV_024 */
    if (card_locked_itf != ITF_TOTAL || card_locked_func != NULL) {
        usb_send_event(EV_EXIT);
        uint32_t m;
        while (queue_is_empty(&usb_to_card_q) == false) {
            if (queue_try_remove(&usb_to_card_q, &m) == false) {
                break;
            }
        }
        while (queue_is_empty(&card_to_usb_q) == false) {
#ifndef ENABLE_EMULATION
            mutex_enter_blocking(&mutex);
#endif
            if (queue_try_remove(&card_to_usb_q, &m) == false) {
                break;
            }
#ifndef ENABLE_EMULATION
            mutex_exit(&mutex);
#endif
        }
        led_set_mode(MODE_SUSPENDED);
#ifdef ESP_PLATFORM
        /* The statically-backed dispatcher persists between CTAP1/CTAP2 loops. */
#endif
    }
    card_locked_itf = ITF_TOTAL;
    card_locked_func = NULL;
}
extern void hid_task(void);
extern void ccid_task(void);
void usb_task(void) {
#ifdef USB_ITF_HID
    hid_task();
#endif
#ifdef ENABLE_EMULATION
    emul_task();
#else
#ifdef USB_ITF_CCID
    ccid_task();
#endif
#endif
}

int card_status(uint8_t itf) {
    if (card_locked_itf == itf) {
        if (timeout == 0) {
            return PICOKEYS_ERR_FILE_NOT_FOUND;
        }
        uint32_t m = 0x0;
#ifndef ENABLE_EMULATION
        mutex_enter_blocking(&mutex);
#endif
        bool has_m = queue_try_remove(&card_to_usb_q, &m);
#ifndef ENABLE_EMULATION
        mutex_exit(&mutex);
#endif
        //if (m != 0)
        //    printf("\n ------ M = %lu\n",m);
        if (has_m) {
            if (m == EV_EXEC_FINISHED) {
                timeout_stop();
                if (led_get_mode() == MODE_PROCESSING) {
                    led_set_mode(MODE_MOUNTED);
                }
                return PICOKEYS_OK;
            }
#ifndef ENABLE_EMULATION
            else if (m == EV_PRESS_BUTTON) {
                button_wait_start();
            }
#endif
#ifdef PICO_PLATFORM
            else if (m == EV_RESET) {
                usb_secure_reboot_now();
            }
#endif
            return PICOKEYS_ERR_FILE_NOT_FOUND;
        }
        else {
            if (timeout > 0) {
                if (timeout + timeout_counter[itf] < board_millis()) {
                    timeout = board_millis();
                    return PICOKEYS_ERR_BLOCKED;
                }
            }
        }
    }
    return PICOKEYS_ERR_FILE_NOT_FOUND;
}

#ifndef USB_ITF_CCID
#include "device/usbd_pvt.h"
/* Native standard HID; no extra class driver. */
#endif
