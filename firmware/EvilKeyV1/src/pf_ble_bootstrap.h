/* SPDX-License-Identifier: AGPL-3.0-or-later */
#pragma once
#include <stdbool.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

/* The HID bootstrap owns no persistent objects on its stack. It publishes
 * readiness then suspends itself; only its owner deletes it after suspension.
 * External deletion reclaims the stack before advertising, without relying
 * on idle-task cleanup of a self-deleted task. Never delete a running task. */
static inline bool pf_ble_retire_bootstrap(TaskHandle_t task, TickType_t timeout) {
    if(!task)return false;
    const TickType_t start=xTaskGetTickCount();
    do {
        if(eTaskGetState(task)==eSuspended) {
            vTaskDelete(task);
            return true;
        }
        vTaskDelay(1);
    } while((TickType_t)(xTaskGetTickCount()-start)<timeout);
    return false;
}
