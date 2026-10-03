/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include <assert.h>
#include <stdio.h>
#include "pf_ble_bootstrap.h"
static unsigned delays,deletes,suspend_after;
static TickType_t now;
static eTaskState state;
static int task_storage;
TickType_t xTaskGetTickCount(void){return now;}
eTaskState eTaskGetState(TaskHandle_t task){assert(task==&task_storage);return state;}
void vTaskDelay(TickType_t ticks){
    assert(ticks==1);++now;++delays;
    if(suspend_after && delays==suspend_after)state=eSuspended;
}
void vTaskDelete(TaskHandle_t task){
    assert(task==&task_storage && state==eSuspended);
    ++deletes;state=eDeleted;
}
static void reset(eTaskState value,TickType_t tick,unsigned after){
    state=value;now=tick;suspend_after=after;delays=deletes=0;
}
int main(void){
    reset(eSuspended,0,0);
    assert(pf_ble_retire_bootstrap(&task_storage,10));assert(deletes==1 && delays==0);
    reset(eRunning,0,3);
    assert(pf_ble_retire_bootstrap(&task_storage,10));assert(deletes==1 && delays==3);
    reset(eBlocked,0,0);
    assert(!pf_ble_retire_bootstrap(&task_storage,5));assert(deletes==0 && delays==5);
    reset(eReady,UINT32_MAX-2,0);
    assert(!pf_ble_retire_bootstrap(&task_storage,5));assert(deletes==0 && delays==5);
    reset(eRunning,0,0);
    assert(!pf_ble_retire_bootstrap(NULL,5));assert(deletes==0 && delays==0);
    puts("PASS: Gamepad bootstrap retires only after suspension; bounded wait, tick wrap and missing handle preserve running tasks");
}
