#pragma once
#include "FreeRTOS.h"
#include <assert.h>
static inline TaskHandle_t xTaskCreateStaticPinnedToCore(void(*work)(void*),const char*name,unsigned bytes,void*arg,unsigned priority,StackType_t*stack,StaticTask_t*tcb,BaseType_t core){assert(priority==2&&bytes==4096);++helper_creates;return tcb;}
static inline unsigned uxTaskGetStackHighWaterMark(TaskHandle_t task){return 3000;}
static inline void vTaskDelete(TaskHandle_t task){}
static inline unsigned xPortGetCoreID(void){return 0;}
static inline unsigned xTaskGetSchedulerState(void){return taskSCHEDULER_RUNNING;}
static inline UBaseType_t uxTaskPriorityGet(TaskHandle_t task){return fake_priority;}
static inline void vTaskPrioritySet(TaskHandle_t task,UBaseType_t priority){++fake_priority_sets;fake_priority=priority;}
