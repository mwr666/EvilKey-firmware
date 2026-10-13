#pragma once
#include "FreeRTOS.h"
static inline SemaphoreHandle_t xSemaphoreCreateMutexStatic(StaticSemaphore_t*p){return p;}
static inline SemaphoreHandle_t xSemaphoreCreateBinaryStatic(StaticSemaphore_t*p){return p;}
static inline BaseType_t xSemaphoreTake(SemaphoreHandle_t p,unsigned ticks){if(fake_inherit&&!ticks){fake_inherit=0;fake_priority=2;return 0;}return pdTRUE;}
static inline BaseType_t xSemaphoreGive(SemaphoreHandle_t p){return pdTRUE;}
