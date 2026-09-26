#pragma once
#include "FreeRTOS.h"
typedef void *SemaphoreHandle_t;
SemaphoreHandle_t xSemaphoreCreateBinary(void);
BaseType_t xSemaphoreGiveFromISR(SemaphoreHandle_t,BaseType_t*);
BaseType_t xSemaphoreTake(SemaphoreHandle_t,unsigned);
