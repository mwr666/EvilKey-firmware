#pragma once
#include "FreeRTOS.h"
typedef void *TaskHandle_t;
typedef enum {eRunning,eReady,eBlocked,eSuspended,eDeleted,eInvalid} eTaskState;
TickType_t xTaskGetTickCount(void);
eTaskState eTaskGetState(TaskHandle_t task);
void vTaskDelete(TaskHandle_t task);
void vTaskDelay(TickType_t ticks);
