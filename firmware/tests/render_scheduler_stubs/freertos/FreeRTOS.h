#pragma once
#include <stdint.h>
#include <stddef.h>
typedef unsigned UBaseType_t;typedef int BaseType_t;typedef uint32_t StackType_t;
typedef struct{uint8_t bytes[80];}StaticTask_t;
typedef struct{uint8_t bytes[80];}StaticSemaphore_t;
typedef void *SemaphoreHandle_t;typedef void *TaskHandle_t;
#define pdTRUE 1
#define portMAX_DELAY 0xffffffffu
#define taskSCHEDULER_RUNNING 2
extern unsigned fake_priority,fake_inherit,helper_creates;
extern unsigned fake_priority_sets;
