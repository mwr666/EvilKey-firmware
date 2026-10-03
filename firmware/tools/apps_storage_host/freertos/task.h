#pragma once
void vTaskDelay(unsigned);
unsigned uxTaskGetStackHighWaterMark(void *);
int xTaskCreate(void (*)(void *),const char *,unsigned,void *,unsigned,void *);
