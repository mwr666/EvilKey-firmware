#pragma once
#include <stdio.h>
/* Type-check and consume log arguments without emitting host-test logs. */
#define ESP_LOGE(tag,...) do { (void)(tag); if (0) printf(__VA_ARGS__); } while (0)
#define ESP_LOGW(tag,...) ESP_LOGE(tag,__VA_ARGS__)
#define ESP_LOGI(tag,...) ESP_LOGE(tag,__VA_ARGS__)
