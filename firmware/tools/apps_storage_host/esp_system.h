#pragma once
enum esp_reset_reason_t {ESP_RST_POWERON=1,ESP_RST_PANIC,ESP_RST_INT_WDT,ESP_RST_TASK_WDT,ESP_RST_WDT,ESP_RST_BROWNOUT};
static inline esp_reset_reason_t esp_reset_reason(void){return ESP_RST_POWERON;}
