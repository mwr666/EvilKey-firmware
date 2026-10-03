/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef EVILKEY_NVS_GUARD_LINKED
#error "Build with build_arduino.py/EvilKey.cmd: mandatory NVS linker guards are required"
#endif
#include "esp_err.h"
#include "esp_log.h"
#include "esp_partition.h"
#include <string.h>

extern "C" esp_err_t __real_esp_partition_erase_range(const esp_partition_t *,size_t,size_t);
extern "C" esp_err_t __wrap_esp_partition_erase_range(const esp_partition_t *p,size_t offset,size_t length) {
    if(!p || offset>p->size || length>p->size-offset)return ESP_ERR_INVALID_ARG;
    bool protected_store=(p->type==ESP_PARTITION_TYPE_DATA && p->subtype==ESP_PARTITION_SUBTYPE_DATA_NVS) ||
        strcmp(p->label,"part0")==0;
    // Arduino 3.3.12 formats failed default NVS using this generic API rather
    // than nvs_flash_erase(). Deny that path too; NVS page GC remains usable.
    if(protected_store && length==p->size) {
        ESP_LOGE("ek_nvs_guard","Whole persistent partition erase denied");
        return ESP_ERR_INVALID_STATE;
    }
    return __real_esp_partition_erase_range(p,offset,length);
}

// Linker wrappers are a second barrier against dependency recovery code.
// Normal NVS writes/garbage collection and per-key BLE bond deletion remain usable.
extern "C" esp_err_t __wrap_nvs_flash_erase(void) {
    ESP_LOGE("ek_nvs_guard", "Whole NVS erase denied");
    return ESP_ERR_INVALID_STATE;
}
extern "C" esp_err_t __wrap_nvs_flash_erase_partition(const char *) {
    ESP_LOGE("ek_nvs_guard", "Whole NVS partition erase denied");
    return ESP_ERR_INVALID_STATE;
}
