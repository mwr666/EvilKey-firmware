#include "esp_partition.h"
#include <cassert>
#include <cstdio>
#include <cstring>
extern "C" esp_err_t __wrap_nvs_flash_erase(void);
extern "C" esp_err_t __wrap_nvs_flash_erase_partition(const char *);
extern "C" esp_err_t __wrap_esp_partition_erase_range(const esp_partition_t *,size_t,size_t);
static unsigned calls;
extern "C" esp_err_t __real_esp_partition_erase_range(const esp_partition_t *,size_t,size_t){++calls;return ESP_OK;}
int main() {
    assert(__wrap_nvs_flash_erase()==ESP_ERR_INVALID_STATE);
    assert(__wrap_nvs_flash_erase_partition("wsdev")==ESP_ERR_INVALID_STATE);
    const esp_partition_t stores[]={{1,2,0x5000,"nvs"},{1,2,0x10000,"wsdev"},{0x40,1,0x100000,"part0"}};
    for(const auto &p:stores) {
        assert(__wrap_esp_partition_erase_range(&p,0,p.size)==ESP_ERR_INVALID_STATE);
        assert(calls==0);
        assert(__wrap_esp_partition_erase_range(&p,0,p.size+1)==ESP_ERR_INVALID_ARG);
        assert(calls==0);
    }
    assert(__wrap_esp_partition_erase_range(nullptr,0,0x1000)==ESP_ERR_INVALID_ARG);
    assert(__wrap_esp_partition_erase_range(&stores[1],0x2000,0x1000)==ESP_OK && calls==1);
    puts("PASS: NVS initialization/whole-partition recovery erase denied; ordinary page GC can proceed");
}
