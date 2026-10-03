#pragma once
#include <stddef.h>
#include "esp_err.h"
#define ESP_PARTITION_TYPE_DATA 1
#define ESP_PARTITION_SUBTYPE_DATA_NVS 2
typedef struct { unsigned type,subtype; size_t size; char label[17]; } esp_partition_t;
