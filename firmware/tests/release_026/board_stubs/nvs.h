#pragma once
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"
typedef uint32_t nvs_handle_t;
#define NVS_READONLY 0
#define NVS_READWRITE 1
static inline esp_err_t nvs_open_from_partition(const char *p,const char *n,int mode,nvs_handle_t *h)
{(void)p;(void)n;(void)mode;(void)h;return -1;}
static inline esp_err_t nvs_get_blob(nvs_handle_t h,const char *key,void *data,size_t *size)
{(void)h;(void)key;(void)data;(void)size;return -1;}
static inline esp_err_t nvs_set_blob(nvs_handle_t h,const char *key,const void *data,size_t size)
{(void)h;(void)key;(void)data;(void)size;return -1;}
static inline esp_err_t nvs_commit(nvs_handle_t h){(void)h;return -1;}
static inline void nvs_close(nvs_handle_t h){(void)h;}
