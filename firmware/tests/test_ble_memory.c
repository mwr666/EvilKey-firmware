/* Exercise the pinned production allocator with Arduino's internal-only SDK default. */
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include "esp_heap_caps.h"
#include "nimble/esp_port/port/include/esp_nimble_mem.h"
static unsigned calls;
static int deny_psram;
void *heap_caps_malloc(size_t size, uint32_t caps) {
    assert(caps == (MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT));
    ++calls;
    return deny_psram ? NULL : malloc(size);
}
void *heap_caps_calloc(size_t n, size_t size, uint32_t caps) {
    assert(caps == (MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT));
    ++calls;
    return deny_psram ? NULL : calloc(n, size);
}
void heap_caps_free(void *ptr) { free(ptr); }
int main(void) {
    unsigned char *pool=nimble_platform_mem_calloc(24, 320);
    assert(pool);
    for(unsigned i=0;i<24*320;++i)assert(pool[i]==0);
    nimble_platform_mem_free(pool);
    pool=nimble_platform_mem_malloc(1024);assert(pool);
    nimble_platform_mem_free(pool);
    deny_psram=1;
    assert(nimble_platform_mem_malloc(256)==NULL);
    assert(nimble_platform_mem_calloc(12,256)==NULL);
    assert(calls==4); /* No silent fallback consumes controller/DMA SRAM. */
    puts("PASS: production NimBLE allocator uses PSRAM despite SDK internal default; allocation failure has no internal fallback");
    return 0;
}
