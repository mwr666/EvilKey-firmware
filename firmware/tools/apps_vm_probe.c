/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "../EvilKeyV1/src/apps/ek_vm.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { unsigned rects, frames; int32_t last_x, last_y; } Screen;

static void draw(void *ctx, int32_t x, int32_t y, int32_t w, int32_t h,
                 uint16_t color) {
    Screen *screen = (Screen *)ctx;
    (void)w; (void)h; (void)color;
    ++screen->rects;
    screen->last_x = x;
    screen->last_y = y;
}
static void present(void *ctx) { ++((Screen *)ctx)->frames; }

static uint8_t *read_file(const char *name, size_t *size) {
    FILE *f = fopen(name, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long length = ftell(f);
    if (length < 0 || length > EK_VM_MAX_WASM || fseek(f, 0, SEEK_SET) != 0) {
        fclose(f); return NULL;
    }
    uint8_t *p = (uint8_t *)malloc((size_t)length);
    if (!p || fread(p, 1, (size_t)length, f) != (size_t)length) {
        free(p); fclose(f); return NULL;
    }
    fclose(f);
    *size = (size_t)length;
    return p;
}

int main(int argc, char **argv) {
    if (argc != 10) {
        fprintf(stderr, "usage: apps_vm_probe valid.wasm loop.wasm forbidden.wasm overmemory.wasm pixel_bomb.wasm recursion.wasm legacy_abi.wasm bad_pointer.wasm bad_command.wasm\n");
        return 2;
    }
    Screen screen = {0};
    EkVmHost host = {&screen, draw, present};
    EkVm vm;
    size_t size;
    uint8_t *bytes = read_file(argv[1], &size);
    if (!bytes || !ek_vm_open(&vm, bytes, size, host)) {
        fprintf(stderr, "Synthetic guest load failed: %s\n", ek_vm_error(&vm));
        free(bytes); return 1;
    }
    free(bytes);
    uint64_t linear_bytes = m3_GetResourceUsage(vm.runtime, c_m3Limit_MemoryBytes);
    if (linear_bytes == 0 || linear_bytes > EK_VM_MAX_MEMORY) {
        fprintf(stderr, "Synthetic guest exceeded memory budget: %llu bytes\n",
                (unsigned long long)linear_bytes);
        ek_vm_close(&vm); return 1;
    }
    if (!ek_vm_init(&vm)) {
        fprintf(stderr, "Synthetic guest init failed: %s\n", ek_vm_error(&vm));
        ek_vm_close(&vm);
        return 1;
    }
    if (!ek_vm_step(&vm, 0, 31, 42, 1) ||
        screen.frames != 1 || screen.rects != 1 ||
        screen.last_x != 31 || screen.last_y != 42) {
        fprintf(stderr, "Touch coordinates or drawing command failed: %s\n",
                ek_vm_error(&vm));
        ek_vm_close(&vm); return 1;
    }
    if (!ek_vm_step(&vm, 33, -1, -1, 0) ||
        screen.frames != 2 || screen.rects != 2 ||
        screen.last_x != 0 || screen.last_y != 0) {
        fprintf(stderr, "Touch release or presentation failed: %s\n",
                ek_vm_error(&vm));
        ek_vm_close(&vm); return 1;
    }
    printf("Synthetic ABI v3 guest: touch, release and drawing verified\n");
    ek_vm_close(&vm);

    bytes = read_file(argv[2], &size);
    if (!bytes || !ek_vm_open(&vm, bytes, size, host)) {
        fprintf(stderr, "Loop load failed: %s\n", ek_vm_error(&vm));
        free(bytes); return 1;
    }
    free(bytes);
    if (!ek_vm_init(&vm) || ek_vm_step(&vm, 0, -1, -1, 0) ||
        strstr(ek_vm_error(&vm), "gas") == NULL) {
        fprintf(stderr, "Infinite loop was not stopped by gas: %s\n", ek_vm_error(&vm));
        return 1;
    }
    printf("Loop: stopped by gas budget\n");
    ek_vm_close(&vm);

    bytes = read_file(argv[3], &size);
    if (!bytes) return 1;
    if (ek_vm_open(&vm, bytes, size, host) ||
        strstr(ek_vm_error(&vm), "forbidden") == NULL) {
        fprintf(stderr, "Forbidden import was accepted: %s\n", ek_vm_error(&vm));
        free(bytes); return 1;
    }
    free(bytes);
    printf("Zero-import ABI: forbidden host import rejected\n");

    bytes = read_file(argv[4], &size);
    if (!bytes) return 1;
    if (ek_vm_open(&vm, bytes, size, host)) {
        fprintf(stderr, "Oversized linear memory was accepted\n");
        ek_vm_close(&vm); free(bytes); return 1;
    }
    free(bytes);
    printf("Memory cap: oversized linear memory rejected (%s)\n", ek_vm_error(&vm));
    bytes = read_file(argv[5], &size);
    if (!bytes || !ek_vm_open(&vm, bytes, size, host)) {
        free(bytes);return 1;
    }
    free(bytes);
    if (!ek_vm_init(&vm) || ek_vm_step(&vm, 0, -1, -1, 0) ||
        strstr(ek_vm_error(&vm), "pixel quota") == NULL) {
        fprintf(stderr,"Pixel flood was not stopped: %s\n",ek_vm_error(&vm));
        ek_vm_close(&vm);return 1;
    }
    printf("Display quota: pixel flood rejected\n");
    ek_vm_close(&vm);
    bytes = read_file(argv[6], &size);
    if (!bytes || !ek_vm_open(&vm, bytes, size, host)) {
        free(bytes); return 1;
    }
    free(bytes);
    if (!ek_vm_init(&vm) || ek_vm_step(&vm, 0, -1, -1, 0) ||
        strstr(ek_vm_error(&vm), "stack") == NULL) {
        fprintf(stderr, "Recursive guest was not bounded: %s\n", ek_vm_error(&vm));
        ek_vm_close(&vm); return 1;
    }
    printf("Recursion: stack overflow trapped (%s)\n", ek_vm_error(&vm));
    ek_vm_close(&vm);
    bytes = read_file(argv[7], &size);
    if (!bytes) return 1;
    if (ek_vm_open(&vm, bytes, size, host) ||
        strstr(ek_vm_error(&vm), "i(iiii)") == NULL) {
        fprintf(stderr, "Legacy void-return ABI guest was accepted: %s\n", ek_vm_error(&vm));
        ek_vm_close(&vm); free(bytes); return 1;
    }
    free(bytes);
    printf("Legacy void-return ABI: rejected\n");
    bytes = read_file(argv[8], &size);
    if (!bytes || !ek_vm_open(&vm, bytes, size, host)) {
        free(bytes); return 1;
    }
    free(bytes);
    if (!ek_vm_init(&vm) || ek_vm_step(&vm, 0, -1, -1, 0) ||
        strstr(ek_vm_error(&vm), "pointer out of bounds") == NULL) {
        fprintf(stderr, "Invalid output pointer was accepted: %s\n", ek_vm_error(&vm));
        ek_vm_close(&vm); return 1;
    }
    ek_vm_close(&vm);
    bytes = read_file(argv[9], &size);
    if (!bytes || !ek_vm_open(&vm, bytes, size, host)) {
        free(bytes); return 1;
    }
    free(bytes);
    unsigned before_rects = screen.rects, before_frames = screen.frames;
    if (!ek_vm_init(&vm) || ek_vm_step(&vm, 0, -1, -1, 0) ||
        strstr(ek_vm_error(&vm), "drawing command") == NULL ||
        screen.rects != before_rects || screen.frames != before_frames) {
        fprintf(stderr, "Invalid drawing command affected display: %s\n",
                ek_vm_error(&vm));
        ek_vm_close(&vm); return 1;
    }
    ek_vm_close(&vm);
    printf("Output bounds and command validation: invalid guest data rejected\n");
    return 0;
}
