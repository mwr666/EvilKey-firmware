/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef EVILKEY_APPS_VM_H
#define EVILKEY_APPS_VM_H

#include <stddef.h>
#include <stdint.h>
#include "wasm3/wasm3.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    EK_VM_MAX_WASM = 65536,
    EK_VM_MAX_MEMORY = 2 * 1024 * 1024,
    EK_VM_GAS_PER_CALL = 6000000,
    EK_VM_MAX_RECTS_PER_CALL = 512,
    EK_VM_MAX_PIXELS_PER_CALL = 600000
};

typedef struct {
    void *user;
    void (*rect)(void *user, int32_t x, int32_t y, int32_t width,
                 int32_t height, uint16_t rgb565);
    void (*present)(void *user);
} EkVmHost;

typedef struct {
    IM3Environment environment;
    IM3Runtime runtime;
    IM3Module module;
    IM3Function init_function;
    IM3Function step_function;
    uint8_t *bytes;
    EkVmHost host;
    char error[128];
} EkVm;

/* Caller keeps vm at one address from open until close. Return 0 on failure. */
int ek_vm_open(EkVm *vm, const uint8_t *bytes, size_t size, EkVmHost host);
int ek_vm_init(EkVm *vm);
/* x/y are display pixels or -1 on release; down is 0 or 1. */
int ek_vm_step(EkVm *vm, uint32_t now_ms, int32_t x, int32_t y, uint32_t down);
void ek_vm_close(EkVm *vm);
const char *ek_vm_error(const EkVm *vm);

#ifdef __cplusplus
}
#endif
#endif
