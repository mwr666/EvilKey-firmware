/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef EVILKEY_APPS_VM_H
#define EVILKEY_APPS_VM_H

#include <stddef.h>
#include <stdint.h>
#include "wasm3/wasm3.h"
#include "ek_assets.h"
#include "evilkey_app_abi.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    EK_VM_MAX_WASM = 65536,
    EK_VM_MAX_MEMORY = 2 * 1024 * 1024,
    EK_VM_GAS_PER_CALL = 6000000,
    EK_VM_MAX_DRAWS_PER_CALL = 512,
    EK_VM_MAX_PIXELS_PER_CALL = 600000
};

typedef struct {
    void *user;
    void (*rect)(void *user, int32_t x, int32_t y, int32_t width,
                 int32_t height, uint16_t rgb565);
    void (*present)(void *user, int32_t x, int32_t y, int32_t width,
                    int32_t height);
    void (*blit)(void *user, int32_t x, int32_t y, const EkAsset *asset);
    void (*text)(void *user, int32_t x, int32_t y, uint32_t scale,
                 uint16_t rgb565, const uint8_t *ascii, uint32_t length);
    int (*save)(void *user, const uint8_t *data, uint32_t length);
    const EkAssets *assets;
    void (*blit_region)(void *user, int32_t x, int32_t y,
                        uint32_t source_x, uint32_t source_y,
                        uint32_t width, uint32_t height, const EkAsset *asset);
} EkVmHost;

typedef struct {
    IM3Environment environment;
    IM3Runtime runtime;
    IM3Module module;
    IM3Function init_function;
    IM3Function step_function;
    IM3Function input_function;
    uint32_t input_offset;
    uint32_t save_status;
    uint8_t *bytes;
    EkVmHost host;
    char error[128];
} EkVm;

/* Caller keeps vm at one address from open until close. Return 0 on failure. */
int ek_vm_open(EkVm *vm, const uint8_t *bytes, size_t size, EkVmHost host);
int ek_vm_init(EkVm *vm, const EvilKeyAppInput *input);
int ek_vm_step(EkVm *vm, const EvilKeyAppInput *input);
void ek_vm_close(EkVm *vm);
const char *ek_vm_error(const EkVm *vm);

#ifdef __cplusplus
}
#endif
#endif
