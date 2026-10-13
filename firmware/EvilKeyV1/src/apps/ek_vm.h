/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef EVILKEY_APPS_VM_H
#define EVILKEY_APPS_VM_H

#include <stddef.h>
#include <stdint.h>
#include "wasm3/wasm3.h"
#include "ek_assets.h"
#include "evilkey_app_abi.h"
#include "ek_scene3d.h"

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
    uint16_t abi_version; /* 0 -> legacy ABI4, package-selected 4 or 5 */
    EkSceneStats (*scene3d)(void *user, const uint8_t *scene,
        unsigned x,unsigned y,unsigned width,unsigned height);
    /* Optional zero-import app_measurement export. UINT32_MAX invalidates
     * telemetry only; absence does not change legacy execution. */
    void (*measurement)(void *user,uint32_t token,uint32_t gas,uint32_t memory);
    /* Optional firmware wall-clock profiling, no guest-visible imports. */
    uint64_t (*clock)(void *user);
    void (*execution_profile)(void *user,uint32_t guest_us,uint32_t output_us);
    void (*execution_detail)(void *user,uint32_t validation_us,uint32_t draw_us,uint32_t present_us);
    /* Internal bounded profiling: rect/opaque/key/text wall-time per output. */
    void (*execution_draw)(void *user,const uint32_t groups_us[4]);
} EkVmHost;

typedef struct {
    IM3Environment environment;
    IM3Runtime runtime;
    IM3Module module;
    IM3Function init_function;
    IM3Function step_function;
    IM3Function input_function;
    IM3Function measurement_function;
    uint32_t measurement_invalid,last_call_gas,draw_profile_tick;
    uint32_t input_offset;
    uint32_t save_status;
    EkSceneStats scene_stats;
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
