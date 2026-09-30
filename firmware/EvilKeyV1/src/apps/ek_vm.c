/* SPDX-License-Identifier: AGPL-3.0-or-later
 * EvilKey Apps ABI v4: zero imports, bounded input mailbox and command list.
 */
#include "ek_vm.h"
#include "wasm3/m3_env.h"
#include "wasm3/m3_function.h"
#include "wasm3/m3_config.h"
#include <stdlib.h>
#include <string.h>

#if !d_m3HasGasMetering
#error "EvilKey Apps requires Wasm3 gas metering"
#endif

static void set_error(EkVm *vm, const char *message) {
    if (!message) message = "unknown VM error";
    size_t n = strlen(message);
    if (n >= sizeof(vm->error)) n = sizeof(vm->error) - 1;
    memcpy(vm->error, message, n);
    vm->error[n] = 0;
}
static uint16_t rd16(const uint8_t *p) {
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}
static uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static int region(uint32_t x, uint32_t y, uint32_t w, uint32_t h) {
    return w && h && x < EVILKEY_APP_DISPLAY_WIDTH &&
           y < EVILKEY_APP_DISPLAY_HEIGHT &&
           w <= EVILKEY_APP_DISPLAY_WIDTH - x &&
           h <= EVILKEY_APP_DISPLAY_HEIGHT - y;
}
static int memory_region(size_t size, uint32_t offset, uint32_t length) {
    return offset <= size && length <= size - offset;
}
static int add_pixels(EkVm *vm, uint32_t *total, uint32_t amount) {
    if (amount > EK_VM_MAX_PIXELS_PER_CALL - *total) {
        set_error(vm, "EvilKey pixel quota exceeded");
        return 0;
    }
    *total += amount;
    return 1;
}

static int apply_output(EkVm *vm, uint32_t offset) {
    size_t memory_size = 0;
    const uint8_t *memory = m3_GetMemory(vm->module, &memory_size, 0);
    if (!memory || !memory_region(memory_size, offset, 4)) {
        set_error(vm, "app output pointer out of bounds"); return 0;
    }
    const uint8_t *output = memory + offset;
    uint32_t count = rd32(output);
    if (count > EVILKEY_APP_MAX_COMMANDS ||
        count > (memory_size - offset - 4) / sizeof(EvilKeyAppCommand)) {
        set_error(vm, "app output length out of bounds"); return 0;
    }
    uint32_t draws = 0, pixels = 0, presents = 0, saves = 0;
    for (uint32_t i = 0; i < count; ++i) {
        const uint8_t *c = output + 4 + i * sizeof(EvilKeyAppCommand);
        uint16_t kind = rd16(c), flags = rd16(c + 2);
        uint32_t x = rd16(c + 4), y = rd16(c + 6);
        uint32_t w = rd16(c + 8), h = rd16(c + 10);
        uint32_t arg0 = rd32(c + 12), arg1 = rd32(c + 16);
        if (kind == EVILKEY_APP_RECT) {
            if (flags || arg0 > 0xffff || arg1 || !region(x,y,w,h) ||
                ++draws > EK_VM_MAX_DRAWS_PER_CALL ||
                !add_pixels(vm,&pixels,w*h)) goto invalid;
        } else if (kind == EVILKEY_APP_PRESENT) {
            if (flags || arg0 || arg1 || !region(x,y,w,h) || ++presents > 2)
                goto invalid;
        } else if (kind == EVILKEY_APP_BLIT) {
            const EkAsset *asset = ek_assets_find(vm->host.assets,(uint16_t)arg0);
            if (flags || w || h || !arg0 || arg0 > 0xffff || arg1 || !asset ||
                !region(x,y,asset->width,asset->height) ||
                ++draws > EK_VM_MAX_DRAWS_PER_CALL ||
                !add_pixels(vm,&pixels,(uint32_t)asset->width*asset->height))
                goto invalid;
        } else if (kind == EVILKEY_APP_BLIT_REGION) {
            const EkAsset *asset = arg0 && arg0 <= 0xffff ?
                ek_assets_find(vm->host.assets,(uint16_t)arg0) : NULL;
            uint32_t sx = arg1 & 0xffffu, sy = arg1 >> 16;
            if (flags || !asset || !vm->host.blit_region ||
                !region(x,y,w,h) || sx > asset->width || sy > asset->height ||
                w > asset->width - sx || h > asset->height - sy ||
                ++draws > EK_VM_MAX_DRAWS_PER_CALL ||
                !add_pixels(vm,&pixels,w*h)) goto invalid;
        } else if (kind == EVILKEY_APP_TEXT) {
            if (h || w < 1 || w > 3 || arg1 < 1 || arg1 > 64 ||
                !memory_region(memory_size,arg0,arg1) ||
                !region(x,y,arg1*6*w,8*w) ||
                ++draws > EK_VM_MAX_DRAWS_PER_CALL ||
                !add_pixels(vm,&pixels,arg1*6*w*8*w)) goto invalid;
            for (uint32_t j = 0; j < arg1; ++j)
                if (memory[arg0+j] < 0x20 || memory[arg0+j] > 0x7e) goto invalid;
        } else if (kind == EVILKEY_APP_SAVE) {
            if (flags || x || y || w || h || arg1 > EVILKEY_APP_MAX_SAVE_BYTES ||
                !memory_region(memory_size,arg0,arg1) || ++saves > 1)
                goto invalid;
        } else goto invalid;
        continue;
invalid:
        if (!vm->error[0]) set_error(vm, "invalid EvilKey app command");
        return 0;
    }
    /* Nothing reaches display or SD until the full list has passed. */
    for (uint32_t i = 0; i < count; ++i) {
        const uint8_t *c = output + 4 + i * sizeof(EvilKeyAppCommand);
        uint16_t kind = rd16(c);
        uint32_t x = rd16(c + 4), y = rd16(c + 6);
        uint32_t w = rd16(c + 8), h = rd16(c + 10);
        uint32_t arg0 = rd32(c + 12), arg1 = rd32(c + 16);
        if (kind == EVILKEY_APP_RECT)
            vm->host.rect(vm->host.user,x,y,w,h,(uint16_t)arg0);
        else if (kind == EVILKEY_APP_PRESENT)
            vm->host.present(vm->host.user,x,y,w,h);
        else if (kind == EVILKEY_APP_BLIT)
            vm->host.blit(vm->host.user,x,y,
                          ek_assets_find(vm->host.assets,(uint16_t)arg0));
        else if (kind == EVILKEY_APP_BLIT_REGION)
            vm->host.blit_region(vm->host.user,x,y,arg1&0xffffu,arg1>>16,w,h,
                                 ek_assets_find(vm->host.assets,(uint16_t)arg0));
        else if (kind == EVILKEY_APP_TEXT)
            vm->host.text(vm->host.user,x,y,w,rd16(c+2),memory+arg0,arg1);
        else {
            vm->save_status = vm->host.save(vm->host.user,memory+arg0,arg1)
                ? EVILKEY_APP_SAVE_OK : EVILKEY_APP_SAVE_FAILED;
        }
    }
    return 1;
}

static int allowed_imports(IM3Module module) {
    if (module->startFunction != -1 || module->numMemories != 1 ||
        module->numTables > 1) return 0;
    for (uint32_t i = 0; i < module->numMemories; ++i)
        if (module->memories[i]->imported) return 0;
    for (uint32_t i = 0; i < module->numTables; ++i)
        if (module->tables[i]->imported) return 0;
    for (uint32_t i = 0; i < module->numGlobals; ++i)
        if (module->globals[i].imported) return 0;
    return module->numFuncImports == 0;
}
static int signature_ok(IM3Function function) {
    return function && m3_GetArgCount(function) == 0 &&
           m3_GetRetCount(function) == 1 &&
           m3_GetRetType(function,0) == c_m3Type_i32;
}
static int call_u32(EkVm *vm, IM3Function function, uint32_t *out) {
    M3Result result = m3_SetResourceLimit(vm->runtime,c_m3Limit_GasUnits,
                                          EK_VM_GAS_PER_CALL);
    if (!result) result = m3_Call(function,0,NULL);
    if (!result) {
        const void *returns[] = {out};
        result = m3_GetResults(function,1,returns);
    }
    if (result) { set_error(vm,result); return 0; }
    return 1;
}

int ek_vm_open(EkVm *vm, const uint8_t *bytes, size_t size, EkVmHost host) {
    if (!vm) return 0;
    memset(vm,0,sizeof(*vm));
    vm->host = host;
    if (!bytes || size < 8 || size > EK_VM_MAX_WASM || !host.rect ||
        !host.present || !host.blit || !host.text || !host.save) {
        set_error(vm,"invalid EvilKey app input"); return 0;
    }
    vm->bytes = (uint8_t *)malloc(size);
    if (!vm->bytes) { set_error(vm,"bytecode allocation failed"); return 0; }
    memcpy(vm->bytes,bytes,size);
    vm->environment = m3_NewEnvironment();
    if (!vm->environment) { set_error(vm,"Wasm3 environment allocation failed"); goto fail; }
    vm->runtime = m3_NewRuntime(vm->environment,8192,vm);
    if (!vm->runtime) { set_error(vm,"Wasm3 runtime allocation failed"); goto fail; }
    M3Result result = m3_SetResourceLimit(vm->runtime,c_m3Limit_MemoryBytes,EK_VM_MAX_MEMORY);
    if (result) { set_error(vm,result); goto fail; }
    result = m3_SetResourceLimit(vm->runtime,c_m3Limit_TableElements,16);
    if (result) { set_error(vm,result); goto fail; }
    result = m3_SetResourceLimit(vm->runtime,c_m3Limit_GasUnits,EK_VM_GAS_PER_CALL);
    if (result) { set_error(vm,result); goto fail; }
    result = m3_ParseModule(vm->environment,&vm->module,vm->bytes,(uint32_t)size);
    if (result) { set_error(vm,result); goto fail; }
    if (!allowed_imports(vm->module)) {
        set_error(vm,"forbidden Wasm import or module feature"); goto fail;
    }
    IM3Module parsed = vm->module;
    vm->module = NULL; /* m3_LoadModule owns it even on failure. */
    result = m3_LoadModule(vm->runtime,parsed);
    if (result) { set_error(vm,result); goto fail; }
    vm->module = parsed;
    result = m3_CompileModule(vm->module);
    if (result) { set_error(vm,result); goto fail; }
    result = m3_FindFunctionIn(&vm->input_function,vm->module,"app_input_ptr");
    if (result || !signature_ok(vm->input_function)) {
        set_error(vm,"app_input_ptr must have signature i()"); goto fail;
    }
    result = m3_FindFunctionIn(&vm->init_function,vm->module,"app_init");
    if (result || !signature_ok(vm->init_function)) {
        set_error(vm,"app_init must have signature i()"); goto fail;
    }
    result = m3_FindFunctionIn(&vm->step_function,vm->module,"app_step");
    if (result || !signature_ok(vm->step_function)) {
        set_error(vm,"app_step must have signature i()"); goto fail;
    }
    if (!call_u32(vm,vm->input_function,&vm->input_offset)) goto fail;
    size_t memory_size = 0;
    uint8_t *memory = m3_GetMemory(vm->module,&memory_size,0);
    if (!memory || !memory_region(memory_size,vm->input_offset,
                                  sizeof(EvilKeyAppInput))) {
        set_error(vm,"app input pointer out of bounds"); goto fail;
    }
    return 1;
fail:
    {
        char error[sizeof(vm->error)];
        memcpy(error,vm->error,sizeof(error));
        ek_vm_close(vm);
        memcpy(vm->error,error,sizeof(error));
    }
    return 0;
}

static int deliver_input(EkVm *vm, const EvilKeyAppInput *input) {
    if (!vm || !vm->module || !input || input->touch_count > 2 ||
        input->save_size > EVILKEY_APP_MAX_SAVE_BYTES) return 0;
    size_t memory_size = 0;
    uint8_t *memory = m3_GetMemory(vm->module,&memory_size,0);
    if (!memory || !memory_region(memory_size,vm->input_offset,
                                  sizeof(EvilKeyAppInput))) {
        set_error(vm,"app input pointer out of bounds"); return 0;
    }
    EvilKeyAppInput copy = *input;
    copy.abi = EVILKEY_APP_ABI_VERSION;
    if (vm->save_status != EVILKEY_APP_SAVE_NONE) {
        copy.save_status = vm->save_status;
        copy.save_size = 0;
        memset(copy.save_data,0,sizeof(copy.save_data));
        vm->save_status = EVILKEY_APP_SAVE_NONE;
    }
    memcpy(memory+vm->input_offset,&copy,sizeof(copy));
    return 1;
}
int ek_vm_init(EkVm *vm, const EvilKeyAppInput *input) {
    uint32_t output;
    return deliver_input(vm,input) &&
           call_u32(vm,vm->init_function,&output) && apply_output(vm,output);
}
int ek_vm_step(EkVm *vm, const EvilKeyAppInput *input) {
    uint32_t output;
    return deliver_input(vm,input) &&
           call_u32(vm,vm->step_function,&output) && apply_output(vm,output);
}
void ek_vm_close(EkVm *vm) {
    if (!vm) return;
    if (vm->module && !vm->runtime) m3_FreeModule(vm->module);
    if (vm->runtime) m3_FreeRuntime(vm->runtime);
    if (vm->environment) m3_FreeEnvironment(vm->environment);
    free(vm->bytes);
    memset(vm,0,sizeof(*vm));
}
const char *ek_vm_error(const EkVm *vm) {
    return vm ? vm->error : "missing VM";
}
