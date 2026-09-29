/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Restrictive EvilKey Apps ABI v3. The guest has no imports. It returns an
 * offset into its own linear memory containing a bounded drawing command list.
 */
#include "ek_vm.h"
#include "wasm3/m3_env.h"
#include "wasm3/m3_function.h"
#include "wasm3/m3_config.h"
#include <stdlib.h>
#include <string.h>

#if !d_m3HasGasMetering
#error "EvilKey Apps requires Wasm3 gas metering on every target"
#endif

static void set_error(EkVm *vm, const char *message) {
    if (!message) message = "unknown VM error";
    size_t n = strlen(message);
    if (n >= sizeof(vm->error)) n = sizeof(vm->error) - 1;
    memcpy(vm->error, message, n);
    vm->error[n] = 0;
}

static uint16_t read16(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t read32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

enum { EK_VM_COMMAND_BYTES = 12, EK_VM_MAX_COMMANDS = EK_VM_MAX_RECTS_PER_CALL + 2 };

static int apply_output(EkVm *vm, uint32_t offset) {
    size_t memory_size = 0;
    const uint8_t *memory = m3_GetMemory(vm->module, &memory_size, 0);
    if (!memory || offset > memory_size || memory_size - offset < 4) {
        set_error(vm, "app output pointer out of bounds");
        return 0;
    }
    const uint8_t *output = memory + offset;
    uint32_t count = read32(output);
    if (count > EK_VM_MAX_COMMANDS ||
        count > (memory_size - offset - 4) / EK_VM_COMMAND_BYTES) {
        set_error(vm, "app output length out of bounds");
        return 0;
    }
    uint32_t rects = 0, pixels = 0, presents = 0;
    for (uint32_t i = 0; i < count; ++i) {
        const uint8_t *command = output + 4 + i * EK_VM_COMMAND_BYTES;
        uint16_t kind = read16(command);
        if (kind == 1) {
            uint32_t x = read16(command + 2), y = read16(command + 4);
            uint32_t width = read16(command + 6), height = read16(command + 8);
            if (++rects > EK_VM_MAX_RECTS_PER_CALL) {
                set_error(vm, "EvilKey draw quota exceeded"); return 0;
            }
            if (!width || !height || x >= 280 || y >= 456 ||
                width > 280 - x || height > 456 - y) {
                set_error(vm, "EvilKey rectangle out of bounds"); return 0;
            }
            uint32_t area = width * height;
            if (area > EK_VM_MAX_PIXELS_PER_CALL - pixels) {
                set_error(vm, "EvilKey pixel quota exceeded"); return 0;
            }
            pixels += area;
        } else if (kind == 2) {
            if (++presents > 2 ||
                read16(command + 2) || read16(command + 4) ||
                read16(command + 6) || read16(command + 8) ||
                read16(command + 10)) {
                set_error(vm, "invalid EvilKey present command"); return 0;
            }
        } else {
            set_error(vm, "invalid EvilKey drawing command"); return 0;
        }
    }
    /* Validate the entire guest-owned buffer before touching the display. */
    for (uint32_t i = 0; i < count; ++i) {
        const uint8_t *command = output + 4 + i * EK_VM_COMMAND_BYTES;
        if (read16(command) == 1)
            vm->host.rect(vm->host.user, read16(command + 2), read16(command + 4),
                          read16(command + 6), read16(command + 8),
                          read16(command + 10));
        else vm->host.present(vm->host.user);
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

static int signature_ok(IM3Function function, uint32_t args) {
    if (!function || m3_GetArgCount(function) != args ||
        m3_GetRetCount(function) != 1 ||
        m3_GetRetType(function, 0) != c_m3Type_i32) return 0;
    for (uint32_t i = 0; i < args; ++i)
        if (m3_GetArgType(function, i) != c_m3Type_i32) return 0;
    return 1;
}

int ek_vm_open(EkVm *vm, const uint8_t *bytes, size_t size, EkVmHost host) {
    if (!vm) return 0;
    memset(vm, 0, sizeof(*vm));
    vm->host = host;
    if (!bytes || size < 8 || size > EK_VM_MAX_WASM ||
        !host.rect || !host.present) {
        set_error(vm, "invalid EvilKey app input");
        return 0;
    }
    vm->bytes = (uint8_t *)malloc(size);
    if (!vm->bytes) { set_error(vm, "bytecode allocation failed"); return 0; }
    memcpy(vm->bytes, bytes, size);
    vm->environment = m3_NewEnvironment();
    if (!vm->environment) { set_error(vm, "Wasm3 environment allocation failed"); goto fail; }
    vm->runtime = m3_NewRuntime(vm->environment, 8192, vm);
    if (!vm->runtime) { set_error(vm, "Wasm3 runtime allocation failed"); goto fail; }
    M3Result result = m3_SetResourceLimit(vm->runtime, c_m3Limit_MemoryBytes,
                                          EK_VM_MAX_MEMORY);
    if (result) { set_error(vm, result); goto fail; }
    result = m3_SetResourceLimit(vm->runtime, c_m3Limit_TableElements, 16);
    if (result) { set_error(vm, result); goto fail; }
    /* This must precede compilation; otherwise already compiled code is unmetered. */
    result = m3_SetResourceLimit(vm->runtime, c_m3Limit_GasUnits,
                                 EK_VM_GAS_PER_CALL);
    if (result) { set_error(vm, result); goto fail; }
    result = m3_ParseModule(vm->environment, &vm->module, vm->bytes,
                            (uint32_t)size);
    if (result) { set_error(vm, result); goto fail; }
    if (!allowed_imports(vm->module)) {
        set_error(vm, "forbidden Wasm import or module feature");
        goto fail;
    }
    IM3Module parsed = vm->module;
    vm->module = NULL; /* m3_LoadModule takes ownership even if it fails. */
    result = m3_LoadModule(vm->runtime, parsed);
    if (result) { set_error(vm, result); goto fail; }
    vm->module = parsed; /* borrowed from runtime until ek_vm_close */
    result = m3_CompileModule(vm->module);
    if (result) { set_error(vm, result); goto fail; }
    result = m3_FindFunctionIn(&vm->init_function, vm->module, "app_init");
    if (result || !signature_ok(vm->init_function, 0)) {
        set_error(vm, "app_init must have signature i()"); goto fail;
    }
    result = m3_FindFunctionIn(&vm->step_function, vm->module, "app_step");
    if (result || !signature_ok(vm->step_function, 4)) {
        set_error(vm, "app_step must have signature i(iiii)"); goto fail;
    }
    return 1;
fail:
    /* Keep error text after releasing resources. */
    {
        char error[sizeof(vm->error)];
        memcpy(error, vm->error, sizeof(error));
        ek_vm_close(vm);
        memcpy(vm->error, error, sizeof(error));
    }
    return 0;
}

static int call_with_budget(EkVm *vm, IM3Function function, uint32_t argc,
                            const void *args[]) {
    if (!vm || !vm->runtime || !function) return 0;
    M3Result result = m3_SetResourceLimit(vm->runtime, c_m3Limit_GasUnits,
                                           EK_VM_GAS_PER_CALL);
    if (!result) result = m3_Call(function, argc, args);
    if (result) { set_error(vm, result); return 0; }
    uint32_t offset = 0;
    const void *returns[] = { &offset };
    result = m3_GetResults(function, 1, returns);
    if (result) { set_error(vm, result); return 0; }
    return apply_output(vm, offset);
}

int ek_vm_init(EkVm *vm) {
    return call_with_budget(vm, vm ? vm->init_function : NULL, 0, NULL);
}

int ek_vm_step(EkVm *vm, uint32_t now_ms, int32_t x, int32_t y, uint32_t down) {
    if (!vm) return 0;
    if (!down || x < 0 || x >= 280 || y < 0 || y >= 456) {
        x = -1; y = -1; down = 0;
    } else {
        down = 1;
    }
    const void *args[] = { &now_ms, &x, &y, &down };
    return call_with_budget(vm, vm->step_function, 4, args);
}

void ek_vm_close(EkVm *vm) {
    if (!vm) return;
    if (vm->module && !vm->runtime) m3_FreeModule(vm->module);
    if (vm->runtime) m3_FreeRuntime(vm->runtime);
    if (vm->environment) m3_FreeEnvironment(vm->environment);
    free(vm->bytes);
    memset(vm, 0, sizeof(*vm));
}

const char *ek_vm_error(const EkVm *vm) {
    return vm ? vm->error : "missing VM";
}
