/* SPDX-License-Identifier: MIT
 * Synthetic guest for the ABI v4 host probe. No firmware source included.
 */
#include "evilkey_app_abi.h"
#include <stdint.h>

static EvilKeyAppInput input;
static struct {
    uint32_t count;
    EvilKeyAppCommand command[6];
} output;
static const char label[] = "V4";
static const uint8_t save_bytes[] = {4, 0x45, 0x4b, 0x59};

uint32_t app_input_ptr(void) { return (uint32_t)(uintptr_t)&input; }
uint32_t app_init(void) {
    output.count=2;
    output.command[0]=(EvilKeyAppCommand){EVILKEY_APP_RECT,0,0,0,280,456,0x001f,0};
    output.command[1]=(EvilKeyAppCommand){EVILKEY_APP_PRESENT,0,0,0,280,456,0,0};
    return (uint32_t)(uintptr_t)&output;
}
uint32_t app_step(void) {
    output.count=5;
    output.command[0]=(EvilKeyAppCommand){EVILKEY_APP_BLIT,0,10,10,0,0,1,0};
    output.command[1]=(EvilKeyAppCommand){EVILKEY_APP_BLIT_REGION,0,14,10,1,1,
                                         1,1u|(1u<<16)};
    output.command[2]=(EvilKeyAppCommand){EVILKEY_APP_TEXT,0xffff,30,30,2,0,
                                         (uint32_t)(uintptr_t)label,2};
    output.command[3]=(EvilKeyAppCommand){EVILKEY_APP_SAVE,0,0,0,0,0,
                                         (uint32_t)(uintptr_t)save_bytes,4};
    output.command[4]=(EvilKeyAppCommand){EVILKEY_APP_PRESENT,0,10,10,80,40,0,0};
#ifdef EVILKEY_PROBE_BAD_COMMAND
    output.command[1].arg1=2u|(1u<<16); /* source crop overflows 2x2 asset */
#endif
    return (uint32_t)(uintptr_t)&output;
}
int32_t app_probe_input(void) {
    return (int32_t)(input.touch_count == 2 && input.touch[0].id == 3 &&
        input.touch[1].id == 7 && input.accel_valid &&
        input.accel_x_mg == -250 && input.save_status == EVILKEY_APP_SAVE_NONE &&
        input.abi == EVILKEY_APP_ABI_VERSION);
}
