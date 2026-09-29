/* SPDX-License-Identifier: MIT
 * Independently authored declarations for the EvilKey Apps ABI v3.
 */
#ifndef EVILKEY_APP_ABI_H
#define EVILKEY_APP_ABI_H
#include <stdint.h>

#define EVILKEY_APP_ABI_VERSION 3u
#define EVILKEY_APP_DISPLAY_WIDTH 280u
#define EVILKEY_APP_DISPLAY_HEIGHT 456u
#define EVILKEY_APP_MAX_COMMANDS 514u
#define EVILKEY_APP_COMMAND_RECT 1u
#define EVILKEY_APP_COMMAND_PRESENT 2u

/* Wire records are little-endian and exactly 12 bytes. Do not pass host
 * pointers or native structures across the Wasm/firmware boundary. */
typedef struct {
    uint16_t kind, x, y, width, height, rgb565;
} EvilKeyAppCommand;

/* Required Wasm exports. Each return value is a byte offset in guest memory
 * to a u32 command count followed by that many EvilKeyAppCommand records. */
uint32_t app_init(void);
uint32_t app_step(int32_t now_ms, int32_t x, int32_t y, int32_t down);

#endif
