/* SPDX-License-Identifier: MIT
 * Independent wire declarations for EvilKey Apps ABI v4. No firmware code.
 */
#ifndef EVILKEY_APP_ABI_H
#define EVILKEY_APP_ABI_H
#include <stdint.h>

#define EVILKEY_APP_ABI_VERSION 4u
#define EVILKEY_APP_DISPLAY_WIDTH 280u
#define EVILKEY_APP_DISPLAY_HEIGHT 456u
/* UI contract corner-exit-v1; these constants do not alter the mailbox.
 * Firmware owns the larger touch zone: no app controls inside it.
 * The smaller visual zone is background only; labels/scores may start at x=50.
 * Contacts begun elsewhere remain app-owned until every finger is up. */
#define EVILKEY_APP_UI_PROFILE 1u
#define EVILKEY_APP_SYSTEM_ZONE_X 0u
#define EVILKEY_APP_SYSTEM_ZONE_Y 0u
#define EVILKEY_APP_SYSTEM_ZONE_WIDTH 56u
#define EVILKEY_APP_SYSTEM_ZONE_HEIGHT 56u
#define EVILKEY_APP_SYSTEM_VISUAL_ZONE_WIDTH 48u
#define EVILKEY_APP_SYSTEM_VISUAL_ZONE_HEIGHT 48u
#define EVILKEY_APP_HEADER_CONTENT_X 50u
#define EVILKEY_APP_MAX_SAVE_BYTES 4096u
#define EVILKEY_APP_MAX_COMMANDS 515u
#define EVILKEY_APP_RECT 1u
#define EVILKEY_APP_PRESENT 2u
#define EVILKEY_APP_BLIT 3u
#define EVILKEY_APP_TEXT 4u
#define EVILKEY_APP_SAVE 5u
#define EVILKEY_APP_BLIT_REGION 6u
#define EVILKEY_APP_SAVE_NONE 0u
#define EVILKEY_APP_SAVE_LOADED 1u
#define EVILKEY_APP_SAVE_OK 2u
#define EVILKEY_APP_SAVE_FAILED 3u

/* Little-endian, 8 bytes each. A point is active only when included in
 * touch_count. The ID is the controller's contact ID, not an array index. */
typedef struct {
    int16_t x, y;
    uint16_t id, reserved;
} EvilKeyAppTouch;

/* app_input_ptr returns the offset of this 4160-byte mailbox. The host
 * rewrites it before app_init and every app_step. */
typedef struct {
    uint32_t abi, now_ms, touch_count, accel_valid;
    EvilKeyAppTouch touch[2];
    int32_t accel_x_mg, accel_y_mg, accel_z_mg;
    uint32_t save_status, save_size;
    uint32_t reserved[3];
    uint8_t save_data[EVILKEY_APP_MAX_SAVE_BYTES];
} EvilKeyAppInput;

/* Little-endian, 20 bytes. RECT: arg0 RGB565. PRESENT: dirty region.
 * BLIT: arg0 asset ID. TEXT: flags RGB565, width scale 1..3, arg0 guest
 * offset, arg1 ASCII length. SAVE: arg0 guest offset, arg1 byte count.
 * BLIT_REGION: x,y destination; width,height region size; arg0 asset ID;
 * arg1 = source_x | (source_y << 16). Source and destination stay in bounds. */
typedef struct {
    uint16_t kind, flags, x, y, width, height;
    uint32_t arg0, arg1;
} EvilKeyAppCommand;

/* Zero imports. All return values are unsigned offsets in Wasm memory. */
uint32_t app_input_ptr(void);
uint32_t app_init(void);
uint32_t app_step(void);

#endif
