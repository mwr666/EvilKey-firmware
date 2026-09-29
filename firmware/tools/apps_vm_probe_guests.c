/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Synthetic ABI v3 guests for validating the import-free display protocol.
 */
#include <stdint.h>

#ifdef EVILKEY_PROBE_FORBIDDEN
__attribute__((import_module("env"), import_name("danger")))
extern void danger(void);
#endif

#ifdef EVILKEY_PROBE_RECURSION
__attribute__((noinline)) static uint32_t dive(uint32_t depth) {
    if (depth > 10000) return depth;
    volatile uint32_t result = dive(depth + 1);
    return result + depth;
}
#endif

static uint8_t output[4 + 7 * 12];

static void put16(uint8_t *p, uint16_t value) {
    p[0] = (uint8_t)value; p[1] = (uint8_t)(value >> 8);
}

static uint32_t output_offset(void) {
    return (uint32_t)(uintptr_t)output;
}

__attribute__((export_name("app_init"))) uint32_t app_init(void) {
    return output_offset();
}

__attribute__((export_name("app_step")))
#ifdef EVILKEY_PROBE_LEGACY_ABI
void app_step(int32_t now_ms, int32_t x, int32_t y, int32_t down) {
    (void)now_ms; (void)x; (void)y; (void)down;
}
#else
uint32_t app_step(int32_t now_ms, int32_t x, int32_t y, int32_t down) {
    (void)now_ms; (void)x; (void)y; (void)down;
#ifdef EVILKEY_PROBE_FORBIDDEN
    danger();
#elif defined(EVILKEY_PROBE_VALID)
    output[0] = 2;
    uint8_t *p = output + 4;
    put16(p, 1);
    put16(p + 2, (uint16_t)(down && x >= 0 && x <= 270 ? x : 0));
    put16(p + 4, (uint16_t)(down && y >= 0 && y <= 446 ? y : 0));
    put16(p + 6, 10);
    put16(p + 8, 10);
    put16(p + 10, 0xffff);
    put16(output + 16, 2);
#elif defined(EVILKEY_PROBE_PIXEL_BOMB)
    output[0] = 7;
    for (int i = 0; i < 6; ++i) {
        uint8_t *p = output + 4 + i * 12;
        put16(p, 1); put16(p + 2, 0); put16(p + 4, 0);
        put16(p + 6, 280); put16(p + 8, 456); put16(p + 10, 0xffff);
    }
    put16(output + 4 + 6 * 12, 2);
#elif defined(EVILKEY_PROBE_BAD_POINTER)
    return 0x7fffffffu;
#elif defined(EVILKEY_PROBE_BAD_COMMAND)
    output[0] = 1;
    put16(output + 4, 99);
#elif defined(EVILKEY_PROBE_RECURSION)
    (void)dive(0);
#else
    for (;;) __asm__ volatile ("" ::: "memory");
#endif
    return output_offset();
}
#endif
