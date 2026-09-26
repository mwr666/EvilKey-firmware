#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    DUCKY_OK = 0,
    DUCKY_INVALID_ARGUMENT,
    DUCKY_OUT_OF_MEMORY,
    DUCKY_PARSE_ERROR,
    DUCKY_UNSUPPORTED,
    DUCKY_IO_ERROR,
    DUCKY_LIMIT_EXCEEDED,
    DUCKY_STOPPED,
} ducky_status_t;

typedef struct {
    ducky_status_t status;
    size_t line;
    char message[128];
} ducky_result_t;


enum {
    DUCKY_LED_OPT_SYSTEM = 1U << 0,
    DUCKY_LED_OPT_STORAGE = 1U << 1,
    DUCKY_LED_OPT_CONTINUOUS_STORAGE = 1U << 2,
    DUCKY_LED_OPT_INJECTING = 1U << 3,
    DUCKY_LED_OPT_EXFIL = 1U << 4,
    DUCKY_LED_OPT_SHOW_CAPS = 1U << 5,
    DUCKY_LED_OPT_SHOW_NUM = 1U << 6,
    DUCKY_LED_OPT_SHOW_SCROLL = 1U << 7,
};

enum {
    DUCKY_CAP_VARIABLE_EXFIL = 1U << 0,
    DUCKY_CAP_KEYSTROKE_REFLECTION = 1U << 1,
    DUCKY_CAP_PAYLOAD_HIDING = 1U << 2,
};

typedef struct {
    uint8_t mode;
    uint16_t vid;
    uint16_t pid;
    char manufacturer[33];
    char product[33];
    char serial[13];
    bool custom_identity;
} ducky_attackmode_t;

typedef struct {
    void *context;
    bool (*keyboard)(void *context, uint8_t modifiers, const uint8_t keycodes[6]);
    bool (*mouse)(void *context, uint8_t buttons, int8_t x, int8_t y, int8_t wheel, int8_t pan);
    bool (*absolute_mouse)(void *context, uint8_t buttons, int16_t x, int16_t y, int8_t wheel, int8_t pan);
    bool (*consumer)(void *context, uint16_t usage);
    bool (*system)(void *context, uint8_t usage);
    void (*delay_ms)(void *context, uint32_t milliseconds);
    bool (*wait_for_button)(void *context, uint32_t timeout_ms);
    uint8_t (*keyboard_leds)(void *context);
    /* Logical Ducky LED state. LED_ON is the green/default state. */
    void (*status_led)(void *context, uint8_t state);
    uint32_t (*random_u32)(void *context);
    void (*runtime_options)(void *context, uint8_t led_options,
                            uint16_t storage_activity_timeout_ms);
    uint32_t (*storage_activity_age_ms)(void *context);
    bool (*button_pressed)(void *context, uint16_t debounce_ms);
    bool (*attackmode)(void *context, uint8_t mode);
    bool (*attackmode_profile)(void *context, const ducky_attackmode_t *profile);
    uint8_t (*current_attackmode)(void *context);
    uint16_t (*current_vid)(void *context);
    uint16_t (*current_pid)(void *context);
    bool (*host_lock_reply_received)(void *context);
    uint16_t (*host_configuration_request_count)(void *context);
    bool (*reset_host_configuration_request_count)(void *context);
    uint16_t (*host_os_guess)(void *context);
    bool (*variable_exfil)(void *context, uint16_t value);
    bool (*set_exfil_mode)(void *context, bool enabled);
    bool (*exfil_mode_enabled)(void *context);
} ducky_io_t;

typedef struct {
    uint32_t key_press_ms;
    uint32_t button_timeout_ms;
    uint32_t lock_wait_timeout_ms;
    uint32_t max_execution_steps;
    uint16_t max_lines;
} ducky_config_t;

#define DUCKY_CONFIG_DEFAULT()                    \
    (ducky_config_t) {                            \
        .key_press_ms = 8,                        \
        .button_timeout_ms = 0,                   \
        .lock_wait_timeout_ms = 60000,            \
        .max_execution_steps = 100000,            \
        .max_lines = 8192,                        \
    }

uint32_t ducky_inspect_capabilities(const char *script, size_t script_length);

ducky_result_t ducky_run(
    const char *script,
    size_t script_length,
    const ducky_io_t *io,
    const ducky_config_t *config);

const char *ducky_status_name(ducky_status_t status);

#ifdef __cplusplus
}
#endif
