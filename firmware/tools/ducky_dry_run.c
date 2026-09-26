#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "ducky.h"

typedef struct {
    uint8_t attackmode;
    uint8_t led_phase;
    uint16_t configuration_requests;
    uint16_t os;
    bool lock_reply;
    bool exfil_mode;
    uint32_t random_state;
    uint32_t storage_phase;
} dry_context_t;

static bool keyboard(void *context, uint8_t modifiers, const uint8_t keycodes[6])
{
    (void)context;
    (void)modifiers;
    (void)keycodes;
    return true;
}

static bool mouse(void *context, uint8_t buttons, int8_t x, int8_t y, int8_t wheel, int8_t pan)
{
    (void)context;
    (void)buttons;
    (void)x;
    (void)y;
    (void)wheel;
    (void)pan;
    return true;
}

static bool absolute_mouse(void *context, uint8_t buttons, int16_t x, int16_t y,
                           int8_t wheel, int8_t pan)
{
    (void)context;
    (void)buttons;
    (void)x;
    (void)y;
    (void)wheel;
    (void)pan;
    return true;
}

static bool consumer(void *context, uint16_t usage)
{
    (void)context;
    (void)usage;
    return true;
}

static bool system_control(void *context, uint8_t usage)
{
    (void)context;
    (void)usage;
    return usage <= 3U;
}

static void delay_ms(void *context, uint32_t milliseconds)
{
    (void)context;
    (void)milliseconds;
}

static bool wait_for_button(void *context, uint32_t timeout_ms)
{
    (void)context;
    (void)timeout_ms;
    return true;
}

static uint8_t keyboard_leds(void *context)
{
    dry_context_t *dry = (dry_context_t *)context;
    /* Alternating all lock bits lets ON, OFF and CHANGE waits make progress
     * without pretending a fixed target-host state. */
    return (++dry->led_phase & 1U) != 0U ? 0U : 0x07U;
}

static void status_led(void *context, uint8_t state)
{
    (void)context;
    (void)state;
}

static uint32_t random_u32(void *context)
{
    dry_context_t *dry = (dry_context_t *)context;
    dry->random_state = dry->random_state * 1664525U + 1013904223U;
    return dry->random_state;
}

static bool attackmode(void *context, uint8_t mode)
{
    if (mode > 3U) return false;
    ((dry_context_t *)context)->attackmode = mode;
    return true;
}

static bool attackmode_profile(void *context, const ducky_attackmode_t *profile)
{
    if (profile == NULL || profile->mode > 3U) return false;
    ((dry_context_t *)context)->attackmode = profile->mode;
    return true;
}

static uint8_t current_attackmode(void *context)
{
    return ((dry_context_t *)context)->attackmode;
}

static uint16_t current_vid(void *context)
{
    (void)context;
    return 0xfffeU;
}

static uint16_t current_pid(void *context)
{
    (void)context;
    return 0xfbfcU;
}

static bool host_lock_reply(void *context)
{
    return ((dry_context_t *)context)->lock_reply;
}

static uint16_t host_configuration_requests(void *context)
{
    return ((dry_context_t *)context)->configuration_requests;
}

static bool reset_host_configuration_requests(void *context)
{
    ((dry_context_t *)context)->configuration_requests = 0U;
    return true;
}

static uint16_t host_os_guess(void *context)
{
    return ((dry_context_t *)context)->os;
}

static bool variable_exfil(void *context,uint16_t value)
{(void)context;(void)value;return true;}

static bool set_exfil_mode(void *context,bool enabled)
{((dry_context_t *)context)->exfil_mode=enabled;return true;}

static bool exfil_mode_enabled(void *context)
{return ((dry_context_t *)context)->exfil_mode;}

static uint32_t storage_activity_age_ms(void *context)
{
    dry_context_t *dry = (dry_context_t *)context;
    return (++dry->storage_phase & 1U) != 0U ? 0U : UINT32_MAX;
}

static ducky_result_t run_scenario(const char *script, size_t length, unsigned scenario)
{
    dry_context_t dry = {
        .attackmode = 1U,
        .led_phase = (uint8_t)scenario,
        .configuration_requests = scenario == 0U ? 3U : 1U,
        .os = (uint16_t)(scenario + 1U),
        .lock_reply = scenario != 2U,
        .random_state = 0x9e3779b9U ^ scenario,
    };
    ducky_io_t io = {
        .context = &dry,
        .keyboard = keyboard,
        .mouse = mouse,
        .absolute_mouse = absolute_mouse,
        .consumer = consumer,
        .system = system_control,
        .delay_ms = delay_ms,
        .wait_for_button = wait_for_button,
        .keyboard_leds = keyboard_leds,
        .status_led = status_led,
        .random_u32 = random_u32,
        .storage_activity_age_ms = storage_activity_age_ms,
        .attackmode = attackmode,
        .attackmode_profile = attackmode_profile,
        .current_attackmode = current_attackmode,
        .current_vid = current_vid,
        .current_pid = current_pid,
        .host_lock_reply_received = host_lock_reply,
        .host_configuration_request_count = host_configuration_requests,
        .reset_host_configuration_request_count = reset_host_configuration_requests,
        .host_os_guess = host_os_guess,
        .variable_exfil = variable_exfil,
        .set_exfil_mode = set_exfil_mode,
        .exfil_mode_enabled = exfil_mode_enabled,
    };
    ducky_config_t config = DUCKY_CONFIG_DEFAULT();
    config.key_press_ms = 0U;
    config.lock_wait_timeout_ms = 20U;
    return ducky_run(script, length, &io, &config);
}

int main(void)
{
    size_t length = 0U;
    size_t capacity = 4096U;
    char *script = (char *)malloc(capacity + 1U);
    if (script == NULL) return 2;
    for (;;) {
        if (length == capacity) {
            if (capacity >= 1024U * 1024U) {
                free(script);
                fputs("input-too-large\t0\tPayload exceeds dry-run limit\n", stdout);
                return 2;
            }
            capacity *= 2U;
            char *grown = (char *)realloc(script, capacity + 1U);
            if (grown == NULL) {
                free(script);
                return 2;
            }
            script = grown;
        }
        size_t got = fread(script + length, 1U, capacity - length, stdin);
        length += got;
        if (got == 0U) break;
    }
    script[length] = '\0';

    for (unsigned scenario = 0U; scenario < 3U; ++scenario) {
        ducky_result_t result = run_scenario(script, length, scenario);
        if (result.status != DUCKY_OK && result.status != DUCKY_STOPPED) {
            printf("%s\t%zu\tscenario=%u: %s\n",
                   ducky_status_name(result.status), result.line,
                   scenario + 1U, result.message);
            free(script);
            return 10;
        }
    }
    puts("ok\t0\tthree dry-run scenarios passed");
    free(script);
    return 0;
}
