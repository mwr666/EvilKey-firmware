#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "ducky.h"

typedef struct {
    uint8_t modifiers[24];
    uint8_t keycodes[24];
    size_t count;
} keyboard_log_t;

static bool keyboard(void *context, uint8_t modifiers, const uint8_t keycodes[6])
{
    keyboard_log_t *log = (keyboard_log_t *)context;
    if (modifiers != 0U || keycodes[0] != 0U) {
        assert(log->count < 24U);
        log->modifiers[log->count] = modifiers;
        log->keycodes[log->count] = keycodes[0];
        ++log->count;
    }
    return true;
}

static void delay_ms(void *context, uint32_t milliseconds)
{
    (void)context;
    (void)milliseconds;
}

static ducky_result_t run_script(keyboard_log_t *log, const char *script)
{
    ducky_io_t io = {
        .context = log,
        .keyboard = keyboard,
        .delay_ms = delay_ms,
    };
    ducky_config_t config = DUCKY_CONFIG_DEFAULT();
    config.key_press_ms = 0U;
    return ducky_run(script, strlen(script), &io, &config);
}

static void assert_event(const keyboard_log_t *log, size_t index,
                         uint8_t modifiers, uint8_t keycode)
{
    assert(index < log->count);
    if (log->modifiers[index] != modifiers || log->keycodes[index] != keycode) {
        fprintf(stderr,
                "event %zu: expected modifiers=0x%02x key=0x%02x, got modifiers=0x%02x key=0x%02x\n",
                index, modifiers, keycode, log->modifiers[index], log->keycodes[index]);
    }
    assert(log->modifiers[index] == modifiers);
    assert(log->keycodes[index] == keycode);
}

static void expect_invalid(const char *script)
{
    keyboard_log_t log = {0};
    ducky_result_t result = run_script(&log, script);
    assert(result.status == DUCKY_PARSE_ERROR);
    assert(log.count == 0U);
}

int main(void)
{
    keyboard_log_t log = {0};
    const char *script =
        "CTRL-ALT DELETE\n"
        "CTRL-SHIFT ENTER\n"
        "ALT-F4\n"
        "CTRL-K\n"
        "ALT-F2\n"
        "CTRL-SHIFT-ENTER\n"
        "COMMAND OPTION SHIFT P\n"
        "CONTROL ALT DELETE\n"
        "-\n"
        "HOLD CTRL-SHIFT\n"
        "RELEASE CTRL-SHIFT\n"
        "INJECT_MOD CTRL-SHIFT\n"
        "LEFT_ARROW\n"
        "KPAD_2\n"
        "KPAD_PLUS\n"
        "KPAD_ENTER\n"
        "REPEAT 2 TAB\n";
    ducky_result_t result = run_script(&log, script);
    if (result.status != DUCKY_OK) {
        fprintf(stderr, "DuckyScript failed at line %zu: %s\n",
                result.line + 1U, result.message);
    }
    assert(result.status == DUCKY_OK);
    assert(log.count == 17U);
    assert_event(&log, 0U, 0x05U, 0x4cU);  /* CTRL ALT DELETE */
    assert_event(&log, 1U, 0x03U, 0x28U);  /* CTRL SHIFT ENTER */
    assert_event(&log, 2U, 0x04U, 0x3dU);  /* ALT F4 */
    assert_event(&log, 3U, 0x01U, 0x0eU);  /* CTRL K */
    assert_event(&log, 4U, 0x04U, 0x3bU);  /* ALT F2 */
    assert_event(&log, 5U, 0x03U, 0x28U);  /* CTRL SHIFT ENTER */
    assert_event(&log, 6U, 0x0eU, 0x13U);  /* COMMAND OPTION SHIFT P */
    assert_event(&log, 7U, 0x05U, 0x4cU);  /* CONTROL ALT DELETE */
    assert_event(&log, 8U, 0x00U, 0x2dU);  /* literal minus key */
    assert_event(&log, 9U, 0x03U, 0x00U);  /* HOLD CTRL SHIFT */
    assert_event(&log, 10U, 0x03U, 0x00U); /* INJECT_MOD CTRL SHIFT */
    assert_event(&log, 11U, 0x00U, 0x50U); /* LEFT_ARROW */
    assert_event(&log, 12U, 0x00U, 0x5aU); /* KPAD_2 */
    assert_event(&log, 13U, 0x00U, 0x57U); /* KPAD_PLUS */
    assert_event(&log, 14U, 0x00U, 0x58U); /* KPAD_ENTER */
    assert_event(&log, 15U, 0x00U, 0x2bU); /* inline REPEAT TAB */
    assert_event(&log, 16U, 0x00U, 0x2bU); /* inline REPEAT TAB */

    expect_invalid("CTRL--ALT DELETE\n");
    expect_invalid("CTRL-NOT_A_KEY\n");
    expect_invalid("CTRL-\n");

    puts("PASS: official space-separated chords and Hak5 hyphenated aliases");
    return 0;
}
