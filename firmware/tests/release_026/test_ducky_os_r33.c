#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "ducky.h"

typedef struct {
    uint8_t modifiers[16];
    uint8_t keycodes[16];
    size_t count;
} keyboard_log_t;

static bool keyboard(void *context, uint8_t modifiers, const uint8_t keycodes[6])
{
    keyboard_log_t *log = (keyboard_log_t *)context;
    if (keycodes[0] != 0U) {
        assert(log->count < 16U);
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

static void expect_pass(const char *script)
{
    keyboard_log_t log = {0};
    ducky_io_t io = {
        .context = &log,
        .keyboard = keyboard,
        .delay_ms = delay_ms,
    };
    ducky_config_t config = DUCKY_CONFIG_DEFAULT();
    config.key_press_ms = 0U;
    ducky_result_t result = ducky_run(script, strlen(script), &io, &config);
    if (result.status != DUCKY_OK) {
        fprintf(stderr, "DuckyScript failed at line %zu: %s\n", result.line + 1U, result.message);
    }
    assert(result.status == DUCKY_OK);
    assert(log.count == 4U);
    assert(log.modifiers[0] == 0x02U && log.keycodes[0] == 0x13U); /* P */
    assert(log.modifiers[1] == 0x02U && log.keycodes[1] == 0x04U); /* A */
    assert(log.modifiers[2] == 0x02U && log.keycodes[2] == 0x16U); /* S */
    assert(log.modifiers[3] == 0x02U && log.keycodes[3] == 0x16U); /* S */
}

int main(void)
{
    expect_pass(
        "VAR $READY = TRUE\n"
        "DEFINE #NOT_WINDOWS 7\n"
        "$_OS = WINDOWS\n"
        "IF ($_OS == WINDOWS) THEN\n"
        "STRING PASS\n"
        "END_IF\n");

    expect_pass(
        "DEFINE #NOT_WINDOWS 7\n"
        "$_OS = #NOT_WINDOWS\n"
        "IF ($_OS == #NOT_WINDOWS) THEN\n"
        "$_OS = WINDOWS\n"
        "END_IF\n"
        "IF ($_OS == WINDOWS) THEN\n"
        "STRING PASS\n"
        "END_IF\n");

    puts("PASS: $_OS read/write and symbolic OS constants");
    return 0;
}
