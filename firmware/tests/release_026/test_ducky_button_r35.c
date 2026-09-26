#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "ducky.h"

typedef struct {
    unsigned polls;
    unsigned trigger_at;
    uint16_t observed_debounce;
    char text[32];
    size_t length;
} test_context_t;

static bool keyboard(void *context, uint8_t modifiers, const uint8_t keycodes[6])
{
    test_context_t *test = (test_context_t *)context;
    if (keycodes[0] >= 0x04U && keycodes[0] <= 0x1dU) {
        char value = (char)('a' + keycodes[0] - 0x04U);
        if ((modifiers & 0x22U) != 0U) value = (char)(value - 'a' + 'A');
        assert(test->length + 1U < sizeof(test->text));
        test->text[test->length++] = value;
        test->text[test->length] = '\0';
    }
    return true;
}

static void delay_ms(void *context, uint32_t milliseconds)
{
    (void)context;
    (void)milliseconds;
}

static bool button_pressed(void *context, uint16_t debounce_ms)
{
    test_context_t *test = (test_context_t *)context;
    test->observed_debounce = debounce_ms;
    ++test->polls;
    return test->polls == test->trigger_at;
}

static ducky_result_t run(const char *script, test_context_t *test)
{
    ducky_io_t io = {
        .context = test,
        .keyboard = keyboard,
        .delay_ms = delay_ms,
        .button_pressed = button_pressed,
    };
    ducky_config_t config = DUCKY_CONFIG_DEFAULT();
    config.key_press_ms = 0U;
    return ducky_run(script, strlen(script), &io, &config);
}

int main(void)
{
    test_context_t asynchronous = {.trigger_at = 4U};
    ducky_result_t result = run(
        "$_BUTTON_TIMEOUT = 37\n"
        "BUTTON_DEF\n"
        "STRING B\n"
        "END_BUTTON\n"
        "DELAY 50\n"
        "STRING A\n"
        "IF ($_BUTTON_PUSH_RECEIVED == TRUE) THEN\n"
        "STRING P\n"
        "END_IF\n",
        &asynchronous);
    assert(result.status == DUCKY_OK);
    assert(strcmp(asynchronous.text, "BAP") == 0);
    assert(asynchronous.observed_debounce == 37U);

    test_context_t waiting = {.trigger_at = 2U};
    result = run(
        "WAIT_FOR_BUTTON_PRESS\n"
        "IF ($_BUTTON_PUSH_RECEIVED == TRUE) THEN\n"
        "STRING W\n"
        "END_IF\n",
        &waiting);
    assert(result.status == DUCKY_OK);
    assert(strcmp(waiting.text, "W") == 0);
    assert(waiting.observed_debounce == 1000U);

    test_context_t default_stop = {.trigger_at = 2U};
    result = run("DELAY 50\nSTRING X\n", &default_stop);
    assert(result.status == DUCKY_STOPPED);
    assert(default_stop.length == 0U);

    puts("PASS: asynchronous BUTTON_DEF, debounce variables and default button stop");
    return 0;
}
