#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "ducky.h"

typedef struct {
    uint8_t modifiers[32];
    uint8_t keycodes[32];
    size_t key_count;
    uint16_t configuration_requests;
    uint16_t os_guess;
    bool lock_reply;
    bool reset_called;
} test_context_t;

static bool keyboard(void *context, uint8_t modifiers, const uint8_t keycodes[6])
{
    test_context_t *test = (test_context_t *)context;
    if (keycodes[0] != 0U) {
        assert(test->key_count < 32U);
        test->modifiers[test->key_count] = modifiers;
        test->keycodes[test->key_count] = keycodes[0];
        ++test->key_count;
    }
    return true;
}

static void delay_ms(void *context, uint32_t milliseconds)
{
    (void)context;
    (void)milliseconds;
}

static bool host_lock_reply(void *context)
{
    return ((test_context_t *)context)->lock_reply;
}

static uint16_t host_configuration_requests(void *context)
{
    return ((test_context_t *)context)->configuration_requests;
}

static bool reset_host_configuration_requests(void *context)
{
    test_context_t *test = (test_context_t *)context;
    test->configuration_requests = 0U;
    test->reset_called = true;
    return true;
}

static uint16_t host_os_guess(void *context)
{
    return ((test_context_t *)context)->os_guess;
}

static void expect_pass(const char *script, test_context_t *test)
{
    ducky_io_t io = {
        .context = test,
        .keyboard = keyboard,
        .delay_ms = delay_ms,
        .host_lock_reply_received = host_lock_reply,
        .host_configuration_request_count = host_configuration_requests,
        .reset_host_configuration_request_count = reset_host_configuration_requests,
        .host_os_guess = host_os_guess,
    };
    ducky_config_t config = DUCKY_CONFIG_DEFAULT();
    config.key_press_ms = 0U;
    ducky_result_t result = ducky_run(script, strlen(script), &io, &config);
    if (result.status != DUCKY_OK) {
        fprintf(stderr, "DuckyScript failed at line %zu: %s\n", result.line + 1U, result.message);
    }
    assert(result.status == DUCKY_OK);
    assert(test->key_count == 4U);
    assert(test->modifiers[0] == 0x02U && test->keycodes[0] == 0x13U); /* P */
    assert(test->modifiers[1] == 0x02U && test->keycodes[1] == 0x04U); /* A */
    assert(test->modifiers[2] == 0x02U && test->keycodes[2] == 0x16U); /* S */
    assert(test->modifiers[3] == 0x02U && test->keycodes[3] == 0x16U); /* S */
}

int main(void)
{
    fprintf(stderr, "CASE compile gates\n");
    test_context_t preprocessor = {0};
    expect_pass(
        "DEFINE #ENABLED TRUE\n"
        "DEFINE #DISABLED FALSE\n"
        "IF_DEFINED_TRUE #DISABLED\n"
        "THIS_INACTIVE_COMMAND_MUST_NOT_PARSE\n"
        "ELSE_DEFINED\n"
        "IF_DEFINED_TRUE #ENABLED\n"
        "STRING PASS\n"
        "END_IF_DEFINED\n"
        "END_IF_DEFINED\n",
        &preprocessor);

    fprintf(stderr, "CASE missing define\n");
    test_context_t missing_define = {0};
    expect_pass(
        "IF_NOT_DEFINED_TRUE #MISSING\n"
        "STRING PASS\n"
        "END_IF_DEFINED\n",
        &missing_define);

    fprintf(stderr, "CASE counter reset\n");
    test_context_t reset = {.configuration_requests = 9U};
    expect_pass(
        "$_HOST_CONFIGURATION_REQUEST_COUNT = 0\n"
        "IF ($_HOST_CONFIGURATION_REQUEST_COUNT == 0) THEN\n"
        "STRING PASS\n"
        "END_IF\n",
        &reset);
    assert(reset.reset_called);

    fprintf(stderr, "CASE OS snapshot\n");
    test_context_t snapshot = {.os_guess = 1U};
    expect_pass(
        "IF ($_OS == WINDOWS) THEN\n"
        "STRING PASS\n"
        "END_IF\n",
        &snapshot);

    fprintf(stderr, "CASE passive Windows\n");
    test_context_t passive = {
        .configuration_requests = 3U,
        .lock_reply = true,
    };
    expect_pass(
        "EXTENSION PASSIVE_WINDOWS_DETECT\n"
        "DEFINE #MAX_WAIT 150\n"
        "DEFINE #CHECK_INTERVAL 20\n"
        "DEFINE #WINDOWS_HOST_REQUEST_COUNT 2\n"
        "DEFINE #NOT_WINDOWS 7\n"
        "$_OS = #NOT_WINDOWS\n"
        "VAR $MAX_TRIES = #MAX_WAIT\n"
        "WHILE(($_RECEIVED_HOST_LOCK_LED_REPLY == FALSE) && ($MAX_TRIES > 0))\n"
        "DELAY #CHECK_INTERVAL\n"
        "$MAX_TRIES = ($MAX_TRIES - 1)\n"
        "END_WHILE\n"
        "IF ($_HOST_CONFIGURATION_REQUEST_COUNT > #WINDOWS_HOST_REQUEST_COUNT) THEN\n"
        "$_OS = WINDOWS\n"
        "END_IF\n"
        "END_EXTENSION\n"
        "IF ($_OS == WINDOWS) THEN\n"
        "STRING PASS\n"
        "END_IF\n",
        &passive);

    puts("PASS: DuckyScript compile gates, exact host counter reset, OS snapshot and passive Windows detection");
    return 0;
}
