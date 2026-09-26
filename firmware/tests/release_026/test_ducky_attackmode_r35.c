#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "ducky.h"

typedef struct {
    ducky_attackmode_t profiles[4];
    size_t count;
    uint32_t random_state;
} test_context_t;

static bool keyboard(void *context, uint8_t modifiers, const uint8_t keycodes[6])
{
    (void)context;
    (void)modifiers;
    (void)keycodes;
    return true;
}

static void delay_ms(void *context, uint32_t milliseconds)
{
    (void)context;
    (void)milliseconds;
}

static uint32_t random_u32(void *context)
{
    test_context_t *test = (test_context_t *)context;
    test->random_state = test->random_state * 1664525U + 1013904223U;
    return test->random_state;
}

static bool attackmode_profile(void *context, const ducky_attackmode_t *profile)
{
    test_context_t *test = (test_context_t *)context;
    assert(profile->mode <= 3U);
    assert(test->count < sizeof(test->profiles) / sizeof(test->profiles[0]));
    test->profiles[test->count++] = *profile;
    return true;
}

static uint16_t current_vid(void *context)
{
    (void)context;
    return 0xfeffU;
}

static uint16_t current_pid(void *context)
{
    (void)context;
    return 0xfcfbU;
}

static ducky_result_t run_script(test_context_t *test, const char *script)
{
    ducky_io_t io = {
        .context = test,
        .keyboard = keyboard,
        .delay_ms = delay_ms,
        .random_u32 = random_u32,
        .attackmode_profile = attackmode_profile,
        .current_vid = current_vid,
        .current_pid = current_pid,
    };
    ducky_config_t config = DUCKY_CONFIG_DEFAULT();
    config.key_press_ms = 0U;
    return ducky_run(script, strlen(script), &io, &config);
}

static bool all_digits(const char *text)
{
    for (; *text != '\0'; ++text) {
        if (*text < '0' || *text > '9') return false;
    }
    return true;
}

int main(void)
{
    const char *explicit_script =
        "ATTACKMODE HID VID_046D PID_C31C MAN_HAK5 PROD_DUCKY SERIAL_1337\n"
        "SAVE_ATTACKMODE\n"
        "ATTACKMODE OFF\n"
        "RESTORE_ATTACKMODE\n";
    test_context_t explicit_test = {.random_state = 1U};
    ducky_result_t result = run_script(&explicit_test, explicit_script);
    if (result.status != DUCKY_OK) {
        fprintf(stderr, "DuckyScript failed at line %zu: %s\n", result.line, result.message);
    }
    assert(result.status == DUCKY_OK);
    assert(explicit_test.count == 3U);
    const ducky_attackmode_t *configured = &explicit_test.profiles[0];
    assert(configured->mode == 1U && configured->custom_identity);
    assert(configured->vid == 0x046dU && configured->pid == 0xc31cU);
    assert(strcmp(configured->manufacturer, "HAK5") == 0);
    assert(strcmp(configured->product, "DUCKY") == 0);
    assert(strcmp(configured->serial, "1337") == 0);
    assert(explicit_test.profiles[1].mode == 0U);
    assert(memcmp(configured, &explicit_test.profiles[2], sizeof(*configured)) == 0);

    const char *random_script =
        "ATTACKMODE HID STORAGE VID_RANDOM PID_RANDOM MAN_RANDOM PROD_RANDOM SERIAL_RANDOM\n";
    test_context_t random_test = {.random_state = 7U};
    result = run_script(&random_test, random_script);
    assert(result.status == DUCKY_OK);
    assert(random_test.count == 1U);
    const ducky_attackmode_t *random = &random_test.profiles[0];
    assert(random->mode == 3U && random->custom_identity);
    assert(strlen(random->manufacturer) == 12U);
    assert(strlen(random->product) == 12U);
    assert(strlen(random->serial) == 12U && all_digits(random->serial));

    test_context_t group_test = {.random_state = 8U};
    result = run_script(&group_test,
        "ATTACKMODE HID MAN_HAK5 PROD_DUCKY SERIAL_1337\n");
    assert(result.status == DUCKY_OK && group_test.count == 1U);
    assert(group_test.profiles[0].vid == 0xfeffU);
    assert(group_test.profiles[0].pid == 0xfcfbU);
    assert(strcmp(group_test.profiles[0].manufacturer, "HAK5") == 0);

    memset(&group_test, 0, sizeof(group_test));
    result = run_script(&group_test, "ATTACKMODE HID VID_05AC PID_021E\n");
    assert(result.status == DUCKY_OK && group_test.count == 1U);
    assert(group_test.profiles[0].vid == 0x05acU);
    assert(group_test.profiles[0].manufacturer[0] == '\0');

    memset(&group_test, 0, sizeof(group_test));
    result = run_script(&group_test,
        "IF ($_CURRENT_VID == 65534) THEN\nATTACKMODE OFF\nEND_IF\n");
    assert(result.status == DUCKY_OK && group_test.count == 1U);
    assert(group_test.profiles[0].mode == 0U);

    test_context_t invalid_test = {.random_state = 9U};
    result = run_script(&invalid_test, "ATTACKMODE HID VID_046D\n");
    assert(result.status == DUCKY_PARSE_ERROR);
    assert(invalid_test.count == 0U);

    puts("PASS: dynamic ATTACKMODE identity, random descriptors and full save/restore");
    return 0;
}
