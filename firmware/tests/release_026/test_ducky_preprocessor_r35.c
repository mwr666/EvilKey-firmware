#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "ducky.h"

typedef struct {
    char text[256];
    size_t length;
    uint8_t attackmode;
    uint8_t led_states[8];
    size_t led_count;
    bool saw_gui_r;
} test_context_t;

static char key_to_ascii(uint8_t modifiers, uint8_t key)
{
    bool shift = (modifiers & 0x22U) != 0U;
    if (key >= 0x04U && key <= 0x1dU) {
        char value = (char)('a' + key - 0x04U);
        return shift ? (char)(value - 'a' + 'A') : value;
    }
    if (key == 0x2cU) return ' ';
    if (key == 0x28U) return '\n';
    return '\0';
}

static bool keyboard(void *context, uint8_t modifiers, const uint8_t keycodes[6])
{
    test_context_t *test = (test_context_t *)context;
    if ((modifiers & 0x08U) != 0U && keycodes[0] == 0x15U) test->saw_gui_r = true;
    if (keycodes[0] != 0U && (modifiers & 0x08U) == 0U) {
        char value = key_to_ascii(modifiers, keycodes[0]);
        if (value != '\0') {
            assert(test->length + 1U < sizeof(test->text));
            test->text[test->length++] = value;
            test->text[test->length] = '\0';
        }
    }
    return true;
}

static void delay_ms(void *context, uint32_t milliseconds)
{
    (void)context;
    (void)milliseconds;
}

static bool attackmode(void *context, uint8_t mode)
{
    ((test_context_t *)context)->attackmode = mode;
    return true;
}

static void status_led(void *context, uint8_t state)
{
    test_context_t *test = (test_context_t *)context;
    assert(test->led_count < sizeof(test->led_states));
    test->led_states[test->led_count++] = state;
}

static ducky_result_t run(const char *script, test_context_t *test)
{
    ducky_io_t io = {
        .context = test,
        .keyboard = keyboard,
        .delay_ms = delay_ms,
        .status_led = status_led,
        .attackmode = attackmode,
    };
    ducky_config_t config = DUCKY_CONFIG_DEFAULT();
    config.key_press_ms = 0U;
    return ducky_run(script, strlen(script), &io, &config);
}

int main(void)
{
    const char *script =
        "DEFINE #MODE HID\n"
        "DEFINE #OPEN GUI r\n"
        "DEFINE #TYPE STRING alias\n"
        "DEFINE #WORD hello\n"
        "DEFINE #INNER ENTER\n"
        "DEFINE #OUTER #INNER\n"
        "ATTACKMODE #MODE\n"
        "#OPEN\n"
        "#TYPE\n"
        "STRING #WORD\n"
        "STRING\n"
        "    a\n"
        "      b\n"
        "END_STRING\n"
        "STRINGLN\n"
        "\t  c  \n"
        "\t d\n"
        "END_STRINGLN\n"
        "#OUTER\n";
    test_context_t test = {0};
    ducky_result_t result = run(script, &test);
    if (result.status != DUCKY_OK) {
        fprintf(stderr, "DuckyScript failed at line %zu: %s\n", result.line, result.message);
    }
    assert(result.status == DUCKY_OK);
    assert(test.attackmode == 1U);
    assert(test.saw_gui_r);
    assert(strcmp(test.text, "aliashelloab  c  \n d\n\n") == 0);

    const char *led_script = "LED_R\nLED_G\nLED_RED\nLED_GREEN\nLED_ON\nLED_OFF\n";
    test_context_t leds = {0};
    result = run(led_script, &leds);
    assert(result.status == DUCKY_OK);
    assert(leds.led_count == 6U);
    assert(leds.led_states[0] == 1U);
    assert(leds.led_states[1] == 2U);
    assert(leds.led_states[2] == 1U);
    assert(leds.led_states[3] == 2U);
    assert(leds.led_states[4] == 2U);
    assert(leds.led_states[5] == 0U);

    const char *literal_script =
        "REM_BLOCK\n"
        "DEFINE #COMMENTED STRING wrong\n"
        "END_REM\n"
        "IF_NOT_DEFINED_TRUE #COMMENTED\n"
        "STRING ok\n"
        "END_IF_DEFINED\n";
    test_context_t literal = {0};
    result = run(literal_script, &literal);
    assert(result.status == DUCKY_OK);
    assert(strcmp(literal.text, "ok") == 0);

    const char *library_compat_script =
        "\xEF\xBB\xBFREM UTF-8 BOM\n"
        "REM: legacy comment\n"
        "REM< legacy comment\n"
        "# repository comment\n"
        "#### repository section comment ####\n"
        "DEFINE OPEN-COMMAND STRING bare\n"
        "DEFINE #SOCIAL-ACCOUNT-2 STRING hash\n"
        "DEFINE THIS_IDENTIFIER_IS_LONGER_THAN_THIRTY_ONE STRING long\n"
        "OPEN-COMMAND\n"
        "#SOCIAL-ACCOUNT-2\n"
        "THIS_IDENTIFIER_IS_LONGER_THAN_THIRTY_ONE\n"
        "STRING_POWERSHELL\n"
        "  power\n"
        "  shell\n"
        "END_STRING\n"
        "STRINGLN_BASH\n"
        "\tbash\n"
        "END_STRINGLN\n"
        "STRINGLN_BLOCK\n"
        "\tblock\n"
        "END_STRINGLN\n";
    test_context_t library_compat = {0};
    result = run(library_compat_script, &library_compat);
    assert(result.status == DUCKY_OK);
    assert(strcmp(library_compat.text, "barehashlongpowershellbash\nblock\n") == 0);

    const char *cycle_script =
        "DEFINE #A #B\n"
        "DEFINE #B #A\n"
        "STRING #A\n";
    test_context_t cycle = {0};
    result = run(cycle_script, &cycle);
    assert(result.status == DUCKY_LIMIT_EXCEEDED);
    assert(result.line == 3U);

    puts("PASS: DEFINE variants, PayloadStudio STRING blocks, comments and Ducky LED state");
    return 0;
}
