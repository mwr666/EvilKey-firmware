#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "ducky.h"

typedef struct {
    char text[32];
    size_t length;
    uint8_t led_options;
    uint16_t storage_timeout_ms;
    unsigned option_updates;
    unsigned storage_checks;
} test_context_t;

static bool keyboard(void *context, uint8_t modifiers, const uint8_t keycodes[6])
{
    test_context_t *test=(test_context_t *)context;
    if(keycodes[0]>=0x04U && keycodes[0]<=0x1dU && (modifiers&0x08U)==0U) {
        char value=(char)('a'+keycodes[0]-0x04U);
        if(modifiers&0x22U)value=(char)(value-'a'+'A');
        assert(test->length+1U<sizeof(test->text));
        test->text[test->length++]=value;
        test->text[test->length]='\0';
    }
    return true;
}

static void delay_ms(void *context,uint32_t milliseconds)
{
    (void)context;(void)milliseconds;
}

static uint32_t entropy(void *context)
{
    (void)context;return 0x12345678U;
}

static void runtime_options(void *context,uint8_t led_options,uint16_t timeout_ms)
{
    test_context_t *test=(test_context_t *)context;
    test->led_options=led_options;
    test->storage_timeout_ms=timeout_ms;
    ++test->option_updates;
}

static uint32_t storage_activity_age_ms(void *context)
{
    test_context_t *test=(test_context_t *)context;
    return test->storage_checks++ == 0U ? 0U : UINT32_MAX;
}

int main(void)
{
    const char *script=
        "$_SYSTEM_LEDS_ENABLED = FALSE\n"
        "$_STORAGE_LEDS_ENABLED = TRUE\n"
        "$_LED_CONTINUOUS_SHOW_STORAGE_ACTIVITY = FALSE\n"
        "$_INJECTING_LEDS_ENABLED = FALSE\n"
        "$_EXFIL_LEDS_ENABLED = FALSE\n"
        "$_LED_SHOW_CAPS = TRUE\n"
        "$_LED_SHOW_NUM = TRUE\n"
        "$_LED_SHOW_SCROLL = TRUE\n"
        "$_STORAGE_ACTIVITY_TIMEOUT = 42\n"
        "WAIT_FOR_STORAGE_ACTIVITY\n"
        "WAIT_FOR_STORAGE_INACTIVITY\n"
        "VAR $RAW_KEY = 4\n"
        "INJECT_VAR $RAW_KEY\n"
        "VAR $D = 1\n"
        "VAR $D = 2\n"
        "IF ($D == 2) THEN\n"
        "STRING d\n"
        "END_IF\n"
        "FUNCTION RESET_LOCAL()\n"
        "VAR $LOCAL = 1\n"
        "END_FUNCTION\n"
        "RESET_LOCAL()\n"
        "RESET_LOCAL()\n"
        "$IMPLICIT = 3\n"
        "IF ($IMPLICIT == 3) THEN\n"
        "STRING i\n"
        "END_IF\n"
        "$_RANDOM_MIN = 0\n"
        "$_RANDOM_MAX = 65535\n"
        "$_RANDOM_SEED = 123\n"
        "VAR $A = $_RANDOM_INT\n"
        "$_RANDOM_SEED = 123\n"
        "VAR $B = $_RANDOM_INT\n"
        "IF ($A == $B) THEN\n"
        "STRING s\n"
        "END_IF\n"
        "VAR $L = $_RANDOM_LOWER_LETTER_KEYCODE\n"
        "VAR $U = $_RANDOM_UPPER_LETTER_KEYCODE\n"
        "VAR $R = $_RANDOM_LETTER_KEYCODE\n"
        "VAR $N = $_RANDOM_NUMBER_KEYCODE\n"
        "VAR $P = $_RANDOM_SPECIAL_KEYCODE\n"
        "VAR $C = $_RANDOM_CHAR_KEYCODE\n"
        "IF (($L >= 4) && ($L <= 29) && ($U >= 4) && ($U <= 29) && ($R >= 4) && ($R <= 29)) THEN\n"
        "STRING k\n"
        "END_IF\n"
        "IF (($N >= 30) && ($N <= 39) && ($P >= 30) && ($P <= 39) && ($C >= 4) && ($C <= 39)) THEN\n"
        "STRING n\n"
        "END_IF\n"
        "IF (($_STORAGE_ACTIVITY_TIMEOUT == 42) && ($_RANDOM_SEED == 123) && ($_LED_SHOW_CAPS == TRUE) && ($_SYSTEM_LEDS_ENABLED == FALSE)) THEN\n"
        "STRING v\n"
        "END_IF\n";
    test_context_t test={0};
    ducky_io_t io={
        .context=&test,
        .keyboard=keyboard,
        .delay_ms=delay_ms,
        .random_u32=entropy,
        .runtime_options=runtime_options,
        .storage_activity_age_ms=storage_activity_age_ms,
    };
    ducky_config_t config=DUCKY_CONFIG_DEFAULT();
    config.key_press_ms=0U;
    ducky_result_t result=ducky_run(script,strlen(script),&io,&config);
    if(result.status!=DUCKY_OK)
        fprintf(stderr,"DuckyScript failed at line %zu: %s\n",result.line,result.message);
    assert(result.status==DUCKY_OK);
    assert(strcmp(test.text,"adisknv")==0);
    assert(test.option_updates>=10U);
    assert(test.storage_timeout_ms==42U);
    assert(test.storage_checks==2U);
    assert(test.led_options==(DUCKY_LED_OPT_STORAGE|DUCKY_LED_OPT_SHOW_CAPS|
        DUCKY_LED_OPT_SHOW_NUM|DUCKY_LED_OPT_SHOW_SCROLL));
    puts("PASS: random/keycode variables, storage waits and LED internal variables");
    return 0;
}
