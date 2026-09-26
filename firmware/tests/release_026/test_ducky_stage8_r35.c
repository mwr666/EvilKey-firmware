#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "ducky.h"

typedef struct {
    uint16_t values[8];
    size_t count;
    bool reflection;
    unsigned transitions;
} test_context_t;

static bool keyboard(void *context,uint8_t modifiers,const uint8_t keycodes[6])
{(void)context;(void)modifiers;(void)keycodes;return true;}
static void delay_ms(void *context,uint32_t milliseconds)
{(void)context;(void)milliseconds;}
static bool exfil(void *context,uint16_t value)
{
    test_context_t *test=(test_context_t *)context;
    assert(test->count<8U);test->values[test->count++]=value;return true;
}
static bool set_reflection(void *context,bool enabled)
{
    test_context_t *test=(test_context_t *)context;
    test->reflection=enabled;++test->transitions;return true;
}
static bool reflection(void *context)
{return ((test_context_t *)context)->reflection;}

static ducky_result_t run(const char *script,test_context_t *test,bool callbacks)
{
    ducky_io_t io={.context=test,.keyboard=keyboard,.delay_ms=delay_ms};
    if(callbacks){io.variable_exfil=exfil;io.set_exfil_mode=set_reflection;io.exfil_mode_enabled=reflection;}
    ducky_config_t cfg=DUCKY_CONFIG_DEFAULT();cfg.key_press_ms=0U;
    return ducky_run(script,strlen(script),&io,&cfg);
}

int main(void)
{
    const char *scan=
        "REM EXFIL $IGNORED\n"
        "STRING\nEXFIL $ALSO_IGNORED\nEND_STRING\n"
        "IF ($_OS == WINDOWS) THEN\nEXFIL $A\nEND_IF\n"
        "$_EXFIL_MODE_ENABLED = TRUE\n";
    uint32_t caps=ducky_inspect_capabilities(scan,strlen(scan));
    assert((caps&DUCKY_CAP_VARIABLE_EXFIL)!=0U);
    assert((caps&DUCKY_CAP_KEYSTROKE_REFLECTION)!=0U);
    assert((caps&DUCKY_CAP_PAYLOAD_HIDING)==0U);
    assert(ducky_inspect_capabilities("HIDE_PAYLOAD\n",13U)==DUCKY_CAP_PAYLOAD_HIDING);

    test_context_t test={0};
    const char *ok="VAR $A = 4660\nEXFIL $A\nEXFIL $_CURRENT_ATTACKMODE\n$_EXFIL_MODE_ENABLED = TRUE\n$_EXFIL_MODE_ENABLED = FALSE\n";
    ducky_result_t result=run(ok,&test,true);
    if(result.status!=DUCKY_OK)fprintf(stderr,"line %zu: %s\n",result.line,result.message);
    assert(result.status==DUCKY_OK);assert(test.count==2U);
    assert(test.values[0]==0x1234U);assert(test.values[1]==1U);
    assert(test.transitions==2U);assert(!test.reflection);

    test=(test_context_t){0};result=run("EXFIL 7\n",&test,true);
    assert(result.status==DUCKY_PARSE_ERROR);
    result=run("VAR $A = 1\nEXFIL $A\n",&test,false);
    assert(result.status==DUCKY_UNSUPPORTED);
    puts("PASS: Stage 8 callbacks, strict EXFIL and shared capability inspector");
    return 0;
}
