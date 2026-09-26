/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "ws_presence.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>

static const ws_contact_t UP={true,false,WS_ACTION_NONE};
static const ws_contact_t DOWN={true,true,WS_ACTION_APPROVE};
static const ws_contact_t CANCEL={true,true,WS_ACTION_CANCEL};
static const ws_contact_t BAD={false,false,WS_ACTION_NONE};
static ws_presence_t p;
static unsigned tests;

#define STEP(t,b,d) ws_presence_step(&p,(uint32_t)(t),false,(b),(d))
#define WAIT(t,b,d) assert(STEP(t,b,d)==WS_UP_WAITING)
static void start(uint32_t t) { ws_presence_start(&p,t,30000); ++tests; }

int main(void)
{
    /* Fresh physical press and release, followed by no reusable decision. */
    start(0); WAIT(0,UP,BAD); WAIT(40,UP,BAD);
    WAIT(100,DOWN,BAD); WAIT(140,DOWN,BAD); WAIT(200,UP,BAD);
    assert(STEP(240,UP,BAD)==WS_UP_APPROVED);
    assert(STEP(250,UP,BAD)==WS_UP_WAITING);

    /* Already held at request start: releasing is not approval. */
    start(0); WAIT(0,DOWN,BAD); WAIT(80,DOWN,BAD); WAIT(90,UP,BAD);
    WAIT(140,UP,BAD); WAIT(180,DOWN,BAD); WAIT(220,DOWN,BAD);
    WAIT(260,UP,BAD); assert(STEP(300,UP,BAD)==WS_UP_APPROVED);

    /* No press: expires exactly at the deadline. */
    start(0); WAIT(0,UP,BAD); WAIT(29999,UP,BAD);
    assert(STEP(30000,UP,BAD)==WS_UP_TIMED_OUT);

    /* Release debounce cannot extend the request deadline. */
    start(0); WAIT(0,UP,BAD); WAIT(40,UP,BAD);
    WAIT(29900,DOWN,BAD); WAIT(29940,DOWN,BAD); WAIT(29980,UP,BAD);
    assert(STEP(30020,UP,BAD)==WS_UP_TIMED_OUT);

    /* Bounce shorter than 40 ms is not a press. */
    start(0); WAIT(0,UP,BAD); WAIT(40,UP,BAD);
    WAIT(60,DOWN,BAD); WAIT(65,UP,BAD); WAIT(120,UP,BAD);
    WAIT(150,DOWN,BAD); WAIT(155,UP,BAD); WAIT(220,UP,BAD);

    /* Host cancel wins over any press. */
    start(0); WAIT(0,UP,BAD); WAIT(40,UP,BAD); WAIT(60,DOWN,BAD);
    assert(ws_presence_step(&p,100,true,DOWN,BAD)==WS_UP_CANCELLED);

    /* A valid touch approve gesture. */
    start(0); WAIT(0,UP,UP); WAIT(40,UP,UP);
    WAIT(100,UP,DOWN); WAIT(140,UP,DOWN); WAIT(200,UP,UP);
    assert(STEP(240,UP,UP)==WS_UP_APPROVED);

    /* An I2C error must not synthesize release of a held touch. */
    start(0); WAIT(0,UP,UP); WAIT(40,UP,UP);
    WAIT(100,UP,DOWN); WAIT(140,UP,DOWN); WAIT(200,UP,BAD);
    WAIT(240,UP,UP); WAIT(300,UP,UP);
    assert(p.active);

    /* Fresh recovery after I2C failure. */
    WAIT(340,UP,DOWN); WAIT(380,UP,DOWN); WAIT(440,UP,UP);
    assert(STEP(480,UP,UP)==WS_UP_APPROVED);

    /* Sliding across targets invalidates the tap. */
    start(0); WAIT(0,UP,UP); WAIT(40,UP,UP);
    WAIT(100,UP,DOWN); WAIT(140,UP,DOWN); WAIT(160,UP,CANCEL);
    WAIT(200,UP,DOWN); WAIT(240,UP,UP); WAIT(280,UP,UP);
    assert(p.active);

    /* Touch cancel. */
    start(0); WAIT(0,UP,UP); WAIT(40,UP,UP);
    WAIT(100,UP,CANCEL); WAIT(140,UP,CANCEL); WAIT(200,UP,UP);
    assert(STEP(240,UP,UP)==WS_UP_CANCELLED);

    /* Simultaneous physical approval and touch cancel: cancel wins. */
    start(0); WAIT(0,UP,UP); WAIT(40,UP,UP);
    WAIT(100,DOWN,CANCEL); WAIT(140,DOWN,CANCEL); WAIT(200,UP,UP);
    assert(STEP(240,UP,UP)==WS_UP_CANCELLED);

    /* uint32_t wrap during an otherwise valid press. */
    uint32_t base=UINT32_MAX-150U;
    start(base); WAIT(base,UP,BAD); WAIT(base+40U,UP,BAD);
    WAIT(base+80U,DOWN,BAD); WAIT(base+120U,DOWN,BAD);
    WAIT(base+160U,UP,BAD);
    assert(STEP(base+200U,UP,BAD)==WS_UP_APPROVED);

    /* Wrap-safe expiry. */
    start(base); WAIT(base,UP,BAD); WAIT(base+29999U,UP,BAD);
    assert(STEP(base+30000U,UP,BAD)==WS_UP_TIMED_OUT);

    /* No touch can carry into the next request. */
    start(0); WAIT(0,UP,UP); WAIT(40,UP,UP);
    WAIT(60,UP,DOWN); WAIT(100,UP,DOWN); WAIT(160,UP,UP);
    assert(STEP(200,UP,UP)==WS_UP_APPROVED);
    start(201); WAIT(201,UP,UP); WAIT(250,UP,UP); WAIT(300,UP,UP);
    assert(p.active);

    /* Device failure on touch does not disable the independent BOOT path. */
    start(0); WAIT(0,UP,BAD); WAIT(40,UP,BAD);
    WAIT(100,DOWN,BAD); WAIT(140,DOWN,BAD); WAIT(200,UP,BAD);
    assert(STEP(240,UP,BAD)==WS_UP_APPROVED);

    /* Invalid timeout configuration defaults to 30 seconds. */
    ++tests; ws_presence_start(&p,123,0); assert(p.timeout_ms==30000);
    ++tests; ws_presence_start(&p,123,UINT32_MAX); assert(p.timeout_ms==30000);

    printf("PASS: %u presence scenarios\n",tests);
    return 0;
}
