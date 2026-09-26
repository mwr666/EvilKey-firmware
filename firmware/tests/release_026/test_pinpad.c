#include "ws_pinpad.h"
#include "ws_ui.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
static unsigned now=100;
static ws_contact_t sample(bool valid,bool down,int key) {
    ws_contact_t c={.valid=valid,.down=down,.action=(ws_action_t)key};return c;
}
static void tap(ws_pinpad_t *p,int key) {
    ws_pinpad_step(p,now+=1,false,true,sample(true,false,0));
    ws_pinpad_step(p,now+=45,false,true,sample(true,false,0));
    ws_pinpad_step(p,now+=1,false,true,sample(true,true,key));
    ws_pinpad_step(p,now+=45,false,true,sample(true,true,key));
    ws_pinpad_step(p,now+=1,false,true,sample(true,false,0));
    ws_pinpad_step(p,now+=45,false,true,sample(true,false,0));
}
int main(void) {
    ws_pinpad_t p;char output[64];size_t n;
    ws_pinpad_begin(&p,now,120000);
    tap(&p,11);tap(&p,12);tap(&p,13);tap(&p,14);tap(&p,21);
    assert(p.status==WS_PIN_SUBMITTED && ws_pinpad_take(&p,output,sizeof(output),&n));
    assert(n==4 && strcmp(output,"1234")==0);
    for(size_t i=0;i<sizeof(p.digits);++i) assert(p.digits[i]==0);
    assert(!ws_pinpad_take(&p,output,sizeof(output),&n) && n==0 && output[0]==0);
    ws_pinpad_begin(&p,now,120000);tap(&p,11);tap(&p,21);assert(p.status==WS_PIN_EDITING);
    tap(&p,20);assert(p.length==0);tap(&p,10);assert(p.length==1 && p.digits[0]=='0');
    tap(&p,22);assert(p.status==WS_PIN_CANCELLED && p.length==0 && p.digits[0]==0);
    ws_pinpad_begin(&p,now,120000);
    for(int i=0;i<80;++i) tap(&p,11);
    assert(p.length==63 && p.digits[63]==0);
    tap(&p,21);assert(!ws_pinpad_take(&p,output,4,&n) && p.status==WS_PIN_IO_ERROR);
    ws_pinpad_begin(&p,now,120000);
    ws_pinpad_step(&p,now+=1,false,true,sample(true,true,11));
    ws_pinpad_step(&p,now+=100,false,true,sample(true,true,11));
    ws_pinpad_step(&p,now+=1,false,true,sample(true,false,0));
    ws_pinpad_step(&p,now+=100,false,true,sample(true,false,0));
    assert(p.length==0); /* Held before request is not a digit. */
    tap(&p,11);assert(p.length==1);
    ws_pinpad_step(&p,now+=1,false,true,sample(true,false,0));
    ws_pinpad_step(&p,now+=45,false,true,sample(true,false,0));
    ws_pinpad_step(&p,now+=1,false,true,sample(true,true,12));
    ws_pinpad_step(&p,now+=45,false,true,sample(true,true,13));
    ws_pinpad_step(&p,now+=1,false,true,sample(true,false,0));
    ws_pinpad_step(&p,now+=45,false,true,sample(true,false,0));assert(p.length==1);
    /* Invalid sample cannot be interpreted as lifting a finger. */
    tap(&p,11);unsigned before=p.length;
    ws_pinpad_step(&p,now+=1,false,true,sample(true,false,0));
    ws_pinpad_step(&p,now+=45,false,true,sample(true,false,0));
    ws_pinpad_step(&p,now+=1,false,true,sample(true,true,14));
    ws_pinpad_step(&p,now+=45,false,true,sample(true,true,14));
    ws_pinpad_step(&p,now+=1,false,true,sample(false,false,0));
    ws_pinpad_step(&p,now+=45,false,true,sample(true,false,0));assert(p.length==before);
    ws_pinpad_step(&p,now,true,true,sample(true,false,0));assert(p.status==WS_PIN_CANCELLED && p.length==0);
    ws_pinpad_begin(&p,UINT32_MAX-50,100);ws_pinpad_step(&p,55,false,true,sample(true,false,0));assert(p.status==WS_PIN_TIMEOUT);
    ws_pinpad_begin(&p,now,1000);tap(&p,11);ws_pinpad_step(&p,now,false,false,sample(true,false,0));assert(p.status==WS_PIN_IO_ERROR && p.length==0);
    assert(ws_pinpad_hit_test(8,132)==11 && ws_pinpad_hit_test(271,323)==19);
    assert(ws_pinpad_hit_test(100,334)==10 && ws_pinpad_hit_test(10,399)==0);
    assert(ws_pinpad_hit_test(10,400)==22 && ws_pinpad_hit_test(272,400)==0);
    for(unsigned y=0;y<456;++y)for(unsigned x=0;x<280;++x) {
        int expected=0;
        for(unsigned row=0;row<4;++row)for(unsigned col=0;col<3;++col)
            if(x>=8+col*90 && x<92+col*90 && y>=132+row*66 && y<192+row*66)
                expected=row<3?(int)(11+row*3+col):col==0?20:col==1?10:21;
        if(x>=8 && x<272 && y>=400 && y<448)expected=22;
        assert(ws_pinpad_hit_test((uint16_t)x,(uint16_t)y)==expected);
    }
    assert(ws_pinpad_hit_test(UINT16_MAX,UINT16_MAX)==0);
    puts("PASS: all 127680 PIN hit coordinates and out-of-screen point");
    /* The LVGL snapshot deliberately exposes only PIN length/status, never digits. */
    for(unsigned len=0;len<=63;++len) {
        ws_ui_snapshot_t view={.state=WS_UI_PIN,.pin_length=len,.uv_retries=8,.seconds_left=120,.touch_enabled=true,.touch_available=true};
        assert(view.pin_length==len && view.uv_retries==8 && view.seconds_left==120);
    }
    puts("PIN keypad state, bounds, cancellation, wraparound and masked LVGL snapshot: PASS");
}
