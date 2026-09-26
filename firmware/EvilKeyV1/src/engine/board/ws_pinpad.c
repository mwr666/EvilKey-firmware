#include "../../pf_build_config.h"
/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "ws_pinpad.h"
#include "ws_ui_layout.h"
#include <string.h>
void ws_pinpad_zero(void *p, size_t n) {
    volatile unsigned char *v=(volatile unsigned char *)p;
    while(n--) *v++=0;
}
void ws_pinpad_begin(ws_pinpad_t *p, uint32_t now, uint32_t timeout_ms) {
    ws_pinpad_zero(p,sizeof(*p));
    p->status=WS_PIN_EDITING; p->started_at=now;
    p->timeout_ms=timeout_ms>0 && timeout_ms<=120000U ? timeout_ms:120000U;
}
void ws_pinpad_abort(ws_pinpad_t *p, ws_pin_status_t reason) {
    ws_pinpad_zero(p,sizeof(*p)); p->status=reason;
}
int ws_pinpad_hit_test(uint16_t x, uint16_t y) {
    if(x>=WS_PIN_CANCEL_X && x<WS_PIN_CANCEL_X+WS_PIN_CANCEL_W &&
       y>=WS_PIN_CANCEL_Y && y<WS_PIN_CANCEL_Y+WS_PIN_CANCEL_H) return WS_PIN_KEY_CANCEL;
    for(unsigned row=0;row<4;++row) for(unsigned col=0;col<3;++col) {
        unsigned left=WS_KEY_X+WS_KEY_DX*col, top=WS_KEY_Y+WS_KEY_DY*row;
        if(x>=left && x<left+WS_KEY_W && y>=top && y<top+WS_KEY_H) {
            if(row<3) return WS_PIN_KEY_0+(int)(1+row*3+col);
            return col==0 ? WS_PIN_KEY_DELETE : col==1 ? WS_PIN_KEY_0 : WS_PIN_KEY_ENTER;
        }
    }
    return WS_ACTION_NONE;
}
void ws_pinpad_step(ws_pinpad_t *p,uint32_t now,bool cancel,bool io_ok,ws_contact_t touch) {
    if(p->status!=WS_PIN_EDITING) return;
    if(cancel) { ws_pinpad_abort(p,WS_PIN_CANCELLED);return; }
    if(!io_ok) { ws_pinpad_abort(p,WS_PIN_IO_ERROR);return; }
    if((uint32_t)(now-p->started_at)>=p->timeout_ms) {
        ws_pinpad_abort(p,WS_PIN_TIMEOUT);return;
    }
    int k=(int)ws_gesture_step(&p->gesture,now,touch);
    if(k==WS_PIN_KEY_CANCEL) { ws_pinpad_abort(p,WS_PIN_CANCELLED);return; }
    if(k==WS_PIN_KEY_DELETE) {
        if(p->length) p->digits[--p->length]=0;
    } else if(k==WS_PIN_KEY_ENTER) {
        /* Existing FIDO PINs may have four digits. New PIN policy is owned by CTAP. */
        if(p->length>=4) p->status=WS_PIN_SUBMITTED;
    } else if(k>=WS_PIN_KEY_0 && k<WS_PIN_KEY_0+10 && p->length<WS_PIN_MAX_BYTES) {
        p->digits[p->length++]=(char)('0'+k-WS_PIN_KEY_0);
        p->digits[p->length]=0;
    }
}
bool ws_pinpad_take(ws_pinpad_t *p,char *out,size_t cap,size_t *len) {
    if(!out || !len || cap==0) return false;
    ws_pinpad_zero(out,cap); *len=0;
    if(p->status!=WS_PIN_SUBMITTED || cap<=p->length) {
        if(p->status==WS_PIN_SUBMITTED) ws_pinpad_abort(p,WS_PIN_IO_ERROR);
        return false;
    }
    *len=p->length;memcpy(out,p->digits,p->length);
    ws_pinpad_abort(p,WS_PIN_IDLE);return true;
}
