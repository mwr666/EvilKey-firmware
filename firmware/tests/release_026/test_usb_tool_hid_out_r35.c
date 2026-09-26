/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include "../../EvilKeyV1/src/UsbToolHidOut.h"

enum {
    REPORT_ID_KEYBOARD=1,
    REPORT_TYPE_INVALID=0,
    REPORT_TYPE_INPUT=1,
    REPORT_TYPE_OUTPUT=2
};

int main(void)
{
    uint8_t leds=0xffU;
    const uint8_t control[]={0x05U};
    assert(pf_usb_tool_decode_keyboard_led_report(
        REPORT_ID_KEYBOARD,REPORT_ID_KEYBOARD,REPORT_TYPE_OUTPUT,
        REPORT_TYPE_OUTPUT,control,sizeof(control),&leds));
    assert(leds==0x05U);

    const uint8_t interrupt_output[]={REPORT_ID_KEYBOARD,0x02U};
    assert(pf_usb_tool_decode_keyboard_led_report(
        REPORT_ID_KEYBOARD,0U,REPORT_TYPE_OUTPUT,REPORT_TYPE_OUTPUT,
        interrupt_output,sizeof(interrupt_output),&leds));
    assert(leds==0x02U);

    const uint8_t interrupt_legacy[]={REPORT_ID_KEYBOARD,0x04U};
    assert(pf_usb_tool_decode_keyboard_led_report(
        REPORT_ID_KEYBOARD,0U,REPORT_TYPE_INVALID,REPORT_TYPE_OUTPUT,
        interrupt_legacy,sizeof(interrupt_legacy),&leds));
    assert(leds==0x04U);

    const uint8_t wrong_report[]={2U,0x07U};
    assert(!pf_usb_tool_decode_keyboard_led_report(
        REPORT_ID_KEYBOARD,0U,REPORT_TYPE_OUTPUT,REPORT_TYPE_OUTPUT,
        wrong_report,sizeof(wrong_report),&leds));
    assert(!pf_usb_tool_decode_keyboard_led_report(
        REPORT_ID_KEYBOARD,0U,REPORT_TYPE_OUTPUT,REPORT_TYPE_OUTPUT,
        interrupt_output,1U,&leds));
    assert(!pf_usb_tool_decode_keyboard_led_report(
        REPORT_ID_KEYBOARD,REPORT_ID_KEYBOARD,REPORT_TYPE_INPUT,
        REPORT_TYPE_OUTPUT,control,sizeof(control),&leds));
    assert(!pf_usb_tool_decode_keyboard_led_report(
        REPORT_ID_KEYBOARD,REPORT_ID_KEYBOARD,REPORT_TYPE_OUTPUT,
        REPORT_TYPE_OUTPUT,0,sizeof(control),&leds));

    puts("PASS: TinyUSB control and interrupt HID OUT LED reports");
    return 0;
}
