/* SPDX-License-Identifier: AGPL-3.0-or-later */
#pragma once

#include <stdbool.h>
#include <stdint.h>

/* TinyUSB exposes HID output reports in two forms:
 *
 * - SET_REPORT control transfers carry report_id separately and buffer[0]
 *   is the LED byte;
 * - interrupt OUT transfers use report_id 0 and retain the report ID prefix
 *   in buffer[0], followed by the LED byte in buffer[1].
 *
 * Some TinyUSB revisions report the interrupt form with type OUTPUT, while
 * older revisions use type INVALID (0).  The report-ID prefix keeps accepting
 * the latter unambiguous and limited to the keyboard report.
 */
static inline bool pf_usb_tool_decode_keyboard_led_report(
    uint8_t keyboard_report_id,
    uint8_t report_id,
    uint8_t report_type,
    uint8_t output_report_type,
    const uint8_t *buffer,
    uint16_t size,
    uint8_t *leds)
{
    if(buffer==0 || leds==0)return false;

    if(report_id==keyboard_report_id && report_type==output_report_type && size>=1U){
        *leds=buffer[0];
        return true;
    }

    if(report_id==0U &&
       (report_type==0U || report_type==output_report_type) &&
       size>=2U && buffer[0]==keyboard_report_id){
        *leds=buffer[1];
        return true;
    }

    return false;
}
