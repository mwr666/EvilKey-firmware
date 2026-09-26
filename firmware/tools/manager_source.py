"""M1 source-generation transforms. Not a patch installer. Locked upstream only."""
from __future__ import annotations

def one(text: str, old: str, new: str) -> str:
    if text.count(old) != 1:
        raise RuntimeError("M1 source anchor missing/ambiguous: " + old[:80])
    return text.replace(old,new,1)

def config_source(text: str) -> str:
    text=one(text,'#include "pico_time.h"',
        '#include "pico_time.h"\n#include "ws_settings.h"\n#include "ws_manager_drive_state.h"\n#include "pf_engine_api.h"\n#include "object_authorization.h"')
    text=one(text,'    uint8_t *verify_payload = (uint8_t *) calloc(1, 32 + 1 + 1 + raw_subpara_len);',
        '''    /* PFM1: validate token memory before passing it to the existing HMAC code. */
    if (subcommand==0xFF &&
        (vendorCommandId==WS_MANAGER_READ_ID || vendorCommandId==WS_MANAGER_WRITE_ID ||
         vendorCommandId==WS_MANAGER_DRIVE_READ_ID || vendorCommandId==WS_MANAGER_DRIVE_WRITE_ID) &&
        (!paut.data || paut.len!=32 || !paut.in_use)) {
        CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
    }
    uint8_t *verify_payload = (uint8_t *) calloc(1, 32 + 1 + 1 + raw_subpara_len);
    if (!verify_payload) { CBOR_ERROR(CTAP2_ERR_PROCESSING); }''')
    text=one(text,'    memcpy(verify_payload + 34, raw_subpara, raw_subpara_len);',
        '    if (raw_subpara_len) memcpy(verify_payload + 34, raw_subpara, raw_subpara_len);')
    anchor='''    if (!(paut.permissions & CTAP_PERMISSION_ACFG)) {
        CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
    }'''
    text=one(text,anchor,anchor+'\n\n#include "ws_manager_config.h"')
    return text

def button_source(text: str) -> str:
    text=one(text,'#include "ws_board.h"','#include "ws_board.h"\n#include "ws_settings.h"')
    return one(text,'(uint32_t)FIDO_V1_PRESENCE_TIMEOUT_SECONDS * 1000u',
        'ws_settings_presence_timeout_ms()')

TRANSFORMS={"fido/src/fido/cbor_config.c":config_source,"sdk/src/button.c":button_source}
