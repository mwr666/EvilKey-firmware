#!/usr/bin/env python3
"""Opt-in on-device PIN/UV for the locked 0.2.3 source tree; fail on changed anchors."""
from pathlib import Path
import re
ROOT=Path(__file__).resolve().parents[1]
MARKER='PF_LOCAL_UV_024'

def one(s,old,new):
    if s.count(old)!=1: raise RuntimeError('Touch patch anchor not unique: '+repr(old[:100]))
    return s.replace(old,new,1)

# PF_WINDOWS_PIN_PROBE_FIX_R1
# CTAP authenticator-selection probe: an empty pinUvAuthParam with a configured
# PIN must return CTAP2_ERR_PIN_INVALID (0x31), not PIN_AUTH_INVALID (0x33).
# Windows uses this distinction while deciding whether an authenticator already
# has a ClientPIN.
def windows_pin_probe_fix(s):
    pattern = re.compile(
        r'(?P<i>[ \t]+)if \(!file_has_data\(ef_pin\)\) \{\n'
        r'(?P=i)    CBOR_ERROR\(CTAP2_ERR_PIN_NOT_SET\);\n'
        r'(?P=i)\}\n'
        r'(?P=i)else \{\n'
        r'(?P=i)    CBOR_ERROR\(CTAP2_ERR_PIN_AUTH_INVALID\);\n'
        r'(?P=i)\}'
    )
    matches=list(pattern.finditer(s))
    if len(matches)!=1:
        raise RuntimeError('Windows PIN probe patch anchor not unique: expected 1, found '+str(len(matches)))
    m=matches[0]
    fixed=m.group(0).replace('CTAP2_ERR_PIN_AUTH_INVALID','CTAP2_ERR_PIN_INVALID',1)
    return s[:m.start()]+fixed+s[m.end():]

def client_pin(s):
    if MARKER in s: raise RuntimeError('Local UV already applied')
    head='''\n#include "ws_local_uv.h"
#include "ws_pinpad.h"
#include "ws_uv_retries.h"
#include "button.h" /* Shared SDK cancellation flag; do not redeclare locally. */
static int pf_local_uv_token(uint8_t,uint64_t,int64_t,int64_t,int64_t,
    const CborByteString *,const CborByteString *,const CborCharString *,uint8_t [48],uint16_t *);
'''
    s=one(s,'uint8_t new_pin_mismatches = 0;',head+'\nuint8_t new_pin_mismatches = 0;')
    s=one(s,'    uint64_t subcommand = 0x0, pinUvAuthProtocol = 0, permissions = 0;',
          '    uint64_t subcommand = 0x0, pinUvAuthProtocol = 0, permissions = 0;\n    bool protocol_present=false, permissions_present=false;')
    s=one(s,'''        if (val_c <= 2 && val_c != val_u) {
            CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
        }''','        /* Retry queries may omit protocol (key 1). */')
    s=one(s,'            CBOR_FIELD_GET_UINT(pinUvAuthProtocol, 1);',
          '            CBOR_FIELD_GET_UINT(pinUvAuthProtocol, 1);\n            protocol_present=true;')
    s=one(s,'            CBOR_FIELD_GET_UINT(permissions, 1);',
          '            CBOR_FIELD_GET_UINT(permissions, 1);\n            permissions_present=true;')
    s=one(s,'''    if (pinUvAuthProtocol != 1 && pinUvAuthProtocol != 2) {
        CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
    }

    cbor_encoder_init''','''    if (subcommand == 0 || (!protocol_present && subcommand != 1 && subcommand != 7)) {
        CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
    }
    if (protocol_present && pinUvAuthProtocol != 1 && pinUvAuthProtocol != 2) {
        CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
    }

    cbor_encoder_init''')
    # Independent UV retry budget is reset only once the ORIGINAL host verifier
    # has already succeeded (including setPIN/changePIN). No bypass branch.
    old='        new_pin_mismatches = 0;'
    if s.count(old)!=3: raise RuntimeError('Expected exactly three successful ClientPIN hooks')
    s=s.replace(old,old+'''\n#if FIDO_V1_LOCAL_UV
        if (!ws_uv_retries_reset()) { CBOR_ERROR(CTAP2_ERR_PROCESSING); }
#endif''')
    branches='''#if FIDO_V1_LOCAL_UV
    else if (subcommand == 0x7) { /* getUVRetries */
        int n=ws_uv_retries_get();
        if(n<0) { CBOR_ERROR(CTAP2_ERR_PROCESSING); }
        if(file_has_data(ef_pin) && (*file_get_data(ef_pin)&PIN_RETRY_COUNT_MASK)==0) n=0;
        CBOR_CHECK(cbor_encoder_create_map(&encoder,&mapEncoder,1));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder,0x05));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder,(uint64_t)n));
    }
    else if (subcommand == 0x6) { /* getPinUvAuthTokenUsingUvWithPermissions */
        if(!permissions_present || !kax.present || !kay.present) {
            CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
        }
        if(pinHashEnc.present || newPinEnc.present || pinUvAuthParam.present) {
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        uint8_t wrapped[48]={0}; uint16_t wrapped_len=0;
        int uv_error=pf_local_uv_token((uint8_t)pinUvAuthProtocol,permissions,kty,alg,crv,
            &kax,&kay,&rpId,wrapped,&wrapped_len);
        if(uv_error) { CBOR_ERROR(uv_error); }
        /* Fixed-size response always fits the CTAP buffer. */
        CborError encode_error=cbor_encoder_create_map(&encoder,&mapEncoder,1);
        if(encode_error==CborNoError) encode_error=cbor_encode_uint(&mapEncoder,0x02);
        if(encode_error==CborNoError) encode_error=cbor_encode_byte_string(&mapEncoder,wrapped,wrapped_len);
        mbedtls_platform_zeroize(wrapped,sizeof(wrapped));
        CBOR_CHECK(encode_error);
    }
#endif
'''
    s=one(s,'    else if (subcommand == 0x2) { //getKeyAgreement',branches+'    else if (subcommand == 0x2) { //getKeyAgreement')
    # Do not use an uncomputed shared coordinate after an ECDH error.
    s=one(s,'    ret = kdf(protocol, &z, sharedSecret);', '    if (ret == 0) ret = kdf(protocol, &z, sharedSecret);')
    return s+'\n'+(ROOT/'templates/local_uv_engine.inc').read_text(encoding='utf-8')

def info(s):
    # PF_FIRMWARE_VERSION_FIX_R2: report this port, not pinned upstream PICO_FIDO_VERSION.
    s=one(s,
          '    CBOR_CHECK(cbor_encode_uint(&mapEncoder, PICO_FIDO_VERSION)); // firmwareVersion',
          '    CBOR_CHECK(cbor_encode_uint(&mapEncoder, PF_FIRMWARE_VERSION_U32)); // firmwareVersion: PicoFido port')
    # PF_WINDOWS_PIN_PROBE_FIX_R1: CTAP versions are FIDO_2_0, FIDO_2_1, FIDO_2_3.
    s=one(s,
          'CBOR_CHECK(cbor_encoder_create_array(&mapEncoder, &arrayEncoder, 4 + !alwaysUv));',
          'CBOR_CHECK(cbor_encoder_create_array(&mapEncoder, &arrayEncoder, 3 + !alwaysUv));')
    s=one(s,'    CBOR_CHECK(cbor_encode_text_stringz(&arrayEncoder, "FIDO_2_2"));\n','')
    # The inherited UVM extension reports external PIN + hardware protection.
    # Do not advertise that tuple for this local/software development port.
    s=one(s,'8 + (file_has_data(ef_pin_policy) ? 1 : 0)',
          '7 + (file_has_data(ef_pin_policy) ? 1 : 0)')
    s=one(s,'    CBOR_CHECK(cbor_encode_text_stringz(&arrayEncoder, "uvm"));\n','')
    s=one(s,'uint8_t lfields = 20;','uint8_t lfields = 20 + (FIDO_V1_LOCAL_UV ? 2 : 0); /* PF_LOCAL_UV_024 */')
    s=one(s,'enterprise_profile ? 11 : 10','(enterprise_profile ? 11 : 10) + (FIDO_V1_LOCAL_UV ? 1 : 0)')
    anchor='    CBOR_CHECK(cbor_encode_text_stringz(&arrayEncoder, "alwaysUv"));'
    s=one(s,anchor,'''#pragma message ("PICO_FIDO_GETINFO_CBOR_C1: canonical options order")
#if FIDO_V1_LOCAL_UV
    CBOR_CHECK(cbor_encode_text_stringz(&arrayEncoder,"uv"));
    CBOR_CHECK(cbor_encode_boolean(&arrayEncoder,pf_local_uv_ready()));
#endif
'''+anchor)
    anchor='    CBOR_CHECK(cbor_encode_uint(&mapEncoder, MAX_RPIDS_MINPIN_LENGTH)); // maxRPIDsForSetMinPINLength'
    s=one(s,anchor,anchor+'''
#if FIDO_V1_LOCAL_UV
    CBOR_CHECK(cbor_encode_uint(&mapEncoder,0x11)); /* preferredPlatformUvAttempts */
    CBOR_CHECK(cbor_encode_uint(&mapEncoder,3));
    CBOR_CHECK(cbor_encode_uint(&mapEncoder,0x12)); /* uvModality: internal passcode */
    CBOR_CHECK(cbor_encode_uint(&mapEncoder,0x00000004));
#endif''')
    return '#include "ws_local_uv.h"\n'+s

def make(s):
    s=windows_pin_probe_fix(s)
    s=one(s,'    uint8_t flags = FIDO2_AUT_FLAG_AT;',
          '    uvm = NULL; /* UVM extension is not advertised by this port. */\n    uint8_t flags = FIDO2_AUT_FLAG_AT;')
    old='''        if (options.uv == ptrue) { //5.3
            CBOR_ERROR(CTAP2_ERR_INVALID_OPTION);
        }'''
    s=one(s,old,'''        if (options.uv == ptrue && (pinUvAuthParam.present || !pf_local_uv_ready())) {
            CBOR_ERROR(CTAP2_ERR_INVALID_OPTION);
        }''')
    anchor='    for (size_t e = 0; e < excludeList_len; e++) { //12.1'
    s=one(s,anchor,'''    /* PF_LOCAL_UV_024: legacy direct-uv operation, without fabricating a token. */
    if(options.uv == ptrue && !pinUvAuthParam.present) {
        int local_result=pf_local_uv_verify(CTAP_PERMISSION_MC);
        if(local_result) { CBOR_ERROR(local_result); }
        flags |= FIDO2_AUT_FLAG_UV | FIDO2_AUT_FLAG_UP;
    }
'''+anchor)
    # Ensure the no-token path collects UP rather than just setting the flag.
    anchor='    if (options.up == ptrue || options.up == NULL) { //14.1'
    s=one(s,anchor,'''    if(!pinUvAuthParam.present && !(flags & FIDO2_AUT_FLAG_UP)) {
        if(!check_user_presence()) { CBOR_ERROR(CTAP2_ERR_OPERATION_DENIED); }
        flags |= FIDO2_AUT_FLAG_UP;
    }
'''+anchor)
    return '#include "ws_local_uv.h"\n'+s

def assertion(s):
    s=windows_pin_probe_fix(s)
    old='''            if (options.uv == ptrue) { //4.3
                CBOR_ERROR(CTAP2_ERR_INVALID_OPTION);
            }'''
    s=one(s,old,'''            if (options.uv == ptrue && (pinUvAuthParam.present || !pf_local_uv_ready())) {
                CBOR_ERROR(CTAP2_ERR_INVALID_OPTION);
            }''')
    anchor='        bool silent = (up == false && uv == false);'
    s=one(s,anchor,'''        /* PF_LOCAL_UV_024: PIN verification precedes credential access. */
        if(options.uv == ptrue && !pinUvAuthParam.present) {
            int local_result=pf_local_uv_verify(CTAP_PERMISSION_GA);
            if(local_result) { CBOR_ERROR(local_result); }
            flags |= FIDO2_AUT_FLAG_UV | FIDO2_AUT_FLAG_UP;
        }
'''+anchor)
    return '#include "ws_local_uv.h"\n'+s

def hid(s):
    s=one(s,'resp->init.data[0] = is_req_button_pending() ? 2 : 1;',
          'resp->init.data[0] = (is_req_button_pending() || ws_board_pin_pending()) ? 2 : 1; /* PF_LOCAL_UV_024 */')
    anchor='''        driver_init_hid();

        hid_rx[ITF_HID_CTAP].r_ptr += HID_RPT_SIZE;'''
    s=one(s,anchor,'''        driver_init_hid();

        /* R13_RW_PIN_USB_GATE: local Settings PIN is modal. Do not let a host
         * CTAP command overlap the READ ONLY -> READ/WRITE authorization. */
        if (ws_board_settings_pin_busy()) {
            msg_packet.len = msg_packet.current_len = 0;
            last_packet_time = 0;
            return ctap_error(CTAP1_ERR_CHANNEL_BUSY);
        }

        hid_rx[ITF_HID_CTAP].r_ptr += HID_RPT_SIZE;''')
    return '#include "ws_board.h"\n#include "ws_local_uv.h"\n'+s

def usb(s):
    s=one(s,'void card_exit(void) {', 'void card_exit(void) {\n    ws_board_pin_abort(); /* PF_LOCAL_UV_024 */')
    return '#include "ws_local_uv.h"\n'+s

TRANSFORMS={
 'fido/src/fido/cbor_client_pin.c':client_pin,
 'fido/src/fido/cbor_get_info.c':info,
 'fido/src/fido/cbor_make_credential.c':make,
 'fido/src/fido/cbor_get_assertion.c':assertion,
 'sdk/src/usb/hid/hid.c':hid,
 'sdk/src/usb/usb.c':usb,
}
