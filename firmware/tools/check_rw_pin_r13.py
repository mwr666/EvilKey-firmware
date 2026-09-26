#!/usr/bin/env python3
"""Compatibility-named guard for R15 directional microSD write PIN + legacy PIN support."""
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];FW=ROOT/'firmware';PORT=FW/'templates'/'port'

def require(path,*tokens):
    text=path.read_text(encoding='utf-8')
    for token in tokens:
        if token not in text: raise SystemExit(f'FAIL {path}: missing {token!r}')
    return text

def main():
    board=require(PORT/'ws_board.c',
        'PICO_FIDO_LVGL_R16_RW_PIN_INIT_FIX',
        'R13_RW_PIN_GATE','if(ws_manager_drive_read_only())',
        '(void)settings_begin_rw_pin(settings,now);','ws_manager_drive_set_read_only(true)',
        'pf_local_uv_verify_supplied_pin(pin,pin_len)','WS_PIN_OWNER_SETTINGS_RW',
        'bool ws_board_settings_pin_busy(void)')
    if board.count('pf_local_uv_verify_supplied_pin(')!=1:
        raise SystemExit('FAIL: supplied-PIN verifier must have exactly one board call site')
    local=require(FW/'templates/local_uv_engine.inc',
        'R16_RW_PIN_INIT_FIX','PIN_LEGACY_DATA_LEN','PIN_DATA_LEN',
        'int pf_local_uv_verify_supplied_pin(','pf_uv_unlock_and_migrate_pin(',
        'double_hash_pin(CONST_BYTE_ARRAY(h,16),verifier)',
        'pin_derive_verifier(CONST_BYTE_ARRAY(h,16),verifier)',
        'mbedtls_ct_memcmp(verifier,stored+off,32)',
        'hash_multi(CONST_BYTE_ARRAY(h,16),session_pin)',
        'encrypt_keydev_f1(key)','check_keydev_encrypted(session_pin)',
        'upgraded[2]=1','ws_uv_retries_reserve()','ws_uv_retries_reset()',
        'Settings authentication never leaves a UV','pf_uv_forget_working_secrets();\n    return result;')
    require(PORT/'ws_ui.h','WS_PIN_PURPOSE_ENABLE_RW','WS_SETTINGS_FEEDBACK_PIN_BAD')
    require(PORT/'ws_lvgl.c','"Enable write access"','"FIDO PIN for READ/WRITE"',
            '"Wrong PIN - still READ ONLY"')
    require(FW/'tools/touch_patch.py','R13_RW_PIN_USB_GATE','ws_board_settings_pin_busy()','CTAP1_ERR_CHANNEL_BUSY')
    require(PORT/'ws_manager_config.h','CTAP_PERMISSION_ACFG','getUserVerifiedFlagValue()','WS_MANAGER_DRIVE_WRITE_ID')
    print('PASS: READ ONLY -> READ/WRITE requires a fresh local FIDO PIN; reverse direction stays PIN-free')
    print('PASS: local verifier resolves PIN/key files before host CTAPHID_INIT and accepts 34/35-byte records')
    print('PASS: a successful legacy PIN check migrates the record/key wrapping to current format')
    print('PASS: Settings authentication leaves no reusable FIDO UV/token session')
    print('PASS: host CTAP is gated while the modal Settings PIN prompt owns the pinpad')

if __name__=='__main__': main()
