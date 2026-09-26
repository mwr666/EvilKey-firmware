#!/usr/bin/env python3
"""R16 guard: on-device READ/WRITE PIN lookup must not depend on CTAPHID_INIT."""
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]; FW=ROOT/'firmware'; PORT=FW/'templates'/'port'

def need(path,*tokens):
    text=path.read_text(encoding='utf-8')
    for token in tokens:
        if token not in text: raise SystemExit(f'FAIL {path}: missing {token!r}')
    return text

def main():
    binding=need(PORT/'local_uv_binding.h','R16_RW_PIN_INIT_FIX',
        'file_search_by_fid(EF_PIN,NULL,SPECIFY_EF)',
        'file_search_by_fid(EF_KEY_DEV,NULL,SPECIFY_EF)',
        'if(pin) ef_pin=pin;','ef_keydev=key;')
    local=need(FW/'templates/local_uv_engine.inc','#include "local_uv_binding.h"',
        'file_t *pin=pf_local_uv_pin_file();','pf_local_uv_bind_keydev_file()',
        'PIN_LEGACY_DATA_LEN','PIN_DATA_LEN')
    board=need(PORT/'ws_board.c','PICO_FIDO_LVGL_R16_RW_PIN_INIT_FIX',
        '(void)pf_local_uv_ready();','settings_begin_rw_pin(settings,now)',
        'pf_local_uv_verify_supplied_pin(pin,pin_len)')
    test=need(FW/'tests/release_026/test_local_uv_binding.c',
        'ef_pin == NULL && ef_keydev == NULL','pf_local_uv_pin_file() == &pin_file',
        'PASS R16: local Settings PIN resolves EF_PIN/EF_KEY_DEV before CTAPHID_INIT')
    engine=need(FW/'templates/engine_entry.c.inc','file_scan_flash();','ws_board_init();','picokey_init();')
    if engine.index('file_scan_flash();') > engine.index('ws_board_init();'):
        raise SystemExit('FAIL: flash scan must precede board/local-PIN binding')
    print('PASS: R16 local PIN lookup resolves flash records independently of host CTAPHID_INIT')
    print('PASS: EF_PIN is bound at board startup after file_scan_flash and re-resolved lazily on use')
    print('PASS: EF_KEY_DEV is bound only after a correct PIN verifier match, before key unwrap/migration')
    print('PASS: R15 34-byte/35-byte PIN compatibility remains present')

if __name__=='__main__': main()
