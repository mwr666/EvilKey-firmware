#!/usr/bin/env python3
"""R18 guard: Settings PIN must not inherit stale CTAP cancel_button state."""
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
FW=ROOT/'firmware'; PORT=FW/'templates'/'port'

def need(path,*tokens):
    text=path.read_text(encoding='utf-8')
    for token in tokens:
        if token not in text:
            raise SystemExit(f'FAIL {path}: missing {token!r}')
    return text

def main():
    board=need(PORT/'ws_board.c',
        'R18_SETTINGS_PIN_CANCEL_FIX',
        'cancel_button=false;',
        'bool pin_cancel=s_pin_owner==WS_PIN_OWNER_FIDO && cancel_button;',
        'ws_pinpad_step(&s_pinpad,now,pin_cancel',
        'ws_board_pin_abort()')
    # Ordering: stale level is cleared before the Settings pinpad begins.
    begin=board.index('static bool settings_begin_rw_pin')
    clear=board.index('cancel_button=false;',begin)
    start=board.index('ws_pinpad_begin(&s_pinpad',begin)
    if clear > start:
        raise SystemExit('FAIL: stale cancel must be cleared before Settings PIN begins')
    test=need(FW/'tests/release_026/test_board_ui1.c',
        'R18 regression', 'cancel_button=true;',
        'assert(!cancel_button);assert(ws_board_settings_pin_busy())')
    print('PASS: R18 starts Settings READ/WRITE PIN with a fresh cancel scope')
    print('PASS: stale CTAP/USB cancel level cannot instantly cancel the Settings PIN')
    print('PASS: real transport abort still uses ws_board_pin_abort; FIDO PIN keeps cancel_button')

if __name__=='__main__': main()
