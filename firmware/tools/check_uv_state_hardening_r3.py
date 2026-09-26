#!/usr/bin/env python3
from __future__ import annotations
from pathlib import Path
import argparse
import sys

MARKER="PF_UV_STALE_STATE_R3"

def normalize_root(p: Path) -> Path:
    p=p.resolve()
    if (p/'firmware/templates/port/ws_board.c').is_file(): return p
    if (p/'templates/port/ws_board.c').is_file() and p.name.lower()=='firmware': return p.parent
    raise RuntimeError('firmware/templates/port/ws_board.c was not found')

def main()->int:
    ap=argparse.ArgumentParser();ap.add_argument('--firmware-root',type=Path,default=Path.cwd());args=ap.parse_args()
    try: root=normalize_root(args.firmware_root)
    except Exception as e:
        print('FAIL:',e);return 1
    board=root/'firmware/templates/port/ws_board.c'
    s=board.read_text(encoding='utf-8',errors='replace')
    checks={
      'R3 marker': s.count(MARKER)>=3,
      'epoch ownership': 'owns_pinpad=s_pin_active && s_pin_owner==WS_PIN_OWNER_FIDO && s_pin_epoch==my_epoch' in s,
      'immediate abort invalidation': 's_pin_active=false;\n        s_pin_owner=WS_PIN_OWNER_NONE;\n        s_pin_epoch=(s_pin_epoch+1U)|0x80000000U;' in s,
      'terminal presence recovery': 'if(s_pending && !s_presence.active)' in s,
      'live presence remains busy': '|| s_pending)' in s,
    }
    failed=False
    for name,ok in checks.items():
        print(('PASS' if ok else 'FAIL')+': '+name)
        failed |= not ok
    t=root/'firmware/tests/release_026/test_board_ui1.c'
    if t.is_file():
        ts=t.read_text(encoding='utf-8',errors='replace')
        ok='PASS board hardening: live presence request is never stolen by local UV' in ts
        print(('PASS' if ok else 'WARN')+': source regression tests '+('present' if ok else 'not patched'))
    eng=root/'firmware/EvilKeyV1/src/engine/board/ws_board.c'
    if eng.is_file():
        ok=MARKER in eng.read_text(encoding='utf-8',errors='replace')
        print(('PASS' if ok else 'WARN')+': generated Arduino engine '+('contains R3' if ok else 'is stale - regenerate before flashing'))
    else:
        print('INFO: generated Arduino engine not present yet')
    if failed: return 1
    print('Result: PASS (source).')
    return 0
if __name__=='__main__': raise SystemExit(main())
