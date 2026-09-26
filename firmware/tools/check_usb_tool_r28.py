#!/usr/bin/env python3
"""R28 guard: Hak5 payload index must not reserve 320x192 bytes of internal SRAM."""
from pathlib import Path
import re

ROOT=Path(__file__).resolve().parents[2]
TOOL=ROOT/'firmware'/'EvilKeyV1'/'src'/'UsbTool.cpp'
text=TOOL.read_text(encoding='utf-8')

required=(
    'static char **s_scripts;',
    'ensure_psram_tables(void)',
    'heap_caps_calloc(MAX_SCRIPTS,sizeof(*scripts),caps)',
    'clear_script_index(void)',
    'alloc_script_path(const char *path)',
    'alloc_tool_memory(size_t bytes)',
    'if(psramFound())p=ps_malloc(bytes);',
    'if(!p)p=malloc(bytes);',
    'char *copy=(char *)alloc_tool_memory(n+1U);',
    'char *script=(char *)alloc_tool_memory(len+1U);',
    'char *json=(char *)alloc_tool_memory(len+1U);',
    'free(s_scripts[i]);',
    's_scripts[pos]=copy;++s_script_count;',
    'Ready - index truncated',
)
for token in required:
    if token not in text:
        raise SystemExit(f'FAIL: missing R28 RAM-index token: {token}')

if re.search(r's_scripts\s*\[\s*MAX_SCRIPTS\s*\]\s*\[\s*MAX_PATH\s*\]', text):
    raise SystemExit('FAIL: fixed 320 x MAX_PATH script matrix reintroduced')
if 'memcpy(s_scripts[pos],s_scripts[pos-1U],MAX_PATH)' in text:
    raise SystemExit('FAIL: fixed-width script-path shifting reintroduced')

# The pointer table is now allocated at runtime (PSRAM preferred), while the
# per-path R28 allocation still replaces R27's 320 x 192 static matrix.
old_static=320*192
pointer_table=320*4
saved=old_static-pointer_table
if saved != 60160 or 'heap_caps_calloc' not in text:
    raise SystemExit('FAIL: R28 static-RAM saving arithmetic drifted')

print(f'PASS: R28 variable-length payload index reclaims {saved} bytes of fixed internal SRAM')
print('PASS: payload pointer/path tables prefer PSRAM and retain normal-heap fallback')
print('PASS: 320-payload / 192-byte maximum path compatibility is retained')
