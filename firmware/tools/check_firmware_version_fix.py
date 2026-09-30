# PF_FIRMWARE_VERSION_FIX_R2
#!/usr/bin/env python3
from pathlib import Path
import re,sys
root=Path.cwd().resolve()
if not (root/'firmware/tools/touch_patch.py').is_file():
    print('FAIL: run from the EvilKey firmware project root')
    raise SystemExit(1)
errors=[]
def check(cond,msg):
    if cond: print('PASS:',msg)
    else: errors.append(msg);print('FAIL:',msg)
vh=root/'firmware/EvilKeyV1/src/pf_firmware_version.h'
check(vh.is_file(),'canonical firmware version header exists')
if vh.is_file():
    text=vh.read_text(encoding='utf-8')
    vals={}
    for key in ('MAJOR','MINOR','PATCH','BUILD'):
        m=re.search(r'^#define\s+PF_FIRMWARE_VERSION_'+key+r'\s+(\d+)\s*$',text,re.M)
        if m: vals[key]=int(m.group(1))
    check(vals=={'MAJOR':0,'MINOR':5,'PATCH':0,'BUILD':0},'version header encodes 0.5.0 build 0')
    check('#define PF_FIRMWARE_VERSION_SUFFIX ""' in text,'0.5.0 version has no suffix')
build=(root/'firmware/EvilKeyV1/src/pf_build_config.h').read_text(encoding='utf-8')
check('#include "pf_firmware_version.h"' in build,'pf_build_config includes canonical version header')
m1=(root/'firmware/templates/port/ws_manager_config.h').read_text(encoding='utf-8')
check('PF_FIRMWARE_VERSION_STRING' in m1,'M1 reply uses canonical version string')
touch=(root/'firmware/tools/touch_patch.py').read_text(encoding='utf-8')
check('PF_FIRMWARE_VERSION_U32' in touch,'GetInfo transform uses canonical uint32 version')
engine=root/'firmware/EvilKeyV1/src/engine/fido/src/fido/cbor_get_info.c'
if engine.is_file():
    e=engine.read_text(encoding='utf-8')
    check('PF_FIRMWARE_VERSION_U32' in e,'generated GetInfo uses PicoFido firmware version')
else:
    print('INFO: generated engine not present; regenerate before Arduino build.')
if errors:
    print('\nResult: FAIL (%d problem(s))'%len(errors));raise SystemExit(1)
print('\nResult: PASS')
