#!/usr/bin/env python3
"""Regenerate the bounded 3D frontend and pinned Jet files, without upstream edits."""
import hashlib
import json
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENGINE = ROOT / 'EvilKeyV1/src/engine'
def main():
    manifest_path=ROOT/'EvilKeyV1/GENERATED_MANIFEST.json'
    manifest=json.loads(manifest_path.read_text(encoding='utf-8'))
    port=json.loads((ROOT/'ARDUINO_PORT.json').read_text(encoding='utf-8'))
    manifest['port_version']=port['port_version']
    manifest['package_revision']='EVILKEY_'+port['port_version'].replace('.','_')+'_JET_OS_ABI_V5'
    updates={}
    for source in sorted((ROOT/'third_party/jet').glob('*')):
        if source.suffix in ('.cpp','.hpp','.h') and source.name!='JetConfig.example.hpp':
            updates['jet/'+source.name]=source.read_text(encoding='utf-8')
    for name in ('ws_lvgl.c','ws_gui_3d.cpp','ws_gui_3d.h','ws_gui_3d_geometry.h','ws_gui_3d_meshes.h','ws_gamepad_view.c','ws_gui_theme.h','ws_board.c','ws_board.h','ws_panel.c'):
        text=(ROOT/'templates/port'/name).read_text(encoding='utf-8')
        text=text.replace('../../EvilKeyV1/src/apps/','../../apps/')
        text=text.replace('../../third_party/jet/','../jet/')
        text=text.replace('#include "pf_firmware_version.h"','#include "../../pf_firmware_version.h"')
        text=text.replace('#include "pf_engine_api.h"','#include "../../pf_engine_api.h"')
        text=text.replace('#include "led/led.h"','#include "../sdk/src/led/led.h"')
        text=text.replace('#include "button.h"','#include "../sdk/src/button.h"')
        if name.endswith(('.c','.cpp')):text='#include "../../pf_build_config.h"\n'+text
        updates['board/'+name]=text
    entry=ROOT/'templates/engine_entry.c.inc'
    main_path=ENGINE/'sdk/src/main.c'
    current=main_path.read_text(encoding='utf-8')
    marker='/* Arduino startup replaces app_main and the ESP-IDF TinyUSB driver install. */'
    if current.count(marker)!=1:raise RuntimeError('Unexpected engine startup layout')
    updates['sdk/src/main.c']=current[:current.index(marker)]+entry.read_text(encoding='utf-8')
    for rel,text in updates.items():
        dest=ENGINE/rel;dest.parent.mkdir(parents=True,exist_ok=True)
        data=text.encode('utf-8')
        if not dest.exists() or dest.read_bytes()!=data:dest.write_bytes(data)
        manifest['generated_sha256'][rel]=hashlib.sha256(text.encode()).hexdigest()
    manifest['jet']={'repository':'https://github.com/CubeCoders/Jet',
                     'commit':'c56dfc0c012ba7a09a6e49b4123340ec24981441','license':'MIT'}
    manifest_data=(json.dumps(manifest,indent=2)+'\n').encode('utf-8')
    if manifest_path.read_bytes()!=manifest_data:manifest_path.write_bytes(manifest_data)
    shutil.copyfile(ROOT/'third_party/jet/LICENSE', ROOT/'EvilKeyV1/data/upstream-licenses/Jet_LICENSE')
    print(f'Synchronized {len(updates)} 3D frontend and Jet files')
if __name__=='__main__':main()
