# SPDX-License-Identifier: AGPL-3.0-or-later
"""Actual LVGL composition/rasterization; panel and logo inflater are host mocks."""
import argparse,subprocess,os
from pathlib import Path
p=argparse.ArgumentParser();compiler=p.add_mutually_exclusive_group(required=True)
compiler.add_argument('--zig');compiler.add_argument('--gxx');p.add_argument('--rings-only',action='store_true');p.add_argument('--scene-profile-only',action='store_true');a=p.parse_args()
root=Path(__file__).resolve().parents[3];here=Path(__file__).parent
renderer=root/'firmware/build/launcher-renderer.c'
renderer.parent.mkdir(exist_ok=True)
text=Path(os.getenv('EVILKEY_LVGL_SOURCE',str(root/'firmware/templates/port/ws_lvgl.c'))).read_text(encoding='utf-8').replace('../../EvilKeyV1/src/apps/','').replace('../lvgl/lvgl.h','lvgl.h')
renderer.write_text(text,encoding='utf-8')
for name in ['ws_gamepad_view.c','ws_gamepad_view.h']:
    text=(root/'firmware/templates/port'/name).read_text().replace('../lvgl/lvgl.h','lvgl.h')
    (renderer.parent/name).write_text(text)
import sys
sys.path.insert(0,str(root/'firmware/tools'))
from run_3d_gui_tests import build_objects
jet_objects=build_objects(a.zig,a.gxx)
sources=sorted((root/'firmware/EvilKeyV1/src/engine/lvgl/src').rglob('*.c'))
out=root/'firmware/build/launcher-lvgl-test.exe';out.parent.mkdir(exist_ok=True)
command=[str(Path(a.gxx).with_name('gcc.exe'))] if a.gxx else [a.zig,'cc','-target','x86-windows-gnu']
cmd=[*command,'-O1','-UNDEBUG','-include','stdlib.h','-DLV_ASSERT_HANDLER=abort();',f'-I{here}',f'-I{root}/firmware/EvilKeyV1/src',f'-I{root}/firmware/EvilKeyV1/src/apps',f'-I{root}/firmware/templates/port',f'-I{root}/firmware/EvilKeyV1/src/engine/lvgl',f'-I{root}/firmware/build',str(here/'test.c'),str(root/'firmware/templates/port/ws_ui.c'),str(renderer.parent/'ws_gamepad_view.c'),str(root/'firmware/templates/port/ws_controls.c'),*map(str,sources),*map(str,jet_objects),'-lstdc++' if a.gxx else '-lc++','-o',str(out)]
rsp=root/'firmware/build/launcher-lvgl.rsp'
rsp.write_text('\n'.join('"'+arg.replace('\\','/').replace('"','\\"')+'"' for arg in cmd[len(command):]),encoding='utf-8')
r=subprocess.run([*command,'@'+str(rsp)],capture_output=True,text=True)
if r.returncode:print(r.stderr);raise SystemExit(r.returncode)
if os.getenv('EVILKEY_BUFFER_FRAMES'):
    subprocess.run([str(out),'--buffer-frames'],check=True,timeout=90,cwd=root)
    raise SystemExit(0)
if a.scene_profile_only:
    subprocess.run([str(out),'--scene-profile-only'],check=True,timeout=60,cwd=root)
    raise SystemExit(0)
if a.rings_only:
    subprocess.run([str(out),'--rings-only'],check=True,timeout=60,cwd=root)
    raise SystemExit(0)
from PIL import Image
import struct
packages=[root.parent/name/'package'/f'{ident}.ekapp' for name,ident in [('EvilBlocks','evil.blocks'),('EvilBreaker','evil.breaker'),('EvilInvaders','evil.invaders'),('EvilPinball','evil.pinball'),('EvilRacer','evil.racer')]]
source=root.parent/'EvilBlocks/package/host.ppm'
if not source.exists():source=root.parent/'EvilBlocks/assets/01.png'
image=Image.open(source).convert('RGB');assert image.size==(280,456)
frame=root/'firmware/build/blocks-ui.rgb565'
frame.write_bytes(b''.join(struct.pack('<H',(r>>3)<<11|(g>>2)<<5|(b>>3)) for r,g,b in image.get_flattened_data()))
subprocess.run([str(out),*map(str,packages),str(frame)],check=True,timeout=60,cwd=root)

env=os.environ.copy();env['EVILKEY_TEST_STAGING']='1'
subprocess.run([str(out),*map(str,packages),str(frame)],check=True,timeout=60,cwd=root,env=env)
env=os.environ.copy();env['EVILKEY_TEST_USB_MOUSE']='1'
subprocess.run([str(out),*map(str,packages),str(frame)],check=True,timeout=60,cwd=root,env=env)

env=os.environ.copy();env['EVILKEY_TEST_BLE_MOUSE']='1'
subprocess.run([str(out),*map(str,packages),str(frame)],check=True,timeout=60,cwd=root,env=env)
env=os.environ.copy();env['EVILKEY_TEST_BLE_PAD']='1'
subprocess.run([str(out),*map(str,packages),str(frame)],check=True,timeout=60,cwd=root,env=env)
for name in ['launcher-five','launcher-intro','launcher-dots-intro','launcher-dots-grid','settings-intro','launcher-to-settings','settings-to-launcher','app-exit-idle','app-exit-drag','app-exit-ready','app-exit-confirm','airmouse-ble-settings','airmouse-ble-forget','airmouse-latched','3d-ready','3d-saver','3d-glitch','3d-pin','3d-diagnostics','gamepad-dma']:
    Image.open(root/f'firmware/build/{name}.ppm').save(root/f'firmware/build/{name}.png')
# Execute the same navigation/PIN contract without any Jet image sources.
# The legacy compressed-logo inflater remains mocked on this host path.
env=os.environ.copy();env['EVILKEY_TEST_3D_FALLBACK']='1'
subprocess.run([str(out),*map(str,packages),str(frame)],check=True,timeout=60,cwd=root,env=env)
# Frontal reference renders from the original icon builders for Jet shape QA.
env['EVILKEY_EXPORT_CLASSIC_ICONS']='1'
subprocess.run([str(out),*map(str,packages),str(frame)],check=True,timeout=60,cwd=root,env=env)
