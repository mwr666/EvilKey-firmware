# SPDX-License-Identifier: AGPL-3.0-or-later
"""Actual LVGL composition/rasterization; panel and logo inflater are host mocks."""
import argparse,subprocess,os
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--zig',required=True)
p.add_argument('--packages',nargs=5,type=Path,required=True,help='Five compatible packages you are authorized to use')
p.add_argument('--frame',type=Path,required=True,help='280x456 test frame you are authorized to use')
a=p.parse_args()
root=Path(__file__).resolve().parents[3];here=Path(__file__).parent
renderer=root/'firmware/build/launcher-renderer.c'
renderer.parent.mkdir(exist_ok=True)
text=(root/'firmware/templates/port/ws_lvgl.c').read_text().replace('../../EvilKeyV1/src/apps/','').replace('../lvgl/lvgl.h','lvgl.h')
renderer.write_text(text)
for name in ['ws_gamepad_view.c','ws_gamepad_view.h']:
    text=(root/'firmware/templates/port'/name).read_text().replace('../lvgl/lvgl.h','lvgl.h')
    (renderer.parent/name).write_text(text)
sources=sorted((root/'firmware/EvilKeyV1/src/engine/lvgl/src').rglob('*.c'))
out=root/'firmware/build/launcher-lvgl-test.exe';out.parent.mkdir(exist_ok=True)
cmd=[a.zig,'cc','-target','x86-windows-gnu','-O1','-UNDEBUG','-include','stdlib.h','-DLV_ASSERT_HANDLER=abort();',f'-I{here}',f'-I{root}/firmware/EvilKeyV1/src',f'-I{root}/firmware/EvilKeyV1/src/apps',f'-I{root}/firmware/templates/port',f'-I{root}/firmware/EvilKeyV1/src/engine/lvgl',f'-I{root}/firmware/build',str(here/'test.c'),str(root/'firmware/templates/port/ws_ui.c'),str(renderer.parent/'ws_gamepad_view.c'),str(root/'firmware/templates/port/ws_controls.c'),*map(str,sources),'-o',str(out)]
r=subprocess.run(cmd,capture_output=True,text=True)
if r.returncode:print(r.stderr);raise SystemExit(r.returncode)
from PIL import Image
import struct
packages=[x.resolve(strict=True) for x in a.packages]
source=a.frame.resolve(strict=True)
image=Image.open(source).convert('RGB');assert image.size==(280,456)
frame=root/'firmware/build/blocks-ui.rgb565'
frame.write_bytes(b''.join(struct.pack('<H',(r>>3)<<11|(g>>2)<<5|(b>>3)) for r,g,b in image.get_flattened_data()))
subprocess.run([str(out),*map(str,packages),str(frame)],check=True,timeout=60,cwd=root)
env=os.environ.copy();env['EVILKEY_TEST_USB_MOUSE']='1'
subprocess.run([str(out),*map(str,packages),str(frame)],check=True,timeout=60,cwd=root,env=env)

env=os.environ.copy();env['EVILKEY_TEST_BLE_MOUSE']='1'
subprocess.run([str(out),*map(str,packages),str(frame)],check=True,timeout=60,cwd=root,env=env)
env=os.environ.copy();env['EVILKEY_TEST_BLE_PAD']='1'
subprocess.run([str(out),*map(str,packages),str(frame)],check=True,timeout=60,cwd=root,env=env)
for name in ['launcher-five','launcher-intro','launcher-dots-intro','launcher-dots-grid','settings-intro','launcher-to-settings','settings-to-launcher','app-exit-idle','app-exit-drag','app-exit-ready','app-exit-confirm','airmouse-ble-settings','airmouse-ble-forget','airmouse-latched']:
    Image.open(root/f'firmware/build/{name}.ppm').save(root/f'firmware/build/{name}.png')
