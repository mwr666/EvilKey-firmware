"""Rasterize the native LVGL gamepad with physical flush-bound checks."""
import argparse
from pathlib import Path
import subprocess
from PIL import Image
p=argparse.ArgumentParser();p.add_argument('--zig',required=True);a=p.parse_args()
root=Path(__file__).resolve().parents[3];here=Path(__file__).parent
engine=root/'firmware/EvilKeyV1/src/engine';out=root/'firmware/build/gamepad-lvgl-test.exe'
out.parent.mkdir(exist_ok=True)
for name in ['ws_gamepad_view.c','ws_gamepad_view.h']:
    text=(root/'firmware/templates/port'/name).read_text().replace('../lvgl/lvgl.h','lvgl.h')
    (out.parent/name).write_text(text)
cmd=[a.zig,'cc','-target','x86-windows-gnu','-O1','-UNDEBUG','-include','stdlib.h',
     '-DLV_ASSERT_HANDLER=abort();',f'-I{root}/firmware/tools/launcher_lvgl_host',
     f'-I{out.parent}',f'-I{root}/firmware/templates/port',f'-I{engine}/lvgl',str(here/'test.c'),str(root/'firmware/templates/port/ws_controls.c'),
     *map(str, sorted((engine/'lvgl/src').rglob('*.c'))),'-o',str(out)]
subprocess.run(cmd,check=True);subprocess.run([str(out)],check=True,cwd=root,timeout=60)
for name in ['dpad','pressed','analog','exit','settings','forget','rotated','center','settings-pressed']:
    path=root/f'firmware/build/gamepad-{name}.ppm'
    image=Image.open(path).transpose(Image.Transpose.ROTATE_90 if name=='rotated' else Image.Transpose.ROTATE_270)
    image.save(path.with_suffix('.png'))
