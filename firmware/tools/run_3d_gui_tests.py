#!/usr/bin/env python3
"""Build Jet and its real firmware frontend on the host; emit native RGB565 frames."""
import argparse
import os
import subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
def build_objects(zig=None,gxx=None):
    build=ROOT/'firmware/build/jet';build.mkdir(parents=True,exist_ok=True)
    vendor=ROOT/'firmware/third_party/jet';port=ROOT/'firmware/templates/port'
    sources=[*sorted(vendor.glob('*.cpp')),port/'ws_gui_3d.cpp']
    objects=[]
    for source in sources:
        obj=build/(source.stem+'.o');objects.append(obj)
        compiler=[gxx] if gxx else [zig,'c++','-target','x86-windows-gnu']
        subprocess.run([*compiler,'-std=c++17','-O2','-UNDEBUG','-DWS_3D_HOST',
                        '-I'+str(port),'-I'+str(ROOT/'firmware/tools/launcher_lvgl_host'),
                        '-I'+str(vendor),'-c',str(source),'-o',str(obj)],check=True)
    return objects
def main():
    parser=argparse.ArgumentParser();compiler=parser.add_mutually_exclusive_group(required=True)
    compiler.add_argument('--zig');compiler.add_argument('--gxx');a=parser.parse_args()
    objects=build_objects(a.zig,a.gxx);out=ROOT/'firmware/build/jet-test.exe'
    command=[a.gxx] if a.gxx else [a.zig,'c++','-target','x86-windows-gnu']
    subprocess.run([*command,'-std=c++17','-O2','-UNDEBUG','-DWS_3D_HOST',
                    '-I'+str(ROOT/'firmware/templates/port'),str(ROOT/'firmware/tests/test_gui_3d.cpp'),
                    *map(str,objects),'-o',str(out)],check=True)
    env=os.environ.copy();env['EVILKEY_VERIFY_TILED']='1'
    subprocess.run([str(out)],cwd=ROOT,check=True,timeout=120,env=env)
if __name__=='__main__':main()
