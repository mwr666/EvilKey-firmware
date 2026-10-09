#!/usr/bin/env python3
"""Build Jet and its real firmware frontend on the host; emit native RGB565 frames."""
import argparse
import os
import subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
def build_objects(zig=None,gxx=None,defines=()):
    build=ROOT/'firmware/build/jet';build.mkdir(parents=True,exist_ok=True)
    vendor=ROOT/'firmware/third_party/jet';port=ROOT/'firmware/templates/port'
    sources=[*sorted(vendor.glob('*.cpp')),port/'ws_gui_3d.cpp',ROOT/'firmware/EvilKeyV1/src/apps/ek_render_parallel.c']
    objects=[]
    for source in sources:
        obj=build/(source.stem+'.o');objects.append(obj)
        is_c=source.suffix=='.c'
        compiler=[str(Path(gxx).with_name(Path(gxx).name.replace('g++','gcc')))] if gxx and is_c else ([gxx] if gxx else [zig,'cc' if is_c else 'c++','-target','x86-windows-gnu'])
        subprocess.run([*compiler,'-std=c11' if is_c else '-std=c++17','-O2','-UNDEBUG','-DWS_3D_HOST',
                        '-DEK_RENDER_HOST_THREADS',*['-D'+d for d in defines],
                        '-I'+str(port),'-I'+str(ROOT/'firmware/tools/launcher_lvgl_host'),
                        '-I'+str(vendor),'-c',str(source),'-o',str(obj)],check=True)
    return objects
def main():
    parser=argparse.ArgumentParser();compiler=parser.add_mutually_exclusive_group(required=True)
    compiler.add_argument('--zig');compiler.add_argument('--gxx');a=parser.parse_args()
    defines=[]
    objects=build_objects(a.zig,a.gxx,defines);out=ROOT/'firmware/build/jet-test.exe'
    command=[a.gxx] if a.gxx else [a.zig,'c++','-target','x86-windows-gnu']
    subprocess.run([*command,'-std=c++17','-O2','-UNDEBUG','-DWS_3D_HOST',
                    *['-D'+d for d in defines],
                    '-I'+str(ROOT/'firmware/templates/port'),str(ROOT/'firmware/tests/test_gui_3d.cpp'),
                    *map(str,objects),'-o',str(out)],check=True)
    env=os.environ.copy();env['EVILKEY_VERIFY_TILED']='1'
    subprocess.run([str(out)],cwd=ROOT,check=True,timeout=120,env=env)
    for mode in ['EVILKEY_TEST_3D_PARALLEL_ALLOC_FAIL','EVILKEY_TEST_3D_LOW_INTERNAL','EVILKEY_TEST_3D_ALLOC_FAIL']:
        fallback=env.copy();fallback[mode]='1'
        subprocess.run([str(out)],cwd=ROOT,check=True,timeout=120,env=fallback)
if __name__=='__main__':main()
