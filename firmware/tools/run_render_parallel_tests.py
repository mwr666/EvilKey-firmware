#!/usr/bin/env python3
"""Compile the production C executor and test genuine concurrency and fallback."""
import argparse
import subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
def main():
    p=argparse.ArgumentParser()
    compiler=p.add_mutually_exclusive_group(required=True)
    compiler.add_argument('--zig')
    compiler.add_argument('--gxx')
    p.add_argument('--baseline',action='store_true',help='RED: replace missing pool with a serial fixture')
    a=p.parse_args()
    build=ROOT/'firmware/build/render-parallel';build.mkdir(parents=True,exist_ok=True)
    app=ROOT/'firmware/EvilKeyV1/src/apps'
    source=app/'ek_render_parallel.c'
    if a.baseline:
        source=build/'serial_baseline.c'
        source.write_text('#include "ek_render_parallel.h"\n'
          'static bool enabled=true;\nvoid ek_render_workers_start(void){}\n'
          'bool ek_render_workers_ready(void){return false;}\n'
          'void ek_render_parallel_enable(bool e){enabled=e;}\n'
          'unsigned ek_render_core_id(void){return 0;}\n'
          'bool ek_render_parallel(EkRenderWork w,void*a,void*b){if(w){w(a);w(b);}return false;}\n'
          'void ek_render_worker_stats(EkRenderWorkerStats*s){if(s)*s=(EkRenderWorkerStats){0,enabled,{0,0},{0,0}};}\n')
    for mode in (['threaded'] if a.baseline else ['threaded','serial','failure']):
        obj=build/(mode+'.o')
        out=build/(mode+'.exe')
        flags=['-DEK_RENDER_HOST_THREADS'] if mode!='serial' else []
        if mode=='failure':
            flags+=['-include',str(ROOT/'firmware/tests/render_parallel_start_failure.h')]
        cc=[str(Path(a.gxx).with_name('gcc.exe'))] if a.gxx else [a.zig,'cc']
        cxx=[a.gxx] if a.gxx else [a.zig,'c++']
        subprocess.run([*cc,'-std=c11','-O2','-Wall','-Wextra','-Werror',*flags,
                        '-I'+str(app),'-c',str(source),'-o',str(obj)],check=True)
        subprocess.run([*cxx,'-std=c++17','-O2','-UNDEBUG','-I'+str(app),
                        str(ROOT/'firmware/tests/test_render_parallel.cpp'),str(obj),'-o',str(out)],check=True)
        subprocess.run([str(out),*([mode] if mode!='threaded' else [])],check=True,timeout=30)
        if not a.baseline:
            native=build/(mode+'-native.o');frame=build/(mode+'-frame.exe')
            subprocess.run([*cc,'-std=c11','-Os','-UNDEBUG',*flags,'-I'+str(app),
                            '-c',str(app/'ek_scene3d.c'),'-o',str(native)],check=True)
            subprocess.run([*cxx,'-std=c++17','-Os','-UNDEBUG','-I'+str(app),
                            str(ROOT/'firmware/tests/test_render_frame.cpp'),str(obj),str(native),'-o',str(frame)],check=True)
            subprocess.run([str(frame),*([mode] if mode!='threaded' else [])],check=True,timeout=30)
if __name__=='__main__':main()
