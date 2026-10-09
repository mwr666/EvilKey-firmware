#!/usr/bin/env python3
"""Real threaded native image/quota/rollback checks and unchanged serial diagnostics."""
import argparse,subprocess
from pathlib import Path
root=Path(__file__).resolve().parents[2]
a=argparse.ArgumentParser();a.add_argument('--zig',required=True);args=a.parse_args()
apps=root/'firmware/EvilKeyV1/src/apps';out=root/'firmware/test-output/scene3d';out.mkdir(parents=True,exist_ok=True)
for name in ('parallel','profile',''):
    test=root/('firmware/tests/test_scene3d'+('_'+name if name else '')+'.c')
    exe=out/('native-'+(name or 'regression')+'.exe')
    flags=['-DEK_RENDER_HOST_THREADS'] if name=='parallel' else []
    subprocess.run([args.zig,'cc','-Os','-UNDEBUG',*flags,'-I'+str(apps),str(apps/'ek_scene3d.c'),str(apps/'ek_render_parallel.c'),str(test),'-o',str(exe)],check=True)
    subprocess.run([str(exe)],check=True,timeout=60)
# Includes the production kernel directly to inspect private row ownership.
exe=out/'row-ownership.exe'
subprocess.run([args.zig,'cc','-Os','-UNDEBUG','-I'+str(apps),str(root/'firmware/tests/test_scene3d_row_ownership.c'),str(apps/'ek_render_parallel.c'),'-o',str(exe)],check=True)
subprocess.run([str(exe)],check=True,timeout=60)

exe=out/'clock-poll.exe'
subprocess.run([args.zig,'cc','-Os','-UNDEBUG','-DEK_RENDER_HOST_THREADS','-I'+str(apps),str(root/'firmware/tests/test_scene3d_clock_poll.c'),str(apps/'ek_render_parallel.c'),'-o',str(exe)],check=True)
subprocess.run([str(exe)],check=True,timeout=60)

exe=out/'prepare-once.exe'
subprocess.run([args.zig,'cc','-Os','-UNDEBUG','-DEK_RENDER_HOST_THREADS','-I'+str(apps),str(root/'firmware/tests/test_scene3d_prepare_once.c'),str(apps/'ek_render_parallel.c'),'-o',str(exe)],check=True)
subprocess.run([str(exe)],check=True,timeout=60)

exe=out/'span.exe'
subprocess.run([args.zig,'cc','-Os','-UNDEBUG','-I'+str(apps),str(root/'firmware/tests/test_scene3d_span.c'),str(apps/'ek_render_parallel.c'),'-o',str(exe)],check=True)
subprocess.run([str(exe)],check=True,timeout=60)
